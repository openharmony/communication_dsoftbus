/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "lnn_distributed_net_ledger.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <securec.h>

#include "lnn_event.h"
#include "anonymizer.h"
#include "auth_deviceprofile.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_fast_offline.h"
#include "lnn_lane_info.h"
#include "lnn_map.h"
#include "lnn_node_info.h"
#include "lnn_lane_def.h"
#include "lnn_deviceinfo_to_profile.h"
#include "lnn_device_info_recovery.h"
#include "lnn_feature_capability.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_adapter_crypto.h"
#include "softbus_bus_center.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_adapter_crypto.h"
#include "softbus_utils.h"
#include "softbus_hidumper_buscenter.h"
#include "bus_center_manager.h"
#include "softbus_hisysevt_bus_center.h"
#include "bus_center_event.h"

#define TIME_THOUSANDS_FACTOR (1000)
#define BLE_ADV_LOST_TIME 5000
#define LONG_TO_STRING_MAX_LEN 21
#define LNN_COMMON_LEN_64 8
#define DEVICE_TYPE_SIZE_LEN 3
#define SOFTBUS_BUSCENTER_DUMP_REMOTEDEVICEINFO "remote_device_info"

#define RETURN_IF_GET_NODE_VALID(networkId, buf, info)                                \
    do {                                                                              \
        if ((networkId) == NULL || (buf) == NULL) {                                   \
            LNN_LOGE(LNN_LEDGER, "networkId or buf is invalid");                      \
            return SOFTBUS_INVALID_PARAM;                                             \
        }                                                                             \
        (info) = LnnGetNodeInfoById((networkId), (CATEGORY_NETWORK_ID));              \
        if ((info) == NULL) {                                                         \
            char *anonyNetworkId = NULL;                                              \
            Anonymize(networkId, &anonyNetworkId);                                    \
            LNN_LOGE(LNN_LEDGER, "get node info fail. networkId=%{public}s", anonyNetworkId); \
            AnonymizeFree(anonyNetworkId);                                            \
            return SOFTBUS_ERR;                                                       \
        }                                                                             \
    } while (0)

#define CONNECTION_FREEZE_TIMEOUT_MILLIS (10 * 1000)

// softbus version for support initConnectFlag
#define SOFTBUS_VERSION_FOR_INITCONNECTFLAG "11.1.0.001"

typedef struct {
    Map udidMap;
    Map ipMap;
    Map macMap;
} DoubleHashMap;

typedef enum {
    DL_INIT_UNKNOWN = 0,
    DL_INIT_FAIL,
    DL_INIT_SUCCESS,
} DistributedLedgerStatus;

typedef struct {
    Map connectionCode;
} ConnectionCode;

typedef struct {
    DoubleHashMap distributedInfo;
    ConnectionCode cnnCode;
    int32_t countMax;
    SoftBusMutex lock;
    DistributedLedgerStatus status;
} DistributedNetLedger;

typedef struct {
    bool isOffline;
    bool oldWifiFlag;
    bool oldBrFlag;
    bool oldBleFlag;
    bool isChanged;
    bool isMigrateEvent;
    bool isNetworkChanged;
    bool newWifiFlag;
    bool newBleBrFlag;
} NodeInfoAbility;

static DistributedNetLedger g_distributedNetLedger;

static void UpdateNetworkInfo(const char *udid)
{
    NodeBasicInfo basic;
    if (memset_s(&basic, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memset_s basic fail!");
    }
    if (LnnGetBasicInfoByUdid(udid, &basic) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "GetBasicInfoByUdid fail.");
        return;
    }
    LnnNotifyBasicInfoChanged(&basic, TYPE_NETWORK_INFO);
}

static uint64_t GetCurrentTime(void)
{
    SoftBusSysTime now = { 0 };
    if (SoftBusGetTime(&now) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "GetCurrentTime fail.");
        return 0;
    }
    return (uint64_t)now.sec * TIME_THOUSANDS_FACTOR + (uint64_t)now.usec / TIME_THOUSANDS_FACTOR;
}

int32_t LnnSetAuthTypeValue(uint32_t *authTypeValue, AuthType type)
{
    if (authTypeValue == NULL || type >= AUTH_TYPE_BUTT) {
        LNN_LOGE(LNN_LEDGER, "in para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    *authTypeValue = (*authTypeValue) | (1 << (uint32_t)type);
    return SOFTBUS_OK;
}

int32_t LnnClearAuthTypeValue(uint32_t *authTypeValue, AuthType type)
{
    if (authTypeValue == NULL || type >= AUTH_TYPE_BUTT) {
        LNN_LOGE(LNN_LEDGER, "in para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    *authTypeValue = (*authTypeValue) & (~(1 << (uint32_t)type));
    return SOFTBUS_OK;
}

static NodeInfo *GetNodeInfoFromMap(const DoubleHashMap *map, const char *id)
{
    if (map == NULL || id == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error!");
        return NULL;
    }
    NodeInfo *info = NULL;
    if ((info = (NodeInfo *)LnnMapGet(&map->udidMap, id)) != NULL) {
        return info;
    }
    if ((info = (NodeInfo *)LnnMapGet(&map->macMap, id)) != NULL) {
        return info;
    }
    if ((info = (NodeInfo *)LnnMapGet(&map->ipMap, id)) != NULL) {
        return info;
    }
    LNN_LOGE(LNN_LEDGER, "id not exist!");
    return NULL;
}

static int32_t InitDistributedInfo(DoubleHashMap *map)
{
    if (map == NULL) {
        LNN_LOGE(LNN_LEDGER, "fail:para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    LnnMapInit(&map->udidMap);
    LnnMapInit(&map->ipMap);
    LnnMapInit(&map->macMap);
    return SOFTBUS_OK;
}

static void DeinitDistributedInfo(DoubleHashMap *map)
{
    if (map == NULL) {
        LNN_LOGE(LNN_LEDGER, "fail: para error!");
        return;
    }
    LnnMapDelete(&map->udidMap);
    LnnMapDelete(&map->ipMap);
    LnnMapDelete(&map->macMap);
}

static int32_t InitConnectionCode(ConnectionCode *cnnCode)
{
    if (cnnCode == NULL) {
        LNN_LOGE(LNN_LEDGER, "fail: para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    LnnMapInit(&cnnCode->connectionCode);
    return SOFTBUS_OK;
}

static void DeinitConnectionCode(ConnectionCode *cnnCode)
{
    if (cnnCode == NULL) {
        LNN_LOGE(LNN_LEDGER, "fail: para error!");
        return;
    }
    LnnMapDelete(&cnnCode->connectionCode);
    return;
}

void LnnDeinitDistributedLedger(void)
{
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail!");
        return;
    }
    g_distributedNetLedger.status = DL_INIT_UNKNOWN;
    DeinitDistributedInfo(&g_distributedNetLedger.distributedInfo);
    DeinitConnectionCode(&g_distributedNetLedger.cnnCode);
    if (SoftBusMutexUnlock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "unlock mutex fail!");
    }
    SoftBusMutexDestroy(&g_distributedNetLedger.lock);
}

static void NewWifiDiscovered(const NodeInfo *oldInfo, NodeInfo *newInfo)
{
    const char *macAddr = NULL;
    if (oldInfo == NULL || newInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error!");
        return;
    }
    newInfo->discoveryType = newInfo->discoveryType | oldInfo->discoveryType;
    macAddr = LnnGetBtMac(newInfo);
    if (macAddr == NULL) {
        LNN_LOGE(LNN_LEDGER, "LnnGetBtMac Fail!");
        return;
    }
    if (strcmp(macAddr, DEFAULT_MAC) == 0) {
        LnnSetBtMac(newInfo, LnnGetBtMac(oldInfo));
    }
}

static void NewBrBleDiscovered(const NodeInfo *oldInfo, NodeInfo *newInfo)
{
    const char *ipAddr = NULL;
    if (oldInfo == NULL || newInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error!");
        return;
    }
    newInfo->discoveryType = newInfo->discoveryType | oldInfo->discoveryType;
    ipAddr = LnnGetWiFiIp(newInfo);
    if (ipAddr == NULL) {
        LNN_LOGE(LNN_LEDGER, "LnnGetWiFiIp Fail!");
        return;
    }
    if (strcmp(ipAddr, DEFAULT_IP) == 0) {
        LnnSetWiFiIp(newInfo, LnnGetWiFiIp(oldInfo));
    }

    newInfo->connectInfo.authPort = oldInfo->connectInfo.authPort;
    newInfo->connectInfo.proxyPort = oldInfo->connectInfo.proxyPort;
    newInfo->connectInfo.sessionPort = oldInfo->connectInfo.sessionPort;
}

static void RetainOfflineCode(const NodeInfo *oldInfo, NodeInfo *newInfo)
{
    if (oldInfo == NULL || newInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error!");
        return;
    }
    // 4 represents the number of destination bytes and source bytes.
    if (memcpy_s(newInfo->offlineCode, 4, oldInfo->offlineCode, 4) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "memcpy offlineCode error!");
        return;
    }
}
static int32_t ConvertNodeInfoToBasicInfo(const NodeInfo *info, NodeBasicInfo *basic)
{
    if (info == NULL || basic == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strncpy_s(basic->deviceName, DEVICE_NAME_BUF_LEN, info->deviceInfo.deviceName,
        strlen(info->deviceInfo.deviceName)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strncpy_s name error!");
        return SOFTBUS_MEM_ERR;
    }
    if (strncpy_s(basic->networkId, NETWORK_ID_BUF_LEN, info->networkId, strlen(info->networkId)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strncpy_s networkID error!");
        return SOFTBUS_MEM_ERR;
    }
    basic->deviceTypeId = info->deviceInfo.deviceTypeId;
    return SOFTBUS_OK;
}

static bool IsMetaNode(NodeInfo *info)
{
    if (info == NULL) {
        return false;
    }
    return info->metaInfo.isMetaNode;
}

static int32_t GetDLOnlineNodeNumLocked(int32_t *infoNum, bool isNeedMeta)
{
    NodeInfo *info = NULL;
    DoubleHashMap *map = &g_distributedNetLedger.distributedInfo;
    MapIterator *it = LnnMapInitIterator(&map->udidMap);

    if (it == NULL) {
        return SOFTBUS_ERR;
    }
    *infoNum = 0;
    while (LnnMapHasNext(it)) {
        it = LnnMapNext(it);
        if (it == NULL) {
            return SOFTBUS_ERR;
        }
        info = (NodeInfo *)it->node->value;
        if (!isNeedMeta) {
            if (LnnIsNodeOnline(info)) {
                (*infoNum)++;
            }
        } else {
            if (LnnIsNodeOnline(info) || IsMetaNode(info)) {
                (*infoNum)++;
            }
        }
    }
    LnnMapDeinitIterator(it);
    return SOFTBUS_OK;
}

static int32_t FillDLOnlineNodeInfoLocked(NodeBasicInfo *info, int32_t infoNum, bool isNeedMeta)
{
    NodeInfo *nodeInfo = NULL;
    DoubleHashMap *map = &g_distributedNetLedger.distributedInfo;
    MapIterator *it = LnnMapInitIterator(&map->udidMap);
    int32_t i = 0;

    if (it == NULL) {
        LNN_LOGE(LNN_LEDGER, "it is null");
        return SOFTBUS_ERR;
    }
    while (LnnMapHasNext(it) && i < infoNum) {
        it = LnnMapNext(it);
        if (it == NULL) {
            LnnMapDeinitIterator(it);
            return SOFTBUS_ERR;
        }
        nodeInfo = (NodeInfo *)it->node->value;
        if (!isNeedMeta) {
            if (LnnIsNodeOnline(nodeInfo)) {
                ConvertNodeInfoToBasicInfo(nodeInfo, info + i);
                ++i;
            }
        } else {
            if (LnnIsNodeOnline(nodeInfo) || IsMetaNode(nodeInfo)) {
                ConvertNodeInfoToBasicInfo(nodeInfo, info + i);
                ++i;
            }
        }
    }
    LnnMapDeinitIterator(it);
    return SOFTBUS_OK;
}

static bool IsNetworkIdChanged(NodeInfo *newInfo, NodeInfo *oldInfo)
{
    if (newInfo == NULL || oldInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error!");
        return false;
    }
    if (strcmp(newInfo->networkId, oldInfo->networkId) == 0) {
        return false;
    }
    return true;
}

void PostOnlineNodesToCb(const INodeStateCb *callBack)
{
    NodeInfo *info = NULL;
    NodeBasicInfo basic;
    if (memset_s(&basic, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memset_s basic fail!");
    }
    DoubleHashMap *map = &g_distributedNetLedger.distributedInfo;
    if (callBack->onNodeOnline == NULL) {
        LNN_LOGE(LNN_LEDGER, "onNodeOnline IS null!");
        return;
    }
    MapIterator *it = LnnMapInitIterator(&map->udidMap);
    if (it == NULL) {
        return;
    }
    while (LnnMapHasNext(it)) {
        it = LnnMapNext(it);
        if (it == NULL) {
            return;
        }
        info = (NodeInfo *)it->node->value;
        if (LnnIsNodeOnline(info)) {
            ConvertNodeInfoToBasicInfo(info, &basic);
            callBack->onNodeOnline(&basic);
        }
    }
    LnnMapDeinitIterator(it);
}

NodeInfo *LnnGetNodeInfoById(const char *id, IdCategory type)
{
    NodeInfo *info = NULL;
    DoubleHashMap *map = &g_distributedNetLedger.distributedInfo;
    if (id == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return info;
    }
    if (type == CATEGORY_UDID) {
        return GetNodeInfoFromMap(map, id);
    }
    MapIterator *it = LnnMapInitIterator(&map->udidMap);
    LNN_CHECK_AND_RETURN_RET_LOGE(it != NULL, NULL, LNN_LEDGER, "LnnMapInitIterator is null");

    while (LnnMapHasNext(it)) {
        it = LnnMapNext(it);
        LNN_CHECK_AND_RETURN_RET_LOGE(it != NULL, info, LNN_LEDGER, "it next is null");
        info = (NodeInfo *)it->node->value;
        if (info == NULL) {
            continue;
        }
        if (type == CATEGORY_NETWORK_ID) {
            if (strcmp(info->networkId, id) == 0) {
                LnnMapDeinitIterator(it);
                return info;
            }
        } else if (type == CATEGORY_UUID) {
            if (strcmp(info->uuid, id) == 0) {
                LnnMapDeinitIterator(it);
                return info;
            }
        } else {
            LNN_LOGE(LNN_LEDGER, "type error");
        }
    }
    LnnMapDeinitIterator(it);
    return NULL;
}

static NodeInfo *LnnGetNodeInfoByDeviceId(const char *id)
{
    NodeInfo *info = NULL;
    DoubleHashMap *map = &g_distributedNetLedger.distributedInfo;
    NodeInfo *udidInfo = GetNodeInfoFromMap(map, id);
    if (udidInfo != NULL) {
        return udidInfo;
    }
    MapIterator *it = LnnMapInitIterator(&map->udidMap);
    if (it == NULL) {
        return info;
    }
    while (LnnMapHasNext(it)) {
        it = LnnMapNext(it);
        if (it == NULL) {
            return info;
        }
        info = (NodeInfo *)it->node->value;
        if (info == NULL) {
            continue;
        }
        if (strcmp(info->networkId, id) == 0) {
            LnnMapDeinitIterator(it);
            return info;
        }
        if (strcmp(info->uuid, id) == 0) {
            LnnMapDeinitIterator(it);
            return info;
        }
        if (StrCmpIgnoreCase(info->connectInfo.macAddr, id) == 0) {
            LnnMapDeinitIterator(it);
            return info;
        }
        if (strcmp(info->connectInfo.deviceIp, id) == 0) {
            LnnMapDeinitIterator(it);
            return info;
        }
        LNN_LOGE(LNN_LEDGER, "type error");
    }
    LnnMapDeinitIterator(it);
    return NULL;
}

int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info)
{
    if (id == NULL || info == NULL) {
        LNN_LOGE(LNN_LEDGER, "param error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(id, type);
    if (nodeInfo == NULL) {
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        char *anonyId = NULL;
        Anonymize(id, &anonyId);
        LNN_LOGI(LNN_LEDGER, "can not find target node, id=%{public}s, type=%{public}d", anonyId, type);
        AnonymizeFree(anonyId);
        return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;
    }
    if (memcpy_s(info, sizeof(NodeInfo), nodeInfo, sizeof(NodeInfo)) != EOK) {
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_MEM_ERR;
    }
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

/* key means networkId/udid/uuid/macAddr/ip */
int32_t LnnGetRemoteNodeInfoByKey(const char *key, NodeInfo *info)
{
    if (key == NULL || info == NULL) {
        LNN_LOGE(LNN_LEDGER, "param error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoByDeviceId(key);
    if (nodeInfo == NULL) {
        LNN_LOGI(LNN_LEDGER, "can not find target node");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;
    }
    if (memcpy_s(info, sizeof(NodeInfo), nodeInfo, sizeof(NodeInfo)) != EOK) {
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_MEM_ERR;
    }
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

bool LnnGetOnlineStateById(const char *id, IdCategory type)
{
    bool state = false;
    if (!IsValidString(id, ID_MAX_LEN)) {
        LNN_LOGE(LNN_LEDGER, "id is invalid");
        return state;
    }

    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail!");
        return state;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(id, type);
    if (nodeInfo == NULL) {
        LNN_LOGI(LNN_LEDGER, "can not find target node");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return state;
    }
    state = (nodeInfo->status == STATUS_ONLINE) ? true : false;
    if (!state) {
        state = nodeInfo->metaInfo.isMetaNode;
    }
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return state;
}

static int32_t DlGetDeviceUuid(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (strncpy_s((char*)buf, len, info->uuid, strlen(info->uuid)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetDeviceOfflineCode(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (memcpy_s(buf, len, info->offlineCode, OFFLINE_CODE_BYTE_SIZE) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy_s offlinecode ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetDeviceUdid(const char *networkId, void *buf, uint32_t len)
{
    const char *udid = NULL;
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    udid = LnnGetDeviceUdid(info);
    if (udid == NULL) {
        LNN_LOGE(LNN_LEDGER, "get device udid fail");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    if (strncpy_s((char*)buf, len, udid, strlen(udid)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetNodeSoftBusVersion(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (strncpy_s((char*)buf, len, info->softBusVersion, strlen(info->softBusVersion)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetDeviceType(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    char *deviceType = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    deviceType = LnnConvertIdToDeviceType(info->deviceInfo.deviceTypeId);
    if (deviceType == NULL) {
        LNN_LOGE(LNN_LEDGER, "deviceType fail.");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    if (strncpy_s((char*)buf, len, deviceType, strlen(deviceType)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "MEM COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetDeviceTypeId(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((int32_t *)buf) = info->deviceInfo.deviceTypeId;
    return SOFTBUS_OK;
}

static int32_t DlGetAuthType(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((uint32_t *)buf) = info->AuthTypeValue;
    return SOFTBUS_OK;
}

static int32_t DlGetDeviceName(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    const char *deviceName = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    deviceName = LnnGetDeviceName(&info->deviceInfo);
    if (deviceName == NULL) {
        LNN_LOGE(LNN_LEDGER, "get device name fail.");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    if (strncpy_s((char*)buf, len, deviceName, strlen(deviceName)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetBtMac(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    const char *mac = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    mac = LnnGetBtMac(info);
    if (mac == NULL) {
        LNN_LOGE(LNN_LEDGER, "get bt mac fail.");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    if (strncpy_s((char*)buf, len, mac, strlen(mac)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetWlanIp(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    const char *ip = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    ip = LnnGetWiFiIp(info);
    if (ip == NULL) {
        LNN_LOGE(LNN_LEDGER, "get wifi ip fail.");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    if (strncpy_s((char*)buf, len, ip, strlen(ip)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetMasterUdid(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    const char *masterUdid = NULL;

    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (!LnnIsNodeOnline(info)) {
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    masterUdid = LnnGetMasterUdid(info);
    if (masterUdid == NULL) {
        LNN_LOGE(LNN_LEDGER, "get master uiid fail");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    if (strncpy_s((char*)buf, len, masterUdid, strlen(masterUdid)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy master udid to buf fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetNodeBleMac(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;

    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (strlen(info->connectInfo.bleMacAddr) == 0) {
        LNN_LOGE(LNN_LEDGER, "ble mac is invalid.");
        return SOFTBUS_ERR;
    }
    if (info->bleMacRefreshSwitch != 0) {
        uint64_t currentTimeMs = GetCurrentTime();
        LNN_CHECK_AND_RETURN_RET_LOGE(info->connectInfo.latestTime + BLE_ADV_LOST_TIME >= currentTimeMs, SOFTBUS_ERR,
            LNN_LEDGER, "ble mac out date, lastAdvTime=%{public}" PRIu64 ", now=%{public}" PRIu64,
            info->connectInfo.latestTime, currentTimeMs);
    }
    if (strcpy_s((char *)buf, len, info->connectInfo.bleMacAddr) != EOK) {
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetRemotePtk(const char *networkId, void *buf, uint32_t len)
{
    if (len != PTK_DEFAULT_LEN) {
        LNN_LOGE(LNN_LEDGER, "length error");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (memcpy_s(buf, len, info->remotePtk, PTK_DEFAULT_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy remote ptk err");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetStaticCapLen(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    if (len != LNN_COMMON_LEN) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (!LnnIsNodeOnline(info)) {
        LNN_LOGE(LNN_LEDGER, "device is offline");
        return SOFTBUS_ERR;
    }
    *((int32_t *)buf) = info->staticCapLen;
    return SOFTBUS_OK;
}

static int32_t DlGetStaticCap(const char *networkId, void *buf, uint32_t len)
{
    if (len > STATIC_CAP_LEN) {
        LNN_LOGE(LNN_LEDGER, "length error");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (memcpy_s(buf, len, info->staticCapability, STATIC_CAP_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy static cap err");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

void LnnUpdateNodeBleMac(const char *networkId, char *bleMac, uint32_t len)
{
    if ((networkId == NULL) || (bleMac == NULL) || (len != MAC_LEN)) {
        LNN_LOGE(LNN_LEDGER, "invalid arg");
        return;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail!");
        return;
    }
    NodeInfo *info = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "get node info fail.");
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return;
    }
    if (memcpy_s(info->connectInfo.bleMacAddr, MAC_LEN, bleMac, len) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy fail.");
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return;
    }
    info->connectInfo.latestTime = GetCurrentTime();

    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
}

static int32_t DlGetAuthPort(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    if (len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((int32_t *)buf) = LnnGetAuthPort(info);
    return SOFTBUS_OK;
}

static int32_t DlGetSessionPort(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    if (len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((int32_t *)buf) = LnnGetSessionPort(info);
    return SOFTBUS_OK;
}

static int32_t DlGetProxyPort(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    if (len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((int32_t *)buf) = LnnGetProxyPort(info);
    return SOFTBUS_OK;
}

static int32_t DlGetNetCap(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    if (len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((int32_t *)buf) = (int32_t)info->netCapacity;
    return SOFTBUS_OK;
}

static int32_t DlGetFeatureCap(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    if (len != LNN_COMMON_LEN_64) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((uint64_t *)buf) = info->feature;
    return SOFTBUS_OK;
}

static int32_t DlGetNetType(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    if (len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((int32_t *)buf) = (int32_t)info->discoveryType;
    return SOFTBUS_OK;
}

static int32_t DlGetMasterWeight(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;

    if (len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((int32_t *)buf) = info->masterWeight;
    return SOFTBUS_OK;
}

static int32_t DlGetP2pMac(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    const char *mac = NULL;

    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if ((!LnnIsNodeOnline(info)) && (!info->metaInfo.isMetaNode)) {
        LNN_LOGE(LNN_LEDGER, "node is offline");
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    mac = LnnGetP2pMac(info);
    if (mac == NULL) {
        LNN_LOGE(LNN_LEDGER, "get p2p mac fail");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    if (strcpy_s((char*)buf, len, mac) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy p2p mac to buf fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetWifiDirectAddr(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    const char *wifiDirectAddr = NULL;

    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if ((!LnnIsNodeOnline(info)) && (!info->metaInfo.isMetaNode)) {
        LNN_LOGE(LNN_LEDGER, "node is offline");
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    wifiDirectAddr = LnnGetWifiDirectAddr(info);
    if (wifiDirectAddr == NULL) {
        LNN_LOGE(LNN_LEDGER, "get wifidirect addr fail");
        return SOFTBUS_ERR;
    }
    if (strcpy_s((char*)buf, len, wifiDirectAddr) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy wifidirect addr to buf fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetNodeAddr(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (!LnnIsNodeOnline(info)) {
        LNN_LOGE(LNN_LEDGER, "node is offline");
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    if (strcpy_s((char*)buf, len, info->nodeAddress) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy node addr to buf fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetP2pGoMac(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    const char *mac = NULL;

    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if ((!LnnIsNodeOnline(info)) && (!info->metaInfo.isMetaNode)) {
        LNN_LOGE(LNN_LEDGER, "node is offline");
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    mac = LnnGetP2pGoMac(info);
    if (mac == NULL) {
        LNN_LOGE(LNN_LEDGER, "get p2p go mac fail");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    if (strcpy_s((char*)buf, len, mac) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy p2p go mac to buf fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetWifiCfg(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    const char *wifiCfg = NULL;

    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if ((!LnnIsNodeOnline(info)) && (!info->metaInfo.isMetaNode)) {
        LNN_LOGE(LNN_LEDGER, "node is offline");
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    wifiCfg = LnnGetWifiCfg(info);
    if (wifiCfg == NULL) {
        LNN_LOGE(LNN_LEDGER, "get wifi cfg fail");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    if (strcpy_s((char*)buf, len, wifiCfg) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy wifi cfg to buf fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetChanList5g(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    const char *chanList5g = NULL;

    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if ((!LnnIsNodeOnline(info)) && (!info->metaInfo.isMetaNode)) {
        LNN_LOGE(LNN_LEDGER, "node is offline");
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    chanList5g = LnnGetChanList5g(info);
    if (chanList5g == NULL) {
        LNN_LOGE(LNN_LEDGER, "get chan list 5g fail");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    if (strcpy_s((char*)buf, len, chanList5g) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy chan list 5g to buf fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetP2pRole(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;

    if (len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if ((!LnnIsNodeOnline(info)) && (!info->metaInfo.isMetaNode)) {
        LNN_LOGE(LNN_LEDGER, "node is offline");
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    *((int32_t *)buf) = LnnGetP2pRole(info);
    return SOFTBUS_OK;
}

static int32_t DlGetStateVersion(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;

    if (len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (!LnnIsNodeOnline(info)) {
        LNN_LOGE(LNN_LEDGER, "node is offline");
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    *((int32_t *)buf) = info->stateVersion;
    return SOFTBUS_OK;
}

static int32_t DlGetStaFrequency(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;

    if (len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if ((!LnnIsNodeOnline(info)) && (!info->metaInfo.isMetaNode)) {
        LNN_LOGE(LNN_LEDGER, "node is offline");
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    *((int32_t *)buf) = LnnGetStaFrequency(info);
    return SOFTBUS_OK;
}

static int32_t DlGetNodeDataChangeFlag(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;

    if (len != DATA_CHANGE_FLAG_BUF_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (!LnnIsNodeOnline(info)) {
        LNN_LOGE(LNN_LEDGER, "node is offline");
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    *((int16_t *)buf) = (int16_t)LnnGetDataChangeFlag(info);
    return SOFTBUS_OK;
}

static int32_t DlGetNodeTlvNegoFlag(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    if (len != sizeof(bool)) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (!LnnIsNodeOnline(info) && !IsMetaNode(info)) {
        LNN_LOGE(LNN_LEDGER, "node is offline");
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    *((bool *)buf) = IsFeatureSupport(info->feature, BIT_WIFI_DIRECT_TLV_NEGOTIATION);
    return SOFTBUS_OK;
}

static int32_t DlGetAccountHash(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    if (len != SHA_256_HASH_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (!LnnIsNodeOnline(info)) {
        LNN_LOGE(LNN_LEDGER, "node is offline");
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    if (memcpy_s(buf, len, info->accountHash, SHA_256_HASH_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy account hash fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetDeviceIrk(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (memcpy_s(buf, len, info->rpaInfo.peerIrk, LFINDER_IRK_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy peerIrk fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetDevicePubMac(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (memcpy_s(buf, len, info->rpaInfo.publicAddress, LFINDER_MAC_ADDR_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy publicAddress fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetDeviceCipherInfoKey(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (memcpy_s(buf, len, info->cipherInfo.key, SESSION_KEY_LENGTH) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy cipher key fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetDeviceCipherInfoIv(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (memcpy_s(buf, len, info->cipherInfo.iv, BROADCAST_IV_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy cipher iv fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetNodeP2pIp(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (strcpy_s((char *)buf, len, info->p2pInfo.p2pIp) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy p2pIp to buf fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static DistributedLedgerKey g_dlKeyTable[] = {
    {STRING_KEY_HICE_VERSION, DlGetNodeSoftBusVersion},
    {STRING_KEY_DEV_UDID, DlGetDeviceUdid},
    {STRING_KEY_UUID, DlGetDeviceUuid},
    {STRING_KEY_DEV_TYPE, DlGetDeviceType},
    {STRING_KEY_DEV_NAME, DlGetDeviceName},
    {STRING_KEY_BT_MAC, DlGetBtMac},
    {STRING_KEY_WLAN_IP, DlGetWlanIp},
    {STRING_KEY_MASTER_NODE_UDID, DlGetMasterUdid},
    {STRING_KEY_P2P_MAC, DlGetP2pMac},
    {STRING_KEY_WIFI_CFG, DlGetWifiCfg},
    {STRING_KEY_CHAN_LIST_5G, DlGetChanList5g},
    {STRING_KEY_P2P_GO_MAC, DlGetP2pGoMac},
    {STRING_KEY_NODE_ADDR, DlGetNodeAddr},
    {STRING_KEY_OFFLINE_CODE, DlGetDeviceOfflineCode},
    {STRING_KEY_BLE_MAC, DlGetNodeBleMac},
    {STRING_KEY_WIFIDIRECT_ADDR, DlGetWifiDirectAddr},
    {STRING_KEY_P2P_IP, DlGetNodeP2pIp},
    {NUM_KEY_META_NODE, DlGetAuthType},
    {NUM_KEY_SESSION_PORT, DlGetSessionPort},
    {NUM_KEY_AUTH_PORT, DlGetAuthPort},
    {NUM_KEY_PROXY_PORT, DlGetProxyPort},
    {NUM_KEY_NET_CAP, DlGetNetCap},
    {NUM_KEY_FEATURE_CAPA, DlGetFeatureCap},
    {NUM_KEY_DISCOVERY_TYPE, DlGetNetType},
    {NUM_KEY_MASTER_NODE_WEIGHT, DlGetMasterWeight},
    {NUM_KEY_STA_FREQUENCY, DlGetStaFrequency},
    {NUM_KEY_P2P_ROLE, DlGetP2pRole},
    {NUM_KEY_STATE_VERSION, DlGetStateVersion},
    {NUM_KEY_DATA_CHANGE_FLAG, DlGetNodeDataChangeFlag},
    {NUM_KEY_DEV_TYPE_ID, DlGetDeviceTypeId},
    {NUM_KEY_STATIC_CAP_LEN, DlGetStaticCapLen},
    {BOOL_KEY_TLV_NEGOTIATION, DlGetNodeTlvNegoFlag},
    {BYTE_KEY_ACCOUNT_HASH, DlGetAccountHash},
    {BYTE_KEY_REMOTE_PTK, DlGetRemotePtk},
    {BYTE_KEY_STATIC_CAPABILITY, DlGetStaticCap},
    {BYTE_KEY_IRK, DlGetDeviceIrk},
    {BYTE_KEY_PUB_MAC, DlGetDevicePubMac},
    {BYTE_KEY_BROADCAST_CIPHER_KEY, DlGetDeviceCipherInfoKey},
    {BYTE_KEY_BROADCAST_CIPHER_IV, DlGetDeviceCipherInfoIv},
};

static char *CreateCnnCodeKey(const char *uuid, DiscoveryType type)
{
    if (uuid == NULL || strlen(uuid) >= UUID_BUF_LEN) {
        LNN_LOGE(LNN_LEDGER, "para error!");
        return NULL;
    }
    char *key = (char *)SoftBusCalloc(INT_TO_STR_SIZE + UUID_BUF_LEN);
    if (key == NULL) {
        LNN_LOGE(LNN_LEDGER, "SoftBusCalloc fail!");
        return NULL;
    }
    if (sprintf_s(key, INT_TO_STR_SIZE + UUID_BUF_LEN, "%d%s", type, uuid) == -1) {
        LNN_LOGE(LNN_LEDGER, "type convert char error!");
        goto EXIT_FAIL;
    }
    return key;
EXIT_FAIL:
    SoftBusFree(key);
    return NULL;
}

static void DestroyCnnCodeKey(char *key)
{
    if (key == NULL) {
        return;
    }
    SoftBusFree(key);
}


static int32_t AddCnnCode(Map *cnnCode, const char *uuid, DiscoveryType type, int64_t authSeqNum)
{
    short seq = (short)authSeqNum;
    char *key = CreateCnnCodeKey(uuid, type);
    if (key == NULL) {
        LNN_LOGE(LNN_LEDGER, "CreateCnnCodeKey error!");
        return SOFTBUS_ERR;
    }
    if (LnnMapSet(cnnCode, key, (void *)&seq, sizeof(short)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnMapSet error!");
        DestroyCnnCodeKey(key);
        return SOFTBUS_ERR;
    }
    DestroyCnnCodeKey(key);
    return SOFTBUS_OK;
}

static void RemoveCnnCode(Map *cnnCode, const char *uuid, DiscoveryType type)
{
    char *key = CreateCnnCodeKey(uuid, type);
    if (key == NULL) {
        LNN_LOGE(LNN_LEDGER, "CreateCnnCodeKey error!");
        return;
    }
    if (LnnMapErase(cnnCode, key) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnMapErase error!");
    }
    DestroyCnnCodeKey(key);
    return;
}

short LnnGetCnnCode(const char *uuid, DiscoveryType type)
{
    char *key = CreateCnnCodeKey(uuid, type);
    if (key == NULL) {
        LNN_LOGE(LNN_LEDGER, "CreateCnnCodeKey error!");
        return INVALID_CONNECTION_CODE_VALUE;
    }
    short *ptr = (short *)LnnMapGet(&g_distributedNetLedger.cnnCode.connectionCode, key);
    if (ptr == NULL) {
        LNN_LOGE(LNN_LEDGER, " KEY not exist.");
        DestroyCnnCodeKey(key);
        return INVALID_CONNECTION_CODE_VALUE;
    }
    DestroyCnnCodeKey(key);
    return (*ptr);
}

static void MergeLnnInfo(const NodeInfo *oldInfo, NodeInfo *info)
{
    int32_t i, j;

    for (i = 0; i < CONNECTION_ADDR_MAX; ++i) {
        info->relation[i] += oldInfo->relation[i];
        info->relation[i] &= LNN_RELATION_MASK;
        for (j = 0; j < AUTH_SIDE_MAX; ++j) {
            if (oldInfo->authChannelId[i][j] != 0 && info->authChannelId[i][j] == 0) {
                info->authChannelId[i][j] = oldInfo->authChannelId[i][j];
            }
        }
        if (oldInfo->authChannelId[i][AUTH_AS_CLIENT_SIDE] != 0 ||
            oldInfo->authChannelId[i][AUTH_AS_SERVER_SIDE] != 0 || info->authChannelId[i][AUTH_AS_CLIENT_SIDE] != 0 ||
            info->authChannelId[i][AUTH_AS_SERVER_SIDE] != 0 ) {
            LNN_LOGD(LNN_LEDGER,
                "Merge authChannelId. authChannelId:%{public}d|%{public}d->%{public}d|%{public}d, addrType=%{public}d",
                oldInfo->authChannelId[i][AUTH_AS_CLIENT_SIDE], oldInfo->authChannelId[i][AUTH_AS_SERVER_SIDE],
                info->authChannelId[i][AUTH_AS_CLIENT_SIDE], info->authChannelId[i][AUTH_AS_SERVER_SIDE], i);
        }
    }
}

int32_t LnnUpdateNetworkId(const NodeInfo *newInfo)
{
    const char *udid = NULL;
    DoubleHashMap *map = NULL;
    NodeInfo *oldInfo = NULL;

    udid = LnnGetDeviceUdid(newInfo);
    map = &g_distributedNetLedger.distributedInfo;
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }
    oldInfo = (NodeInfo *)LnnMapGet(&map->udidMap, udid);
    if (oldInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "no online node newInfo!");
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_ERR;
    }
    if (strcpy_s(oldInfo->networkId, NETWORK_ID_BUF_LEN, newInfo->networkId) != EOK) {
        LNN_LOGE(LNN_LEDGER, "networkId cpy fail");
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_OK;
    }
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

static void UpdateNewNodeAccountHash(NodeInfo *info)
{
    char accountString[LONG_TO_STRING_MAX_LEN] = {0};
    if (sprintf_s(accountString, LONG_TO_STRING_MAX_LEN, "%" PRId64, info->accountId) == -1) {
        LNN_LOGE(LNN_LEDGER, "long to string fail");
        return;
    }
    LNN_LOGD(LNN_LEDGER, "accountString=%{public}s", accountString);
    int ret = SoftBusGenerateStrHash((uint8_t *)accountString,
        strlen(accountString), (unsigned char *)info->accountHash);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "account hash fail, ret=%{public}d", ret);
        return;
    }
}

int32_t LnnUpdateNodeInfo(NodeInfo *newInfo)
{
    const char *udid = NULL;
    DoubleHashMap *map = NULL;
    NodeInfo *oldInfo = NULL;

    UpdateNewNodeAccountHash(newInfo);
    UpdateDpSameAccount(newInfo->accountHash, newInfo->deviceInfo.deviceUdid);
    udid = LnnGetDeviceUdid(newInfo);
    map = &g_distributedNetLedger.distributedInfo;
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }
    oldInfo = (NodeInfo *)LnnMapGet(&map->udidMap, udid);
    if (oldInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "no online node newInfo!");
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_ERR;
    }
    if (LnnHasDiscoveryType(newInfo, DISCOVERY_TYPE_WIFI) ||
        LnnHasDiscoveryType(newInfo, DISCOVERY_TYPE_LSA)) {
        oldInfo->discoveryType = newInfo->discoveryType | oldInfo->discoveryType;
        oldInfo->connectInfo.authPort = newInfo->connectInfo.authPort;
        oldInfo->connectInfo.proxyPort = newInfo->connectInfo.proxyPort;
        oldInfo->connectInfo.sessionPort = newInfo->connectInfo.sessionPort;
    }
    if (strcpy_s(oldInfo->deviceInfo.deviceName, DEVICE_NAME_BUF_LEN, newInfo->deviceInfo.deviceName) != 0) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s fail");
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_STRCPY_ERR;
    }
    if (memcpy_s(oldInfo->accountHash, SHA_256_HASH_LEN, newInfo->accountHash, SHA_256_HASH_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy account hash failed");
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_ERR;
    }
    oldInfo->accountId = newInfo->accountId;
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

int32_t LnnAddMetaInfo(NodeInfo *info)
{
    const char *udid = NULL;
    DoubleHashMap *map = NULL;
    NodeInfo *oldInfo = NULL;
    udid = LnnGetDeviceUdid(info);
    map = &g_distributedNetLedger.distributedInfo;
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "LnnAddMetaInfo lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }
    oldInfo = (NodeInfo *)LnnMapGet(&map->udidMap, udid);
    if (oldInfo != NULL && strcmp(oldInfo->networkId, info->networkId) == 0) {
        MetaInfo temp = info->metaInfo;
        if (memcpy_s(info, sizeof(NodeInfo), oldInfo, sizeof(NodeInfo)) != EOK) {
            LNN_LOGE(LNN_LEDGER, "LnnAddMetaInfo copy fail!");
            SoftBusMutexUnlock(&g_distributedNetLedger.lock);
            return SOFTBUS_MEM_ERR;
        }
        info->metaInfo.isMetaNode = true;
        info->metaInfo.metaDiscType = info->metaInfo.metaDiscType | temp.metaDiscType;
    }
    LnnSetAuthTypeValue(&info->AuthTypeValue, ONLINE_METANODE);
    int32_t ret = LnnMapSet(&map->udidMap, udid, info, sizeof(NodeInfo));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "lnn map set failed, ret=%{public}d", ret);
    }
    LNN_LOGI(LNN_LEDGER, "LnnAddMetaInfo success");
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

int32_t LnnDeleteMetaInfo(const char *udid, ConnectionAddrType type)
{
    NodeInfo *info = NULL;
    DiscoveryType discType = LnnConvAddrTypeToDiscType(type);
    if (discType == DISCOVERY_TYPE_COUNT) {
        LNN_LOGE(LNN_LEDGER, "DeleteMetaInfo type error fail!");
        return SOFTBUS_NETWORK_DELETE_INFO_ERR;
    }
    DoubleHashMap *map = &g_distributedNetLedger.distributedInfo;
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "DeleteAddMetaInfo lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }
    info = (NodeInfo *)LnnMapGet(&map->udidMap, udid);
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "DeleteAddMetaInfo para error!");
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_NETWORK_DELETE_INFO_ERR;
    }
    info->metaInfo.metaDiscType = (uint32_t)info->metaInfo.metaDiscType & ~(1 << (uint32_t)discType);
    if (info->metaInfo.metaDiscType == 0) {
        info->metaInfo.isMetaNode = false;
    }
    LnnClearAuthTypeValue(&info->AuthTypeValue, ONLINE_METANODE);
    int32_t ret = LnnMapSet(&map->udidMap, udid, info, sizeof(NodeInfo));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "lnn map set failed, ret=%{public}d", ret);
    }
    LNN_LOGI(LNN_LEDGER, "LnnDeleteMetaInfo success");
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

static void OnlinePreventBrConnection(const NodeInfo *info)
{
    const NodeInfo *localNodeInfo = LnnGetLocalNodeInfo();
    if (localNodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get local node info fail");
        return;
    }
    ConnectOption option;
    option.type = CONNECT_BR;
    if (strcpy_s(option.brOption.brMac, BT_MAC_LEN, info->connectInfo.macAddr) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy br mac fail");
        return;
    }

    bool preventFlag = false;
    do {
        LNN_LOGI(LNN_LEDGER, "check the ble start timestamp, local=%{public}" PRId64", peer=%{public}" PRId64"",
            localNodeInfo->bleStartTimestamp, info->bleStartTimestamp);
        if (localNodeInfo->bleStartTimestamp < info->bleStartTimestamp) {
            LNN_LOGI(LNN_LEDGER, "peer later, prevent br connection");
            preventFlag = true;
            break;
        }
        if (localNodeInfo->bleStartTimestamp > info->bleStartTimestamp) {
            LNN_LOGI(LNN_LEDGER, "local later, do not prevent br connection");
            break;
        }
        if (strcmp(info->softBusVersion, SOFTBUS_VERSION_FOR_INITCONNECTFLAG) < 0) {
            LNN_LOGI(LNN_LEDGER, "peer is old version, peerVersion=%{public}s", info->softBusVersion);
            preventFlag = true;
            break;
        }
        if (strcmp(info->networkId, localNodeInfo->networkId) <= 0) {
            LNN_LOGI(LNN_LEDGER, "peer network id is smaller");
            preventFlag = true;
            break;
        }
    } while (false);
    if (preventFlag) {
        LNN_LOGI(LNN_LEDGER, "prevent br connection for a while");
        ConnPreventConnection(&option, CONNECTION_FREEZE_TIMEOUT_MILLIS);
    }
}

static void NotifyMigrateUpgrade(NodeInfo *info)
{
    NodeBasicInfo basic;
    (void)memset_s(&basic, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    if (LnnGetBasicInfoByUdid(info->deviceInfo.deviceUdid, &basic) == SOFTBUS_OK) {
        LnnNotifyMigrate(true, &basic);
    } else {
        LNN_LOGE(LNN_LEDGER, "NotifyMigrateUpgrade, GetBasicInfoByUdid fail!");
    }
}

static void FilterWifiInfo(NodeInfo *info)
{
    (void)LnnClearDiscoveryType(info, DISCOVERY_TYPE_WIFI);
    info->authChannelId[CONNECTION_ADDR_WLAN][AUTH_AS_CLIENT_SIDE] = 0;
    info->authChannelId[CONNECTION_ADDR_WLAN][AUTH_AS_SERVER_SIDE] = 0;
}

static void FilterBrInfo(NodeInfo *info)
{
    (void)LnnClearDiscoveryType(info, DISCOVERY_TYPE_BR);
    info->authChannelId[CONNECTION_ADDR_BR][AUTH_AS_CLIENT_SIDE] = 0;
    info->authChannelId[CONNECTION_ADDR_BR][AUTH_AS_SERVER_SIDE] = 0;
}

static bool IsDeviceInfoChanged(NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGI(LNN_LEDGER, "invalid param");
        return false;
    }
    NodeInfo deviceInfo;
    if (memset_s(&deviceInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memset_s basic fail!");
        return false;
    }
    uint8_t udidHash[SHA_256_HASH_LEN] = {0};
    char hashStr[SHORT_UDID_HASH_HEX_LEN + 1] = {0};
    if (SoftBusGenerateStrHash((const unsigned char *)info->deviceInfo.deviceUdid,
        strlen(info->deviceInfo.deviceUdid), udidHash) != SOFTBUS_OK) {
        LNN_LOGI(LNN_LEDGER, "generate udidhash fail");
        return false;
    }
    if (ConvertBytesToHexString(hashStr, SHORT_UDID_HASH_HEX_LEN + 1, udidHash,
        SHORT_UDID_HASH_HEX_LEN / HEXIFY_UNIT_LEN) != SOFTBUS_OK) {
        LNN_LOGI(LNN_LEDGER, "convert udidhash to hexstr fail");
        return false;
    }
    if (LnnRetrieveDeviceInfo(hashStr, &deviceInfo) != SOFTBUS_OK) {
        LNN_LOGI(LNN_LEDGER, "get deviceInfo by udidhash fail");
        return false;
    }
    return memcmp(info, &deviceInfo, (size_t)&(((NodeInfo *)0)->relation)) != 0 ? true : false;
}

static void BleDirectlyOnlineProc(NodeInfo *info)
{
    if (!LnnHasDiscoveryType(info, DISCOVERY_TYPE_BLE)) {
        NodeInfo deviceInfo;
        if (memset_s(&deviceInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo)) != EOK) {
            LNN_LOGE(LNN_LEDGER, "memset_s basic fail!");
        }
        uint8_t udidHash[SHA_256_HASH_LEN] = {0};
        char hashStr[SHORT_UDID_HASH_HEX_LEN + 1] = {0};
        if (SoftBusGenerateStrHash((const unsigned char *)info->deviceInfo.deviceUdid,
            strlen(info->deviceInfo.deviceUdid), udidHash) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "generate udidhash fail");
            return;
        }
        if (ConvertBytesToHexString(hashStr, SHORT_UDID_HASH_HEX_LEN + 1, udidHash,
            SHORT_UDID_HASH_HEX_LEN / HEXIFY_UNIT_LEN) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "convert udidhash to hexstr fail");
            return;
        }
        if (LnnRetrieveDeviceInfo(hashStr, &deviceInfo) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "get deviceInfo by udidhash fail");
            return;
        }
        char *anonyDevNetworkId = NULL;
        char *anonyNetworkId = NULL;
        Anonymize(deviceInfo.networkId, &anonyDevNetworkId);
        Anonymize(info->networkId, &anonyNetworkId);
        LNN_LOGI(LNN_LEDGER, "oldNetworkId=%{public}s, newNetworkid=%{public}s", anonyDevNetworkId, anonyNetworkId);
        AnonymizeFree(anonyDevNetworkId);
        AnonymizeFree(anonyNetworkId);
        if (strcpy_s(deviceInfo.networkId, sizeof(deviceInfo.networkId), info->networkId) != EOK) {
            LNN_LOGE(LNN_LEDGER, "strcpy_s networkId fail");
            return;
        }
        if(LnnSaveRemoteDeviceInfo(&deviceInfo) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "save remote devInfo fail");
            return;
        }
        return;
    }
    if (LnnHasDiscoveryType(info, DISCOVERY_TYPE_WIFI)) {
        FilterWifiInfo(info);
    }
    if (LnnHasDiscoveryType(info, DISCOVERY_TYPE_BR)) {
        FilterBrInfo(info);
    }
    if (IsDeviceInfoChanged(info)) {
        if (LnnSaveRemoteDeviceInfo(info) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "save remote devInfo fail");
        }
    } else {
        LnnUpdateRemoteDeviceInfo(info);
    }
}

static void NodeOnlineProc(NodeInfo *info)
{
    NodeInfo nodeInfo;
    if (memcpy_s(&nodeInfo, sizeof(nodeInfo), info, sizeof(NodeInfo)) != EOK) {
        return;
    }
    BleDirectlyOnlineProc(&nodeInfo);
}

static void GetNodeInfoDiscovery(NodeInfo *oldInfo, NodeInfo *info, NodeInfoAbility *infoAbility)
{
    infoAbility->isOffline = true;
    infoAbility->oldWifiFlag = false;
    infoAbility->oldBrFlag = false;
    infoAbility->oldBleFlag = false;
    infoAbility->isChanged = false;
    infoAbility->isMigrateEvent = false;
    infoAbility->isNetworkChanged = false;
    infoAbility->newWifiFlag = LnnHasDiscoveryType(info, DISCOVERY_TYPE_WIFI);
    infoAbility->newBleBrFlag =
        LnnHasDiscoveryType(info, DISCOVERY_TYPE_BLE) || LnnHasDiscoveryType(info, DISCOVERY_TYPE_BR);
    if (oldInfo != NULL) {
        info->metaInfo = oldInfo->metaInfo;
    }
    if (oldInfo != NULL && LnnIsNodeOnline(oldInfo)) {
        LNN_LOGI(LNN_LEDGER, "addOnlineNode find online node");
        infoAbility->isOffline = false;
        infoAbility->isChanged = IsNetworkIdChanged(info, oldInfo);
        infoAbility->oldWifiFlag = LnnHasDiscoveryType(oldInfo, DISCOVERY_TYPE_WIFI);
        infoAbility->oldBleFlag = LnnHasDiscoveryType(oldInfo, DISCOVERY_TYPE_BLE);
        infoAbility->oldBrFlag = LnnHasDiscoveryType(oldInfo, DISCOVERY_TYPE_BR);
        if ((infoAbility->oldBleFlag || infoAbility->oldBrFlag) && infoAbility->newWifiFlag) {
            NewWifiDiscovered(oldInfo, info);
            infoAbility->isNetworkChanged = true;
        } else if (infoAbility->oldWifiFlag && infoAbility->newBleBrFlag) {
            RetainOfflineCode(oldInfo, info);
            NewBrBleDiscovered(oldInfo, info);
            infoAbility->isNetworkChanged = true;
        } else {
            RetainOfflineCode(oldInfo, info);
            LNN_LOGE(LNN_LEDGER, "flag error");
        }
        if ((infoAbility->oldBleFlag || infoAbility->oldBrFlag) && !infoAbility->oldWifiFlag &&
            infoAbility->newWifiFlag) {
            infoAbility->isMigrateEvent = true;
        }
        // update lnn discovery type
        info->discoveryType |= oldInfo->discoveryType;
        info->heartbeatTimestamp = oldInfo->heartbeatTimestamp;
        MergeLnnInfo(oldInfo, info);
        UpdateProfile(info);
    }
}

static void DfxRecordLnnAddOnlineNodeEnd(NodeInfo *info, int32_t onlineNum, int32_t reason)
{
    LnnEventExtra extra = { 0 };
    LnnEventExtraInit(&extra);
    extra.onlineNum = onlineNum;
    extra.errcode = reason;
    extra.result = (reason == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED;
    if (info == NULL) {
        LNN_EVENT(EVENT_SCENE_JOIN_LNN, EVENT_STAGE_JOIN_LNN_END, extra);
        return;
    }

    char netWorkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (strncpy_s(netWorkId, NETWORK_ID_BUF_LEN, info->networkId, NETWORK_ID_BUF_LEN - 1) == EOK) {
        extra.peerNetworkId = netWorkId;
    }
    char udidData[UDID_BUF_LEN] = { 0 };
    if (strncpy_s(udidData, UDID_BUF_LEN, info->deviceInfo.deviceUdid, UDID_BUF_LEN - 1) == EOK) {
        extra.peerUdid = udidData;
    }
    char bleMacAddr[MAC_LEN] = { 0 };
    if (strncpy_s(bleMacAddr, MAC_LEN, info->connectInfo.bleMacAddr, MAC_LEN - 1) == EOK) {
        extra.peerBleMac = bleMacAddr;
    }
    char deviceType[DEVICE_TYPE_SIZE_LEN + 1] = { 0 };
    if (snprintf_s(deviceType, DEVICE_TYPE_SIZE_LEN + 1, DEVICE_TYPE_SIZE_LEN, "%03X",
        info->deviceInfo.deviceTypeId) >= 0) {
        extra.peerDeviceType = deviceType;
    }
    LNN_EVENT(EVENT_SCENE_JOIN_LNN, EVENT_STAGE_JOIN_LNN_END, extra);
}

static void DfxRecordLnnSetNodeOfflineEnd(const char *udid, int32_t onlineNum, int32_t reason)
{
    LnnEventExtra extra = { 0 };
    LnnEventExtraInit(&extra);
    extra.onlineNum = onlineNum;
    extra.errcode = reason;
    extra.result = (reason == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED;

    char udidData[UDID_BUF_LEN] = { 0 };
    if (udid != NULL && strnlen(udid, UDID_BUF_LEN) != UDID_BUF_LEN && strncpy_s(udidData,
        UDID_BUF_LEN, udid, UDID_BUF_LEN - 1) == EOK) {
        extra.peerUdid = udidData;
    }
    LNN_EVENT(EVENT_SCENE_LEAVE_LNN, EVENT_STAGE_LEAVE_LNN, extra);
}

ReportCategory LnnAddOnlineNode(NodeInfo *info)
{
    // judge map
    info->onlinetTimestamp = LnnUpTimeMs();
    if (info == NULL) {
        return REPORT_NONE;
    }
    if (LnnHasDiscoveryType(info, DISCOVERY_TYPE_BR)) {
        LNN_LOGI(LNN_LEDGER, "DiscoveryType = BR.");
        AddCnnCode(&g_distributedNetLedger.cnnCode.connectionCode, info->uuid, DISCOVERY_TYPE_BR, info->authSeqNum);
    }

    NodeInfoAbility infoAbility;
    const char *udid = LnnGetDeviceUdid(info);
    DoubleHashMap *map = &g_distributedNetLedger.distributedInfo;
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail!");
        return REPORT_NONE;
    }
    NodeInfo *oldInfo = (NodeInfo *)LnnMapGet(&map->udidMap, udid);
    GetNodeInfoDiscovery(oldInfo, info, &infoAbility);
    LnnSetNodeConnStatus(info, STATUS_ONLINE);
    LnnSetAuthTypeValue(&info->AuthTypeValue, ONLINE_HICHAIN);
    UpdateNewNodeAccountHash(info);
    int32_t ret = LnnMapSet(&map->udidMap, udid, info, sizeof(NodeInfo));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "lnn map set failed, ret=%{public}d", ret);
    }
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    NodeOnlineProc(info);
    UpdateDpSameAccount(info->accountHash, info->deviceInfo.deviceUdid);
    if (infoAbility.isNetworkChanged) {
        UpdateNetworkInfo(info->deviceInfo.deviceUdid);
    }
    if (infoAbility.isOffline) {
        if (!infoAbility.oldWifiFlag && !infoAbility.newWifiFlag && infoAbility.newBleBrFlag) {
            OnlinePreventBrConnection(info);
        }
        InsertToProfile(info);
        DfxRecordLnnAddOnlineNodeEnd(info, (int32_t)MapGetSize(&map->udidMap), SOFTBUS_OK);
        return REPORT_ONLINE;
    }
    if (infoAbility.isMigrateEvent) {
        NotifyMigrateUpgrade(info);
    }
    if (infoAbility.isChanged) {
        return REPORT_CHANGE;
    }
    return REPORT_NONE;
}

int32_t LnnUpdateAccountInfo(const NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "info is null");
        return SOFTBUS_INVALID_PARAM;
    }
    const char *udid = NULL;
    DoubleHashMap *map = NULL;
    NodeInfo *oldInfo = NULL;
    udid = LnnGetDeviceUdid(info);

    map = &g_distributedNetLedger.distributedInfo;
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail!");
        return REPORT_NONE;
    }
    oldInfo = (NodeInfo *)LnnMapGet(&map->udidMap, udid);
    if (oldInfo != NULL) {
        oldInfo->accountId = info->accountId;
        UpdateNewNodeAccountHash(oldInfo);
    }
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

int32_t LnnUpdateGroupType(const NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "info is null");
        return SOFTBUS_INVALID_PARAM;
    }
    const char *udid = NULL;
    DoubleHashMap *map = NULL;
    NodeInfo *oldInfo = NULL;
    udid = LnnGetDeviceUdid(info);
    int32_t groupType = AuthGetGroupType(udid, info->uuid);
    LNN_LOGI(LNN_LEDGER, "groupType=%{public}d", groupType);
    int32_t ret = SOFTBUS_ERR;
    map = &g_distributedNetLedger.distributedInfo;
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }
    oldInfo = (NodeInfo *)LnnMapGet(&map->udidMap, udid);
    if (oldInfo != NULL) {
        oldInfo->groupType = groupType;
        ret = SOFTBUS_OK;
    }
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return ret;
}

static void NotifyMigrateDegrade(const char *udid)
{
    NodeBasicInfo basic;
    (void)memset_s(&basic, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    if (LnnGetBasicInfoByUdid(udid, &basic) == SOFTBUS_OK) {
        LnnNotifyMigrate(false, &basic);
    } else {
        LNN_LOGE(LNN_LEDGER, "NotifyMigrateDegrade, GetBasicInfoByUdid fail!");
    }
}

static ReportCategory ClearAuthChannelId(NodeInfo *info, ConnectionAddrType type, int32_t authId)
{
    if (LnnHasDiscoveryType(info, DISCOVERY_TYPE_WIFI) && LnnConvAddrTypeToDiscType(type) == DISCOVERY_TYPE_WIFI) {
        if (info->authChannelId[type][AUTH_AS_CLIENT_SIDE] == authId) {
            info->authChannelId[type][AUTH_AS_CLIENT_SIDE] = 0;
        }
        if (info->authChannelId[type][AUTH_AS_SERVER_SIDE] == authId) {
            info->authChannelId[type][AUTH_AS_SERVER_SIDE] = 0;
        }
        if (info->authChannelId[type][AUTH_AS_CLIENT_SIDE] != 0 ||
            info->authChannelId[type][AUTH_AS_SERVER_SIDE] != 0) {
            LNN_LOGI(LNN_LEDGER,
                "authChannelId not clear, not need to report offline. authChannelId=%{public}d|%{public}d",
                info->authChannelId[type][AUTH_AS_CLIENT_SIDE], info->authChannelId[type][AUTH_AS_SERVER_SIDE]);
            return REPORT_NONE;
        }
    }
    info->authChannelId[type][AUTH_AS_CLIENT_SIDE] = 0;
    info->authChannelId[type][AUTH_AS_SERVER_SIDE] = 0;
    return REPORT_OFFLINE;
}

static void LnnCleanNodeInfo(NodeInfo *info)
{
    LnnSetNodeConnStatus(info, STATUS_OFFLINE);
    LnnClearAuthTypeValue(&info->AuthTypeValue, ONLINE_HICHAIN);
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    LNN_LOGI(LNN_LEDGER, "need to report offline");
}

ReportCategory LnnSetNodeOffline(const char *udid, ConnectionAddrType type, int32_t authId)
{
    NodeInfo *info = NULL;
    DoubleHashMap *map = &g_distributedNetLedger.distributedInfo;
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail!");
        return REPORT_NONE;
    }
    info = (NodeInfo *)LnnMapGet(&map->udidMap, udid);
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "PARA ERROR!");
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return REPORT_NONE;
    }
    if (type != CONNECTION_ADDR_MAX && info->relation[type] > 0) {
        info->relation[type]--;
    }
    if (LnnHasDiscoveryType(info, DISCOVERY_TYPE_BR) && LnnConvAddrTypeToDiscType(type) == DISCOVERY_TYPE_BR) {
        RemoveCnnCode(&g_distributedNetLedger.cnnCode.connectionCode, info->uuid, DISCOVERY_TYPE_BR);
    }
    if (ClearAuthChannelId(info, type, authId) == REPORT_NONE) {
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return REPORT_NONE;
    }
    if (LnnConvAddrTypeToDiscType(type) == DISCOVERY_TYPE_WIFI) {
        LnnSetWiFiIp(info, LOCAL_IP);
    }
    LnnClearDiscoveryType(info, LnnConvAddrTypeToDiscType(type));
    if (info->discoveryType != 0) {
        LNN_LOGI(LNN_LEDGER, "after clear, not need to report offline. discoveryType=%{public}u", info->discoveryType);
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        UpdateNetworkInfo(udid);
        if (type == CONNECTION_ADDR_WLAN) {
            NotifyMigrateDegrade(udid);
        }
        return REPORT_NONE;
    }
    if (!LnnIsNodeOnline(info)) {
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        LNN_LOGI(LNN_LEDGER, "the state is already offline, no need to report offline");
        return REPORT_NONE;
    }
    LnnCleanNodeInfo(info);
    DfxRecordLnnSetNodeOfflineEnd(udid, (int32_t)MapGetSize(&map->udidMap), SOFTBUS_OK);
    return REPORT_OFFLINE;
}

int32_t LnnGetBasicInfoByUdid(const char *udid, NodeBasicInfo *basicInfo)
{
    if (udid == NULL || basicInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "PARA ERROR");
        return SOFTBUS_INVALID_PARAM;
    }
    DoubleHashMap *map = &g_distributedNetLedger.distributedInfo;
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *info = (NodeInfo *)LnnMapGet(&map->udidMap, udid);
    int32_t ret = ConvertNodeInfoToBasicInfo(info, basicInfo);
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return ret;
}

void LnnRemoveNode(const char *udid)
{
    DoubleHashMap *map = &g_distributedNetLedger.distributedInfo;
    if (udid == NULL) {
        return;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return;
    }
    LnnMapErase(&map->udidMap, udid);
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
}

const char *LnnConvertDLidToUdid(const char *id, IdCategory type)
{
    NodeInfo *info = NULL;
    if (id == NULL) {
        return NULL;
    }
    info = LnnGetNodeInfoById(id, type);
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "uuid not find node info.");
        return NULL;
    }
    return LnnGetDeviceUdid(info);
}

int32_t LnnConvertDlId(const char *srcId, IdCategory srcIdType, IdCategory dstIdType,
    char *dstIdBuf, uint32_t dstIdBufLen)
{
    NodeInfo *info = NULL;
    const char *id = NULL;
    int32_t rc = SOFTBUS_OK;

    if (srcId == NULL || dstIdBuf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    info = LnnGetNodeInfoById(srcId, srcIdType);
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "no node info srcIdType=%{public}d", srcIdType);
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_NOT_FIND;
    }
    switch (dstIdType) {
        case CATEGORY_UDID:
            id = info->deviceInfo.deviceUdid;
            break;
        case CATEGORY_UUID:
            id = info->uuid;
            break;
        case CATEGORY_NETWORK_ID:
            id = info->networkId;
            break;
        default:
            SoftBusMutexUnlock(&g_distributedNetLedger.lock);
            return SOFTBUS_INVALID_PARAM;
    }
    if (strcpy_s(dstIdBuf, dstIdBufLen, id) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy id fail");
        rc = SOFTBUS_MEM_ERR;
    }
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return rc;
}

int32_t LnnGetLnnRelation(const char *id, IdCategory type, uint8_t *relation, uint32_t len)
{
    NodeInfo *info = NULL;

    if (id == NULL || relation == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    info = LnnGetNodeInfoById(id, type);
    if (info == NULL || !LnnIsNodeOnline(info)) {
        LNN_LOGE(LNN_LEDGER, "node not online");
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_NOT_FIND;
    }
    if (memcpy_s(relation, len, info->relation, CONNECTION_ADDR_MAX) != EOK) {
        LNN_LOGE(LNN_LEDGER, "copy relation fail");
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_MEM_ERR;
    }
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

bool LnnSetDLDeviceInfoName(const char *udid, const char *name)
{
    DoubleHashMap *map = &g_distributedNetLedger.distributedInfo;
    NodeInfo *info = NULL;
    if (udid == NULL || name == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return false;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return false;
    }
    info = GetNodeInfoFromMap(map, udid);
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "udid not exist");
        goto EXIT;
    }
    if (strcmp(LnnGetDeviceName(&info->deviceInfo), name) == 0) {
        LNN_LOGI(LNN_LEDGER, "devicename not change");
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return true;
    }
    if (LnnSetDeviceName(&info->deviceInfo, name) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "set device name error");
        goto EXIT;
    }
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return true;
EXIT:
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return false;
}

bool LnnSetDLDeviceNickName(const char *networkId, const char *name)
{
    NodeInfo *node = NULL;
    if (networkId == NULL || name == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return false;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return false;
    }
    node = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (node == NULL) {
        LNN_LOGE(LNN_LEDGER, "networkId not found");
        goto EXIT;
    }
    if (strcpy_s(node->deviceInfo.nickName, DEVICE_NAME_BUF_LEN, name) != EOK) {
        goto EXIT;
    }
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return true;
EXIT:
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return false;
}

bool LnnSetDLP2pInfo(const char *networkId, const P2pInfo *info)
{
    NodeInfo *node = NULL;
    if (networkId == NULL || info == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return false;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return false;
    }
    node = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (node == NULL) {
        LNN_LOGE(LNN_LEDGER, "udid not found");
        goto EXIT;
    }
    if (LnnSetP2pRole(node, info->p2pRole) != SOFTBUS_OK ||
        LnnSetP2pMac(node, info->p2pMac) != SOFTBUS_OK ||
        LnnSetP2pGoMac(node, info->goMac) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "set p2p info fail");
        goto EXIT;
    }
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return true;
EXIT:
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return false;
}

bool LnnSetDlPtk(const char *networkId, const char *remotePtk)
{
    NodeInfo *node = NULL;
    if (networkId == NULL || remotePtk == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return false;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return false;
    }
    node = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (node == NULL) {
        LNN_LOGE(LNN_LEDGER, "get node info fail");
        goto EXIT;
    }
    if (LnnSetPtk(node, remotePtk) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "set ptk fail");
        goto EXIT;
    }
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return true;
EXIT:
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return false;
}

int32_t LnnGetRemoteStrInfo(const char *networkId, InfoKey key, char *info, uint32_t len)
{
    uint32_t i;
    int32_t ret;
    if (!IsValidString(networkId, ID_MAX_LEN)) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "info is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (key >= STRING_KEY_END) {
        LNN_LOGE(LNN_LEDGER, "KEY error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    for (i = 0; i < sizeof(g_dlKeyTable) / sizeof(DistributedLedgerKey); i++) {
        if (key == g_dlKeyTable[i].key) {
            if (g_dlKeyTable[i].getInfo != NULL) {
                ret = g_dlKeyTable[i].getInfo(networkId, (void *)info, len);
                SoftBusMutexUnlock(&g_distributedNetLedger.lock);
                return ret;
            }
        }
    }
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    LNN_LOGE(LNN_LEDGER, "KEY NOT exist");
    return SOFTBUS_NOT_FIND;
}

int32_t LnnGetRemoteNumInfo(const char *networkId, InfoKey key, int32_t *info)
{
    uint32_t i;
    int32_t ret;
    if (!IsValidString(networkId, ID_MAX_LEN)) {
        LNN_LOGE(LNN_LEDGER, "networkId is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "info is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (key < NUM_KEY_BEGIN || key >= NUM_KEY_END) {
        LNN_LOGE(LNN_LEDGER, "KEY error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    for (i = 0; i < sizeof(g_dlKeyTable) / sizeof(DistributedLedgerKey); i++) {
        if (key == g_dlKeyTable[i].key) {
            if (g_dlKeyTable[i].getInfo != NULL) {
                ret = g_dlKeyTable[i].getInfo(networkId, (void *)info, LNN_COMMON_LEN);
                SoftBusMutexUnlock(&g_distributedNetLedger.lock);
                return ret;
            }
        }
    }
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    LNN_LOGE(LNN_LEDGER, "KEY NOT exist");
    return SOFTBUS_NOT_FIND;
}

int32_t LnnGetRemoteNumU64Info(const char *networkId, InfoKey key, uint64_t *info)
{
    uint32_t i;
    int32_t ret;
    if (!IsValidString(networkId, ID_MAX_LEN)) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "info is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (key < NUM_KEY_BEGIN || key >= NUM_KEY_END) {
        LNN_LOGE(LNN_LEDGER, "KEY error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    for (i = 0; i < sizeof(g_dlKeyTable) / sizeof(DistributedLedgerKey); i++) {
        if (key == g_dlKeyTable[i].key) {
            if (g_dlKeyTable[i].getInfo != NULL) {
                ret = g_dlKeyTable[i].getInfo(networkId, (void *)info, LNN_COMMON_LEN_64);
                SoftBusMutexUnlock(&g_distributedNetLedger.lock);
                return ret;
            }
        }
    }
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    LNN_LOGE(LNN_LEDGER, "KEY NOT exist");
    return SOFTBUS_NOT_FIND;
}

int32_t LnnGetRemoteNum16Info(const char *networkId, InfoKey key, int16_t *info)
{
    uint32_t i;
    int32_t ret;
    if (!IsValidString(networkId, ID_MAX_LEN)) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "info is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (key < NUM_KEY_BEGIN || key >= NUM_KEY_END) {
        LNN_LOGE(LNN_LEDGER, "KEY error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    for (i = 0; i < sizeof(g_dlKeyTable) / sizeof(DistributedLedgerKey); i++) {
        if (key == g_dlKeyTable[i].key) {
            if (g_dlKeyTable[i].getInfo != NULL) {
                ret = g_dlKeyTable[i].getInfo(networkId, (void *)info, sizeof(int16_t));
                SoftBusMutexUnlock(&g_distributedNetLedger.lock);
                return ret;
            }
        }
    }
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    LNN_LOGE(LNN_LEDGER, "KEY NOT exist");
    return SOFTBUS_NOT_FIND;
}

int32_t LnnGetRemoteBoolInfo(const char *networkId, InfoKey key, bool *info)
{
    uint32_t i;
    int32_t ret;
    if (!IsValidString(networkId, ID_MAX_LEN)) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "info is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (key < BOOL_KEY_BEGIN || key >= BOOL_KEY_END) {
        LNN_LOGE(LNN_LEDGER, "KEY error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    for (i = 0; i < sizeof(g_dlKeyTable) / sizeof(DistributedLedgerKey); i++) {
        if (key == g_dlKeyTable[i].key) {
            if (g_dlKeyTable[i].getInfo != NULL) {
                ret = g_dlKeyTable[i].getInfo(networkId, (void *)info, sizeof(bool));
                SoftBusMutexUnlock(&g_distributedNetLedger.lock);
                return ret;
            }
        }
    }
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    LNN_LOGE(LNN_LEDGER, "KEY NOT exist");
    return SOFTBUS_NOT_FIND;
}

int32_t LnnGetRemoteByteInfo(const char *networkId, InfoKey key, uint8_t *info, uint32_t len)
{
    uint32_t i;
    int32_t ret;
    if (!IsValidString(networkId, ID_MAX_LEN)) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (key < BYTE_KEY_BEGIN || key >= BYTE_KEY_END) {
        LNN_LOGE(LNN_LEDGER, "KEY error.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }
    for (i = 0; i < sizeof(g_dlKeyTable) / sizeof(DistributedLedgerKey); i++) {
        if (key == g_dlKeyTable[i].key) {
            if (g_dlKeyTable[i].getInfo != NULL) {
                ret = g_dlKeyTable[i].getInfo(networkId, info, len);
                SoftBusMutexUnlock(&g_distributedNetLedger.lock);
                return ret;
            }
        }
    }
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    LNN_LOGE(LNN_LEDGER, "KEY NOT exist.");
    return SOFTBUS_NOT_FIND;
}

static int32_t GetAllOnlineAndMetaNodeInfo(NodeBasicInfo **info, int32_t *infoNum, bool isNeedMeta)
{
    if (info == NULL || infoNum == NULL) {
        LNN_LOGE(LNN_LEDGER, "key params are null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }
    int32_t ret = SOFTBUS_ERR;
    do {
        *info = NULL;
        if (GetDLOnlineNodeNumLocked(infoNum, isNeedMeta) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "get online node num failed");
            break;
        }
        if (*infoNum == 0) {
            ret = SOFTBUS_OK;
            break;
        }
        *info = (NodeBasicInfo*)SoftBusMalloc((*infoNum) * sizeof(NodeBasicInfo));
        if (*info == NULL) {
            LNN_LOGE(LNN_LEDGER, "malloc node info buffer failed");
            break;
        }
        if (FillDLOnlineNodeInfoLocked(*info, *infoNum, isNeedMeta) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "fill online node num failed");
            break;
        }
        ret = SOFTBUS_OK;
    } while (false);
    if (ret != SOFTBUS_OK) {
        if (*info != NULL) {
            SoftBusFree(*info);
            *info = NULL;
        }
        *infoNum = 0;
    }
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return ret;
}

bool LnnIsLSANode(const NodeBasicInfo *info)
{
    NodeInfo *nodeInfo = LnnGetNodeInfoById(info->networkId, CATEGORY_NETWORK_ID);
    if (nodeInfo != NULL && LnnHasDiscoveryType(nodeInfo, DISCOVERY_TYPE_LSA)) {
        return true;
    }
    return false;
}

int32_t LnnGetAllOnlineNodeNum(int32_t *nodeNum)
{
    if (nodeNum == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    /* node num include meta node */
    if (GetDLOnlineNodeNumLocked(nodeNum, true) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get online node num failed");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_NOT_FIND;
    }
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

int32_t LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    return GetAllOnlineAndMetaNodeInfo(info, infoNum, false);
}

int32_t LnnGetAllOnlineAndMetaNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    return GetAllOnlineAndMetaNodeInfo(info, infoNum, true);
}

int32_t LnnGetNetworkIdByBtMac(const char *btMac, char *buf, uint32_t len)
{
    if (btMac == NULL || btMac[0] == '\0' || buf == NULL) {
        LNN_LOGE(LNN_LEDGER, "btMac is empty");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    MapIterator *it = LnnMapInitIterator(&g_distributedNetLedger.distributedInfo.udidMap);
    if (it == NULL) {
        LNN_LOGE(LNN_LEDGER, "it is null");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_ERR;
    }
    while (LnnMapHasNext(it)) {
        it = LnnMapNext(it);
        if (it == NULL) {
            (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
            return SOFTBUS_ERR;
        }
        NodeInfo *nodeInfo = (NodeInfo *)it->node->value;
        if ((LnnIsNodeOnline(nodeInfo) || nodeInfo->metaInfo.isMetaNode) &&
            StrCmpIgnoreCase(nodeInfo->connectInfo.macAddr, btMac) == 0) {
            if (strcpy_s(buf, len, nodeInfo->networkId) != EOK) {
                LNN_LOGE(LNN_LEDGER, "strcpy_s networkId fail");
                LnnMapDeinitIterator(it);
                (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
                return SOFTBUS_MEM_ERR;
            }
            LnnMapDeinitIterator(it);
            (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
            return SOFTBUS_OK;
        }
    }
    LnnMapDeinitIterator(it);
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_NOT_FIND;
}

int32_t LnnGetNetworkIdByUdidHash(const uint8_t *udidHash, uint32_t udidHashLen, char *buf, uint32_t len)
{
    if (udidHash == NULL || buf == NULL || udidHashLen == 0) {
        LNN_LOGE(LNN_LEDGER, "udidHash is empty");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    MapIterator *it = LnnMapInitIterator(&g_distributedNetLedger.distributedInfo.udidMap);
    if (it == NULL) {
        LNN_LOGE(LNN_LEDGER, "it is null");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_ERR;
    }
    uint8_t nodeUdidHash[SHA_256_HASH_LEN] = {0};
    while (LnnMapHasNext(it)) {
        it = LnnMapNext(it);
        if (it == NULL) {
            (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
            return SOFTBUS_ERR;
        }
        NodeInfo *nodeInfo = (NodeInfo *)it->node->value;
        if (LnnIsNodeOnline(nodeInfo) || nodeInfo->metaInfo.isMetaNode) {
            if (SoftBusGenerateStrHash((uint8_t*)nodeInfo->deviceInfo.deviceUdid,
                strlen(nodeInfo->deviceInfo.deviceUdid), nodeUdidHash) != SOFTBUS_OK) {
                continue;
            }
            if (memcmp(nodeUdidHash, udidHash, SHA_256_HASH_LEN) != 0) {
                continue;
            }
            if (strcpy_s(buf, len, nodeInfo->networkId) != EOK) {
                LNN_LOGE(LNN_LEDGER, "strcpy_s networkId fail");
                LnnMapDeinitIterator(it);
                (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
                return SOFTBUS_MEM_ERR;
            }
            LnnMapDeinitIterator(it);
            (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
            return SOFTBUS_OK;
        }
    }
    LnnMapDeinitIterator(it);
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_NOT_FIND;
}

int32_t LnnGetConnSubFeatureByUdidHashStr(const char *udidHashStr, uint64_t *connSubFeature)
{
    if (udidHashStr == NULL || udidHashStr[0] == '\0' || connSubFeature == NULL) {
        LNN_LOGE(LNN_LEDGER, "para is empty");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    MapIterator *it = LnnMapInitIterator(&g_distributedNetLedger.distributedInfo.udidMap);
    if (it == NULL) {
        LNN_LOGE(LNN_LEDGER, "it is null");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_ERR;
    }
    unsigned char shortUdidHashStr[SHORT_UDID_HASH_HEX_LEN + 1] = {0};
    while (LnnMapHasNext(it)) {
        it = LnnMapNext(it);
        if (it == NULL) {
            (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
            return SOFTBUS_ERR;
        }
        NodeInfo *nodeInfo = (NodeInfo *)it->node->value;
        if (LnnIsNodeOnline(nodeInfo)) {
            if (GenerateStrHashAndConvertToHexString((const unsigned char *)nodeInfo->deviceInfo.deviceUdid,
                SHORT_UDID_HASH_HEX_LEN, shortUdidHashStr, SHORT_UDID_HASH_HEX_LEN + 1) != SOFTBUS_OK) {
                continue;
            }
            if (memcmp(shortUdidHashStr, udidHashStr, SHORT_UDID_HASH_HEX_LEN) != 0) {
                continue;
            }
            *connSubFeature = nodeInfo->connSubFeature;
            LnnMapDeinitIterator(it);
            (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
            return SOFTBUS_OK;
        }
    }
    LnnMapDeinitIterator(it);
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_NOT_FIND;
}

int32_t LnnGetNetworkIdByUuid(const char *uuid, char *buf, uint32_t len)
{
    if (!IsValidString(uuid, ID_MAX_LEN)) {
        LNN_LOGE(LNN_LEDGER, "uuid is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(uuid, CATEGORY_UUID);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_NOT_FIND;
    }
    if (strncpy_s(buf, len, nodeInfo->networkId, strlen(nodeInfo->networkId)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_MEM_ERR;
    }
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

int32_t LnnGetNetworkIdByUdid(const char *udid, char *buf, uint32_t len)
{
    if (!IsValidString(udid, ID_MAX_LEN)) {
        LNN_LOGE(LNN_LEDGER, "udid is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(udid, CATEGORY_UDID);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_NOT_FIND;
    }
    if (strncpy_s(buf, len, nodeInfo->networkId, strlen(nodeInfo->networkId)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_MEM_ERR;
    }
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

int32_t LnnGetDLOnlineTimestamp(const char *networkId, uint64_t *timestamp)
{
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_NOT_FIND;
    }
    *timestamp = nodeInfo->onlinetTimestamp;
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

int32_t LnnGetDLHeartbeatTimestamp(const char *networkId, uint64_t *timestamp)
{
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_NOT_FIND;
    }
    *timestamp = nodeInfo->heartbeatTimestamp;
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

int32_t LnnSetDLHeartbeatTimestamp(const char *networkId, uint64_t timestamp)
{
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_NOT_FIND;
    }
    nodeInfo->heartbeatTimestamp = timestamp;
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

int32_t LnnGetDLBleDirectTimestamp(const char *networkId, uint64_t *timestamp)
{
    if (networkId == NULL || timestamp == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_NOT_FIND;
    }
    *timestamp = nodeInfo->bleDirectTimestamp;
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

int32_t LnnSetDLBleDirectTimestamp(const char *networkId, uint64_t timestamp)
{
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_NOT_FIND;
    }
    nodeInfo->bleDirectTimestamp = timestamp;
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

int32_t LnnSetDLConnCapability(const char *networkId, uint32_t connCapability)
{
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_NOT_FIND;
    }
    nodeInfo->netCapacity = connCapability;
    if (LnnSaveRemoteDeviceInfo(nodeInfo) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        LNN_LOGE(LNN_LEDGER, "save remote netCapacity fail");
        return SOFTBUS_ERR;
    }
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

int32_t LnnSetDLBatteryInfo(const char *networkId, const BatteryInfo *info)
{
    if (networkId == NULL || info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_NOT_FIND;
    }
    nodeInfo->batteryInfo.batteryLevel = info->batteryLevel;
    nodeInfo->batteryInfo.isCharging = info->isCharging;
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

int32_t LnnSetDLBssTransInfo(const char *networkId, const BssTransInfo *info)
{
    if (networkId == NULL || info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_NOT_FIND;
    }
    if (memcpy_s(&(nodeInfo->bssTransInfo), sizeof(BssTransInfo), info,
        sizeof(BssTransInfo)) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_MEM_ERR;
    }
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

int32_t LnnSetDLNodeAddr(const char *id, IdCategory type, const char *addr)
{
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(id, type);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_NOT_FIND;
    }
    int ret = strcpy_s(nodeInfo->nodeAddress, sizeof(nodeInfo->nodeAddress), addr);
    if (ret != EOK) {
        LNN_LOGE(LNN_LEDGER, "set node addr failed! ret=%{public}d", ret);
    }
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return ret == EOK ? SOFTBUS_OK : SOFTBUS_ERR;
}

int32_t LnnSetDLProxyPort(const char *id, IdCategory type, int32_t proxyPort)
{
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(id, type);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_NOT_FIND;
    }
    nodeInfo->connectInfo.proxyPort = proxyPort;
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

int32_t LnnSetDLSessionPort(const char *id, IdCategory type, int32_t sessionPort)
{
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(id, type);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_NOT_FIND;
    }
    nodeInfo->connectInfo.sessionPort = sessionPort;
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

int32_t LnnSetDLAuthPort(const char *id, IdCategory type, int32_t authPort)
{
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(id, type);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_NOT_FIND;
    }
    nodeInfo->connectInfo.authPort = authPort;
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

int32_t LnnSetDLP2pIp(const char *id, IdCategory type, const char *p2pIp)
{
    if (id == NULL || p2pIp == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(id, type);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "get info fail");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_NOT_FIND;
    }
    if (strcpy_s(nodeInfo->p2pInfo.p2pIp, sizeof(nodeInfo->p2pInfo.p2pIp), p2pIp) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_MEM_ERR;
    }
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

int32_t SoftBusDumpBusCenterRemoteDeviceInfo(int32_t fd)
{
    SOFTBUS_DPRINTF(fd, "-----RemoteDeviceInfo-----\n");
    NodeBasicInfo *remoteNodeInfo = NULL;
    int32_t infoNum = 0;
    if (LnnGetAllOnlineNodeInfo(&remoteNodeInfo, &infoNum) != 0) {
        LNN_LOGE(LNN_LEDGER, "LnnGetAllOnlineNodeInfo failed");
        return SOFTBUS_ERR;
    }
    SOFTBUS_DPRINTF(fd, "remote device num = %d\n", infoNum);
    for (int32_t i = 0; i < infoNum; i++) {
        SOFTBUS_DPRINTF(fd, "\n[NO.%d]\n", i + 1);
        SoftBusDumpBusCenterPrintInfo(fd, remoteNodeInfo + i);
    }
    return SOFTBUS_OK;
}

int32_t LnnInitDistributedLedger(void)
{
    if (g_distributedNetLedger.status == DL_INIT_SUCCESS) {
        LNN_LOGI(LNN_LEDGER, "Distributed Ledger already init");
        return SOFTBUS_OK;
    }

    if (InitDistributedInfo(&g_distributedNetLedger.distributedInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "InitDistributedInfo ERROR");
        g_distributedNetLedger.status = DL_INIT_FAIL;
        return SOFTBUS_ERR;
    }

    if (InitConnectionCode(&g_distributedNetLedger.cnnCode) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "InitConnectionCode ERROR");
        g_distributedNetLedger.status = DL_INIT_FAIL;
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexInit(&g_distributedNetLedger.lock, NULL) != SOFTBUS_OK) {
        g_distributedNetLedger.status = DL_INIT_FAIL;
        return SOFTBUS_ERR;
    }
    if (SoftBusRegBusCenterVarDump((char*)SOFTBUS_BUSCENTER_DUMP_REMOTEDEVICEINFO,
        &SoftBusDumpBusCenterRemoteDeviceInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "SoftBusRegBusCenterVarDump regist fail");
        return SOFTBUS_ERR;
    }
    g_distributedNetLedger.status = DL_INIT_SUCCESS;
    return SOFTBUS_OK;
}

const NodeInfo *LnnGetOnlineNodeByUdidHash(const char *recvUdidHash)
{
    int32_t i;
    int32_t infoNum = 0;
    NodeBasicInfo *info = NULL;
    unsigned char shortUdidHash[SHORT_UDID_HASH_LEN + 1] = {0};

    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get all online node info fail");
        return NULL;
    }
    if (info == NULL || infoNum == 0) {
        if (info != NULL) {
            SoftBusFree(info);
        }
        return NULL;
    }
    for (i = 0; i < infoNum; ++i) {
        const NodeInfo *nodeInfo = LnnGetNodeInfoById(info[i].networkId, CATEGORY_NETWORK_ID);
        if (nodeInfo == NULL) {
            LNN_LOGI(LNN_LEDGER, "nodeInfo is null");
            continue;
        }
        if (GenerateStrHashAndConvertToHexString((const unsigned char *)nodeInfo->deviceInfo.deviceUdid,
            SHORT_UDID_HASH_LEN, shortUdidHash, SHORT_UDID_HASH_LEN + 1) != SOFTBUS_OK) {
            continue;
        }
        if (memcmp(shortUdidHash, recvUdidHash, SHORT_UDID_HASH_LEN) == 0) {
            char *anoyUdid = NULL;
            char *anoyUdidHash = NULL;
            Anonymize(nodeInfo->deviceInfo.deviceUdid, &anoyUdid);
            Anonymize((const char *)shortUdidHash, &anoyUdidHash);
            LNN_LOGI(LNN_LEDGER, "node is online. nodeUdid=%{public}s, shortUdidHash=%{public}s",
                anoyUdid, anoyUdidHash);
            AnonymizeFree(anoyUdid);
            AnonymizeFree(anoyUdidHash);
            SoftBusFree(info);
            return nodeInfo;
        }
    }
    SoftBusFree(info);
    return NULL;
}

static void RefreshDeviceOnlineStateInfo(DeviceInfo *device, const InnerDeviceInfoAddtions *addtions)
{
    if (addtions->medium == COAP || addtions->medium == BLE) {
        device->isOnline = ((LnnGetOnlineNodeByUdidHash(device->devId)) != NULL) ? true : false;
    }
}

void LnnRefreshDeviceOnlineStateAndDevIdInfo(const char *pkgName, DeviceInfo *device,
    const InnerDeviceInfoAddtions *addtions)
{
    (void)pkgName;
    RefreshDeviceOnlineStateInfo(device, addtions);
    if (device->devId[0] != '\0') {
        LNN_LOGI(LNN_LEDGER, "device found. medium=%{public}d, udidhash=%{public}s, onlineStatus=%{public}d",
            addtions->medium, device->devId, device->isOnline);
    }
}

bool LnnSetDLWifiDirectAddr(const char *networkId, const char *addr)
{
    NodeInfo *node = NULL;
    if (networkId == NULL || addr == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return false;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "lock mutex fail");
        return false;
    }
    node = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (node == NULL) {
        LNN_LOGE(LNN_LEDGER, "udid not found");
        goto EXIT;
    }
    if (LnnSetWifiDirectAddr(node, addr) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "set wifidirect addr fail");
        goto EXIT;
    }
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return true;
EXIT:
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return false;
}