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

#include "bus_center_event.h"
#include "lnn_map.h"
#include "softbus_bus_center.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"
#include "softbus_utils.h"

#define NUM_BUF_SIZE 4
#define RETURN_IF_GET_NODE_VALID(networkId, buf, info) do {                 \
        if ((networkId) == NULL || (buf) == NULL) {                        \
            return SOFTBUS_INVALID_PARAM;                               \
        }                                                               \
        (info) = LnnGetNodeInfoById((networkId), (CATEGORY_NETWORK_ID)); \
        if ((info) == NULL) {                                           \
            LOG_ERR("get node info fail.");                             \
            return SOFTBUS_ERR;                                         \
        }                                                               \
    } while (0)                                                        \

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
    int countMax;
    pthread_mutex_t lock;
    DistributedLedgerStatus status;
} DistributedNetLedger;

static DistributedNetLedger g_distributedNetLedger;

static NodeInfo *GetNodeInfoFromMap(const DoubleHashMap *map, const char *id)
{
    if (map == NULL || id == NULL) {
        LOG_ERR("para error!");
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
    LOG_ERR("id not exist!");
    return NULL;
}

static int32_t InitDistributedInfo(DoubleHashMap *map)
{
    if (map == NULL) {
        LOG_ERR("fail:para error!");
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
        LOG_ERR("fail: para error!");
        return;
    }
    LnnMapDelete(&map->udidMap);
    LnnMapDelete(&map->ipMap);
    LnnMapDelete(&map->macMap);
}

static int32_t InitConnectionCode(ConnectionCode *cnnCode)
{
    if (cnnCode == NULL) {
        LOG_ERR("fail: para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    LnnMapInit(&cnnCode->connectionCode);
    return SOFTBUS_OK;
}

static void DeinitConnectionCode(ConnectionCode *cnnCode)
{
    if (cnnCode == NULL) {
        LOG_ERR("fail: para error!");
        return;
    }
    LnnMapDelete(&cnnCode->connectionCode);
    return;
}

int32_t LnnInitDistributedLedger(void)
{
    if (g_distributedNetLedger.status == DL_INIT_SUCCESS) {
        LOG_INFO("Distributed Ledger already init");
        return SOFTBUS_OK;
    }

    if (InitDistributedInfo(&g_distributedNetLedger.distributedInfo) != SOFTBUS_OK) {
        LOG_ERR("InitDistributedInfo ERROR!");
        g_distributedNetLedger.status = DL_INIT_FAIL;
        return SOFTBUS_ERR;
    }

    if (InitConnectionCode(&g_distributedNetLedger.cnnCode) != SOFTBUS_OK) {
        LOG_ERR("InitConnectionCode ERROR!");
        g_distributedNetLedger.status = DL_INIT_FAIL;
        return SOFTBUS_ERR;
    }

    if (pthread_mutex_init(&g_distributedNetLedger.lock, NULL) != 0) {
        g_distributedNetLedger.status = DL_INIT_FAIL;
        return SOFTBUS_ERR;
    }
    g_distributedNetLedger.status = DL_INIT_SUCCESS;
    return SOFTBUS_OK;
}

void LnnDeinitDistributedLedger(void)
{
    if (pthread_mutex_lock(&g_distributedNetLedger.lock) != 0) {
        LOG_ERR("lock mutex fail!");
        return;
    }
    g_distributedNetLedger.status = DL_INIT_UNKNOWN;
    DeinitDistributedInfo(&g_distributedNetLedger.distributedInfo);
    DeinitConnectionCode(&g_distributedNetLedger.cnnCode);
    if (pthread_mutex_unlock(&g_distributedNetLedger.lock) != 0) {
        LOG_ERR("unlock mutex fail!");
    }
    pthread_mutex_destroy(&g_distributedNetLedger.lock);
}

static void NewWifiDiscovered(const NodeInfo *oldInfo, NodeInfo *newInfo)
{
    const char *macAddr = NULL;
    if (oldInfo == NULL || newInfo == NULL) {
        LOG_ERR("para error!");
        return;
    }
    newInfo->discoveryType = newInfo->discoveryType | oldInfo->discoveryType;
    macAddr = LnnGetBtMac(newInfo);
    if (macAddr == NULL) {
        LOG_ERR("LnnGetBtMac Fail!");
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
        LOG_ERR("para error!");
        return;
    }
    newInfo->discoveryType = newInfo->discoveryType | oldInfo->discoveryType;
    ipAddr = LnnGetWiFiIp(newInfo);
    if (ipAddr == NULL) {
        LOG_ERR("LnnGetWiFiIp Fail!");
        return;
    }
    if (strcmp(ipAddr, DEFAULT_IP) == 0) {
        LnnSetWiFiIp(newInfo, LnnGetWiFiIp(oldInfo));
    }
}

static int32_t ConvertNodeInfoToBasicInfo(const NodeInfo *info, NodeBasicInfo *basic)
{
    if (info == NULL || basic == NULL) {
        LOG_ERR("para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strncpy_s(basic->deviceName, DEVICE_NAME_BUF_LEN, info->deviceInfo.deviceName,
        strlen(info->deviceInfo.deviceName)) != EOK) {
            LOG_ERR("strncpy_s name error!");
            return SOFTBUS_MEM_ERR;
    }

    if (strncpy_s(basic->networkId, NETWORK_ID_BUF_LEN, info->networkId, strlen(info->networkId)) != EOK) {
            LOG_ERR("strncpy_s networkID error!");
            return SOFTBUS_MEM_ERR;
    }
    basic->deviceTypeId = info->deviceInfo.deviceTypeId;
    return SOFTBUS_OK;
}

static int32_t GetDLOnlineNodeNumLocked(int32_t *infoNum)
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
        if (LnnIsNodeOnline(info)) {
            (*infoNum)++;
        }
    }
    LnnMapDeinitIterator(it);
    return SOFTBUS_OK;
}

static int32_t FillDLOnlineNodeInfoLocked(NodeBasicInfo **info, int32_t infoNum)
{
    NodeInfo *nodeInfo = NULL;
    DoubleHashMap *map = &g_distributedNetLedger.distributedInfo;
    MapIterator *it = LnnMapInitIterator(&map->udidMap);
    int32_t i = 0;

    if (it == NULL) {
        LOG_ERR("it is null");
        return SOFTBUS_ERR;
    }
    while (LnnMapHasNext(it) && i < infoNum) {
        it = LnnMapNext(it);
        if (it == NULL) {
            LnnMapDeinitIterator(it);
            return SOFTBUS_ERR;
        }
        nodeInfo = (NodeInfo *)it->node->value;
        if (LnnIsNodeOnline(nodeInfo)) {
            ConvertNodeInfoToBasicInfo(nodeInfo, info[i++]);
        }
    }
    LnnMapDeinitIterator(it);
    return SOFTBUS_OK;
}

static int32_t PostDeviceBasicInfoChanged(const NodeInfo *info, NodeBasicInfoType type)
{
    NodeBasicInfo basic;
    if (memset_s(&basic, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo)) != EOK) {
        LOG_ERR("memset_s basic fail!");
    }
    if (info == NULL) {
        LOG_ERR("para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (ConvertNodeInfoToBasicInfo(info, &basic) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    LnnNotifyBasicInfoChanged(&basic, type);
    return SOFTBUS_OK;
}

static int32_t PostOnline(NodeBasicInfo *basic)
{
    if (basic == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    LnnNotifyOnlineState(true, basic);
    return SOFTBUS_OK;
}

static int32_t PostOffline(NodeBasicInfo *basic)
{
    if (basic == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    LnnNotifyOnlineState(false, basic);
    return SOFTBUS_OK;
}

static int32_t PostToClient(const NodeInfo *info, ConnectStatus status)
{
    NodeBasicInfo basic;
    if (memset_s(&basic, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo)) != EOK) {
        LOG_ERR("memset_s basic fail!");
    }
    if (info == NULL) {
        LOG_ERR("para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (ConvertNodeInfoToBasicInfo(info, &basic) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (status == STATUS_ONLINE) {
        PostOnline(&basic);
    } else if (status == STATUS_OFFLINE) {
        PostOffline(&basic);
    } else {
        LOG_ERR("status error!");
    }

    return SOFTBUS_OK;
}

static bool IsNetworkIdChanged(NodeInfo *newInfo, NodeInfo *oldInfo)
{
    if (newInfo == NULL || oldInfo == NULL) {
        LOG_ERR("para error!");
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
        LOG_ERR("memset_s basic fail!");
    }
    DoubleHashMap *map = &g_distributedNetLedger.distributedInfo;
    if (callBack->onNodeOnline == NULL) {
        LOG_ERR("onNodeOnline IS null!");
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
        LOG_ERR("para error");
        return info;
    }
    if (type == CATEGORY_UDID) {
        return GetNodeInfoFromMap(map, id);
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
            LOG_ERR("type error");
        }
    }
    LnnMapDeinitIterator(it);
    return NULL;
}

static int32_t DlGetDeviceUuid(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (strncpy_s(buf, len, info->uuid, strlen(info->uuid)) != EOK) {
        LOG_ERR("STR COPY ERROR!");
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
        LOG_ERR("get device udid fail");
        return SOFTBUS_ERR;
    }
    if (strncpy_s(buf, len, udid, strlen(udid)) != EOK) {
        LOG_ERR("STR COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetNodeSoftBusVersion(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (strncpy_s(buf, len, info->softBusVersion, strlen(info->softBusVersion)) != EOK) {
        LOG_ERR("STR COPY ERROR!");
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
        LOG_ERR("deviceType fail.");
        return SOFTBUS_ERR;
    }
    if (strncpy_s(buf, len, deviceType, strlen(deviceType)) != EOK) {
        LOG_ERR("MEM COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetDeviceName(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    const char *deviceName = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    deviceName = LnnGetDeviceName(&info->deviceInfo);
    if (deviceName == NULL) {
        LOG_ERR("get device name fail.");
        return SOFTBUS_ERR;
    }
    if (strncpy_s(buf, len, deviceName, strlen(deviceName)) != EOK) {
        LOG_ERR("STR COPY ERROR!");
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
        LOG_ERR("get bt mac fail.");
        return SOFTBUS_ERR;
    }
    if (strncpy_s(buf, len, mac, strlen(mac)) != EOK) {
        LOG_ERR("STR COPY ERROR!");
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
        LOG_ERR("get wifi ip fail.");
        return SOFTBUS_ERR;
    }
    if (strncpy_s(buf, len, ip, strlen(ip)) != EOK) {
        LOG_ERR("STR COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetAuthPort(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    if (len != NUM_BUF_SIZE) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((int32_t *)buf) = LnnGetAuthPort(info);
    return SOFTBUS_OK;
}

static int32_t DlGetSessionPort(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    if (len != NUM_BUF_SIZE) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((int32_t *)buf) = LnnGetSessionPort(info);
    return SOFTBUS_OK;
}

static int32_t DlGetProxyPort(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    if (len != NUM_BUF_SIZE) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((int32_t *)buf) = LnnGetProxyPort(info);
    return SOFTBUS_OK;
}

static int32_t DlGetNetCap(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    if (len != NUM_BUF_SIZE) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((int32_t *)buf) = info->netCapacity;
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
    {NUM_KEY_SESSION_PORT, DlGetSessionPort},
    {NUM_KEY_AUTH_PORT, DlGetAuthPort},
    {NUM_KEY_PROXY_PORT, DlGetProxyPort},
    {NUM_KEY_NET_CAP, DlGetNetCap},
};

static char *CreateCnnCodeKey(const char *uuid, DiscoveryType type)
{
    if (uuid == NULL || strlen(uuid) >= UUID_BUF_LEN) {
        LOG_ERR("para error!");
        return NULL;
    }
    char *key = (char *)SoftBusCalloc(INT_TO_STR_SIZE + UUID_BUF_LEN);
    if (key == NULL) {
        LOG_ERR("SoftBusCalloc fail!");
        return NULL;
    }
    if (sprintf_s(key, INT_TO_STR_SIZE + UUID_BUF_LEN, "%d%s", type, uuid) == -1) {
        LOG_ERR("type convert char error!");
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
        LOG_ERR("CreateCnnCodeKey error!");
        return SOFTBUS_ERR;
    }
    if (LnnMapSet(cnnCode, key, (void *)&seq, sizeof(short)) != SOFTBUS_OK) {
        LOG_ERR("LnnMapSet error!");
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
        LOG_ERR("CreateCnnCodeKey error!");
        return;
    }
    if (LnnMapErase(cnnCode, key) != SOFTBUS_OK) {
        LOG_ERR("LnnMapErase error!");
    }
    DestroyCnnCodeKey(key);
    return;
}

short LnnGetCnnCode(const char *uuid, DiscoveryType type)
{
    char *key = CreateCnnCodeKey(uuid, type);
    if (key == NULL) {
        LOG_ERR("CreateCnnCodeKey error!");
        return INVALID_CONNECTION_CODE_VALUE;
    }
    short *ptr = (short *)LnnMapGet(&g_distributedNetLedger.cnnCode.connectionCode, key);
    if (ptr == NULL) {
        LOG_ERR(" KEY not exist.");
        DestroyCnnCodeKey(key);
        return INVALID_CONNECTION_CODE_VALUE;
    }
    DestroyCnnCodeKey(key);
    return (*ptr);
}

void LnnAddOnlineNode(NodeInfo *info)
{
    // judge map
    const char *deviceId = NULL;
    DoubleHashMap *map = NULL;
    NodeInfo *oldInfo = NULL;
    bool isOffline = true;
    bool oldWifiFlag = false;
    bool oldBrFlag = false;
    bool oldBleFlag = false;
    bool isChanged = false;
    bool newWifiFlag = LnnHasDiscoveryType(info, DISCOVERY_TYPE_WIFI);
    bool newBleBrFlag = LnnHasDiscoveryType(info, DISCOVERY_TYPE_BLE)
        || LnnHasDiscoveryType(info, DISCOVERY_TYPE_BR);
    if (LnnHasDiscoveryType(info, DISCOVERY_TYPE_BR)) {
        LOG_INFO("DiscoveryType = BR.");
        AddCnnCode(&g_distributedNetLedger.cnnCode.connectionCode, info->uuid, DISCOVERY_TYPE_BR,
            info->authSeqNum);
    }

    deviceId = LnnGetDeviceUdid(info);
    map = &g_distributedNetLedger.distributedInfo;
    if (pthread_mutex_lock(&g_distributedNetLedger.lock) != 0) {
        LOG_ERR("lock mutex fail!");
        return;
    }
    oldInfo = (NodeInfo *)LnnMapGet(&map->udidMap, deviceId);
    if (oldInfo != NULL && LnnIsNodeOnline(oldInfo)) {
        LOG_INFO("addOnlineNode find online node");
        isOffline = false;
        isChanged = IsNetworkIdChanged(info, oldInfo);
        oldWifiFlag = LnnHasDiscoveryType(oldInfo, DISCOVERY_TYPE_WIFI);
        oldBleFlag = LnnHasDiscoveryType(oldInfo, DISCOVERY_TYPE_BLE);
        oldBrFlag = LnnHasDiscoveryType(oldInfo, DISCOVERY_TYPE_BR);
        if ((oldBleFlag || oldBrFlag) && newWifiFlag) {
            NewWifiDiscovered(oldInfo, info);
        } else if (oldWifiFlag && newBleBrFlag) {
            NewBrBleDiscovered(oldInfo, info);
        } else {
            LOG_ERR("flag error");
        }
    }
    LnnSetNodeConnStatus(info, STATUS_ONLINE);
    LnnMapSet(&map->udidMap, deviceId, info, sizeof(NodeInfo));
    pthread_mutex_unlock(&g_distributedNetLedger.lock);
    if (isOffline) {
        PostToClient(info, STATUS_ONLINE);
    }
    if (isChanged) {
        PostDeviceBasicInfoChanged(info, TYPE_NETWORK_ID);
    }
}

void LnnSetNodeOffline(const char *udid)
{
    NodeInfo *info = NULL;
    NodeBasicInfo basic;
    if (memset_s(&basic, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo)) != EOK) {
        LOG_ERR("memset_s basic fail!");
    }
    DoubleHashMap *map = &g_distributedNetLedger.distributedInfo;
    if (pthread_mutex_lock(&g_distributedNetLedger.lock) != 0) {
        LOG_ERR("lock mutex fail!");
        return;
    }
    info = (NodeInfo *)LnnMapGet(&map->udidMap, udid);
    if (info == NULL) {
        LOG_ERR("PARA ERROR!");
        pthread_mutex_unlock(&g_distributedNetLedger.lock);
        return;
    }
    if (LnnHasDiscoveryType(info, DISCOVERY_TYPE_BR)) {
        RemoveCnnCode(&g_distributedNetLedger.cnnCode.connectionCode, info->uuid, DISCOVERY_TYPE_BR);
    }
    LnnSetNodeConnStatus(info, STATUS_OFFLINE);
    if (ConvertNodeInfoToBasicInfo(info, &basic) != SOFTBUS_OK) {
        pthread_mutex_unlock(&g_distributedNetLedger.lock);
        return;
    }
    pthread_mutex_unlock(&g_distributedNetLedger.lock);
    if (PostOffline(&basic) != SOFTBUS_OK) {
        LOG_ERR("post offline fail!");
    }
}

void LnnRemoveNode(const char *udid)
{
    DoubleHashMap *map = &g_distributedNetLedger.distributedInfo;
    if (udid == NULL) {
        return;
    }
    if (pthread_mutex_lock(&g_distributedNetLedger.lock) != 0) {
        LOG_ERR("lock mutex fail!");
        return;
    }
    LnnMapErase(&map->udidMap, udid);
    pthread_mutex_unlock(&g_distributedNetLedger.lock);
}

const char *LnnConvertDLidToUdid(const char *id, IdCategory type)
{
    NodeInfo *info = NULL;
    if (id == NULL) {
        return NULL;
    }
    info = LnnGetNodeInfoById(id, type);
    if (info == NULL) {
        LOG_ERR("uuid not find node info.");
        return NULL;
    }
    return LnnGetDeviceUdid(info);
}

bool LnnSetDLDeviceInfoName(const char *udid, const char *name)
{
    DoubleHashMap *map = &g_distributedNetLedger.distributedInfo;
    NodeInfo *info = NULL;
    NodeBasicInfo basic;
    if (memset_s(&basic, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo)) != EOK) {
        LOG_ERR("memset_s basic fail!");
    }
    if (udid == NULL || name == NULL) {
        LOG_ERR("para error!");
        return false;
    }
    if (pthread_mutex_lock(&g_distributedNetLedger.lock) != 0) {
        LOG_ERR("lock mutex fail!");
        return false;
    }
    info = GetNodeInfoFromMap(map, udid);
    if (info == NULL) {
        LOG_ERR("udid not exist !");
        goto EXIT;
    }
    if (strcmp(LnnGetDeviceName(&info->deviceInfo), name) == 0) {
        LOG_INFO("devicename not change!");
        pthread_mutex_unlock(&g_distributedNetLedger.lock);
        return true;
    }
    if (LnnSetDeviceName(&info->deviceInfo, name) != SOFTBUS_OK) {
        LOG_ERR("set device name error!");
        goto EXIT;
    }
    if (ConvertNodeInfoToBasicInfo(info, &basic) != SOFTBUS_OK) {
        goto EXIT;
    }
    pthread_mutex_unlock(&g_distributedNetLedger.lock);
    LnnNotifyBasicInfoChanged(&basic, TYPE_DEVICE_NAME);
    return true;
EXIT:
    pthread_mutex_unlock(&g_distributedNetLedger.lock);
    return false;
}

int32_t LnnGetDLStrInfo(const char *networkId, InfoKey key, char *info, uint32_t len)
{
    uint32_t i;
    int32_t ret;
    if (networkId == NULL || info == NULL) {
        LOG_ERR("para error.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (key >= STRING_KEY_END) {
        LOG_ERR("KEY error.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&g_distributedNetLedger.lock) != 0) {
        LOG_ERR("lock mutex fail!");
        return SOFTBUS_ERR;
    }
    for (i = 0; i < sizeof(g_dlKeyTable) / sizeof(DistributedLedgerKey); i++) {
        if (key == g_dlKeyTable[i].key) {
            if (g_dlKeyTable[i].getInfo != NULL) {
                ret = g_dlKeyTable[i].getInfo(networkId, (void *)info, len);
                pthread_mutex_unlock(&g_distributedNetLedger.lock);
                return ret;
            }
        }
    }
    pthread_mutex_unlock(&g_distributedNetLedger.lock);
    LOG_ERR("KEY NOT exist.");
    return SOFTBUS_ERR;
}

int32_t LnnGetDLNumInfo(const char *networkId, InfoKey key, int32_t *info)
{
    uint32_t i;
    int32_t ret;
    if (networkId == NULL || info == NULL) {
        LOG_ERR("para error.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (key < NUM_KEY_BEGIN || key >= NUM_KEY_END) {
        LOG_ERR("KEY error.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&g_distributedNetLedger.lock) != 0) {
        LOG_ERR("lock mutex fail!");
        return SOFTBUS_ERR;
    }
    for (i = 0; i < sizeof(g_dlKeyTable) / sizeof(DistributedLedgerKey); i++) {
        if (key == g_dlKeyTable[i].key) {
            if (g_dlKeyTable[i].getInfo != NULL) {
                ret = g_dlKeyTable[i].getInfo(networkId, (void *)info, NUM_BUF_SIZE);
                pthread_mutex_unlock(&g_distributedNetLedger.lock);
                return ret;
            }
        }
    }
    pthread_mutex_unlock(&g_distributedNetLedger.lock);
    LOG_ERR("KEY NOT exist.");
    return SOFTBUS_ERR;
}

int32_t LnnGetDistributedNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    int ret = SOFTBUS_ERR;

    if (info == NULL || infoNum == NULL) {
        LOG_ERR("key params are null");
        return ret;
    }
    if (pthread_mutex_lock(&g_distributedNetLedger.lock) != 0) {
        LOG_ERR("lock mutex fail!");
    }
    do {
        *info = NULL;
        if (GetDLOnlineNodeNumLocked(infoNum) != SOFTBUS_OK) {
            LOG_ERR("get online node num failed");
            break;
        }
        if (*infoNum == 0) {
            ret = SOFTBUS_OK;
            break;
        }
        *info = SoftBusMalloc((*infoNum) * sizeof(NodeBasicInfo));
        if (*info == NULL) {
            LOG_ERR("malloc node info buffer failed");
            break;
        }
        if (FillDLOnlineNodeInfoLocked(info, *infoNum) != SOFTBUS_OK) {
            LOG_ERR("fill online node num failed");
            break;
        }
        ret = SOFTBUS_OK;
    } while (false);
    if (ret != SOFTBUS_OK && (*info != NULL)) {
        SoftBusFree(*info);
    }
    if (pthread_mutex_unlock(&g_distributedNetLedger.lock) != 0) {
        LOG_ERR("unlock mutex fail!");
    }
    return ret;
}

int32_t LnnGetNetworkIdByUuid(const char *uuid, char *buf, uint32_t len)
{
    if (!IsValidString(uuid, ID_MAX_LEN)) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (pthread_mutex_lock(&g_distributedNetLedger.lock) != 0) {
        LOG_ERR("lock mutex fail!");
        return SOFTBUS_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(uuid, CATEGORY_UUID);
    if (nodeInfo == NULL) {
        LOG_ERR("get info fail");
        (void)pthread_mutex_unlock(&g_distributedNetLedger.lock);
        return SOFTBUS_ERR;
    }
    if (strncpy_s(buf, len, nodeInfo->networkId, strlen(nodeInfo->networkId)) != EOK) {
        LOG_ERR("STR COPY ERROR!");
        (void)pthread_mutex_unlock(&g_distributedNetLedger.lock);
        return SOFTBUS_MEM_ERR;
    }
    (void)pthread_mutex_unlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}