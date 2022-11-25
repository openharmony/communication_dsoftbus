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

#include "lnn_connection_addr_utils.h"
#include "lnn_fast_offline.h"
#include "lnn_lane_info.h"
#include "lnn_map.h"
#include "lnn_node_info.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_bus_center.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"
#include "softbus_hidumper_buscenter.h"
#include "bus_center_manager.h"

#define SOFTBUS_BUSCENTER_DUMP_REMOTEDEVICEINFO "remote_device_info"
#define RETURN_IF_GET_NODE_VALID(networkId, buf, info) do {                 \
        if ((networkId) == NULL || (buf) == NULL) {                        \
            return SOFTBUS_INVALID_PARAM;                               \
        }                                                               \
        (info) = LnnGetNodeInfoById((networkId), (CATEGORY_NETWORK_ID)); \
        if ((info) == NULL) {                                           \
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get node info fail."); \
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
    SoftBusMutex lock;
    DistributedLedgerStatus status;
    int32_t laneCount[LNN_LINK_TYPE_BUTT];
} DistributedNetLedger;

static DistributedNetLedger g_distributedNetLedger;

int32_t LnnSetAuthTypeValue(uint32_t *authTypeValue, AuthType type)
{
    if (authTypeValue == NULL || type >= AUTH_TYPE_BUTT) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "in para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    *authTypeValue = (*authTypeValue) | (1 << (uint32_t)type);
    return SOFTBUS_OK;
}

int32_t LnnClearAuthTypeValue(uint32_t *authTypeValue, AuthType type)
{
    if (authTypeValue == NULL || type >= AUTH_TYPE_BUTT) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "in para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    *authTypeValue = (*authTypeValue) & (~(1 << (uint32_t)type));
    return SOFTBUS_OK;
}

static NodeInfo *GetNodeInfoFromMap(const DoubleHashMap *map, const char *id)
{
    if (map == NULL || id == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error!");
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
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "id not exist!");
    return NULL;
}

static int32_t InitDistributedInfo(DoubleHashMap *map)
{
    if (map == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail:para error!");
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: para error!");
        return;
    }
    LnnMapDelete(&map->udidMap);
    LnnMapDelete(&map->ipMap);
    LnnMapDelete(&map->macMap);
}

static int32_t InitConnectionCode(ConnectionCode *cnnCode)
{
    if (cnnCode == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    LnnMapInit(&cnnCode->connectionCode);
    return SOFTBUS_OK;
}

static void DeinitConnectionCode(ConnectionCode *cnnCode)
{
    if (cnnCode == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: para error!");
        return;
    }
    LnnMapDelete(&cnnCode->connectionCode);
    return;
}

static void InitLaneStatus(void)
{
    uint32_t len = LNN_LINK_TYPE_BUTT * sizeof(int32_t);
    (void)memset_s(g_distributedNetLedger.laneCount, len, 0, len);
}

void LnnDeinitDistributedLedger(void)
{
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return;
    }
    g_distributedNetLedger.status = DL_INIT_UNKNOWN;
    DeinitDistributedInfo(&g_distributedNetLedger.distributedInfo);
    DeinitConnectionCode(&g_distributedNetLedger.cnnCode);
    if (SoftBusMutexUnlock(&g_distributedNetLedger.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "unlock mutex fail!");
    }
    SoftBusMutexDestroy(&g_distributedNetLedger.lock);
}

static void NewWifiDiscovered(const NodeInfo *oldInfo, NodeInfo *newInfo)
{
    const char *macAddr = NULL;
    if (oldInfo == NULL || newInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error!");
        return;
    }
    newInfo->discoveryType = newInfo->discoveryType | oldInfo->discoveryType;
    macAddr = LnnGetBtMac(newInfo);
    if (macAddr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnGetBtMac Fail!");
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error!");
        return;
    }
    newInfo->discoveryType = newInfo->discoveryType | oldInfo->discoveryType;
    ipAddr = LnnGetWiFiIp(newInfo);
    if (ipAddr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnGetWiFiIp Fail!");
        return;
    }
    if (strcmp(ipAddr, DEFAULT_IP) == 0) {
        LnnSetWiFiIp(newInfo, LnnGetWiFiIp(oldInfo));
    }

    newInfo->connectInfo.authPort = oldInfo->connectInfo.authPort;
    newInfo->connectInfo.proxyPort = oldInfo->connectInfo.proxyPort;
    newInfo->connectInfo.sessionPort = oldInfo->connectInfo.sessionPort;
}

static int32_t ConvertNodeInfoToBasicInfo(const NodeInfo *info, NodeBasicInfo *basic)
{
    if (info == NULL || basic == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strncpy_s(basic->deviceName, DEVICE_NAME_BUF_LEN, info->deviceInfo.deviceName,
        strlen(info->deviceInfo.deviceName)) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "strncpy_s name error!");
            return SOFTBUS_MEM_ERR;
    }

    if (strncpy_s(basic->networkId, NETWORK_ID_BUF_LEN, info->networkId, strlen(info->networkId)) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "strncpy_s networkID error!");
            return SOFTBUS_MEM_ERR;
    }
    basic->deviceTypeId = info->deviceInfo.deviceTypeId;
    return SOFTBUS_OK;
}

static bool isMetaNode(NodeInfo *info)
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
            if (LnnIsNodeOnline(info) || isMetaNode(info)) {
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "it is null");
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
            if (LnnIsNodeOnline(nodeInfo) || isMetaNode(nodeInfo)) {
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error!");
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "memset_s basic fail!");
    }
    DoubleHashMap *map = &g_distributedNetLedger.distributedInfo;
    if (callBack->onNodeOnline == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "onNodeOnline IS null!");
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error");
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
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "type error");
        }
    }
    LnnMapDeinitIterator(it);
    return NULL;
}

bool LnnGetOnlineStateById(const char *id, IdCategory type)
{
    bool state = false;
    if (!IsValidString(id, ID_MAX_LEN)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "id is invalid");
        return state;
    }

    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return state;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(id, type);
    if (nodeInfo == NULL) {
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
    if (strncpy_s(buf, len, info->uuid, strlen(info->uuid)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "STR COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetDeviceOfflineCode(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (memcpy_s(buf, len, info->offlineCode, OFFLINE_CODE_BYTE_SIZE) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "memcpy_s offlinecode ERROR!");
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get device udid fail");
        return SOFTBUS_ERR;
    }
    if (strncpy_s(buf, len, udid, strlen(udid)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "STR COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetNodeSoftBusVersion(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (strncpy_s(buf, len, info->softBusVersion, strlen(info->softBusVersion)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "STR COPY ERROR!");
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "deviceType fail.");
        return SOFTBUS_ERR;
    }
    if (strncpy_s(buf, len, deviceType, strlen(deviceType)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "MEM COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get device name fail.");
        return SOFTBUS_ERR;
    }
    if (strncpy_s(buf, len, deviceName, strlen(deviceName)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "STR COPY ERROR!");
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get bt mac fail.");
        return SOFTBUS_ERR;
    }
    if (strncpy_s(buf, len, mac, strlen(mac)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "STR COPY ERROR!");
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get wifi ip fail.");
        return SOFTBUS_ERR;
    }
    if (strncpy_s(buf, len, ip, strlen(ip)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "STR COPY ERROR!");
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
        return SOFTBUS_ERR;
    }
    masterUdid = LnnGetMasterUdid(info);
    if (masterUdid == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get master uiid fail");
        return SOFTBUS_ERR;
    }
    if (strncpy_s(buf, len, masterUdid, strlen(masterUdid)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy master udid to buf fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
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
    *((int32_t *)buf) = info->netCapacity;
    return SOFTBUS_OK;
}

static int32_t DlGetNetType(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    if (len != LNN_COMMON_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    *((int32_t *)buf) = info->discoveryType;
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "node is offline");
        return SOFTBUS_ERR;
    }
    mac = LnnGetP2pMac(info);
    if (mac == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get p2p mac fail");
        return SOFTBUS_ERR;
    }
    if (strcpy_s(buf, len, mac) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy p2p mac to buf fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DlGetNodeAddr(const char *networkId, void *buf, uint32_t len)
{
    NodeInfo *info = NULL;
    RETURN_IF_GET_NODE_VALID(networkId, buf, info);
    if (!LnnIsNodeOnline(info)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "node is offline");
        return SOFTBUS_ERR;
    }

    if (strcpy_s(buf, len, info->nodeAddress) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy node addr to buf fail");
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "node is offline");
        return SOFTBUS_ERR;
    }
    mac = LnnGetP2pGoMac(info);
    if (mac == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get p2p go mac fail");
        return SOFTBUS_ERR;
    }
    if (strcpy_s(buf, len, mac) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy p2p go mac to buf fail");
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "node is offline");
        return SOFTBUS_ERR;
    }
    *((int32_t *)buf) = LnnGetP2pRole(info);
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "node is offline");
        return SOFTBUS_ERR;
    }
    *((int16_t *)buf) = LnnGetDataChangeFlag(info);
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
    {STRING_KEY_P2P_GO_MAC, DlGetP2pGoMac},
    {STRING_KEY_NODE_ADDR, DlGetNodeAddr},
    {STRING_KEY_OFFLINE_CODE, DlGetDeviceOfflineCode},
    {NUM_KEY_META_NODE, DlGetAuthType},
    {NUM_KEY_SESSION_PORT, DlGetSessionPort},
    {NUM_KEY_AUTH_PORT, DlGetAuthPort},
    {NUM_KEY_PROXY_PORT, DlGetProxyPort},
    {NUM_KEY_NET_CAP, DlGetNetCap},
    {NUM_KEY_DISCOVERY_TYPE, DlGetNetType},
    {NUM_KEY_MASTER_NODE_WEIGHT, DlGetMasterWeight},
    {NUM_KEY_P2P_ROLE, DlGetP2pRole},
    {NUM_KEY_DATA_CHANGE_FLAG, DlGetNodeDataChangeFlag},
};

static char *CreateCnnCodeKey(const char *uuid, DiscoveryType type)
{
    if (uuid == NULL || strlen(uuid) >= UUID_BUF_LEN) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error!");
        return NULL;
    }
    char *key = (char *)SoftBusCalloc(INT_TO_STR_SIZE + UUID_BUF_LEN);
    if (key == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "SoftBusCalloc fail!");
        return NULL;
    }
    if (sprintf_s(key, INT_TO_STR_SIZE + UUID_BUF_LEN, "%d%s", type, uuid) == -1) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "type convert char error!");
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "CreateCnnCodeKey error!");
        return SOFTBUS_ERR;
    }
    if (LnnMapSet(cnnCode, key, (void *)&seq, sizeof(short)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnMapSet error!");
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "CreateCnnCodeKey error!");
        return;
    }
    if (LnnMapErase(cnnCode, key) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnMapErase error!");
    }
    DestroyCnnCodeKey(key);
    return;
}

short LnnGetCnnCode(const char *uuid, DiscoveryType type)
{
    char *key = CreateCnnCodeKey(uuid, type);
    if (key == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "CreateCnnCodeKey error!");
        return INVALID_CONNECTION_CODE_VALUE;
    }
    short *ptr = (short *)LnnMapGet(&g_distributedNetLedger.cnnCode.connectionCode, key);
    if (ptr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, " KEY not exist.");
        DestroyCnnCodeKey(key);
        return INVALID_CONNECTION_CODE_VALUE;
    }
    DestroyCnnCodeKey(key);
    return (*ptr);
}

static void MergeLnnInfo(const NodeInfo *oldInfo, NodeInfo *info)
{
    int32_t i;

    for (i = 0; i < CONNECTION_ADDR_MAX; ++i) {
        info->relation[i] += oldInfo->relation[i];
        info->relation[i] &= LNN_RELATION_MASK;
        if (oldInfo->authChannelId[i] != 0) {
            info->authChannelId[i] = oldInfo->authChannelId[i];
        }
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO,
            "Update authChannelId: %d, addrType=%d.", info->authChannelId[i], i);
    }
}

static void UpdateAuthSeq(const NodeInfo *oldInfo, NodeInfo *info)
{
    DiscoveryType type;
    for (type = DISCOVERY_TYPE_WIFI; type < DISCOVERY_TYPE_P2P; type++) {
        if (LnnHasDiscoveryType(info, type)) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO,
                "UpdateAuthSeq: authSeq=%" PRId64 ", type=%d.", info->authSeq[type], type);
            continue;
        }
        info->authSeq[type] = oldInfo->authSeq[type];
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO,
            "UpdateAuthSeq: authSeq=%" PRId64 ", type=%d.", info->authSeq[type], type);
    }
}

int32_t LnnUpdateNodeInfo(NodeInfo *newInfo)
{
    const char *udid = NULL;
    DoubleHashMap *map = NULL;
    NodeInfo *oldInfo = NULL;

    udid = LnnGetDeviceUdid(newInfo);
    map = &g_distributedNetLedger.distributedInfo;
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }
    oldInfo = (NodeInfo *)LnnMapGet(&map->udidMap, udid);
    if (oldInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "no online node newInfo!");
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_ERR;
    }
    if (LnnHasDiscoveryType(newInfo, DISCOVERY_TYPE_WIFI)) {
        oldInfo->discoveryType = newInfo->discoveryType | oldInfo->discoveryType;
        oldInfo->connectInfo.authPort = newInfo->connectInfo.authPort;
        oldInfo->connectInfo.proxyPort = newInfo->connectInfo.proxyPort;
        oldInfo->connectInfo.sessionPort = newInfo->connectInfo.sessionPort;
    }
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnAddMetaInfo lock mutex fail!");
        return SOFTBUS_ERR;
    }
    oldInfo = (NodeInfo *)LnnMapGet(&map->udidMap, udid);
    if (oldInfo != NULL) {
        MetaInfo temp = info->metaInfo;
        if (memcpy_s(info, sizeof(NodeInfo), oldInfo, sizeof(NodeInfo)) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnAddMetaInfo copy fail!");
            SoftBusMutexUnlock(&g_distributedNetLedger.lock);
            return SOFTBUS_MEM_ERR;
        }
        info->metaInfo.isMetaNode = true;
        info->metaInfo.metaDiscType = info->metaInfo.metaDiscType | temp.metaDiscType;
    }
    LnnSetAuthTypeValue(&info->AuthTypeValue, ONLINE_METANODE);
    LnnMapSet(&map->udidMap, udid, info, sizeof(NodeInfo));
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "LnnAddMetaInfo success");
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

int32_t LnnDeleteMetaInfo(const char *udid, ConnectionAddrType type)
{
    NodeInfo *info = NULL;
    DiscoveryType discType = LnnConvAddrTypeToDiscType(type);
    if (discType == DISCOVERY_TYPE_COUNT) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "DeleteMetaInfo type error fail!");
        return SOFTBUS_ERR;
    }
    DoubleHashMap *map = &g_distributedNetLedger.distributedInfo;
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "DeleteAddMetaInfo lock mutex fail!");
        return SOFTBUS_ERR;
    }
    info = (NodeInfo *)LnnMapGet(&map->udidMap, udid);
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "DeleteAddMetaInfo para error!");
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_ERR;
    }
    info->metaInfo.metaDiscType = (uint32_t)info->metaInfo.metaDiscType & ~(1 << (uint32_t)discType);
    if (info->metaInfo.metaDiscType == 0) {
        info->metaInfo.isMetaNode = false;
    }
    LnnClearAuthTypeValue(&info->AuthTypeValue, ONLINE_METANODE);
    LnnMapSet(&map->udidMap, udid, info, sizeof(NodeInfo));
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "LnnDeleteMetaInfo success");
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

ReportCategory LnnAddOnlineNode(NodeInfo *info)
{
    // judge map
    if (info == NULL) {
        return REPORT_NONE;
    }
    const char *udid = NULL;
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "DiscoveryType = BR.");
        AddCnnCode(&g_distributedNetLedger.cnnCode.connectionCode, info->uuid, DISCOVERY_TYPE_BR,
            info->authSeqNum);
    }

    udid = LnnGetDeviceUdid(info);
    map = &g_distributedNetLedger.distributedInfo;
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return REPORT_NONE;
    }
    oldInfo = (NodeInfo *)LnnMapGet(&map->udidMap, udid);
    if (oldInfo != NULL) {
        info->metaInfo = oldInfo->metaInfo;
    }
    if (oldInfo != NULL && LnnIsNodeOnline(oldInfo)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "addOnlineNode find online node");
        UpdateAuthSeq(oldInfo, info);
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
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "flag error");
        }
        // update lnn discovery type
        info->discoveryType |= oldInfo->discoveryType;
        MergeLnnInfo(oldInfo, info);
    }
    LnnSetNodeConnStatus(info, STATUS_ONLINE);
    LnnSetAuthTypeValue(&info->AuthTypeValue, ONLINE_HICHAIN);
    LnnMapSet(&map->udidMap, udid, info, sizeof(NodeInfo));
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    if (isOffline) {
        return REPORT_ONLINE;
    }
    if (isChanged) {
        return REPORT_CHANGE;
    }
    return REPORT_NONE;
}

ReportCategory LnnSetNodeOffline(const char *udid, ConnectionAddrType type, int32_t authId)
{
    NodeInfo *info = NULL;

    DoubleHashMap *map = &g_distributedNetLedger.distributedInfo;
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return REPORT_NONE;
    }
    info = (NodeInfo *)LnnMapGet(&map->udidMap, udid);
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "PARA ERROR!");
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return REPORT_NONE;
    }
    if (type != CONNECTION_ADDR_MAX && info->relation[type] > 0) {
        info->relation[type]--;
    }
    if (LnnHasDiscoveryType(info, DISCOVERY_TYPE_BR) && LnnConvAddrTypeToDiscType(type) == DISCOVERY_TYPE_BR) {
        RemoveCnnCode(&g_distributedNetLedger.cnnCode.connectionCode, info->uuid, DISCOVERY_TYPE_BR);
    }
    if (LnnHasDiscoveryType(info, DISCOVERY_TYPE_WIFI) && LnnConvAddrTypeToDiscType(type) == DISCOVERY_TYPE_WIFI &&
        info->authChannelId[type] != authId) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "authChannelId != authId, not need to report offline.");
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return REPORT_NONE;
    }
    info->authChannelId[type] = 0;
    LnnClearDiscoveryType(info, LnnConvAddrTypeToDiscType(type));
    if (info->discoveryType != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "discoveryType=%u after clear, not need to report offline.",
            info->discoveryType);
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return REPORT_NONE;
    }
    LnnSetNodeConnStatus(info, STATUS_OFFLINE);
    LnnClearAuthTypeValue(&info->AuthTypeValue, ONLINE_HICHAIN);
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "need to report offline.");
    return REPORT_OFFLINE;
}

int32_t LnnGetBasicInfoByUdid(const char *udid, NodeBasicInfo *basicInfo)
{
    if (udid == NULL || basicInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "PARA ERROR!");
        return SOFTBUS_INVALID_PARAM;
    }
    DoubleHashMap *map = &g_distributedNetLedger.distributedInfo;
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "uuid not find node info.");
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    info = LnnGetNodeInfoById(srcId, srcIdType);
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "no node info for: %d", srcIdType);
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy id fail");
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    info = LnnGetNodeInfoById(id, type);
    if (info == NULL || !LnnIsNodeOnline(info)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "node not online");
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_NOT_FIND;
    }
    if (memcpy_s(relation, len, info->relation, CONNECTION_ADDR_MAX) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy relation fail");
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error!");
        return false;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return false;
    }
    info = GetNodeInfoFromMap(map, udid);
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "udid not exist !");
        goto EXIT;
    }
    if (strcmp(LnnGetDeviceName(&info->deviceInfo), name) == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "devicename not change!");
        SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return true;
    }
    if (LnnSetDeviceName(&info->deviceInfo, name) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "set device name error!");
        goto EXIT;
    }
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return true;
EXIT:
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return false;
}

bool LnnSetDLP2pInfo(const char *networkId, const P2pInfo *info)
{
    NodeInfo *node = NULL;
    if (networkId == NULL || info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return false;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock mutex fail.");
        return false;
    }
    node = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (node == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "udid not found.");
        goto EXIT;
    }
    if (LnnSetP2pRole(node, info->p2pRole) != SOFTBUS_OK ||
        LnnSetP2pMac(node, info->p2pMac) != SOFTBUS_OK ||
        LnnSetP2pGoMac(node, info->goMac) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "set p2p info fail.");
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "info is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (key >= STRING_KEY_END) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "KEY error.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
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
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "KEY NOT exist.");
    return SOFTBUS_ERR;
}

int32_t LnnGetRemoteNumInfo(const char *networkId, InfoKey key, int32_t *info)
{
    uint32_t i;
    int32_t ret;
    if (!IsValidString(networkId, ID_MAX_LEN)) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "info is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (key < NUM_KEY_BEGIN || key >= NUM_KEY_END) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "KEY error.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
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
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "KEY NOT exist.");
    return SOFTBUS_ERR;
}

int32_t LnnGetRemoteNum16Info(const char *networkId, InfoKey key, int16_t *info)
{
    uint32_t i;
    int32_t ret;
    if (!IsValidString(networkId, ID_MAX_LEN)) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "info is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (key < NUM_KEY_BEGIN || key >= NUM_KEY_END) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "KEY error.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }
    for (i = 0; i < sizeof(g_dlKeyTable) / sizeof(DistributedLedgerKey); i++) {
        if (key == g_dlKeyTable[i].key) {
            if (g_dlKeyTable[i].getInfo != NULL) {
                ret = g_dlKeyTable[i].getInfo(networkId, (void *)info, DATA_CHANGE_FLAG_BUF_LEN);
                SoftBusMutexUnlock(&g_distributedNetLedger.lock);
                return ret;
            }
        }
    }
    SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "KEY NOT exist.");
    return SOFTBUS_ERR;
}

static int32_t GetAllOnlineAndMetaNodeInfo(NodeBasicInfo **info, int32_t *infoNum, bool isNeedMeta)
{
    int ret = SOFTBUS_ERR;

    if (info == NULL || infoNum == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "key params are null");
        return ret;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return ret;
    }
    do {
        *info = NULL;
        if (GetDLOnlineNodeNumLocked(infoNum, isNeedMeta) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get online node num failed");
            break;
        }
        if (*infoNum == 0) {
            ret = SOFTBUS_OK;
            break;
        }
        *info = SoftBusMalloc((*infoNum) * sizeof(NodeBasicInfo));
        if (*info == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc node info buffer failed");
            break;
        }
        if (FillDLOnlineNodeInfoLocked(*info, *infoNum, isNeedMeta) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fill online node num failed");
            break;
        }
        ret = SOFTBUS_OK;
    } while (false);
    if (ret != SOFTBUS_OK && (*info != NULL)) {
        SoftBusFree(*info);
        *info = NULL;
    }
    if (SoftBusMutexUnlock(&g_distributedNetLedger.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "unlock mutex fail!");
    }
    return ret;
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "btMac is empty");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }
    MapIterator *it = LnnMapInitIterator(&g_distributedNetLedger.distributedInfo.udidMap);
    if (it == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "it is null");
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
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "strcpy_s networkId fail!");
            }
            LnnMapDeinitIterator(it);
            (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
            return SOFTBUS_OK;
        }
    }
    LnnMapDeinitIterator(it);
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_ERR;
}

int32_t LnnGetNetworkIdByUuid(const char *uuid, char *buf, uint32_t len)
{
    if (!IsValidString(uuid, ID_MAX_LEN)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "uuid is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(uuid, CATEGORY_UUID);
    if (nodeInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get info fail");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_ERR;
    }
    if (strncpy_s(buf, len, nodeInfo->networkId, strlen(nodeInfo->networkId)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "STR COPY ERROR!");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_MEM_ERR;
    }
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

int32_t LnnGetNetworkIdByUdid(const char *udid, char *buf, uint32_t len)
{
    if (!IsValidString(udid, ID_MAX_LEN)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "udid is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(udid, CATEGORY_UDID);
    if (nodeInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get info fail");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_ERR;
    }
    if (strncpy_s(buf, len, nodeInfo->networkId, strlen(nodeInfo->networkId)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "STR COPY ERROR!");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_MEM_ERR;
    }
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

int32_t LnnGetAllAuthSeq(const char *udid, int64_t *authSeq, uint32_t num)
{
    if (!IsValidString(udid, ID_MAX_LEN) || authSeq == NULL || num != DISCOVERY_TYPE_COUNT) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "[offline]udid is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "[offline]lock mutex fail!");
        return SOFTBUS_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(udid, CATEGORY_UDID);
    if (nodeInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "[offline] get node info fail");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_ERR;
    }
    if (memcpy_s(authSeq, sizeof(int64_t) * num, nodeInfo->authSeq, sizeof(nodeInfo->authSeq)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "[offline]memcpy_s authSeq fail");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_MEM_ERR;
    }
    DiscoveryType type;
    for (type = DISCOVERY_TYPE_WIFI; type < DISCOVERY_TYPE_P2P; type++) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO,
            "[offline]LnnGetAllAuthSeq: authSeq=%" PRId64 ", type=%d.", authSeq[type], type);
    }
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

int32_t LnnGetLaneCount(int32_t laneId)
{
    if (laneId < 0 || laneId >= LNN_LINK_TYPE_BUTT) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "laneId is error! laneId: %d", laneId);
        return SOFTBUS_ERR;
    }
    return g_distributedNetLedger.laneCount[laneId];
}

int32_t LnnSetLaneCount(int32_t laneId, int32_t num)
{
    if (laneId < 0 || laneId >= LNN_LINK_TYPE_BUTT) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "laneId is error! laneId:%d", laneId);
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }
    g_distributedNetLedger.laneCount[laneId] += num;
    if (g_distributedNetLedger.laneCount[laneId] < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "laneCount(%d) error", g_distributedNetLedger.laneCount[laneId]);
        g_distributedNetLedger.laneCount[laneId] = 0;
    }
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

int32_t LnnGetDLHeartbeatTimestamp(const char *networkId, uint64_t *timestamp)
{
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (nodeInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get info fail");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_ERR;
    }
    *timestamp = nodeInfo->heartbeatTimeStamp;
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

int32_t LnnSetDLHeartbeatTimestamp(const char *networkId, uint64_t timestamp)
{
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (nodeInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get info fail");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_ERR;
    }
    nodeInfo->heartbeatTimeStamp = timestamp;
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

int32_t LnnSetDLConnCapability(const char *networkId, uint64_t connCapability)
{
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (nodeInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get info fail");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_ERR;
    }
    nodeInfo->netCapacity = (uint32_t)connCapability;
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return SOFTBUS_OK;
}

int32_t LnnSetDLNodeAddr(const char *id, IdCategory type, const char *addr)
{
    if (SoftBusMutexLock(&g_distributedNetLedger.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(id, type);
    if (nodeInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get info fail");
        (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
        return SOFTBUS_ERR;
    }
    int ret = strcpy_s(nodeInfo->nodeAddress, sizeof(nodeInfo->nodeAddress), addr);
    if (ret != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "set node addr failed!ret=%d", ret);
    }
    (void)SoftBusMutexUnlock(&g_distributedNetLedger.lock);
    return ret == EOK ? SOFTBUS_OK : SOFTBUS_ERR;
}

int32_t SoftBusDumpBusCenterRemoteDeviceInfo(int fd)
{
    SOFTBUS_DPRINTF(fd, "-----RemoteDeviceInfo-----\n");
    NodeBasicInfo *remoteNodeInfo = NULL;
    int32_t infoNum = 0;
    if (LnnGetAllOnlineNodeInfo(&remoteNodeInfo, &infoNum) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnGetAllOnlineNodeInfo failed!");
        return SOFTBUS_ERR;
    }
    SOFTBUS_DPRINTF(fd, "remote device num = %d\n", infoNum);
    for (int i = 0; i < infoNum; i++) {
        SOFTBUS_DPRINTF(fd, "\n[NO.%d]\n", i + 1);
        SoftBusDumpBusCenterPrintInfo(fd, remoteNodeInfo + i);
    }
    return SOFTBUS_OK;
}

int32_t LnnInitDistributedLedger(void)
{
    if (g_distributedNetLedger.status == DL_INIT_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "Distributed Ledger already init");
        return SOFTBUS_OK;
    }

    if (InitDistributedInfo(&g_distributedNetLedger.distributedInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "InitDistributedInfo ERROR!");
        g_distributedNetLedger.status = DL_INIT_FAIL;
        return SOFTBUS_ERR;
    }

    if (InitConnectionCode(&g_distributedNetLedger.cnnCode) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "InitConnectionCode ERROR!");
        g_distributedNetLedger.status = DL_INIT_FAIL;
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexInit(&g_distributedNetLedger.lock, NULL) != SOFTBUS_OK) {
        g_distributedNetLedger.status = DL_INIT_FAIL;
        return SOFTBUS_ERR;
    }
    if (SoftBusRegBusCenterVarDump(SOFTBUS_BUSCENTER_DUMP_REMOTEDEVICEINFO,
        &SoftBusDumpBusCenterRemoteDeviceInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftBusRegBusCenterVarDump regist fail");
        return SOFTBUS_ERR;
    }
    InitLaneStatus();
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get all online node info fail");
        return NULL;
    }
    if (info == NULL || infoNum == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "none online node");
        if (info != NULL) {
            SoftBusFree(info);
        }
        return NULL;
    }
    for (i = 0; i < infoNum; ++i) {
        const NodeInfo *nodeInfo = LnnGetNodeInfoById(info[i].networkId, CATEGORY_NETWORK_ID);
        if (nodeInfo == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "nodeInfo is null.");
            continue;
        }
        if (GenerateStrHashAndConvertToHexString((const unsigned char *)nodeInfo->deviceInfo.deviceUdid,
            SHORT_UDID_HASH_LEN, shortUdidHash, SHORT_UDID_HASH_LEN + 1) != SOFTBUS_OK) {
            continue;
        }
        if (memcmp(shortUdidHash, recvUdidHash, SHORT_UDID_HASH_LEN) == 0) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "node shortUdidHash:%s is online",
                AnonymizesUDID((const char *)shortUdidHash));
            SoftBusFree(info);
            return nodeInfo;
        }
    }
    SoftBusFree(info);
    return NULL;
}

static void RefreshDeviceInfoByDevId(DeviceInfo *device, const InnerDeviceInfoAddtions *addtions)
{
    if (addtions->medium != BLE) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "RefreshDeviceInfoDevId parameter error");
        return;
    }
    const NodeInfo *nodeInfo = LnnGetOnlineNodeByUdidHash(device->devId);
    if (nodeInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "device udidhash:%s is not online",
            AnonymizesUDID(device->devId));
        return;
    }
    if (memcpy_s(device->devId, DISC_MAX_DEVICE_ID_LEN, nodeInfo->deviceInfo.deviceUdid, UDID_BUF_LEN) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "memcpy deviceUdid fail");
    }
}

static void RefreshDeviceOnlineStateInfo(DeviceInfo *device, const InnerDeviceInfoAddtions *addtions)
{
    if (addtions->medium == COAP) {
        device->isOnline = LnnGetOnlineStateById(device->devId, CATEGORY_UDID);
    }
    if (addtions->medium == BLE) {
        device->isOnline = ((LnnGetOnlineNodeByUdidHash(device->devId)) != NULL) ? true : false;
    }
}

void LnnRefreshDeviceOnlineStateAndDevIdInfo(const char *pkgName, DeviceInfo *device,
    const InnerDeviceInfoAddtions *addtions)
{
    (void)pkgName;
    RefreshDeviceOnlineStateInfo(device, addtions);
    RefreshDeviceInfoByDevId(device, addtions);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "device found by medium=%d, online status=%d",
        addtions->medium, device->isOnline);
}