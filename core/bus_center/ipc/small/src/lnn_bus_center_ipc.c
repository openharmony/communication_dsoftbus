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

#include "lnn_bus_center_ipc.h"

#include <securec.h>
#include <string.h>

#include "bus_center_client_proxy.h"
#include "bus_center_manager.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_log.h"
#include "lnn_meta_node_ledger.h"
#include "lnn_time_sync_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

typedef struct {
    ListNode node;
    char pkgName[PKG_NAME_SIZE_MAX];
    ConnectionAddr addr;
} JoinLnnRequestInfo;

typedef struct {
    ListNode node;
    char pkgName[PKG_NAME_SIZE_MAX];
    char networkId[NETWORK_ID_BUF_LEN];
} LeaveLnnRequestInfo;

typedef struct {
    SoftBusList *joinLNNRequestInfo;
    SoftBusList *leaveLNNRequestInfo;
    SoftBusMutex lock;
} LNNRequestInfo;

static LNNRequestInfo g_lnnRequestInfo;

int32_t LnnIpcInit(void)
{
    g_lnnRequestInfo.joinLNNRequestInfo = NULL;
    g_lnnRequestInfo.leaveLNNRequestInfo = NULL;
    if (SoftBusMutexInit(&g_lnnRequestInfo.lock, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "lock init fail");
        return SOFTBUS_LOCK_ERR;
    }

    return SOFTBUS_OK;
}

void LnnIpcDeinit(void)
{
    (void)SoftBusMutexDestroy(&g_lnnRequestInfo.lock);
}

static int32_t OnRefreshDeviceFound(const char *pkgName, const DeviceInfo *device,
    const InnerDeviceInfoAddtions *additions);

static IServerDiscInnerCallback g_discInnerCb = {
    .OnServerDeviceFound = OnRefreshDeviceFound,
};

static JoinLnnRequestInfo *FindJoinLNNRequest(ConnectionAddr *addr)
{
    JoinLnnRequestInfo *info = NULL;
    SoftBusList *list = g_lnnRequestInfo.joinLNNRequestInfo;

    if (list == NULL) {
        LNN_LOGE(LNN_EVENT, "request info list empty");
        return NULL;
    }
    LIST_FOR_EACH_ENTRY(info, &list->list, JoinLnnRequestInfo, node) {
        if (LnnIsSameConnectionAddr(addr, &info->addr, false)) {
            return info;
        }
    }
    return NULL;
}

static LeaveLnnRequestInfo *FindLeaveLNNRequest(const char *networkId)
{
    LeaveLnnRequestInfo *info = NULL;
    SoftBusList *list = g_lnnRequestInfo.leaveLNNRequestInfo;

    if (list == NULL) {
        LNN_LOGE(LNN_EVENT, "request info list empty");
        return NULL;
    }
    LIST_FOR_EACH_ENTRY(info, &list->list, LeaveLnnRequestInfo, node) {
        if (strncmp(networkId, info->networkId, strlen(networkId)) == 0) {
            return info;
        }
    }
    return NULL;
}

static bool IsRepeatJoinLNNRequest(const char *pkgName, const ConnectionAddr *addr)
{
    JoinLnnRequestInfo *info = NULL;
    SoftBusList *list = g_lnnRequestInfo.joinLNNRequestInfo;

    if (list == NULL) {
        LNN_LOGE(LNN_EVENT, "request info list empty");
        return SOFTBUS_LIST_EMPTY;
    }
    LIST_FOR_EACH_ENTRY(info, &list->list, JoinLnnRequestInfo, node) {
        if (strncmp(pkgName, info->pkgName, strlen(pkgName)) != 0) {
            continue;
        }
        if (LnnIsSameConnectionAddr(addr, &info->addr, false)) {
            return true;
        }
    }
    return false;
}

static int32_t AddJoinLNNInfo(const char *pkgName, const ConnectionAddr *addr)
{
    SoftBusList *list = g_lnnRequestInfo.joinLNNRequestInfo;
    JoinLnnRequestInfo *info = (JoinLnnRequestInfo *)SoftBusMalloc(sizeof(JoinLnnRequestInfo));
    if (info == NULL) {
        LNN_LOGE(LNN_EVENT, "request info malloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(&info->node);
    if (strncpy_s(info->pkgName, PKG_NAME_SIZE_MAX, pkgName, strlen(pkgName)) != EOK) {
        LNN_LOGE(LNN_EVENT, "copy pkgName fail");
        SoftBusFree(info);
        return SOFTBUS_MEM_ERR;
    }
    info->addr = *addr;
    ListAdd(&list->list, &info->node);
    list->cnt++;
    return SOFTBUS_OK;
}

static bool IsRepeatLeaveLNNRequest(const char *pkgName, const char *networkId)
{
    LeaveLnnRequestInfo *info = NULL;
    SoftBusList *list = g_lnnRequestInfo.leaveLNNRequestInfo;
    LIST_FOR_EACH_ENTRY(info, &list->list, LeaveLnnRequestInfo, node) {
        if (strncmp(pkgName, info->pkgName, strlen(pkgName)) != 0) {
            continue;
        }
        if (strncmp(networkId, info->networkId, strlen(networkId)) == 0) {
            return true;
        }
    }
    return false;
}

static int32_t AddLeaveLNNInfo(const char *pkgName, const char *networkId)
{
    SoftBusList *list = g_lnnRequestInfo.leaveLNNRequestInfo;
    LeaveLnnRequestInfo *info = (LeaveLnnRequestInfo *)SoftBusMalloc(sizeof(LeaveLnnRequestInfo));
    if (info == NULL) {
        LNN_LOGE(LNN_EVENT, "malloc request info fail");
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(&info->node);
    if (strncpy_s(info->pkgName, PKG_NAME_SIZE_MAX, pkgName, strlen(pkgName)) != EOK) {
        LNN_LOGE(LNN_EVENT, "copy pkgName fail");
        SoftBusFree(info);
        return SOFTBUS_STRCPY_ERR;
    }
    if (strncpy_s(info->networkId, NETWORK_ID_BUF_LEN, networkId, strlen(networkId)) != EOK) {
        LNN_LOGE(LNN_EVENT, "copy networkId fail");
        SoftBusFree(info);
        return SOFTBUS_STRCPY_ERR;
    }
    ListAdd(&list->list, &info->node);
    list->cnt++;
    return SOFTBUS_OK;
}

static int32_t OnRefreshDeviceFound(const char *pkgName, const DeviceInfo *device,
    const InnerDeviceInfoAddtions *additions)
{
    DeviceInfo newDevice;
    if (memcpy_s(&newDevice, sizeof(DeviceInfo), device, sizeof(DeviceInfo)) != EOK) {
        LNN_LOGE(LNN_EVENT, "copy new device info error");
        return SOFTBUS_MEM_ERR;
    }
    LnnRefreshDeviceOnlineStateAndDevIdInfo(pkgName, &newDevice, additions);
    return ClientOnRefreshDeviceFound(pkgName, 0, &newDevice, sizeof(DeviceInfo));
}

int32_t LnnIpcServerJoin(const char *pkgName, int32_t callingPid, void *addr, uint32_t addrTypeLen)
{
    (void)callingPid;
    ConnectionAddr *connAddr = (ConnectionAddr *)addr;

    if (pkgName == NULL || connAddr == NULL) {
        LNN_LOGE(LNN_EVENT, "parameter is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (addrTypeLen != sizeof(ConnectionAddr)) {
        LNN_LOGE(LNN_EVENT, "addr is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_lnnRequestInfo.lock) != 0) {
        LNN_LOGE(LNN_EVENT, "get lock fail");
    }
    if (g_lnnRequestInfo.joinLNNRequestInfo == NULL) {
        g_lnnRequestInfo.joinLNNRequestInfo = CreateSoftBusList();
        if (g_lnnRequestInfo.joinLNNRequestInfo == NULL) {
            LNN_LOGE(LNN_EVENT, "lnn request Info is null");
            (void)SoftBusMutexUnlock(&g_lnnRequestInfo.lock);
            return SOFTBUS_MALLOC_ERR;
        }
    }
    if (IsRepeatJoinLNNRequest(pkgName, connAddr)) {
        LNN_LOGE(LNN_EVENT, "repeat join lnn request pkgName=%{public}s", pkgName);
        (void)SoftBusMutexUnlock(&g_lnnRequestInfo.lock);
        return SOFTBUS_ALREADY_EXISTED;
    }
    int32_t ret = LnnServerJoin(connAddr, pkgName);
    if (ret == SOFTBUS_OK) {
        ret = AddJoinLNNInfo(pkgName, connAddr);
    }
    if (SoftBusMutexUnlock(&g_lnnRequestInfo.lock) != 0) {
        LNN_LOGE(LNN_EVENT, "release lock fail");
    }
    return ret;
}

int32_t LnnIpcServerLeave(const char *pkgName, int32_t callingPid, const char *networkId)
{
    (void)callingPid;
    if (pkgName == NULL || networkId == NULL) {
        LNN_LOGE(LNN_EVENT, "parameter is NULL");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_lnnRequestInfo.lock) != 0) {
        LNN_LOGE(LNN_EVENT, "get lock fail");
    }
    if (g_lnnRequestInfo.leaveLNNRequestInfo == NULL) {
        g_lnnRequestInfo.leaveLNNRequestInfo = CreateSoftBusList();
        if (g_lnnRequestInfo.leaveLNNRequestInfo == NULL) {
            LNN_LOGE(LNN_EVENT, "request info is null");
            (void)SoftBusMutexUnlock(&g_lnnRequestInfo.lock);
            return SOFTBUS_INVALID_PARAM;
        }
    }
    if (IsRepeatLeaveLNNRequest(pkgName, networkId)) {
        LNN_LOGE(LNN_EVENT, "repeat leave lnn request pkgName=%{public}s", pkgName);
        (void)SoftBusMutexUnlock(&g_lnnRequestInfo.lock);
        return SOFTBUS_ALREADY_EXISTED;
    }
    int32_t ret = LnnServerLeave(networkId, pkgName);
    if (ret == SOFTBUS_OK) {
        ret = AddLeaveLNNInfo(pkgName, networkId);
    }
    if (SoftBusMutexUnlock(&g_lnnRequestInfo.lock) != 0) {
        LNN_LOGE(LNN_EVENT, "release lock fail");
    }
    return ret;
}

int32_t LnnIpcGetAllOnlineNodeInfo(const char *pkgName, void **info, uint32_t infoTypeLen,
    int32_t *infoNum)
{
    (void)pkgName;
    if (infoTypeLen != sizeof(NodeBasicInfo)) {
        LNN_LOGE(LNN_EVENT, "infoTypeLen is invalid, infoTypeLen=%{public}d", infoTypeLen);
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnGetAllOnlineNodeInfo((NodeBasicInfo **)info, infoNum);
}

int32_t LnnIpcGetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen)
{
    (void)pkgName;
    (void)infoTypeLen;
    return LnnGetLocalDeviceInfo((NodeBasicInfo *)info);
}

int32_t LnnIpcGetNodeKeyInfo(const char *pkgName, const char *networkId, int32_t key, unsigned char *buf,
    uint32_t len)
{
    if (key == NODE_KEY_BLE_OFFLINE_CODE) {
        LNN_LOGE(LNN_EVENT, "the process has been abandoned");
        return SOFTBUS_INVALID_PARAM;
    }
    (void)pkgName;
    return LnnGetNodeKeyInfo(networkId, key, buf, len);
}

int32_t LnnIpcSetNodeDataChangeFlag(const char *pkgName, const char *networkId,
    uint16_t dataChangeFlag)
{
    (void)pkgName;
    return LnnSetNodeDataChangeFlag(networkId, dataChangeFlag);
}

int32_t LnnIpcGetNodeKeyInfoLen(int32_t key)
{
    return LnnGetNodeKeyInfoLen(key);
}

int32_t LnnIpcStartTimeSync(const char *pkgName,  int32_t callingPid, const char *targetNetworkId,
    int32_t accuracy, int32_t period)
{
    return LnnStartTimeSync(pkgName, callingPid, targetNetworkId, (TimeSyncAccuracy)accuracy, (TimeSyncPeriod)period);
}

int32_t LnnIpcStopTimeSync(const char *pkgName, const char *targetNetworkId, int32_t callingPid)
{
    return LnnStopTimeSync(pkgName, targetNetworkId, callingPid);
}

int32_t LnnIpcPublishLNN(const char *pkgName, const PublishInfo *info)
{
    return LnnPublishService(pkgName, info, false);
}

int32_t LnnIpcStopPublishLNN(const char *pkgName, int32_t publishId)
{
    return LnnUnPublishService(pkgName, publishId, false);
}

int32_t LnnIpcRefreshLNN(const char *pkgName, int32_t callingPid, const SubscribeInfo *info)
{
    (void)callingPid;
    InnerCallback callback = {
        .serverCb = g_discInnerCb,
    };
    return LnnStartDiscDevice(pkgName, info, &callback, false);
}

int32_t LnnIpcStopRefreshLNN(const char *pkgName, int32_t callingPid, int32_t refreshId)
{
    (void)callingPid;
    return LnnStopDiscDevice(pkgName, refreshId, false);
}

int32_t LnnIpcActiveMetaNode(const MetaNodeConfigInfo *info, char *metaNodeId)
{
    return LnnActiveMetaNode(info, metaNodeId);
}

int32_t LnnIpcDeactiveMetaNode(const char *metaNodeId)
{
    return LnnDeactiveMetaNode(metaNodeId);
}

int32_t LnnIpcGetAllMetaNodeInfo(MetaNodeInfo *infos, int32_t *infoNum)
{
    return LnnGetAllMetaNodeInfo(infos, infoNum);
}

int32_t LnnIpcShiftLNNGear(const char *pkgName, const char *callerId, const char *targetNetworkId,
    const GearMode *mode)
{
    return LnnShiftLNNGear(pkgName, callerId, targetNetworkId, mode);
}

int32_t LnnIpcSyncTrustedRelationShip(const char *pkgName, const char *msg, uint32_t msgLen)
{
    (void)pkgName;
    (void)msg;
    (void)msgLen;
    LNN_LOGW(LNN_EVENT, "not implement");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnIpcNotifyJoinResult(void *addr, uint32_t addrTypeLen, const char *networkId,
    int32_t retCode)
{
    if (addr == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    ConnectionAddr *connAddr = (ConnectionAddr *)addr;
    JoinLnnRequestInfo *info = NULL;
    SoftBusList *list = g_lnnRequestInfo.joinLNNRequestInfo;
    if (list == NULL) {
        LNN_LOGE(LNN_EVENT, "request info is null");
        return SOFTBUS_LIST_EMPTY;
    }
    if (SoftBusMutexLock(&g_lnnRequestInfo.lock) != 0) {
        LNN_LOGE(LNN_EVENT, "get lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    while ((info = FindJoinLNNRequest(connAddr)) != NULL) {
        ListDelete(&info->node);
        ClientOnJoinLNNResult(info->pkgName, connAddr, addrTypeLen, networkId, retCode);
        --list->cnt;
        SoftBusFree(info);
    }
    if (SoftBusMutexUnlock(&g_lnnRequestInfo.lock) != 0) {
        LNN_LOGE(LNN_EVENT, "release lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnIpcNotifyLeaveResult(const char *networkId, int32_t retCode)
{
    if (networkId == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    LeaveLnnRequestInfo *info = NULL;
    SoftBusList *list = g_lnnRequestInfo.leaveLNNRequestInfo;
    if (list == NULL) {
        LNN_LOGE(LNN_EVENT, "request info is null");
        return SOFTBUS_LIST_EMPTY;
    }
    if (SoftBusMutexLock(&g_lnnRequestInfo.lock) != 0) {
        LNN_LOGE(LNN_EVENT, "get lock fail");
        return SOFTBUS_LOCK_ERR;
    }

    while ((info = FindLeaveLNNRequest(networkId)) != NULL) {
        ListDelete(&info->node);
        ClientOnLeaveLNNResult(info->pkgName, networkId, retCode);
        --list->cnt;
        SoftBusFree(info);
    }
    if (SoftBusMutexUnlock(&g_lnnRequestInfo.lock) != 0) {
        LNN_LOGE(LNN_EVENT, "release lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnIpcNotifyOnlineState(bool isOnline, void *info, uint32_t infoTypeLen)
{
    return ClinetOnNodeOnlineStateChanged(isOnline, info, infoTypeLen);
}

int32_t LnnIpcNotifyBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type)
{
    return ClinetOnNodeBasicInfoChanged(info, infoTypeLen, type);
}

int32_t LnnIpcNotifyNodeStatusChanged(void *info, uint32_t infoTypeLen, int32_t type)
{
    (void)info;
    (void)infoTypeLen;
    (void)type;
    LNN_LOGI(LNN_EVENT, "not implement");
    return SOFTBUS_OK;
}

int32_t LnnIpcLocalNetworkIdChanged(void)
{
    LNN_LOGI(LNN_EVENT, "not implement");
    return SOFTBUS_OK;
}

int32_t LnnIpcNotifyDeviceTrustedChange(int32_t type, const char *msg, uint32_t msgLen)
{
    (void)type;
    (void)msg;
    (void)msgLen;
    LNN_LOGI(LNN_EVENT, "not implement");
    return SOFTBUS_OK;
}

int32_t LnnIpcNotifyHichainProofException(
    const char *proofInfo, uint32_t proofLen, uint16_t deviceTypeId, int32_t errCode)
{
    (void)proofInfo;
    (void)proofLen;
    (void)deviceTypeId;
    (void)errCode;
    LNN_LOGI(LNN_EVENT, "not implement");
    return SOFTBUS_OK;
}

int32_t LnnIpcNotifyTimeSyncResult(const char *pkgName, int32_t pid, const void *info,
    uint32_t infoTypeLen, int32_t retCode)
{
    return ClientOnTimeSyncResult(pkgName, pid, info, infoTypeLen, retCode);
}

void BusCenterServerDeathCallback(const char *pkgName)
{
    (void)pkgName;
}

int32_t LnnIpcSetDisplayName(const char *pkgName, const char *nameData, uint32_t len)
{
    (void)pkgName;
    (void)nameData;
    (void)len;
    LNN_LOGI(LNN_EVENT, "not implement");
    return SOFTBUS_OK;
}