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

#include <cstring>
#include <mutex>
#include <securec.h>
#include <vector>

#include "bus_center_client_proxy.h"
#include "bus_center_manager.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_log.h"
#include "lnn_meta_node_ledger.h"
#include "lnn_time_sync_manager.h"
#include "lnn_meta_node_interface.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_permission.h"

struct JoinLnnRequestInfo {
    char pkgName[PKG_NAME_SIZE_MAX];
    int32_t pid;
    ConnectionAddr addr;
};

struct RefreshLnnRequestInfo {
    char pkgName[PKG_NAME_SIZE_MAX];
    int32_t pid;
    int32_t subscribeId;
};

struct LeaveLnnRequestInfo {
    char pkgName[PKG_NAME_SIZE_MAX];
    int32_t pid;
    char networkId[NETWORK_ID_BUF_LEN];
};

static std::mutex g_lock;
static std::vector<JoinLnnRequestInfo *> g_joinLNNRequestInfo;
static std::vector<LeaveLnnRequestInfo *> g_leaveLNNRequestInfo;
static std::vector<RefreshLnnRequestInfo *> g_refreshLnnRequestInfo;

static int32_t OnRefreshDeviceFound(const char *pkgName, const DeviceInfo *device,
    const InnerDeviceInfoAddtions *addtions);

static IServerDiscInnerCallback g_discInnerCb = {
    .OnServerDeviceFound = OnRefreshDeviceFound,
};

static bool IsRepeatJoinLNNRequest(const char *pkgName, int32_t callingPid, const ConnectionAddr *addr)
{
    for (const auto &iter : g_joinLNNRequestInfo) {
        if (strncmp(pkgName, (*iter).pkgName, strlen(pkgName)) != 0 || (*iter).pid != callingPid) {
            continue;
        }
        if (LnnIsSameConnectionAddr(addr, &(*iter).addr, false)) {
            return true;
        }
    }
    return false;
}

static int32_t AddJoinLNNInfo(const char *pkgName, int32_t callingPid, const ConnectionAddr *addr)
{
    JoinLnnRequestInfo *info = new (std::nothrow) JoinLnnRequestInfo();
    if (info == nullptr) {
        return SOFTBUS_MEM_ERR;
    }
    if (strncpy_s(info->pkgName, PKG_NAME_SIZE_MAX, pkgName, strlen(pkgName)) != EOK) {
        LNN_LOGE(LNN_EVENT, "copy pkgName fail");
        delete info;
        return SOFTBUS_MEM_ERR;
    }
    info->pid = callingPid;
    info->addr = *addr;
    g_joinLNNRequestInfo.push_back(info);
    return SOFTBUS_OK;
}

static bool IsRepeatLeaveLNNRequest(const char *pkgName, int32_t callingPid, const char *networkId)
{
    for (const auto &iter : g_leaveLNNRequestInfo) {
        if (strncmp(pkgName, (*iter).pkgName, strlen(pkgName)) != 0 || (*iter).pid != callingPid) {
            continue;
        }
        if (strncmp(networkId, (*iter).networkId, strlen(networkId)) == 0) {
            return true;
        }
    }
    return false;
}

static int32_t AddLeaveLNNInfo(const char *pkgName, int32_t callingPid, const char *networkId)
{
    LeaveLnnRequestInfo *info = new (std::nothrow) LeaveLnnRequestInfo();
    if (info == nullptr) {
        return SOFTBUS_MEM_ERR;
    }
    if (strncpy_s(info->pkgName, PKG_NAME_SIZE_MAX, pkgName, strlen(pkgName)) != EOK) {
        LNN_LOGE(LNN_EVENT, "copy pkgName fail");
        delete info;
        return SOFTBUS_MEM_ERR;
    }
    if (strncpy_s(info->networkId, NETWORK_ID_BUF_LEN, networkId, strlen(networkId)) != EOK) {
        LNN_LOGE(LNN_EVENT, "copy networkId fail");
        delete info;
        return SOFTBUS_MEM_ERR;
    }
    info->pid = callingPid;
    g_leaveLNNRequestInfo.push_back(info);
    return SOFTBUS_OK;
}

static int32_t OnRefreshDeviceFound(const char *pkgName, const DeviceInfo *device,
    const InnerDeviceInfoAddtions *addtions)
{
    DeviceInfo newDevice;
    if (memcpy_s(&newDevice, sizeof(DeviceInfo), device, sizeof(DeviceInfo)) != EOK) {
        LNN_LOGE(LNN_EVENT, "copy new device info error");
        return SOFTBUS_MEM_ERR;
    }
    std::lock_guard<std::mutex> autoLock(g_lock);
    for (const auto &iter : g_refreshLnnRequestInfo) {
        if (strncmp(pkgName, (*iter).pkgName, strlen(pkgName)) != 0) {
            continue;
        }
        LnnRefreshDeviceOnlineStateAndDevIdInfo(pkgName, &newDevice, addtions);
        (void)ClientOnRefreshDeviceFound(pkgName, (*iter).pid, &newDevice, sizeof(DeviceInfo));
    }
    return SOFTBUS_OK;
}

int32_t LnnIpcServerJoin(const char *pkgName, int32_t callingPid, void *addr, uint32_t addrTypeLen)
{
    ConnectionAddr *connAddr = reinterpret_cast<ConnectionAddr *>(addr);

    if (pkgName == nullptr || connAddr == nullptr) {
        LNN_LOGE(LNN_EVENT, "parameters are nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    if (addrTypeLen != sizeof(ConnectionAddr)) {
        LNN_LOGE(LNN_EVENT, "addr is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> autoLock(g_lock);
    if (IsRepeatJoinLNNRequest(pkgName, callingPid, connAddr)) {
        LNN_LOGE(LNN_EVENT, "repeat join lnn request pkgName=%{public}s", pkgName);
        return SOFTBUS_ALREADY_EXISTED;
    }
    int32_t ret = LnnServerJoin(connAddr, pkgName);
    if (ret == SOFTBUS_OK) {
        ret = AddJoinLNNInfo(pkgName, callingPid, connAddr);
    }
    return ret;
}

int32_t LnnIpcServerLeave(const char *pkgName, int32_t callingPid, const char *networkId)
{
    if (pkgName == nullptr || networkId == nullptr) {
        LNN_LOGE(LNN_EVENT, "parameters are nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> autoLock(g_lock);
    if (IsRepeatLeaveLNNRequest(pkgName, callingPid, networkId)) {
        LNN_LOGE(LNN_EVENT, "repeat leave lnn request pkgName=%{public}s", pkgName);
        return SOFTBUS_ALREADY_EXISTED;
    }
    int32_t ret = LnnServerLeave(networkId, pkgName);
    if (ret == SOFTBUS_OK) {
        ret = AddLeaveLNNInfo(pkgName, callingPid, networkId);
    }
    return ret;
}

int32_t LnnIpcGetAllOnlineNodeInfo(const char *pkgName, void **info, uint32_t infoTypeLen,
    int *infoNum)
{
    if (infoTypeLen != sizeof(NodeBasicInfo)) {
        LNN_LOGE(LNN_EVENT, "infoTypeLen is invalid, infoTypeLen=%{public}d", infoTypeLen);
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnGetAllOnlineNodeInfo(reinterpret_cast<NodeBasicInfo **>(info), infoNum);
}

int32_t LnnIpcGetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen)
{
    (void)infoTypeLen;
    return LnnGetLocalDeviceInfo(reinterpret_cast<NodeBasicInfo *>(info));
}

int32_t LnnIpcGetNodeKeyInfo(const char *pkgName, const char *networkId, int key, unsigned char *buf,
    uint32_t len)
{
    return LnnGetNodeKeyInfo(networkId, key, buf, len);
}

int32_t LnnIpcSetNodeDataChangeFlag(const char *pkgName, const char *networkId,
    uint16_t dataChangeFlag)
{
    (void)pkgName;
    return LnnSetNodeDataChangeFlag(networkId, dataChangeFlag);
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

static bool IsRepeatRfreshLnnRequest(const char *pkgName, int32_t callingPid)
{
    std::lock_guard<std::mutex> autoLock(g_lock);
    for (const auto &iter : g_refreshLnnRequestInfo) {
        if (strncmp(pkgName, (*iter).pkgName, strlen(pkgName)) == 0 && (*iter).pid == callingPid) {
            return true;
        }
    }
    return false;
}

static int32_t AddRefreshLnnInfo(const char *pkgName, int32_t callingPid, int32_t subscribeId)
{
    RefreshLnnRequestInfo *info = new (std::nothrow) RefreshLnnRequestInfo();
    if (info == nullptr) {
        return SOFTBUS_MEM_ERR;
    }
    if (strncpy_s(info->pkgName, PKG_NAME_SIZE_MAX, pkgName, strlen(pkgName)) != EOK) {
        LNN_LOGE(LNN_EVENT, "copy pkgName fail");
        delete info;
        return SOFTBUS_MEM_ERR;
    }
    info->pid = callingPid;
    info->subscribeId = subscribeId;
    std::lock_guard<std::mutex> autoLock(g_lock);
    g_refreshLnnRequestInfo.push_back(info);
    return SOFTBUS_OK;
}

static int32_t DeleteRefreshLnnInfo(const char *pkgName, int32_t callingPid)
{
    std::lock_guard<std::mutex> autoLock(g_lock);
    std::vector<RefreshLnnRequestInfo *>::iterator iter;
    for (iter = g_refreshLnnRequestInfo.begin(); iter != g_refreshLnnRequestInfo.end();) {
        if (strncmp(pkgName, (*iter)->pkgName, strlen(pkgName)) != 0 || (*iter)->pid != callingPid) {
            ++iter;
            continue;
        }
        delete *iter;
        iter = g_refreshLnnRequestInfo.erase(iter);
    }
    return SOFTBUS_OK;
}

int32_t LnnIpcRefreshLNN(const char *pkgName, int32_t callingPid, const SubscribeInfo *info)
{
    if (pkgName == nullptr || info == nullptr) {
        LNN_LOGE(LNN_EVENT, "parameters are nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    if (IsRepeatRfreshLnnRequest(pkgName, callingPid)) {
        LNN_LOGD(LNN_EVENT, "repeat refresh lnn request pkgName=%{public}s", pkgName);
    } else {
        (void)AddRefreshLnnInfo(pkgName, callingPid, info->subscribeId);
    }
    InnerCallback callback = {
        .serverCb = g_discInnerCb,
    };
    return LnnStartDiscDevice(pkgName, info, &callback, false);
}

int32_t LnnIpcStopRefreshLNN(const char *pkgName, int32_t callingPid, int32_t refreshId)
{
    if (IsRepeatRfreshLnnRequest(pkgName, callingPid) && (DeleteRefreshLnnInfo(pkgName, callingPid) != SOFTBUS_OK)) {
        LNN_LOGE(LNN_EVENT, "stop refresh lnn, clean info fail");
        return SOFTBUS_ERR;
    }
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

int32_t LnnIpcNotifyJoinResult(void *addr, uint32_t addrTypeLen, const char *networkId,
    int32_t retCode)
{
    if (addr == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    ConnectionAddr *connAddr = reinterpret_cast<ConnectionAddr *>(addr);
    std::lock_guard<std::mutex> autoLock(g_lock);
    std::vector<JoinLnnRequestInfo *>::iterator iter;
    for (iter = g_joinLNNRequestInfo.begin(); iter != g_joinLNNRequestInfo.end();) {
        if (!LnnIsSameConnectionAddr(connAddr, &(*iter)->addr, false)) {
            ++iter;
            continue;
        }
        PkgNameAndPidInfo info;
        info.pid = (*iter)->pid;
        if (strcpy_s(info.pkgName, PKG_NAME_SIZE_MAX, (*iter)->pkgName) != EOK) {
            LNN_LOGE(LNN_EVENT, "strcpy_s fail");
            continue;
        }
        ClientOnJoinLNNResult(&info, addr, addrTypeLen, networkId, retCode);
        delete *iter;
        iter = g_joinLNNRequestInfo.erase(iter);
    }
    return SOFTBUS_OK;
}

int32_t LnnIpcNotifyLeaveResult(const char *networkId, int32_t retCode)
{
    if (networkId == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> autoLock(g_lock);
    std::vector<LeaveLnnRequestInfo *>::iterator iter;
    for (iter = g_leaveLNNRequestInfo.begin(); iter != g_leaveLNNRequestInfo.end();) {
        if (strncmp(networkId, (*iter)->networkId, strlen(networkId))) {
            ++iter;
            continue;
        }
        ClientOnLeaveLNNResult((*iter)->pkgName, (*iter)->pid, networkId, retCode);
        delete *iter;
        iter = g_leaveLNNRequestInfo.erase(iter);
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

int32_t LnnIpcNotifyTimeSyncResult(const char *pkgName, int32_t pid, const void *info,
    uint32_t infoTypeLen, int32_t retCode)
{
    return ClientOnTimeSyncResult(pkgName, pid, info, infoTypeLen, retCode);
}

static void RemoveJoinRequestInfoByPkgName(const char *pkgName)
{
    std::lock_guard<std::mutex> autoLock(g_lock);
    std::vector<JoinLnnRequestInfo *>::iterator iter;
    for (iter = g_joinLNNRequestInfo.begin(); iter != g_joinLNNRequestInfo.end();) {
        if (strncmp(pkgName, (*iter)->pkgName, strlen(pkgName))) {
            ++iter;
            continue;
        }
        delete *iter;
        iter = g_joinLNNRequestInfo.erase(iter);
    }
}

static void RemoveLeaveRequestInfoByPkgName(const char *pkgName)
{
    std::lock_guard<std::mutex> autoLock(g_lock);
    std::vector<LeaveLnnRequestInfo *>::iterator iter;
    for (iter = g_leaveLNNRequestInfo.begin(); iter != g_leaveLNNRequestInfo.end();) {
        if (strncmp(pkgName, (*iter)->pkgName, strlen(pkgName))) {
            ++iter;
            continue;
        }
        delete *iter;
        iter = g_leaveLNNRequestInfo.erase(iter);
    }
}

static void RemoveRefreshRequestInfoByPkgName(const char *pkgName)
{
    std::lock_guard<std::mutex> autoLock(g_lock);
    std::vector<RefreshLnnRequestInfo *>::iterator iter;
    for (iter = g_refreshLnnRequestInfo.begin(); iter != g_refreshLnnRequestInfo.end();) {
        if (strncmp(pkgName, (*iter)->pkgName, strlen(pkgName)) != 0) {
            ++iter;
            continue;
        }
        delete *iter;
        iter = g_refreshLnnRequestInfo.erase(iter);
    }
}

void BusCenterServerDeathCallback(const char *pkgName)
{
    if (pkgName == nullptr) {
        return;
    }
    RemoveJoinRequestInfoByPkgName(pkgName);
    RemoveLeaveRequestInfoByPkgName(pkgName);
    RemoveRefreshRequestInfoByPkgName(pkgName);
}