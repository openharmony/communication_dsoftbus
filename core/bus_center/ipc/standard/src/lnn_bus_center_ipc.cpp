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
#include "lnn_ipc_utils.h"
#include "lnn_meta_node_ledger.h"
#include "lnn_time_sync_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_permission.h"

struct JoinLnnRequestInfo {
    char pkgName[PKG_NAME_SIZE_MAX];
    ConnectionAddr addr;
};

struct LeaveLnnRequestInfo {
    char pkgName[PKG_NAME_SIZE_MAX];
    char networkId[NETWORK_ID_BUF_LEN];
};

static std::mutex g_lock;
static std::vector<JoinLnnRequestInfo *> g_joinLNNRequestInfo;
static std::vector<JoinLnnRequestInfo *> g_joinMetaNodeRequestInfo;
static std::vector<LeaveLnnRequestInfo *> g_leaveLNNRequestInfo;
static std::vector<LeaveLnnRequestInfo *> g_leaveMetaNodeRequestInfo;

static int32_t OnRefreshDeviceFound(const char *pkgName, const DeviceInfo *device,
    const InnerDeviceInfoAddtions *addtions);

static IServerDiscInnerCallback g_discInnerCb = {
    .OnServerDeviceFound = OnRefreshDeviceFound,
};

static bool IsRepeatJoinLNNRequest(const char *pkgName, const ConnectionAddr *addr)
{
    std::vector<JoinLnnRequestInfo *>::iterator iter;
    for (iter = g_joinLNNRequestInfo.begin(); iter != g_joinLNNRequestInfo.end(); ++iter) {
        if (strncmp(pkgName, (*iter)->pkgName, strlen(pkgName)) != 0) {
            continue;
        }
        if (LnnIsSameConnectionAddr(addr, &(*iter)->addr)) {
            return true;
        }
    }
    return false;
}

static bool IsRepeatJoinMetaNodeRequest(const char *pkgName, const ConnectionAddr *addr)
{
    std::vector<JoinLnnRequestInfo *>::iterator iter;
    for (iter = g_joinMetaNodeRequestInfo.begin(); iter != g_joinMetaNodeRequestInfo.end(); ++iter) {
        if (strncmp(pkgName, (*iter)->pkgName, strlen(pkgName)) != 0) {
            continue;
        }
        if (LnnIsSameConnectionAddr(addr, &(*iter)->addr)) {
            return true;
        }
    }
    return false;
}

static int32_t AddJoinLNNInfo(const char *pkgName, const ConnectionAddr *addr)
{
    JoinLnnRequestInfo *info = new (std::nothrow) JoinLnnRequestInfo();
    if (info == nullptr) {
        return SOFTBUS_MEM_ERR;
    }
    if (strncpy_s(info->pkgName, PKG_NAME_SIZE_MAX, pkgName, strlen(pkgName)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy pkgName fail");
        delete info;
        return SOFTBUS_MEM_ERR;
    }
    info->addr = *addr;
    g_joinLNNRequestInfo.push_back(info);
    return SOFTBUS_OK;
}

static int32_t AddJoinMetaNodeInfo(const char *pkgName, const ConnectionAddr *addr)
{
    JoinLnnRequestInfo *info = new (std::nothrow) JoinLnnRequestInfo();
    if (info == nullptr) {
        return SOFTBUS_MEM_ERR;
    }
    if (strncpy_s(info->pkgName, PKG_NAME_SIZE_MAX, pkgName, strlen(pkgName)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy pkgName fail");
        delete info;
        return SOFTBUS_MEM_ERR;
    }
    info->addr = *addr;
    g_joinMetaNodeRequestInfo.push_back(info);
    return SOFTBUS_OK;
}

static bool IsRepeatLeaveLNNRequest(const char *pkgName, const char *networkId)
{
    std::vector<LeaveLnnRequestInfo *>::iterator iter;
    for (iter = g_leaveLNNRequestInfo.begin(); iter != g_leaveLNNRequestInfo.end(); ++iter) {
        if (strncmp(pkgName, (*iter)->pkgName, strlen(pkgName)) != 0) {
            continue;
        }
        if (strncmp(networkId, (*iter)->networkId, strlen(networkId)) == 0) {
            return true;
        }
    }
    return false;
}

static bool IsRepeatLeaveMetaNodeRequest(const char *pkgName, const char *networkId)
{
    std::vector<LeaveLnnRequestInfo *>::iterator iter;
    for (iter = g_leaveMetaNodeRequestInfo.begin(); iter != g_leaveMetaNodeRequestInfo.end(); ++iter) {
        if (strncmp(pkgName, (*iter)->pkgName, strlen(pkgName)) != 0) {
            continue;
        }
        if (strncmp(networkId, (*iter)->networkId, strlen(networkId)) == 0) {
            return true;
        }
    }
    return false;
}

static int32_t AddLeaveLNNInfo(const char *pkgName, const char *networkId)
{
    LeaveLnnRequestInfo *info = new (std::nothrow) LeaveLnnRequestInfo();
    if (info == nullptr) {
        return SOFTBUS_MEM_ERR;
    }
    if (strncpy_s(info->pkgName, PKG_NAME_SIZE_MAX, pkgName, strlen(pkgName)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy pkgName fail");
        delete info;
        return SOFTBUS_MEM_ERR;
    }
    if (strncpy_s(info->networkId, NETWORK_ID_BUF_LEN, networkId, strlen(networkId)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy networkId fail");
        delete info;
        return SOFTBUS_MEM_ERR;
    }
    g_leaveLNNRequestInfo.push_back(info);
    return SOFTBUS_OK;
}

static int32_t AddLeaveMetaNodeInfo(const char *pkgName, const char *networkId)
{
    LeaveLnnRequestInfo *info = new (std::nothrow) LeaveLnnRequestInfo();
    if (info == nullptr) {
        return SOFTBUS_MEM_ERR;
    }
    if (strncpy_s(info->pkgName, PKG_NAME_SIZE_MAX, pkgName, strlen(pkgName)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy pkgName fail");
        delete info;
        return SOFTBUS_MEM_ERR;
    }
    if (strncpy_s(info->networkId, NETWORK_ID_BUF_LEN, networkId, strlen(networkId)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy networkId fail");
        delete info;
        return SOFTBUS_MEM_ERR;
    }
    g_leaveMetaNodeRequestInfo.push_back(info);
    return SOFTBUS_OK;
}

static int32_t OnRefreshDeviceFound(const char *pkgName, const DeviceInfo *device,
    const InnerDeviceInfoAddtions *addtions)
{
    DeviceInfo newDevice;
    if (memcpy_s(&newDevice, sizeof(DeviceInfo), device, sizeof(DeviceInfo)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy new device info error");
        return SOFTBUS_ERR;
    }
    LnnRefreshDeviceOnlineStateAndDevIdInfo(pkgName, &newDevice, addtions);
    return ClientOnRefreshDeviceFound(pkgName, &newDevice, sizeof(DeviceInfo));
}

int32_t LnnIpcServerJoin(const char *pkgName, void *addr, uint32_t addrTypeLen)
{
    ConnectionAddr *connAddr = reinterpret_cast<ConnectionAddr *>(addr);

    (void)addrTypeLen;
    if (pkgName == nullptr || connAddr == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "parameters are nullptr!\n");
        return SOFTBUS_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> autoLock(g_lock);
    if (IsRepeatJoinLNNRequest(pkgName, connAddr)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "repeat join lnn request from: %s", pkgName);
        return SOFTBUS_ALREADY_EXISTED;
    }
    int32_t ret = LnnServerJoin(connAddr);
    if (ret == SOFTBUS_OK) {
        ret = AddJoinLNNInfo(pkgName, connAddr);
    }
    return ret;
}

int32_t MetaNodeIpcServerJoin(const char *pkgName, void *addr, CustomData *customData, uint32_t addrTypeLen)
{
    ConnectionAddr *connAddr = reinterpret_cast<ConnectionAddr *>(addr);

    (void)addrTypeLen;
    if (pkgName == nullptr || connAddr == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "parameters are nullptr!\n");
        return SOFTBUS_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> autoLock(g_lock);
    if (IsRepeatJoinMetaNodeRequest(pkgName, connAddr)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "repeat join lnn request from: %s", pkgName);
        return SOFTBUS_ALREADY_EXISTED;
    }
    int32_t ret = MetaNodeServerJoin(connAddr, customData);
    if (ret == SOFTBUS_OK) {
        ret = AddJoinMetaNodeInfo(pkgName, connAddr);
    }
    return ret;
}

int32_t LnnIpcServerLeave(const char *pkgName, const char *networkId)
{
    if (pkgName == nullptr || networkId == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "parameters are nullptr!\n");
        return SOFTBUS_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> autoLock(g_lock);
    if (IsRepeatLeaveLNNRequest(pkgName, networkId)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "repeat leave lnn request from: %s", pkgName);
        return SOFTBUS_ALREADY_EXISTED;
    }
    int32_t ret = LnnServerLeave(networkId);
    if (ret == SOFTBUS_OK) {
        ret = AddLeaveLNNInfo(pkgName, networkId);
    }
    return ret;
}

int32_t MetaNodeIpcServerLeave(const char *pkgName, const char *networkId)
{
    if (pkgName == nullptr || networkId == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "parameters are nullptr!\n");
        return SOFTBUS_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> autoLock(g_lock);
    if (IsRepeatLeaveMetaNodeRequest(pkgName, networkId)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "repeat leave lnn request from: %s", pkgName);
        return SOFTBUS_ALREADY_EXISTED;
    }
    int32_t ret = MetaNodeServerLeave(networkId);
    if (ret == SOFTBUS_OK) {
        ret = AddLeaveMetaNodeInfo(pkgName, networkId);
    }
    return ret;
}

int32_t LnnIpcGetAllOnlineNodeInfo(const char *pkgName, void **info, uint32_t infoTypeLen, int *infoNum)
{
    if (infoTypeLen != sizeof(NodeBasicInfo)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "infoTypeLen is invalid, infoTypeLen = %d", infoTypeLen);
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnGetAllOnlineNodeInfo(reinterpret_cast<NodeBasicInfo **>(info), infoNum);
}

int32_t LnnIpcGetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen)
{
    (void)infoTypeLen;
    return LnnGetLocalDeviceInfo(reinterpret_cast<NodeBasicInfo *>(info));
}

int32_t LnnIpcGetNodeKeyInfo(const char *pkgName, const char *networkId, int key, unsigned char *buf, uint32_t len)
{
    return LnnGetNodeKeyInfo(networkId, key, buf, len);
}

int32_t LnnIpcSetNodeDataChangeFlag(const char *pkgName, const char *networkId, uint16_t dataChangeFlag)
{
    (void)pkgName;
    return LnnSetNodeDataChangeFlag(networkId, dataChangeFlag);
}

int32_t LnnIpcStartTimeSync(const char *pkgName, const char *targetNetworkId, int32_t accuracy, int32_t period)
{
    return LnnStartTimeSync(pkgName, targetNetworkId, (TimeSyncAccuracy)accuracy, (TimeSyncPeriod)period);
}

int32_t LnnIpcStopTimeSync(const char *pkgName, const char *targetNetworkId)
{
    return LnnStopTimeSync(pkgName, targetNetworkId);
}

int32_t LnnIpcPublishLNN(const char *pkgName, const void *info, uint32_t infoTypeLen)
{
    (void)infoTypeLen;
    PublishInfo pubInfo;
    (void)memset_s(&pubInfo, sizeof(PublishInfo), 0, sizeof(PublishInfo));
    ConvertVoidToPublishInfo(info, &pubInfo);
    int32_t ret = LnnPublishService(pkgName, &pubInfo, false);
    return ret;
}

int32_t LnnIpcStopPublishLNN(const char *pkgName, int32_t publishId)
{
    return LnnUnPublishService(pkgName, publishId, false);
}

int32_t LnnIpcRefreshLNN(const char *pkgName, const void *info, uint32_t infoTypeLen)
{
    (void)infoTypeLen;
    SubscribeInfo subInfo;
    (void)memset_s(&subInfo, sizeof(SubscribeInfo), 0, sizeof(SubscribeInfo));
    ConvertVoidToSubscribeInfo(info, &subInfo);
    SetCallLnnStatus(false);
    InnerCallback callback = {
        .serverCb = g_discInnerCb,
    };
    int32_t ret = LnnStartDiscDevice(pkgName, &subInfo, &callback, false);
    return ret;
}

int32_t LnnIpcStopRefreshLNN(const char *pkgName, int32_t refreshId)
{
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

int32_t LnnIpcShiftLNNGear(const char *pkgName, const char *callerId, const char *targetNetworkId, const GearMode *mode)
{
    return LnnShiftLNNGear(pkgName, callerId, targetNetworkId, mode);
}

int32_t LnnIpcNotifyJoinResult(void *addr, uint32_t addrTypeLen, const char *networkId, int32_t retCode)
{
    if (addr == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    ConnectionAddr *connAddr = reinterpret_cast<ConnectionAddr *>(addr);
    std::lock_guard<std::mutex> autoLock(g_lock);
    std::vector<JoinLnnRequestInfo *>::iterator iter;
    for (iter = g_joinLNNRequestInfo.begin(); iter != g_joinLNNRequestInfo.end();) {
        if (!LnnIsSameConnectionAddr(connAddr, &(*iter)->addr)) {
            ++iter;
            continue;
        }
        ClientOnJoinLNNResult((*iter)->pkgName, addr, addrTypeLen, networkId, retCode);
        delete *iter;
        iter = g_joinLNNRequestInfo.erase(iter);
    }
    return SOFTBUS_OK;
}

int32_t MetaNodeIpcNotifyJoinResult(void *addr, uint32_t addrTypeLen, const char *networkId, int32_t retCode)
{
    if (addr == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    ConnectionAddr *connAddr = reinterpret_cast<ConnectionAddr *>(addr);
    std::lock_guard<std::mutex> autoLock(g_lock);
    std::vector<JoinLnnRequestInfo *>::iterator iter;
    for (iter = g_joinMetaNodeRequestInfo.begin(); iter != g_joinMetaNodeRequestInfo.end();) {
        if (!LnnIsSameConnectionAddr(connAddr, &(*iter)->addr)) {
            ++iter;
            continue;
        }
        ClientOnJoinMetaNodeResult((*iter)->pkgName, addr, addrTypeLen, networkId, retCode);
        delete *iter;
        iter = g_joinMetaNodeRequestInfo.erase(iter);
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
        ClientOnLeaveLNNResult((*iter)->pkgName, networkId, retCode);
        delete *iter;
        iter = g_leaveLNNRequestInfo.erase(iter);
    }
    return SOFTBUS_OK;
}

int32_t MetaNodeIpcNotifyLeaveResult(const char *networkId, int32_t retCode)
{
    if (networkId == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> autoLock(g_lock);
    std::vector<LeaveLnnRequestInfo *>::iterator iter;
    for (iter = g_leaveMetaNodeRequestInfo.begin(); iter != g_leaveMetaNodeRequestInfo.end();) {
        if (strncmp(networkId, (*iter)->networkId, strlen(networkId))) {
            ++iter;
            continue;
        }
        ClientOnLeaveMetaNodeResult((*iter)->pkgName, networkId, retCode);
        delete *iter;
        iter = g_leaveMetaNodeRequestInfo.erase(iter);
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

int32_t LnnIpcNotifyTimeSyncResult(const char *pkgName, const void *info, uint32_t infoTypeLen, int32_t retCode)
{
    return ClientOnTimeSyncResult(pkgName, info, infoTypeLen, retCode);
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

void BusCenterServerDeathCallback(const char *pkgName)
{
    if (pkgName == nullptr) {
        return;
    }
    RemoveJoinRequestInfoByPkgName(pkgName);
    RemoveLeaveRequestInfoByPkgName(pkgName);
}