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

#include "bus_center_manager.h"
#include "lnn_connection_addr_utils.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_interface.h"
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
static std::vector<LeaveLnnRequestInfo *> g_leaveLNNRequestInfo;

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

static int32_t AddJoinLNNInfo(const char *pkgName, const ConnectionAddr *addr)
{
    JoinLnnRequestInfo *info = new JoinLnnRequestInfo();
    if (strncpy_s(info->pkgName, PKG_NAME_SIZE_MAX, pkgName, strlen(pkgName)) != EOK) {
        LOG_ERR("copy pkgName fail");
        delete info;
        return SOFTBUS_ERR;
    }
    info->addr = *addr;
    g_joinLNNRequestInfo.push_back(info);
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

static int32_t AddLeaveLNNInfo(const char *pkgName, const char *networkId)
{
    LeaveLnnRequestInfo *info = new LeaveLnnRequestInfo();
    if (strncpy_s(info->pkgName, PKG_NAME_SIZE_MAX, pkgName, strlen(pkgName)) != EOK) {
        LOG_ERR("copy pkgName fail");
        delete info;
        return SOFTBUS_ERR;
    }
    if (strncpy_s(info->networkId, NETWORK_ID_BUF_LEN, networkId, strlen(networkId)) != EOK) {
        LOG_ERR("copy networkId fail");
        delete info;
        return SOFTBUS_ERR;
    }
    g_leaveLNNRequestInfo.push_back(info);
    return SOFTBUS_OK;
}

int32_t LnnIpcServerJoin(const char *pkgName, void *addr, uint32_t addrTypeLen)
{
    if (CheckBusCenterPermission(pkgName) != true) {
        LOG_ERR("ServerJoinLNN no permission!");
        return SOFTBUS_PERMISSION_DENIED;
    }
    ConnectionAddr *connAddr = (ConnectionAddr *)addr;

    (void)addrTypeLen;
    if (pkgName == nullptr || connAddr == nullptr) {
        LOG_ERR("parameters are nullptr!\n");
        return SOFTBUS_ERR;
    }
    std::lock_guard<std::mutex> autoLock(g_lock);
    if (IsRepeatJoinLNNRequest(pkgName, connAddr)) {
        LOG_ERR("repeat join lnn request from: %s", pkgName);
        return SOFTBUS_ERR;
    }
    int32_t ret = LnnServerJoin(connAddr);
    if (ret == SOFTBUS_OK) {
        ret = AddJoinLNNInfo(pkgName, connAddr);
    }
    return ret;
}

int32_t LnnIpcServerLeave(const char *pkgName, const char *networkId)
{
    if (CheckBusCenterPermission(pkgName) != true) {
        LOG_ERR("ServerLeaveLNN no permission!");
        return SOFTBUS_PERMISSION_DENIED;
    }
    if (pkgName == nullptr || networkId == nullptr) {
        LOG_ERR("parameters are nullptr!\n");
        return SOFTBUS_ERR;
    }
    std::lock_guard<std::mutex> autoLock(g_lock);
    if (IsRepeatLeaveLNNRequest(pkgName, networkId)) {
        LOG_ERR("repeat leave lnn request from: %s", pkgName);
        return SOFTBUS_ERR;
    }
    int32_t ret = LnnServerLeave(networkId);
    if (ret == SOFTBUS_OK) {
        ret = AddLeaveLNNInfo(pkgName, networkId);
    }
    return ret;
}

int32_t LnnIpcGetAllOnlineNodeInfo(const char *pkgName, void **info, uint32_t infoTypeLen, int *infoNum)
{
    if (CheckBusCenterPermission(pkgName) != true) {
        LOG_ERR("ServerGetAllOnlineNodeInfo no permission!");
        return SOFTBUS_PERMISSION_DENIED;
    }
    (void)infoTypeLen;
    return LnnGetAllOnlineNodeInfo((NodeBasicInfo **)info, infoNum);
}

int32_t LnnIpcGetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen)
{
    if (CheckBusCenterPermission(pkgName) != true) {
        LOG_ERR("ServerGetLocalDeviceInfo no permission!");
        return SOFTBUS_PERMISSION_DENIED;
    }
    (void)infoTypeLen;
    return LnnGetLocalDeviceInfo((NodeBasicInfo *)info);
}

int32_t LnnIpcGetNodeKeyInfo(const char *pkgName, const char *networkId, int key, unsigned char *buf, uint32_t len)
{
    if (CheckBusCenterPermission(pkgName) != true) {
        LOG_ERR("ServerGetNodeKeyInfo no permission!");
        return SOFTBUS_PERMISSION_DENIED;
    }
    return LnnGetNodeKeyInfo(networkId, key, buf, len);
}

int32_t LnnIpcNotifyJoinResult(void *addr, uint32_t addrTypeLen, const char *networkId, int32_t retCode)
{
    if (addr == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    ConnectionAddr *connAddr = (ConnectionAddr *)addr;
    std::lock_guard<std::mutex> autoLock(g_lock);
    std::vector<JoinLnnRequestInfo *>::iterator iter, iter2;
    for (iter = g_joinLNNRequestInfo.begin(); iter != g_joinLNNRequestInfo.end();) {
        if (!LnnIsSameConnectionAddr(connAddr, &(*iter)->addr)) {
            ++iter;
            continue;
        }
        GetClientProvideInterface()->onJoinLNNResult((*iter)->pkgName, addr, addrTypeLen, networkId, retCode);
        iter2 = iter;
        iter = g_joinLNNRequestInfo.erase(iter);
        delete *iter2;
    }
    return SOFTBUS_OK;
}

int32_t LnnIpcNotifyLeaveResult(const char *networkId, int32_t retCode)
{
    if (networkId == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> autoLock(g_lock);
    std::vector<LeaveLnnRequestInfo *>::iterator iter, iter2;
    for (iter = g_leaveLNNRequestInfo.begin(); iter != g_leaveLNNRequestInfo.end();) {
        if (strncmp(networkId, (*iter)->networkId, strlen(networkId))) {
            ++iter;
            continue;
        }
        GetClientProvideInterface()->onLeaveLNNResult((*iter)->pkgName, networkId, retCode);
        iter2 = iter;
        iter = g_leaveLNNRequestInfo.erase(iter);
        delete *iter2;
    }
    return SOFTBUS_OK;
}

int32_t LnnIpcNotifyOnlineState(bool isOnline, void *info, uint32_t infoTypeLen)
{
    return GetClientProvideInterface()->onNodeOnlineStateChanged(isOnline, info, infoTypeLen);
}

int32_t LnnIpcNotifyBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type)
{
    return GetClientProvideInterface()->onNodeBasicInfoChanged(info, infoTypeLen, type);
}