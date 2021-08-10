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

#include "client_bus_center.h"

#include <string.h>

#include "softbus_adapter_mem.h"
#include "softbus_client_frame_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_type_def.h"
#include "softbus_utils.h"

static bool IsValidNodeStateCb(INodeStateCb *callback)
{
    if (callback == NULL) {
        return false;
    }
    if (callback->events == 0) {
        return false;
    }
    if ((callback->events & EVENT_NODE_STATE_ONLINE) != 0 &&
        callback->onNodeOnline == NULL) {
        return false;
    }
    if ((callback->events & EVENT_NODE_STATE_OFFLINE) != 0 &&
        callback->onNodeOffline == NULL) {
        return false;
    }
    if ((callback->events & EVENT_NODE_STATE_INFO_CHANGED) != 0 &&
        callback->onNodeBasicInfoChanged == NULL) {
        return false;
    }
    return true;
}

int32_t GetAllNodeDeviceInfo(const char *pkgName, NodeBasicInfo **info, int32_t *infoNum)
{
    if (pkgName == NULL || info == NULL || infoNum == NULL) {
        LOG_ERR("fail: params are null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (InitSoftBus(pkgName) != SOFTBUS_OK) {
        LOG_ERR("fail: init softbus");
        return SOFTBUS_ERR;
    }
    if (CheckPackageName(pkgName) != SOFTBUS_OK) {
        LOG_ERR("check packageName failed");
        return SOFTBUS_INVALID_PARAM;
    }
    return GetAllNodeDeviceInfoInner(pkgName, info, infoNum);
}

void FreeNodeInfo(NodeBasicInfo *info)
{
    if (info == NULL) {
        return;
    }
    SoftBusFree(info);
}

int32_t GetLocalNodeDeviceInfo(const char *pkgName, NodeBasicInfo *info)
{
    if (pkgName == NULL || info == NULL) {
        LOG_ERR("fail: params are null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (InitSoftBus(pkgName) != SOFTBUS_OK) {
        LOG_ERR("fail: init softbus");
        return SOFTBUS_ERR;
    }
    if (CheckPackageName(pkgName) != SOFTBUS_OK) {
        LOG_ERR("check packageName failed");
        return SOFTBUS_INVALID_PARAM;
    }
    return GetLocalNodeDeviceInfoInner(pkgName, info);
}

int32_t GetNodeKeyInfo(const char *pkgName, const char *networkId, NodeDeivceInfoKey key,
    uint8_t *info, int32_t infoLen)
{
    if (pkgName == NULL) {
        LOG_ERR("fail: pkgName is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (InitSoftBus(pkgName) != SOFTBUS_OK) {
        LOG_ERR("fail: init softbus");
        return SOFTBUS_ERR;
    }
    if (!IsValidString(networkId, NETWORK_ID_BUF_LEN) || info == NULL) {
        LOG_ERR("invalid params");
        return SOFTBUS_INVALID_PARAM;
    }
    if (CheckPackageName(pkgName) != SOFTBUS_OK) {
        LOG_ERR("check packageName failed");
        return SOFTBUS_INVALID_PARAM;
    }
    return GetNodeKeyInfoInner(pkgName, networkId, key, info, infoLen);
}

int32_t JoinLNN(const char *pkgName, ConnectionAddr *target, OnJoinLNNResult cb)
{
    if (pkgName == NULL || target == NULL || cb == NULL) {
        LOG_ERR("fail : params are NULL!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (InitSoftBus(pkgName) != SOFTBUS_OK) {
        LOG_ERR("fail: init softbus");
        return SOFTBUS_ERR;
    }
    if (CheckPackageName(pkgName) != SOFTBUS_OK) {
        LOG_ERR("check packageName failed");
        return SOFTBUS_INVALID_PARAM;
    }
    return JoinLNNInner(pkgName, target, cb);
}

int32_t LeaveLNN(const char *networkId, OnLeaveLNNResult cb)
{
    if (networkId == NULL || cb == NULL) {
        LOG_ERR("fail : networkId or cb is NULL!");
        return SOFTBUS_INVALID_PARAM;
    }
    char clientName[PKG_NAME_SIZE_MAX];
    int ret = GetSoftBusClientName(clientName, PKG_NAME_SIZE_MAX);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("LeaveLNN get client name failed!");
        return SOFTBUS_ERR;
    }
    return LeaveLNNInner(clientName, networkId, cb);
}

int32_t RegNodeDeviceStateCb(const char *pkgName, INodeStateCb *callback)
{
    if (pkgName == NULL || IsValidNodeStateCb(callback) == false) {
        LOG_ERR("fail: invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    if (InitSoftBus(pkgName) != SOFTBUS_OK) {
        LOG_ERR("fail: init softbus");
        return SOFTBUS_ERR;
    }
    if (CheckPackageName(pkgName) != SOFTBUS_OK) {
        LOG_ERR("check packageName failed");
        return SOFTBUS_INVALID_PARAM;
    }
    return RegNodeDeviceStateCbInner(pkgName, callback);
}

int32_t UnregNodeDeviceStateCb(INodeStateCb *callback)
{
    if (callback == NULL) {
        LOG_ERR("para callback = null!");
        return SOFTBUS_INVALID_PARAM;
    }
    return UnregNodeDeviceStateCbInner(callback);
}
