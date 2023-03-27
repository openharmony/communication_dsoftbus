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

#include "client_trans_session_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_client_frame_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_type_def.h"
#include "softbus_utils.h"

static int32_t CommonInit(const char *pkgName)
{
    if (InitSoftBus(pkgName) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "init softbus failed");
        return SOFTBUS_NETWORK_NOT_INIT;
    }
    if (CheckPackageName(pkgName) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "check packageName failed");
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

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

static int32_t PublishInfoCheck(const PublishInfo *info)
{
    if ((info->mode != DISCOVER_MODE_PASSIVE) && (info->mode != DISCOVER_MODE_ACTIVE)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "mode is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if ((info->medium < AUTO) || (info->medium > COAP)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "medium is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if ((info->freq < LOW) || (info->freq > SUPER_HIGH)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "freq is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if ((info->capabilityData == NULL) && (info->dataLen != 0)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "data is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if ((info->capabilityData != NULL) &&
        ((info->dataLen > MAX_CAPABILITYDATA_LEN) ||
        (strlen((char *)(info->capabilityData)) >= MAX_CAPABILITYDATA_LEN))) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "data exceeds the maximum length");
        return SOFTBUS_INVALID_PARAM;
    }

    return SOFTBUS_OK;
}

static int32_t SubscribeInfoCheck(const SubscribeInfo *info)
{
    if ((info->mode != DISCOVER_MODE_PASSIVE) && (info->mode != DISCOVER_MODE_ACTIVE)) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "mode is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if ((info->medium < AUTO) || (info->medium > COAP)) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "medium is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if ((info->freq < LOW) || (info->freq > SUPER_HIGH)) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "freq is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if ((info->capabilityData == NULL) && (info->dataLen != 0)) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "data is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if ((info->capabilityData != NULL) &&
        ((info->dataLen > MAX_CAPABILITYDATA_LEN) ||
        (strlen((char *)(info->capabilityData)) >= MAX_CAPABILITYDATA_LEN))) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "data exceeds the maximum length");
        return SOFTBUS_INVALID_PARAM;
    }

    return SOFTBUS_OK;
}

int32_t GetAllNodeDeviceInfo(const char *pkgName, NodeBasicInfo **info, int32_t *infoNum)
{
    if (pkgName == NULL || info == NULL || infoNum == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: params are null");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CommonInit(pkgName);
    if (ret != SOFTBUS_OK) {
        return ret;
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: params are null");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CommonInit(pkgName);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return GetLocalNodeDeviceInfoInner(pkgName, info);
}

int32_t GetNodeKeyInfo(const char *pkgName, const char *networkId, NodeDeviceInfoKey key,
    uint8_t *info, int32_t infoLen)
{
    if (pkgName == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: pkgName is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!IsValidString(networkId, NETWORK_ID_BUF_LEN) || info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid params");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CommonInit(pkgName);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return GetNodeKeyInfoInner(pkgName, networkId, key, info, infoLen);
}

int32_t SetNodeDataChangeFlag(const char *pkgName, const char *networkId, uint16_t dataChangeFlag)
{
    if (pkgName == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: pkgName is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!IsValidString(networkId, NETWORK_ID_BUF_LEN)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid params");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CommonInit(pkgName);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return SetNodeDataChangeFlagInner(pkgName, networkId, dataChangeFlag);
}

int32_t JoinLNN(const char *pkgName, ConnectionAddr *target, OnJoinLNNResult cb)
{
    if (pkgName == NULL || target == NULL || cb == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail : params are NULL!");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CommonInit(pkgName);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return JoinLNNInner(pkgName, target, cb);
}

int32_t JoinMetaNode(const char *pkgName, ConnectionAddr *target, CustomData *customData, OnJoinMetaNodeResult cb)
{
    if (pkgName == NULL || target == NULL || customData == NULL || cb == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail : params are NULL!");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CommonInit(pkgName);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (target->type == CONNECTION_ADDR_SESSION) {
        ret = ClientGetChannelBySessionId(target->info.session.sessionId, &target->info.session.channelId,
            &target->info.session.type, NULL);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail : get channel error!");
            return ret;
        }
    }
    return JoinMetaNodeInner(pkgName, target, customData, cb);
}

int32_t LeaveLNN(const char *pkgName, const char *networkId, OnLeaveLNNResult cb)
{
    if (!IsValidString(networkId, NETWORK_ID_BUF_LEN) || cb == NULL || !IsValidString(pkgName, PKG_NAME_SIZE_MAX - 1)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail : networkId or cb is NULL!");
        return SOFTBUS_INVALID_PARAM;
    }
    return LeaveLNNInner(pkgName, networkId, cb);
}

int32_t LeaveMetaNode(const char *pkgName, const char *networkId, OnLeaveMetaNodeResult cb)
{
    if (!IsValidString(networkId, NETWORK_ID_BUF_LEN) || cb == NULL || !IsValidString(pkgName, PKG_NAME_SIZE_MAX - 1)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail : networkId or cb is NULL!");
        return SOFTBUS_INVALID_PARAM;
    }
    return LeaveMetaNodeInner(pkgName, networkId, cb);
}

int32_t RegNodeDeviceStateCb(const char *pkgName, INodeStateCb *callback)
{
    if (pkgName == NULL || IsValidNodeStateCb(callback) == false) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CommonInit(pkgName);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return RegNodeDeviceStateCbInner(pkgName, callback);
}

int32_t UnregNodeDeviceStateCb(INodeStateCb *callback)
{
    if (callback == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para callback = null!");
        return SOFTBUS_INVALID_PARAM;
    }
    return UnregNodeDeviceStateCbInner(callback);
}

int32_t StartTimeSync(const char *pkgName, const char *targetNetworkId, TimeSyncAccuracy accuracy,
    TimeSyncPeriod period, ITimeSyncCb *cb)
{
    if (pkgName == NULL || targetNetworkId == NULL || cb == NULL || cb->onTimeSyncResult == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CommonInit(pkgName);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return StartTimeSyncInner(pkgName, targetNetworkId, accuracy, period, cb);
}

int32_t StopTimeSync(const char *pkgName, const char *targetNetworkId)
{
    if (pkgName == NULL || targetNetworkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CommonInit(pkgName);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return StopTimeSyncInner(pkgName, targetNetworkId);
}

int32_t PublishLNN(const char *pkgName, const PublishInfo *info, const IPublishCb *cb)
{
    if ((pkgName == NULL) || (info == NULL) || (cb == NULL)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CommonInit(pkgName);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (PublishInfoCheck(info) != SOFTBUS_OK) {
        return SOFTBUS_INVALID_PARAM;
    }
    return PublishLNNInner(pkgName, info, cb);
}

int32_t StopPublishLNN(const char *pkgName, int32_t publishId)
{
    if (pkgName == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CommonInit(pkgName);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return StopPublishLNNInner(pkgName, publishId);
}

int32_t RefreshLNN(const char *pkgName, const SubscribeInfo *info, const IRefreshCallback *cb)
{
    if ((pkgName == NULL) || (info == NULL) || (cb == NULL)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CommonInit(pkgName);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (SubscribeInfoCheck(info) != SOFTBUS_OK) {
        return SOFTBUS_INVALID_PARAM;
    }
    return RefreshLNNInner(pkgName, info, cb);
}

int32_t StopRefreshLNN(const char *pkgName, int32_t refreshId)
{
    if (pkgName == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CommonInit(pkgName);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return StopRefreshLNNInner(pkgName, refreshId);
}

int32_t ActiveMetaNode(const char *pkgName, const MetaNodeConfigInfo *info, char *metaNodeId)
{
    if (pkgName == NULL || info == NULL || metaNodeId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid active meta node para");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CommonInit(pkgName);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return ActiveMetaNodeInner(pkgName, info, metaNodeId);
}

int32_t DeactiveMetaNode(const char *pkgName, const char *metaNodeId)
{
    if (pkgName == NULL || metaNodeId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid deactive meta node para");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CommonInit(pkgName);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return DeactiveMetaNodeInner(pkgName, metaNodeId);
}

int32_t GetAllMetaNodeInfo(const char *pkgName, MetaNodeInfo *infos, int32_t *infoNum)
{
    if (pkgName == NULL || infos == NULL || infoNum == NULL || *infoNum > MAX_META_NODE_NUM) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid query meta node info para");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CommonInit(pkgName);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return GetAllMetaNodeInfoInner(pkgName, infos, infoNum);
}

int32_t ShiftLNNGear(const char *pkgName, const char *callerId, const char *targetNetworkId, const GearMode *mode)
{
    if (pkgName == NULL || callerId == NULL || mode == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid shift lnn gear para");
        return SOFTBUS_INVALID_PARAM;
    }
    if (CommonInit(pkgName) != SOFTBUS_OK) {
        return SOFTBUS_INVALID_PARAM;
    }
    size_t len = strnlen(callerId, CALLER_ID_MAX_LEN);
    if (len == 0 || len >= CALLER_ID_MAX_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (targetNetworkId != NULL && strnlen(targetNetworkId, NETWORK_ID_BUF_LEN) != NETWORK_ID_BUF_LEN - 1) {
        return SOFTBUS_INVALID_PARAM;
    }
    return ShiftLNNGearInner(pkgName, callerId, targetNetworkId, mode);
}
