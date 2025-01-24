/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include <securec.h>
#include <string.h>

#include "client_bus_center_manager.h"
#include "data_level.h"
#include "client_trans_session_manager.h"
#include "lnn_event.h"
#include "lnn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_client_frame_manager.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_type_def.h"
#include "softbus_utils.h"

static const char *g_dbPkgName = "distributeddata-default";

static int32_t CommonInit(const char *pkgName)
{
    if (InitSoftBus(pkgName) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "init softbus failed");
        return SOFTBUS_NETWORK_NOT_INIT;
    }
    if (CheckPackageName(pkgName) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "check packageName failed");
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
    if ((callback->events & EVENT_NODE_STATUS_CHANGED) != 0 &&
        callback->onNodeStatusChanged == NULL) {
        return false;
    }
    if ((callback->events & EVENT_NODE_HICHAIN_PROOF_EXCEPTION) != 0 &&
        callback->onHichainProofException == NULL) {
        return false;
    }
    return true;
}

static int32_t PublishInfoCheck(const PublishInfo *info)
{
    if ((info->mode != DISCOVER_MODE_PASSIVE) && (info->mode != DISCOVER_MODE_ACTIVE)) {
        LNN_LOGE(LNN_STATE, "mode is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if ((info->medium < AUTO) || (info->medium > COAP)) {
        LNN_LOGE(LNN_STATE, "medium is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if ((info->freq < LOW) || (info->freq >= FREQ_BUTT)) {
        LNN_LOGE(LNN_STATE, "freq is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (info->capability == NULL) {
        LNN_LOGE(LNN_STATE, "capability is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if ((info->capabilityData == NULL) && (info->dataLen != 0)) {
        LNN_LOGE(LNN_STATE, "data is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (info->dataLen == 0) {
        return SOFTBUS_OK;
    }
    if ((info->capabilityData != NULL) &&
        ((info->dataLen > MAX_CAPABILITYDATA_LEN) ||
        (strnlen((char *)(info->capabilityData), MAX_CAPABILITYDATA_LEN) == MAX_CAPABILITYDATA_LEN))) {
        LNN_LOGE(LNN_STATE, "data exceeds the maximum length");
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

static int32_t SubscribeInfoCheck(const SubscribeInfo *info)
{
    if ((info->mode != DISCOVER_MODE_PASSIVE) && (info->mode != DISCOVER_MODE_ACTIVE)) {
        LNN_LOGE(LNN_STATE, "mode is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if ((info->medium < AUTO) || (info->medium > USB)) {
        LNN_LOGE(LNN_STATE, "medium is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if ((info->medium == USB) && (info->mode == DISCOVER_MODE_ACTIVE)) {
        LNN_LOGE(LNN_STATE, "usb is not support active mode");
        return SOFTBUS_INVALID_PARAM;
    }
    if ((info->freq < LOW) || (info->freq >= FREQ_BUTT)) {
        LNN_LOGE(LNN_STATE, "freq is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (info->capability == NULL) {
        LNN_LOGE(LNN_STATE, "capability is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if ((info->capabilityData == NULL) && (info->dataLen != 0)) {
        LNN_LOGE(LNN_STATE, "data is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (info->dataLen == 0) {
        return SOFTBUS_OK;
    }
    if ((info->capabilityData != NULL) &&
        ((info->dataLen > MAX_CAPABILITYDATA_LEN) ||
        (strnlen((char *)(info->capabilityData), MAX_CAPABILITYDATA_LEN) == MAX_CAPABILITYDATA_LEN))) {
        LNN_LOGE(LNN_STATE, "data exceeds the maximum length");
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

static void DfxRecordSdkJoinLnnEnd(const char *packageName, int32_t reason)
{
    if (reason == SOFTBUS_OK) {
        return;
    }

    LnnEventExtra extra = { 0 };
    LnnEventExtraInit(&extra);
    extra.errcode = reason;
    extra.result = EVENT_STAGE_RESULT_FAILED;

    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
    if (packageName != NULL && IsValidString(packageName, PKG_NAME_SIZE_MAX - 1) && strncpy_s(pkgName,
        PKG_NAME_SIZE_MAX, packageName, PKG_NAME_SIZE_MAX - 1) == EOK) {
        extra.callerPkg = pkgName;
    }
    LNN_EVENT(EVENT_SCENE_LNN, EVENT_STAGE_LNN_JOIN_SDK, extra);
}

static void DfxRecordSdkLeaveLnnEnd(const char *packageName, int32_t reason)
{
    if (reason == SOFTBUS_OK) {
        return;
    }

    LnnEventExtra extra = { 0 };
    LnnEventExtraInit(&extra);
    extra.errcode = reason;
    extra.result = EVENT_STAGE_RESULT_FAILED;

    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
    if (packageName != NULL && IsValidString(packageName, PKG_NAME_SIZE_MAX - 1) && strncpy_s(pkgName,
        PKG_NAME_SIZE_MAX, packageName, PKG_NAME_SIZE_MAX - 1) == EOK) {
        extra.callerPkg = pkgName;
    }
    LNN_EVENT(EVENT_SCENE_LNN, EVENT_STAGE_LNN_LEAVE_SDK, extra);
}

static void DfxRecordSdkShiftGearStart(const char *packageName, const GearMode *mode)
{
    LnnEventExtra extra = { 0 };
    LnnEventExtraInit(&extra);
    if (mode != NULL) {
        extra.gearCycle = mode->cycle;
        extra.gearDuration = mode->duration;
    }
    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
    if (packageName != NULL && IsValidString(packageName, PKG_NAME_SIZE_MAX - 1) && strncpy_s(pkgName,
        PKG_NAME_SIZE_MAX, packageName, PKG_NAME_SIZE_MAX - 1) == EOK) {
        extra.callerPkg = pkgName;
    }
    LNN_EVENT(EVENT_SCENE_LNN, EVENT_STAGE_LNN_SHIFT_GEAR, extra);
}

static void DfxRecordLnnDiscServerEnd(int32_t serverType, const char *packageName, int32_t reason)
{
    if (reason == SOFTBUS_OK) {
        return;
    }

    LnnEventExtra extra = { 0 };
    LnnEventExtraInit(&extra);
    extra.discServerType = serverType;
    extra.errcode = reason;
    extra.result = EVENT_STAGE_RESULT_FAILED;

    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
    if (packageName != NULL && IsValidString(packageName, PKG_NAME_SIZE_MAX - 1) && strncpy_s(pkgName,
        PKG_NAME_SIZE_MAX, packageName, PKG_NAME_SIZE_MAX - 1) == EOK) {
        extra.callerPkg = pkgName;
    }
    LNN_EVENT(EVENT_SCENE_LNN, EVENT_STAGE_LNN_DISC_SDK, extra);
}

static void DfxRecordRegNodeStart(const char *packageName)
{
    LnnEventExtra extra = { 0 };
    LnnEventExtraInit(&extra);
    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
    if (packageName != NULL && IsValidString(packageName, PKG_NAME_SIZE_MAX - 1) && strncpy_s(pkgName,
        PKG_NAME_SIZE_MAX, packageName, PKG_NAME_SIZE_MAX - 1) == EOK) {
        extra.callerPkg = pkgName;
    }
    LNN_EVENT(EVENT_SCENE_LNN, EVENT_STAGE_LNN_REG_NODE, extra);
}

int32_t GetAllNodeDeviceInfo(const char *pkgName, NodeBasicInfo **info, int32_t *infoNum)
{
    if (pkgName == NULL || info == NULL || infoNum == NULL) {
        LNN_LOGE(LNN_STATE, "params are null");
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
        LNN_LOGE(LNN_STATE, "params are null");
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
    if (pkgName == NULL || infoLen <= 0) {
        LNN_LOGE(LNN_STATE, "pkgName is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!IsValidString(networkId, NETWORK_ID_BUF_LEN) || info == NULL) {
        LNN_LOGE(LNN_STATE, "invalid params");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CommonInit(pkgName);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    (void)memset_s(info, infoLen, 0, infoLen);
    return GetNodeKeyInfoInner(pkgName, networkId, key, info, infoLen);
}

int32_t SetNodeDataChangeFlag(const char *pkgName, const char *networkId, uint16_t dataChangeFlag)
{
    if (pkgName == NULL) {
        LNN_LOGE(LNN_STATE, "pkgName is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!IsValidString(networkId, NETWORK_ID_BUF_LEN)) {
        LNN_LOGE(LNN_STATE, "invalid params");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CommonInit(pkgName);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return SetNodeDataChangeFlagInner(pkgName, networkId, dataChangeFlag);
}

int32_t RegDataLevelChangeCb(const char *pkgName, IDataLevelCb *callback)
{
    if (pkgName == NULL || callback == NULL) {
        LNN_LOGE(LNN_STATE, "pkgName or callback is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strcmp(g_dbPkgName, pkgName) != 0) {
        LNN_LOGE(LNN_STATE, "pkgName is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CommonInit(pkgName);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "CommonInit failed");
        return ret;
    }
    return RegDataLevelChangeCbInner(pkgName, callback);
}

int32_t UnregDataLevelChangeCb(const char *pkgName)
{
    if (pkgName == NULL) {
        LNN_LOGE(LNN_STATE, "pkgName is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strcmp(g_dbPkgName, pkgName) != 0) {
        LNN_LOGE(LNN_STATE, "pkgName is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    return UnregDataLevelChangeCbInner(pkgName);
}

int32_t SetDataLevel(const DataLevel *dataLevel)
{
    if (dataLevel == NULL) {
        LNN_LOGE(LNN_STATE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    LNN_LOGI(LNN_STATE, "SetDataLevel, dynamic: %{public}hu, static: %{public}hu, "
        "switch: %{public}u, switchLen: %{public}hu", dataLevel->dynamicLevel, dataLevel->staticLevel,
        dataLevel->switchLevel, dataLevel->switchLength);
    return SetDataLevelInner(dataLevel);
}

int32_t JoinLNN(const char *pkgName, ConnectionAddr *target, OnJoinLNNResult cb)
{
    if (pkgName == NULL || target == NULL || cb == NULL) {
        DfxRecordSdkJoinLnnEnd(pkgName, SOFTBUS_INVALID_PARAM);
        LNN_LOGE(LNN_STATE, "params are NULL");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CommonInit(pkgName);
    if (ret != SOFTBUS_OK) {
        DfxRecordSdkJoinLnnEnd(pkgName, ret);
        return ret;
    }
    ret = JoinLNNInner(pkgName, target, cb);
    DfxRecordSdkJoinLnnEnd(pkgName, ret);
    return ret;
}

int32_t LeaveLNN(const char *pkgName, const char *networkId, OnLeaveLNNResult cb)
{
    if (!IsValidString(networkId, NETWORK_ID_BUF_LEN) || cb == NULL || !IsValidString(pkgName, PKG_NAME_SIZE_MAX - 1)) {
        DfxRecordSdkLeaveLnnEnd(pkgName, SOFTBUS_INVALID_PARAM);
        LNN_LOGE(LNN_STATE, "networkId or cb is NULL");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = LeaveLNNInner(pkgName, networkId, cb);
    DfxRecordSdkLeaveLnnEnd(pkgName, ret);
    return ret;
}

int32_t RegNodeDeviceStateCb(const char *pkgName, INodeStateCb *callback)
{
    DfxRecordRegNodeStart(pkgName);
    if (pkgName == NULL || IsValidNodeStateCb(callback) == false) {
        LNN_LOGE(LNN_STATE, "invalid parameters");
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
        LNN_LOGE(LNN_STATE, "para callback = null");
        return SOFTBUS_INVALID_PARAM;
    }
    return UnregNodeDeviceStateCbInner(callback);
}

int32_t StartTimeSync(const char *pkgName, const char *targetNetworkId, TimeSyncAccuracy accuracy,
    TimeSyncPeriod period, ITimeSyncCb *cb)
{
    if (pkgName == NULL || !IsValidString(targetNetworkId, NETWORK_ID_BUF_LEN) ||
        cb == NULL || cb->onTimeSyncResult == NULL) {
        LNN_LOGE(LNN_STATE, "invalid parameters");
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
    if (pkgName == NULL || !IsValidString(targetNetworkId, NETWORK_ID_BUF_LEN)) {
        LNN_LOGE(LNN_STATE, "invalid parameters");
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
    if (pkgName == NULL || info == NULL || cb == NULL) {
        DfxRecordLnnDiscServerEnd(DISC_SERVER_PUBLISH, pkgName, SOFTBUS_INVALID_PARAM);
        LNN_LOGE(LNN_STATE, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CommonInit(pkgName);
    if (ret != SOFTBUS_OK) {
        DfxRecordLnnDiscServerEnd(DISC_SERVER_PUBLISH, pkgName, ret);
        return ret;
    }
    if (PublishInfoCheck(info) != SOFTBUS_OK) {
        DfxRecordLnnDiscServerEnd(DISC_SERVER_PUBLISH, pkgName, SOFTBUS_INVALID_PARAM);
        return SOFTBUS_INVALID_PARAM;
    }
    ret = PublishLNNInner(pkgName, info, cb);
    DfxRecordLnnDiscServerEnd(DISC_SERVER_PUBLISH, pkgName, ret);
    return ret;
}

int32_t StopPublishLNN(const char *pkgName, int32_t publishId)
{
    if (pkgName == NULL) {
        DfxRecordLnnDiscServerEnd(DISC_SERVER_STOP_PUBLISH, pkgName, SOFTBUS_INVALID_PARAM);
        LNN_LOGE(LNN_STATE, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CommonInit(pkgName);
    if (ret != SOFTBUS_OK) {
        DfxRecordLnnDiscServerEnd(DISC_SERVER_STOP_PUBLISH, pkgName, ret);
        return ret;
    }
    ret = StopPublishLNNInner(pkgName, publishId);
    DfxRecordLnnDiscServerEnd(DISC_SERVER_STOP_PUBLISH, pkgName, ret);
    return ret;
}

int32_t RefreshLNN(const char *pkgName, const SubscribeInfo *info, const IRefreshCallback *cb)
{
    if (pkgName == NULL || info == NULL || cb == NULL) {
        DfxRecordLnnDiscServerEnd(DISC_SERVER_DISCOVERY, pkgName, SOFTBUS_INVALID_PARAM);
        LNN_LOGE(LNN_STATE, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CommonInit(pkgName);
    if (ret != SOFTBUS_OK) {
        DfxRecordLnnDiscServerEnd(DISC_SERVER_DISCOVERY, pkgName, ret);
        return ret;
    }
    if (SubscribeInfoCheck(info) != SOFTBUS_OK) {
        DfxRecordLnnDiscServerEnd(DISC_SERVER_DISCOVERY, pkgName, SOFTBUS_INVALID_PARAM);
        return SOFTBUS_INVALID_PARAM;
    }
    ret = RefreshLNNInner(pkgName, info, cb);
    DfxRecordLnnDiscServerEnd(DISC_SERVER_DISCOVERY, pkgName, ret);
    return ret;
}

int32_t StopRefreshLNN(const char *pkgName, int32_t refreshId)
{
    if (pkgName == NULL) {
        DfxRecordLnnDiscServerEnd(DISC_SERVER_STOP_DISCOVERY, pkgName, SOFTBUS_INVALID_PARAM);
        LNN_LOGE(LNN_STATE, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CommonInit(pkgName);
    if (ret != SOFTBUS_OK) {
        DfxRecordLnnDiscServerEnd(DISC_SERVER_STOP_DISCOVERY, pkgName, ret);
        return ret;
    }
    ret = StopRefreshLNNInner(pkgName, refreshId);
    DfxRecordLnnDiscServerEnd(DISC_SERVER_STOP_DISCOVERY, pkgName, ret);
    return ret;
}

int32_t ActiveMetaNode(const char *pkgName, const MetaNodeConfigInfo *info, char *metaNodeId)
{
    if (pkgName == NULL || info == NULL || metaNodeId == NULL) {
        LNN_LOGE(LNN_STATE, "invalid active meta node para");
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
        LNN_LOGE(LNN_STATE, "invalid deactive meta node para");
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
        LNN_LOGE(LNN_STATE, "invalid query meta node info para");
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
    DfxRecordSdkShiftGearStart(pkgName, mode);
    if (pkgName == NULL || callerId == NULL || mode == NULL) {
        LNN_LOGE(LNN_STATE, "invalid shift lnn gear para");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CommonInit(pkgName);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    size_t len = strnlen(callerId, CALLER_ID_MAX_LEN);
    if (len == 0 || len >= CALLER_ID_MAX_LEN) {
        LNN_LOGE(LNN_STATE, "invalid shift lnn gear callerId len=%{public}zu", len);
        return SOFTBUS_INVALID_PARAM;
    }
    if (targetNetworkId != NULL &&
        strnlen(targetNetworkId, NETWORK_ID_BUF_LEN) != NETWORK_ID_BUF_LEN - 1) {
        LNN_LOGE(LNN_STATE, "invalid shift lnn gear targetNetworkId");
        return SOFTBUS_INVALID_PARAM;
    }
    return ShiftLNNGearInner(pkgName, callerId, targetNetworkId, mode);
}

int32_t SyncTrustedRelationShip(const char *pkgName, const char *msg, uint32_t msgLen)
{
    if (pkgName == NULL || msg == NULL) {
        LNN_LOGE(LNN_STATE, "invalid SyncTrustedRelationShip para");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CommonInit(pkgName);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "common init fail, ret=%{public}d", ret);
        return ret;
    }
    return SyncTrustedRelationShipInner(pkgName, msg, msgLen);
}

int32_t SetDisplayName(const char *pkgName, const char *nameData, uint32_t len)
{
    if (!IsValidString(pkgName, PKG_NAME_SIZE_MAX - 1) || nameData == NULL) {
        LNN_LOGE(LNN_STATE, "invalid SetDisplayName para");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CommonInit(pkgName);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "common init fail, ret=%{public}d", ret);
        return ret;
    }
    return SetDisplayNameInner(pkgName, nameData, len);
}