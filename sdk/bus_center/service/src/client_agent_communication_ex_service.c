/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "anonymizer.h"
#include "client_bus_center_manager.h"
#include "lnn_event.h"
#include "lnn_log.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "softbus_agent_communication.h"
#include "softbus_client_frame_manager.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

static void DfxRecordSdkPostConversationData(const char *deviceId, const ConversationBusiness *info,
    uint32_t len, uint64_t timeMs, int32_t ret)
{
    LnnEventExtra extra = { 0 };
    extra.result = ret;
    extra.dataLen = len;
    extra.peerUdid = deviceId;
    if (info != NULL) {
        extra.bundleName = info->bundleName;
        extra.abilityName = info->abilityName;
    }
    extra.statsTime = SoftBusFormatTimestamp(timeMs);
    LNN_EVENT(EVENT_SCENE_AGENT_COMM, EVENT_STAGE_LNN_CONVERSATION_RESULT, extra);
}

static int32_t CommonInit(const char *ablilityName)
{
    if (InitSoftBus(ablilityName) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "init softbus failed");
        return SOFTBUS_NETWORK_NOT_INIT;
    }
    if (CheckPackageName(ablilityName) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "check ablilityName failed");
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

int32_t PostConversationData(const char *deviceId, const ConversationBusiness *info, const char *data, uint32_t len)
{
    LNN_LOGI(LNN_EVENT, "enter");
    uint64_t timeMs = SoftBusGetSysTimeMs();
    if (deviceId == NULL) {
        LNN_LOGE(LNN_EVENT, "invalid deviceId");
        DfxRecordSdkPostConversationData(deviceId, info, len, timeMs, SOFTBUS_INVALID_PARAM);
        return SOFTBUS_INVALID_PARAM;
    }
    if (info == NULL) {
        LNN_LOGE(LNN_EVENT, "invalid info");
        DfxRecordSdkPostConversationData(deviceId, info, len, timeMs, SOFTBUS_INVALID_PARAM);
        return SOFTBUS_INVALID_PARAM;
    }
    if (data == NULL) {
        LNN_LOGE(LNN_EVENT, "invalid data");
        DfxRecordSdkPostConversationData(deviceId, info, len, timeMs, SOFTBUS_INVALID_PARAM);
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t deviceIdLen = strnlen(deviceId, NETWORK_ID_BUF_LEN);
    if (deviceIdLen != NETWORK_ID_BUF_LEN - 1) {
        LNN_LOGE(LNN_EVENT, "invalid deviceId, len=%{public}d", deviceIdLen);
        DfxRecordSdkPostConversationData(deviceId, info, len, timeMs, SOFTBUS_INVALID_PARAM);
        return SOFTBUS_INVALID_PARAM;
    }
    if (len == 0 || len > COMMUNICATION_DATA_MAX_LEN) {
        LNN_LOGI(LNN_EVENT,  "invalid len=%{public}u", len);
        DfxRecordSdkPostConversationData(deviceId, info, len, timeMs, SOFTBUS_INVALID_PARAM);
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CommonInit(info->abilityName);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "common init fail, ret=%d", ret);
        DfxRecordSdkPostConversationData(deviceId, info, len, timeMs, ret);
        return ret;
    }
    ret = PostConversationDataInner(deviceId, info, data, len);
    DfxRecordSdkPostConversationData(deviceId, info, len, timeMs, ret);
    return ret;
}

void FreeDeviceNodeInfo(DeviceNodeInfo *info)
{
    LNN_LOGI(LNN_EVENT,  "enter");
    if (info == NULL) {
        LNN_LOGI(LNN_EVENT,  "info is null");
        return;
    }
    SoftBusFree(info);
}

static void DfxRecordSdkRegisterConversationListener(const ConversationBusiness *info, int32_t ret)
{
    LnnEventExtra extra = { 0 };
    extra.result = ret;
    if (info != NULL) {
        extra.bundleName = info->bundleName;
        extra.abilityName = info->abilityName;
    }

    LNN_EVENT(EVENT_SCENE_AGENT_COMM, EVENT_STAGE_LNN_CONVERSATION_REGISTER, extra);
}

int32_t RegisterConversationListener(const ConversationBusiness *info, const ConversationListener *listener)
{
    LNN_LOGI(LNN_EVENT,  "enter");
    if (info == NULL || listener == NULL || listener->OnDataReceived == NULL) {
        LNN_LOGE(LNN_EVENT,  "invalid param");
        DfxRecordSdkRegisterConversationListener(info, SOFTBUS_INVALID_PARAM);
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CommonInit(info->abilityName);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "common init fail, ret=%d", ret);
        DfxRecordSdkRegisterConversationListener(info, ret);
        return ret;
    }
    ret = RegisterConversationListenerInner(info, listener);
    DfxRecordSdkRegisterConversationListener(info, ret);
    return ret;
}

void UnregisterConversationListener(const ConversationBusiness *info)
{
    LNN_LOGI(LNN_EVENT,  "enter");
    if (info == NULL) {
        LNN_LOGE(LNN_EVENT,  "invalid param");
        return;
    }
    int32_t ret = CommonInit(info->abilityName);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "common init fail, ret=%d", ret);
        return;
    }
    UnregisterConversationListenerInner(info);
}

int32_t GetTrustedDevices(DeviceNodeInfo **info, int32_t *nums)
{
    LNN_LOGI(LNN_EVENT,  "enter");
    LNN_CHECK_AND_RETURN_RET_LOGE(info != NULL, SOFTBUS_INVALID_PARAM, LNN_EVENT, "invalid info");
    LNN_CHECK_AND_RETURN_RET_LOGE(nums != NULL, SOFTBUS_INVALID_PARAM, LNN_EVENT, "invalid nums");
    return GetTrustedDevicesInner(info, nums);
}