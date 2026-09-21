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
#include "perception_manager.h"

#include <stdatomic.h>
#include <stdbool.h>

#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "g_enhance_lnn_func_pack.h"
#include "lnn_async_callback_utils.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_perception.h"
#include "message_handler.h"
#include "perception_advertiser.h"
#include "perception_scanner.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

static atomic_bool g_mgrInited = false;

static int32_t ValidatePkgName(const char *pkgName)
{
    if (pkgName == NULL) {
        return SOFTBUS_INVALID_PKGNAME;
    }
    if (!IsValidStringSafe(pkgName, PKG_NAME_SIZE_MAX)) {
        return SOFTBUS_INVALID_PKGNAME;
    }
    return SOFTBUS_OK;
}

static bool ValidateType(PerceptionType type)
{
    return type >= PERCEPTION_TYPE_COLLABORATIVE_WAKE && type < PERCEPTION_TYPE_BUTT;
}

static bool ValidateCycle(PerceptionCycle cycle)
{
    return cycle >= PERCEPTION_CYCLE_LOW && cycle < PERCEPTION_CYCLE_BUTT;
}

static int32_t CheckSessionArgs(const char *pkgName, PerceptionType type)
{
    int32_t ret = ValidatePkgName(pkgName);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "perception session invalid pkgName, ret=%{public}d", ret);
        return ret;
    }
    if (!ValidateType(type)) {
        LNN_LOGE(LNN_STATE, "perception session invalid type=%{public}d", (int32_t)type);
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

static int32_t CheckLocalScanCapability(void)
{
    int32_t localDevTypeId = 0;
    if (LnnGetLocalNumInfo(NUM_KEY_DEV_TYPE_ID, &localDevTypeId) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "get local device type fail");
        return SOFTBUS_FUNC_NOT_SUPPORT;
    }
    if (localDevTypeId != TYPE_PHONE_ID && localDevTypeId != TYPE_PAD_ID && localDevTypeId != TYPE_2IN1_ID) {
        LNN_LOGE(LNN_STATE, "perception scan not supported on device type=%{public}d", localDevTypeId);
        return SOFTBUS_FUNC_NOT_SUPPORT;
    }
    if (!LnnIsLocalSupportBurstFeature() && !IsSupportLpFeaturePacked()) {
        LNN_LOGE(LNN_STATE, "perception scan capability not supported");
        return SOFTBUS_FUNC_NOT_SUPPORT;
    }
    return SOFTBUS_OK;
}

static int32_t CheckMgrInited(void)
{
    if (!atomic_load(&g_mgrInited)) {
        LNN_LOGE(LNN_STATE, "perception not inited");
        return SOFTBUS_NO_INIT;
    }
    return SOFTBUS_OK;
}

static void PerceptionBtStateChangedAsync(void *para)
{
    bool *isBtOn = (bool *)para;
    bool on = (isBtOn != NULL) ? *isBtOn : false;
    SoftBusFree(isBtOn);
    LNN_LOGI(LNN_STATE, "perception handle bt state change, isBtOn=%{public}d", on);
    PerceptionAdvOnBtStateChanged(on);
    PerceptionScanOnBtStateChanged(on);
}

static void PerceptionScreenStateChangeAsync(void *para)
{
    bool *isScreenOn = (bool *)para;
    bool on = (isScreenOn != NULL) ? *isScreenOn : false;
    SoftBusFree(isScreenOn);
    LNN_LOGI(LNN_STATE, "perception handle screen %{public}s, refresh scan params", on ? "on" : "off");
    PerceptionScanOnScreenStateChanged(on);
}

static void PostBtStateChange(bool isBtOn)
{
    bool *para = (bool *)SoftBusCalloc(sizeof(bool));
    if (para == NULL) {
        LNN_LOGE(LNN_STATE, "post bt state change malloc fail");
        return;
    }
    *para = isBtOn;
    int32_t ret = LnnAsyncCallbackHelper(GetLooper(LOOP_TYPE_DEFAULT), PerceptionBtStateChangedAsync, (void *)para);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "post bt state change err, ret=%{public}d", ret);
        SoftBusFree(para);
    }
}

static void PostScreenStateChange(bool isScreenOn)
{
    bool *para = (bool *)SoftBusCalloc(sizeof(bool));
    if (para == NULL) {
        LNN_LOGE(LNN_STATE, "post screen state change malloc fail");
        return;
    }
    *para = isScreenOn;
    int32_t ret =
        LnnAsyncCallbackHelper(GetLooper(LOOP_TYPE_DEFAULT), PerceptionScreenStateChangeAsync, (void *)para);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "post screen state change err, ret=%{public}d", ret);
        SoftBusFree(para);
    }
}

static void PerceptionBtStateChangeEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_BT_STATE_CHANGED) {
        LNN_LOGE(LNN_STATE, "perception bt state change evt handler get invalid param");
        return;
    }
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    SoftBusBtState btState = (SoftBusBtState)event->status;
    if (btState == SOFTBUS_BLE_TURN_OFF) {
        PostBtStateChange(false);
    } else if (btState == SOFTBUS_BLE_TURN_ON) {
        PostBtStateChange(true);
    }
}

static void PerceptionScreenStateChangeEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_SCREEN_STATE_CHANGED) {
        LNN_LOGE(LNN_STATE, "perception screen state change evt handler get invalid param");
        return;
    }
    const LnnMonitorScreenStateChangedEvent *event = (const LnnMonitorScreenStateChangedEvent *)info;
    SoftBusScreenState state = (SoftBusScreenState)event->status;
    if (state == SOFTBUS_SCREEN_ON) {
        PostScreenStateChange(true);
    } else if (state == SOFTBUS_SCREEN_OFF) {
        PostScreenStateChange(false);
    }
}

int32_t LnnStartPerceptionAdv(const char *pkgName, PerceptionType type, const PerceptionAdvParam *param)
{
    int32_t ret = CheckSessionArgs(pkgName, type);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (param == NULL || param->customDataLen > PERCEPTION_CUSTOM_DATA_MAX_LEN) {
        LNN_LOGE(LNN_STATE, "start perception adv invalid param, type=%{public}d", (int32_t)type);
        return SOFTBUS_INVALID_PARAM;
    }
    ret = CheckMgrInited();
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return PerceptionAdvStart(type, param);
}

int32_t LnnSetPerceptionAdvHighFreq(const char *pkgName, PerceptionType type, const PerceptionAdvParam *param)
{
    int32_t ret = CheckSessionArgs(pkgName, type);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (param == NULL || param->customDataLen > PERCEPTION_CUSTOM_DATA_MAX_LEN) {
        LNN_LOGE(LNN_STATE, "set perception adv high freq invalid param, type=%{public}d", (int32_t)type);
        return SOFTBUS_INVALID_PARAM;
    }
    ret = CheckMgrInited();
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return PerceptionAdvSetHighFreq(type, param);
}

int32_t LnnStopPerceptionAdv(const char *pkgName, PerceptionType type)
{
    int32_t ret = CheckSessionArgs(pkgName, type);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return PerceptionAdvStop();
}

int32_t LnnStartPerceptionScan(const char *pkgName, PerceptionType type, PerceptionCycle cycle)
{
    int32_t ret = CheckSessionArgs(pkgName, type);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (!ValidateCycle(cycle)) {
        LNN_LOGE(LNN_STATE, "perception scan invalid cycle=%{public}d", (int32_t)cycle);
        return SOFTBUS_INVALID_PARAM;
    }
    ret = CheckLocalScanCapability();
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    ret = CheckMgrInited();
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return PerceptionScanStart(type, cycle);
}

int32_t LnnStopPerceptionScan(const char *pkgName, PerceptionType type)
{
    int32_t ret = CheckSessionArgs(pkgName, type);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return PerceptionScanStop();
}

int32_t LnnGetPerceptionDeviceList(
    const char *pkgName, PerceptionType type, PerceptionDeviceInfo **list, uint32_t *count)
{
    int32_t ret = CheckSessionArgs(pkgName, type);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (list == NULL || count == NULL) {
        LNN_LOGE(LNN_STATE, "get perception device list invalid param, type=%{public}d", (int32_t)type);
        return SOFTBUS_INVALID_PARAM;
    }
    ret = CheckLocalScanCapability();
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    ret = CheckMgrInited();
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return PerceptionScanGetDeviceList(type, list, count);
}

int32_t PerceptionManagerInit(void)
{
    if (atomic_load(&g_mgrInited)) {
        return SOFTBUS_OK;
    }
    int32_t ret = PerceptionEnhanceInitPacked();
    if (ret != SOFTBUS_OK) {
        LNN_LOGW(LNN_INIT, "perception mgr packed init not available, ret=%{public}d", ret);
    }
    ret = PerceptionAdvertiserInit();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "perception advertiser init fail, ret=%{public}d", ret);
        return ret;
    }
    ret = PerceptionScannerInit();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "perception scanner init fail, ret=%{public}d", ret);
        PerceptionAdvertiserDeinit();
        return ret;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_BT_STATE_CHANGED, PerceptionBtStateChangeEventHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "perception regist bt state change evt handler fail");
        PerceptionScannerDeinit();
        PerceptionAdvertiserDeinit();
        return SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_SCREEN_STATE_CHANGED, PerceptionScreenStateChangeEventHandler) !=
        SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "perception regist screen state change evt handler fail");
        LnnUnregisterEventHandler(LNN_EVENT_BT_STATE_CHANGED, PerceptionBtStateChangeEventHandler);
        PerceptionScannerDeinit();
        PerceptionAdvertiserDeinit();
        return SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR;
    }
    atomic_store(&g_mgrInited, true);
    LNN_LOGI(LNN_INIT, "perception manager init ok");
    return SOFTBUS_OK;
}

void PerceptionManagerDeinit(void)
{
    if (!atomic_load(&g_mgrInited)) {
        return;
    }
    atomic_store(&g_mgrInited, false);
    LnnUnregisterEventHandler(LNN_EVENT_SCREEN_STATE_CHANGED, PerceptionScreenStateChangeEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_BT_STATE_CHANGED, PerceptionBtStateChangeEventHandler);
    PerceptionScannerDeinit();
    PerceptionAdvertiserDeinit();
    PerceptionEnhanceDeinitPacked();
    LNN_LOGI(LNN_INIT, "perception manager deinit ok");
}
