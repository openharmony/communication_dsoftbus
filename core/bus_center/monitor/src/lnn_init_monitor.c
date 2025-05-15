/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "comm_log.h"
#include "lnn_async_callback_utils.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_init_monitor.h"
#include "lnn_log.h"
#include "lnn_network_manager.h"
#include "message_handler.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_type_def.h"

typedef struct {
    InitDepsStatus status;
    ModuleInitCallBack callback;
    int32_t ret;
    SoftBusMutex lock;
} InitDepsInfo;

typedef struct {
    uint32_t module;
    ModuleInitCallBack callback;
    uint32_t retryMax;
    uint32_t retry;
    uint32_t delay;
} InitDepsCbParam;

typedef struct {
    uint8_t depInitEnd;
    uint8_t deviceInfoReady;
} LnnInitMonitorInfo;

static InitDepsInfo g_lnnEnableModuleDeps[INIT_DEPS_MODULE_BUTT];
static InitDepsInfo g_lnnDeviceInfoDeps[LEDGER_INFO_BUTT];
static LnnInitMonitorInfo g_lnnInitMonitorInfoMgr;

void LnnInitModuleReturnSet(uint32_t module, uint32_t ret)
{
    if (module < INIT_DEPS_MODULE_BUTT) {
        SoftBusMutexLock(&g_lnnEnableModuleDeps[module].lock);
        g_lnnEnableModuleDeps[module].ret = ret;
        SoftBusMutexUnlock(&g_lnnEnableModuleDeps[module].lock);
    }
}

void LnnInitModuleCbRegister(uint32_t module, ModuleInitCallBack callback)
{
    if (module < INIT_DEPS_MODULE_BUTT) {
        SoftBusMutexLock(&g_lnnEnableModuleDeps[module].lock);
        g_lnnEnableModuleDeps[module].callback = callback;
        SoftBusMutexUnlock(&g_lnnEnableModuleDeps[module].lock);
    }
}

static InitDepsStatus LnnInitModuleStatusGet(uint32_t module)
{
    if (module >= INIT_DEPS_MODULE_BUTT) {
        LNN_LOGE(LNN_INIT, "Module({public}%u) is invalid.", module);
        return DEPS_STATUS_NOT_INIT;
    }
    SoftBusMutexLock(&g_lnnEnableModuleDeps[module].lock);
    InitDepsStatus status = g_lnnEnableModuleDeps[module].status;
    SoftBusMutexUnlock(&g_lnnEnableModuleDeps[module].lock);
    return status;
}

void LnnModuleMonitorRestartNetwork(void)
{
    RestartCoapDiscovery();
    HbEnableDiscovery();
    LNN_LOGI(LNN_INIT, "Module monitors and changes heartbeat (HB) conditions, and restarts CoAP discovery.");
}

static void LnnInitMonitorInitComplete(void *para)
{
    (void)para;
    g_lnnInitMonitorInfoMgr.depInitEnd = true;
    if (g_lnnInitMonitorInfoMgr.deviceInfoReady) {
        LnnModuleMonitorRestartNetwork();
    }
}

static void LnnInitModuleCheckEach(void)
{
    for (uint32_t depModule = 0; depModule < INIT_DEPS_MODULE_BUTT; depModule++) {
        if (LnnInitModuleStatusGet(depModule) == DEPS_STATUS_NOT_INIT) {
            return;
        }
    }
    LnnAsyncCallbackHelper(GetLooper(LOOP_TYPE_DEFAULT), LnnInitMonitorInitComplete, NULL);
}

void LnnInitModuleStatusSet(uint32_t module, InitDepsStatus status)
{
    if (module < INIT_DEPS_MODULE_BUTT) {
        SoftBusMutexLock(&g_lnnEnableModuleDeps[module].lock);
        g_lnnEnableModuleDeps[module].status = status;
        SoftBusMutexUnlock(&g_lnnEnableModuleDeps[module].lock);
        LnnInitModuleCheckEach();
    }
}

void LnnInitDeviceInfoStatusSet(uint32_t module, InitDepsStatus status)
{
    if (module < LEDGER_INFO_BUTT) {
        SoftBusMutexLock(&g_lnnDeviceInfoDeps[module].lock);
        g_lnnDeviceInfoDeps[module].status = status;
        SoftBusMutexUnlock(&g_lnnDeviceInfoDeps[module].lock);
    }
}

static InitDepsStatus LnnInitDeviceInfoStatusGet(uint32_t module)
{
    if (module >= LEDGER_INFO_BUTT) {
        LNN_LOGE(LNN_INIT, "Device info(%u) is invalid.", module);
        return DEPS_STATUS_NOT_INIT;
    }
    SoftBusMutexLock(&g_lnnDeviceInfoDeps[module].lock);
    InitDepsStatus status = g_lnnDeviceInfoDeps[module].status;
    SoftBusMutexUnlock(&g_lnnDeviceInfoDeps[module].lock);
    return status;
}

void LnnInitSetDeviceInfoReady(void)
{
    g_lnnInitMonitorInfoMgr.deviceInfoReady = true;
    if (g_lnnInitMonitorInfoMgr.depInitEnd) {
        LnnModuleMonitorRestartNetwork();
    }
}

void LnnInitMonitorInit(void)
{
    LNN_LOGI(LNN_INIT, "Module init monitor start.");
    for (uint32_t depModule = 0; depModule < INIT_DEPS_MODULE_BUTT; depModule++) {
        SoftBusMutexInit(&g_lnnEnableModuleDeps[depModule].lock, NULL);
        g_lnnEnableModuleDeps[depModule].status = DEPS_STATUS_NOT_INIT;
        g_lnnEnableModuleDeps[depModule].callback = NULL;
        g_lnnEnableModuleDeps[depModule].ret = SOFTBUS_OK;
    }
    for (uint32_t depLeger = 0; depLeger < LEDGER_INFO_BUTT; depLeger++) {
        SoftBusMutexInit(&g_lnnDeviceInfoDeps[depLeger].lock, NULL);
        g_lnnDeviceInfoDeps[depLeger].status = DEPS_STATUS_NOT_INIT;
    }
    g_lnnInitMonitorInfoMgr.depInitEnd = false;
    g_lnnInitMonitorInfoMgr.deviceInfoReady = false;
    /* The passive listening module is set to a state of "failed" in initialization. */
    g_lnnEnableModuleDeps[INIT_DEPS_DATA_SHARE].status = DEPS_STATUS_FAILED;
    g_lnnEnableModuleDeps[INIT_DEPS_PROCESS_BOOT].status = DEPS_STATUS_FAILED;
}

bool IsLnnInitCheckSucceed(uint32_t netType)
{
    if (g_lnnInitMonitorInfoMgr.depInitEnd && g_lnnInitMonitorInfoMgr.deviceInfoReady) {
        return true;
    }
    if (netType == MONITOR_WIFI_NET) {
        LNN_LOGI(LNN_INIT, "CoapDiscovery need restart, because the monitor is not ready.");
    } else if (netType == MONITOR_BLE_NET) {
        LNN_LOGI(LNN_INIT, "Hb condition need to change, because the monitor is not ready.");
    }

    return false;
}

static void LnnModuleInitRetryCallback(void *param)
{
    InitDepsCbParam *retryParam = (InitDepsCbParam *)param;
    ModuleInitCallBack callback = g_lnnEnableModuleDeps[retryParam->module].callback;

    LNN_LOGI(LNN_INIT, "module(%{public}u) is retrying.", retryParam->module);
    if ((retryParam->retry >= retryParam->retryMax) || (callback == NULL)) {
        LnnInitModuleStatusSet(retryParam->module, DEPS_STATUS_FAILED);
        LNN_LOGE(LNN_INIT, "Module(%{public}u) retry to max times(%{public}s) ", retryParam->module,
            callback == NULL ? ", callback is null" : "");
        SoftBusFree(retryParam);
        return;
    }

    int32_t ret = callback();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "Module(%{public}u) hast tried %{public}u times", retryParam->module, retryParam->retry + 1);
        LnnInitModuleReturnSet(retryParam->module, ret);
        retryParam->retry++;
        if (LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), LnnModuleInitRetryCallback, param,
            retryParam->delay) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "LnnAsyncCallbackDelayHelper fail");
            LnnInitModuleStatusSet(retryParam->module, DEPS_STATUS_FAILED);
            SoftBusFree(retryParam);
        }
    } else {
        LNN_LOGI(LNN_INIT, "Module(%{public}u) retry success.", retryParam->module);
        LnnInitModuleStatusSet(retryParam->module, DEPS_STATUS_SUCCESS);
        SoftBusFree(retryParam);
    }
}

int32_t LnnInitModuleNotifyWithRetryAsync(uint32_t module, ModuleInitCallBack callback, uint32_t retryMax,
    uint32_t delay, bool isFirstDelay)
{
    if (callback == NULL || module >= INIT_DEPS_MODULE_BUTT) {
        LNN_LOGE(LNN_LEDGER, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    LnnInitModuleCbRegister(module, callback);
    LnnInitModuleStatusSet(module, DEPS_STATUS_INIT_PROGRESS);
    InitDepsCbParam *retryParam = (InitDepsCbParam *)SoftBusCalloc(sizeof(InitDepsCbParam));
    if (retryParam == NULL) {
        LNN_LOGE(LNN_LEDGER, "SoftBusCalloc fail");
        LnnInitModuleStatusSet(module, DEPS_STATUS_FAILED);
        return SOFTBUS_MEM_ERR;
    }
    retryParam->module = module;
    retryParam->retryMax = retryMax + 1;
    retryParam->delay = delay;
    retryParam->retry = 0;
    int32_t ret = LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), LnnModuleInitRetryCallback, retryParam,
        isFirstDelay ? delay : 0);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnAsyncCallbackDelayHelper fail");
        LnnInitModuleStatusSet(module, DEPS_STATUS_FAILED);
        SoftBusFree(retryParam);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t LnnInitModuleNotifyWithRetrySync(uint32_t module, ModuleInitCallBack callback, uint32_t retryMax,
    uint32_t delay)
{
    if (callback == NULL || module >= INIT_DEPS_MODULE_BUTT) {
        LNN_LOGE(LNN_LEDGER, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = callback();
    if (ret != SOFTBUS_OK) {
        LnnInitModuleReturnSet(module, ret);
        LnnInitModuleStatusSet(module, DEPS_STATUS_INIT_PROGRESS);
        LnnInitModuleCbRegister(module, callback);
        InitDepsCbParam *retryParam = (InitDepsCbParam *)SoftBusCalloc(sizeof(InitDepsCbParam));
        if (retryParam == NULL) {
            LNN_LOGE(LNN_LEDGER, "SoftBusCalloc fail");
            LnnInitModuleStatusSet(module, DEPS_STATUS_FAILED);
            return SOFTBUS_MEM_ERR;
        }
        retryParam->module = module;
        retryParam->retryMax = retryMax;
        retryParam->delay = delay;
        retryParam->retry = 0;
        ret = LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), LnnModuleInitRetryCallback, retryParam, delay);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "LnnAsyncCallbackDelayHelper fail");
            LnnInitModuleStatusSet(module, DEPS_STATUS_FAILED);
            SoftBusFree(retryParam);
            return ret;
        }
        return SOFTBUS_OK;
    }
    LnnInitModuleStatusSet(module, DEPS_STATUS_SUCCESS);
    return SOFTBUS_OK;
}

static void LnnInitModuleFailedLog(void *param)
{
    (void)param;
    char failedModules[DEP_INFO_LEN] = { 0 };
    size_t offset = 0;
    int32_t ret;
    bool reCheck = false;

    if (!g_lnnInitMonitorInfoMgr.depInitEnd) {
        LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), LnnInitModuleFailedLog, NULL, DELAY_FIVE_MIN_LEN);
        return;
    }
    for (uint32_t depModule = 0; depModule < INIT_DEPS_MODULE_BUTT; depModule++) {
        if (LnnInitModuleStatusGet(depModule) == DEPS_STATUS_FAILED) {
            ret = snprintf_s(failedModules + offset, DEP_INFO_LEN - offset, DEP_INFO_LEN - offset - 1,
                "Module(%u), ret(%d); ", depModule, g_lnnEnableModuleDeps[depModule].ret);
            if (ret < 0) {
                LNN_LOGE(LNN_LEDGER, "snprintf_s failed");
                break;
            }
            offset += ret;
            reCheck = true;
        } else if (LnnInitModuleStatusGet(depModule) == DEPS_STATUS_INIT_PROGRESS) {
            reCheck = true;
        }
    }
    if (failedModules[0] != '\0') {
        LNN_LOGE(LNN_INIT, "Module init failed: %{public}s", failedModules);
    }
    if (reCheck) {
        LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), LnnInitModuleFailedLog, NULL, DELAY_FIVE_MIN_LEN);
    }
}

static void LnnInitDeviceInfoFailLog(void *param)
{
    (void)param;
    bool reCheck = false;
    char depLegerInfo[DEP_INFO_LEN] = { 0 };
    size_t offset = 0;
    int32_t ret;

    for (uint32_t depLeger = 0; depLeger < LEDGER_INFO_BUTT; depLeger++) {
        InitDepsStatus status = LnnInitDeviceInfoStatusGet(depLeger);
        if (status == DEPS_STATUS_FAILED) {
            ret = snprintf_s(depLegerInfo + offset, DEP_INFO_LEN - offset, DEP_INFO_LEN - offset - 1, "Leger(%u); ",
                depLeger);
            if (ret < 0) {
                LNN_LOGE(LNN_LEDGER, "snprintf_s failed");
                break;
            }
            offset += ret;
            reCheck = true;
        } else if (status == DEPS_STATUS_NOT_INIT) {
            reCheck = true;
        }
    }
    if (depLegerInfo[0] != '\0') {
        LNN_LOGE(LNN_INIT, "Device init failed: %{public}s", depLegerInfo);
    }
    if (reCheck) {
        LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), LnnInitDeviceInfoFailLog, NULL, DELAY_FIVE_MIN_LEN);
    }
}

void LnnModuleInitMonitorCheckStart(void)
{
    LnnInitDeviceInfoFailLog(NULL);
    LnnInitModuleFailedLog(NULL);
}