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

#ifndef LNN_MODULE_INIT_MONITOR_H
#define LNN_MODULE_INIT_MONITOR_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MONITOR_DELAY 1000
#define DELAY_FIVE_MIN_LEN 300000
#define DEP_INFO_LEN 1024

typedef enum {
    D2D_STATE_UPDATE,
    SLE_DATA_TRANSFER_UPDATE,
    SLE_RANGING_UPDATE,
    COMMON_EVENT_UNKNOWN,
} CommonEventType;

typedef enum {
    NOTIFY_MODULE,
    NOTIFY_LEDGER
} InitNotifyType;

typedef enum {
    MONITOR_WIFI_NET,
    MONITOR_BLE_NET
} MonitorNetType;

typedef enum {
    INIT_DEPS_DEVICE_PROFILE = 0,
    INIT_DEPS_SCREEN_STATUS,
    INIT_DEPS_NETLINK,
    INIT_DEPS_PROCESS_BOOT,
    INIT_DEPS_KVSTORE,
    INIT_DEPS_DATA_SHARE,
    INIT_DEPS_HUKS,
    INIT_DEPS_HICHAIN,
    INIT_DEPS_BLUETOOTH,
    INIT_DEPS_USB,
    INIT_DEPS_MODULE_BUTT
} InitModuleDeps;

typedef enum {
    LEDGER_INFO_DEVICE_NAME,
    LEDGER_INFO_UUID,
    LEDGER_INFO_UDID,
    LEDGER_INFO_NETWORKID,
    LEDGER_INFO_DEVICE_SECURITY_LEVEL,
    LEDGER_INFO_ACCOUNTID,
    LEDGER_INFO_BUTT
} LedgerInfoDeps;

typedef enum {
    DEPS_STATUS_NOT_INIT,
    DEPS_STATUS_INIT_PROGRESS,
    DEPS_STATUS_SUCCESS,
    DEPS_STATUS_FAILED,
} InitDepsStatus;

typedef int32_t (*ModuleInitCallBack)(void);

bool IsLnnInitCheckSucceed(uint32_t netType);
void LnnInitMonitorInit(void);
void LnnModuleInitMonitorCheckStart(void);

void LnnInitModuleReturnSet(uint32_t module, int32_t ret);
void LnnInitModuleStatusSet(uint32_t module, InitDepsStatus status);
void LnnInitDeviceInfoStatusSet(uint32_t module, InitDepsStatus status);

int32_t LnnInitModuleNotifyWithRetryAsync(uint32_t module, ModuleInitCallBack callback, uint32_t retryMax,
    uint32_t delay, bool isFirstDelay);
int32_t LnnInitModuleNotifyWithRetrySync(uint32_t module, ModuleInitCallBack callback, uint32_t retry,
    uint32_t delay);
void LnnRestartNetwork(void);

void LnnInitSetDeviceInfoReady(void);

#ifdef __cplusplus
}
#endif
#endif /* LNN_MODULE_INIT_MONITOR_H */
