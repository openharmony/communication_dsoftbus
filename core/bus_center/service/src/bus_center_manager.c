/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "bus_center_manager.h"

#include <stdint.h>
#include <stdlib.h>

#include "bus_center_decision_center.h"
#include "bus_center_event.h"
#include "lnn_async_callback_utils.h"
#include "lnn_coap_discovery_impl.h"
#include "lnn_discovery_manager.h"
#include "lnn_event_monitor.h"
#include "lnn_lane_hub.h"
#include "lnn_log.h"
#include "lnn_meta_node_interface.h"
#include "lnn_net_builder.h"
#include "lnn_net_ledger.h"
#include "lnn_network_manager.h"
#include "lnn_ohos_account_adapter.h"
#include "legacy/softbus_adapter_xcollie.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_utils.h"

#define WATCHDOG_TASK_NAME "LNN_WATCHDOG_TASK"
#define WATCHDOG_INTERVAL_TIME 10000
#define WATCHDOG_DELAY_TIME 5000
#define DEFAULT_DELAY_LEN 1500
#define RETRY_MAX 10

int32_t __attribute__((weak)) InitNodeAddrAllocator(void)
{
    return SOFTBUS_OK;
}
void __attribute__((weak)) DeinitNodeAddrAllocator(void) {}

int32_t __attribute__((weak)) RouteLSInit(void)
{
    return SOFTBUS_OK;
}
void __attribute__((weak)) RouteLSDeinit(void) {}

typedef int32_t (*LnnInitDelayImpl)(void);

typedef enum {
    INIT_LOCAL_LEDGER_DELAY_TYPE = 0,
    INIT_EVENT_MONITER_DELAY_TYPE,
    INIT_NETWORK_MANAGER_DELAY_TYPE,
    INIT_NETBUILDER_DELAY_TYPE,
    INIT_LANEHUB_DELAY_TYPE,
    INIT_DELAY_MAX_TYPE,
} InitDelayType;

typedef struct {
    LnnInitDelayImpl implInit;
    bool isInit;
} InitDelayImpl;

typedef struct {
    InitDelayImpl initDelayImpl[INIT_DELAY_MAX_TYPE];
    int32_t delayLen;
} LnnLocalConfigInit;

static void WatchdogProcess(void)
{
    if (GetWatchdogFlag()) {
        LNN_LOGI(LNN_STATE, "softbus net_builder thread running normally");
        return;
    }
    LNN_LOGW(LNN_STATE, "softbus net_builder thread exception");
}

static LnnLocalConfigInit g_lnnLocalConfigInit = {
    .initDelayImpl = {
        [INIT_LOCAL_LEDGER_DELAY_TYPE] = {
            .implInit = LnnInitNetLedgerDelay,
            .isInit = false,
        },
        [INIT_EVENT_MONITER_DELAY_TYPE] = {
            .implInit = LnnInitEventMoniterDelay,
            .isInit = false,
        },
        [INIT_NETWORK_MANAGER_DELAY_TYPE] = {
            .implInit = LnnInitNetworkManagerDelay,
            .isInit = false,
        },
        [INIT_NETBUILDER_DELAY_TYPE] = {
            .implInit = LnnInitNetBuilderDelay,
            .isInit = false,
        },
        [INIT_LANEHUB_DELAY_TYPE] = {
            .implInit = LnnInitLaneHubDelay,
            .isInit = false,
        },
    },
};

static void ReadDelayConfig(void)
{
    if (SoftbusGetConfig(SOFTBUS_INT_LNN_UDID_INIT_DELAY_LEN,
        (unsigned char *)&g_lnnLocalConfigInit.delayLen, sizeof(g_lnnLocalConfigInit.delayLen)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "get lnn delay init len fail, use default value");
        g_lnnLocalConfigInit.delayLen = DEFAULT_DELAY_LEN;
    }
    LNN_LOGI(LNN_STATE, "lnn delay init len=%{public}u", g_lnnLocalConfigInit.delayLen);
}

static void BusCenterServerDelayInit(void *para)
{
    (void)para;
    static int32_t retry = 0;
    if (retry > RETRY_MAX) {
        LNN_LOGE(LNN_STATE, "try exceeds max times");
        return;
    }
    int32_t ret = SOFTBUS_OK;
    uint32_t i;
    for (i = 0; i < INIT_DELAY_MAX_TYPE; ++i) {
        if (g_lnnLocalConfigInit.initDelayImpl[i].implInit == NULL) {
            continue;
        }
        /* initialize the lane hub module after successfully initializing the local ledger. */
        if (i == INIT_LANEHUB_DELAY_TYPE &&
            !g_lnnLocalConfigInit.initDelayImpl[INIT_LOCAL_LEDGER_DELAY_TYPE].isInit) {
            continue;
        }
        if (!g_lnnLocalConfigInit.initDelayImpl[i].isInit &&
            g_lnnLocalConfigInit.initDelayImpl[i].implInit() != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "init delay impl failed. i=%{public}u", i);
            ret = SOFTBUS_NO_INIT;
        } else {
            g_lnnLocalConfigInit.initDelayImpl[i].isInit = true;
        }
    }
    LnnCoapConnectInit();
    if (ret != SOFTBUS_OK) {
        retry++;
        SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
        ret = LnnAsyncCallbackDelayHelper(looper, BusCenterServerDelayInit, NULL, g_lnnLocalConfigInit.delayLen);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "LnnAsyncCallbackDelayHelper fail");
        }
    }
}

static int32_t StartDelayInit(void)
{
    ReadDelayConfig();
    int32_t ret = LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), BusCenterServerDelayInit,
        NULL, g_lnnLocalConfigInit.delayLen);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "call LnnAsyncCallbackDelayHelper fail");
    }
    return ret;
}

static int32_t BusCenterServerInitFirstStep(void)
{
    if (LnnInitLnnLooper() != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "init lnn looper fail");
        return SOFTBUS_LOOPER_ERR;
    }
    if (LnnInitNetLedger() != SOFTBUS_OK) {
        return SOFTBUS_NETWORK_LEDGER_INIT_FAILED;
    }
    if (LnnInitBusCenterEvent() != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "init bus center event fail");
        return SOFTBUS_CENTER_EVENT_INIT_FAILED;
    }
    if (LnnInitEventMonitor() != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "init event monitor fail");
        return SOFTBUS_EVENT_MONITER_INIT_FAILED;
    }
    if (LnnInitDiscoveryManager() != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "init discovery manager fail");
        return SOFTBUS_DISCOVER_MANAGER_INIT_FAIL;
    }
    if (LnnInitNetworkManager() != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "init lnn network manager fail");
        return SOFTBUS_NETWORK_MANAGER_INIT_FAILED;
    }
    if (LnnInitNetBuilder() != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "init net builder fail");
        return SOFTBUS_NETWORK_BUILDER_INIT_FAILED;
    }
    if (LnnInitMetaNode() != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "init meta node fail");
        return SOFTBUS_NETWORK_META_NODE_INIT_FAILED;
    }
    if (IsActiveOsAccountUnlocked()) {
        LNN_LOGI(LNN_INIT, "user unlocked try load local deviceinfo");
        RestoreLocalDeviceInfo();
    }
    return SOFTBUS_OK;
}

static int32_t BusCenterServerInitSecondStep(void)
{
    SoftBusRunPeriodicalTask(WATCHDOG_TASK_NAME, WatchdogProcess, WATCHDOG_INTERVAL_TIME, WATCHDOG_DELAY_TIME);
    if (LnnInitLaneHub() != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "init lane hub fail");
        return SOFTBUS_NO_INIT;
    }
    if (InitNodeAddrAllocator() != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "init nodeAddr fail");
        return SOFTBUS_NO_INIT;
    }
    if (RouteLSInit() != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "init route fail");
        return SOFTBUS_NO_INIT;
    }
    if (StartDelayInit() != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "start delay init fail");
        return SOFTBUS_NO_INIT;
    }
    if (InitDecisionCenter() != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "initDecisionCenter fail");
        return SOFTBUS_NO_INIT;
    }
    return SOFTBUS_OK;
}

int32_t LnnInitLnnLooper(void)
{
    SoftBusLooper *looper = CreateNewLooper("Lnn_Lp");
    if (!looper) {
        LNN_LOGE(LNN_LANE, "init laneLooper fail");
        return SOFTBUS_LOOPER_ERR;
    }
    SetLooper(LOOP_TYPE_LNN, looper);
    LNN_LOGI(LNN_LANE, "init laneLooper success");
    return SOFTBUS_OK;
}

void LnnDeinitLnnLooper(void)
{
    SoftBusLooper *looper = GetLooper(LOOP_TYPE_LNN);
    if (looper != NULL) {
        DestroyLooper(looper);
        SetLooper(LOOP_TYPE_LNN, NULL);
    }
}

int32_t BusCenterServerInit(void)
{
    int32_t ret = BusCenterServerInitFirstStep();
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    ret = BusCenterServerInitSecondStep();
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    LNN_LOGI(LNN_INIT, "bus center server init ok");
    return SOFTBUS_OK;
}

void BusCenterServerDeinit(void)
{
    RouteLSDeinit();
    DeinitNodeAddrAllocator();
    LnnDeinitLaneHub();
    LnnDeinitNetBuilder();
    LnnDeinitNetworkManager();
    LnnDeinitEventMonitor();
    LnnDeinitBusCenterEvent();
    LnnDeinitNetLedger();
    DeinitDecisionCenter();
    LnnDeinitMetaNode();
    LnnCoapConnectDeinit();
    LnnDeinitLnnLooper();
    LNN_LOGI(LNN_INIT, "bus center server deinit");
}
