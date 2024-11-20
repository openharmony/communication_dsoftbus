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

#include "softbus_server_frame.h"

#include "auth_interface.h"
#include "bus_center_manager.h"
#include "disc_event_manager.h"
#include "instant_statistics.h"
#include "lnn_bus_center_ipc.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_conn_ble_direct.h"
#include "softbus_disc_server.h"
#include "softbus_feature_config.h"
#include "legacy/softbus_hidumper_interface.h"
#include "legacy/softbus_hisysevt_common.h"
#include "softbus_utils.h"
#include "trans_session_service.h"
#include "wifi_direct_manager.h"

static bool g_isInit = false;

int __attribute__((weak)) ServerStubInit(void)
{
    COMM_LOGW(COMM_SVC, "softbus server stub init(weak function).");
    return SOFTBUS_OK;
}

static void ServerModuleDeinit(void)
{
    DiscEventManagerDeinit();
    DiscServerDeinit();
    ConnServerDeinit();
    TransServerDeinit();
    BusCenterServerDeinit();
    AuthDeinit();
    SoftBusTimerDeInit();
    LooperDeinit();
    SoftBusHiDumperDeinit();
    DeinitSoftbusSysEvt();
}

bool GetServerIsInit(void)
{
    return g_isInit;
}

static int32_t InitServicesAndModules(void)
{
    if (ConnServerInit() != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "softbus conn server init failed.");
        return SOFTBUS_CONN_SERVER_INIT_FAILED;
    }

    if (AuthInit() != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "softbus auth init failed.");
        return SOFTBUS_AUTH_INIT_FAIL;
    }

    if (DiscServerInit() != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "softbus disc server init failed.");
        return SOFTBUS_DISC_SERVER_INIT_FAILED;
    }

    if (BusCenterServerInit() != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "softbus buscenter server init failed.");
        return SOFTBUS_CENTER_SERVER_INIT_FAILED;
    }

    if (TransServerInit() != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "softbus trans server init failed.");
        return SOFTBUS_TRANS_SERVER_INIT_FAILED;
    }

    if (DiscEventManagerInit() != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "softbus disc event manager init failed.");
        return SOFTBUS_DISCOVER_MANAGER_INIT_FAIL;
    }

    if (GetWifiDirectManager()->init() != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "softbus wifi direct init failed.");
        return SOFTBUS_WIFI_DIRECT_INIT_FAILED;
    }

    if (ConnBleDirectInit() != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "softbus ble direct init failed.");
        return SOFTBUS_CONN_BLE_DIRECT_INIT_FAILED;
    }

    if (InitSoftbusSysEvt() != SOFTBUS_OK || SoftBusHiDumperInit() != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "softbus dfx init failed.");
        return SOFTBUS_DFX_INIT_FAILED;
    }

    InstRegister(NULL);
    return SOFTBUS_OK;
}

void InitSoftBusServer(void)
{
    SoftbusConfigInit();

    if (ServerStubInit() != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "server stub init failed.");
        return;
    }

    if (SoftBusTimerInit() != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "softbus timer init failed.");
        return;
    }

    if (LooperInit() != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "softbus looper init failed.");
        return;
    }

    int32_t ret = InitServicesAndModules();
    if (ret != SOFTBUS_OK) {
        ServerModuleDeinit();
        COMM_LOGE(COMM_SVC, "softbus framework init failed, err = %{public}d", ret);
        return;
    }

    ret = SoftBusBtInit();
    if (ret != SOFTBUS_OK) {
        ServerModuleDeinit();
        COMM_LOGE(COMM_SVC, "softbus bt init failed, err = %{public}d", ret);
        return;
    }
    g_isInit = true;
    COMM_LOGI(COMM_SVC, "softbus framework init success.");
}

void ClientDeathCallback(const char *pkgName, int32_t pid)
{
    DiscServerDeathCallback(pkgName);
    TransServerDeathCallback(pkgName, pid);
    BusCenterServerDeathCallback(pkgName);
    AuthServerDeathCallback(pkgName, pid);
}
