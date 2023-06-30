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

#include "softbus_server_frame.h"

#include "auth_interface.h"
#include "bus_center_manager.h"
#include "lnn_bus_center_ipc.h"
#include "message_handler.h"
#include "wifi_direct_initiator.h"
#include "softbus_conn_interface.h"
#include "softbus_conn_ble_direct.h"
#include "softbus_disc_server.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log.h"
#include "softbus_utils.h"
#include "trans_session_manager.h"
#include "trans_session_service.h"
#include "softbus_hidumper_interface.h"
#include "softbus_hisysevt_common.h"

static bool g_isInit = false;

int __attribute__((weak)) ServerStubInit(void)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_WARN, "softbus server stub init(weak function).");
    return SOFTBUS_OK;
}

static void ServerModuleDeinit(void)
{
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

NO_SANITIZE("cfi") bool GetServerIsInit(void)
{
    return g_isInit;
}

NO_SANITIZE("cfi") void InitSoftBusServer(void)
{
    SoftbusConfigInit();

    if (ServerStubInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "server stub init failed.");
        return;
    }

    if (SoftBusTimerInit() == SOFTBUS_ERR) {
        return;
    }

    if (LooperInit() == -1) {
        return;
    }
    if (ConnServerInit() == SOFTBUS_ERR) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "softbus conn server init failed.");
        goto ERR_EXIT;
    }

    if (AuthInit() == SOFTBUS_ERR) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "softbus auth init failed.");
        goto ERR_EXIT;
    }

    if (DiscServerInit() == SOFTBUS_ERR) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "softbus disc server init failed.");
        goto ERR_EXIT;
    }

    if (BusCenterServerInit() == SOFTBUS_ERR) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "softbus buscenter server init failed.");
        goto ERR_EXIT;
    }
    ConnBleDirectInit();
    if (TransServerInit() == SOFTBUS_ERR) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "softbus trans server init failed.");
        goto ERR_EXIT;
    }

    if (WifiDirectInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "softbus wifi direct init failed.");
        goto ERR_EXIT;
    }

    if (InitSoftbusSysEvt() != SOFTBUS_OK || SoftBusHiDumperInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "softbus dfx init failed.");
        goto ERR_EXIT;
    }

    g_isInit = true;
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "softbus framework init success.");
    return;
ERR_EXIT:
    ServerModuleDeinit();
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "softbus framework init failed.");
    return;
}

NO_SANITIZE("cfi") void ClientDeathCallback(const char *pkgName, int32_t pid)
{
    DiscServerDeathCallback(pkgName);
    TransServerDeathCallback(pkgName, pid);
    BusCenterServerDeathCallback(pkgName);
}
