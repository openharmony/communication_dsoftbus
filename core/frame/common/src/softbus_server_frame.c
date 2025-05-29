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

#include <dlfcn.h>

#include "auth_interface.h"
#include "auth_uk_manager.h"
#include "bus_center_manager.h"
#include "conn_log.h"
#include "disc_event_manager.h"
#include "g_enhance_conn_func.h"
#include "g_enhance_conn_func_pack.h"
#include "g_enhance_lnn_func.h"
#include "g_enhance_trans_func.h"
#include "g_enhance_disc_func.h"
#include "g_enhance_adapter_func.h"
#include "g_enhance_auth_func.h"
#include "instant_statistics.h"
#include "lnn_bus_center_ipc.h"
#include "lnn_sle_monitor.h"
#include "lnn_init_monitor.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_disc_server.h"
#include "softbus_feature_config.h"
#include "legacy/softbus_hidumper_interface.h"
#include "legacy/softbus_hisysevt_common.h"
#include "softbus_utils.h"
#include "softbus_lnn_init.h"
#include "softbus_conn_init.h"
#include "softbus_adapter_init.h"
#include "softbus_authentication_init.h"
#include "softbus_disc_init.h"
#include "softbus_trans_init.h"
#include "softbus_ddos.h"
#include "softbus_init_common.h"
#include "trans_session_service.h"
#include "wifi_direct_manager.h"

#ifdef __aarch64__
static const char *SOFTBUS_SERVER_PLUGIN_PATH_NAME = "/system/lib64/libdsoftbus_server_plugin.z.so";
#else
static const char *SOFTBUS_SERVER_PLUGIN_PATH_NAME = "/system/lib/libdsoftbus_server_plugin.z.so";
#endif

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
    DeinitDdos();
    LnnDeinitSle();
}

bool GetServerIsInit(void)
{
    return g_isInit;
}

static int32_t softbusServerOpenFuncInit(void *soHandle)
{
    if (soHandle == NULL) {
        return SOFTBUS_NETWORK_DLOPEN_FAILED;
    }
    if (LnnOpenFuncInit(soHandle) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "softbus Lnn Open Func init failed.");
        return SOFTBUS_NETWORK_LNN_OPEN_FUNC_INIT_FAILED;
    }
    if (ConnOpenFuncInit(soHandle) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "softbus Conn Open Func init failed.");
        return SOFTBUS_NETWORK_CONN_OPEN_FUNC_INIT_FAILED;
    }
    if (AdapterOpenFuncInit(soHandle) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "softbus Adapter Open Func init failed.");
        return SOFTBUS_NETWORK_ADAPTER_OPEN_FUNC_INIT_FAILED;
    }
    if (AuthOpenFuncInit(soHandle) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "softbus Auth Open Func init failed.");
        return SOFTBUS_NETWORK_AUTH_OPEN_FUNC_INIT_FAILED;
    }
    if (DiscOpenFuncInit(soHandle) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "softbus Disc Open Func init failed.");
        return SOFTBUS_NETWORK_DISC_OPEN_FUNC_INIT_FAILED;
    }
    if (TransOpenFuncInit(soHandle) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "softbus Trans Open Func init failed.");
        return SOFTBUS_NETWORK_TRANS_ENHANCE_FUNC_INIT_FAILED;
    }
    return SOFTBUS_OK;
}
 
static int32_t softbusServerEnhanceFuncInit(void *soHandle)
{
    if (soHandle == NULL) {
        return SOFTBUS_NETWORK_DLOPEN_FAILED;
    }
    if (LnnRegisterEnhanceFunc(soHandle) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "softbus Lnn Enhance Func init failed.");
        return SOFTBUS_NETWORK_LNN_ENHANCE_FUNC_INIT_FAILED;
    }
    if (ConnRegisterEnhanceFunc(soHandle) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "softbus Conn Enhance Func init failed.");
        return SOFTBUS_NETWORK_CONN_ENHANCE_FUNC_INIT_FAILED;
    }
    if (AdapterRegisterEnhanceFunc(soHandle) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "softbus Adapter Enhance Func init failed.");
        return SOFTBUS_NETWORK_ADAPTER_ENHANCE_FUNC_INIT_FAILED;
    }
    if (AuthRegisterEnhanceFunc(soHandle) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "softbus Auth Enhance Func init failed.");
        return SOFTBUS_NETWORK_AUTH_ENHANCE_FUNC_INIT_FAILED;
    }
    if (DiscRegisterEnhanceFunc(soHandle) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "softbus Disc Enhance Func init failed.");
        return SOFTBUS_NETWORK_DISC_ENHANCE_FUNC_INIT_FAILED;
    }
    if (TransRegisterEnhanceFunc(soHandle) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "softbus Trans Enhance Func init failed.");
        return SOFTBUS_NETWORK_TRANS_ENHANCE_FUNC_INIT_FAILED;
    }
    return SOFTBUS_OK;
}
 
static void ServerFuncInit(void)
{
    int ret = SOFTBUS_OK;
    void *pluginServerSoHandle = NULL;
    (void)SoftBusDlopen(SOFTBUS_SERVER_PLUGIN_PATH_NAME, &pluginServerSoHandle);
    if (pluginServerSoHandle == NULL) {
        COMM_LOGE(COMM_SVC, "dlopen libdsoftbus_server_plugin.z.so failed.");
        SoftbusServerPluginLoadedFlagSet(false);
        return;
    }
 
    ret = softbusServerOpenFuncInit(pluginServerSoHandle);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "init softbus server Open func failed");
    }
 
    ret = softbusServerEnhanceFuncInit(pluginServerSoHandle);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "init softbus server Enhance func failed");
    } else {
        SoftbusServerPluginLoadedFlagSet(true);
    }
 
    // SoftBusDlclose(pluginServerSoHandle);
}

static int32_t InitServicesAndModules(void)
{
    COMM_CHECK_AND_RETURN_RET_LOGE(ConnServerInit() == SOFTBUS_OK,
        SOFTBUS_CONN_SERVER_INIT_FAILED, COMM_SVC, "softbus conn server init failed.");

    COMM_CHECK_AND_RETURN_RET_LOGE(AuthInit() == SOFTBUS_OK,
        SOFTBUS_AUTH_INIT_FAIL, COMM_SVC, "softbus auth init failed.");

    COMM_CHECK_AND_RETURN_RET_LOGE(DiscServerInit() == SOFTBUS_OK,
        SOFTBUS_DISC_SERVER_INIT_FAILED, COMM_SVC, "softbus disc server init failed.");

    COMM_CHECK_AND_RETURN_RET_LOGE(BusCenterServerInit() == SOFTBUS_OK,
        SOFTBUS_CENTER_SERVER_INIT_FAILED, COMM_SVC, "softbus buscenter server init failed.");

    COMM_CHECK_AND_RETURN_RET_LOGE(TransServerInit() == SOFTBUS_OK,
        SOFTBUS_TRANS_SERVER_INIT_FAILED, COMM_SVC, "softbus trans server init failed.");

    COMM_CHECK_AND_RETURN_RET_LOGE(DiscEventManagerInit() == SOFTBUS_OK,
        SOFTBUS_DISCOVER_MANAGER_INIT_FAIL, COMM_SVC, "softbus disc event manager init failed.");

    COMM_CHECK_AND_RETURN_RET_LOGE(GetWifiDirectManager()->init() == SOFTBUS_OK,
        SOFTBUS_WIFI_DIRECT_INIT_FAILED, COMM_SVC, "softbus wifi direct init failed.");

    COMM_CHECK_AND_RETURN_RET_LOGE(ConnBleDirectInitPacked() == SOFTBUS_OK,
        SOFTBUS_CONN_BLE_DIRECT_INIT_FAILED, COMM_SVC, "softbus ble direct init failed.");

    if (InitSoftbusSysEvt() != SOFTBUS_OK || SoftBusHiDumperInit() != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "softbus dfx init failed.");
        return SOFTBUS_DFX_INIT_FAILED;
    }
    if (LnnInitSle() != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "softbus lnn sle init failed.");
    }
    InstRegister(NULL);
    return SOFTBUS_OK;
}

void InitSoftBusServer(void)
{
    ServerFuncInit();
    SoftbusConfigInit();
    LnnInitMonitorInit();
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

    if (InitDdos() != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "softbus ddos init failed.");
    }

    int32_t ret = InitServicesAndModules();
    if (ret != SOFTBUS_OK) {
        ServerModuleDeinit();
        COMM_LOGE(COMM_SVC, "softbus framework init failed, err = %{public}d", ret);
        return;
    }
    ret = SoftBusBtInit();
    if (ret != SOFTBUS_OK) {
        LnnInitModuleReturnSet(INIT_DEPS_BLUETOOTH, ret);
        LnnInitModuleStatusSet(INIT_DEPS_BLUETOOTH, DEPS_STATUS_FAILED);
        ServerModuleDeinit();
        COMM_LOGE(COMM_SVC, "softbus bt init failed, err = %{public}d", ret);
        return;
    }
    LnnInitModuleStatusSet(INIT_DEPS_BLUETOOTH, DEPS_STATUS_SUCCESS);
    LnnModuleInitMonitorCheckStart();
    UkNegotiateSessionInit();
    g_isInit = true;
    COMM_LOGI(COMM_SVC, "softbus framework init success.");
}

void ClientDeathCallback(const char *pkgName, int32_t pid)
{
    DiscServerDeathCallback(pkgName, pid);
    TransServerDeathCallback(pkgName, pid);
    BusCenterServerDeathCallback(pkgName);
    AuthServerDeathCallback(pkgName, pid);
    ConnDeathCallback(pkgName, pid);
}
