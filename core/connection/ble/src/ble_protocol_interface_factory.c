/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "ble_protocol_interface_factory.h"
#include "conn_log.h"
#include "g_enhance_conn_func.h"
#include "softbus_init_common.h"
#include "softbus_common.h"
#include "softbus_conn_ble_connection.h"
#include "softbus_conn_ble_client.h"
#include "softbus_conn_ble_server.h"

#ifdef DSOFTBUS_FEATURE_CONN_COC
static int32_t ConnCocClientConnect(ConnBleConnection *connection)
{
    ConnEnhanceFuncList *pfnConnEnhanceFuncList = ConnEnhanceFuncListGet();
    if (pfnConnEnhanceFuncList->connCocClientConnect == NULL) {
        CONN_LOGE(CONN_BLE, "connCocClientConnect not register");
        return SOFTBUS_FUNC_NOT_REGISTER;
    }
    return pfnConnEnhanceFuncList->connCocClientConnect(connection);
}

static int32_t ConnCocClientDisconnect(ConnBleConnection *connection, bool ignore1, bool ignore2)
{
    ConnEnhanceFuncList *pfnConnEnhanceFuncList = ConnEnhanceFuncListGet();
    if (pfnConnEnhanceFuncList->connCocClientDisconnect == NULL) {
        CONN_LOGE(CONN_BLE, "connCocClientDisconnect not register");
        return SOFTBUS_FUNC_NOT_REGISTER;
    }
    return pfnConnEnhanceFuncList->connCocClientDisconnect(connection, ignore1, ignore2);
}

static int32_t ConnCocClientSend(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module)
{
    ConnEnhanceFuncList *pfnConnEnhanceFuncList = ConnEnhanceFuncListGet();
    if (pfnConnEnhanceFuncList->connCocClientSend == NULL) {
        CONN_LOGE(CONN_BLE, "connCocClientSend not register");
        return SOFTBUS_FUNC_NOT_REGISTER;
    }
    return pfnConnEnhanceFuncList->connCocClientSend(connection, data, dataLen, module);
}

static int32_t ConnCocClientUpdatePriority(ConnBleConnection *connection, ConnectBlePriority priority)
{
    ConnEnhanceFuncList *pfnConnEnhanceFuncList = ConnEnhanceFuncListGet();
    if (pfnConnEnhanceFuncList->connCocClientUpdatePriority == NULL) {
        CONN_LOGE(CONN_BLE, "connCocClientUpdatePriority not register");
        return SOFTBUS_FUNC_NOT_REGISTER;
    }
    return pfnConnEnhanceFuncList->connCocClientUpdatePriority(connection, priority);
}

static int32_t ConnCocServerStartService(void)
{
    ConnEnhanceFuncList *pfnConnEnhanceFuncList = ConnEnhanceFuncListGet();
    if (pfnConnEnhanceFuncList->connCocServerStartService == NULL) {
        CONN_LOGE(CONN_BLE, "connCocServerStartService not register");
        return SOFTBUS_FUNC_NOT_REGISTER;
    }
    return pfnConnEnhanceFuncList->connCocServerStartService();
}

static int32_t ConnCocServerStopService(void)
{
    ConnEnhanceFuncList *pfnConnEnhanceFuncList = ConnEnhanceFuncListGet();
    if (pfnConnEnhanceFuncList->connCocServerStopService == NULL) {
        CONN_LOGE(CONN_BLE, "connCocServerStopService not register");
        return SOFTBUS_FUNC_NOT_REGISTER;
    }
    return pfnConnEnhanceFuncList->connCocServerStopService();
}

static int32_t ConnCocServerSend(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module)
{
    ConnEnhanceFuncList *pfnConnEnhanceFuncList = ConnEnhanceFuncListGet();
    if (pfnConnEnhanceFuncList->connCocServerSend == NULL) {
        CONN_LOGE(CONN_BLE, "connCocServerSend not register");
        return SOFTBUS_FUNC_NOT_REGISTER;
    }
    return pfnConnEnhanceFuncList->connCocServerSend(connection, data, dataLen, module);
}

static int32_t ConnCocServerDisconnect(ConnBleConnection *connection)
{
    ConnEnhanceFuncList *pfnConnEnhanceFuncList = ConnEnhanceFuncListGet();
    if (pfnConnEnhanceFuncList->connCocServerDisconnect == NULL) {
        CONN_LOGE(CONN_BLE, "connCocServerDisconnect not register");
        return SOFTBUS_FUNC_NOT_REGISTER;
    }
    return pfnConnEnhanceFuncList->connCocServerDisconnect(connection);
}

static int32_t ConnCocServerConnect(ConnBleConnection *connection)
{
    ConnEnhanceFuncList *pfnConnEnhanceFuncList = ConnEnhanceFuncListGet();
    if (pfnConnEnhanceFuncList->connCocServerConnect == NULL) {
        CONN_LOGE(CONN_BLE, "connCocServerConnect not register");
        return SOFTBUS_FUNC_NOT_REGISTER;
    }
    return pfnConnEnhanceFuncList->connCocServerConnect(connection);
}

static int32_t ConnCocInitClientModule(SoftBusLooper *looper, const ConnBleClientEventListener *cListener)
{
    ConnEnhanceFuncList *pfnConnEnhanceFuncList = ConnEnhanceFuncListGet();
    if (pfnConnEnhanceFuncList->connCocInitClientModule == NULL) {
        CONN_LOGE(CONN_BLE, "connCocInitClientModule not register");
        return SOFTBUS_FUNC_NOT_REGISTER;
    }

    return pfnConnEnhanceFuncList->connCocInitClientModule(looper, cListener);
}

static int32_t ConnCocInitServerModule(SoftBusLooper *looper, const ConnBleServerEventListener *sListener)
{
    ConnEnhanceFuncList *pfnConnEnhanceFuncList = ConnEnhanceFuncListGet();
    if (pfnConnEnhanceFuncList->connCocInitServerModule == NULL) {
        CONN_LOGE(CONN_BLE, "connCocInitServerModule not register");
        return SOFTBUS_FUNC_NOT_REGISTER;
    }
    return pfnConnEnhanceFuncList->connCocInitServerModule(looper, sListener);
}
#endif

static BleUnifyInterface g_bleUnifyInterface[BLE_PROTOCOL_MAX] = {
    [BLE_GATT] = {
        .bleClientConnect = ConnGattClientConnect,
        .bleClientDisconnect = ConnGattClientDisconnect,
        .bleClientSend = ConnGattClientSend,
        .bleClientUpdatePriority = ConnGattClientUpdatePriority,
        .bleServerStartService = ConnGattServerStartService,
        .bleServerStopService = ConnGattServerStopService,
        .bleServerSend = ConnGattServerSend,
        .bleServerDisconnect = ConnGattServerDisconnect,
        .bleServerConnect = ConnGattServerConnect,
        .bleClientInitModule = ConnGattInitClientModule,
        .bleServerInitModule = ConnGattInitServerModule,
    }
};

static void ConnCocInit(void)
{
    if (SoftbusServerPluginLoadedFlagGet()) {
#ifdef DSOFTBUS_FEATURE_CONN_COC
        g_bleUnifyInterface[BLE_COC].bleClientConnect = ConnCocClientConnect;
        g_bleUnifyInterface[BLE_COC].bleClientDisconnect = ConnCocClientDisconnect;
        g_bleUnifyInterface[BLE_COC].bleClientSend = ConnCocClientSend;
        g_bleUnifyInterface[BLE_COC].bleClientUpdatePriority= ConnCocClientUpdatePriority;
        g_bleUnifyInterface[BLE_COC].bleServerStartService = ConnCocServerStartService;
        g_bleUnifyInterface[BLE_COC].bleServerStopService = ConnCocServerStopService;
        g_bleUnifyInterface[BLE_COC].bleServerSend = ConnCocServerSend;
        g_bleUnifyInterface[BLE_COC].bleServerDisconnect = ConnCocServerDisconnect;
        g_bleUnifyInterface[BLE_COC].bleServerConnect = ConnCocServerConnect;
        g_bleUnifyInterface[BLE_COC].bleClientInitModule = ConnCocInitClientModule;
        g_bleUnifyInterface[BLE_COC].bleServerInitModule = ConnCocInitServerModule;
#endif
    }

    return;
}

const BleUnifyInterface *ConnBleGetUnifyInterface(BleProtocolType type)
{
    if (type != BLE_GATT && type != BLE_COC) {
        CONN_LOGE(CONN_BLE, "Failed to return type.");
        return NULL;
    }
    ConnCocInit();
    if (g_bleUnifyInterface[BLE_COC].bleClientConnect == NULL ||
        g_bleUnifyInterface[BLE_COC].bleClientDisconnect == NULL ||
        g_bleUnifyInterface[BLE_COC].bleClientSend == NULL ||
        g_bleUnifyInterface[BLE_COC].bleClientUpdatePriority == NULL ||
        g_bleUnifyInterface[BLE_COC].bleServerStartService == NULL ||
        g_bleUnifyInterface[BLE_COC].bleServerStopService == NULL ||
        g_bleUnifyInterface[BLE_COC].bleServerSend == NULL ||
        g_bleUnifyInterface[BLE_COC].bleServerDisconnect == NULL ||
        g_bleUnifyInterface[BLE_COC].bleClientInitModule == NULL ||
        g_bleUnifyInterface[BLE_COC].bleServerInitModule == NULL) {
        if (type == BLE_COC) {
            CONN_LOGE(CONN_BLE, "Failed to return type, ble_coc not register.");
            return NULL;
        }
    }
    return &g_bleUnifyInterface[type];
}