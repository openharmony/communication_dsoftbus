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
#include "softbus_common.h"
#include "softbus_conn_ble_connection.h"
#include "softbus_conn_ble_client.h"
#include "softbus_conn_ble_server.h"

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

const BleUnifyInterface *ConnBleGetUnifyInterface(BleProtocolType type)
{
    if (type != BLE_GATT) {
        CONN_LOGE(CONN_BLE, "Failed to return type.");
        return NULL;
    }
    return &g_bleUnifyInterface[type];
}