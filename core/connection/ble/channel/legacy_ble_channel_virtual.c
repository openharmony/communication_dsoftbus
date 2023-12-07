/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "conn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_ble_connection.h"
#include "softbus_conn_interface.h"
#include "softbus_error_code.h"

ConnBleConnection *g_connection = NULL;
ConnBleConnection *LegacyBleCreateConnection(const char *addr, ConnSideType side,
    int32_t underlayerHandle, bool fastestConnectEnable)
{
    if (g_connection == NULL) {
        g_connection = (ConnBleConnection *)SoftBusCalloc(sizeof(ConnBleConnection));
        CONN_CHECK_AND_RETURN_RET_LOGE(g_connection != NULL, NULL, CONN_NEARBY, "ble connection calloc failed");
        g_connection->side = side;
        g_connection->underlayerHandle = underlayerHandle;
        g_connection->serviceId = LEGACY_GATT_SERVICE;
    }
    return g_connection;
}

ConnBleConnection *LegacyBleGetConnectionByHandle(int32_t underlayerHandle, ConnSideType side)
{
    return g_connection;
}

ConnBleConnection *LegacyBleGetConnectionById(uint32_t connectinId)
{
    return g_connection;
}

int32_t LegacyBleSaveConnection(ConnBleConnection *connection)
{
    return SOFTBUS_OK;
}

void LegacyBleReturnConnection(ConnBleConnection **connection)
{
}

void LegacyBleRemoveConnection(ConnBleConnection *connection)
{
    SoftBusFree(g_connection);
    g_connection = NULL;
}