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

#include "softbus_conn_ble_coc.h"

#include "securec.h"

#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_coc.h"
#include "softbus_conn_ble_connection.h"
#include "softbus_conn_ble_manager.h"
#include "softbus_feature_config.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_type_def.h"
#include "softbus_utils.h"

int32_t ConnCocClientConnect(ConnBleConnection *connection)
{
    (void)connection;
    return SOFTBUS_ERR;
}

int32_t ConnCocClientDisconnect(ConnBleConnection *connection, bool ignore1, bool ignore2)
{
    (void)connection;
    (void)ignore1;
    (void)ignore2;
    return SOFTBUS_ERR;
}

int32_t ConnCocClientSend(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module)
{
    (void)connection;
    (void)data;
    (void)dataLen;
    (void)module;
    return SOFTBUS_ERR;
}

int32_t ConnCocClientUpdatePriority(ConnBleConnection *connection, ConnectBlePriority priority)
{
    (void)connection;
    (void)priority;
    return SOFTBUS_ERR;
}

int32_t ConnCocGetServerPsm()
{
    return SOFTBUS_ERR;
}

int32_t ConnCocServerStartService()
{
    return SOFTBUS_OK;
}

int32_t ConnCocServerStopService(void)
{
    return SOFTBUS_OK;
}

int32_t ConnCocServerSend(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module)
{
    return SOFTBUS_ERR;
}

int32_t ConnCocServerDisconnect(ConnBleConnection *connection)
{
    (void)connection;
    return SOFTBUS_ERR;
}

int32_t ConnCocServerConnect(ConnBleConnection *connection)
{
    (void)connection;
    return SOFTBUS_ERR;
}

int32_t ConnCocInitModule(SoftBusLooper *looper, const ConnBleClientEventListener *cListener,
    const ConnBleServerEventListener *sListener)
{
    (void)looper;
    (void)cListener;
    (void)sListener;
    return SOFTBUS_OK;
}