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

#include "softbus_adapter_bt_common.h"
#include "softbus_conn_ble_manager.h"

ConnectFuncInterface *ConnInitBle(const ConnectCallback *callback)
{
    (void)callback;
    return NULL;
}

int SoftBusGetBtState(void)
{
    return BLE_DISABLE;
}

ConnBleConnection *ConnBleGetClientConnectionByUdid(const char *udid, BleProtocolType protocol)
{
    (void)udid;
    (void)protocol;
    return NULL;
}

ConnBleConnection *ConnBleGetConnectionByUdid(const char *addr, const char *udid, BleProtocolType protocol)
{
    (void)addr;
    (void)udid;
    (void)protocol;
    return NULL;
}

void ConnBleReturnConnection(ConnBleConnection **connection)
{
    (void)connection;
}
