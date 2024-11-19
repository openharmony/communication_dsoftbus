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
#include "softbus_conn_interface.h"
#include "softbus_conn_ble_direct.h"
#include "softbus_error_code.h"

int32_t ConnBleDirectConnectDevice(const ConnectOption *option, uint32_t reqId, const ConnectResult* result)
{
    CONN_LOGW(CONN_BLE, "do not support ble direct connection");
    return SOFTBUS_NOT_IMPLEMENT;
}

bool ConnBleDirectIsEnable(BleProtocolType protocol)
{
    CONN_LOGW(CONN_BLE, "do not support ble direct connection");
    return false;
}

int32_t ConnBleDirectInit(void)
{
    return SOFTBUS_OK;
}