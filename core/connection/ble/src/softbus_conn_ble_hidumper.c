/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "softbus_conn_ble_snapshot.h"
#include "legacy/softbus_hidumper_conn.h"

#define CONN_BLE_HIDUMPER "ConnBleHiDumper"

int32_t BleHiDumperRegister(void)
{
    return SoftBusRegConnVarDump(CONN_BLE_HIDUMPER, BleHiDumper);
}