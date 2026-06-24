/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

/* Keep consistent with labels 0xd005760 - 0xd00577f*/
const SoftBusLogLabel CONN_LABELS[CONN_LABEL_MAX] = {
    {CONN_INIT,         0xd005760,      "ConnInit"},
    {CONN_BLE,          0xd005761,      "ConnBle"},
    {CONN_BR,           0xd005762,      "ConnBr"},
    {CONN_COMMON,       0xd005763,      "ConnCommon"},
    {CONN_WIFI_DIRECT,  0xd005764,      "ConnWD"},
    {CONN_NEARBY,       0xd005765,      "ConnNearby"},
    {CONN_BLE_DIRECT,   0xd005766,      "ConnBD"},
    {CONN_BROADCAST,    0xd005767,      "ConnBC"},
    {CONN_NEWIP,        0xd005768,      "ConnNewIp"},
    {CONN_ACTION,       0xd005769,      "ConnAction"},
    {CONN_SLE,          0xd005761,      "ConnSle"},
    {CONN_EVENT,        0xd00576a,      "ConnEvent"},
    {CONN_PROXY,        0xd005762,      "ConnProxy"},
    {CONN_FARFIELD,     0xd005762,      "ConnFarField"},
    {CONN_TEST,         DOMAIN_ID_TEST, "ConnTest"},
};
