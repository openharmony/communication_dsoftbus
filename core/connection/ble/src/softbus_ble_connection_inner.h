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

#ifndef BLE_CONNECTION_INNER_H
#define BLE_CONNECTION_INNER_H

#include "common_list.h"
#include "softbus_adapter_ble_gatt_server.h"
#include "softbus_conn_manager.h"

#define MAX_CACHE_NUM_PER_CONN 3

typedef struct {
    int32_t isUsed;
    int32_t timeStamp;
    int32_t seq;
    int32_t currentSize;
    char *cache;
} BleRecvCache;

typedef struct {
    ListNode node;
    int32_t halConnId;
    uint32_t connId;
    SoftBusBtAddr btBinaryAddr;
    ConnectionInfo info;
    int32_t state;
    int32_t refCount;
    int32_t mtu;
    int32_t peerType;
    char peerDevId[UDID_BUF_LEN];
    BleRecvCache recvCache[MAX_CACHE_NUM_PER_CONN];
} BleConnectionInfo;

BleConnectionInfo* GetBleConnInfoByHalConnId(int32_t halConnectionId);
int32_t GetBleAttrHandle(int32_t module);

#endif