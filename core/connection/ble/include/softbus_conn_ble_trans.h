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

#ifndef SOFTBUS_CONN_BLE_TRANS_H
#define SOFTBUS_CONN_BLE_TRANS_H

#include "softbus_conn_common.h"
#include "softbus_conn_manager.h"
#include "softbus_conn_ble_trans_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t ConnBlePostBytesInner(
    uint32_t connectionId, uint8_t *data, uint32_t len, int32_t pid, int32_t flag, int32_t module, int64_t seq,
    PostBytesFinishAction postBytesFinishAction);
uint8_t *ConnGattTransRecv(
    uint32_t connectionId, uint8_t *data, uint32_t dataLen, ConnBleReadBuffer *buffer, uint32_t *outLen);
uint8_t *ConnCocTransRecv(
    uint32_t connectionId, LimitedBuffer *buffer, int32_t *outLen);
int64_t ConnBlePackCtlMessage(BleCtlMessageSerializationContext ctx, uint8_t **outData, uint32_t *outLen);
int32_t ConnBleTransConfigPostLimit(const LimitConfiguration *configuration);

int32_t ConnBleInitTransModule(ConnBleTransEventListener *listener);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* SOFTBUS_CONN_BLE_TRANS_H */