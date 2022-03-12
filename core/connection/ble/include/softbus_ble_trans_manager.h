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

#ifndef SOFTBUS_BLE_TRANS_MANAGER_H
#define SOFTBUS_BLE_TRANS_MANAGER_H

#include "softbus_ble_connection_inner.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define MAX_DATA_LEN 4096

typedef struct {
    BleConnectionInfo* (*GetBleConnInfoByHalConnId)(BleHalConnInfo halConnInfo);
} SoftBusBleTransCalback;

int32_t BleTransInit(SoftBusBleTransCalback *cb);
int32_t BleTransSend(BleConnectionInfo *connInfo, const char *data, uint32_t len, int32_t seq, int32_t module);
char *BleTransRecv(BleHalConnInfo halConnInfo, char *value, uint32_t len, uint32_t *outLen, int32_t *index);
void BleTransCacheFree(BleHalConnInfo halConnInfo, int32_t index);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif