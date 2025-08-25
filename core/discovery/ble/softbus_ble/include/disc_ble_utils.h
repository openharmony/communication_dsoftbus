/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef DISC_BLE_UTILS_H
#define DISC_BLE_UTILS_H

#include <stdbool.h>
#include <stdint.h>

#include "broadcast_protocol_constant.h"
#include "disc_ble_utils_struct.h"
#include "softbus_common.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

bool CheckBitMapEmpty(uint32_t capBitMapNum, const uint32_t *capBitMap);
bool CheckCapBitMapExist(uint32_t capBitMapNum, const uint32_t *capBitMap, uint32_t pos);
void SetCapBitMapPos(uint32_t capBitMapNum, uint32_t *capBitMap, uint32_t pos);
void UnsetCapBitMapPos(uint32_t capBitMapNum, uint32_t *capBitMap, uint32_t pos);

int32_t DiscBleGetDeviceName(char *deviceName, uint32_t size);
uint16_t DiscBleGetDeviceType(void);
int32_t DiscBleGetDeviceIdHash(unsigned char *devIdHash, uint32_t len);
int32_t DiscBleGetShortUserIdHash(unsigned char *hashStr, uint32_t len);

int32_t AssembleTLV(BroadcastData *broadcastData, unsigned char dataType, const void *data, uint32_t dataLen);
int32_t GetDeviceInfoFromDisAdvData(DeviceWrapper *device, const uint8_t *data, uint32_t dataLen);
int32_t DiscSoftbusBleBuildReportJson(DeviceInfo *device, uint32_t handleId);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif
