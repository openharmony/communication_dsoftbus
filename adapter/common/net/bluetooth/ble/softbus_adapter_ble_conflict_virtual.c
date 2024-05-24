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

#include "softbus_adapter_ble_conflict.h"

void SoftbusBleConflictRegisterListener(SoftBusBleConflictListener *listener)
{
    (void)listener;
}

void SoftbusBleConflictNotifyConnectResult(uint32_t requestId, int32_t underlayerHandle, bool status)
{
    (void)requestId;
    (void)underlayerHandle;
    (void)status;
}

void SoftbusBleConflictNotifyDateReceive(int32_t underlayerHandle, const uint8_t *data, uint32_t dataLen)
{
    (void)underlayerHandle;
    (void)data;
    (void)dataLen;
}

void SoftbusBleConflictNotifyDisconnect(const char *addr, const char *udid)
{
    (void)addr;
    (void)udid;
}
