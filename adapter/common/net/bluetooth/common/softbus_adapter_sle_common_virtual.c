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

#include "softbus_adapter_sle_common.h"

#include "comm_log.h"
#include "softbus_error_code.h"

#define MAX_SLE_STATE_LISTENER_NUM 16

typedef struct {
    bool isUsed;
    SoftBusSleStateListener *listener;
} SleStateListener;

bool IsSleEnabled(void)
{
    return false;
}

int SoftBusAddSleStateListener(const SoftBusSleStateListener *listener, int *listenerId)
{
    (void)listener;
    return SOFTBUS_OK;
}
void SoftBusRemoveSleStateListener(int listenerId)
{}

int32_t GetSleRangeCapacity(void)
{
    return 0;
}

int32_t GetLocalSleAddr(char *sleAddr, uint32_t sleAddrLen)
{
    (void)sleAddr;
    (void)sleAddrLen;
    return SOFTBUS_OK;
}

