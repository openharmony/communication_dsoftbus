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

#include "disc_coap_capability.h"

#include "disc_nstackx_adapter.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

void DiscCoapParseExtendServiceData(const cJSON *data, DeviceInfo *device)
{
    (void)data;
    (void)device;
}

int32_t DiscCoapAssembleCapData(uint32_t capability, const char *capabilityData, uint32_t dataLen, char *outData)
{
    (void)capability;
    (void)capabilityData;
    (void)dataLen;
    (void)outData;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

void DiscVerifySoftbus(DeviceInfo *device)
{
    if (DiscCoapSendRsp(device) != SOFTBUS_OK) {
        DLOGE("send response failed");
    }
}