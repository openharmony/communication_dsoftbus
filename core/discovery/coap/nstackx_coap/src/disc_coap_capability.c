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
#include "softbus_log_old.h"

int32_t DiscCoapParseExtendServiceData(const cJSON *data, DeviceInfo *device)
{
    (void)data;
    (void)device;
    return SOFTBUS_OK;
}

int32_t DiscCoapAssembleCapData(uint32_t capability, const char *capabilityData, uint32_t dataLen, char *outData)
{
    (void)capability;
    (void)capabilityData;
    (void)dataLen;
    (void)outData;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

void DiscVerifyBroadcastType(DeviceInfo *device, uint8_t bType)
{
    if (DiscCoapSendRsp(device, bType) != SOFTBUS_OK) {
        DLOGE("send response failed for bType(%u)", bType);
    }
}

void DiscCheckBtype(DeviceInfo *device, uint8_t bType)
{
    (void)device;
    (void)bType;
}

void DiscFillBtype(uint32_t capability, uint32_t allCap, NSTACKX_DiscoverySettings *discSet)
{
    (void)allCap;
    DISC_CHECK_AND_RETURN_LOG(discSet != NULL, "discSet is NULL");
    switch (capability) {
        case 1 << OSD_CAPABILITY_BITMAP:
            discSet->businessType = (uint8_t)NSTACKX_BUSINESS_TYPE_NULL;
            break;
        case 1 << DDMP_CAPABILITY_BITMAP:
            discSet->businessType = (uint8_t)NSTACKX_BUSINESS_TYPE_AUTONET;
            break;
        case 1 << SHARE_CAPABILITY_BITMAP:
            discSet->businessType = (uint8_t)NSTACKX_BUSINESS_TYPE_STRATEGY;
            break;
        default:
            DLOGI("use the default bType for capability(%u)", capability);
            discSet->businessType = (uint8_t)NSTACKX_BUSINESS_TYPE_NULL;
            break;
    }
}