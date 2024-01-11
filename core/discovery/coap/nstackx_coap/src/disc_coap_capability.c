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

#include "disc_log.h"
#include "disc_nstackx_adapter.h"
#include "softbus_errcode.h"

int32_t DiscCoapAssembleCapData(uint32_t capability, const char *capabilityData, uint32_t dataLen, char *outData,
    uint32_t outLen)
{
    (void)capability;
    (void)capabilityData;
    (void)dataLen;
    (void)outData;
    (void)outLen;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

void DiscFillBtype(uint32_t capability, uint32_t allCap, NSTACKX_DiscoverySettings *discSet)
{
    (void)allCap;
    DISC_CHECK_AND_RETURN_LOGW(discSet != NULL, DISC_COAP, "discSet is NULL");
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
            DISC_LOGW(DISC_COAP, "use the default bType, capability=%{public}u", capability);
            discSet->businessType = (uint8_t)NSTACKX_BUSINESS_TYPE_NULL;
            break;
    }
}

int32_t DiscCoapProcessDeviceInfo(const NSTACKX_DeviceInfo *nstackxInfo, DeviceInfo *devInfo,
    const DiscInnerCallback *discCb)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(nstackxInfo != NULL, SOFTBUS_INVALID_PARAM, DISC_COAP, "nstackx devInfo is NULL");
    DISC_CHECK_AND_RETURN_RET_LOGE(devInfo != NULL, SOFTBUS_INVALID_PARAM, DISC_COAP, "devInfo is NULL");
    DISC_CHECK_AND_RETURN_RET_LOGE(discCb != NULL && discCb->OnDeviceFound != NULL,
        SOFTBUS_INVALID_PARAM, DISC_COAP, "discCb is NULL");

    InnerDeviceInfoAddtions addtions = {
        .medium = COAP,
    };
    if (nstackxInfo->discoveryType == NSTACKX_DISCOVERY_TYPE_ACTIVE ||
        nstackxInfo->mode == PUBLISH_MODE_PROACTIVE) {
        DISC_LOGI(DISC_COAP,
            "DiscFound: devName=%{public}s, netIf=%{public}s", devInfo->devName, nstackxInfo->networkName);
        discCb->OnDeviceFound(devInfo, &addtions);
        return SOFTBUS_OK;
    }

    uint8_t bType = nstackxInfo->businessType;
    DISC_LOGI(DISC_COAP, "DiscRecv: broadcast devName=%{public}s, bType=%{public}u", devInfo->devName, bType);
    if (bType != NSTACKX_BUSINESS_TYPE_NULL && DiscCoapSendRsp(devInfo, bType) != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "send response failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}