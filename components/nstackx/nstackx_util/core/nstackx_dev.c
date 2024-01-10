/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "nstackx_dev.h"
#include "nstackx_error.h"
#include "nstackx_log.h"
#include "securec.h"

#define TAG "nStackXDev"

int32_t GetConnectionTypeByDev(const uint32_t sourceIp, uint16_t *connectType);

static int32_t GetConnectionTypeByIP(const uint32_t sourceIp, const uint32_t destinationIp, uint16_t *connectType)
{
    if (sourceIp == htonl(SOFTAP_ADDR_KEY) || destinationIp == htonl(SOFTAP_ADDR_KEY) ||
        sourceIp == htonl(P2P_ADDR_KEY) || destinationIp == htonl(P2P_ADDR_KEY)) {
        *connectType = CONNECT_TYPE_P2P;
        LOGI(TAG, "connType is P2P(%u)", *connectType);
        return NSTACKX_EOK;
    }
    return NSTACKX_EFAILED;
}

int32_t GetConnectionType(const uint32_t sourceIp, const uint32_t destinationIp, uint16_t *connectType)
{
    if (GetConnectionTypeByIP(sourceIp, destinationIp, connectType) == NSTACKX_EOK) {
        return NSTACKX_EOK;
    }
    return GetConnectionTypeByDev(sourceIp, connectType);
}

uint8_t DFileGetDeviceBits(void)
{
    if (TYPE_BITS_NUM(char *) == DEVICE_32_BITS) {
        return DEVICE_32_BITS;
    }

    return DEVICE_64_BITS;
}