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

#include "lnn_net_capability.h"

#include <stdint.h>

#include "softbus_errcode.h"
#include "softbus_log.h"

int32_t LnnSetNetCapability(uint32_t *capability, NetCapability type)
{
    if (capability == NULL || type >= BIT_COUNT) {
        LOG_ERR("in para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    *capability = (*capability) | (1 << (uint32_t)type);
    return SOFTBUS_OK;
}

uint32_t LnnGetNetCapabilty(void)
{
    uint32_t capability = 0;
    capability = capability | (1 << BIT_BR);
    return capability;
}