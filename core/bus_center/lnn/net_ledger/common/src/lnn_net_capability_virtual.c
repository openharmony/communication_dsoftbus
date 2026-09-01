/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "lnn_log.h"
#include "softbus_error_code.h"

bool LnnHasCapability(uint32_t capability, NetCapability type)
{
    (void)capability;
    (void)type;
    return false;
}

uint32_t LnnGetNetCapabilty(void)
{
    return 0;
}

int32_t LnnSetNetCapability(uint32_t *capability, NetCapability type)
{
    (void)capability;
    (void)type;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnClearNetCapability(uint32_t *capability, NetCapability type)
{
    (void)capability;
    (void)type;
    return SOFTBUS_NOT_IMPLEMENT;
}

bool LnnHasStaticNetCap(uint32_t capability, StaticNetCapability type)
{
    (void)capability;
    (void)type;
    return false;
}

int32_t LnnSetStaticNetCap(uint32_t *capability, StaticNetCapability type)
{
    (void)capability;
    (void)type;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnClearStaticNetCap(uint32_t *capability, StaticNetCapability type)
{
    (void)capability;
    (void)type;
    return SOFTBUS_NOT_IMPLEMENT;
}

uint32_t LnnGetDefaultStaticNetCap(void)
{
    return 0;
}
