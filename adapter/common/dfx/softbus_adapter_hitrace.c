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

#include "softbus_adapter_hitrace.h"

#include "hitrace/tracechain.h"
#include "softbus_adapter_crypto.h"

void SoftbusHitraceStart(int32_t flags, uint64_t chainId)
{
    HiTraceIdStruct pId = HiTraceChainGetId();
    pId.valid = (uint32_t)flags;
    pId.chainId = chainId > 0 ? chainId : (uint64_t)SoftBusCryptoRand();
    HiTraceChainSetId(&pId);
}

void SoftbusHitraceStop(void)
{
    HiTraceChainClearId();
}
