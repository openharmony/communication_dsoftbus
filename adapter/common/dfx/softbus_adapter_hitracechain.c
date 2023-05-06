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

#include "softbus_adapter_hitracechain.h"

#include "softbus_adapter_log.h"
#include "softbus_def.h"

bool SoftbusHitraceChainIsValid(const HiTraceIdStruct *pId)
{
    return (pId) && (pId->valid == HITRACE_ID_VALID);
}

HiTraceIdStruct SoftbusHitraceChainBegin(const char *name, int flags)
{
    return HiTraceChainBegin(name, flags);
}

void SoftbusHitraceChainEnd(const HiTraceIdStruct *pId)
{
    HiTraceChainEnd(pId);
}

HiTraceIdStruct SoftbusHitraceChainGetId(void)
{
    return HiTraceChainGetId();
}

void SoftbusHitraceChainSetChainId(HiTraceIdStruct *pId, uint64_t chainId)
{
    if (!pId || chainId == 0) {
        return;
    }
    pId->valid = HITRACE_ID_VALID;
    pId->chainId = chainId;
    HiTraceChainSetId(pId);
}

void SoftbusHitraceChainClearId(void)
{
    HiTraceChainClearId();
}
