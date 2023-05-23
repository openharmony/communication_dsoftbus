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

#include <sys/time.h>
#include "hitrace/tracechain.h"

typedef struct SoftbusHiTraceChainIdStruct {
    union {
        struct {
            uint64_t reserved : 4;
            uint64_t usecond : 20;
            uint64_t second : 16;
            uint64_t cpuId : 4;
            uint64_t deviceId : 20;
        };
        struct {
            uint64_t padding : 4;
            uint64_t chainId : 60;
        };
    };
} SoftbusHiTraceChainIdStruct;

static uint64_t HiTraceCreateChainId(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    SoftbusHiTraceChainIdStruct chainId = {
        .padding = 0,
        .chainId = 0
    };
    chainId.deviceId = (uint64_t)(tv.tv_sec);
    chainId.cpuId = (uint64_t)(tv.tv_usec);
    chainId.second = (uint64_t)(tv.tv_sec);
    chainId.usecond = (uint64_t)(tv.tv_usec);
    return chainId.chainId;
}

void SoftbusHitraceStart(int32_t flags, uint64_t chainId)
{
    HiTraceIdStruct pId = HiTraceChainGetId();
    pId.valid = flags;
    pId.chainId = chainId > 0 ? chainId : HiTraceCreateChainId();
    HiTraceChainSetId(&pId);
}

void SoftbusHitraceStop(void)
{
    HiTraceChainClearId();
}
