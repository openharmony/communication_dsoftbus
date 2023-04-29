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

#ifndef SOFTBUS_ADAPTER_HITRACECHAIN_H
#define SOFTBUS_ADAPTER_HITRACECHAIN_H
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include "hitrace/tracechain.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

bool SoftbusHitraceChainIsValid(const HiTraceIdStruct *pId);
HiTraceIdStruct SoftbusHitraceChainBegin(const char *name, int flags);
void SoftbusHitraceChainEnd(const HiTraceIdStruct *pId);
HiTraceIdStruct SoftbusHitraceChainGetId(void);
void SoftbusHitraceChainSetChainId(HiTraceIdStruct *pId, uint64_t chainId);
void SoftbusHitraceChainClearId(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* SOFTBUS_ADAPTER_HITRACECHAIN_H */