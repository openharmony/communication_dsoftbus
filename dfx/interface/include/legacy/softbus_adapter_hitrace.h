/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_ADAPTER_HITRACE_H
#define SOFTBUS_ADAPTER_HITRACE_H
#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef enum SoftbusHiTraceIdValid {
    SOFTBUS_HITRACE_ID_INVALID = 0,
    SOFTBUS_HITRACE_ID_VALID = 1,
} SoftbusHiTraceIdValid;

void SoftbusHitraceStart(uint32_t flags, uint64_t chainId);
void SoftbusHitraceStop(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* SOFTBUS_ADAPTER_HITRACE_H */