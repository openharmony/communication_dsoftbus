/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#ifndef SOFTBUS_DDOS_H
#define SOFTBUS_DDOS_H
#include "softbus_def.h"
#include "softbus_server_ipc_interface_code.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TIME_THRESHOLD_SIZE 10
#define INTERFACEID_COUNT 50

typedef struct {
    enum SoftBusFuncId interfaceId;
    char pkgName[PKG_NAME_SIZE_MAX];
    time_t timestamp;
    ListNode node;
} CallRecord;

int32_t IsOverThreshold(const char* pkgName, enum SoftBusFuncId interfaceId);
int32_t InitDdos(void);
void DeinitDdos(void);
#ifdef __cplusplus
}
#endif
#endif // SOFTBUS_DDOS_H

