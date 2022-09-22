/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef LNN_FAST_OFFLINE_H
#define LNN_FAST_OFFLINE_H

#include <stdint.h>
#include "lnn_node_info.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char udid[UDID_BUF_LEN];
    int64_t authSeq[DISCOVERY_TYPE_COUNT];
} NotTrustedDelayInfo;

int32_t LnnInitFastOffline(void);
void LnnDeinitFastOffline(void);
int32_t LnnSendNotTrustedInfo(NotTrustedDelayInfo *info, uint32_t num);
int32_t LnnBleFastOfflineOnceBegin(void);
void LnnIpAddrChangeEventHandler(void);

#ifdef __cplusplus
}
#endif

#endif // LNN_FAST_OFFLINE_H