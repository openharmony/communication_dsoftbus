/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_FLOW_CONTROL_H
#define SOFTBUS_FLOW_CONTROL_H

#include "stdint.h"

#include "common_list.h"
#include "softbus_adapter_thread.h"
#include "softbus_error_code.h"

#ifdef __cplusplus
extern "C" {
#endif

// invalid parameters range
#define MIN_WINDOW_IN_MILLIS 100               // 100ms
#define MAX_WINDOW_IN_MILLIS 2000              // 2s
#define MIN_QUOTA_IN_BYTES   (10 * 1024)       // 10kB
#define MAX_QUOTA_IN_BYTES   (2 * 1024 * 1024) // 2MB

struct ConnSlideWindowController {
    int32_t (*apply)(struct ConnSlideWindowController *self, int32_t expect);
    int32_t (*enable)(struct ConnSlideWindowController *self, int32_t windowInMillis, int32_t quotaInBytes);
    int32_t (*disable)(struct ConnSlideWindowController *self);

    // lock protect fields of this section, as they are access by send thread and modification by config thread
    SoftBusMutex lock;
    bool active;
    int32_t windowInMillis;
    int32_t quotaInBytes;
    ListNode histories;
};

int32_t ConnSlideWindowControllerConstructor(struct ConnSlideWindowController *self);
void ConnSlideWindowControllerDestructor(struct ConnSlideWindowController *self);
struct ConnSlideWindowController *ConnSlideWindowControllerNew(void);
void ConnSlideWindowControllerDelete(struct ConnSlideWindowController *self);

#ifdef __cplusplus
}
#endif

#endif // SOFTBUS_FLOW_CONTROL_H
