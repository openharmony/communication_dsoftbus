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
#ifndef WIFI_DIRECT_TIMER_H
#define WIFI_DIRECT_TIMER_H

#include "common_list.h"
#include "softbus_adapter_thread.h"
#include "wifi_direct_work_queue.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*TimeoutHandler)(void *data);
enum WifiDirectTimerFlag {
    TIMER_FLAG_ONE_SHOOT = 0,
    TIMER_FLAG_REPEATED = 1,
};

struct WifiDirectTimerList {
    int32_t (*startTimer)(TimeoutHandler handler, int64_t timeoutMs, enum WifiDirectTimerFlag flag, void *data);
    void* (*stopTimer)(int32_t timeId);

    int32_t timerId;
    ListNode timers;
    SoftBusMutex mutex;
};

struct WifiDirectTimerList* GetWifiDirectTimerList(void);
int32_t WifiDirectTimerListInit(void);

#ifdef __cplusplus
}
#endif
#endif