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
#ifndef WIFI_DIRECT_WORK_QUEUE_H
#define WIFI_DIRECT_WORK_QUEUE_H

#include <stdint.h>
#include "message_handler.h"

#ifdef __cplusplus
extern "C" {
#endif

struct WifiDirectWork;
typedef void (*WorkFunction)(void *data);

struct WifiDirectWorkQueue {
    void (*scheduleWork)(struct WifiDirectWork *work);
    void (*scheduleDelayWork)(struct WifiDirectWork *work, int64_t timeMs);
    void (*removeWork)(struct WifiDirectWork *work);

    SoftBusHandler handler;
    bool isInited;
};

struct WifiDirectWorkQueue *GetWifiDirectWorkQueue(void);
struct WifiDirectWork* ObtainWifiDirectWork(WorkFunction function, void *data);
int32_t CallMethodAsync(WorkFunction function, void *data, int64_t delayTimeMs);

int32_t WifiDirectWorkQueueInit(void);

#ifdef __cplusplus
}
#endif
#endif