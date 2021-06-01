/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef NSTACKX_TIMER_H
#define NSTACKX_TIMER_H

#include "nstackx_epoll.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NSTACKX_MILLI_TICKS             1000
#define NSTACKX_MICRO_TICKS             1000000
#define NSTACKX_NANO_TICKS              1000000000
#define NSTACKX_MICRO_SEC_PER_MILLI_SEC (NSTACKX_MICRO_TICKS / NSTACKX_MILLI_TICKS)
#define NSTACKX_NANO_SEC_PER_MILLI_SEC  (NSTACKX_NANO_TICKS / NSTACKX_MILLI_TICKS)
#define NSTACKX_NANO_SEC_PER_MICRO_SEC  (NSTACKX_NANO_TICKS / NSTACKX_MICRO_TICKS)

typedef void (*TimeoutHandle)(void *data);

typedef struct  {
    EpollTask task;
    TimeoutHandle timeoutHandle;
    void *data;
    uint8_t disabled;
} Timer;

NSTACKX_EXPORT uint32_t GetTimeDiffMs(const struct timespec *etv, const struct timespec *stv);
NSTACKX_EXPORT int32_t TimerSetTimeout(Timer *timer, uint32_t timeoutMs, uint8_t repeated);
NSTACKX_EXPORT int32_t TimerGetRemainTime(Timer *timer, uint32_t *remainTimeMsPtr);
NSTACKX_EXPORT Timer *TimerStart(EpollDesc epollfd, uint32_t ms, uint8_t repeated, TimeoutHandle handle, void *data);
NSTACKX_EXPORT void TimerDelete(Timer *timer);
NSTACKX_EXPORT uint32_t GetTimeDiffUs(const struct timespec *etv, const struct timespec *stv);

#ifdef __cplusplus
}
#endif

#endif // NSTACKX_TIMER_H
