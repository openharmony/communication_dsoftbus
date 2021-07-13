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

#include "nstackx_timer.h"
#include "nstackx_log.h"
#include "nstackx_error.h"
#include "securec.h"

#define TAG "nStackXTimer"

void TimerDelete(Timer *timer)
{
    if (timer == NULL) {
        return;
    }
    if (timer->task.taskfd != INVALID_TASK_DESC) {
        if (DeRegisterEpollTask(&(timer->task)) != NSTACKX_EOK) {
            LOGE(TAG, "DeRegisterEpollTask failed");
        }
        if (close(timer->task.taskfd) < 0) {
            LOGE(TAG, "close timer task failed");
        }
        timer->task.taskfd = INVALID_TASK_DESC;
    }
    free(timer);
}

static void TimerReadHandle(void *arg)
{
    EpollTask *task = arg;
    Timer *timer = NULL;
    uint64_t exp;
    if (task == NULL) {
        LOGE(TAG, "Timer task is NULL");
        return;
    }

    timer = task->ptr;
    if (timer == NULL) {
        LOGE(TAG, "Timer is NULL");
        return;
    }

    if (timer->disabled) {
        LOGD(TAG, "User disable timer before timer callback.");
        return;
    }

    if (read(task->taskfd, &exp, sizeof(exp)) != (ssize_t)(sizeof(uint64_t))) {
        LOGE(TAG, "read invalid exp");
        return;
    }

    if (timer->timeoutHandle != NULL) {
        timer->timeoutHandle(timer->data);
    }
    return;
}

int32_t TimerGetRemainTime(Timer *timer, uint32_t *remainTimeMsPtr)
{
    struct itimerspec currValue = {{0}, {0}};

    if (timer == NULL || remainTimeMsPtr == NULL) {
        LOGE(TAG, "Invalid timer parameter");
        return NSTACKX_EINVAL;
    }

    if (timerfd_gettime(timer->task.taskfd, &currValue) < 0) {
        LOGE(TAG, "timerfd_gettime() failed! %d", errno);
        return NSTACKX_EFAILED;
    }

    *remainTimeMsPtr = (uint32_t)(currValue.it_value.tv_sec * NSTACKX_MILLI_TICKS +
        currValue.it_value.tv_nsec / NSTACKX_MILLI_TICKS / NSTACKX_MILLI_TICKS);

    return NSTACKX_EOK;
}

int32_t TimerSetTimeout(Timer *timer, uint32_t timeoutMs, uint8_t repeated)
{
    struct itimerspec ts;

    if (timer == NULL) {
        LOGE(TAG, "Invalid timer parameter");
        return NSTACKX_EINVAL;
    }

    (void)memset_s(&ts, sizeof(ts), 0, sizeof(ts));
    if (timeoutMs) {
        ts.it_value.tv_sec = timeoutMs / NSTACKX_MILLI_TICKS;
        ts.it_value.tv_nsec = (timeoutMs % NSTACKX_MILLI_TICKS) * NSTACKX_NANO_SEC_PER_MILLI_SEC;
        if (repeated) {
            ts.it_interval.tv_sec = ts.it_value.tv_sec;
            ts.it_interval.tv_nsec = ts.it_value.tv_nsec;
        }
        timer->disabled = NSTACKX_FALSE;
    } else {
        timer->disabled = NSTACKX_TRUE;
    }

    if (timerfd_settime(timer->task.taskfd, 0, &ts, NULL) < 0) {
        LOGE(TAG, "timerfd_settime failed! %d", errno);
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

Timer *TimerStart(EpollDesc epollfd, uint32_t ms, uint8_t repeated, TimeoutHandle handle, void *data)
{
    Timer *timer = calloc(1, sizeof(Timer));
    if (timer == NULL) {
        LOGE(TAG, "timer malloc failed");
        return NULL;
    }

    timer->timeoutHandle = handle;
    timer->data = data;
    timer->disabled = NSTACKX_FALSE;

    timer->task.taskfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
    if (timer->task.taskfd < 0) {
        LOGE(TAG, "timer create failed! errno %d", errno);
        TimerDelete(timer);
        return NULL;
    }
    timer->task.epollfd = epollfd;
    timer->task.readHandle = TimerReadHandle;
    timer->task.writeHandle = NULL;
    timer->task.errorHandle = NULL;
    timer->task.ptr = timer;

    if (TimerSetTimeout(timer, ms, repeated) != NSTACKX_EOK) {
        TimerDelete(timer);
        return NULL;
    }

    if (RegisterEpollTask(&timer->task, EPOLLIN) != NSTACKX_EOK) {
        LOGE(TAG, "RegisterEpollTask failed");
        TimerDelete(timer);
        return NULL;
    }
    return timer;
}
