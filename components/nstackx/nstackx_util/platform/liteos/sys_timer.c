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
#include <signal.h>
#include <time.h>

#define TAG "nStackXTimer"

#define TIMERID_TO_TASKFD(timerid) ((int32_t)(uintptr_t)(timerid))
#define TASKFD_TO_TIMERID(taskfd) ((timer_t)(uintptr_t)(taskfd))

void TimerDelete(Timer *timer)
{
    if (timer == NULL) {
        return;
    }
    if (TASKFD_TO_TIMERID(timer->task.taskfd) != NULL) {
        if (timer_delete(TASKFD_TO_TIMERID(timer->task.taskfd)) < 0) {
            LOGE(TAG, "close timer task failed");
        }
        timer->task.taskfd = TIMERID_TO_TASKFD(NULL);
    }
    free(timer);
}

static void TimerReadHandle(void *arg)
{
    EpollTask *task = arg;
    Timer *timer = NULL;
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

    if (timer_gettime(TASKFD_TO_TIMERID(timer->task.taskfd), &currValue) < 0) {
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

    if (timer_settime(TASKFD_TO_TIMERID(timer->task.taskfd), 0, &ts, NULL) < 0) {
        LOGE(TAG, "timerfd_settime failed! %d", errno);
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

static void TimerTimeoutHandle(union sigval v)
{
    EpollTask *task = (EpollTask *)(v.sival_ptr);

    if (RunEpollTask((void *)task, EPOLLIN) != NSTACKX_EOK) {
        LOGE(TAG, "TimerTimeoutHandle failed!");
    }
}

Timer *TimerStart(EpollDesc epollfd, uint32_t ms, uint8_t repeated, TimeoutHandle handle, void *data)
{
    struct sigevent evp;
    timer_t timerid;
    Timer *timer = calloc(1, sizeof(Timer));
    if (timer == NULL) {
        LOGE(TAG, "timer malloc failed");
        return NULL;
    }

    timer->timeoutHandle = handle;
    timer->data = data;
    timer->disabled = NSTACKX_FALSE;

    (void)memset_s(&evp, sizeof(struct sigevent), 0, sizeof(struct sigevent));
    evp.sigev_value.sival_ptr = (void *)&timer->task;
    evp.sigev_notify = SIGEV_THREAD;
    evp.sigev_notify_function = TimerTimeoutHandle;

    if (timer_create(CLOCK_REALTIME, &evp, &timerid) < 0) {
        LOGE(TAG, "timer create failed! errno %d", errno);
        TimerDelete(timer);
        return NULL;
    }
    timer->task.taskfd = TIMERID_TO_TASKFD(timerid);
    timer->task.epollfd = epollfd;
    timer->task.readHandle = TimerReadHandle;
    timer->task.writeHandle = NULL;
    timer->task.errorHandle = NULL;
    timer->task.ptr = timer;

    if (TimerSetTimeout(timer, ms, repeated) != NSTACKX_EOK) {
        TimerDelete(timer);
        return NULL;
    }

    return timer;
}
