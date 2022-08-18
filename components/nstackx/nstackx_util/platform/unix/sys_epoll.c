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

#include "nstackx_epoll.h"
#include "nstackx_log.h"
#include "nstackx_error.h"

#define TAG "nStackXEpoll"
#define MAX_EPOLL_SIZE 128

int32_t RefreshEpollTask(EpollTask *task, uint32_t events)
{
    struct epoll_event event;
    if (task == NULL) {
        return NSTACKX_EINVAL;
    }
    event.data.ptr = task;
    event.events = events;

    if (epoll_ctl(task->epollfd, EPOLL_CTL_MOD, task->taskfd, &event) < 0) {
        LOGE(TAG, "Refresh task failed: %d", errno);
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

int32_t RegisterEpollTask(EpollTask *task, uint32_t events)
{
    struct epoll_event event;
    if (task == NULL) {
        return NSTACKX_EINVAL;
    }
    event.data.ptr = task;
    event.events = events;
    if (epoll_ctl(task->epollfd, EPOLL_CTL_ADD, task->taskfd, &event) < 0) {
        LOGE(TAG, "Register task failed: %d", errno);
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

int32_t DeRegisterEpollTask(EpollTask *task)
{
    if (task == NULL) {
        return NSTACKX_EINVAL;
    }
    if (epoll_ctl(task->epollfd, EPOLL_CTL_DEL, task->taskfd, NULL) < 0) {
        LOGE(TAG, "De-register task failed: %d", errno);
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

EpollDesc CreateEpollDesc(void)
{
    return epoll_create(1);
}

int32_t EpollLoop(EpollDesc epollfd, int32_t timeout)
{
    int32_t i, nfds;
    EpollTask *task = NULL;
    struct epoll_event events[MAX_EPOLL_SIZE];

    nfds = epoll_wait(epollfd, events, MAX_EPOLL_SIZE, timeout);
    if (nfds < 0) {
        if (errno == EINTR) {
            LOGD(TAG, "epoll_wait EINTR");
            return NSTACKX_EINTR;
        }
        LOGE(TAG, "epoll_wait returned n=%d, error: %d", nfds, errno);
        return NSTACKX_EFAILED;
    }

    for (i = 0; i < nfds; i++) {
        task = events[i].data.ptr;
        if (task == NULL) {
            continue;
        }

        if (events[i].events & EPOLLIN) {
            if (task->readHandle != NULL) {
                task->readHandle(task);
            }
        }

        if (events[i].events & EPOLLOUT) {
            if (task->writeHandle != NULL) {
                task->writeHandle(task);
            }
        }
    }

    return ((nfds > 0) ? nfds : NSTACKX_ETIMEOUT);
}
