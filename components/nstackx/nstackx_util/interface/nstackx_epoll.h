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

#ifndef NSTACKX_EPOLL_H
#define NSTACKX_EPOLL_H

#include "sys_epoll.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef EPOLLIN
#define EPOLLIN 0x00000001U
#endif

#ifndef EPOLLOUT
#define EPOLLOUT 0x00000004U
#endif

#ifndef EPOLLERR
#define EPOLLERR 0x00000008U
#endif

#ifndef EPOLLHUP
#define EPOLLHUP 0x00000010U
#endif

typedef void (*TaskHandle)(void *arg);

typedef struct {
    EpollDesc epollfd;
    TaskDesc taskfd;
    TaskHandle readHandle;
    TaskHandle writeHandle;
    TaskHandle errorHandle;
    void *ptr;
    uint64_t count;
} EpollTask;

NSTACKX_EXPORT int32_t RegisterEpollTask(EpollTask *task, uint32_t events);
NSTACKX_EXPORT int32_t DeRegisterEpollTask(EpollTask *task);
NSTACKX_EXPORT int32_t RefreshEpollTask(EpollTask *task, uint32_t events);
NSTACKX_EXPORT EpollDesc CreateEpollDesc(void);
NSTACKX_EXPORT int32_t EpollLoop(EpollDesc epollfd, int32_t timeout);
static inline bool IsEpollDescValid(EpollDesc epollfd);
static inline bool IsEpollDescEqual(EpollDesc epollfd1, EpollDesc epollfd2);
static inline void CloseEpollDesc(EpollDesc epollfd);

#ifdef __cplusplus
}
#endif

#endif // NSTACKX_EPOLL_H
