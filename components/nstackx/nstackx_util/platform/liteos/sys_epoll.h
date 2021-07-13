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

#ifndef SYS_EPOLL_H
#define SYS_EPOLL_H

#include "nstackx_common_header.h"

typedef struct EpollDescStr {
    int32_t recvFd;
    int32_t sendFd;
} *EpollDesc;

struct EpollEvent {
    uint32_t op;
    uint32_t events;
    void *ptr;
#ifdef NSTACKX_DEBUG
    uint32_t evtSeq;
#endif
};

typedef int32_t TaskDesc;

#ifndef EPOLL_CTL_ADD
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3
#endif

#define EPOLL_CTL_RUN ((EPOLL_CTL_MOD) + 1)

#define INVALID_EPOLL_DESC (NULL)
#define INVALID_TASK_DESC (-1)

#define REPRESENT_EPOLL_DESC(epollfd) ((epollfd)->recvFd)

int32_t CreateEpollFdPair(struct EpollDescStr *epollfd);
int32_t RunEpollTask(void *task, uint32_t events);
void CloseEpollDescInner(EpollDesc epollfd);
void CloseDescClearEpollPtr(int32_t desc);

static inline bool IsEpollDescValid(EpollDesc epollfd)
{
    return (epollfd != INVALID_EPOLL_DESC);
}

static inline bool IsEpollDescEqual(EpollDesc epollfd1, EpollDesc epollfd2)
{
    return (epollfd1 == epollfd2);
}

static inline void CloseEpollDesc(EpollDesc epollfd)
{
    CloseEpollDescInner(epollfd);
}

void EpollEventPtrInit(void);

#endif // SYS_EPOLL_H
