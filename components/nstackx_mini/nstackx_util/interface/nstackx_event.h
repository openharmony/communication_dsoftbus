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

#ifndef NSTACKX_EVENT_H
#define NSTACKX_EVENT_H

#include "sys_event.h"
#include "nstackx_epoll.h"
#include "nstackx_list.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*EventHandle)(void *arg);

typedef struct EventNode {
    List list;
    EpollDesc epollfd;
    PipeDesc pipeFd[PIPE_FD_NUM];
    EpollTask task;
} EventNode;

NSTACKX_EXPORT int32_t PostEvent(const List *eventNodeChain, EpollDesc epollfd, EventHandle handle, void *arg);
NSTACKX_EXPORT void ClearEvent(const List *eventNodeChain, EpollDesc epollfd);
NSTACKX_EXPORT int32_t EventModuleInit(List *eventNodeChain, EpollDesc epollfd);
NSTACKX_EXPORT void EventModuleClean(const List *eventNodeChain, EpollDesc epollfd);
NSTACKX_EXPORT void EventNodeChainClean(List *eventNodeChain);
NSTACKX_EXPORT EpollTask *GetEpollTask(List *eventNodeChain, EpollDesc epollfd);

#ifdef __cplusplus
}
#endif

#endif // NSTACKX_EVENT_H
