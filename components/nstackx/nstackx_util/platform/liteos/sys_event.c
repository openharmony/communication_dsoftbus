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
#include "nstackx_event.h"
#include "nstackx_log.h"
#include "nstackx_error.h"
#include "nstackx_util.h"
#include "nstackx_epoll.h"
#include "securec.h"

#define TAG "nStackXEvent"

typedef struct {
    EventHandle handle;
    void *arg;
} EventInfo;

EventNode *SearchEventNode(const List *eventNodeChain, EpollDesc epollfd);

void CloseNodePipe(const EventNode *node)
{
    CloseDesc(node->pipeFd[PIPE_OUT]);
    CloseDesc(node->pipeFd[PIPE_IN]);
}

static void EventProcessHandle(void *arg)
{
    int32_t ret;
    EventInfo event = {0};
    EpollTask *task = arg;
    EventNode *node = container_of(task, EventNode, task);

#ifdef NSTACKX_WITH_LITEOS_M
    ret = (int32_t)recvfrom(node->pipeFd[PIPE_OUT], &event, sizeof(event), 0, NULL, NULL);
#else
    ret = (int32_t)read(node->pipeFd[PIPE_OUT], &event, sizeof(event));
#endif
    if (ret != (int32_t)sizeof(event)) {
        LOGE(TAG, "failed to read from pipe: %d", GetErrno());
        return;
    }

    if (event.handle != NULL) {
        event.handle(event.arg);
    }
}

int32_t PostEvent(const List *eventNodeChain, EpollDesc epollfd, EventHandle handle, void *arg)
{
    int32_t ret;
    EventNode *node = NULL;
    EventInfo event = {
        .handle = handle,
        .arg = arg,
    };

    if (eventNodeChain == NULL || handle == NULL) {
        return NSTACKX_EINVAL;
    }

    node = SearchEventNode(eventNodeChain, epollfd);
    if (node == NULL) {
        LOGE(TAG, "Cannot find event node for %d", epollfd->recvFd);
        return NSTACKX_EFAILED;
    }
#ifdef NSTACKX_WITH_LITEOS_M
    ret = (int32_t)sendto(node->pipeFd[PIPE_IN], &event, sizeof(event), 0, NULL, 0);
#else
    ret = (int32_t)write(node->pipeFd[PIPE_IN], &event, sizeof(event));
#endif
    if (ret != (int32_t)sizeof(event)) {
        LOGE(TAG, "failed to write to pipe: %d", errno);
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

void ClearEvent(const List *eventNodeChain, EpollDesc epollfd)
{
    EventNode *node = NULL;
    EventInfo event = {0};
    int32_t eventLen = (int32_t)sizeof(event);
    if (eventNodeChain == NULL) {
        LOGE(TAG, "eventNodeChain is null");
        return;
    }

    node = SearchEventNode(eventNodeChain, epollfd);
    if (node == NULL) {
        return;
    }

    int32_t ret = eventLen;
    while (ret == eventLen) {
#ifdef NSTACKX_WITH_LITEOS_M
        ret = (int32_t)recvfrom(node->pipeFd[PIPE_OUT], &event, sizeof(event), 0, NULL, NULL);
#else
        ret = (int32_t)read(node->pipeFd[PIPE_OUT], &event, sizeof(event));
#endif
        if (ret != eventLen) {
            break;
        }

        if (event.handle != NULL) {
            event.handle(event.arg);
        }
    }
}

static int32_t CreateNonBlockPipe(EventNode *node)
{
    struct EpollDescStr fds;

    if (CreateEpollFdPair(&fds) != NSTACKX_EOK) {
        LOGE(TAG, "CreateEpollFdPair failed");
        return NSTACKX_EFAILED;
    }

    node->pipeFd[PIPE_OUT] = fds.recvFd;
    node->pipeFd[PIPE_IN] = fds.sendFd;

    return NSTACKX_EOK;
}

int32_t EventModuleInit(List *eventNodeChain, EpollDesc epollfd)
{
    List *pos = NULL;
    EventNode *node = NULL;
    if (eventNodeChain == NULL) {
        LOGE(TAG, "eventNodeChain is null");
        return NSTACKX_EINVAL;
    }
    LIST_FOR_EACH(pos, eventNodeChain) {
        node = (EventNode *)pos;
        if (IsEpollDescEqual(node->epollfd, epollfd)) {
            return NSTACKX_EOK;
        }
    }

    node = calloc(1, sizeof(EventNode));
    if (node == NULL) {
        LOGE(TAG, "calloc failed");
        return NSTACKX_ENOMEM;
    }

    if (CreateNonBlockPipe(node) != NSTACKX_EOK) {
        LOGE(TAG, "create pipe failed");
        goto L_ERR_FAILED;
    }

    node->task.taskfd = node->pipeFd[PIPE_OUT];
    node->task.epollfd = epollfd;
    node->task.readHandle = EventProcessHandle;

    node->epollfd = epollfd;
    if (RegisterEpollTask(&node->task, EPOLLIN) != NSTACKX_EOK) {
        LOGE(TAG, "RegisterEpollTask failed");
        CloseNodePipe(node);
        goto L_ERR_FAILED;
    }

    ListInsertTail(eventNodeChain, &(node->list));
    return NSTACKX_EOK;
L_ERR_FAILED:
    free(node);
    return NSTACKX_EFAILED;
}

void DeleteEventNode(EventNode *node)
{
    ListRemoveNode(&node->list);
    if (DeRegisterEpollTask(&node->task) != NSTACKX_EOK) {
        LOGE(TAG, "DeRegisterEpollTask failed");
    }
    CloseNodePipe(node);
    free(node);
}
