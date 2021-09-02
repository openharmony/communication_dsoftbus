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
#include "securec.h"

#define TAG "nStackXEvent"

void DeleteEventNode(EventNode *node);

EventNode *SearchEventNode(const List *eventNodeChain, EpollDesc epollfd)
{
    List *pos = NULL;
    List *tmp = NULL;
    EventNode *node = NULL;

    LIST_FOR_EACH_SAFE(pos, tmp, eventNodeChain) {
        node = (EventNode *)pos;
        if (IsEpollDescEqual(node->epollfd, epollfd)) {
            break;
        }
        node = NULL;
    }
    return node;
}

void EventModuleClean(const List *eventNodeChain, EpollDesc epollfd)
{
    List *pos = NULL;
    EventNode *node = NULL;
    if (eventNodeChain == NULL) {
        LOGE(TAG, "eventNodeChain is null");
        return;
    }
    LIST_FOR_EACH(pos, eventNodeChain) {
        node = (EventNode *)pos;
        if (IsEpollDescEqual(node->epollfd, epollfd)) {
            break;
        }
        node = NULL;
    }

    if (node == NULL) {
        return;
    }

    DeleteEventNode(node);
}

void EventNodeChainClean(List *eventNodeChain)
{
    List *tmp = NULL;
    List *pos = NULL;
    EventNode *node = NULL;

    if (eventNodeChain == NULL) {
        LOGE(TAG, "eventNodeChain is null");
        return;
    }

    LIST_FOR_EACH_SAFE(pos, tmp, eventNodeChain) {
        node = (EventNode *)pos;
        if (node != NULL) {
            DeleteEventNode(node);
        }
    }
}

EpollTask *GetEpollTask(List *eventNodeChain, EpollDesc epollfd)
{
    if (eventNodeChain == NULL) {
        LOGE(TAG, "eventNodeChain is null");
        return NULL;
    }

    EventNode *node = SearchEventNode(eventNodeChain, epollfd);
    if (node == NULL) {
        LOGE(TAG, "Cannot find event node for %d", REPRESENT_EPOLL_DESC(epollfd));
        return NULL;
    }
    return &node->task;
}
