/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_WATCH_EVENT_INTERFACE_H
#define SOFTBUS_WATCH_EVENT_INTERFACE_H

#include <stdbool.h>
#include <stdint.h>

#include "common_list.h"
#include "softbus_adapter_mem.h"
#include "softbus_socket.h"

#ifdef __cplusplus
extern "C" {
#endif

struct FdNode {
    ListNode node;
    int32_t fd;
    uint32_t triggerSet;
};

typedef int32_t (*GetAllFdEventCallback)(ListNode *list);

typedef struct {
    GetAllFdEventCallback callback;
    int32_t watcherId;
} EventWatcher;

EventWatcher* RegisterEventWatcher(const GetAllFdEventCallback callback);
int32_t AddEvent(EventWatcher *watcher, int32_t fd, uint32_t event);
int32_t ModifyEvent(EventWatcher *watcher, int32_t fd, uint32_t event);
int32_t RemoveEvent(EventWatcher *watcher, int32_t fd);
int32_t WatchEvent(EventWatcher *watcher, int32_t timeoutMS, ListNode *out);
void CloseEventWatcher(EventWatcher *watcher);

int32_t WaitEvent(int32_t fd, enum SocketEvent events, int32_t timeout);

inline static void ReleaseFdNode(ListNode *fdNode)
{
    struct FdNode *it = NULL;
    struct FdNode *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, fdNode, struct FdNode, node) {
        ListDelete(&it->node);
        SoftBusFree(it);
    }
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* SOFTBUS_WATCH_EVENT_INTERFACE_H  */