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

#include "softbus_watch_event_interface.h"

#include <sys/select.h>

#include <securec.h>

#include "common_list.h"
#include "conn_log.h"
#include "softbus_adapter_errcode.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_base_listener.h"
#include "softbus_socket.h"

#define MAX_LISTEN_EVENTS 1024
#define SELECT_INTERVAL_US (100 * 1000)

typedef struct {
    SoftBusFdSet readSet;
    SoftBusFdSet writeSet;
    SoftBusFdSet exceptSet;
} SoftBusFdSets;

EventWatcher* RegisterEventWatcher(GetAllFdEventCallback callback)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(callback != NULL, NULL, CONN_COMMON, "callback is NULL");
    EventWatcher *watcher = (EventWatcher *)SoftBusCalloc(sizeof(EventWatcher));
    CONN_CHECK_AND_RETURN_RET_LOGE(watcher != NULL, NULL, CONN_COMMON, "malloc eventWatcher failed");
    watcher->callback = callback;
    CONN_LOGI(CONN_COMMON, "register event watcher success");
    return watcher;
}

int32_t AddEvent(EventWatcher *watcher, int32_t fd, uint32_t event)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(watcher != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "event watcher is NULL");
    CONN_CHECK_AND_RETURN_RET_LOGE(fd <= MAX_LISTEN_EVENTS, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "fd is too big, maxFd=%{public}d, fd=%{public}d", MAX_LISTEN_EVENTS, fd);
    return SOFTBUS_OK;
}

int32_t ModifyEvent(EventWatcher *watcher, int32_t fd, uint32_t event)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(watcher != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "event watcher is NULL");
    CONN_CHECK_AND_RETURN_RET_LOGE(fd <= MAX_LISTEN_EVENTS, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "fd is too big, maxFd=%{public}d, fd=%{public}d", MAX_LISTEN_EVENTS, fd);
    return SOFTBUS_OK;
}

int32_t RemoveEvent(EventWatcher *watcher, int32_t fd)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(watcher != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "event watcher is NULL");
    CONN_CHECK_AND_RETURN_RET_LOGE(fd <= MAX_LISTEN_EVENTS, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "fd is too big, maxFd=%{public}d, fd=%{public}d", MAX_LISTEN_EVENTS, fd);
    return SOFTBUS_OK;
}

static int32_t PrepareFdSets(ListNode *list, SoftBusFdSets *fdSets)
{
    int32_t maxFd = 0;
    struct FdNode *it = NULL;
    LIST_FOR_EACH_ENTRY(it, list, struct FdNode, node) {
        bool valid = false;
        if ((it->triggerSet & READ_TRIGGER) != 0) {
            valid = true;
            SoftBusSocketFdSet(it->fd, &fdSets->readSet);
        }
        if ((it->triggerSet & WRITE_TRIGGER) != 0) {
            valid = true;
            SoftBusSocketFdSet(it->fd, &fdSets->writeSet);
        }
        if ((it->triggerSet & EXCEPT_TRIGGER) != 0) {
            valid = true;
            SoftBusSocketFdSet(it->fd, &fdSets->exceptSet);
        }
        if (valid) {
            maxFd = it->fd > maxFd ? it->fd : maxFd;
        }
    }
    return maxFd;
}

static void SetReadyFdEvent(SoftBusFdSets *fdSets, ListNode *fdEvents, ListNode *out)
{
    struct FdNode *it = NULL;
    struct FdNode *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, fdEvents, struct FdNode, node) {
        it->triggerSet = 0;
        if (SoftBusSocketFdIsset(it->fd, &fdSets->readSet)) {
            it->triggerSet |= READ_TRIGGER;
        }
        if (SoftBusSocketFdIsset(it->fd, &fdSets->writeSet)) {
            it->triggerSet |= WRITE_TRIGGER;
        }
        if (SoftBusSocketFdIsset(it->fd, &fdSets->exceptSet)) {
            it->triggerSet |= EXCEPT_TRIGGER;
        }
        ListDelete(&it->node);
        if (it->triggerSet == 0) {
            SoftBusFree(it);
            continue;
        }
        ListAdd(out, &it->node);
    }
}

int32_t WatchEvent(EventWatcher *watcher, int32_t timeoutMS, ListNode *out)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(watcher != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "watcher is NULL");
    CONN_CHECK_AND_RETURN_RET_LOGE(out != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "fd node is NULL");

    ListNode fdHeadNode;
    ListInit(&fdHeadNode);
    int32_t status = watcher->callback(&fdHeadNode);
    CONN_CHECK_AND_RETURN_RET_LOGE(status == SOFTBUS_OK, status, CONN_COMMON, "get all fd event failed");
    SoftBusFdSets fdSets = {0};
    int32_t maxFd = PrepareFdSets(&fdHeadNode, &fdSets);
            
    SoftBusSockTimeOut timeout = {0};
    timeout.usec = SELECT_INTERVAL_US;
    CONN_LOGI(CONN_COMMON, "select start");
    int32_t nEvents = SoftBusSocketSelect(maxFd + 1, &fdSets.readSet, &fdSets.writeSet, &fdSets.exceptSet, &timeout);
    if (nEvents <= 0) {
        CONN_LOGE(CONN_COMMON, "epoll wait failed or not exist ready event, status=%{public}d", nEvents);
        ReleaseFdNode(&fdHeadNode);
        return nEvents;
    }
    SetReadyFdEvent(&fdSets, &fdHeadNode, out);
    return nEvents;
}

void CloseEventWatcher(EventWatcher *watcher)
{
    CONN_CHECK_AND_RETURN_LOGE(watcher != NULL, CONN_COMMON, "event watcher is NULL");
    watcher->callback = NULL;
    SoftBusFree(watcher);
}

int32_t WaitEvent(int32_t fd, enum SocketEvent events, int32_t timeout)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(fd >= 0, SOFTBUS_INVALID_PARAM, CONN_COMMON, "invalid params. fd=%{public}d", fd);
    SoftBusSockTimeOut tv = { 0 };
    tv.sec = 0;
    tv.usec = timeout;
    int32_t rc = 0;
    switch (events) {
        case SOFTBUS_SOCKET_OUT: {
            SoftBusFdSet writeSet;
            SoftBusSocketFdZero(&writeSet);
            SoftBusSocketFdSet(fd, &writeSet);
            rc = SOFTBUS_TEMP_FAILURE_RETRY(SoftBusSocketSelect(fd + 1, NULL, &writeSet, NULL, &tv));
            if (rc < 0) {
                break;
            }
            if (!SoftBusSocketFdIsset(fd, &writeSet)) {
                CONN_LOGE(CONN_COMMON, "Enter SoftBusSocketFdIsset.");
                rc = 0;
            }
            break;
        }
        case SOFTBUS_SOCKET_IN: {
            SoftBusFdSet readSet;
            SoftBusSocketFdZero(&readSet);
            SoftBusSocketFdSet(fd, &readSet);
            rc = SOFTBUS_TEMP_FAILURE_RETRY(SoftBusSocketSelect(fd + 1, &readSet, NULL, NULL, &tv));
            if (rc < 0) {
                break;
            }
            if (!SoftBusSocketFdIsset(fd, &readSet)) {
                rc = 0;
            }
            break;
        }
        default:
            break;
    }
    return rc;
}
