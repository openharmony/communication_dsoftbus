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

#include <sys/epoll.h>

#include <securec.h>

#include "common_list.h"
#include "conn_log.h"
#include "softbus_adapter_errcode.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_base_listener.h"
#include "softbus_socket.h"

#define SOFTBUS_FD_EVENT 16
#define SOFTBUS_USEC_TRANS_MSEC 1000

static int32_t SoftBusSocketEpollCreate(void)
{
    int32_t ret = epoll_create(0);
    if (ret < 0) {
        CONN_LOGE(CONN_COMMON, "epoll create failed errno=%{public}s, ret=%{public}d", strerror(errno), ret);
        return SOFTBUS_ERRNO(KERNELS_SUB_MODULE_CODE) + abs(errno);
    }

    return ret;
}

static int32_t SoftBusSocketEpollCtl(int32_t fd, int32_t op, int32_t fd2, struct epoll_event *ev)
{
    int32_t ret = epoll_ctl(fd, op, fd2, ev);
    if (ret < 0) {
        CONN_LOGE(CONN_COMMON, "epoll ctl failed errno=%{public}s, ret=%{public}d", strerror(errno), ret);
        return SOFTBUS_ERRNO(KERNELS_SUB_MODULE_CODE) + abs(errno);
    }

    return SOFTBUS_OK;
}

static int32_t SoftBusSocketEpollWait(int32_t fd, struct epoll_event *ev, int32_t cnt, int32_t timeoutMs)
{
    int32_t ret = epoll_wait(fd, ev, cnt, timeoutMs);
    if (ret < 0) {
        CONN_LOGE(CONN_COMMON, "epoll wait failed errno=%{public}s, ret=%{public}d", strerror(errno), ret);
        if (errno == EINTR) {
            return SOFTBUS_ADAPTER_SOCKET_EINTR;
        }
        return SOFTBUS_ERRNO(KERNELS_SUB_MODULE_CODE) + abs(errno);
    }

    return ret;
}

EventWatcher* RegisterEventWatcher(GetAllFdEventCallback callback)
{
    (void)callback;
    EventWatcher *watcher = (EventWatcher *)SoftBusCalloc(sizeof(EventWatcher));
    CONN_CHECK_AND_RETURN_RET_LOGE(watcher != NULL, NULL, CONN_COMMON, "calloc event watcher failed");
    int32_t watcherId = SoftBusSocketEpollCreate();
    if (watcherId < 0) {
        SoftBusFree(watcher);
        return NULL;
    }
    watcher->watcherId = watcherId;
    CONN_LOGI(CONN_COMMON, "register event watcher success");
    return watcher;
}

static uint32_t TriggerEventToEpollEvent(uint32_t triggerEvent)
{
    uint32_t events = 0;
    if ((triggerEvent & READ_TRIGGER) != 0) {
        events |= EPOLLIN;
    }
    if ((triggerEvent & WRITE_TRIGGER) != 0) {
        events |= EPOLLOUT;
    }
    if ((triggerEvent & EXCEPT_TRIGGER) != 0) {
        events |= EPOLLPRI;
    }
    return events;
}

static int32_t OperateEpollEvent(int32_t epollFd, int32_t epollOperation, int32_t fd, uint32_t event)
{
    struct epoll_event fdEvent = {0};
    fdEvent.data.fd = fd;
    fdEvent.events = TriggerEventToEpollEvent(event);
    return SoftBusSocketEpollCtl(epollFd, epollOperation, fd, &fdEvent);
}

int32_t AddEvent(EventWatcher *watcher, int32_t fd, uint32_t event)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(watcher != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "watcher is NULL");
    CONN_CHECK_AND_RETURN_RET_LOGE(watcher->watcherId >= 0, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "watcher->watcherId < 0, watcherId=%{public}d", watcher->watcherId);
    return OperateEpollEvent(watcher->watcherId, EPOLL_CTL_ADD, fd, event);
}

int32_t ModifyEvent(EventWatcher *watcher, int32_t fd, uint32_t event)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(watcher != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "watcher is NULL");
    CONN_CHECK_AND_RETURN_RET_LOGE(watcher->watcherId >= 0, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "watcher->watcherId < 0, watcherId=%{public}d", watcher->watcherId);
    return OperateEpollEvent(watcher->watcherId, EPOLL_CTL_MOD, fd, event);
}

int32_t RemoveEvent(EventWatcher *watcher, int32_t fd)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(watcher != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "watcher is NULL");
    CONN_CHECK_AND_RETURN_RET_LOGE(watcher->watcherId >= 0, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "watcher->watcherId < 0, watcherId=%{public}d", watcher->watcherId);
    return OperateEpollEvent(watcher->watcherId, EPOLL_CTL_DEL, fd, 0);
}

static uint32_t EpollEventToTriggerEvent(uint32_t epollEvent)
{
    uint32_t events = 0;
    if ((epollEvent & EPOLLIN) != 0) {
        events |= READ_TRIGGER;
    }
    if ((epollEvent & EPOLLOUT) != 0) {
        events |= WRITE_TRIGGER;
    }
    if ((epollEvent & EPOLLPRI) != 0) {
        events |= EXCEPT_TRIGGER;
    }
    return events;
}

static void SetReadyFdEvent(struct epoll_event *events, int32_t nEvents, ListNode *out)
{
    for (int32_t i = 0; i < nEvents; i++) {
        struct FdNode *fdNode = (struct FdNode *)SoftBusCalloc(sizeof(struct FdNode));
        if (fdNode == NULL) {
            CONN_LOGE(CONN_COMMON, "calloc fd node failed, fd=%{public}d", events[i].data.fd);
            continue;
        }
        ListInit(&fdNode->node);
        fdNode->fd = events[i].data.fd;
        fdNode->triggerSet = EpollEventToTriggerEvent(events[i].events);
        ListAdd(out, &fdNode->node);
    }
}

int32_t WatchEvent(EventWatcher *watcher, int32_t timeoutMS, ListNode *out)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(watcher != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "watcher is NULL");
    CONN_CHECK_AND_RETURN_RET_LOGE(watcher->watcherId >= 0, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "watcher->watcherId < 0, watcherId=%{public}d", watcher->watcherId);
    struct epoll_event events[SOFTBUS_FD_EVENT] = {0};
    CONN_LOGI(CONN_COMMON, "epoll wait start");
    int32_t nEvents = SoftBusSocketEpollWait(watcher->watcherId, events, SOFTBUS_FD_EVENT, timeoutMS);
    CONN_CHECK_AND_RETURN_RET_LOGW(nEvents > 0, nEvents, CONN_COMMON,
        "epoll wait failed or not exist ready event, status=%{public}d", nEvents);
    SetReadyFdEvent(events, nEvents, out);
    return nEvents;
}

void CloseEventWatcher(EventWatcher *watcher)
{
    CONN_CHECK_AND_RETURN_LOGE(watcher != NULL, CONN_COMMON, "watcher is NULL");
    if (watcher->watcherId >= 0) {
        SoftBusSocketClose(watcher->watcherId);
    }
    watcher->watcherId = 0;
    SoftBusFree(watcher);
}

static int32_t WaitEpollReadyEvent(struct epoll_event fdEvent, int32_t fd, int32_t timeoutMs)
{
    int32_t epollFd = SoftBusSocketEpollCreate();
    CONN_CHECK_AND_RETURN_RET_LOGE(epollFd >= 0, epollFd, CONN_COMMON, "create epollFd failed");
    int32_t ret = SoftBusSocketEpollCtl(epollFd, EPOLL_CTL_ADD, fd, &fdEvent);
    if (ret < 0) {
        CONN_LOGE(CONN_COMMON, "add epoll event failed");
        SoftBusSocketClose(epollFd);
        return ret;
    }
    struct epoll_event events = {0};
    ret = SoftBusSocketEpollWait(epollFd, &events, 1, timeoutMs);
    SoftBusSocketClose(epollFd);
    return ret;
}

static int32_t EpollProcess(int32_t fd, uint32_t epollEvent, int32_t timeout)
{
    struct epoll_event fdEvent = {0};
    fdEvent.data.fd = fd;
    fdEvent.events = epollEvent;
    return SOFTBUS_TEMP_FAILURE_RETRY(WaitEpollReadyEvent(fdEvent, fd, timeout / SOFTBUS_USEC_TRANS_MSEC));
}

int32_t WaitEvent(int32_t fd, enum SocketEvent events, int32_t timeout)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(fd >= 0, SOFTBUS_INVALID_PARAM, CONN_COMMON, "invalid params. fd=%{public}d", fd);
    int32_t rc = 0;
    switch (events) {
        case SOFTBUS_SOCKET_OUT:
            rc = EpollProcess(fd, EPOLLOUT, timeout);
            break;
        case SOFTBUS_SOCKET_IN:
            rc = EpollProcess(fd, EPOLLIN, timeout);
            break;
        default:
            break;
    }
    return rc;
}
