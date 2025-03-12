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
#include "nstackx_list.h"
#include "nstackx_error.h"

#define TAG "nStackXEpoll"
#define MAX_EPOLL_SIZE 128
#define PRINT_RIGHT_MOVE 48
static List g_epollTaskList;
static bool g_isInit = false;
static pthread_mutex_t g_taskListMutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    List list;
    EpollTask *task;
} TaskList;

static inline void PrintTaskInfo(EpollTask *task)
{
    uint64_t taskAddress = (uint64_t)task;
    uint64_t readHandleAddress = (uint64_t)&task->readHandle;
    LOGI(TAG, "task : %02x******%06x, task->epollfd: %d, task->taskFd: %d, task->readHandle: %02x******%06x",
         (taskAddress >> PRINT_RIGHT_MOVE) & 0xff, taskAddress & 0xffffff, task->epollfd, task->taskfd,
         (readHandleAddress >> PRINT_RIGHT_MOVE) & 0xff, readHandleAddress & 0xffffff);
}

static inline void PrintTaskDebugInfo(EpollTask *task, const char *str)
{
    uint64_t taskAddress = (uint64_t)task;
    uint64_t readHandleAddress = (uint64_t)&task->readHandle;
    LOGD(TAG, "%s task : %02x******%06x, task->epollfd: %d, task->taskFd: %d, task->readHandle: %02x******%06x",
         str, (taskAddress >> PRINT_RIGHT_MOVE) & 0xff, taskAddress & 0xffffff, task->epollfd, task->taskfd,
         (readHandleAddress >> PRINT_RIGHT_MOVE) & 0xff, readHandleAddress & 0xffffff);
}

static bool IsEpollTaskEqual(EpollTask *oldTask, EpollTask *newTask)
{
    if (oldTask == newTask && oldTask->epollfd == newTask->epollfd &&
        oldTask->taskfd == newTask->taskfd && oldTask->readHandle == newTask->readHandle) {
        return true;
    }
    return false;
}

static TaskList *GetTaskFromList(EpollTask *task)
{
    if (pthread_mutex_lock(&g_taskListMutex) != 0) {
        LOGE(TAG, "lock g_taskListMutex failed");
        return NULL;
    }
    if (ListIsEmpty(&g_epollTaskList)) {
        (void)pthread_mutex_unlock(&g_taskListMutex);
        return NULL;
    }
    TaskList *taskList = NULL;
    List *pos = NULL;
    TaskList *node = NULL;
    LIST_FOR_EACH(pos, &g_epollTaskList) {
        node = (TaskList *)pos;
        if (IsEpollTaskEqual(task, node->task)) {
            taskList = node;
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_taskListMutex);
    return taskList;
}

static int32_t AddTaskToList(EpollTask *task)
{
    if (task == NULL) {
        return NSTACKX_EINVAL;
    }

    if (!g_isInit) {
        if (pthread_mutex_lock(&g_taskListMutex) != 0) {
            LOGE(TAG, "lock g_taskListMutex failed");
            return NSTACKX_EFAILED;
        }
        if (!g_isInit) {
            ListInitHead(&g_epollTaskList);
            g_isInit = true;
        }
        (void)pthread_mutex_unlock(&g_taskListMutex);
    }

    TaskList *taskListCheck = GetTaskFromList(task);
    if (taskListCheck != NULL) {
        LOGE(TAG, "taskListCheck GetTaskFromList failed");
        return NSTACKX_EFAILED;
    }
    TaskList *taskList = calloc(1, sizeof(TaskList));
    if (taskList == NULL) {
        LOGE(TAG, "calloc failed");
        return NSTACKX_EFAILED;
    }
    taskList->task = task;
    if (pthread_mutex_lock(&g_taskListMutex) != 0) {
        free(taskList);
        LOGE(TAG, "lock g_taskListMutex failed");
        return NSTACKX_EFAILED;
    }
    ListInsertTail(&g_epollTaskList, &taskList->list);
    (void)pthread_mutex_unlock(&g_taskListMutex);

    return NSTACKX_EOK;
}

static int32_t DelTaskFromList(EpollTask *task)
{
    if (task == NULL) {
        LOGE(TAG, "task is null");
        return NSTACKX_EINVAL;
    }
    TaskList *taskList = GetTaskFromList(task);
    if (taskList == NULL) {
        LOGE(TAG, "task is not exist");
        PrintTaskInfo(task);
        return NSTACKX_EFAILED;
    }
    if (pthread_mutex_lock(&g_taskListMutex) != 0) {
        LOGE(TAG, "lock g_taskListMutex failed");
        return NSTACKX_EFAILED;
    }
    ListRemoveNode(&taskList->list);
    (void)pthread_mutex_unlock(&g_taskListMutex);
    free(taskList);
    return NSTACKX_EOK;
}

int32_t RefreshEpollTask(EpollTask *task, uint32_t events)
{
    struct epoll_event event;
    if (task == NULL) {
        return NSTACKX_EINVAL;
    }

    TaskList *taskList = GetTaskFromList(task);
    if (taskList == NULL) {
        LOGE(TAG, "task is not exist");
        PrintTaskInfo(task);
        return NSTACKX_EFAILED;
    }
    event.data.ptr = task;
    event.events = events;

    if (epoll_ctl(task->epollfd, EPOLL_CTL_MOD, task->taskfd, &event) < 0) {
        LOGE(TAG, "Refresh task failed: %d", errno);
        return NSTACKX_EFAILED;
    }

    PrintTaskDebugInfo(task, "RefreshEpollTask");
    return NSTACKX_EOK;
}

int32_t RegisterEpollTask(EpollTask *task, uint32_t events)
{
    struct epoll_event event;
    if (task == NULL) {
        return NSTACKX_EINVAL;
    }

    if (AddTaskToList(task) != NSTACKX_EOK) {
        LOGE(TAG, "task is exist");
        PrintTaskInfo(task);
        return NSTACKX_EFAILED;
    }

    event.data.ptr = task;
    event.events = events;
    if (epoll_ctl(task->epollfd, EPOLL_CTL_ADD, task->taskfd, &event) < 0) {
        LOGE(TAG, "Register task failed: %d", errno);
        DelTaskFromList(task);
        return NSTACKX_EFAILED;
    }

    PrintTaskDebugInfo(task, "RegisterEpollTask");
    return NSTACKX_EOK;
}

int32_t DeRegisterEpollTask(EpollTask *task)
{
    if (task == NULL) {
        return NSTACKX_EINVAL;
    }

    if (DelTaskFromList(task) != NSTACKX_EOK) {
        LOGE(TAG, "task is not exist");
        PrintTaskInfo(task);
        return NSTACKX_EFAILED;
    }
    if (epoll_ctl(task->epollfd, EPOLL_CTL_DEL, task->taskfd, NULL) < 0) {
        LOGE(TAG, "De-register task failed: %d", errno);
        return NSTACKX_EFAILED;
    }

    PrintTaskDebugInfo(task, "DeRegisterEpollTask");
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
            TaskList *taskList = GetTaskFromList(task);
            if (taskList == NULL) {
                LOGE(TAG, "task is not exist");
                PrintTaskInfo(task);
                return NSTACKX_OVERFLOW;
            }
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
