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

#include "securec.h"
#include "nstackx_epoll.h"
#include "nstackx_log.h"
#include "nstackx_error.h"
#include "nstackx_list.h"
#include "nstackx_socket.h"
#include "nstackx_timer.h"

#define TAG "nStackXEpoll"

#ifndef LWIP_LITEOS_A_COMPAT
#define IS_INVALID_SOCKET_DESC(fd) \
    (((fd) < LWIP_SOCKET_OFFSET) || ((fd) >= (LWIP_CONFIG_NUM_SOCKETS + LWIP_SOCKET_OFFSET)))
#define EVENT_PTR_IDX(fd) ((fd) - (LWIP_SOCKET_OFFSET))
#else
#define IS_INVALID_SOCKET_DESC(fd) ((fd) < 0)
#endif /* LWIP_LITEOS_A_COMPAT */

typedef struct {
    fd_set *readfds;
    fd_set *writefds;
    fd_set *exceptfds;
} EpollSetPtr;

typedef struct {
    struct EpollDescStr epollfd;
    int32_t maxfd;
    fd_set readfds;
    fd_set writefds;
    fd_set exceptfds;
    pthread_mutex_t mutex;
} EpollSet;

#ifdef LWIP_LITEOS_A_COMPAT
struct EpollTaskList {
    List list;
    EpollTask *taskPtr;
};

struct EpollEventPtr {
    List list;
    List taskList;
    EpollSet *epollSetPtr;
};
#else
struct EpollEventPtr {
    EpollSet *epollSetPtr;
    EpollTask *taskPtr;
};
#endif

typedef void (*EpollTraverseFunc)(EpollSet *epollSetPtr, void *param, int32_t fd);
typedef void (*EpollEventCtrlFunc)(EpollSet *epollSetPtr, uint32_t events, EpollTask *task);

static uint8_t g_epollInited = NSTACKX_FALSE;
static pthread_mutex_t g_epollEventPtrMutex;

#ifdef LWIP_LITEOS_A_COMPAT
static List g_epollEventPtrList;
#else
static struct EpollEventPtr *g_epollEventPtrArray = NULL;
#endif

static void EpollFdEventAdd(EpollSet *epollSetPtr, uint32_t events, EpollTask *task);
static void EpollFdEventDel(EpollSet *epollSetPtr, uint32_t events, EpollTask *task);
static void EpollFdEventMod(EpollSet *epollSetPtr, uint32_t events, EpollTask *task);

static int32_t CtlEpollDesc(EpollTask *task, int op, uint32_t events)
{
    struct EpollEvent event;
#ifdef NSTACKX_DEBUG
    static uint32_t evtCnt = 0;
#endif

    if ((task == NULL) || ((op != EPOLL_CTL_RUN) && IS_INVALID_SOCKET_DESC(task->taskfd)) ||
        (!IsEpollDescValid(task->epollfd))) {
        LOGE(TAG, "invalid params");
        return NSTACKX_EINVAL;
    }

    event.op = op;
    event.events = events;
    event.ptr = (void *)task;
#ifdef NSTACKX_DEBUG
    event.evtSeq = evtCnt++;
    LOGD(TAG, "%d op %d event seq: %u", task->epollfd->recvFd, op, event.evtSeq);
#endif
    if (sendto(task->epollfd->sendFd, (const void *)&event, sizeof(event), 0, NULL, 0) < 0) {
        LOGE(TAG, "ctrl epollfd failed: %d", errno);
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

static int32_t CtlEpollDescSync(EpollTask *task, EpollEventCtrlFunc func, uint32_t events)
{
    EpollSet *epollSetPtr = NULL;
    if ((task == NULL) || IS_INVALID_SOCKET_DESC(task->taskfd) || (!IsEpollDescValid(task->epollfd))) {
        LOGE(TAG, "invalid params");
        return NSTACKX_EINVAL;
    }

    epollSetPtr = container_of(task->epollfd, EpollSet, epollfd);
    if (pthread_mutex_lock(&(epollSetPtr->mutex)) != 0) {
        LOGE(TAG, "pthread mutex lock error");
        return NSTACKX_EFAILED;
    }
    func(epollSetPtr, events, task);
    if (pthread_mutex_unlock(&(epollSetPtr->mutex)) != 0) {
        LOGE(TAG, "pthread mutex unlock error");
    }

    return NSTACKX_EOK;
}

int32_t RunEpollTask(void *task, uint32_t events)
{
    return CtlEpollDesc((EpollTask *)task, EPOLL_CTL_RUN, events);
}

int32_t RefreshEpollTask(EpollTask *task, uint32_t events)
{
    return CtlEpollDescSync(task, EpollFdEventMod, events);
}

int32_t RegisterEpollTask(EpollTask *task, uint32_t events)
{
    return CtlEpollDescSync(task, EpollFdEventAdd, events);
}

int32_t DeRegisterEpollTask(EpollTask *task)
{
    return CtlEpollDescSync(task, EpollFdEventDel, 0);
}

#ifdef LWIP_LITEOS_A_COMPAT
static EpollSet *EpollSetFindByFd(int32_t fd)
{
    List *curr = NULL;
    struct EpollEventPtr *ptr = NULL;
    LIST_FOR_EACH(curr, &g_epollEventPtrList) {
        ptr = container_of(curr, struct EpollEventPtr, list);
        if (FD_ISSET(fd, &(ptr->epollSetPtr->exceptfds))) {
            return ptr->epollSetPtr;
        }
    }
    return NULL;
}

static struct EpollEventPtr *EpollEventListFind(const EpollSet *epollSetPtr)
{
    List *curr = NULL;
    struct EpollEventPtr *ptr = NULL;
    LIST_FOR_EACH(curr, &g_epollEventPtrList) {
        ptr = container_of(curr, struct EpollEventPtr, list);
        if (ptr->epollSetPtr == epollSetPtr) {
            return ptr;
        }
    }
    return NULL;
}

static struct EpollTaskList *EpollTaskListFind(const struct EpollEventPtr *ptr, const EpollTask *task)
{
    List *curr = NULL;
    struct EpollTaskList *taskListPtr = NULL;
    LIST_FOR_EACH(curr, &(ptr->taskList)) {
        taskListPtr = container_of(curr, struct EpollTaskList, list);
        if (taskListPtr->taskPtr == task) {
            return taskListPtr;
        }
    }
    return NULL;
}

static struct EpollTaskList *EpollTaskListNew(EpollTask *task)
{
    struct EpollTaskList *taskListPtr = (struct EpollTaskList *)malloc(sizeof(struct EpollTaskList));
    if (taskListPtr == NULL) {
        LOGE(TAG, "alloc EpollTaskList failed");
        return NULL;
    }
    (void)memset_s(taskListPtr, sizeof(*taskListPtr), 0, sizeof(*taskListPtr));
    taskListPtr->taskPtr = task;
    ListInitHead(&(taskListPtr->list));
    return taskListPtr;
}

static int32_t EpollEventTaskListAdd(const EpollSet *epollSetPtr, EpollTask *task)
{
    struct EpollEventPtr *ptr = EpollEventListFind(epollSetPtr);
    struct EpollTaskList *taskListPtr = NULL;
    if (ptr == NULL) {
        LOGE(TAG, "EpollSet not in list");
        return NSTACKX_NOEXIST;
    }
    taskListPtr = EpollTaskListNew(task);
    if (taskListPtr == NULL) {
        return NSTACKX_ENOMEM;
    }
    ListInsertTail(&(ptr->taskList), &(taskListPtr->list));
    return NSTACKX_EOK;
}

static void EpollEventTaskListDel(const EpollSet *epollSetPtr, const EpollTask *task)
{
    struct EpollEventPtr *ptr = EpollEventListFind(epollSetPtr);
    struct EpollTaskList *taskListPtr = NULL;
    if (ptr == NULL) {
        LOGE(TAG, "EpollSet not in list");
        return;
    }
    taskListPtr = EpollTaskListFind(ptr, task);
    if (taskListPtr == NULL) {
        return;
    }
    ListRemoveNode(&(taskListPtr->list));
    free(taskListPtr);
    return;
}

static EpollTask *EpollTaskFindByFd(const struct EpollEventPtr *ptr, int32_t fd)
{
    List *curr = NULL;
    struct EpollTaskList *taskListPtr = NULL;
    LIST_FOR_EACH(curr, &(ptr->taskList)) {
        taskListPtr = container_of(curr, struct EpollTaskList, list);
        if (taskListPtr->taskPtr->taskfd == fd) {
            return taskListPtr->taskPtr;
        }
    }
    return NULL;
}

static EpollTask *EpollSetFindTaskByFd(const EpollSet *epollSetPtr, int32_t fd)
{
    struct EpollEventPtr *ptr = EpollEventListFind(epollSetPtr);
    if (ptr == NULL) {
        LOGE(TAG, "EpollSet not in list");
        return NULL;
    }
    return EpollTaskFindByFd(ptr, fd);
}
#endif /* LWIP_LITEOS_A_COMPAT */

static int32_t ConnectPeerFd(int32_t localFd, int32_t peerFd)
{
    struct sockaddr_in addr = {0};
    socklen_t addr_len = sizeof(addr);

    if (getsockname(peerFd, (struct sockaddr *)&addr, &addr_len) != 0) {
        LOGE(TAG, "getsockname failed: %d", errno);
        return NSTACKX_EFAILED;
    }
    if (connect(localFd, (struct sockaddr *)&addr, addr_len) != 0) {
        LOGE(TAG, "connect failed: %d", errno);
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

static int32_t GetLoopbackFd(int32_t peerFd)
{
    int32_t fd;
    struct sockaddr_in addr = {0};
    struct sockaddr *sockaddr = NULL;
    socklen_t addr_len;

    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    sockaddr = (struct sockaddr *)&addr;
    addr_len = sizeof(addr);

    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        LOGE(TAG, "socket failed: %d", errno);
        return -1;
    }

    if (SetSocketNonBlock(fd) != NSTACKX_EOK) {
        LOGE(TAG, "set socket nonblock failed");
        close(fd);
        return -1;
    }

    if (bind(fd, sockaddr, addr_len) != 0) {
        LOGE(TAG, "bind failed: %d", errno);
        close(fd);
        return -1;
    }

    if (peerFd < 0) {
        /* if peerFd is invalid, there is no need to connect to it, just return */
        return fd;
    }

    if ((ConnectPeerFd(fd, peerFd) == NSTACKX_EFAILED) || (ConnectPeerFd(peerFd, fd) == NSTACKX_EFAILED)) {
        close(fd);
        return -1;
    }

    return fd;
}

int32_t CreateEpollFdPair(struct EpollDescStr *epollfd)
{
    if (epollfd == NULL) {
        LOGE(TAG, "invalid param");
        return NSTACKX_EINVAL;
    }

    epollfd->recvFd = GetLoopbackFd(-1);
    if (epollfd->recvFd < 0) {
        epollfd->recvFd = -1;
        epollfd->sendFd = -1;
        return NSTACKX_EFAILED;
    }

    epollfd->sendFd = GetLoopbackFd(epollfd->recvFd);
    if (epollfd->sendFd < 0) {
        close(epollfd->recvFd);
        epollfd->recvFd = -1;
        epollfd->sendFd = -1;
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

void EpollEventPtrInit(void)
{
    if (g_epollInited == NSTACKX_TRUE) {
        return;
    }
    /* this function is called when init lwip thread */
    if (pthread_mutex_init(&g_epollEventPtrMutex, NULL) != 0) {
        LOGE(TAG, "pthread_mutex_init error");
        return;
    }
#ifdef LWIP_LITEOS_A_COMPAT
    ListInitHead(&g_epollEventPtrList);
#else
    /* as ported to LwIP, once the memory is allocated, it will not be freed ever */
    g_epollEventPtrArray = (struct EpollEventPtr *)malloc(LWIP_CONFIG_NUM_SOCKETS * sizeof(struct EpollEventPtr));
    if (g_epollEventPtrArray == NULL) {
        LOGE(TAG, "malloc epoll ptr array failed");
        return;
    }
    (void)memset_s(g_epollEventPtrArray, LWIP_CONFIG_NUM_SOCKETS * sizeof(struct EpollEventPtr), 0x0,
        LWIP_CONFIG_NUM_SOCKETS * sizeof(struct EpollEventPtr));
#endif
    g_epollInited = NSTACKX_TRUE;
    LOGD(TAG, "epoll event init success");
    return;
}

static int32_t EpollEventRecordAdd(EpollSet *epollSetPtr)
{
    if (pthread_mutex_lock(&g_epollEventPtrMutex) != 0) {
        LOGE(TAG, "pthread mutex lock error");
        return NSTACKX_EFAILED;
    }
#ifdef LWIP_LITEOS_A_COMPAT
    struct EpollEventPtr *ptr = (struct EpollEventPtr *)malloc(sizeof(struct EpollEventPtr));
    if (ptr == NULL) {
        if (pthread_mutex_unlock(&g_epollEventPtrMutex) != 0) {
            LOGE(TAG, "pthread mutex unlock error");
        }
        LOGE(TAG, "EpollEventPtr alloc failed");
        return NSTACKX_ENOMEM;
    }
    (void)memset_s(ptr, sizeof(struct EpollEventPtr), 0, sizeof(struct EpollEventPtr));
    ListInitHead(&(ptr->list));
    ListInitHead(&(ptr->taskList));
    ptr->epollSetPtr = epollSetPtr;
    ListInsertTail(&g_epollEventPtrList, &(ptr->list));
#else
    g_epollEventPtrArray[EVENT_PTR_IDX(epollSetPtr->epollfd.recvFd)].epollSetPtr = epollSetPtr;
    g_epollEventPtrArray[EVENT_PTR_IDX(epollSetPtr->epollfd.sendFd)].epollSetPtr = epollSetPtr;
#endif
    if (pthread_mutex_unlock(&g_epollEventPtrMutex) != 0) {
        /* just give log, no error returned */
        LOGE(TAG, "pthread mutex unlock error");
    }
    return NSTACKX_EOK;
}

EpollDesc CreateEpollDesc(void)
{
    EpollSet *epollSetPtr = NULL;

    if (g_epollInited != NSTACKX_TRUE) {
        LOGE(TAG, "Epoll Event Ptr Not Init");
        return NULL;
    }

    epollSetPtr = (EpollSet *)malloc(sizeof(EpollSet));
    if (epollSetPtr == NULL) {
        LOGE(TAG, "malloc EpollSet failed");
        return NULL;
    }
    (void)memset_s(epollSetPtr, sizeof(EpollSet), 0, sizeof(EpollSet));

    if (pthread_mutex_init(&(epollSetPtr->mutex), NULL) != 0) {
        LOGE(TAG, "pthread_mutex_init error");
        goto FAIL_FREE;
    }

    if (CreateEpollFdPair(&(epollSetPtr->epollfd)) != NSTACKX_EOK) {
        LOGE(TAG, "Create Epoll failed");
        goto FAIL_MUTEX;
    }

    FD_SET(epollSetPtr->epollfd.recvFd, &epollSetPtr->readfds);
    FD_SET(epollSetPtr->epollfd.recvFd, &epollSetPtr->exceptfds);
    epollSetPtr->maxfd = epollSetPtr->epollfd.recvFd;

    if (EpollEventRecordAdd(epollSetPtr) != NSTACKX_EOK) {
        goto FAIL_CLOSE;
    }

    return &(epollSetPtr->epollfd);
FAIL_CLOSE:
    close(epollSetPtr->epollfd.recvFd);
    close(epollSetPtr->epollfd.sendFd);
FAIL_MUTEX:
    if (pthread_mutex_destroy(&(epollSetPtr->mutex)) != 0) {
        LOGE(TAG, "pthread mutex destroy error: %d", errno);
    }
FAIL_FREE:
    free(epollSetPtr);
    return NULL;
}

static int32_t RearZeroBitNum(unsigned long x)
{
    int32_t n = 1;
    int bitMov = TYPE_BITS_NUM(x) >> 1;
    int bitNum = bitMov;

    /* through binarySearch */
    while (bitNum > 1) {
        if ((x << bitMov) == 0) {
            n = n + bitNum;
            x = x >> bitNum;
        }
        bitNum = bitNum >> 1;
        bitMov += bitNum;
    }

    n = n - (x & 1);
    return n;
}

static int32_t PreZeroBitNum(unsigned long x)
{
    int n = 1;
    int bitMov = TYPE_BITS_NUM(x) >> 1;
    int bitNum = bitMov;

    /* through binarySearch */
    while (bitNum > 1) {
        if ((x >> bitMov) == 0) {
            n = n + bitNum;
            x = x << bitNum;
        }
        bitNum = bitNum >> 1;
        bitMov += bitNum;
    }

    n = n - (x >> (TYPE_BITS_NUM(x) - 1));
    return n;
}

static void EpollTaskEventHandle(uint32_t events, EpollTask *task)
{
    if ((events & EPOLLERR) == EPOLLERR) {
        if (task->errorHandle != NULL) {
            task->errorHandle(task);
        }
        return;
    }

    if (((events & EPOLLIN) == EPOLLIN) && (task->readHandle != NULL)) {
        task->readHandle(task);
    }

    /* Caution: It is possible for xxxHandle to free the Timer struct part of which the `task` is pointing to.
     * See ClientSettingTimeoutHandle() and ServerSettingTimeoutHandle() functions for an example. Coders must
     * logically assert that the `task` pointer will never be dereferenced if its content is previously freed.
     */
    if (((events & EPOLLOUT) == EPOLLOUT) && (task->writeHandle != NULL)) {
        task->writeHandle(task);
    }
}

static int32_t EpollFdEventTaskAdd(EpollSet *epollSetPtr, EpollTask *task)
{
    int32_t ret = NSTACKX_EOK;
    if (pthread_mutex_lock(&g_epollEventPtrMutex) != 0) {
        LOGE(TAG, "pthread mutex lock error");
        return NSTACKX_EFAILED;
    }
#ifdef LWIP_LITEOS_A_COMPAT
    if (EpollEventTaskListAdd(epollSetPtr, task) != NSTACKX_EOK) {
        ret = NSTACKX_EFAILED;
    }
#else
    g_epollEventPtrArray[EVENT_PTR_IDX(task->taskfd)].epollSetPtr = epollSetPtr;
    g_epollEventPtrArray[EVENT_PTR_IDX(task->taskfd)].taskPtr = task;
#endif
    if (pthread_mutex_unlock(&g_epollEventPtrMutex) != 0) {
        LOGE(TAG, "pthread mutex unlock error");
    }
    return ret;
}

static void EpollFdEventAdd(EpollSet *epollSetPtr, uint32_t events, EpollTask *task)
{
#ifndef LWIP_LITEOS_A_COMPAT
    EpollSet *setPtr = g_epollEventPtrArray[EVENT_PTR_IDX(task->taskfd)].epollSetPtr;
    if ((setPtr != NULL) && (setPtr != epollSetPtr)) {
        LOGE(TAG, "ADD: fd %d ptr has been used", task->taskfd);
        return;
    }
#endif
    if (FD_ISSET(task->taskfd, &epollSetPtr->exceptfds)) {
        LOGD(TAG, "ADD: fd %d has in epoll ctl", task->taskfd);
        return;
    }
    if ((events & (EPOLLIN | EPOLLOUT)) == 0) {
        LOGI(TAG, "invalid events");
        return;
    }
    if ((events & EPOLLIN) == EPOLLIN) {
        FD_SET(task->taskfd, &epollSetPtr->readfds);
    }
    if ((events & EPOLLOUT) == EPOLLOUT) {
        FD_SET(task->taskfd, &epollSetPtr->writefds);
    }
    FD_SET(task->taskfd, &epollSetPtr->exceptfds);

    if (EpollFdEventTaskAdd(epollSetPtr, task) != NSTACKX_EOK) {
        FD_CLR(task->taskfd, &epollSetPtr->readfds);
        FD_CLR(task->taskfd, &epollSetPtr->writefds);
        FD_CLR(task->taskfd, &epollSetPtr->exceptfds);
        return;
    }
    if (task->taskfd > epollSetPtr->maxfd) {
        epollSetPtr->maxfd = task->taskfd;
    }
}

static void EpollSetMaxFdUpdate(EpollSet *epollSetPtr)
{
    int32_t i, fd;

#ifdef __LITEOS__
#ifdef FDSETSAFESET
    for (i = (epollSetPtr->maxfd - LWIP_SOCKET_OFFSET) / BYTE_BITS_NUM; i >= 0; i--) {
        uint8_t bits = epollSetPtr->exceptfds.fd_bits[i];
#else
    for (i = epollSetPtr->maxfd / NFDBITS; i >= LWIP_SOCKET_OFFSET / NFDBITS; i--) {
        unsigned long bits = epollSetPtr->exceptfds.fds_bits[i];
#endif
#else
    for (i = epollSetPtr->maxfd / __NFDBITS; i >= LWIP_SOCKET_OFFSET / __NFDBITS; i--) {
        unsigned long bits = (unsigned long)(__FDS_BITS(&(epollSetPtr->exceptfds))[i]);
#endif
        if (bits == 0) {
            continue;
        }
        int32_t bitIdx = PreZeroBitNum(bits);
#ifdef __LITEOS__
#ifdef FDSETSAFESET
        fd = i * BYTE_BITS_NUM + (TYPE_BITS_NUM(unsigned long) - 1 - bitIdx) + LWIP_SOCKET_OFFSET;
#else
        fd = i * NFDBITS + (TYPE_BITS_NUM(unsigned long) - 1 - bitIdx);
#endif
#else
        fd = i * __NFDBITS + (TYPE_BITS_NUM(unsigned long) - 1 - bitIdx);
#endif
        epollSetPtr->maxfd = fd;
        break;
    }

    return;
}

static void EpollFdEventTaskDel(const EpollSet *epollSetPtr, const EpollTask *task)
{
    if (pthread_mutex_lock(&g_epollEventPtrMutex) != 0) {
        LOGE(TAG, "pthread mutex lock error");
        return;
    }
#ifdef LWIP_LITEOS_A_COMPAT
    EpollEventTaskListDel(epollSetPtr, task);
#else
    g_epollEventPtrArray[EVENT_PTR_IDX(task->taskfd)].epollSetPtr = NULL;
    g_epollEventPtrArray[EVENT_PTR_IDX(task->taskfd)].taskPtr = NULL;
#endif
    if (pthread_mutex_unlock(&g_epollEventPtrMutex) != 0) {
        LOGE(TAG, "pthread mutex unlock error");
    }
}

static void EpollFdEventDel(EpollSet *epollSetPtr, uint32_t events, EpollTask *task)
{
#ifndef LWIP_LITEOS_A_COMPAT
    EpollSet *setPtr = g_epollEventPtrArray[EVENT_PTR_IDX(task->taskfd)].epollSetPtr;
    if ((setPtr != NULL) && (setPtr != epollSetPtr)) {
        LOGE(TAG, "DEL: fd %d ptr has been used", task->taskfd);
        return;
    }
#endif
    (void)events;
    if (!FD_ISSET(task->taskfd, &epollSetPtr->exceptfds)) {
        LOGD(TAG, "DEL: fd %d not in epoll ctl", task->taskfd);
        return;
    }
    FD_CLR(task->taskfd, &epollSetPtr->readfds);
    FD_CLR(task->taskfd, &epollSetPtr->writefds);
    FD_CLR(task->taskfd, &epollSetPtr->exceptfds);

    EpollFdEventTaskDel(epollSetPtr, task);

    if (task->taskfd == epollSetPtr->maxfd) {
        EpollSetMaxFdUpdate(epollSetPtr);
    }

    return;
}

static void EpollFdEventMod(EpollSet *epollSetPtr, uint32_t events, EpollTask *task)
{
#ifndef LWIP_LITEOS_A_COMPAT
    EpollSet *setPtr = g_epollEventPtrArray[EVENT_PTR_IDX(task->taskfd)].epollSetPtr;
    if ((setPtr != NULL) && (setPtr != epollSetPtr)) {
        LOGE(TAG, "MOD: fd %d ptr has been used", task->taskfd);
        return;
    }
#endif
    if (!FD_ISSET(task->taskfd, &epollSetPtr->exceptfds)) {
        LOGD(TAG, "MOD: fd %d not in epoll ctl", task->taskfd);
        return;
    }
    if ((events & (EPOLLIN | EPOLLOUT)) == 0) {
        LOGI(TAG, "invalid events");
        return;
    }
    FD_CLR(task->taskfd, &epollSetPtr->readfds);
    FD_CLR(task->taskfd, &epollSetPtr->writefds);
    if ((events & EPOLLIN) == EPOLLIN) {
        FD_SET(task->taskfd, &epollSetPtr->readfds);
    }
    if ((events & EPOLLOUT) == EPOLLOUT) {
        FD_SET(task->taskfd, &epollSetPtr->writefds);
    }

    return;
}

static void EpollFdEventRun(EpollSet *epollSetPtr, uint32_t events, EpollTask *task)
{
    (void)epollSetPtr;
    EpollTaskEventHandle(events, task);
}

static void EpollFdEventOpHandle(EpollSet *epollSetPtr, int op, uint32_t events, EpollTask *task)
{
    switch (op) {
        case EPOLL_CTL_ADD:
        case EPOLL_CTL_DEL:
        case EPOLL_CTL_MOD:
            break;
        case EPOLL_CTL_RUN:
            EpollFdEventRun(epollSetPtr, events, task);
            break;
        default:
            LOGI(TAG, "unsupported op %u", op);
            break;
    }
}

static void EpollFdEventHandle(EpollSet *epollSetPtr, fd_set *readfds)
{
    int32_t ret;
    EpollTask *task = NULL;
    struct EpollEvent event;
    if (!FD_ISSET(epollSetPtr->epollfd.recvFd, readfds)) {
        return;
    }

    while (NSTACKX_TRUE) {
        ret = recvfrom(epollSetPtr->epollfd.recvFd, (void *)&event, sizeof(event), 0, NULL, NULL);
        if (ret < (int32_t)(sizeof(event))) {
            break;
        }
#ifdef NSTACKX_DEBUG
        LOGD(TAG, "Handle task %d event seq: %u", epollSetPtr->epollfd.recvFd, event.evtSeq);
#endif
        task = (EpollTask *)event.ptr;
        if (task == NULL) {
            continue;
        }
        EpollFdEventOpHandle(epollSetPtr, event.op, event.events, task);
    }
}

static void EpollEventHandle(EpollSet *epollSetPtr, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, int32_t fd)
{
    uint32_t events = 0;
    EpollTask *task = NULL;

#ifdef LWIP_LITEOS_A_COMPAT
    task = EpollSetFindTaskByFd(epollSetPtr, fd);
#else
    EpollSet *setPtr = g_epollEventPtrArray[EVENT_PTR_IDX(fd)].epollSetPtr;
    if (setPtr != epollSetPtr) {
        return;
    }
    task = g_epollEventPtrArray[EVENT_PTR_IDX(fd)].taskPtr;
#endif
    if (task == NULL) {
        return;
    }

    if (FD_ISSET(fd, readfds)) {
        events |= EPOLLIN;
    }
    if (FD_ISSET(fd, writefds)) {
        events |= EPOLLOUT;
    }
    if (FD_ISSET(fd, exceptfds)) {
        events |= EPOLLERR;
    }
    if (events == 0) {
        return;
    }

    EpollTaskEventHandle(events, task);
}

static void EpollSetFdHandle(EpollSet *epollSetPtr, void *param, int32_t fd)
{
    EpollSetPtr *setPtr = (EpollSetPtr *)param;
    fd_set *readfds = setPtr->readfds;
    fd_set *writefds = setPtr->writefds;
    fd_set *exceptfds = setPtr->exceptfds;
    if (fd == epollSetPtr->epollfd.recvFd) {
        EpollFdEventHandle(epollSetPtr, readfds);
#ifdef LWIP_LITEOS_A_COMPAT
    } else {
#else
    } else if (g_epollEventPtrArray[EVENT_PTR_IDX(fd)].epollSetPtr == epollSetPtr) {
#endif
        EpollEventHandle(epollSetPtr, readfds, writefds, exceptfds, fd);
    }
}

static void EpollSetTraverse(EpollSet *epollSetPtr, EpollTraverseFunc func, void *param)
{
#ifdef __LITEOS__
#ifdef FDSETSAFESET
    for (int32_t i = 0; i <= (epollSetPtr->maxfd - LWIP_SOCKET_OFFSET) / BYTE_BITS_NUM; i++) {
        uint8_t bits = epollSetPtr->exceptfds.fd_bits[i];
#else
    for (int32_t i = LWIP_SOCKET_OFFSET / NFDBITS; i <= epollSetPtr->maxfd / NFDBITS; i++) {
        unsigned long bits = epollSetPtr->exceptfds.fds_bits[i];
#endif
#else
    for (int32_t i = LWIP_SOCKET_OFFSET / __NFDBITS; i <= epollSetPtr->maxfd / __NFDBITS; i++) {
        unsigned long bits = (unsigned long)(__FDS_BITS(&(epollSetPtr->exceptfds))[i]);
#endif
        while (bits != 0) {
            int32_t fd;
            int32_t bitIdx = RearZeroBitNum(bits);
#ifdef __LITEOS__
#ifdef FDSETSAFESET
            fd = i * BYTE_BITS_NUM + bitIdx + LWIP_SOCKET_OFFSET;
#else
            fd = i * NFDBITS + bitIdx;
#endif
#else
            fd = i * __NFDBITS + bitIdx;
#endif
            func(epollSetPtr, param, fd);
            bits &= (bits - 1);
        }
    }
}

int32_t EpollLoop(EpollDesc epollfd, int32_t timeout)
{
    EpollSet *epollSetPtr = NULL;
    fd_set readfds, writefds, exceptfds;
    EpollSetPtr param = {&readfds, &writefds, &exceptfds};
    int32_t ret;
    struct timeval tv;
    struct timeval *tvp = NULL;

    if (!IsEpollDescValid(epollfd)) {
        return NSTACKX_EFAILED;
    }

    if (timeout != -1) {
        tv.tv_sec = timeout / NSTACKX_MILLI_TICKS;
        tv.tv_usec = (timeout % NSTACKX_MILLI_TICKS) * NSTACKX_MICRO_SEC_PER_MILLI_SEC;
        tvp = &tv;
    }

    epollSetPtr = container_of(epollfd, EpollSet, epollfd);
    if (memcpy_s(&readfds, sizeof(fd_set), &epollSetPtr->readfds, sizeof(fd_set)) != EOK ||
        memcpy_s(&writefds, sizeof(fd_set), &epollSetPtr->writefds, sizeof(fd_set)) != EOK ||
        memcpy_s(&exceptfds, sizeof(fd_set), &epollSetPtr->exceptfds, sizeof(fd_set)) != EOK) {
        return NSTACKX_EFAILED;
    }

    ret = select(epollSetPtr->maxfd + 1, &readfds, &writefds, &exceptfds, tvp);
    if (ret < 0) {
        if (errno == EINTR) {
            return NSTACKX_EINTR;
        }
        LOGE(TAG, "epoll %d select error", epollfd->recvFd);
        return NSTACKX_EFAILED;
    } else if (ret == 0) {
        return NSTACKX_ETIMEOUT;
    }

    EpollSetTraverse(epollSetPtr, EpollSetFdHandle, &param);

    return ret;
}

#ifndef LWIP_LITEOS_A_COMPAT
static void EpollSetClearHandle(EpollSet *epollSetPtr, void *param, int32_t fd)
{
    EpollSet *setPtr = g_epollEventPtrArray[EVENT_PTR_IDX(fd)].epollSetPtr;
    (void)param;
    if ((setPtr != NULL) && (setPtr != epollSetPtr)) {
        LOGE(TAG, "Clear: fd %d ptr has been used", fd);
        return;
    }
    if (pthread_mutex_lock(&g_epollEventPtrMutex) != 0) {
        LOGE(TAG, "pthread mutex lock error");
        return;
    }
    g_epollEventPtrArray[EVENT_PTR_IDX(fd)].epollSetPtr = NULL;
    g_epollEventPtrArray[EVENT_PTR_IDX(fd)].taskPtr = NULL;
    if (pthread_mutex_unlock(&g_epollEventPtrMutex) != 0) {
        LOGE(TAG, "pthread mutex unlock error");
        return;
    }
}

static void EpollEventCleanup(const EpollSet *epollSetPtr)
{
    g_epollEventPtrArray[EVENT_PTR_IDX(epollSetPtr->epollfd.recvFd)].epollSetPtr = NULL;
    g_epollEventPtrArray[EVENT_PTR_IDX(epollSetPtr->epollfd.recvFd)].taskPtr = NULL;
    g_epollEventPtrArray[EVENT_PTR_IDX(epollSetPtr->epollfd.sendFd)].epollSetPtr = NULL;
    g_epollEventPtrArray[EVENT_PTR_IDX(epollSetPtr->epollfd.sendFd)].taskPtr = NULL;
}
#else
static void EpollEventCleanup(const EpollSet *epollSetPtr)
{
    List *pos = NULL;
    List *tmp = NULL;
    struct EpollTaskList *taskListPtr = NULL;
    struct EpollEventPtr *ptr = EpollEventListFind(epollSetPtr);
    if (ptr == NULL) {
        return;
    }
    ListRemoveNode(&(ptr->list));
    LIST_FOR_EACH_SAFE(pos, tmp, &(ptr->taskList)) {
        taskListPtr = container_of(pos, struct EpollTaskList, list);
        ListRemoveNode(&taskListPtr->list);
        free(taskListPtr);
    }
    free(ptr);
}
#endif /* LWIP_LITEOS_A_COMPAT */

void CloseEpollDescInner(EpollDesc epollfd)
{
    EpollSet *epollSetPtr = NULL;
    if (!(IsEpollDescValid(epollfd))) {
        return;
    }
    epollSetPtr = container_of(epollfd, EpollSet, epollfd);
#ifndef LWIP_LITEOS_A_COMPAT
    EpollSetTraverse(epollSetPtr, EpollSetClearHandle, NULL);
#endif /* LWIP_LITEOS_A_COMPAT */
    if (pthread_mutex_lock(&g_epollEventPtrMutex) != 0) {
        LOGE(TAG, "pthread mutex lock error");
        goto FAIL_CLOSE;
    }
    EpollEventCleanup(epollSetPtr);
    if (pthread_mutex_unlock(&g_epollEventPtrMutex) != 0) {
        LOGE(TAG, "pthread mutex unlock error");
    }
FAIL_CLOSE:
    close(epollfd->recvFd);
    close(epollfd->sendFd);
    if (pthread_mutex_destroy(&(epollSetPtr->mutex)) != 0) {
        LOGE(TAG, "pthread mutex destroy error: %d", errno);
    }
    free(epollSetPtr);

    return;
}

#ifdef LWIP_LITEOS_A_COMPAT
static EpollSet *CloseDescEpollHandle(int32_t desc)
{
    return EpollSetFindByFd(desc);
}
#else
static EpollSet *CloseDescEpollHandle(int32_t desc)
{
    EpollSet *epollSetPtr = g_epollEventPtrArray[EVENT_PTR_IDX(desc)].epollSetPtr;
    g_epollEventPtrArray[EVENT_PTR_IDX(desc)].epollSetPtr = NULL;
    g_epollEventPtrArray[EVENT_PTR_IDX(desc)].taskPtr = NULL;
    return epollSetPtr;
}
#endif

void CloseDescClearEpollPtr(int32_t desc)
{
    EpollSet *epollSetPtr = NULL;
    if (IS_INVALID_SOCKET_DESC(desc)) {
        LOGE(TAG, "invalid socket : %d", desc);
        return;
    }
    if (g_epollInited != NSTACKX_TRUE) {
        LOGE(TAG, "Epoll Event Ptr Not Init");
        return;
    }

    if (pthread_mutex_lock(&g_epollEventPtrMutex) != 0) {
        LOGE(TAG, "pthread mutex lock error");
        return;
    }
    epollSetPtr = CloseDescEpollHandle(desc);
    if (pthread_mutex_unlock(&g_epollEventPtrMutex) != 0) {
        LOGE(TAG, "pthread mutex unlock error");
        return;
    }

    if (epollSetPtr == NULL) {
        return;
    }

    if (pthread_mutex_lock(&(epollSetPtr->mutex)) != 0) {
        LOGE(TAG, "pthread mutex lock error");
        return;
    }
    FD_CLR(desc, &epollSetPtr->readfds);
    FD_CLR(desc, &epollSetPtr->writefds);
    FD_CLR(desc, &epollSetPtr->exceptfds);
    if (desc == epollSetPtr->maxfd) {
        EpollSetMaxFdUpdate(epollSetPtr);
    }
    if (pthread_mutex_unlock(&(epollSetPtr->mutex)) != 0) {
        LOGE(TAG, "pthread mutex unlock error");
        return;
    }
}
