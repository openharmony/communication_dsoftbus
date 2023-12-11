/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "epoll.h"
#include "spunge.h"
#include "spunge_app.h"
#include "socket_common.h"
#include "res.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Search the file inside the eventpoll hash. It add usage count to
 * the returned item, so the caller must call ep_release_epitem()
 * after finished using the "struct EpItem".
 */
static struct EpItem *EpFind(struct EventPoll *ep, FILLP_INT fd)
{
    struct RbNode *rbp = FILLP_NULL_PTR;
    struct EpItem *epi = FILLP_NULL_PTR;
    struct EpItem *ret = FILLP_NULL_PTR;

    FILLP_UINT loopLimit = g_spunge->resConf.maxEpollItemNum;

    for (rbp = ep->rbr.rbNode; rbp && loopLimit; loopLimit--) {
        epi = EpItemEntryRbNode(rbp);
        if (fd > epi->fileDespcriptor) {
            rbp = rbp->rbRight;
        } else if (fd < epi->fileDespcriptor) {
            rbp = rbp->rbLeft;
        } else {
            /* Find it */
            ret = epi;
            break;
        }
    }

    return ret;
}

/*
 * insert epitem to eventpoll->rbr
 */
static void EpRbtreeInsert(struct EventPoll *ep, struct EpItem *epi)
{
    struct RbNode **p = &ep->rbr.rbNode;
    struct RbNode *parent = FILLP_NULL_PTR;
    struct EpItem *epic = FILLP_NULL_PTR;
    FILLP_UINT loopLimit = g_spunge->resConf.maxEpollItemNum;

    while (*p && loopLimit--) {
        parent = *p;
        epic = EpItemEntryRbNode(parent);
        if (epi->fileDespcriptor > epic->fileDespcriptor) {
            p = &parent->rbRight;
        } else {
            p = &parent->rbLeft;
        }
    }

    epi->rbn.rbLeft = epi->rbn.rbRight = FILLP_NULL_PTR;
    epi->rbn.rbParent = parent;

    epi->rbn.color = RB_RED;

    *p = &epi->rbn;

    FillpRbInsertColor(&epi->rbn, &ep->rbr);
}

/*
 * Add epitem to sock->epoll_taskList
 * epi is application pointer
 */
static void EpollAddToSockWaitList(struct FtSocket *sock, struct EpItem *epi)
{
    if (SYS_ARCH_SEM_WAIT(&sock->epollTaskListLock)) {
        FILLP_LOGERR("Sem Wait fail");
        return;
    }
    HlistAddTail(&sock->epTaskList, &epi->sockWaitNode);
    (void)SYS_ARCH_SEM_POST(&sock->epollTaskListLock);
}

/* Check and triggle the event when do epoll ctl */
static void EpollCtlTriggleEvent(
    struct EventPoll *ep,
    struct FtSocket *sock,
    struct EpItem *epi)
{
    epi->revents = 0;
    if (SYS_ARCH_ATOMIC_READ(&sock->rcvEvent) > 0) {
        epi->revents |= SPUNGE_EPOLLIN;
    }

    if ((SYS_ARCH_ATOMIC_READ(&sock->sendEvent) != 0) && (SYS_ARCH_ATOMIC_READ(&sock->sendEventCount) > 0)) {
        epi->revents |= SPUNGE_EPOLLOUT;
    }

    epi->revents |= (FILLP_UINT32)sock->errEvent;
    epi->revents &= epi->event.events;

    if (epi->revents > 0) {
        EpSocketReady(ep, epi);
    }
}

static struct EpItem *EpollMallocEpitem(void)
{
    struct EpItem *epi = FILLP_NULL_PTR;
    FILLP_INT ret = DympAlloc(g_spunge->epitemPool, (void **)&epi, FILLP_FALSE);
    if ((ret != ERR_OK) || (epi == FILLP_NULL_PTR)) {
        FILLP_LOGERR("MP_MALLOC epoll failed.");
        return FILLP_NULL_PTR;
    }

    epi->rbn.rbParent = &(epi->rbn);
    epi->fileDespcriptor = -1;
    epi->ep = FILLP_NULL_PTR;
    epi->revents = FILLP_NULL_NUM;
    HLIST_INIT_NODE(&epi->rdlNode);
    HLIST_INIT_NODE(&epi->sockWaitNode);

    return epi;
}

/*
 * Modify the interest event mask by dropping an event if the new mask
 * has a match in the current file status.
 */
static FILLP_INT EpModify(
    struct EventPoll *ep,
    struct FtSocket *sock,
    struct EpItem *epi,
    FILLP_CONST struct SpungeEpollEvent *event)
{
    if (SYS_ARCH_SEM_WAIT(&ep->appCoreSem)) {
        FILLP_LOGERR("Sem wait fail");
        SET_ERRNO(FILLP_EBUSY);
        return ERR_COMM;
    }
    (void)memcpy_s(&epi->event, sizeof(struct SpungeEpollEvent), event, sizeof(struct SpungeEpollEvent));
    EpollCtlTriggleEvent(ep, sock, epi);
    (void)SYS_ARCH_SEM_POST(&ep->appCoreSem);
    return FILLP_OK;
}

/*
  Unlink the "struct EpItem" from all places it might have been hooked up.
  remove epitem from eventpoll->rbn

 Comment 1:
  It can happen that this one is called for an item already unlinked.
  The check protect us from doing a double unlink ( crash ).

 Comment 2:
  Clear the event mask for the unlinked item. This will avoid item
  notifications to be sent after the unlink operation from inside
  the kernel->userspace event transfer loop.

 Comment 3:
  At this point is safe to do the job, unlink the item from our rb-tree.
  This operation togheter with the above check closes the door to
  double unlinks.

 Comment 4:
  If the item we are going to remove is inside the ready file descriptors
  we want to remove it from this list to avoid stale events.
 */
static FILLP_INT EpUnlink(struct EventPoll *ep, struct EpItem *epi)
{
    /* Comment 1 */
    if (epi->rbn.rbParent == &(epi->rbn)) {
        FILLP_LOGERR("struct EpItem already unlinked.");
        SET_ERRNO(FILLP_EINVAL);
        return ERR_FAILURE;
    }

    /* Comment 2 */
    epi->event.events = 0;

    /* Comment 3 */
    FillpRbErase(&epi->rbn, &ep->rbr);

    /* Comment 4 */
    if (SYS_ARCH_SEM_WAIT(&ep->appCoreSem)) {
        FILLP_LOGERR("Sem Wait fail");
        SET_ERRNO(FILLP_EBUSY);
        return ERR_COMM;
    }

    epi->revents = FILLP_NULL_NUM;
    EpDelRdlnode(ep, epi);

    (void)SYS_ARCH_SEM_POST(&ep->appCoreSem);

    return FILLP_OK;
}

/*
 * Removes a "struct EpItem" from the eventpoll hash and deallocates
 * all the associated resources.
 * epi is application pointer
 */
static FILLP_INT EpRemove(struct EventPoll *ep, struct EpItem *epi)
{
    FILLP_INT error;
    FILLP_INT fd;
    struct FtSocket *sock = FILLP_NULL_PTR;
    struct HlistNode *node = FILLP_NULL_PTR;

    if ((ep == FILLP_NULL_PTR) || (epi == FILLP_NULL_PTR)) {
        FILLP_LOGERR("EpRemove: Inavild parameters passed.");
        SET_ERRNO(FILLP_EINVAL);
        return ERR_NULLPTR;
    }

    fd = epi->fileDespcriptor;

    /* For the given fd, already validation is present in upper function
       SpungeEpollCtl. So no need to validate again for ori_sock

       FtEpollCtl->SpungeEpollCtl->EpRemove/EpInsert
    */
    sock = SockGetSocket(fd);
    if ((sock == FILLP_NULL_PTR) || (sock->allocState == SOCK_ALLOC_STATE_EPOLL)) {
        FILLP_LOGERR("EpRemove: SockGetSocket failed.");
        SET_ERRNO(FILLP_EBADF);
        return ERR_COMM;
    }

    if (SYS_ARCH_SEM_WAIT(&(sock->epollTaskListLock))) {
        FILLP_LOGERR("sem wait fail");
        SET_ERRNO(FILLP_EBUSY);
        return ERR_COMM;
    }
    node = HLIST_FIRST(&sock->epTaskList);
    while (node != FILLP_NULL_PTR) {
        if (node == &epi->sockWaitNode) {
            HlistDelete(&sock->epTaskList, node);
            break;
        }
        node = node->next;
    }
    (void)SYS_ARCH_SEM_POST(&(sock->epollTaskListLock));

    /* Really unlink the item from the hash */
    error = EpUnlink(ep, epi);
    if (error != ERR_OK) {
        return error;
    }

    DympFree(epi);

    return FILLP_OK;
}

static FILLP_INT EpGetEventsAndSignal(
    struct EventPoll *ep,
    struct SpungeEpollEvent *events,
    FILLP_INT maxEvents,
    FILLP_SLONG timeout)
{
    FILLP_INT eventCount = 0;
    struct HlistNode *node = FILLP_NULL_PTR;
    struct EpItem *epi = FILLP_NULL_PTR;

    if (SYS_ARCH_SEM_WAIT(&ep->appSem)) {
        FILLP_LOGERR("app-sem wait fail");
        return ERR_COMM;
    }
    if (SYS_ARCH_SEM_WAIT(&ep->appCoreSem)) {
        FILLP_LOGERR("core-sem wait fail");
        (void)SYS_ARCH_SEM_POST(&ep->appSem);
        return ERR_COMM;
    }
    node = HLIST_FIRST(&ep->rdList);
    while ((node != FILLP_NULL_PTR) && (eventCount < maxEvents)) {
        epi = EpItemEntryRdlNode(node);
        node = node->next;

        epi->revents &= epi->event.events;
        EpollUpdateEpEvent(epi);

        if (epi->revents > 0) {
            events[eventCount].events = epi->revents;
            (void)memcpy_s(&events[eventCount].data, sizeof(events[eventCount].data), &epi->event.data,
                sizeof(epi->event.data));
            eventCount++;
        }

        /* Check if event is present or not, if present report to application otherwise remove */
        if ((epi->revents == 0) || (epi->event.events & SPUNGE_EPOLLET)) {
            EpDelRdlnode(ep, epi);
        }
    }

    if ((timeout != 0) && (eventCount == 0)) {
        /* caller will wait for signal in this case, so set set signal variable under appCoreSem sem */
        (void)SYS_ARCH_ATOMIC_SET(&ep->semSignalled, 0);
    }

    (void)SYS_ARCH_SEM_POST(&ep->appCoreSem);
    (void)SYS_ARCH_SEM_POST(&ep->appSem);
    if (eventCount > 0) {
        FILLP_LOGDBG("Get eventCount:%d", eventCount);
    }
    return eventCount;
}

static FILLP_INT EpPoll(
    struct FtSocket *sock,
    struct SpungeEpollEvent *events,
    FILLP_INT maxEvents,
    FILLP_SLONG timeout)
{
    FILLP_INT eventCount = 0;
    FILLP_INT semTimedWait;
    FILLP_LLONG begintime = 0;
    FILLP_LLONG endtime;
    FILLP_UCHAR isTakenBeginTs = 0;
    FILLP_BOOL needLoopNun = FILLP_TRUE;
    FILLP_SLONG timeoutBkp = timeout;
    FILLP_SLONG timeoutWork = timeout;
    struct EventPoll *ep = sock->eventEpoll;

    /*
    * We don't have any available event to return to the caller.
    * We need to sleep here, and we will be wake up by
    * ep_poll_callback() when events will become available.

      Here we do not acquire rdlock, there is diffciulty to handle this. If we
      lock it in the function, and pass the timeout as -1 then it will result in
      deadlock as the core thread will not get the lock and update the readylist.
      Also the FtEpollWait is running in another thread, the check here is
      performs only reading and validate for NULL, hence the wait lock is not
      acquired. Acquire lock here also might reduce performance
    */
    while (needLoopNun == FILLP_TRUE) {
        if (sock->allocState == SOCK_ALLOC_STATE_EPOLL_TO_CLOSE) {
            FILLP_LOGERR("epFd will be destroyed, so return");
            return 0;
        }

        eventCount = EpGetEventsAndSignal(ep, events, maxEvents, timeoutBkp);
        if (eventCount) {
            break;
        }
        if (timeoutBkp == -1) {
            EPOLL_CPU_PAUSE();
            if (SYS_ARCH_SEM_WAIT(&ep->waitSem)) {
                FILLP_LOGERR("ep_wait fail");
                return 0;
            }
        } else if (timeoutBkp == 0) {
            break;
        } else { /* timed wait */
            if (isTakenBeginTs == 0) {
                begintime = SYS_ARCH_GET_CUR_TIME_LONGLONG(); /* microseconds */
                isTakenBeginTs = 1;
            }

            semTimedWait = SYS_ARCH_SEM_WAIT_TIMEOUT(&ep->waitSem, timeoutWork);
            endtime = SYS_ARCH_GET_CUR_TIME_LONGLONG();
            /* timeoutBkp is in milliseconds and SYS_ARCH_GET_CUR_TIME_LONGLONG() is in microseconds */
            if ((FILLP_UTILS_US2MS(endtime - begintime)) >= timeoutBkp) {
                /* Try again if some event is posted or not, as currently we do not check why sem_wait has returned */
                eventCount = EpGetEventsAndSignal(ep, events, maxEvents, 0);
                (void)semTimedWait;

                break;
            }

            timeoutWork = (FILLP_SLONG)(timeoutBkp - (FILLP_UTILS_US2MS(endtime - begintime)));
            continue;
        }
    }

    return eventCount;
}

static struct EventPoll *EpollMallocEventpoll()
{
    struct EventPoll *ep = FILLP_NULL_PTR;
    FILLP_INT ret = DympAlloc(g_spunge->eventpollPool, (void **)&ep, FILLP_FALSE);
    if ((ret != ERR_OK) || (ep == FILLP_NULL_PTR)) {
        FILLP_LOGERR("EpollMallocEventpoll: MP_MALLOC failed. \r\n");
        SET_ERRNO(FILLP_ENOMEM);
        return FILLP_NULL_PTR;
    }

    ret = SYS_ARCH_SEM_INIT(&ep->appSem, 1);
    if (ret != FILLP_OK) {
        FILLP_LOGERR("EpollMallocEventpoll:socket create epoll semaphore failed. ");
        DympFree(ep);
        SET_ERRNO(FILLP_EFAULT);
        return FILLP_NULL_PTR;
    }

    ret = SYS_ARCH_SEM_INIT(&ep->waitSem, 0);
    if (ret != FILLP_OK) {
        (void)SYS_ARCH_SEM_DESTROY(&ep->appSem);
        DympFree(ep);
        SET_ERRNO(FILLP_EFAULT);
        return FILLP_NULL_PTR;
    }

    ep->rbr.rbNode = FILLP_NULL_PTR;
    HLIST_INIT(&ep->rdList);
    ret = SYS_ARCH_SEM_INIT(&ep->appCoreSem, 1);
    if (ret != FILLP_OK) {
        (void)SYS_ARCH_SEM_DESTROY(&ep->waitSem);
        (void)SYS_ARCH_SEM_DESTROY(&ep->appSem);
        DympFree(ep);
        SET_ERRNO(FILLP_EFAULT);
        return FILLP_NULL_PTR;
    }

    (void)SYS_ARCH_ATOMIC_SET(&ep->semSignalled, 0);
    return ep;
}

/*
 * Called by epoll_ctl with "add" op
 */
static FILLP_INT EpInsert(
    struct EventPoll *ep,
    FILLP_CONST struct SpungeEpollEvent *event,
    FILLP_INT fd)
{
    struct EpItem *epi = FILLP_NULL_PTR;

    /* If the file is already "ready" we drop it inside the ready list
       For the given fd, already validation is present in upper function
       SpungeEpollCtl. So no need to validate again for ori_sock
       FtEpollCtl->SpungeEpollCtl->EpRemove/EpInsert
    */
    struct FtSocket *sock = SockGetSocket(fd);
    if (sock == FILLP_NULL_PTR) {
        SET_ERRNO(FILLP_EBADF);
        FILLP_LOGERR("SockGetSocket returns NULL, fillp_sock_id:%d", fd);
        return ERR_NO_SOCK;
    }

    if (sock->allocState == SOCK_ALLOC_STATE_EPOLL) {
        FILLP_LOGERR("Epoll socket not supported, fillp_sock_id:%d", fd);
        SET_ERRNO(FILLP_EBADF);
        return ERR_NO_SOCK;
    }

    epi = EpollMallocEpitem();

    if (epi == FILLP_NULL_PTR) {
        FILLP_LOGERR("EpollMallocEpitem returns NULL.");
        SET_ERRNO(FILLP_ENOMEM);
        return ERR_NULLPTR;
    }

    epi->ep = ep;
    (void)memcpy_s(&epi->event, sizeof(struct SpungeEpollEvent), event, sizeof(struct SpungeEpollEvent));
    epi->fileDespcriptor = fd;

    EpRbtreeInsert(ep, epi);
    /* add to fd wait queue */
    EpollAddToSockWaitList(sock, epi);

    if (SYS_ARCH_SEM_WAIT(&ep->appCoreSem)) {
        FILLP_LOGERR("Fail to wait appCoreSem");
        SET_ERRNO(FILLP_EBUSY);
        return ERR_COMM;
    }
    EpollCtlTriggleEvent(ep, sock, epi);
    (void)SYS_ARCH_SEM_POST(&ep->appCoreSem);

    return FILLP_OK;
}

static struct FtSocket *SpungeGetEpollSocketByFd(FILLP_INT epFd)
{
    struct FtSocket *epollSock = SockGetSocket(epFd);
    if (epollSock == FILLP_NULL_PTR) {
        FILLP_LOGERR("SpungeEpollCtl: SockGetSocket failed.");
        SET_ERRNO(FILLP_EBADF);
        return FILLP_NULL_PTR;
    }

    if (SYS_ARCH_RWSEM_TRYRDWAIT(&epollSock->sockConnSem) != ERR_OK) {
        FILLP_LOGERR("Socket-%d state is changing,maybe closing ", epFd);
        SET_ERRNO(FILLP_EBUSY);
        return FILLP_NULL_PTR;
    }

    if (epollSock->allocState != SOCK_ALLOC_STATE_EPOLL) {
        (void)SYS_ARCH_RWSEM_RDPOST(&epollSock->sockConnSem);
        FILLP_LOGERR("SpungeEpollCtl: epoll socket state is incorrect for epoll sock Id=%d , state=%d",
            epFd, epollSock->allocState);
        SET_ERRNO(FILLP_ENOTSOCK);
        return FILLP_NULL_PTR;
    }

    if (epollSock->eventEpoll == FILLP_NULL_PTR) {
        (void)SYS_ARCH_RWSEM_RDPOST(&epollSock->sockConnSem);
        FILLP_LOGERR("SpungeEpollCtl: epollSock->eventEpoll is null. ");

        SET_ERRNO(FILLP_EINVAL);
        return FILLP_NULL_PTR;
    }

    return epollSock;
}

static FILLP_INT SpungeEpollCtlCheckSockValid(struct FtSocket *epollSock, struct FtSocket *sock, FILLP_INT fd)
{
    if (SYS_ARCH_RWSEM_TRYRDWAIT(&sock->sockConnSem) != ERR_OK) {
        (void)SYS_ARCH_RWSEM_RDPOST(&epollSock->sockConnSem);
        FILLP_LOGERR("Socket-%d state is changing,maybe closing ", fd);
        SET_ERRNO(FILLP_EBUSY);
        return -1;
    }

    if ((sock->allocState != SOCK_ALLOC_STATE_COMM) && (sock->allocState != SOCK_ALLOC_STATE_WAIT_TO_CLOSE)) {
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        (void)SYS_ARCH_RWSEM_RDPOST(&epollSock->sockConnSem);
        FILLP_LOGERR("SpungeEpollCtl: socket stat is wrong ");
        if (sock->allocState == SOCK_ALLOC_STATE_EPOLL) {
            SET_ERRNO(FILLP_EINVAL);
        } else {
            SET_ERRNO(FILLP_EBADF);
        }

        return -1;
    }

    if (SYS_ARCH_SEM_WAIT(&epollSock->eventEpoll->appSem)) {
        FILLP_LOGERR("sem-wait fail");
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        (void)SYS_ARCH_RWSEM_RDPOST(&epollSock->sockConnSem);
        SET_ERRNO(FILLP_EBUSY);
        return -1;
    }

    return ERR_OK;
}

static FILLP_INT SpungeEpollCtlHandleAddEvent(
    struct FtSocket *epollSock,
    struct FtSocket *sock,
    FILLP_INT epFd,
    FILLP_CONST struct EpItem *epi,
    FILLP_CONST struct SpungeEpollEvent *event)
{
    FILLP_INT error = 0;
    struct SpungeEpollEvent epds;

    if (epi != FILLP_NULL_PTR) {
        SET_ERRNO(FILLP_EEXIST);
        return -1;
    }

    /* It means, that A ft-socket can be registered up to 10 epoll instances, not
          more than that. This value is compile config controlled.
    */
    if (sock->associatedEpollInstanceIdx >= FILLP_NUM_OF_EPOLL_INSTANCE_SUPPORTED) {
        FILLP_LOGERR("already added too much socket, sock->associatedEpollInstanceIdx:%u",
            sock->associatedEpollInstanceIdx);
        SET_ERRNO(FILLP_ENOMEM);
        return -1;
    }

    (void)memset_s(&epds, sizeof(struct SpungeEpollEvent), 0, sizeof(struct SpungeEpollEvent));
    (void)memcpy_s(&epds, sizeof(struct SpungeEpollEvent), event, sizeof(struct SpungeEpollEvent));
    epds.events |= ((FILLP_UINT32)SPUNGE_EPOLLERR | (FILLP_UINT32)SPUNGE_EPOLLHUP);

    error = EpInsert(epollSock->eventEpoll, &epds, sock->index);
    if (error != ERR_OK) {
        return -1;
    }
    (void)SYS_ARCH_ATOMIC_INC(&sock->epollWaiting, 1);

    if (SYS_ARCH_SEM_WAIT(&sock->epollTaskListLock)) {
        FILLP_LOGERR("tasklock fail");
        SET_ERRNO(FILLP_EBUSY);
        return -1;
    }
    sock->associatedEpollInstanceArr[sock->associatedEpollInstanceIdx++] = epFd;
    (void)SYS_ARCH_SEM_POST(&sock->epollTaskListLock);

    return ERR_OK;
}

static FILLP_INT SpungeEpollCtlHandleDelEvent(
    struct FtSocket *epollSock,
    struct FtSocket *sock,
    FILLP_INT epFd,
    struct EpItem *epi)
{
    FILLP_INT error;

    if (epi == FILLP_NULL_PTR) {
        SET_ERRNO(FILLP_ENOENT);
        return -1;
    }

    error = EpRemove(epollSock->eventEpoll, epi);
    if (error != ERR_OK) {
        return -1;
    }
    (void)SYS_ARCH_ATOMIC_DEC(&sock->epollWaiting, 1);

    if (SYS_ARCH_SEM_WAIT(&sock->epollTaskListLock)) {
        FILLP_LOGERR("Wait epoll tasklist fail");
        SET_ERRNO(FILLP_EBUSY);
        return -1;
    }
    SpungeDelEpInstFromFtSocket(sock, epFd);
    (void)SYS_ARCH_SEM_POST(&sock->epollTaskListLock);

    return ERR_OK;
}

static FILLP_INT SpungeEpollCtlHandleModEvent(
    struct FtSocket *epollSock,
    struct FtSocket *sock,
    struct EpItem *epi,
    FILLP_CONST struct SpungeEpollEvent *event)
{
    struct SpungeEpollEvent epds;
    FILLP_INT error;

    if (epi == FILLP_NULL_PTR) {
        SET_ERRNO(FILLP_ENOENT);
        return -1;
    }

    (void)memset_s(&epds, sizeof(struct SpungeEpollEvent), 0, sizeof(struct SpungeEpollEvent));
    (void)memcpy_s(&epds, sizeof(struct SpungeEpollEvent), event, sizeof(struct SpungeEpollEvent));
    epds.events |= ((FILLP_UINT32)SPUNGE_EPOLLERR | (FILLP_UINT32)SPUNGE_EPOLLHUP);
    error = EpModify(epollSock->eventEpoll, sock, epi, &epds);
    if (error != ERR_OK) {
        return -1;
    }

    return ERR_OK;
}

static FILLP_INT SpungeEpollCtlParaChk(FILLP_INT epFd, FILLP_INT op, FILLP_INT fd,
    FILLP_CONST struct SpungeEpollEvent *event)
{
    /* For SPUNGE_EPOLL_CTL_DEL: Old kernels do not check the 'event' NULL case */
    if (((op == SPUNGE_EPOLL_CTL_ADD) || (op == SPUNGE_EPOLL_CTL_MOD)) && (event == FILLP_NULL_PTR)) {
        FILLP_LOGERR("SpungeEpollCtl: 'event' param is NULL");
        SET_ERRNO(FILLP_EFAULT);
        return -1;
    }

    if (event != FILLP_NULL_PTR) {
        FILLP_LOGINF("epFd:%d,op:%d,fillp_sock_id:%d,event->events:%x,event->u64:%llx",
            epFd, op, fd, event->events, event->data.u64);
        FILLP_LOGINF("sizeof(event):%zu, sizeof(evnent->events):%zu, sizeof(data):%zu",
            sizeof(*event), sizeof(event->events), sizeof(event->data));
    } else {
        FILLP_LOGWAR("epFd:%d,op:%d,fillp_sock_id:%d,event null", epFd, op, fd);
    }
    return 0;
}

FILLP_INT SpungeEpollCtl(FILLP_INT epFd, FILLP_INT op, FILLP_INT fd, FILLP_CONST struct SpungeEpollEvent *event)
{
    struct FtSocket *epollSock = FILLP_NULL_PTR;
    struct FtSocket *sock = FILLP_NULL_PTR;
    struct EpItem *epi = FILLP_NULL_PTR;
    FILLP_INT error;

    if (SpungeEpollCtlParaChk(epFd, op, fd, event) != 0) {
        return -1;
    }

    /* Get the epoll instance socket ID */
    epollSock = SpungeGetEpollSocketByFd(epFd);
    if (epollSock == FILLP_NULL_PTR) {
        return -1;
    }

    sock = SockGetSocket(fd);
    if (sock == FILLP_NULL_PTR) {
        (void)SYS_ARCH_RWSEM_RDPOST(&epollSock->sockConnSem);
        FILLP_LOGERR("SpungeEpollCtl: SockGetSocket failed.");
        SET_ERRNO(FILLP_EBADF);
        return -1;
    }

    error = SpungeEpollCtlCheckSockValid(epollSock, sock, fd);
    if (error != ERR_OK) {
        return -1;
    }

    epi = EpFind(epollSock->eventEpoll, fd);

    switch (op) {
        case SPUNGE_EPOLL_CTL_ADD:
            error = SpungeEpollCtlHandleAddEvent(epollSock, sock, epFd, epi, event);
            break;
        case SPUNGE_EPOLL_CTL_DEL:
            error = SpungeEpollCtlHandleDelEvent(epollSock, sock, epFd, epi);
            break;
        case SPUNGE_EPOLL_CTL_MOD:
            error = SpungeEpollCtlHandleModEvent(epollSock, sock, epi, event);
            break;
        default:
            SET_ERRNO(FILLP_EINVAL);
            error = -1;
            break;
    }

    (void)SYS_ARCH_SEM_POST(&epollSock->eventEpoll->appSem);
    (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
    (void)SYS_ARCH_RWSEM_RDPOST(&epollSock->sockConnSem);
    FILLP_LOGDBG("return value:%d", error);
    return error;
}

FILLP_INT SpungeEpollFindRemove(FILLP_INT epFd, FILLP_INT fd)
{
    struct FtSocket *sock = FILLP_NULL_PTR;
    struct EpItem *epi = FILLP_NULL_PTR;

    /* Get the epoll instance socket ID */
    struct FtSocket *epollSock = SockGetSocket(epFd);
    if (epollSock == FILLP_NULL_PTR) {
        FILLP_LOGERR("SpungeEpollFindRemove: SockGetSocket failed.");
        SET_ERRNO(FILLP_EBADF);
        return ERR_PARAM;
    }

    if (SYS_ARCH_RWSEM_TRYRDWAIT(&epollSock->sockConnSem) != ERR_OK) {
        FILLP_LOGERR("SpungeEpollFindRemove: Socket-%d state is changing,maybe closing", epFd);
        SET_ERRNO(FILLP_EBUSY);
        return ERR_COMM;
    }

    if (epollSock->allocState != SOCK_ALLOC_STATE_EPOLL) {
        (void)SYS_ARCH_RWSEM_RDPOST(&epollSock->sockConnSem);
        FILLP_LOGWAR("SpungeEpollFindRemove: epoll socket state is incorrect for epoll sock Id=%d , state=%d\r\n",
            epFd, epollSock->allocState);
        return ERR_PARAM;
    }

    if (epollSock->eventEpoll == FILLP_NULL_PTR) {
        (void)SYS_ARCH_RWSEM_RDPOST(&epollSock->sockConnSem);
        FILLP_LOGERR("SpungeEpollFindRemove: epollSock->eventEpoll is null.");
        return ERR_NULLPTR;
    }

    sock = SockGetSocket(fd);
    if (sock == FILLP_NULL_PTR) {
        (void)SYS_ARCH_RWSEM_RDPOST(&epollSock->sockConnSem);
        FILLP_LOGERR("SpungeEpollFindRemove: SockGetSocket failed.");
        SET_ERRNO(FILLP_EBADF);
        return ERR_PARAM;
    }

    if (SYS_ARCH_SEM_WAIT(&epollSock->eventEpoll->appSem)) {
        FILLP_LOGERR("Error to wait appSem");
        (void)SYS_ARCH_RWSEM_RDPOST(&epollSock->sockConnSem);
        return ERR_COMM;
    }

    epi = EpFind(epollSock->eventEpoll, fd);
    if (epi != FILLP_NULL_PTR) {
        (void)EpRemove(epollSock->eventEpoll, epi);
        (void)SYS_ARCH_ATOMIC_DEC(&sock->epollWaiting, 1);
        SpungeDelEpInstFromFtSocket(sock, epFd);
    }

    (void)SYS_ARCH_SEM_POST(&epollSock->eventEpoll->appSem);
    (void)SYS_ARCH_RWSEM_RDPOST(&epollSock->sockConnSem);
    return ERR_OK;
}

FILLP_INT SpungeEpollWait(FILLP_INT epFd, struct SpungeEpollEvent *events, FILLP_INT maxEvents, FILLP_INT timeout)
{
    FILLP_INT num;
    struct FtSocket *sock;
    FILLP_INT ret;
    sock = SockGetSocket(epFd);
    if (sock == FILLP_NULL_PTR) {
        FILLP_LOGERR("SpungeEpollWait: SockGetSocket failed. ");
        SET_ERRNO(FILLP_EBADF);
        return -1;
    }

    ret = SYS_ARCH_RWSEM_TRYRDWAIT(&sock->sockConnSem);
    if (ret != ERR_OK) {
        FILLP_LOGERR("Socket-%d state is changing,maybe closing", epFd);
        SET_ERRNO(FILLP_EBUSY);
        return -1;
    }

    if ((sock->allocState != SOCK_ALLOC_STATE_EPOLL) || (sock->eventEpoll == FILLP_NULL_PTR)) {
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        FILLP_LOGERR("SpungeEpollWait: allocState is not epoll or eventEpoll is NULL. ");

        SET_ERRNO(FILLP_ENOTSOCK);
        return -1;
    }

    /* The maximum number of event must be greater than zero */
    if ((maxEvents <= 0) || (events == FILLP_NULL_PTR)) {
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        FILLP_LOGERR("SpungeEpollWait: The maximum number of event must be greater than zero. ");
        SET_ERRNO(FILLP_EINVAL);
        return -1;
    }

    num = EpPoll(sock, events, maxEvents, timeout);

    (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
    return num;
}

FILLP_INT SpungeEpollCreate(void)
{
    struct FtSocket *sock = SpungeAllocSock(SOCK_ALLOC_STATE_EPOLL);
    struct EventPoll *ep = FILLP_NULL_PTR;

    FILLP_LOGINF("create epoll");

    if (sock == FILLP_NULL_PTR) {
        FILLP_LOGERR("SpungeEpollCreate: alloc sock failed.");
        SET_ERRNO(FILLP_ENOMEM);
        return -1;
    }

    ep = EpollMallocEventpoll();
    if (ep == FILLP_NULL_PTR) {
        FILLP_LOGINF("Fail to alloc ep");
        sock->allocState = SOCK_ALLOC_STATE_FREE;
        SockFreeSocket(sock);
        return -1;
    }

    sock->eventEpoll = ep;
    sock->isListenSock = FILLP_FALSE;
    sock->isSockBind = FILLP_FALSE;

    (void)SYS_ARCH_ATOMIC_SET(&sock->rcvEvent, 0);
    (void)SYS_ARCH_ATOMIC_SET(&sock->sendEvent, 0);
    sock->errEvent = 0;

    (void)SYS_ARCH_ATOMIC_SET(&sock->epollWaiting, 0);
    HLIST_INIT(&sock->epTaskList);

    FILLP_LOGINF("create epoll return, epFd:%d", sock->index);
    return sock->index;
}

#ifdef __cplusplus
}
#endif
