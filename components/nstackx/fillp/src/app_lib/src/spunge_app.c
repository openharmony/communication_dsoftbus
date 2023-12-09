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

#include "spunge_app.h"
#include "spunge.h"
#include "socket_common.h"

#ifdef __cplusplus
extern "C" {
#endif

static FILLP_INT SpungeInitSocket(struct FtSocket *sock)
{
    FILLP_INT i;
    sock->netconn = FILLP_NULL_PTR;
    (void)memset_s(sock->coreErrType, sizeof(sock->coreErrType), 0, sizeof(sock->coreErrType));

    sock->listenBacklog = 0;
    sock->acceptBox = FILLP_NULL_PTR;
    sock->listenNode.next = FILLP_NULL_PTR;
    sock->listenNode.pprev = FILLP_NULL_PTR;

    sock->recvPktBuf = FILLP_NULL_PTR;
    sock->inst = &g_spunge->instPool[0]; /* Alloc should be always in the first instance */
    sock->traceHandle = FILLP_NULL_PTR;

    (void)SYS_ARCH_ATOMIC_SET(&sock->rcvEvent, 0);
    (void)SYS_ARCH_ATOMIC_SET(&sock->epollWaiting, 0);

    /* If socket added to epoll without connect, should report out|err|hup */
    (void)SYS_ARCH_ATOMIC_SET(&sock->sendEvent, 1);
    (void)SYS_ARCH_ATOMIC_SET(&sock->sendEventCount, 1);
    sock->errEvent = SPUNGE_EPOLLHUP;

    sock->eventEpoll = FILLP_NULL_PTR;

    sock->associatedEpollInstanceIdx = 0;
    HLIST_INIT(&sock->epTaskList);
    /* Scan the epoll instance list to which this ft_socket is associated with */
    for (i = 0; i < FILLP_NUM_OF_EPOLL_INSTANCE_SUPPORTED; i++) {
        sock->associatedEpollInstanceArr[i] = FILLP_INVALID_INT;
    }

    sock->offset = 0;

    sock->dataOptionFlag = 0;
    if (g_appResource.common.enableDateOptTimestamp) {
        (void)SockUpdatePktDataOpt(sock, (FILLP_UINT16)FILLP_OPT_FLAG_TIMESTAMP, 0);
    }
    sock->transmit = 0;
    sock->jitter = 0;
    sock->sockAddrType = AF_INET;
    sock->flags = 0;

    sock->isListenSock = FILLP_FALSE;
    sock->traceFlag = FILLP_FALSE;
    sock->isSockBind = FILLP_FALSE;
    SockSetNonblocking(sock, FILLP_FALSE);
    sock->freeTimeCount = FILLP_NULL_NUM;
    (void)memcpy_s(&sock->resConf, sizeof(struct GlobalAppResource), &g_appResource, sizeof(struct GlobalAppResource));
    (void)memset_s(&sock->fillpLinger, sizeof(sock->fillpLinger), 0, sizeof(sock->fillpLinger));
    sock->directlySend = 0;

    /* post here, so that now sock close can acquire lock */
    if (SYS_ARCH_SEM_POST(&sock->sockCloseProtect) != ERR_OK) {
        return ERR_FAILURE;
    }

    return ERR_OK;
}

struct FtSocket *SpungeAllocSock(FILLP_INT allocType)
{
    struct FtSocket *sock = FILLP_NULL_PTR;

    if ((g_spunge == FILLP_NULL_PTR) || (!g_spunge->hasInited) || (g_spunge->sockTable == FILLP_NULL_PTR)) {
        FILLP_LOGERR("FILLP Not yet Initialized");
        return FILLP_NULL_PTR;
    }

    if (allocType != SOCK_ALLOC_STATE_COMM && allocType != SOCK_ALLOC_STATE_EPOLL) {
        FILLP_LOGERR("Wrong Socket Alloc Type");
        return FILLP_NULL_PTR;
    }

    sock = SockAllocSocket();
    if (sock == FILLP_NULL_PTR) {
        FILLP_LOGERR("sockets not available from the sockTable->freeQueqe");
        return FILLP_NULL_PTR;
    }

    if (SpungeInitSocket(sock) != ERR_OK) {
        SockFreeSocket(sock);
        return FILLP_NULL_PTR;
    }

    sock->allocState = allocType;

    return sock;
}

void SpungeDelEpInstFromFtSocket(struct FtSocket *sock, FILLP_INT epFd)
{
    FILLP_INT i;
    FILLP_INT j;
    FILLP_INT next;

    for (i = 0; i < FILLP_NUM_OF_EPOLL_INSTANCE_SUPPORTED; i++) {
        if (sock->associatedEpollInstanceArr[i] == epFd) {
            break;
        }
    }

    for (j = i; j < FILLP_NUM_OF_EPOLL_INSTANCE_SUPPORTED; j++) {
        if (j == (FILLP_NUM_OF_EPOLL_INSTANCE_SUPPORTED - 1)) {
            sock->associatedEpollInstanceArr[j] = FILLP_INVALID_INT;
            break;
        }
        next = j + 1;
        sock->associatedEpollInstanceArr[j] = sock->associatedEpollInstanceArr[next];
    }

    if (sock->associatedEpollInstanceIdx > 0) {
        sock->associatedEpollInstanceIdx--;
    }
}

#ifdef __cplusplus
}
#endif
