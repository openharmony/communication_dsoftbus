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

#include "spunge.h"

#include "socket_common.h"


#ifdef __cplusplus
extern "C" {
#endif

/*
Description: g_spunge hold the infos related to send and recv data, Memory
resources, epoll resources and instance resources.
Value Range: None
Access:g_spunge hold the infos related to send and recv data, Memory
resources, epoll resources and instance resources.
Remarks:
*/
struct Spunge *g_spunge = FILLP_NULL_PTR;

void SpungeEpollAppRecvOne(struct FtSocket *sock)
{
    (void)SYS_ARCH_ATOMIC_DEC(&sock->rcvEvent, 1);
}

void SpungeEpollEventCallback(struct FtSocket *sock, FILLP_INT event, FILLP_INT count)
{
    if (sock == FILLP_NULL_PTR) {
        FILLP_LOGERR("invalid input params");
        return;
    }

    if ((FILLP_UINT32)event & SPUNGE_EPOLLIN) {
        (void)SYS_ARCH_ATOMIC_INC(&sock->rcvEvent, count);
    }

    if (((FILLP_UINT32)event & SPUNGE_EPOLLOUT) && (count > 0)) {
        (void)SYS_ARCH_ATOMIC_SET(&sock->sendEvent, 1);
    }

    sock->errEvent |= ((FILLP_UINT32)event & (SPUNGE_EPOLLRDHUP | SPUNGE_EPOLLHUP | SPUNGE_EPOLLERR));

    if ((sock->netconn != FILLP_NULL_PTR) && (!sock->netconn->closeSet)) {
        if (SYS_ARCH_ATOMIC_READ(&sock->epollWaiting) > 0) {
            EpollEventCallback(sock, (FILLP_UINT32)event);
        }
    }
}

void SockSetOsSocket(struct FtSocket *ftSock, struct SockOsSocket *osSock)
{
    ftSock->netconn->osSocket[SPUNGE_GET_CUR_INSTANCE()->instIndex] = osSock;
    osSock->reference++;
}

#ifdef __cplusplus
}
#endif
