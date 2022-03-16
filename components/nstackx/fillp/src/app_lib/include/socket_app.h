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

#ifndef SOCKET_APP_H
#define SOCKET_APP_H

#include "fillpinc.h"
#include "sockets.h"
#include "socket_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IPV6_ADDR_IS_NULL(addr) \
    (((addr)->sin6_addr.s6_addr[0] == 0) && ((addr)->sin6_addr.s6_addr[1] == 0) && \
    ((addr)->sin6_addr.s6_addr[2] == 0) && ((addr)->sin6_addr.s6_addr[3] == 0) && \
    ((addr)->sin6_addr.s6_addr[4] == 0) && ((addr)->sin6_addr.s6_addr[5] == 0) && \
    ((addr)->sin6_addr.s6_addr[6] == 0) && ((addr)->sin6_addr.s6_addr[7] == 0) && \
    ((addr)->sin6_addr.s6_addr[8] == 0) && ((addr)->sin6_addr.s6_addr[9] == 0) && \
    ((addr)->sin6_addr.s6_addr[10] == 0) && ((addr)->sin6_addr.s6_addr[11] == 0) && \
    ((addr)->sin6_addr.s6_addr[12] == 0) && ((addr)->sin6_addr.s6_addr[13] == 0) && \
    ((addr)->sin6_addr.s6_addr[14] == 0) && ((addr)->sin6_addr.s6_addr[15] == 0))

FILLP_INT SockSocket(FILLP_INT domain, FILLP_INT type, FILLP_INT protocol);
FillpErrorType SockConnect(FILLP_INT sockIndex, FILLP_CONST struct sockaddr *name, socklen_t nameLen);
FILLP_ULLONG SockGetRtt(FILLP_INT sockFd);
FillpErrorType SockBind(FILLP_INT sockIndex, FILLP_CONST struct sockaddr *name, FILLP_UINT32 nameLen);
FILLP_INT SockRecv(FILLP_INT fd, void *mem, FILLP_SIZE_T len, FILLP_INT flags);
FILLP_INT SockSend(FILLP_INT sockIndex, FILLP_CONST void *data, FILLP_SIZE_T size, FILLP_INT flags);
FILLP_INT SockSendFrame(FILLP_INT sockIndex, FILLP_CONST void *data, FILLP_SIZE_T size, FILLP_INT flags,
    FILLP_CONST struct FrameInfo *frame);

FillpErrorType SockReadv(FILLP_INT sockIndex, const struct iovec *iov, FILLP_INT iovCount);
FillpErrorType SockWritev(FILLP_INT sockIndex, const struct iovec *iov, FILLP_INT iovCount);
FILLP_INT SockRecvmsg(FILLP_INT sockIndex, struct msghdr *msg, FILLP_INT flags);
FILLP_INT SockSendmsg(FILLP_INT sockIndex, struct msghdr *msg, FILLP_INT flags);
FillpErrorType SockListen(FILLP_INT sockIndex, FILLP_INT backLog);
FillpErrorType SockAccept(FILLP_INT fd, struct sockaddr *addr, socklen_t *addrLen);

FillpErrorType SockClose(FILLP_INT sockIndex);
FillpErrorType SockShutdown(FILLP_INT sockIndex, FILLP_INT how);


#ifdef FILLP_LINUX
FILLP_INT SockFcntl(FILLP_INT fd, FILLP_INT cmd, FILLP_INT val);
#endif

FILLP_INT SockIoctlsocket(FILLP_INT fd, FILLP_SLONG cmd, FILLP_CONST FILLP_INT *val);

FILLP_INT SockGetsockname(FILLP_INT sockIndex, struct sockaddr *name, socklen_t *nameLen);

FILLP_INT SockGetpeername(FILLP_INT sockIndex, struct sockaddr *name, socklen_t *nameLen);

FILLP_INT SockGetSockEvt(FILLP_INT fd);

#ifdef FILLP_WIN32
#ifndef MSGHDR_IOVEC_DEFINED
struct iovec {
    void *iov_base;
    size_t iov_len;
};

struct msghdr {
    void *msg_name;
    socklen_t msg_namelen;
    struct iovec *msg_iov;
    size_t msg_iovlen;
    void *msg_control;
    size_t msg_controllen;
    int msg_flags;
};

#define MSGHDR_IOVEC_DEFINED 1
#endif

#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0x40
#endif
#endif /* FILLP_WIN32 */

FILLP_INT SockEventInfoGet(int s, FtEventCbkInfo *info);

#define SOCK_DESTROY_CONN(lock, conn, sock, err) \
do { \
    (void)SYS_ARCH_RWSEM_RDPOST(lock); \
    FillpNetconnDestroy(conn); \
    FILLP_SOCK_SET_ERR(sock, err); \
    SET_ERRNO(err); \
} while (0)

#define SOCK_SENDMSG_DATA_MOD_LEN(iovIter, iovRemainLen, itemIter, itemRemainLen, sendLen, dataLen, cpylen) \
do { \
    (iovIter) += (cpylen); \
    (iovRemainLen) -= (cpylen); \
    (itemIter) += (cpylen); \
    (itemRemainLen) -= (cpylen); \
    (sendLen) += (FILLP_INT)(cpylen); \
    (dataLen) += (FILLP_UINT16)(cpylen); \
} while (0)

#define SOCK_SENDMSG_DATA_MOD_IOV(iovRemainLen, iovIter, msg, index) \
do { \
    if ((iovRemainLen) == 0) { \
        (iovIter) = (msg)->msg_iov[index].iov_base; \
        (iovRemainLen) = (FILLP_UINT32)(msg)->msg_iov[index].iov_len; \
        (index)++; \
    } \
} while (0)

#ifdef __cplusplus
}
#endif

#endif /* SOCKET_APP_H */
