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

#ifndef FILLP_NET_H
#define FILLP_NET_H

#include "fillp_os.h"
#include "pcb.h"
#include "spunge_mem.h"
#include "fillp.h"
#include "sysio.h"
#ifdef __cplusplus
extern "C" {
#endif

enum FtConnState {
    CONN_STATE_IDLE = 0,       /* Alloced but not do connect */
    CONN_STATE_LISTENING = 1,  /* Listen socket */
    CONN_STATE_CONNECTING = 2, /* Do connecting, four handshake not finished yet */
    CONN_STATE_CONNECTED = 3,  /* netConn already connected */
    CONN_STATE_CLOSING = 4,    /* send disconn request out */
    CONN_STATE_CLOSED = 5,     /* connection already closed */
    CONN_STATE_BUTT = 0xff
};

struct SockOsSocket {
    /* osListNode is used to get the ft socket index based on address indexing
    so this must be first member of the structure. if need to be changed please
    handle SockOsListEntry first */
    struct HlistNode osListNode; /* This has to be the First member of the structure */
    SysIoSock *ioSock;
    FILLP_INT reference;
    FILLP_INT addrType;
};

#define OS_SOCK_OPS_FUNC_VALID(_osSock, _ops_func) \
    (((_osSock) != FILLP_NULL_PTR) && \
    ((_osSock)->ioSock != FILLP_NULL_PTR) && \
    ((_osSock)->ioSock->ops != FILLP_NULL_PTR) && \
    ((_osSock)->ioSock->ops->_ops_func != FILLP_NULL_PTR))

#ifndef UDP_MAX_SEG
#define UDP_MAX_SEG 44u
#endif

struct FtNetconn {
    struct SpungePcb *pcb;
    void *sock;
    struct SockOsSocket *osSocket[MAX_SPUNGEINSTANCE_NUM];

    FILLP_LLONG connTimeout;

    FILLP_UINT32 closeSet : 1;      /* Application calls close() function */
    FILLP_UINT32 shutdownRdSet : 1; /* Application called shutdown(sock, RD) */
    FILLP_UINT32 shutdownWrSet : 1; /* Application called shutdown(sock, WR) */
    FILLP_UINT32 peerRdSet : 1;     /* Peer notify that it won't read anything */
    FILLP_UINT32 peerWrSet : 1;     /* Peer notify that it won't send anything */
    FILLP_UINT32 sendBufRunOut : 1; /* Send buffer has run out */
    FILLP_UINT32 flagsReverse : 26;
    FILLP_UINT8 state;
    FILLP_UINT8 clientFourHandshakeState;
    FILLP_UINT8 peerFcAlgs; /* bit0: alg1, bit1: alg2 ... */
    FILLP_UINT8 padd[1];
    FILLP_UINT32 peerCharacters;
    FILLP_INT lastErr;
    FILLP_ULLONG calcRttDuringConnect;
    FILLP_UINT32 peerPktSize;
#ifdef FILLP_LINUX
    size_t iovCount;
    struct iovec sendIov[UDP_MAX_SEG];
#endif

#ifdef FILLP_MGT_MSG_LOG
    FILLP_BOOL extParameterExisted[FILLP_PKT_EXT_BUTT];
#endif
};

#define NETCONN_GET_OSSOCK(_conn, _instIdx) ((_conn)->osSocket[(_instIdx)])

FILLP_INT FillpErrToErrno(FILLP_INT err);
void FillpNetconnSetSafeErr(struct FtNetconn *conn, FILLP_INT err);

void FillpNetconnSetState(struct FtNetconn *conn, FILLP_UINT8 state);

#define NETCONN_GET_STATE(_conn) ((_conn)->state)

struct FtNetconn *FillpNetconnAlloc(FILLP_UINT16 domain, struct SpungeInstance *inst);

void NetconnSetSendCacheSize(struct FtNetconn *conn, FILLP_UINT32 cacheSize);
void NetconnSetRecvCacheSize(struct FtNetconn *conn, FILLP_UINT32 cacheSize);
void NetconnSetPktSize(struct FtNetconn *conn, FILLP_UINT32 pktSize);
void NetconnSetOpersiteRate(struct FtNetconn *conn, FILLP_UINT32 rate);
void NetconnSetSlowStart(struct FtNetconn *conn, FILLP_BOOL slowStart);
void NetconnSetPackInterval(struct FtNetconn *conn, FILLP_UINT32 interval);
void NetconnSetLocalPort(struct FtNetconn *conn, FILLP_INT port);
void NetconnSetAddrType(struct FtNetconn *conn, FILLP_UINT16 addrType);
void NetconnSetDirectlySend(struct FtNetconn *conn, FILLP_INT directlySend);
void NetconnSetConnectTimeout(struct FtNetconn *conn, FILLP_LLONG timeoutUs);

FILLP_BOOL NetconnIsConnectTimeout(struct FtNetconn *conn);

void NetconnSetSock(struct FtSocket *sock, struct FtNetconn *conn);
void FillpNetconnDestroy(struct FtNetconn *conn);

void FillpHandleConnConfirmAckInput(struct FtSocket *sock, struct FtNetconn *conn,
    struct FillpPcb *pcb, FILLP_CONST struct NetBuf *p);

void FillpInitNewconnBySock(struct FtNetconn *conn, FILLP_CONST struct FtSocket *sock);
void FillpConnConfirmInput(struct FillpPcb *pcb, FILLP_CONST struct NetBuf *p, struct SpungeInstance *inst);


#ifdef __cplusplus
}
#endif

#endif /* FILLP_NET_H */
