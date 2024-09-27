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

#ifndef FILLP_SOCKETS_H
#define FILLP_SOCKETS_H
#include "opt.h"
#include "queue.h"
#include "epoll.h"
#include "hlist.h"
#include "net.h"

#ifdef FILLP_LINUX
#include <errno.h>
#elif defined(FILLP_WIN32)
#include <Winsock2.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum SockAllockState {
    SOCK_ALLOC_STATE_FREE,
    SOCK_ALLOC_STATE_ERR,

    SOCK_ALLOC_STATE_WAIT_TO_CLOSE, /* app has called SockClose */
    SOCK_ALLOC_STATE_COMM,
    SOCK_ALLOC_STATE_EPOLL,
    SOCK_ALLOC_STATE_EPOLL_TO_CLOSE
};

struct GlobalAppUdpRes {
    FILLP_UINT32 txBurst; /* max pkt number to send each cycle */
#ifdef FILLP_64BIT_ALIGN
    FILLP_UINT32 reserve;
#endif
};

struct GlobalAppCommon {
    FILLP_UINT32 keepAliveTime; /* ms */
    FILLP_UINT32 maxServerAllowSendCache;
    FILLP_UINT32 maxServerAllowRecvCache;
    FILLP_UINT32 udpSendBufSize;
    FILLP_UINT32 recvBufSize;
    FILLP_UINT32 disconnectRetryTimeout; /* Testability addition in the code it is 100. */
    FILLP_UINT32 sendCache;              /* size of send cache */
    FILLP_UINT32 recvCache;              /* size of recv cache  */
    FILLP_UINT32 connectTimeout;         /* seconds */
    FILLP_UINT16 reserve;                /* Now not used, need to remove it */
    FILLP_UINT16 connRetryTimeout;       /* Testability addition in the code it is 10. */
    FILLP_BOOL enableNackDelay;
    FILLP_BOOL enlargePackIntervalFlag;
    FILLP_BOOL enableDateOptTimestamp;
    FILLP_UCHAR pad[3];
    FILLP_LLONG nackDelayTimeout;
    FILLP_UINT32 fcStasticsInterval;
};

struct GlobalAppFlowControl {
    FILLP_UINT32 maxRate; /* maximum data sending rate */
    FILLP_UINT32 maxRecvRate;
    FILLP_UINT32 oppositeSetRate; /* Only for Server */
    FILLP_UINT32 packInterval;    /* us */
    FILLP_UINT16 pktSize;         /* default pkt size to cal flow rate */
    FILLP_BOOL slowStart;
    FILLP_BOOL constRateEnbale;
    FILLP_UCHAR reserve[4];
};

struct GlobalAppResource {
    struct GlobalAppUdpRes udp;
    struct GlobalAppCommon common;
    struct GlobalAppFlowControl flowControl;
};

#define MAX_SPUNGE_TYPE_NUM 24 /* Check with SpungeMsgType it shopuld be more than max elements in this enum */

struct FtSocket {
    FILLP_INT index;      /* index of table */
    FILLP_INT allocState; /* socket has been allocState */
    struct FtNetconn *netconn;
    /* These following members are used for connection and referenced by FtNetconn */
    FILLP_INT coreErrType[MAX_SPUNGE_TYPE_NUM];

    void *recvPktBuf;
    struct SpungeInstance *inst;
    void *traceHandle; /* Handle provided by FillpTrace callback */

    struct HlistNode listenNode;
    SYS_ARCH_SEM acceptSem;
    FillpQueue *acceptBox;
    FILLP_INT listenBacklog;

    FILLP_UINT32 errEvent;
    struct EventPoll *eventEpoll;
    SysArchAtomic rcvEvent;
    SysArchAtomic sendEvent;
    SysArchAtomic sendEventCount;
    SysArchAtomic epollWaiting;

    struct Hlist epTaskList;
    SYS_ARCH_SEM epollTaskListLock;

    /* It means, that A ft-socket can be registered up to 10 epoll instances, not
       more than that. This value is compile config controlled, App can
       increase the number if expects more epoll instances for its user application
    */
    FILLP_INT associatedEpollInstanceArr[FILLP_NUM_OF_EPOLL_INSTANCE_SUPPORTED];
    FILLP_UINT32 associatedEpollInstanceIdx;

    FILLP_UINT32 offset;
    FILLP_UINT16 dataOptionFlag;
    FILLP_UINT16 dataOptionSize;
    FILLP_LLONG jitter;
    FILLP_LLONG transmit;

    FILLP_UINT16 flags;
    FILLP_UINT16 sockAddrType;
    FILLP_INT socketType;     // get from SockSocket
    FILLP_INT socketProtocol; // get from SockSocket

    FILLP_BOOL isListenSock;
    FILLP_BOOL isSockBind;
    FILLP_BOOL lingering;
    FILLP_UINT8 traceFlag; /* Flag for enable indication User/Network */
    FILLP_INT freeTimeCount;
    FILLP_INT err;

    SYS_ARCH_SEM connBlockSem;     /* Used when do connect */
    SYS_ARCH_RW_SEM sockConnSem;   /* Used to protect socket resource not freed */
    SYS_ARCH_SEM sockCloseProtect; /* To make sure that only one close message posted to fillp thread */
    struct GlobalAppResource resConf; /* Total size is 15 * sizeof uint32 */
    struct linger fillpLinger;
    FILLP_INT directlySend; /* directly send packet in the app thread instead of in the main thread */
};

#define FILLP_SOCK_SET_ERR(sk, e) ((sk)->err = (e))

static __inline struct FtSocket *SockEntryListenSocket(struct HlistNode *node)
{
    return (struct FtSocket *)((char *)(node) - (uintptr_t)(&(((struct FtSocket *)0)->listenNode)));
}

#define SOCK_GET_SENDPKTPOOL(_sock) ((_sock)->netconn->pcb->fpcb.send.itemPool)
#define SOCK_GET_SENDBOX(_sock) ((_sock)->netconn->pcb->fpcb.send.unsendBox)
#define SOCK_GET_RECVBOX(_sock) ((_sock)->netconn->pcb->fpcb.recv.recvBox)
#define SOCK_GET_PKTSIZE(_sock) ((_sock)->netconn->pcb->fpcb.pktSize)

#define SOCK_CONN_TRY_RDLOCK(_sock) SYS_ARCH_RWSEM_TRYRDWAIT(&(_sock)->sockConnSem)
#define SOCK_CONN_UNLOCK_RD(_sock) SYS_ARCH_RWSEM_RDPOST(&(_sock)->sockConnSem)

#define SOCK_CONN_TRY_LOCK_CLOSE(_sock) SYS_ARCH_SEM_TRYWAIT(&(_sock)->sockCloseProtect)
#define SOCK_CONN_UNLOCK_CLOSE(_sock) SYS_ARCH_SEM_POST(&(_sock)->sockCloseProtect)

#define SOCK_GET_SENDSEM(_sock) ((_sock)->netconn->pcb->fpcb.send.sendSem)
#define SOCK_GET_RECVSEM(_sock) ((_sock)->netconn->pcb->fpcb.recv.recvSem)

#define SOCK_WAIT_SENDSEM(_sock) SYS_ARCH_SEM_WAIT(&SOCK_GET_SENDSEM(_sock))
#define SOCK_POST_SENDSEM(_sock) SYS_ARCH_SEM_POST(&SOCK_GET_SENDSEM(_sock))
#define SOCK_TRYWAIT_SENDSEM(_sock) SYS_ARCH_SEM_TRYWAIT(&SOCK_GET_SENDSEM(_sock))

#define SOCK_WAIT_RECVSEM(_sock) SYS_ARCH_SEM_WAIT(&SOCK_GET_RECVSEM(_sock))
#define SOCK_POST_RECVSEM(_sock) SYS_ARCH_SEM_POST(&SOCK_GET_RECVSEM(_sock))
#define SOCK_TRYWAIT_RECVSEM(_sock) SYS_ARCH_SEM_TRYWAIT(&SOCK_GET_RECVSEM(_sock))

#ifdef FILLP_LINUX
#if defined(FILLP_LW_LITEOS)
#define SOCK_SEND_CPU_PAUSE() FILLP_SLEEP_MS(10)
#else
#define SOCK_SEND_CPU_PAUSE() (void)FILLP_USLEEP(FILLP_CPU_PAUSE_TIME)
#endif
#else
#define SOCK_SEND_CPU_PAUSE() FILLP_SLEEP_MS(1)
#endif

#if defined(FILLP_LW_LITEOS)
#define SOCK_RECV_CPU_PAUSE() FILLP_SLEEP_MS(10)
#else
#define SOCK_RECV_CPU_PAUSE() FILLP_SLEEP_MS(1)
#endif

#ifdef FILLP_LINUX
#define EPOLL_CPU_PAUSE() (void)FILLP_USLEEP(FILLP_CPU_PAUSE_TIME)
#else
#define EPOLL_CPU_PAUSE() FILLP_SLEEP_MS(1)
#endif

struct FtSocketTable {
    FillpQueue *freeQueqe;
    struct FtSocket **sockPool;
    FILLP_INT size;
    SysArchAtomic used;
};

#ifdef FILLP_LINUX
#define SET_ERRNO(_errno) (errno = (_errno))
#elif defined(FILLP_WIN32)
#define SET_ERRNO(_errno) WSASetLastError(_errno)
#endif

#ifdef FILLP_LINUX
#define FT_OS_GET_ERRNO errno
#elif defined(FILLP_WIN32)
#define FT_OS_GET_ERRNO WSAGetLastError()
#endif

/* Should this netconn avoid blocking? */
#define SOCK_FLAG_NON_BLOCKING 0x0001

/* Get the blocking status of netconn calls (@todo: write/send is missing) */
#define SOCK_IS_NONBLOCKING(sock) (((sock)->flags & SOCK_FLAG_NON_BLOCKING) != 0)
#define SOCK_IS_BLOCKING(sock) (((sock)->flags & SOCK_FLAG_NON_BLOCKING) == 0)

/* Set the blocking status of FtSocket

    The flag (which contains the socket options is in FtSocket and NOT in netconn CB)
    is in FtSocket structure, this is because: Application can set the socket to
    nonblock just after calling FtSocket (before ft_connet/FtAccept), but the
    netconn CB will be available only during FtConnect/FtAccept.
*/
void SockSetNonblocking(struct FtSocket *sock, FILLP_INT val);

struct NackDelayCfg {
    FILLP_INT sockIndex;
    FILLP_UINT32 nackCfgVal;
    FILLP_LLONG nackDelayTimeout;
};

FILLP_INT SysArchSetSockRcvbuf(FILLP_INT sock, FILLP_UINT size);
FILLP_INT SysArchSetSockSndbuf(FILLP_INT sock, FILLP_UINT size);
FILLP_INT SysArchSetSockBlocking(FILLP_INT sock, FILLP_BOOL blocking);
FILLP_INT SysSetThreadName(FILLP_CHAR *name, FILLP_UINT16 nameLen);

#ifdef __cplusplus
}
#endif

#endif /* FILLP_SOCKETS_H */