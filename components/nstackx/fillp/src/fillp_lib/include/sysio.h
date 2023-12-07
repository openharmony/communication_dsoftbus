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

#ifndef FILLP_SYS_IO_H
#define FILLP_SYS_IO_H

#include "fillptypes.h"
#include "hlist.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct InnerSysIoOps {
    int (*doSocket)(void *argSock);
    int (*send)(void *arg, FILLP_CONST char *buf, FILLP_SIZE_T size, FILLP_SOCKADDR *dest, FILLP_UINT16 destAddrLen);
    void *(*recv)(void *arg, FILLP_CONST void *buf, void *databuf);
    void *(*fetchPacket)(void *sock, void *buf, void *count);
    int (*select)(void *arg, FILLP_INT timeoutUs);
    void *(*createSocket)(FILLP_INT domain, FILLP_INT type, FILLP_INT protocol);
    int (*destroySysIoSocket)(void *arg);
    int (*listen)(void *argSock);

    int (*bind)(void *argSock, void *argPcb, FILLP_SOCKADDR *addr, FILLP_UINT16 len);
    int (*connect)(void *sock, void *pcb);
    int (*canSocketRead)(void *arg); /* Is this socket can read */
    int (*handlePacket)(int msgType, void *argSock, void *pcb, void *buf);
    int (*sendPacket)(int msgType, void *argSock, void *pcb, void *buf);
    void (*removePcb)(void *argSock, void *pcb);
    void (*freeSock)(void *argSock, void *argOsSock);
    int (*getSockName)(void *argSock, void *name, void *nameLen);
    void (*addPcb)(void *argSock, void *argPcb);
    int (*getOsSocket)(void *argSock);
    void (*connected)(void *argSock, void *argOsSock);
    int (*getsockopt)(void *argSock, FILLP_INT level, FILLP_INT optName, void *optVal, FILLP_INT *optLen);
    int (*setsockopt)(void *argSock, FILLP_INT level, FILLP_INT optName, FILLP_CONST void *optVal, socklen_t optLen);
} SysIoOps;


typedef struct Innersysiosock {
    SysIoOps *ops;
} SysIoSock;


typedef struct InnersysioUdpSock {
    SysIoSock sysIoSock;
    int udpSock;
    int addrType;
    FILLP_BOOL connected;
    struct SpungePcbhashbucket *pcbHash; /* spunge_pcb will be added when do connect or do accept */
} SysIoUdpSock;

typedef struct InnersysioUdp {
    SysIoOps ops;
    int maxUdpSock;

    FT_FD_SET readSet; /* socket read set for select */
    FT_FD_SET readableSet;
    struct Hlist listenPcbList;
} SysioUdpT;
extern SysioUdpT g_udpIo;

SysIoSock *SysIoSocketFactory(FILLP_INT domain, FILLP_INT type, FILLP_INT protocol);

int SysioSelect(FILLP_INT timeoutUs);
int SysioIsSockReadable(void *arg);


#ifdef __cplusplus
}
#endif

#endif /* FILLP_SYS_IO_H */
