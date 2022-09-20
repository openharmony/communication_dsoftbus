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

#ifndef SPUNGE_MESSAGE_H
#define SPUNGE_MESSAGE_H

#include "spunge.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct SpungeSocketMsg {
    void *sock;
    FILLP_INT domain;
    FILLP_INT type;
    FILLP_INT protocol;
};

struct SpungeBindMsg {
    void *sock;
    struct sockaddr_in *addr;
    socklen_t addrLen;
};

struct SpungeShutdownMsg {
    void *sock;
    FILLP_INT how;
};

struct SpungeConnectMsg {
    void *sock;
    struct sockaddr_in *addr;
    socklen_t addrLen;
};

struct SpungeAcceptMsg {
    void *listenSock;
    void *netconn;
};

struct SpungeEvtInfoMsg {
    void *sock;
    FtEventCbkInfo *info;
};

struct SpungeHiEventCbMsg {
    void *softObj;
    FillpDfxEventCb cb;
};

struct SpungeMsg {
    void *value;
    int msgType;
    FILLP_BOOL block;
    SYS_ARCH_SEM syncSem;
};

/* If you want to add/del some message type here, please check the macro MAX_SPUNGE_TYPE_NUM in sockets.h */
enum SpungeMsgType {
    MSG_TYPE_ALLOC_SOCK,
    MSG_TYPE_FREE_SOCK_EAGAIN, /* free sock failed before, now try again */
    MSG_TYPE_DO_LISTEN,
    MSG_TYPE_DO_CONNECT,
    MSG_TYPE_DO_BIND,
    MSG_TYPE_NETCONN_ACCPETED,
    MSG_TYPE_DO_CLOSE,
    MSG_TYPE_DO_SHUTDOWN,
    MSG_TYPE_SET_SEND_BUF,
    MSG_TYPE_SET_RECV_BUF,
    MSG_TYPE_SET_NACK_DELAY,
    MSG_TYPE_GET_EVENT_INFO,
    MSG_TYPE_SET_KEEP_ALIVE,
    MSG_TYPE_SET_HIEVENT_CB,
    MSG_TYPE_END
};

FillpErrorType SpungePostMsg(struct SpungeInstance *inst, void *value, FILLP_INT type, FILLP_BOOL block);

typedef void (*spungeMsgHandler)(void *value, struct SpungeInstance *inst);
extern spungeMsgHandler g_msgHandler[MSG_TYPE_END];

void *SpungeMsgCreatePool(int initSize, int maxSize);
void SpungeMsgPoolDestroy(DympoolType *msgPool);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SPUNGE_MESSAGE_H */