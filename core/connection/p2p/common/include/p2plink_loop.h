/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef P2PLINK_LOOP_H
#define P2PLINK_LOOP_H

#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef enum {
    P2PLOOP_MSG_PROC,
    P2PLOOP_MSG_TEST,
    START_NEGOTIATION,
    CONN_REQUEST_TIME_OUT,
    WAIT_CONN_TIME_OUT,
    MAGICLINK_CONN_GROUP_TIME_OUT,
    MAGICLINK_CREATE_GROUP_TIME_OUT,
    MAGICLINK_ON_GROUP_CHANGED,
    CONN_REQUEST_FAILED,
    MAGICLINK_ON_CONNECTED,
    CONN_REQUEST,
    CONN_RESPONSE,
    CONN_RESPONSE_FAILED,
    P2PLOOP_CONNINGDEV_TIMER,
    P2PLOOP_P2PAUTHCHAN_OK,
    P2PLOOP_BROADCAST_GROUPSTATE_CHANGED,
    P2PLOOP_BROADCAST_P2PSTATE_CHANGED,
    P2PLOOP_BROADCAST_CONN_STATE,
    P2PLOOP_INTERFACE_ROLE_CONFICT,
    P2PLOOP_INTERFACE_LOOP_DISCONNECT,
    P2PLOOP_INTERFACE_LOOP_CONNECT,
    P2PLOOP_OPEN_AUTH_CHAN,
    P2PLOOP_OPEN_DISCONNECTING_TIMEOUT,
    P2PLOOP_AUTH_CHANNEL_CLOSED,
    WAIT_ROLE_NEG_TIME_OUT,
    DHCP_TIME_OUT,
} P2pLoopMsg;

typedef void (*P2pLoopProcessFunc)(P2pLoopMsg msgType, void *para);

int32_t P2pLoopInit(void);
int32_t P2pLoopProc(P2pLoopProcessFunc callback, void *para, P2pLoopMsg msgType); // para: no use local variable
int32_t P2pLoopProcDelay(P2pLoopProcessFunc callback, void *para, uint64_t delayMillis, P2pLoopMsg msgType);
int32_t P2pLoopProcDelayDel(P2pLoopProcessFunc callback, P2pLoopMsg msgType);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif /* P2PLINK_LOOP_H */

