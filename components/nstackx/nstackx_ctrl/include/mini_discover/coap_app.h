/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef COAP_APP_H
#define COAP_APP_H

#include <arpa/inet.h>

#include "coap_adapter.h"
#include "coap_def.h"
#include "nstackx_epoll.h"

#ifdef __cplusplus
extern "C" {
#endif

#define COAP_SRV_DEFAULT_PORT 5684
#define COAP_SRV_DEFAULT_ADDR "0.0.0.0"

typedef enum {
    SOCKET_READ_EVENT = 0,
    SOCKET_WRITE_EVENT,
    SOCKET_ERROR_EVENT,
    SOCKET_END_EVENT
} SocketEventType;

typedef struct {
    bool inited;
    uint8_t socketErrFlag;
    int32_t listenFd;
    EpollTask task;
    uint64_t socketEventNum[SOCKET_END_EVENT];
    void *iface;
} CoapCtxType;

bool IsCoapContextReady(void);

const char *CoapGetLocalIfaceName(void);
CoapCtxType *CoapGetCoapCtxType(void);

CoapCtxType *CoapServerInit(const struct in_addr *ip, void *iface);
void CoapServerDestroy(CoapCtxType *ctx, bool moduleDeinit);

void ResetCoapSocketTaskCount(uint8_t isBusy);
int32_t CoapSendMessage(const CoapBuildParam *param, uint8_t isBroadcast, uint8_t businessType, bool isAckMsg);

#ifdef __cplusplus
}
#endif

#endif /* COAP_APP_H */
