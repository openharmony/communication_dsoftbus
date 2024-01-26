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

#include <coap3/coap.h>

#include "nstackx_epoll.h"
#include "nstackx_list.h"

#ifdef __cplusplus
extern "C" {
#endif

#define COAP_SRV_DEFAULT_PORT "5684"
#define COAP_SRV_DEFAULT_ADDR "0.0.0.0"

#define MAX_COAP_SOCKET_NUM 64

typedef struct {
    List node;
    coap_context_t *ctx;
    EpollTask taskList[MAX_COAP_SOCKET_NUM];
    uint32_t socketNum;
    uint8_t socketErrFlag;
    uint8_t freeCtxLater;
    void *iface;
} CoapCtxType;

List *GetCoapContextList(void);
bool IsCoapContextReady(void);
CoapCtxType *CoapGetCoapCtxType(const coap_context_t *ctx);

CoapCtxType *CoapServerInit(const struct in_addr *ip, void *iface);
void CoapServerDestroy(CoapCtxType *ctx, bool moduleDeinit);

uint32_t RegisterCoAPEpollTask(EpollDesc epollfd);
void DeRegisterCoAPEpollTask(void);
void ResetCoapSocketTaskCount(uint8_t isBusy);
#ifdef _WIN32
int32_t CoapThreadInit(void);
void CoapThreadDestroy(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* COAP_APP_H */
