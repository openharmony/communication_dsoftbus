/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef COAP_DISCOVER_H
#define COAP_DISCOVER_H
#include <net.h>
#include "nstackx_common.h"

#define COAP_MODULE_NAME_TYPE 0x01
#define COAP_DEVICE_ID_TYPE 0x02
#define COAP_MSG_TYPE 0x03

#define SERVER_TYPE_WLANORETH 0
#define SERVER_TYPE_P2P 1
#define SERVER_TYPE_USB 2

#define INVALID_TYPE 255

typedef struct {
    uint8_t type;
    uint16_t len; /* must be a positive integer */
    uint8_t value[0];
} __attribute__((packed)) CoapMsgUnit;

struct coap_session_t;
struct DeviceInfo;
typedef struct {
    char deviceId[NSTACKX_MAX_DEVICE_ID_LEN];
    char moduleName[NSTACKX_MAX_MODULE_NAME_LEN];
    char p2pAddr[NSTACKX_MAX_IP_STRING_LEN];
    uint8_t *data;
    uint32_t len;
    uint8_t type;
} MsgCtx;

void CoapServiceDiscoverInner(uint8_t userRequest);
void CoapServiceDiscoverInnerAn(uint8_t userRequest);
void CoapServiceDiscoverStopInner(void);
uint8_t CoapDiscoverRequestOngoing(void);
void CoapInitResources(coap_context_t *ctx, uint8_t isNeedInitCtx);
int32_t CoapDiscoverInit(EpollDesc epollfd);
void CoapDiscoverDeinit(void);
void CoapDestroyCtx(uint8_t serverType);
int32_t CoapSendServiceMsg(MsgCtx *msgCtx, struct DeviceInfo *deviceInfo);
int32_t CoapSendServiceMsgWithDefiniteTargetIp(MsgCtx *msgCtx, struct DeviceInfo *deviceInfo);
coap_context_t *GetContext(uint8_t serverType);
void CoapSubscribeModuleInner(uint8_t isSubscribe);
void CoapUnsubscribeModuleInner(uint8_t isUnsubscribe);
void CoapInitSubscribeModuleInner(void);
void ResetCoapDiscoverTaskCount(uint8_t isBusy);
uint8_t GetActualType(const uint8_t type, const char *dstIp);
#endif /* #ifndef COAP_DISCOVER_H */
