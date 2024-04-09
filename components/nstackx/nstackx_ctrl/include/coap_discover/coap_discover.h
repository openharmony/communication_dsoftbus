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

#ifndef COAP_DISCOVER_H
#define COAP_DISCOVER_H
#include <coap3/coap.h>
#include "nstackx_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define COAP_MODULE_NAME_TYPE 0x01
#define COAP_DEVICE_ID_TYPE 0x02
#define COAP_MSG_TYPE 0x03

#define SERVER_TYPE_WLANORETH 0
#define SERVER_TYPE_P2P 1
#define SERVER_TYPE_USB 2

#define INVALID_TYPE 255
#pragma pack(1)
typedef struct {
    uint8_t type;
    uint16_t len; /* must be a positive integer */
    uint8_t value[0];
} CoapMsgUnit;
#pragma pack()
struct coap_session_t;

typedef struct {
    const char *deviceId;
    const char *moduleName;
    const uint8_t *data;
    uint32_t len;
    uint8_t type;
    int32_t err;
    sem_t wait;
} MsgCtx;

typedef struct CoapRequest {
    uint8_t type;
    uint8_t code;
    const char *remoteUrl;
    uint8_t *token;
    size_t tokenLength;
    char *data;
    size_t dataLength;
} CoapRequest;

typedef enum {
    COAP_BROADCAST_TYPE_DEFAULT = 0,
    COAP_BROADCAST_TYPE_USER = 1,
    COAP_BROADCAST_TYPE_USER_DEFINE_INTERVAL = 2
} CoapBroadcastType;

#ifdef DFINDER_SUPPORT_SET_SCREEN_STATUS
void SetScreenStatus(bool isScreenOn);
#endif

void CoapServiceDiscoverInner(uint8_t userRequest);
void CoapServiceDiscoverInnerAn(uint8_t userRequest);
void CoapServiceDiscoverInnerConfigurable(uint8_t userRequest);
void CoapServiceDiscoverStopInner(void);
uint8_t CoapDiscoverRequestOngoing(void);

void CoapServiceNotification(void);

int32_t CoapInitResources(coap_context_t *ctx);

int32_t CoapDiscoverInit(EpollDesc epollfd);
void CoapDiscoverDeinit(void);

int32_t CoapSendServiceMsg(MsgCtx *msgCtx, const char *remoteIpStr, const struct in_addr *remoteIp);
void CoapSubscribeModuleInner(uint8_t isSubscribe);
void CoapUnsubscribeModuleInner(uint8_t isUnsubscribe);
void CoapInitSubscribeModuleInner(void);
void ResetCoapDiscoverTaskCount(uint8_t isBusy);
void SetCoapDiscoverType(CoapBroadcastType type);
void SetCoapUserDiscoverInfo(uint32_t advCount, uint32_t advDuration);
int32_t SetCoapDiscConfig(const DFinderDiscConfig *discConfig);
void SendDiscoveryRsp(const NSTACKX_ResponseSettings *responseSettings);
int32_t LocalizeNotificationInterval(const uint16_t *intervals, const uint8_t intervalLen);
void CoapServiceNotificationStop(void);

#ifdef __cplusplus
}
#endif

#endif /* #ifndef COAP_DISCOVER_H */
