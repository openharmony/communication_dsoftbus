/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_PROXYCHANNEL_TRANSCEIVER_H
#define SOFTBUS_PROXYCHANNEL_TRANSCEIVER_H

#include "common_list.h"
#include "softbus_app_info.h"
#include "softbus_conn_interface.h"
#include "softbus_proxychannel_message.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    ListNode node;
    uint32_t requestId;
    uint32_t connId;
    int32_t ref;
    uint32_t state;
    bool isServerSide;
    ConnectOption connInfo;
} ProxyConnInfo;

void TransProxyPostResetPeerMsgToLoop(const ProxyChannelInfo *chan);
void TransProxyPostHandshakeMsgToLoop(int32_t channelId);
void TransProxyPostDisConnectMsgToLoop(uint32_t connId, bool isServer, const ProxyChannelInfo *chan);
void TransProxyPostOpenClosedMsgToLoop(const ProxyChannelInfo *chan);
void TransProxyPostOpenFailMsgToLoop(const ProxyChannelInfo *chan, int32_t errCode);
void TransProxyPostKeepAliveMsgToLoop(const ProxyChannelInfo *chan);
void TransProxyPostAuthNegoMsgToLooperDelay(uint32_t authRequestId, int32_t channelId, uint32_t delayTime);
int32_t TransProxyTransInit(void);
int32_t TransProxyCloseConnChannel(uint32_t connectionId, bool isServer);
int32_t TransProxyCloseConnChannelReset(uint32_t connectionId, bool isDisconnect, bool isServer, bool deviceType);
int32_t TransProxyOpenConnChannel(const AppInfo *appInfo, const ConnectOption *connInfo, int32_t *channelId);
int32_t TransProxyTransSendMsg(uint32_t connectionId, uint8_t *buf, uint32_t len, int32_t priority, int32_t pid);
void TransCreateConnByConnId(uint32_t connId, bool isServer);
int32_t TransDecConnRefByConnId(uint32_t connId, bool isServer);
int32_t TransAddConnRefByConnId(uint32_t connId, bool isServer);
int32_t TransProxyGetConnInfoByConnId(uint32_t connId, ConnectOption *connInfo);
int32_t TransDelConnByReqId(uint32_t requestId);
int32_t CheckIsProxyAuthChannel(ConnectOption *connInfo);
void TransProxyNegoSessionKeySucc(int32_t channelId);
void TransProxyNegoSessionKeyFail(int32_t channelId, int32_t errCode);
int32_t TransProxyGetConnOptionByChanId(int32_t channelId, ConnectOption *connOpt);

#ifdef __cplusplus
}
#endif

#endif
