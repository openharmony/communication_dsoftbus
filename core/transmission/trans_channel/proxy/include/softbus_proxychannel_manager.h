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

#ifndef SOFTBUS_PROXYCHANNEL_MANAGER_H
#define SOFTBUS_PROXYCHANNEL_MANAGER_H

#include "stdint.h"
#include "softbus_app_info.h"
#include "softbus_conn_interface.h"
#include "softbus_proxychannel_message.h"

int32_t TransProxyManagerInit(void);
void TransProxyManagerDeinit(void);

int32_t TransProxyGetNewChanSeq(int32_t channelId);
int32_t TransProxyOpenProxyChannel(const AppInfo *appInfo, const ConnectOption *connInfo, int32_t *channelId);
int32_t TransProxyCloseProxyChannel(int32_t channelId);
int32_t TransProxySendMsg(int32_t channelId, const char *data, int32_t dataLen, int32_t priority);
void TransProxyDelByConnId(uint32_t connId);
void TransProxyOpenProxyChannelSuccess(int32_t chanId);
void TransProxyOpenProxyChannelFail(int32_t channelId, const AppInfo *appInfo);
void TransProxyonMessageReceived(const ProxyMessage *msg);
int32_t TransProxyGetSessionKeyByChanId(int32_t channelId, char *sessionKey, int32_t sessionKeySize);
int16_t TransProxyGetNewMyId(void);
int32_t TransProxyManagerInit(void);
void TransProxyDelChanByReqId(int32_t reqId);
int32_t TransProxyCreateChanInfo(ProxyChannelInfo *chan, int32_t channelId, const AppInfo *appInfo);
void TransProxyChanProcessByReqId(int32_t reqId, uint32_t connId);
void TransProxyDelChanByChanId(int32_t chanlId);
int32_t TransProxySetChiperSide(int32_t channelId, int32_t side);
int32_t TransProxyGetChiperSide(int32_t channelId, int32_t *side);
int32_t TransProxyGetNameByChanId(int32_t chanId, char *pkgName, char *sessionName,
    uint16_t pkgLen, uint16_t sessionLen);

#endif
