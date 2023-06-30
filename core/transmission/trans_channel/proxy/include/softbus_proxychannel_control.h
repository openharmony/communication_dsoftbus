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

#ifndef SOFTBUS_PROXYCHANNEL_CONTROL_H
#define SOFTBUS_PROXYCHANNEL_CONTROL_H
#include "softbus_proxychannel_message.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t TransProxySendInnerMessage(ProxyChannelInfo *info, const char *payLoad, uint32_t payLoadLen, int32_t priority);
int32_t TransProxyHandshake(ProxyChannelInfo *info);
int32_t TransProxyAckHandshake(uint32_t connId, ProxyChannelInfo *chan, int32_t retCode);
void TransProxyKeepalive(uint32_t connId, const ProxyChannelInfo *info);
int32_t TransProxyAckKeepalive(ProxyChannelInfo *info);
int32_t TransProxyResetPeer(ProxyChannelInfo *info);

#ifdef __cplusplus
}
#endif

#endif
