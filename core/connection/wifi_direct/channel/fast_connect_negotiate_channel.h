/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifndef FAST_CONNECT_NEGOTIATE_CHANNEL_H
#define FAST_CONNECT_NEGOTIATE_CHANNEL_H

#include "wifi_direct_negotiate_channel.h"

#ifdef __cplusplus
extern "C" {
#endif

struct FastConnectNegotiateChannel {
    WIFI_DIRECT_NEGOTIATE_CHANNEL_BASE;

    int32_t channelId;
    char p2pMac[MAC_ADDR_STR_LEN];
};

void FastConnectNegotiateChannelConstructor(struct FastConnectNegotiateChannel *self, int32_t channelId);
void FastConnectNegotiateChannelDestructor(struct FastConnectNegotiateChannel *self);
struct FastConnectNegotiateChannel* FastConnectNegotiateChannelNew(int32_t channelId);
void FastConnectNegotiateChannelDelete(struct FastConnectNegotiateChannel *self);

int32_t FastConnectNegotiateChannelInit(void);

#ifdef __cplusplus
}
#endif
#endif