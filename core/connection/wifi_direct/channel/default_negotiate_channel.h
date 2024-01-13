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

#ifndef DEFAULT_NEGOTIATE_CHANNEL_H
#define DEFAULT_NEGOTIATE_CHANNEL_H

#include "wifi_direct_negotiate_channel.h"
#include "common_list.h"

#ifdef __cplusplus
extern "C" {
#endif

struct DefaultNegotiateChannel {
    WIFI_DIRECT_NEGOTIATE_CHANNEL_BASE;
    int64_t authId;
    bool tlvFeature;
    char p2pMac[MAC_ADDR_STR_LEN];
};

void DefaultNegotiateChannelConstructor(struct DefaultNegotiateChannel *self, int64_t authId);
void DefaultNegotiateChannelDestructor(struct DefaultNegotiateChannel *self);
struct DefaultNegotiateChannel* DefaultNegotiateChannelNew(int64_t authId);
void DefaultNegotiateChannelDelete(struct DefaultNegotiateChannel *self);

struct DefaultNegoChannelOpenCallback {
    void (*onConnectSuccess)(uint32_t requestId, int64_t authId);
    void (*onConnectFailure)(uint32_t requestId, int32_t reason);
};

int32_t OpenDefaultNegotiateChannel(const char *remoteIp, int32_t remotePort,
                                    struct WifiDirectNegotiateChannel *srcChannel,
                                    struct DefaultNegoChannelOpenCallback *callback);
void CloseDefaultNegotiateChannel(struct DefaultNegotiateChannel *self);
int32_t StartListeningForDefaultChannel(const char *localIp);
void StopListeningForDefaultChannel(void);

int32_t DefaultNegotiateChannelInit(void);

#ifdef __cplusplus
}
#endif
#endif