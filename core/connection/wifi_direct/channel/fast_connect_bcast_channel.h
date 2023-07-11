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

#ifndef FAST_CONNECT_BCAST_CHANNEL_H
#define FAST_CONNECT_BCAST_CHANNEL_H

#include "wifi_direct_negotiate_channel.h"

#ifdef __cplusplus
extern "C" {
#endif

struct FastConnectBcastChannel {
    WIFI_DIRECT_NEGOTIATE_CHANNEL_BASE;

    bool (*isEnable)(void);

    char *remoteNetworkId;
    bool tlvFeature;
};

void FastConnectBcastChannelConstructor(struct FastConnectBcastChannel *self, const char *networkId);
void FastConnectBcastChannelDestructor(struct FastConnectBcastChannel *self);
struct FastConnectBcastChannel* FastConnectBcastChannelNew(const char *networkId);
void FastConnectBcastChannelDelete(struct FastConnectBcastChannel *self);

void FastConnectBcastChannelOnScanReceived(const char *networkId, uint8_t *buf, size_t bufLen);

#ifdef __cplusplus
}
#endif
#endif