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
#ifndef WIFI_DIRECT_NEGOTIATE_CHANNEL_H
#define WIFI_DIRECT_NEGOTIATE_CHANNEL_H

#include "wifi_direct_types.h"

#ifdef __cplusplus
extern "C" {
#endif

enum WifiDirectNegotiateChannelType {
    NEGOTIATE_WIFI = 0,
    NEGOTIATE_BLE,
    NEGOTIATE_BR,
    NEGOTIATE_MAX,
};

#define WIFI_DIRECT_NEGOTIATE_CHANNEL_BASE \
    int32_t (*postData)(struct WifiDirectNegotiateChannel *base, const uint8_t *data, size_t size);           \
    int32_t (*getDeviceId)(struct WifiDirectNegotiateChannel *base, char *deviceId, size_t deviceIdSize);     \
    int32_t (*getP2pMac)(struct WifiDirectNegotiateChannel *base, char *p2pMac, size_t p2pMacSize);           \
    void (*setP2pMac)(struct WifiDirectNegotiateChannel *base, const char *p2pMac);                           \
    bool (*isP2pChannel)(struct WifiDirectNegotiateChannel *base);                                            \
    bool (*isMetaChannel)(struct WifiDirectNegotiateChannel *base);                                           \
    bool (*equal)(struct WifiDirectNegotiateChannel *leftBase, struct WifiDirectNegotiateChannel *rightBase); \
    struct WifiDirectNegotiateChannel* (*duplicate)(struct WifiDirectNegotiateChannel *base);                 \
    void (*destructor)(struct WifiDirectNegotiateChannel *base);                                              \
    enum WifiDirectNegotiateChannelType (*getMediumType)(struct WifiDirectNegotiateChannel *base)

struct WifiDirectNegotiateChannel {
    WIFI_DIRECT_NEGOTIATE_CHANNEL_BASE;
};

#ifdef __cplusplus
}
#endif
#endif