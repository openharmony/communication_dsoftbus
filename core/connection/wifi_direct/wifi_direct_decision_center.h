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
#ifndef WIFI_DIRECT_DECISION_CENTER_H
#define WIFI_DIRECT_DECISION_CENTER_H

#include "wifi_direct_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_CONNECTED_DEVICE_COUNT 4

struct NegotiateMessage;
struct WifiDirectProtocol;
struct WifiDirectProcessor;
struct WifiDirectNegotiateChannel;
struct WifiDirectTriggerChannel;

struct WifiDirectDecisionCenter {
    struct WifiDirectProtocol* (*getProtocol)(struct WifiDirectNegotiateChannel *channel);
    void (*putProtocol)(struct WifiDirectProtocol *protocol);
    struct WifiDirectProcessor* (*getProcessorByChannelAndConnectType)(struct WifiDirectNegotiateChannel *channel,
                                                                       enum WifiDirectConnectType connectType);
    struct WifiDirectProcessor* (*getProcessorByChannelAndLinkType)(struct WifiDirectNegotiateChannel *channel,
                                                                    enum WifiDirectLinkType linkType);
    struct WifiDirectProcessor* (*getProcessorByNegotiateMessage)(struct NegotiateMessage *msg);
    struct WifiDirectProcessor* (*getTriggerProcessorByData)(const uint8_t *data, size_t len);
    struct WifiDirectProcessor* (*getTriggerProcessorByChannel)(struct WifiDirectTriggerChannel *channel);
};

struct WifiDirectDecisionCenter *GetWifiDirectDecisionCenter(void);

#ifdef __cplusplus
}
#endif
#endif