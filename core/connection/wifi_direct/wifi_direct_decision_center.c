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

#include "wifi_direct_decision_center.h"
#include "channel/wifi_direct_negotiate_channel.h"
#include "data/link_info.h"
#include "data/inner_link.h"
#include "data/negotiate_message.h"
#include "protocol/wifi_direct_protocol_factory.h"
#include "processor/wifi_direct_processor_factory.h"

static struct WifiDirectProtocol* GetProtocol(struct WifiDirectNegotiateChannel *channel)
{
    (void)channel;
    struct WifiDirectProtocolFactory *factory = GetWifiDirectProtocolFactory();
    return factory->createProtocol(WIFI_DIRECT_PROTOCOL_JSON);
}

static void PutProtocol(struct WifiDirectProtocol *protocol)
{
    struct WifiDirectProtocolFactory *factory = GetWifiDirectProtocolFactory();
    factory->destroyProtocol(protocol);
}

static struct WifiDirectProcessor* GetProcessorByChannelAndConnectType(struct WifiDirectNegotiateChannel *channel,
                                                                       enum WifiDirectConnectType connectType)
{
    (void)channel;
    struct WifiDirectProcessorFactory *factory = GetWifiDirectProcessorFactory();
    return factory->createProcessor(WIFI_DIRECT_PROCESSOR_TYPE_P2P_V1);
}

static struct WifiDirectProcessor* GetProcessorByChannelAndLinkType(struct WifiDirectNegotiateChannel *channel,
                                                                    enum WifiDirectLinkType linkType)
{
    (void)channel;
    (void)linkType;
    struct WifiDirectProcessorFactory *factory = GetWifiDirectProcessorFactory();
    return factory->createProcessor(WIFI_DIRECT_PROCESSOR_TYPE_P2P_V1);
}

static struct WifiDirectProcessor* GetProcessorByNegotiateMessage(struct NegotiateMessage *msg)
{
    (void)msg;
    struct WifiDirectProcessorFactory *factory = GetWifiDirectProcessorFactory();
    return factory->createProcessor(WIFI_DIRECT_PROCESSOR_TYPE_P2P_V1);
}

/* static public method */
static struct WifiDirectDecisionCenter g_decisionCenter = {
    .getProtocol = GetProtocol,
    .putProtocol = PutProtocol,
    .getProcessorByChannelAndConnectType = GetProcessorByChannelAndConnectType,
    .getProcessorByChannelAndLinkType = GetProcessorByChannelAndLinkType,
    .getProcessorByNegotiateMessage = GetProcessorByNegotiateMessage,
};

struct WifiDirectDecisionCenter *GetWifiDirectDecisionCenter(void)
{
    return &g_decisionCenter;
}