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

#include "wifi_direct_fast_connect.h"
#include "softbus_error_code.h"
#include "softbus_log.h"
#include "processor/wifi_direct_processor.h"
#include "data/negotiate_message.h"
#include "wifi_direct_negotiate_channel.h"

#define LOG_LABEL "[WifiDirect] WDFast: "

int32_t FastConnectInit(void)
{
    return SOFTBUS_OK;
}

void FastConnectReset(bool releaseChannel)
{
    (void)releaseChannel;
}

int FastConnectOpenLink(struct WifiDirectConnectInfo *connectInfo, struct WifiDirectProcessor *processor)
{
    (void)connectInfo;
    (void)processor;
    CLOGE(LOG_LABEL "not supported yet");
    return SOFTBUS_ERR;
}

int FastConnectReuseLink(struct WifiDirectConnectInfo *connectInfo, struct WifiDirectProcessor *processor)
{
    (void)connectInfo;
    (void)processor;
    CLOGE(LOG_LABEL "not supported yet");
    return SOFTBUS_ERR;
}

void FastConnectHandleFailure(int result)
{
    (void)result;
    CLOGE(LOG_LABEL "not supported yet");
}

void FastConnectClientConnected(const char *remoteMac)
{
    (void)remoteMac;
    CLOGE(LOG_LABEL "not supported yet");
}

void FastConnectCloseChannel(struct WifiDirectNegotiateChannel *channel)
{
    (void)channel;
    CLOGE(LOG_LABEL "not supported yet");
}

int32_t FastConnectProcessNegotiateMessage(enum WifiDirectNegotiateCmdType cmd, struct NegotiateMessage *msg)
{
    (void)cmd;
    (void)msg;
    CLOGE(LOG_LABEL "not supported yet");
    return SOFTBUS_ERR;
}

void FastConnectSyncLnnInfo(void)
{
}