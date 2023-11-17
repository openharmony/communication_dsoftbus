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
#include "conn_log.h"
#include "softbus_error_code.h"
#include "processor/wifi_direct_processor.h"
#include "data/negotiate_message.h"
#include "wifi_direct_negotiate_channel.h"

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
    CONN_LOGE(CONN_WIFI_DIRECT, "not supported yet");
    return SOFTBUS_ERR;
}

int FastConnectReuseLink(struct WifiDirectConnectInfo *connectInfo, struct WifiDirectProcessor *processor)
{
    (void)connectInfo;
    (void)processor;
    CONN_LOGE(CONN_WIFI_DIRECT, "not supported yet");
    return SOFTBUS_ERR;
}

void FastConnectHandleFailure(int result)
{
    (void)result;
    CONN_LOGE(CONN_WIFI_DIRECT, "not supported yet");
}

void FastConnectClientConnected(const char *remoteMac)
{
    (void)remoteMac;
    CONN_LOGE(CONN_WIFI_DIRECT, "not supported yet");
}

void FastConnectCloseChannel(struct WifiDirectNegotiateChannel *channel)
{
    (void)channel;
    CONN_LOGE(CONN_WIFI_DIRECT, "not supported yet");
}

int32_t FastConnectProcessNegotiateMessage(enum WifiDirectNegotiateCmdType cmd, struct NegotiateMessage *msg)
{
    (void)cmd;
    (void)msg;
    CONN_LOGE(CONN_WIFI_DIRECT, "not supported yet");
    return SOFTBUS_ERR;
}

void FastConnectSyncLnnInfo(void)
{
}