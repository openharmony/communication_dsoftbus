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

#include "client_trans_channel_callback.h"

#include "client_trans_auth_manager.h"
#include "client_trans_proxy_manager.h"
#include "client_trans_session_callback.h"
#include "client_trans_tcp_direct_manager.h"
#include "client_trans_udp_manager.h"
#include "session.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

int32_t TransOnChannelOpened(const char *sessionName, const ChannelInfo *channel)
{
    if (sessionName == NULL || channel == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = SOFTBUS_ERR;
    int32_t udpPort = 0;
    switch (channel->channelType) {
        case CHANNEL_TYPE_AUTH:
            ret = ClientTransAuthOnChannelOpened(sessionName, channel);
            break;
        case CHANNEL_TYPE_PROXY:
            ret = ClientTransProxyOnChannelOpened(sessionName, channel);
            break;
        case CHANNEL_TYPE_TCP_DIRECT:
            ret = ClientTransTdcOnChannelOpened(sessionName, channel);
            break;
        case CHANNEL_TYPE_UDP:
            ret = TransOnUdpChannelOpened(sessionName, channel, &udpPort);
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid type");
            return SOFTBUS_TRANS_INVALID_CHANNEL_TYPE;
    }

    if (channel->channelType == CHANNEL_TYPE_UDP && channel->isServer) {
        return udpPort;
    }

    return ret;
}

int32_t TransOnChannelOpenFailed(int32_t channelId, int32_t channelType)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "[client] TransOnChannelOpenFailed: channelId=%d, channelType=%d",
        channelId, channelType);
    switch (channelType) {
        case CHANNEL_TYPE_AUTH:
            return ClientTransAuthOnChannelOpenFailed(channelId);
        case CHANNEL_TYPE_PROXY:
            return ClientTransProxyOnChannelOpenFailed(channelId);
        case CHANNEL_TYPE_TCP_DIRECT:
            return ClientTransTdcOnChannelOpenFailed(channelId);
        case CHANNEL_TYPE_UDP:
            return TransOnUdpChannelOpenFailed(channelId);
        default:
            return SOFTBUS_TRANS_INVALID_CHANNEL_TYPE;
    }
}

int32_t TransOnChannelClosed(int32_t channelId, int32_t channelType)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "[client] TransOnChannelClosed: channelId=%d, channelType=%d",
        channelId, channelType);
    switch (channelType) {
        case CHANNEL_TYPE_AUTH:
            return ClientTransAuthOnChannelClosed(channelId);
        case CHANNEL_TYPE_PROXY:
            return ClientTransProxyOnChannelClosed(channelId);
        case CHANNEL_TYPE_UDP:
            return TransOnUdpChannelClosed(channelId);
        case CHANNEL_TYPE_TCP_DIRECT:
        default:
            return SOFTBUS_TRANS_INVALID_CHANNEL_TYPE;
    }
}

int32_t TransOnChannelMsgReceived(int32_t channelId, int32_t channelType,
    const void *data, uint32_t len, SessionPktType type)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "[client] TransOnChannelMsgReceived: channelId=%d, channelType=%d",
        channelId, channelType);
    switch (channelType) {
        case CHANNEL_TYPE_AUTH:
            return ClientTransAuthOnDataReceived(channelId, data, len, type);
        case CHANNEL_TYPE_PROXY:
            return ClientTransProxyOnDataReceived(channelId, data, len, type);
        default:
            return SOFTBUS_TRANS_INVALID_CHANNEL_TYPE;
    }
}
