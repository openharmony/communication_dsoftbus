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

#include "client_trans_channel_manager.h"
#include "client_trans_proxy_manager.h"
#include "client_trans_session_callback.h"
#ifndef SOFTBUS_WATCH
#include "client_trans_tcp_direct_manager.h"
#include "client_trans_tcp_direct_message.h"
#endif
#include "session.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

int32_t TransOnChannelOpened(const char *pkgName, const char *sessionName, const ChannelInfo *channel)
{
    (void)pkgName;
    if ((sessionName == NULL) || (channel == NULL)) {
        LOG_ERR("Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = SOFTBUS_ERR;
    uint32_t flag = TYPE_BUTT;
    switch (channel->channelType) {
        case CHANNEL_TYPE_PROXY:
            ret = TransOnProxyChannelOpened(channel);
            flag = TYPE_MESSAGE;
            break;
#ifndef SOFTBUS_WATCH
        case CHANNEL_TYPE_TCP_DIRECT:
            ret = TransTdcOnChannelOpened(channel);
            break;
#endif
        default:
            LOG_ERR("Invalid type");
            return SOFTBUS_ERR;
    }

    if (ret != SOFTBUS_OK) {
        LOG_ERR("channel open failed");
        return SOFTBUS_ERR;
    }

    ret = TransOnSessionOpened(sessionName, channel, flag);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("TransOnSessionOpened failed");
        (void)ClientTransCloseChannel(channel->channelId, channel->channelType);
    }

    return ret;
}

int32_t TransOnChannelOpenFailed(const char *pkgName, int32_t channelId)
{
    (void)pkgName;
    return TransOnSessionOpenFailed(channelId);
}

int32_t TransOnChannelClosed(const char *pkgName, int32_t channelId)
{
    (void)pkgName;
    return TransOnSessionClosed(channelId);
}

int32_t TransOnChannelMsgReceived(const char *pkgName, int32_t channelId, const void *data, uint32_t len,
    SessionPktType type)
{
    (void)pkgName;
    return TransOnDataReceived(channelId, data, len, type);
}
