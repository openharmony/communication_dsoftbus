/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "client_trans_tcp_direct_callback.h"

#include <stddef.h>
#include <securec.h>

#include "softbus_def.h"
#include "softbus_error_code.h"
#include "client_trans_tcp_direct_manager.h"
#include "client_trans_tcp_direct_message.h"
#include "trans_log.h"
#include "client_trans_tcp_direct_listener.h"

static IClientSessionCallBack g_sessionCb;

int32_t ClientTransTdcSetCallBack(const IClientSessionCallBack *cb)
{
    if (cb == NULL) {
        TRANS_LOGE(TRANS_SDK, "cb null.");
        return SOFTBUS_INVALID_PARAM;
    }
    g_sessionCb = *cb;
    return SOFTBUS_OK;
}

int32_t ClientTransTdcOnSessionOpened(const char *sessionName, const ChannelInfo *channel)
{
    if (sessionName == NULL || channel == NULL) {
        TRANS_LOGE(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    SessionType type = TYPE_BUTT;
    switch (channel->businessType) {
        case BUSINESS_TYPE_MESSAGE:
            type = TYPE_MESSAGE;
            break;
        default:
            type = TYPE_BYTES;
            break;
    }
    return g_sessionCb.OnSessionOpened(sessionName, channel, type);
}

int32_t ClientTransTdcOnSessionClosed(int32_t channelId, ShutdownReason reason)
{
    (void)TransDelDataBufNode(channelId);
    (void)TransTdcCloseChannel(channelId);
    return g_sessionCb.OnSessionClosed(channelId, CHANNEL_TYPE_TCP_DIRECT, reason);
}

int32_t ClientTransTdcOnSessionOpenFailed(int32_t channelId, int32_t errCode)
{
    return g_sessionCb.OnSessionOpenFailed(channelId, CHANNEL_TYPE_TCP_DIRECT, errCode);
}

int32_t ClientTransTdcOnDataReceived(int32_t channelId,
    const void *data, uint32_t len, SessionPktType type)
{
    return g_sessionCb.OnDataReceived(channelId, CHANNEL_TYPE_TCP_DIRECT, data, len, type);
}

int32_t ClientTransTdcOnChannelBind(int32_t channelId, int32_t channelType)
{
    if (g_sessionCb.OnChannelBind == NULL) {
        TRANS_LOGW(TRANS_SDK, "OnChannelBind is null channelId=%{public}d", channelId);
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = g_sessionCb.OnChannelBind(channelId, channelType);
    if (ret == SOFTBUS_NOT_NEED_UPDATE) {
        return SOFTBUS_OK;
    }
    if (ret != SOFTBUS_OK) {
        return ret;
    }

    TcpDirectChannelInfo info;
    (void)memset_s(&info, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));
    ret = TransTdcGetInfoById(channelId, &info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "TransTdcGetInfoById failed, channelId=%{public}d", channelId);
        return SOFTBUS_NOT_FIND;
    }

    if (info.detail.needStopListener) {
        TRANS_LOGI(TRANS_SDK, "info.detail.needStopListener is true, channelId=%{public}d", channelId);
        return SOFTBUS_OK;
    }

    ret = TransTdcCreateListener(info.detail.fd);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "TransTdcCreateListener failed, channelId=%{public}d", channelId);
        g_sessionCb.OnSessionClosed(channelId, CHANNEL_TYPE_TCP_DIRECT, SHUTDOWN_REASON_LOCAL);
        return ret;
    }

    return SOFTBUS_OK;
}

int32_t ClientTransTdcIfChannelForSocket(const char *sessionName, bool *isSocket)
{
    return g_sessionCb.IfChannelForSocket(sessionName, isSocket);
}
