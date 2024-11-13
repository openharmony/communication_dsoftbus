/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "client_trans_auth_manager.h"

#include "softbus_error_code.h"
#include "trans_log.h"
#include "trans_server_proxy.h"

static IClientSessionCallBack g_sessionCb;

int32_t ClientTransAuthInit(const IClientSessionCallBack *cb)
{
    if (cb == NULL) {
        TRANS_LOGE(TRANS_SDK, "cb is null.");
        return SOFTBUS_INVALID_PARAM;
    }
    g_sessionCb = *cb;
    return SOFTBUS_OK;
}

int32_t ClientTransAuthOnChannelOpened(const char *sessionName, const ChannelInfo *channel)
{
    if (sessionName == NULL || channel == NULL) {
        TRANS_LOGE(TRANS_SDK, "param invalid.");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = g_sessionCb.OnSessionOpened(sessionName, channel, TYPE_MESSAGE);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "notify session open fail, ret=%{public}d", ret);
        return ret;
    }

    return SOFTBUS_OK;
}

int32_t ClientTransAuthOnChannelClosed(int32_t channelId, ShutdownReason reason)
{
    int32_t ret = g_sessionCb.OnSessionClosed(channelId, CHANNEL_TYPE_AUTH, reason);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "notify session open fail. ret=%{public}d, channelId=%{public}d", ret, channelId);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ClientTransAuthOnChannelOpenFailed(int32_t channelId, int32_t errCode)
{
    int32_t ret = g_sessionCb.OnSessionOpenFailed(channelId, CHANNEL_TYPE_AUTH, errCode);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK,
            "notify session open fail. ret=%{public}d, errCode=%{public}d, channelId=%{public}d",
            ret, errCode, channelId);
        return ret;
    }

    return SOFTBUS_OK;
}

int32_t ClientTransAuthOnDataReceived(int32_t channelId, const void *data, uint32_t len, SessionPktType type)
{
    if (data == NULL) {
        TRANS_LOGE(TRANS_SDK, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = g_sessionCb.OnDataReceived(channelId, CHANNEL_TYPE_AUTH, data, len, type);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "notify data recv err, ret=%{public}d, channelId=%{public}d", ret, channelId);
        return ret;
    }
    return SOFTBUS_OK;
}

void ClientTransAuthCloseChannel(int32_t channelId, ShutdownReason reason)
{
    TRANS_LOGI(TRANS_SDK, "TransCloseAuthChannel, channelId=%{public}d", channelId);
    if (ServerIpcCloseChannel(NULL, channelId, CHANNEL_TYPE_AUTH) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "server ipc close err. channelId=%{public}d", channelId);
    }
    if (ClientTransAuthOnChannelClosed(channelId, reason) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "server auth close err. channelId=%{public}d", channelId);
    }
}

int32_t TransAuthChannelSendBytes(int32_t channelId, const void *data, uint32_t len)
{
    int32_t ret = ServerIpcSendMessage(channelId, CHANNEL_TYPE_AUTH, data, len, TRANS_SESSION_BYTES);
    TRANS_LOGI(TRANS_BYTES, "send bytes: channelId=%{public}d, ret=%{public}d", channelId, ret);
    return ret;
}

int32_t TransAuthChannelSendMessage(int32_t channelId, const void *data, uint32_t len)
{
    int32_t ret = ServerIpcSendMessage(channelId, CHANNEL_TYPE_AUTH, data, len, TRANS_SESSION_BYTES);
    TRANS_LOGI(TRANS_MSG, "send msg: channelId=%{public}d, ret=%{public}d", channelId, ret);
    return ret;
}