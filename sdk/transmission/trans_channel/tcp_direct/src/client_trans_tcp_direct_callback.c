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

#include "softbus_def.h"
#include "softbus_errcode.h"
#include "client_trans_tcp_direct_manager.h"
#include "client_trans_tcp_direct_message.h"
#include "trans_log.h"

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
    return g_sessionCb.OnSessionOpened(sessionName, channel, TYPE_BYTES);
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

