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

#include "trans_tcp_direct_callback.h"

#include <stddef.h>

#include "softbus_def.h"
#include "softbus_error_code.h"

static IServerChannelCallBack g_channelCb;

int32_t TransTdcSetCallBack(const IServerChannelCallBack *cb)
{
    if (cb == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    g_channelCb = *cb;
    return SOFTBUS_OK;
}

int32_t TransTdcOnChannelOpened(const char *pkgName, int32_t pid, const char *sessionName,
    const ChannelInfo *channel)
{
    return g_channelCb.OnChannelOpened(pkgName, pid, sessionName, channel);
}

int32_t TransTdcOnChannelBind(const char *pkgName, int32_t pid, int32_t channelId)
{
    return g_channelCb.OnChannelBind(pkgName, pid, channelId, CHANNEL_TYPE_TCP_DIRECT);
}

int32_t TransTdcOnChannelClosed(const char *pkgName, int32_t pid, int32_t channelId)
{
    return g_channelCb.OnChannelClosed(pkgName, pid, channelId, CHANNEL_TYPE_TCP_DIRECT, MESSAGE_TYPE_NOMAL);
}

int32_t TransTdcOnChannelOpenFailed(const char *pkgName, int32_t pid, int32_t channelId,
    int32_t errCode)
{
    return g_channelCb.OnChannelOpenFailed(pkgName, pid, channelId, CHANNEL_TYPE_TCP_DIRECT, errCode);
}

int32_t TransTdcGetPkgName(const char *sessionName, char *pkgName, uint16_t len)
{
    return g_channelCb.GetPkgNameBySessionName(sessionName, pkgName, len);
}

int32_t TransTdcGetUidAndPid(const char *sessionName, int32_t *uid, int32_t *pid)
{
    return g_channelCb.GetUidAndPidBySessionName(sessionName, uid, pid);
}

int32_t TransTdcOnMsgReceived(const char *pkgName, int32_t pid, int32_t channelId, TransReceiveData *receiveData)
{
    return g_channelCb.OnDataReceived(pkgName, pid, channelId, CHANNEL_TYPE_TCP_DIRECT, receiveData);
}