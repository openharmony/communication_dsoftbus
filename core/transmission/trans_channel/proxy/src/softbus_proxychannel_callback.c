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

#include "softbus_proxychannel_callback.h"

#include "softbus_def.h"
#include "softbus_error_code.h"

static IServerChannelCallBack g_channelCb;

int32_t TransProxySetCallBack(const IServerChannelCallBack *cb)
{
    if (cb == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    g_channelCb = *cb;
    return SOFTBUS_OK;
}

int32_t TransProxyOnChannelOpened(const char *pkgName, int32_t pid, const char *sessionName,
    const ChannelInfo *channel)
{
    return g_channelCb.OnChannelOpened(pkgName, pid, sessionName, channel);
}

int32_t TransProxyOnChannelClosed(const char *pkgName, int32_t pid, int32_t channelId)
{
    return g_channelCb.OnChannelClosed(pkgName, pid, channelId, CHANNEL_TYPE_PROXY, MESSAGE_TYPE_NOMAL);
}

int32_t TransProxyOnChannelBind(const char *pkgName, int32_t pid, int32_t channelId)
{
    return g_channelCb.OnChannelBind(pkgName, pid, channelId, CHANNEL_TYPE_PROXY);
}

int32_t TransProxyOnChannelOpenFailed(const char *pkgName, int32_t pid, int32_t channelId,
    int32_t errCode)
{
    return g_channelCb.OnChannelOpenFailed(pkgName, pid, channelId, CHANNEL_TYPE_PROXY, errCode);
}

int32_t TransProxyOnMsgReceived(const char *pkgName, int32_t pid, int32_t channelId,
    TransReceiveData *receiveData)
{
    return g_channelCb.OnDataReceived(pkgName, pid, channelId, CHANNEL_TYPE_PROXY, receiveData);
}

int32_t TransProxyGetPkgName(const char *sessionName, char *pkgName, uint16_t len)
{
    return g_channelCb.GetPkgNameBySessionName(sessionName, pkgName, len);
}

int32_t TransProxyGetUidAndPidBySessionName(const char *sessionName, int32_t *uid, int32_t *pid)
{
    return g_channelCb.GetUidAndPidBySessionName(sessionName, uid, pid);
}
