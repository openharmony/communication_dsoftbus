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

#include "trans_client_proxy.h"

#include "client_trans_channel_callback.h"
#include "softbus_def.h"
#include "softbus_errcode.h"

int32_t ClientIpcOnChannelOpened(const char *pkgName, const char *sessionName, const ChannelInfo *channel)
{
    (void)pkgName;
    return TransOnChannelOpened(sessionName, channel);
}

int32_t ClientIpcOnChannelOpenFailed(const char *pkgName, int32_t channelId, int32_t channelType, int32_t errCode)
{
    (void)pkgName;
    return TransOnChannelOpenFailed(channelId, channelType, errCode);
}

int32_t ClientIpcOnChannelLinkDown(const char *pkgName, const char *networkId, int32_t routeType)
{
    (void)pkgName;
    return TransOnChannelLinkDown(networkId, routeType);
}

int32_t ClientIpcOnChannelClosed(const char *pkgName, int32_t channelId, int32_t channelType)
{
    (void)pkgName;
    return TransOnChannelClosed(channelId, channelType);
}

int32_t ClientIpcOnChannelMsgReceived(const char *pkgName, int32_t channelId, int32_t channelType, const void *data,
                                      uint32_t len, int32_t type)
{
    (void)pkgName;
    return TransOnChannelMsgReceived(channelId, channelType, data, len, (SessionPktType)type);
}

int32_t ClientIpcOnChannelQosEvent(const char *pkgName, const QosParam *param)
{
    (void)pkgName;
    (void)param;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}
