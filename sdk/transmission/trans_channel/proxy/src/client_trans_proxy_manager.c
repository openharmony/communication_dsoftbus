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

#include "client_trans_proxy_manager.h"

#include "softbus_errcode.h"
#include "softbus_interface.h"
#include "softbus_log.h"

int32_t TransCloseProxyChannel(int32_t channelId)
{
    LOG_INFO("TransCloseProxyChannel, channelId [%d]", channelId);
    return GetServerProvideInterface()->closeChannel(channelId);
}

int32_t TransOnProxyChannelOpened(const ChannelInfo *channel)
{
    LOG_INFO("no need do anything");
    return SOFTBUS_OK;
}

int32_t TransProxyChannelSendBytes(int32_t channelId, const void *data, uint32_t len)
{
    int ret = GetServerProvideInterface()->sendMessage(channelId, data, len, TRANS_SESSION_BYTES);
    LOG_INFO("send bytes: channelId=%d, ret=%d", channelId, ret);
    return ret;
}

int32_t TransProxyChannelSendMessage(int32_t channelId, const void *data, uint32_t len)
{
    int ret = GetServerProvideInterface()->sendMessage(channelId, data, len, TRANS_SESSION_MESSAGE);
    LOG_INFO("send msg: channelId=%d, ret=%d", channelId, ret);
    return ret;
}
