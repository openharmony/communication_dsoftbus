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

#include "client_trans_channel_manager.h"

#include "client_trans_channel_manager_weak.h"
#include "client_trans_proxy_manager.h"
#ifndef SOFTBUS_WATCH
#include "client_trans_tcp_direct_message.h"
#endif
#include "softbus_errcode.h"
#include "softbus_log.h"

int32_t ClientTransChannelInit(void)
{
#ifndef SOFTBUS_WATCH
    if (TransTdcManagerInit() != SOFTBUS_OK) {
        LOG_ERR("trans tcp direct manager init failed.");
        return SOFTBUS_ERR;
    }
#endif
    return SOFTBUS_OK;
}

void ClientTransChannelDeinit(void)
{
#ifndef SOFTBUS_WATCH
    TransTdcManagerDeinit();
#endif
}

int32_t ClientTransCloseChannel(int32_t channelId, int32_t type)
{
    if (channelId < 0) {
        LOG_ERR("Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = SOFTBUS_OK;
    switch (type) {
        case CHANNEL_TYPE_PROXY:
            ret = TransCloseProxyChannel(channelId);
            break;
#ifndef SOFTBUS_WATCH
        case CHANNEL_TYPE_TCP_DIRECT:
            TransTdcCloseChannel(channelId);
            break;
#endif
        default:
            LOG_ERR("Invalid type");
            return SOFTBUS_ERR;
    }
    return ret;
}

int32_t ClientTransChannelSendBytes(int32_t channelId, int32_t type, const void *data, uint32_t len)
{
    if ((data == NULL) || (len == 0)) {
        LOG_ERR("Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = SOFTBUS_OK;
    switch (type) {
        case CHANNEL_TYPE_PROXY:
            ret = TransProxyChannelSendBytes(channelId, data, len);
            break;
#ifndef SOFTBUS_WATCH
        case CHANNEL_TYPE_TCP_DIRECT:
            ret = TransTdcSendBytes(channelId, data, len);
            break;
#endif
        default:
            LOG_ERR("Invalid type");
            return SOFTBUS_ERR;
    }
    return ret;
}

int32_t ClientTransChannelSendMessage(int32_t channelId, int32_t type, const void *data, uint32_t len)
{
    if ((data == NULL) || (len == 0)) {
        LOG_ERR("Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = SOFTBUS_OK;
    switch (type) {
        case CHANNEL_TYPE_PROXY:
            ret = TransProxyChannelSendMessage(channelId, data, len);
            break;
#ifndef SOFTBUS_WATCH
        case CHANNEL_TYPE_TCP_DIRECT:
            ret = TransTdcSendMessage(channelId, data, len);
            break;
#endif
        default:
            LOG_ERR("Invalid type");
            return SOFTBUS_ERR;
    }
    return ret;
}