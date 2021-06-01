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

#include "client_trans_message_service.h"

#include "client_trans_channel_manager.h"
#include "client_trans_session_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

int32_t SendBytes(int32_t sessionId, const void *data, uint32_t len)
{
    if ((data == NULL) || (len == 0) || (len > TRANS_BYTES_LENGTH_MAX) || sessionId < 0) {
        LOG_ERR("Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t channelId = INVALID_CHANNEL_ID;
    int32_t type = CHANNEL_TYPE_BUTT;
    int32_t ret = ClientGetChannelBySessionId(sessionId, &channelId, &type);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("get channel failed");
        return ret;
    }
    if (type == CHANNEL_TYPE_BUTT) {
        LOG_INFO("channel opening");
        return SOFTBUS_TRANS_SESSION_OPENING;
    }

    return ClientTransChannelSendBytes(channelId, type, data, len);
}

int32_t SendMessage(int32_t sessionId, const void *data, uint32_t len)
{
    if ((data == NULL) || (len == 0) || (len > TRANS_MESSAGE_LENGTH_MAX)) {
        LOG_ERR("Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t channelId = INVALID_CHANNEL_ID;
    int32_t type = CHANNEL_TYPE_BUTT;
    int32_t ret = ClientGetChannelBySessionId(sessionId, &channelId, &type);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("get channel failed");
        return ret;
    }
    if (type == CHANNEL_TYPE_BUTT) {
        LOG_INFO("channel opening");
        return SOFTBUS_TRANS_SESSION_OPENING;
    }

    return ClientTransChannelSendMessage(channelId, type, data, len);
}