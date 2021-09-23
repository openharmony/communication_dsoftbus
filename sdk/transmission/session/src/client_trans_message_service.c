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
#include "softbus_feature_config.h"
#include "softbus_log.h"

int32_t SendBytes(int32_t sessionId, const void *data, uint32_t len)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "SendBytes: sessionId=%d", sessionId);
    if (data == NULL || len == 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t maxLen;
    if (SoftbusGetConfig(SOFTBUS_INT_MAX_BYTES_LENGTH, (unsigned char *)&maxLen, sizeof(maxLen)) != SOFTBUS_OK) {
        return SOFTBUS_GET_CONFIG_VAL_ERR;
    }
    if (len > maxLen) {
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t channelId = INVALID_CHANNEL_ID;
    int32_t type = CHANNEL_TYPE_BUTT;
    bool isEnable = false;
    if (ClientGetChannelBySessionId(sessionId, &channelId, &type, &isEnable) != SOFTBUS_OK) {
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }
    if (isEnable != true) {
        return SOFTBUS_TRANS_SESSION_OPENING;
    }

    return ClientTransChannelSendBytes(channelId, type, data, len);
}

int32_t SendMessage(int32_t sessionId, const void *data, uint32_t len)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "SendMessage: sessionId=%d", sessionId);
    if (data == NULL || len == 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t maxLen;
    if (SoftbusGetConfig(SOFTBUS_INT_MAX_MESSAGE_LENGTH, (unsigned char *)&maxLen, sizeof(maxLen)) != SOFTBUS_OK) {
        return SOFTBUS_GET_CONFIG_VAL_ERR;
    }
    if (len > maxLen) {
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t channelId = INVALID_CHANNEL_ID;
    int32_t type = CHANNEL_TYPE_BUTT;
    bool isEnable = false;
    if (ClientGetChannelBySessionId(sessionId, &channelId, &type, &isEnable) != SOFTBUS_OK) {
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }
    if (isEnable != true) {
        return SOFTBUS_TRANS_SESSION_OPENING;
    }

    return ClientTransChannelSendMessage(channelId, type, data, len);
}

int SendStream(int sessionId, const StreamData *data, const StreamData *ext, const FrameInfo *param)
{
    if ((data == NULL) || (ext == 0) || (param == NULL)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t channelId = INVALID_CHANNEL_ID;
    int32_t type = CHANNEL_TYPE_BUTT;
    bool isEnable = false;
    if (ClientGetChannelBySessionId(sessionId, &channelId, &type, &isEnable) != SOFTBUS_OK) {
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }
    if (type != CHANNEL_TYPE_UDP) {
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }
    if (isEnable != true) {
        return SOFTBUS_TRANS_SESSION_OPENING;
    }

    return ClientTransChannelSendStream(channelId, type, data, ext, param);
}

int SendFile(int sessionId, const char *sFileList[], const char *dFileList[], uint32_t fileCnt)
{
    if ((sFileList == NULL) || (fileCnt == 0)) {
        LOG_ERR("Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t channelId = INVALID_CHANNEL_ID;
    int32_t type = CHANNEL_TYPE_BUTT;
    bool isEnable = false;
    if (ClientGetChannelBySessionId(sessionId, &channelId, &type, &isEnable) != SOFTBUS_OK) {
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }
    if (type != CHANNEL_TYPE_UDP) {
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }
    if (isEnable != true) {
        return SOFTBUS_TRANS_SESSION_OPENING;
    }

    return ClientTransChannelSendFile(channelId, sFileList, dFileList, fileCnt);
}