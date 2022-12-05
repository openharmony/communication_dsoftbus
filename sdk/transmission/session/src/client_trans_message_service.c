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
#include "client_trans_file.h"
#include "client_trans_file_listener.h"
#include "client_trans_session_manager.h"
#include "client_trans_session_service.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log.h"
#include "softbus_adapter_mem.h"

int CheckSendLen(int32_t channelType, int32_t businessType, unsigned int len)
{
    ConfigType configType = (ConfigType)FindConfigType(channelType, businessType);
    if (configType == SOFTBUS_CONFIG_TYPE_MAX) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid channelType: %d, businessType: %d",
            channelType, businessType);
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t maxLen;
    if (SoftbusGetConfig(configType, (unsigned char *)&maxLen, sizeof(maxLen)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get config failed, configType: %d.", configType);
        return SOFTBUS_GET_CONFIG_VAL_ERR;
    }
    if (len > maxLen) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "send data len[%u] over limit.", len);
        return SOFTBUS_TRANS_SEND_LEN_BEYOND_LIMIT;
    }

    return SOFTBUS_OK;
}

int SendBytes(int sessionId, const void *data, unsigned int len)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "SendBytes: sessionId=%d", sessionId);
    if (data == NULL || len == 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int ret = CheckPermissionState(sessionId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SendBytes no permission, ret = %d", ret);
        return ret;
    }

    int32_t channelId = INVALID_CHANNEL_ID;
    int32_t channelType = CHANNEL_TYPE_BUTT;
    bool isEnable = false;
    if (ClientGetChannelBySessionId(sessionId, &channelId, &channelType, &isEnable) != SOFTBUS_OK) {
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }
    if (isEnable != true) {
        return SOFTBUS_TRANS_SESSION_NO_ENABLE;
    }

    if (CheckSendLen(channelType, BUSINESS_TYPE_BYTE, len) != SOFTBUS_OK) {
        return SOFTBUS_TRANS_SEND_LEN_BEYOND_LIMIT;
    }

    int32_t businessType = BUSINESS_TYPE_BUTT;
    if (ClientGetChannelBusinessTypeBySessionId(sessionId, &businessType) != SOFTBUS_OK) {
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }
    if ((businessType != BUSINESS_TYPE_BYTE) && (businessType != BUSINESS_TYPE_NOT_CARE) &&
		(channelType != CHANNEL_TYPE_AUTH)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "BusinessType no match, exp: %d", businessType);
        return SOFTBUS_TRANS_BUSINESS_TYPE_NOT_MATCH;
    }

    return ClientTransChannelSendBytes(channelId, channelType, data, len);
}

int SendMessage(int sessionId, const void *data, unsigned int len)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "SendMessage: sessionId=%d", sessionId);
    if (data == NULL || len == 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int ret = CheckPermissionState(sessionId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SendMessage no permission, ret = %d", ret);
        return ret;
    }

    int32_t channelId = INVALID_CHANNEL_ID;
    int32_t channelType = CHANNEL_TYPE_BUTT;
    bool isEnable = false;
    if (ClientGetChannelBySessionId(sessionId, &channelId, &channelType, &isEnable) != SOFTBUS_OK) {
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }
    if (isEnable != true) {
        return SOFTBUS_TRANS_SESSION_NO_ENABLE;
    }

    if (CheckSendLen(channelType, BUSINESS_TYPE_MESSAGE, len) != SOFTBUS_OK) {
        return SOFTBUS_TRANS_SEND_LEN_BEYOND_LIMIT;
    }

    int32_t businessType = BUSINESS_TYPE_BUTT;
    if (ClientGetChannelBusinessTypeBySessionId(sessionId, &businessType) != SOFTBUS_OK) {
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }
    if ((businessType != BUSINESS_TYPE_MESSAGE) && (businessType != BUSINESS_TYPE_NOT_CARE) &&
		(channelType != CHANNEL_TYPE_AUTH)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "BusinessType no match, exp: %d", businessType);
        return SOFTBUS_TRANS_BUSINESS_TYPE_NOT_MATCH;
    }

    return ClientTransChannelSendMessage(channelId, channelType, data, len);
}

int SendStream(int sessionId, const StreamData *data, const StreamData *ext, const StreamFrameInfo *param)
{
    if ((data == NULL) || (ext == NULL) || (param == NULL)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int ret = CheckPermissionState(sessionId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SendStream no permission, ret = %d", ret);
        return ret;
    }

    int32_t channelId = INVALID_CHANNEL_ID;
    int32_t type = CHANNEL_TYPE_BUTT;
    bool isEnable = false;
    if (ClientGetChannelBySessionId(sessionId, &channelId, &type, &isEnable) != SOFTBUS_OK) {
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }
    if (type != CHANNEL_TYPE_UDP) {
        return SOFTBUS_TRANS_STREAM_ONLY_UDP_CHANNEL;
    }
    if (isEnable != true) {
        return SOFTBUS_TRANS_SESSION_NO_ENABLE;
    }

    int32_t businessType = BUSINESS_TYPE_BUTT;
    if (ClientGetChannelBusinessTypeBySessionId(sessionId, &businessType) != SOFTBUS_OK) {
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }
    if ((businessType != BUSINESS_TYPE_STREAM) && (businessType != BUSINESS_TYPE_NOT_CARE)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "BusinessType no match, exp: %d", businessType);
        return SOFTBUS_TRANS_BUSINESS_TYPE_NOT_MATCH;
    }

    return ClientTransChannelSendStream(channelId, type, data, ext, param);
}

int SendFile(int sessionId, const char *sFileList[], const char *dFileList[], uint32_t fileCnt)
{
    if ((sFileList == NULL) || (fileCnt == 0)) {
        LOG_ERR("Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int ret = CheckPermissionState(sessionId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SendFile no permission, ret = %d", ret);
        return ret;
    }

    FileSchemaListener *fileSchemaListener = (FileSchemaListener*)SoftBusCalloc(sizeof(FileSchemaListener));
    if (fileSchemaListener == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    if (CheckFileSchema(sessionId, fileSchemaListener) == SOFTBUS_OK) {
        if (SetSchemaCallback(fileSchemaListener->schema, sFileList, fileCnt) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "set schema callback failed");
            SoftBusFree(fileSchemaListener);
            return SOFTBUS_ERR;
        }
    }

    int32_t channelId = INVALID_CHANNEL_ID;
    int32_t type = CHANNEL_TYPE_BUTT;
    bool isEnable = false;
    if (ClientGetChannelBySessionId(sessionId, &channelId, &type, &isEnable) != SOFTBUS_OK) {
        SoftBusFree(fileSchemaListener);
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }

    int32_t businessType = BUSINESS_TYPE_BUTT;
    if (ClientGetChannelBusinessTypeBySessionId(sessionId, &businessType) != SOFTBUS_OK) {
        SoftBusFree(fileSchemaListener);
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }
    if ((businessType != BUSINESS_TYPE_FILE) && (businessType != BUSINESS_TYPE_NOT_CARE)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "BusinessType no match, exp: %d", businessType);
        SoftBusFree(fileSchemaListener);
        return SOFTBUS_TRANS_BUSINESS_TYPE_NOT_MATCH;
    }

    if (isEnable != true) {
        SoftBusFree(fileSchemaListener);
        return SOFTBUS_TRANS_SESSION_NO_ENABLE;
    }
    SoftBusFree(fileSchemaListener);
    return ClientTransChannelSendFile(channelId, type, sFileList, dFileList, fileCnt);
}
