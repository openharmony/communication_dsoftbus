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
#include "softbus_adapter_mem.h"
#include "trans_log.h"

int CheckSendLen(int32_t channelId, int32_t channelType, unsigned int len, int32_t businessType)
{
    uint32_t dataConfig = INVALID_DATA_CONFIG;
    if (ClientGetDataConfigByChannelId(channelId, channelType, &dataConfig) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get config failed.");
        return SOFTBUS_GET_CONFIG_VAL_ERR;
    }
    if (dataConfig == 0) {
        ConfigType configType = (ConfigType)GetDefaultConfigType(channelType, businessType);
        if (configType == SOFTBUS_CONFIG_TYPE_MAX) {
            TRANS_LOGE(TRANS_SDK, "Invalid channelType=%{public}d, businessType=%{public}d",
                channelType, businessType);
            return SOFTBUS_INVALID_PARAM;
        }
        if (SoftbusGetConfig(configType, (unsigned char *)&dataConfig, sizeof(dataConfig)) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "get config failed, configType=%{public}d.", configType);
            return SOFTBUS_GET_CONFIG_VAL_ERR;
        }
    }
    TRANS_LOGI(TRANS_SDK, "channelId=%{public}d, sendDataLen=%{public}u, maxDataLen=%{public}u",
        channelId, len, dataConfig);
    if (len > dataConfig) {
        TRANS_LOGE(TRANS_SDK, "send data over limit.len=%{public}u", len);
        return SOFTBUS_TRANS_SEND_LEN_BEYOND_LIMIT;
    }

    return SOFTBUS_OK;
}

int SendBytes(int sessionId, const void *data, unsigned int len)
{
    TRANS_LOGI(TRANS_BYTES, "sessionId=%{public}d, len=%{public}d", sessionId, len);
    if (data == NULL || len == 0) {
        TRANS_LOGW(TRANS_BYTES, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int ret = CheckPermissionState(sessionId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_BYTES, "SendBytes no permission, ret=%{public}d", ret);
        return ret;
    }

    int32_t channelId = INVALID_CHANNEL_ID;
    int32_t channelType = CHANNEL_TYPE_BUTT;
    bool isEnable = false;
    if (ClientGetChannelBySessionId(sessionId, &channelId, &channelType, &isEnable) != SOFTBUS_OK) {
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }

    int32_t businessType = BUSINESS_TYPE_BUTT;
    if (ClientGetChannelBusinessTypeBySessionId(sessionId, &businessType) != SOFTBUS_OK) {
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }
    if ((businessType != BUSINESS_TYPE_BYTE) && (businessType != BUSINESS_TYPE_NOT_CARE) &&
        (channelType != CHANNEL_TYPE_AUTH)) {
        TRANS_LOGE(TRANS_BYTES, "BusinessType no match, businessType=%{public}d", businessType);
        return SOFTBUS_TRANS_BUSINESS_TYPE_NOT_MATCH;
    }

    int checkRet = CheckSendLen(channelId, channelType, len, BUSINESS_TYPE_BYTE);
    if (checkRet != SOFTBUS_OK) {
        return checkRet;
    }

    if (!isEnable) {
        return SOFTBUS_TRANS_SESSION_NO_ENABLE;
    }
    (void)ClientResetIdleTimeoutById(sessionId);
    return ClientTransChannelSendBytes(channelId, channelType, data, len);
}

int SendMessage(int sessionId, const void *data, unsigned int len)
{
    TRANS_LOGI(TRANS_MSG, "sessionId=%{public}d, len=%{public}d", sessionId, len);
    if (data == NULL || len == 0) {
        TRANS_LOGW(TRANS_MSG, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int ret = CheckPermissionState(sessionId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_MSG, "SendMessage no permission, ret=%{public}d", ret);
        return ret;
    }

    int32_t channelId = INVALID_CHANNEL_ID;
    int32_t channelType = CHANNEL_TYPE_BUTT;
    bool isEnable = false;
    if (ClientGetChannelBySessionId(sessionId, &channelId, &channelType, &isEnable) != SOFTBUS_OK) {
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }

    int32_t businessType = BUSINESS_TYPE_BUTT;
    if (ClientGetChannelBusinessTypeBySessionId(sessionId, &businessType) != SOFTBUS_OK) {
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }
    if ((businessType != BUSINESS_TYPE_MESSAGE) && (businessType != BUSINESS_TYPE_NOT_CARE) &&
        (channelType != CHANNEL_TYPE_AUTH)) {
        TRANS_LOGE(TRANS_MSG, "BusinessType no match, businessType=%{public}d", businessType);
        return SOFTBUS_TRANS_BUSINESS_TYPE_NOT_MATCH;
    }

    int checkRet = CheckSendLen(channelId, channelType, len, BUSINESS_TYPE_MESSAGE);
    if (checkRet != SOFTBUS_OK) {
        return checkRet;
    }

    if (!isEnable) {
        return SOFTBUS_TRANS_SESSION_NO_ENABLE;
    }
    (void)ClientResetIdleTimeoutById(sessionId);
    return ClientTransChannelSendMessage(channelId, channelType, data, len);
}

int SendStream(int sessionId, const StreamData *data, const StreamData *ext, const StreamFrameInfo *param)
{
    if ((data == NULL) || (ext == NULL) || (param == NULL)) {
        TRANS_LOGW(TRANS_STREAM, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int ret = CheckPermissionState(sessionId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_STREAM, "SendStream no permission, ret=%{public}d", ret);
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

    int32_t businessType = BUSINESS_TYPE_BUTT;
    if (ClientGetChannelBusinessTypeBySessionId(sessionId, &businessType) != SOFTBUS_OK) {
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }
    if ((businessType != BUSINESS_TYPE_STREAM) && (businessType != BUSINESS_TYPE_NOT_CARE)) {
        TRANS_LOGE(TRANS_STREAM, "BusinessType no match, businessType=%{public}d", businessType);
        return SOFTBUS_TRANS_BUSINESS_TYPE_NOT_MATCH;
    }

    if (!isEnable) {
        return SOFTBUS_TRANS_SESSION_NO_ENABLE;
    }
    (void)ClientResetIdleTimeoutById(sessionId);
    return ClientTransChannelSendStream(channelId, type, data, ext, param);
}

int SendFile(int sessionId, const char *sFileList[], const char *dFileList[], uint32_t fileCnt)
{
    if ((sFileList == NULL) || (fileCnt == 0)) {
        TRANS_LOGW(TRANS_FILE, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int ret = CheckPermissionState(sessionId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "SendFile no permission, ret=%{public}d", ret);
        return ret;
    }

    FileSchemaListener *fileSchemaListener = (FileSchemaListener*)SoftBusCalloc(sizeof(FileSchemaListener));
    if (fileSchemaListener == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    if (CheckFileSchema(sessionId, fileSchemaListener) == SOFTBUS_OK) {
        if (SetSchemaCallback(fileSchemaListener->schema, sFileList, fileCnt) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_FILE, "set schema callback failed");
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
        TRANS_LOGE(TRANS_FILE, "BusinessType no match, businessType=%{public}d", businessType);
        SoftBusFree(fileSchemaListener);
        return SOFTBUS_TRANS_BUSINESS_TYPE_NOT_MATCH;
    }

    if (!isEnable) {
        SoftBusFree(fileSchemaListener);
        return SOFTBUS_TRANS_SESSION_NO_ENABLE;
    }
    SoftBusFree(fileSchemaListener);
    (void)ClientResetIdleTimeoutById(sessionId);
    return ClientTransChannelSendFile(channelId, type, sFileList, dFileList, fileCnt);
}
