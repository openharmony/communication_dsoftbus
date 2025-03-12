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
#include "client_trans_socket_manager.h"
#include "client_trans_statistics.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_adapter_mem.h"
#include "trans_log.h"

#define OH_OS_TYPE 10

int32_t CheckSendLenForBooster(unsigned int len)
{
    uint32_t dataConfig = INVALID_DATA_CONFIG;
    int32_t ret = SoftbusGetConfig(SOFTBUS_INT_MAX_BYTES_LENGTH,  (unsigned char *)&dataConfig, sizeof(dataConfig));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get config failed");
        return SOFTBUS_GET_CONFIG_VAL_ERR;
    }
    if (len > dataConfig) {
        TRANS_LOGE(TRANS_SDK, "send data over limit.len=%{public}u", len);
        return SOFTBUS_TRANS_SEND_LEN_BEYOND_LIMIT;
    }
    return SOFTBUS_OK;
}

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

static int32_t CheckBusinessTypeAndOsTypeBySessionId(int32_t sessionId, int32_t channelId, int32_t channelType,
    uint32_t len)
{
    int32_t businessType = BUSINESS_TYPE_BUTT;
    int32_t osType = OH_OS_TYPE;
    int32_t ret = ClientGetChannelBusinessTypeBySessionId(sessionId, &businessType);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret,
        TRANS_BYTES, "ClientGetChannelBusinessTypeBySessionId fail, sessionId=%{public}d", sessionId);
    ret = ClientGetChannelOsTypeBySessionId(sessionId, &osType);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret,
        TRANS_BYTES, "ClientGetChannelOsTypeBySessionId fail, sessionId=%{public}d", sessionId);

    if ((osType == OH_OS_TYPE) && (businessType != BUSINESS_TYPE_BYTE) && (businessType != BUSINESS_TYPE_NOT_CARE) &&
        (channelType != CHANNEL_TYPE_AUTH)) {
        TRANS_LOGE(TRANS_BYTES,
            "BusinessType no match, businessType=%{public}d, sessionId=%{public}d", businessType, sessionId);
        return SOFTBUS_TRANS_BUSINESS_TYPE_NOT_MATCH;
    }
    if (osType != OH_OS_TYPE && businessType == BUSINESS_TYPE_MESSAGE) {
        ret = CheckSendLenForBooster(len);
        TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret,
            TRANS_BYTES, "CheckSendLenForBooster fail, len=%{public}u, sessionId=%{public}d", len, sessionId);
    } else {
        ret = CheckSendLen(channelId, channelType, len, BUSINESS_TYPE_BYTE);
        TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret,
            TRANS_BYTES, "CheckSendLen fail, len=%{public}u, sessionId=%{public}d", len, sessionId);
    }
    return SOFTBUS_OK;
}

int SendBytes(int sessionId, const void *data, unsigned int len)
{
    if (data == NULL || len == 0) {
        TRANS_LOGW(TRANS_BYTES, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int ret = CheckPermissionState(sessionId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_BYTES,
            "SendBytes no permission, sessionId=%{public}d, len=%{public}u, ret=%{public}d", sessionId, len, ret);
        return ret;
    }

    int32_t channelId = INVALID_CHANNEL_ID;
    int32_t channelType = CHANNEL_TYPE_BUTT;
    SessionEnableStatus enableStatus = ENABLE_STATUS_INIT;
    ret = ClientGetChannelBySessionId(sessionId, &channelId, &channelType, &enableStatus);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret,
        TRANS_BYTES, "ClientGetChannelBySessionId fail, sessionId=%{public}d", sessionId);

    ret = CheckBusinessTypeAndOsTypeBySessionId(sessionId, channelId, channelType, len);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret,
        TRANS_BYTES, "CheckBusinessTypeAndOsTypeBySessionId fail, sessionId=%{public}d", sessionId);
    if (enableStatus != ENABLE_STATUS_SUCCESS) {
        TRANS_LOGE(TRANS_BYTES,
            "Enable status fail, len=%{public}u, sessionId=%{public}d", len, sessionId);
        return SOFTBUS_TRANS_SESSION_NO_ENABLE;
    }
    (void)ClientResetIdleTimeoutById(sessionId);
    UpdateChannelStatistics(sessionId, len);
    return ClientTransChannelSendBytes(channelId, channelType, data, len);
}

static int32_t CheckAsyncSendBytesFunc(int32_t channelId, int32_t channelType)
{
    bool supportTlv = false;
    bool needAck = false;
    int32_t ret = GetSupportTlvAndNeedAckById(channelId, channelType, &supportTlv, &needAck);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_BYTES, "GetSupportTlvAndNeedAckById fail, channelId=%{public}d", channelId);
        return ret;
    }
    if (!supportTlv || !needAck) {
        TRANS_LOGE(TRANS_BYTES, "supportTlv or needAck is false, not support async sendbytes, channelId=%{public}d",
            channelId);
        return SOFTBUS_TRANS_NOT_SUPPORT_ASYNC_SEND_BYTES;
    }
    return SOFTBUS_OK;
}

int32_t SendBytesAsync(int32_t socket, uint32_t dataSeq, const void *data, uint32_t len)
{
    if (data == NULL || dataSeq <= 0 || len == 0) {
        TRANS_LOGE(TRANS_BYTES, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int ret = CheckPermissionState(socket);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_BYTES,
            "no permission, socket=%{public}d, len=%{public}u, ret=%{public}d", socket, len, ret);
        return ret;
    }

    int32_t channelId = INVALID_CHANNEL_ID;
    int32_t channelType = CHANNEL_TYPE_BUTT;
    SessionEnableStatus enableStatus = ENABLE_STATUS_INIT;
    ret = ClientGetChannelBySessionId(socket, &channelId, &channelType, &enableStatus);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret,
        TRANS_BYTES, "ClientGetChannelBySessionId fail, socket=%{public}d", socket);
    ret = CheckAsyncSendBytesFunc(channelId, channelType);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret,
        TRANS_BYTES, "checkAsyncSendByts fail, socket=%{public}d", socket);
    ret = CheckBusinessTypeAndOsTypeBySessionId(socket, channelId, channelType, len);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret,
        TRANS_BYTES, "CheckBusinessTypeAndOsTypeBySessionId fail, socket=%{public}d", socket);
    if (enableStatus != ENABLE_STATUS_SUCCESS) {
        TRANS_LOGE(TRANS_BYTES,
            "session is not enable, len=%{public}u, socket=%{public}d", len, socket);
        return SOFTBUS_TRANS_SESSION_NO_ENABLE;
    }
    (void)ClientResetIdleTimeoutById(socket);
    UpdateChannelStatistics(socket, len);
    return ClientTransChannelAsyncSendBytes(channelId, channelType, data, len, dataSeq);
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
    SessionEnableStatus enableStatus = ENABLE_STATUS_INIT;
    if (ClientGetChannelBySessionId(sessionId, &channelId, &channelType, &enableStatus) != SOFTBUS_OK) {
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

    if (enableStatus != ENABLE_STATUS_SUCCESS) {
        return SOFTBUS_TRANS_SESSION_NO_ENABLE;
    }
    (void)ClientResetIdleTimeoutById(sessionId);
    UpdateChannelStatistics(sessionId, len);
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
    SessionEnableStatus enableStatus = ENABLE_STATUS_INIT;
    if (ClientGetChannelBySessionId(sessionId, &channelId, &type, &enableStatus) != SOFTBUS_OK) {
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

    if (enableStatus != ENABLE_STATUS_SUCCESS) {
        return SOFTBUS_TRANS_SESSION_NO_ENABLE;
    }
    (void)ClientResetIdleTimeoutById(sessionId);
    UpdateChannelStatistics(sessionId, data->bufLen);
    return ClientTransChannelSendStream(channelId, type, data, ext, param);
}

int SendFile(int sessionId, const char *sFileList[], const char *dFileList[], uint32_t fileCnt)
{
    if ((sFileList == NULL) || (fileCnt == 0)) {
        TRANS_LOGW(TRANS_FILE, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int ret = CheckPermissionState(sessionId);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret,
        TRANS_FILE,  "SendFile no permission, sessionId=%{public}d, ret=%{public}d", sessionId, ret);

    FileSchemaListener *fileSchemaListener = (FileSchemaListener*)SoftBusCalloc(sizeof(FileSchemaListener));
    if (fileSchemaListener == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    if (CheckFileSchema(sessionId, fileSchemaListener) == SOFTBUS_OK) {
        ret = SetSchemaCallback(fileSchemaListener->schema, sFileList, fileCnt);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_FILE, "set schema callback failed, sessionId=%{public}d, ret=%{public}d", sessionId, ret);
            SoftBusFree(fileSchemaListener);
            return ret;
        }
    }

    int32_t channelId = INVALID_CHANNEL_ID;
    int32_t type = CHANNEL_TYPE_BUTT;
    SessionEnableStatus enableStatus = ENABLE_STATUS_INIT;
    if (ClientGetChannelBySessionId(sessionId, &channelId, &type, &enableStatus) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "ClientGetChannelBySessionId failed, sessionId=%{public}d", sessionId);
        SoftBusFree(fileSchemaListener);
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }

    int32_t businessType = BUSINESS_TYPE_BUTT;
    if (ClientGetChannelBusinessTypeBySessionId(sessionId, &businessType) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "ClientGetChannelBusinessTypeBySessionId failed, sessionId=%{public}d", sessionId);
        SoftBusFree(fileSchemaListener);
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }
    if ((businessType != BUSINESS_TYPE_FILE) && (businessType != BUSINESS_TYPE_NOT_CARE)) {
        TRANS_LOGE(TRANS_FILE,
            "BusinessType no match, sessionId=%{public}d, businessType=%{public}d", sessionId, businessType);
        SoftBusFree(fileSchemaListener);
        return SOFTBUS_TRANS_BUSINESS_TYPE_NOT_MATCH;
    }

    if (enableStatus !=  ENABLE_STATUS_SUCCESS) {
        TRANS_LOGE(TRANS_FILE, "Enable status failed, sessionId=%{public}d", sessionId);
        SoftBusFree(fileSchemaListener);
        return SOFTBUS_TRANS_SESSION_NO_ENABLE;
    }
    SoftBusFree(fileSchemaListener);
    (void)ClientResetIdleTimeoutById(sessionId);
    return ClientTransChannelSendFile(channelId, type, sFileList, dFileList, fileCnt);
}
