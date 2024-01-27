/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "trans_auth_message.h"

#include "securec.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_utils.h"
#include "trans_log.h"

#define CODE_OPEN_AUTH_MSG_CHANNEL 4

int32_t TransAuthChannelMsgPack(cJSON *msg, const AppInfo *appInfo)
{
    if (appInfo == NULL || msg == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (appInfo->reqId[0] == '\0') {
        if (GenerateRandomStr((char *)(appInfo->reqId), REQ_ID_SIZE_MAX) != SOFTBUS_OK) {
            return SOFTBUS_ERR;
        }
    }
    if (!AddNumberToJsonObject(msg, "CODE", CODE_OPEN_AUTH_MSG_CHANNEL) ||
        !AddStringToJsonObject(msg, "DEVICE_ID", appInfo->myData.deviceId) ||
        !AddStringToJsonObject(msg, "PKG_NAME", appInfo->myData.pkgName) ||
        !AddStringToJsonObject(msg, "SRC_BUS_NAME", appInfo->myData.sessionName) ||
        !AddStringToJsonObject(msg, "DST_BUS_NAME", appInfo->peerData.sessionName) ||
        !AddStringToJsonObject(msg, "REQ_ID", appInfo->reqId) ||
        !AddNumberToJsonObject(msg, "MTU_SIZE", (int)appInfo->myData.dataConfig)) {
        TRANS_LOGE(TRANS_SVC, "failed");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransAuthChannelMsgUnpack(const char *msg, AppInfo *appInfo, int32_t len)
{
    if (msg == NULL || appInfo == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    cJSON *obj = cJSON_ParseWithLength(msg, len);
    if (obj == NULL) {
        return SOFTBUS_PARSE_JSON_ERR;
    }
    int32_t errcode;
    if (GetJsonObjectNumberItem(obj, "ERR_CODE", &errcode)) {
        TRANS_LOGE(TRANS_SVC, "unpack errcode=%{public}d", errcode);
        cJSON_Delete(obj);
        return SOFTBUS_ERR;
    }
    if (!GetJsonObjectStringItem(obj, "DEVICE_ID", appInfo->peerData.deviceId, DEVICE_ID_SIZE_MAX) ||
        !GetJsonObjectStringItem(obj, "PKG_NAME", appInfo->peerData.pkgName, PKG_NAME_SIZE_MAX) ||
        !GetJsonObjectStringItem(obj, "SRC_BUS_NAME", appInfo->peerData.sessionName, SESSION_NAME_SIZE_MAX) ||
        !GetJsonObjectStringItem(obj, "DST_BUS_NAME", appInfo->myData.sessionName, SESSION_NAME_SIZE_MAX) ||
        !GetJsonObjectStringItem(obj, "REQ_ID", appInfo->reqId, REQ_ID_SIZE_MAX)) {
        cJSON_Delete(obj);
        return SOFTBUS_PARSE_JSON_ERR;
    }
    if (!GetJsonObjectNumberItem(obj, "MTU_SIZE", (int32_t *)&(appInfo->peerData.dataConfig))) {
        TRANS_LOGW(TRANS_SVC, "peer dataconfig is null.");
    }
    cJSON_Delete(obj);
    return SOFTBUS_OK;
}

int32_t TransAuthChannelErrorPack(int32_t errcode, const char *errMsg, char *cJsonStr,
    int32_t maxLen)
{
    if (errMsg == NULL || cJsonStr == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    cJSON *obj = cJSON_CreateObject();
    if (obj == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    if (!AddNumberToJsonObject(obj, "CODE", CODE_OPEN_AUTH_MSG_CHANNEL) ||
        !AddNumberToJsonObject(obj, "ERR_CODE", errcode) ||
        !AddStringToJsonObject(obj, "ERR_DESC", errMsg)) {
        cJSON_Delete(obj);
        return SOFTBUS_PARSE_JSON_ERR;
    }
    char *data = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);
    if (data == NULL) {
        return SOFTBUS_PARSE_JSON_ERR;
    }
    if (memcpy_s(cJsonStr, maxLen, data, strlen(data)) != EOK) {
        cJSON_free(data);
        return SOFTBUS_MEM_ERR;
    }
    cJSON_free(data);
    return SOFTBUS_OK;
}