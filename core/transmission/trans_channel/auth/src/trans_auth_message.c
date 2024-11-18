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
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "trans_log.h"
#include "lnn_lane_interface.h"

#define CODE_OPEN_AUTH_MSG_CHANNEL 4

int32_t TransAuthChannelMsgPack(cJSON *msg, const AppInfo *appInfo)
{
    if (appInfo == NULL || msg == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (appInfo->reqId[0] == '\0') {
        int32_t ret = GenerateRandomStr((char *)(appInfo->reqId), REQ_ID_SIZE_MAX);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SVC, "GenerateRandomStr fail");
            return ret;
        }
    }
    if (!AddNumberToJsonObject(msg, "CODE", CODE_OPEN_AUTH_MSG_CHANNEL) ||
        !AddStringToJsonObject(msg, "DEVICE_ID", appInfo->myData.deviceId) ||
        !AddStringToJsonObject(msg, "PEER_NETWORK_ID", appInfo->peerNetWorkId) ||
        !AddStringToJsonObject(msg, "PKG_NAME", appInfo->myData.pkgName) ||
        !AddStringToJsonObject(msg, "SRC_BUS_NAME", appInfo->myData.sessionName) ||
        !AddStringToJsonObject(msg, "DST_BUS_NAME", appInfo->peerData.sessionName) ||
        !AddStringToJsonObject(msg, "REQ_ID", appInfo->reqId) ||
        !AddNumberToJsonObject(msg, "MTU_SIZE", (int32_t)appInfo->myData.dataConfig) ||
        !AddNumberToJsonObject(msg, "API_VERSION", (int32_t)appInfo->myData.apiVersion) ||
        !AddNumberToJsonObject(msg, "ROUTE_TYPE", (int32_t)appInfo->routeType)) {
        TRANS_LOGE(TRANS_SVC, "failed");
        return SOFTBUS_CREATE_JSON_ERR;
    }
    if (appInfo->linkType == LANE_HML_RAW) {
        if (!AddNumberToJsonObject(msg, "LANE_LINK_TYPE", appInfo->linkType) ||
            !AddStringToJsonObject(msg, "LOCAL_HML_RAW_IP", appInfo->myData.addr) ||
            !AddStringToJsonObject(msg, "PEER_HML_RAW_IP", appInfo->peerData.addr)) {
            TRANS_LOGE(TRANS_SVC, "add linkType and ip failed");
            return SOFTBUS_CREATE_JSON_ERR;
        }
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
        TRANS_LOGE(TRANS_SVC, "parse json failed.");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    int32_t errcode;
    if (GetJsonObjectInt32Item(obj, "ERR_CODE", &errcode)) {
        TRANS_LOGE(TRANS_SVC, "peer failed: errcode=%{public}d.", errcode);
        cJSON_Delete(obj);
        return errcode;
    }
    if (!GetJsonObjectStringItem(obj, "DEVICE_ID", appInfo->peerData.deviceId, DEVICE_ID_SIZE_MAX) ||
        !GetJsonObjectStringItem(obj, "PKG_NAME", appInfo->peerData.pkgName, PKG_NAME_SIZE_MAX) ||
        !GetJsonObjectStringItem(obj, "SRC_BUS_NAME", appInfo->peerData.sessionName, SESSION_NAME_SIZE_MAX) ||
        !GetJsonObjectStringItem(obj, "DST_BUS_NAME", appInfo->myData.sessionName, SESSION_NAME_SIZE_MAX) ||
        !GetJsonObjectStringItem(obj, "REQ_ID", appInfo->reqId, REQ_ID_SIZE_MAX)) {
        cJSON_Delete(obj);
        TRANS_LOGE(TRANS_SVC, "get json object failed.");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    if (!GetJsonObjectStringItem(obj, "PEER_NETWORK_ID", appInfo->peerNetWorkId, DEVICE_ID_SIZE_MAX)) {
        TRANS_LOGW(TRANS_SVC, "peerNetWorkId is null.");
    }
    if (!GetJsonObjectNumberItem(obj, "MTU_SIZE", (int32_t *)&(appInfo->peerData.dataConfig))) {
        TRANS_LOGW(TRANS_SVC, "peer dataconfig is null.");
    }
    if (!GetJsonObjectNumberItem(obj, "ROUTE_TYPE", (int32_t *)&(appInfo->routeType))) {
        TRANS_LOGW(TRANS_SVC, "routeType is null.");
    }
    if (!GetJsonObjectNumberItem(obj, "API_VERSION", (int32_t *)&appInfo->myData.apiVersion)) {
        TRANS_LOGW(TRANS_SVC, "apiVersion is null.");
    }
    if (GetJsonObjectNumberItem(obj, "LANE_LINK_TYPE", (int32_t *)&(appInfo->linkType))
        && (appInfo->linkType == LANE_HML_RAW)) {
        if (!GetJsonObjectStringItem(obj, "LOCAL_HML_RAW_IP", appInfo->peerData.addr, IP_LEN) ||
            !GetJsonObjectStringItem(obj, "PEER_HML_RAW_IP", appInfo->myData.addr, IP_LEN)) {
            TRANS_LOGE(TRANS_SVC, "get linkType and ip failed");
            cJSON_Delete(obj);
            return SOFTBUS_PARSE_JSON_ERR;
        }
    }
    cJSON_Delete(obj);
    return SOFTBUS_OK;
}

int32_t TransAuthChannelErrorPack(int32_t errcode, const char *errMsg, char *cJsonStr, int32_t maxLen)
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
        TRANS_LOGE(TRANS_SVC, "add json object failed.");
        return SOFTBUS_CREATE_JSON_ERR;
    }
    char *data = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);
    if (data == NULL) {
        TRANS_LOGE(TRANS_SVC, "convert json to string failed.");
        return SOFTBUS_CREATE_JSON_ERR;
    }
    if (memcpy_s(cJsonStr, maxLen, data, strlen(data)) != EOK) {
        cJSON_free(data);
        return SOFTBUS_MEM_ERR;
    }
    cJSON_free(data);
    return SOFTBUS_OK;
}
