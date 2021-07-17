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

#include "softbus_message_open_channel.h"

#include <securec.h>

#include "base64.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"

#define BASE64KEY 45 // Base64 encrypt SessionKey length

char *PackError(int errCode, const char *errDesc)
{
    if (errDesc == NULL) {
        LOG_ERR("invalid param");
        return NULL;
    }
    cJSON *json =  cJSON_CreateObject();
    if (json == NULL) {
        LOG_ERR("Cannot create cJSON object");
        return NULL;
    }
    if (!AddNumberToJsonObject(json, CODE, CODE_OPEN_CHANNEL) ||
        !AddNumberToJsonObject(json, ERR_CODE, errCode) ||
        !AddStringToJsonObject(json, ERR_DESC, errDesc)) {
        cJSON_Delete(json);
        LOG_ERR("add to cJSON object failed");
        return NULL;
    }
    char *data = cJSON_PrintUnformatted(json);
    if (data == NULL) {
        LOG_ERR("cJSON_PrintUnformatted failed");
    }
    cJSON_Delete(json);
    return data;
}

char *PackRequest(const AppInfo *appInfo)
{
    if (appInfo == NULL) {
        LOG_ERR("invalid param");
        return NULL;
    }

    cJSON *json =  cJSON_CreateObject();
    if (json == NULL) {
        LOG_ERR("Cannot create cJSON object");
        return NULL;
    }
    unsigned char encodeSessionKey[BASE64KEY] = {0};
    size_t keyLen = 0;
    int ret = mbedtls_base64_encode(encodeSessionKey, BASE64KEY, &keyLen, (unsigned char*)appInfo->sessionKey,
        SESSION_KEY_LENGTH);
    if (ret != 0) {
        cJSON_Delete(json);
        return NULL;
    }
    if (!AddNumberToJsonObject(json, CODE, CODE_OPEN_CHANNEL) ||
        !AddNumberToJsonObject(json, API_VERSION, appInfo->myData.apiVersion) ||
        !AddStringToJsonObject(json, BUS_NAME, appInfo->peerData.sessionName) ||
        !AddStringToJsonObject(json, GROUP_ID, appInfo->groupId) ||
        !AddNumberToJsonObject(json, UID, appInfo->myData.uid) ||
        !AddNumberToJsonObject(json, PID, appInfo->myData.pid) ||
        !AddStringToJsonObject(json, SESSION_KEY, (char*)encodeSessionKey)) {
        cJSON_Delete(json);
        return NULL;
    }
    char *authState = (char*)appInfo->myData.authState;
    if (appInfo->myData.apiVersion != API_V1) {
        if (!AddStringToJsonObject(json, PKG_NAME, appInfo->myData.pkgName) ||
            !AddStringToJsonObject(json, CLIENT_BUS_NAME, appInfo->myData.sessionName) ||
            !AddStringToJsonObject(json, AUTH_STATE, authState)) {
            cJSON_Delete(json);
            return NULL;
        }
    }
    char *data = cJSON_PrintUnformatted(json);
    if (data == NULL) {
        LOG_ERR("cJSON_PrintUnformatted failed");
    }
    cJSON_Delete(json);
    return data;
}

int UnpackRequest(const cJSON *msg, AppInfo *appInfo)
{
    if (msg == NULL || appInfo == NULL) {
        LOG_ERR("invalid param");
        return SOFTBUS_ERR;
    }
    int apiVersion = API_V1;
    (void)GetJsonObjectNumberItem(msg, API_VERSION, &apiVersion);
    char sessionKey[BASE64KEY] = {0};
    if (!GetJsonObjectStringItem(msg, BUS_NAME, (appInfo->myData.sessionName), SESSION_NAME_SIZE_MAX) ||
        !GetJsonObjectStringItem(msg, GROUP_ID, (appInfo->groupId), GROUP_ID_SIZE_MAX) ||
        !GetJsonObjectStringItem(msg, SESSION_KEY, sessionKey, sizeof(sessionKey))) {
        LOG_ERR("Failed to get BUS_NAME");
        return SOFTBUS_ERR;
    }
    appInfo->peerData.apiVersion = apiVersion;
    appInfo->peerData.uid = -1;
    appInfo->peerData.pid = -1;
    (void)GetJsonObjectNumberItem(msg, UID, &appInfo->peerData.uid);
    (void)GetJsonObjectNumberItem(msg, PID, &appInfo->peerData.pid);

    size_t len = 0;
    int ret = mbedtls_base64_decode((unsigned char *)appInfo->sessionKey, SESSION_KEY_LENGTH,
        &len, (unsigned char *)sessionKey, strlen(sessionKey));
    (void)memset_s(sessionKey, sizeof(sessionKey), 0, sizeof(sessionKey));
    if (len != SESSION_KEY_LENGTH) {
        LOG_ERR("Failed to decode sessionKey %d, len %d", ret, len);
        return SOFTBUS_ERR;
    }
    if (apiVersion == API_V1) {
        return SOFTBUS_OK;
    }

    if (!GetJsonObjectStringItem(msg, PKG_NAME, (appInfo->peerData.pkgName), PKG_NAME_SIZE_MAX) ||
        !GetJsonObjectStringItem(msg, CLIENT_BUS_NAME, (appInfo->peerData.sessionName), SESSION_NAME_SIZE_MAX) ||
        !GetJsonObjectStringItem(msg, AUTH_STATE, (appInfo->peerData.authState), AUTH_STATE_SIZE_MAX)) {
        LOG_ERR("Failed to get pkgName");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

char *PackReply(const AppInfo *appInfo)
{
    if (appInfo == NULL) {
        LOG_ERR("invalid param");
        return NULL;
    }
    cJSON *json =  cJSON_CreateObject();
    if (json == NULL) {
        LOG_ERR("Cannot create cJSON object");
        return NULL;
    }
    if (!AddNumberToJsonObject(json, CODE, CODE_OPEN_CHANNEL) ||
        !AddNumberToJsonObject(json, API_VERSION, appInfo->myData.apiVersion) ||
        !AddStringToJsonObject(json, DEVICE_ID, appInfo->myData.deviceId) ||
        !AddNumberToJsonObject(json, UID, appInfo->myData.uid) ||
        !AddNumberToJsonObject(json, PID, appInfo->myData.pid)) {
        LOG_ERR("Failed to add items");
        cJSON_Delete(json);
        return NULL;
    }
    if (appInfo->myData.apiVersion != API_V1) {
        char *authState = (char*)appInfo->myData.authState;
        if (!AddStringToJsonObject(json, PKG_NAME, appInfo->myData.pkgName) ||
            !AddStringToJsonObject(json, AUTH_STATE, authState)) {
            LOG_ERR("Failed to add pkgName or authState");
            cJSON_Delete(json);
            return NULL;
        }
    }
    char *data = cJSON_PrintUnformatted(json);
    if (data == NULL) {
        LOG_ERR("cJSON_PrintUnformatted failed");
    }
    cJSON_Delete(json);
    return data;
}

int UnpackReply(const cJSON *msg, AppInfo *appInfo)
{
    if (msg == NULL || appInfo == NULL) {
        LOG_ERR("Invalid param");
        return SOFTBUS_ERR;
    }

    char deviceId[DEVICE_ID_SIZE_MAX] = {0};
    if (!GetJsonObjectStringItem(msg, DEVICE_ID, deviceId, DEVICE_ID_SIZE_MAX)) {
        LOG_ERR("Failed to get deviceId");
        return SOFTBUS_ERR;
    }
    if (strcmp(deviceId, appInfo->peerData.deviceId) != 0) {
        LOG_ERR("Invalid deviceId");
        return SOFTBUS_ERR;
    }

    int apiVersion = API_V1;
    (void)GetJsonObjectNumberItem(msg, API_VERSION, &apiVersion);
    appInfo->peerData.apiVersion = apiVersion;
    appInfo->peerData.uid = -1;
    appInfo->peerData.pid = -1;
    (void)GetJsonObjectNumberItem(msg, UID, &appInfo->peerData.uid);
    (void)GetJsonObjectNumberItem(msg, PID, &appInfo->peerData.pid);

    if (apiVersion != API_V1) {
        if (!GetJsonObjectStringItem(msg, PKG_NAME, (appInfo->peerData.pkgName), PKG_NAME_SIZE_MAX) ||
            !GetJsonObjectStringItem(msg, AUTH_STATE, (appInfo->peerData.authState), AUTH_STATE_SIZE_MAX)) {
            LOG_ERR("Failed to get pkgName or authState");
            return SOFTBUS_ERR;
        }
    }

    return SOFTBUS_OK;
}
