/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include <stdatomic.h>

#include "softbus_access_token_adapter.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"
#include "softbus_utils.h"
#include "trans_log.h"

#define BASE64KEY 45 // Base64 encrypt SessionKey length
#define INVALID_USER_ID (-1)

char *PackError(int32_t errCode, const char *errDesc)
{
    if (errDesc == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param");
        return NULL;
    }
    cJSON *json =  cJSON_CreateObject();
    if (json == NULL) {
        TRANS_LOGE(TRANS_CTRL, "Cannot create cJSON object");
        return NULL;
    }
    if (!AddNumberToJsonObject(json, CODE, CODE_OPEN_CHANNEL) ||
        !AddNumberToJsonObject(json, ERR_CODE, errCode) ||
        !AddStringToJsonObject(json, ERR_DESC, errDesc)) {
        cJSON_Delete(json);
        TRANS_LOGE(TRANS_CTRL, "add to cJSON object failed");
        return NULL;
    }
    char *data = cJSON_PrintUnformatted(json);
    if (data == NULL) {
        TRANS_LOGE(TRANS_CTRL, "cJSON_PrintUnformatted failed");
    }
    cJSON_Delete(json);
    return data;
}

static int32_t PackFirstData(const AppInfo *appInfo, cJSON *json)
{
    TRANS_LOGD(TRANS_CTRL, "begin to pack first data");
    uint8_t *encodeFastData = (uint8_t *)SoftBusCalloc(BASE64_FAST_DATA_LEN);
    if (encodeFastData == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc encode fast data failed.");
        return SOFTBUS_MALLOC_ERR;
    }

    uint32_t outLen;
    char *buf = TransTdcPackFastData(appInfo, &outLen);
    if (buf == NULL) {
        TRANS_LOGE(TRANS_CTRL, "failed to pack bytes.");
        SoftBusFree(encodeFastData);
        return SOFTBUS_ENCRYPT_ERR;
    }
    if (outLen != appInfo->fastTransDataSize + FAST_TDC_EXT_DATA_SIZE) {
        TRANS_LOGE(TRANS_CTRL, "pack bytes len error, outlen=%{public}d", outLen);
        SoftBusFree(buf);
        SoftBusFree(encodeFastData);
        return SOFTBUS_ENCRYPT_ERR;
    }
    size_t fastDataSize = 0;
    int32_t ret = SoftBusBase64Encode(encodeFastData, BASE64_FAST_DATA_LEN, &fastDataSize,
        (const unsigned char *)buf, outLen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "base64 encode failed.");
        SoftBusFree(encodeFastData);
        SoftBusFree(buf);
        return SOFTBUS_DECRYPT_ERR;
    }
    if (!AddStringToJsonObject(json, FIRST_DATA, (char *)encodeFastData)) {
        TRANS_LOGE(TRANS_CTRL, "add first data failed.");
        SoftBusFree(encodeFastData);
        SoftBusFree(buf);
        return SOFTBUS_PARSE_JSON_ERR;
    }
    SoftBusFree(encodeFastData);
    SoftBusFree(buf);
    return SOFTBUS_OK;
}

static int32_t JsonObjectPackRequestEx(const AppInfo *appInfo, cJSON *json, unsigned char *encodeSessionKey)
{
    if (!AddNumberToJsonObject(json, CODE, CODE_OPEN_CHANNEL) ||
        !AddNumberToJsonObject(json, API_VERSION, appInfo->myData.apiVersion) ||
        !AddStringToJsonObject(json, BUS_NAME, appInfo->peerData.sessionName) ||
        !AddStringToJsonObject(json, GROUP_ID, appInfo->groupId) ||
        !AddNumberToJsonObject(json, UID, appInfo->myData.uid) ||
        !AddNumberToJsonObject(json, PID, appInfo->myData.pid) ||
        !AddStringToJsonObject(json, SESSION_KEY, (char *)encodeSessionKey) ||
        !AddNumberToJsonObject(json, MTU_SIZE, (int32_t)appInfo->myData.dataConfig)) {
        return SOFTBUS_PARSE_JSON_ERR;
    }

    if (!AddNumberToJsonObject(json, TRANS_CAPABILITY, (int32_t)appInfo->channelCapability)) {
        return SOFTBUS_PARSE_JSON_ERR;
    }

    char *authState = (char *)appInfo->myData.authState;
    if (appInfo->myData.apiVersion != API_V1 && (!AddStringToJsonObject(json, PKG_NAME, appInfo->myData.pkgName) ||
        !AddStringToJsonObject(json, CLIENT_BUS_NAME, appInfo->myData.sessionName) ||
        !AddStringToJsonObject(json, AUTH_STATE, authState) ||
        !AddNumberToJsonObject(json, MSG_ROUTE_TYPE, appInfo->routeType))) {
        return SOFTBUS_PARSE_JSON_ERR;
    }
    (void)AddNumberToJsonObject(json, BUSINESS_TYPE, appInfo->businessType);
    (void)AddNumberToJsonObject(json, AUTO_CLOSE_TIME, appInfo->autoCloseTime);
    (void)AddNumberToJsonObject(json, TRANS_FLAGS, TRANS_FLAG_HAS_CHANNEL_AUTH);
    (void)AddNumberToJsonObject(json, MY_HANDLE_ID, appInfo->myHandleId);
    (void)AddNumberToJsonObject(json, PEER_HANDLE_ID, appInfo->peerHandleId);
    (void)AddNumber64ToJsonObject(json, JSON_KEY_CALLING_TOKEN_ID, (int64_t)appInfo->callingTokenId);
    if (SoftBusCheckIsApp(appInfo->callingTokenId, appInfo->myData.sessionName)) {
        (void)AddNumber64ToJsonObject(json, ACCOUNT_ID, appInfo->myData.accountId);
        (void)AddNumberToJsonObject(json, USER_ID, appInfo->myData.userId);
    }
    return SOFTBUS_OK;
}

char *PackRequest(const AppInfo *appInfo)
{
    if (appInfo == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return NULL;
    }

    cJSON *json =  cJSON_CreateObject();
    if (json == NULL) {
        TRANS_LOGE(TRANS_CTRL, "Cannot create cJSON object");
        return NULL;
    }
    if (!AddNumber16ToJsonObject(json, FIRST_DATA_SIZE, appInfo->fastTransDataSize)) {
        cJSON_Delete(json);
        return NULL;
    }
    if (appInfo->fastTransDataSize > 0 && PackFirstData(appInfo, json) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "pack first data failed");
        cJSON_Delete(json);
        return NULL;
    }

    unsigned char encodeSessionKey[BASE64KEY] = {0};
    size_t keyLen = 0;
    int32_t ret = SoftBusBase64Encode(encodeSessionKey, BASE64KEY,
        &keyLen, (unsigned char *)appInfo->sessionKey, SESSION_KEY_LENGTH);
    if (ret != SOFTBUS_OK) {
        cJSON_Delete(json);
        return NULL;
    }
    ret = JsonObjectPackRequestEx(appInfo, json, encodeSessionKey);
    (void)memset_s(encodeSessionKey, sizeof(encodeSessionKey), 0, sizeof(encodeSessionKey));
    if (ret != SOFTBUS_OK) {
        cJSON_Delete(json);
        return NULL;
    }
    char *data = cJSON_PrintUnformatted(json);
    if (data == NULL) {
        TRANS_LOGW(TRANS_CTRL, "cJSON_PrintUnformatted failed");
    }
    cJSON_Delete(json);
    return data;
}

static int32_t UnpackFirstData(AppInfo *appInfo, const cJSON *json)
{
    if (!GetJsonObjectNumber16Item(json, FIRST_DATA_SIZE, &(appInfo->fastTransDataSize))) {
        appInfo->fastTransDataSize = 0;
    }
    TRANS_LOGD(TRANS_CTRL, "fastDataSize=%{public}d", appInfo->fastTransDataSize);
    if (appInfo->fastTransDataSize > 0 && appInfo->fastTransDataSize <= MAX_FAST_DATA_LEN) {
        uint8_t *encodeFastData = (uint8_t *)SoftBusCalloc(BASE64_FAST_DATA_LEN);
        if (encodeFastData == NULL) {
            TRANS_LOGE(TRANS_CTRL, "malloc encode fast data failed.");
            return SOFTBUS_MALLOC_ERR;
        }
        size_t fastDataSize = 0;
        if (!GetJsonObjectStringItem(json, FIRST_DATA, (char *)encodeFastData, BASE64_FAST_DATA_LEN)) {
            TRANS_LOGE(TRANS_CTRL, "Failed to get fast data");
            SoftBusFree(encodeFastData);
            return SOFTBUS_PARSE_JSON_ERR;
        }
        appInfo->fastTransData = (uint8_t *)SoftBusCalloc(appInfo->fastTransDataSize + FAST_TDC_EXT_DATA_SIZE);
        if (appInfo->fastTransData == NULL) {
            TRANS_LOGE(TRANS_CTRL, "malloc fast data failed.");
            SoftBusFree(encodeFastData);
            return SOFTBUS_MALLOC_ERR;
        }
        int32_t ret = SoftBusBase64Decode((unsigned char *)appInfo->fastTransData, appInfo->fastTransDataSize +
            FAST_TDC_EXT_DATA_SIZE, &fastDataSize, encodeFastData, strlen((char *)encodeFastData));
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "mbedtls decode failed.");
            SoftBusFree((void *)appInfo->fastTransData);
            appInfo->fastTransData = NULL;
            SoftBusFree(encodeFastData);
            return SOFTBUS_DECRYPT_ERR;
        }
        SoftBusFree(encodeFastData);
    }
    return SOFTBUS_OK;
}

static int32_t ParseMessageToAppInfo(const cJSON *msg, AppInfo *appInfo)
{
    char sessionKey[BASE64KEY] = {0};
    if (!GetJsonObjectStringItem(msg, BUS_NAME, (appInfo->myData.sessionName), SESSION_NAME_SIZE_MAX) ||
        !GetJsonObjectStringItem(msg, GROUP_ID, (appInfo->groupId), GROUP_ID_SIZE_MAX) ||
        !GetJsonObjectStringItem(msg, SESSION_KEY, sessionKey, sizeof(sessionKey))) {
        TRANS_LOGE(TRANS_CTRL, "Failed to get BUS_NAME");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    if (!GetJsonObjectNumberItem(msg, MTU_SIZE, (int32_t *)&(appInfo->peerData.dataConfig))) {
        TRANS_LOGW(TRANS_CTRL, "peer dataconfig is null.");
    }
    appInfo->peerData.uid = -1;
    appInfo->peerData.pid = -1;
    (void)GetJsonObjectNumberItem(msg, UID, &appInfo->peerData.uid);
    (void)GetJsonObjectNumberItem(msg, PID, &appInfo->peerData.pid);
    (void)GetJsonObjectSignedNumber64Item(msg, ACCOUNT_ID, &appInfo->peerData.accountId);
    if (!GetJsonObjectNumberItem(msg, USER_ID, &appInfo->peerData.userId)) {
        appInfo->peerData.userId = INVALID_USER_ID;
    }
    appInfo->myHandleId = -1;
    appInfo->peerHandleId = -1;
    if (!GetJsonObjectInt32Item(msg, MY_HANDLE_ID, &(appInfo->peerHandleId)) ||
        !GetJsonObjectInt32Item(msg, PEER_HANDLE_ID, &(appInfo->myHandleId))) {
            appInfo->myHandleId = -1;
            appInfo->peerHandleId = -1;
    }

    size_t len = 0;
    int32_t ret = SoftBusBase64Decode((unsigned char *)appInfo->sessionKey, SESSION_KEY_LENGTH,
        &len, (unsigned char *)sessionKey, strlen(sessionKey));
    (void)memset_s(sessionKey, sizeof(sessionKey), 0, sizeof(sessionKey));
    if (len != SESSION_KEY_LENGTH) {
        TRANS_LOGE(TRANS_CTRL, "Failed to decode sessionKey ret=%{public}d, len=%{public}zu", ret, len);
        return SOFTBUS_PARSE_JSON_ERR;
    }
    return SOFTBUS_OK;
}

int32_t UnpackRequest(const cJSON *msg, AppInfo *appInfo)
{
    if (msg == NULL || appInfo == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = UnpackFirstData(appInfo, msg);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "unpack first data failed");
        return ret;
    }

    int32_t apiVersion = API_V1;
    (void)GetJsonObjectNumberItem(msg, API_VERSION, &apiVersion);
    appInfo->peerData.apiVersion = (ApiVersion)apiVersion;
    if (ParseMessageToAppInfo(msg, appInfo) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "fill appInfo failed.");
        SoftBusFree((void *)appInfo->fastTransData);
        return SOFTBUS_PARSE_JSON_ERR;
    }
    if (apiVersion == API_V1) {
        return SOFTBUS_OK;
    }

    if (!GetJsonObjectStringItem(msg, PKG_NAME, (appInfo->peerData.pkgName), PKG_NAME_SIZE_MAX) ||
        !GetJsonObjectStringItem(msg, CLIENT_BUS_NAME, (appInfo->peerData.sessionName), SESSION_NAME_SIZE_MAX) ||
        !GetJsonObjectStringItem(msg, AUTH_STATE, (appInfo->peerData.authState), AUTH_STATE_SIZE_MAX)) {
        TRANS_LOGE(TRANS_CTRL, "Failed to get pkgName");
        SoftBusFree((void *)appInfo->fastTransData);
        return SOFTBUS_PARSE_JSON_ERR;
    }
    int32_t routeType = WIFI_STA;
    if (GetJsonObjectNumberItem(msg, MSG_ROUTE_TYPE, &routeType) != SOFTBUS_OK) {
        TRANS_LOGW(TRANS_CTRL, "Failed to get route type");
    }
    appInfo->routeType = (RouteType)routeType;

    if (!GetJsonObjectNumberItem(msg, BUSINESS_TYPE, (int32_t *)&appInfo->businessType)) {
        appInfo->businessType = BUSINESS_TYPE_NOT_CARE;
    }
    int32_t transFlag = TRANS_FLAG_HAS_CHANNEL_AUTH;
    (void)GetJsonObjectNumberItem(msg, AUTO_CLOSE_TIME, (int32_t *)&appInfo->autoCloseTime);
    (void)GetJsonObjectNumberItem(msg, TRANS_FLAGS, &transFlag);
    if (!GetJsonObjectNumber64Item(msg, JSON_KEY_CALLING_TOKEN_ID, (int64_t *)&appInfo->callingTokenId)) {
        appInfo->callingTokenId = TOKENID_NOT_SET;
    }
    uint32_t remoteCapability = 0;
    (void)GetJsonObjectNumberItem(msg, TRANS_CAPABILITY, (int32_t *)&remoteCapability);
    appInfo->channelCapability = remoteCapability & TRANS_CHANNEL_CAPABILITY;
    return SOFTBUS_OK;
}

static int32_t AddItemsToJsonObject(const AppInfo *appInfo, cJSON *json)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(AddNumberToJsonObject(json, CODE, CODE_OPEN_CHANNEL),
        SOFTBUS_CREATE_JSON_ERR, TRANS_CTRL, "Failed to add channels");
    TRANS_CHECK_AND_RETURN_RET_LOGE(AddNumberToJsonObject(json, API_VERSION, appInfo->myData.apiVersion),
        SOFTBUS_CREATE_JSON_ERR, TRANS_CTRL, "Failed to add apiVersion");
    TRANS_CHECK_AND_RETURN_RET_LOGE(AddStringToJsonObject(json, DEVICE_ID, appInfo->myData.deviceId),
        SOFTBUS_CREATE_JSON_ERR, TRANS_CTRL, "Failed to add deviceId");
    TRANS_CHECK_AND_RETURN_RET_LOGE(AddNumberToJsonObject(json, UID, appInfo->myData.uid),
        SOFTBUS_CREATE_JSON_ERR, TRANS_CTRL, "Failed to add uid");
    TRANS_CHECK_AND_RETURN_RET_LOGE(AddNumberToJsonObject(json, PID, appInfo->myData.pid),
        SOFTBUS_CREATE_JSON_ERR, TRANS_CTRL, "Failed to add pid");
    TRANS_CHECK_AND_RETURN_RET_LOGE(AddNumberToJsonObject(json, TRANS_CAPABILITY, appInfo->channelCapability),
        SOFTBUS_CREATE_JSON_ERR, TRANS_CTRL, "Failed to add channelCapability");
    return SOFTBUS_OK;
}

char *PackReply(const AppInfo *appInfo)
{
    if (appInfo == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return NULL;
    }
    cJSON *json = cJSON_CreateObject();
    if (json == NULL) {
        return NULL;
    }
    char *data = NULL;
    if (AddItemsToJsonObject(appInfo, json) != SOFTBUS_OK) {
        goto EXIT_FAIL;
    }
    if (appInfo->peerData.dataConfig != 0) {
        if (!AddNumberToJsonObject(json, MTU_SIZE, appInfo->myData.dataConfig)) {
            goto EXIT_FAIL;
        }
    }
    if (!AddNumber16ToJsonObject(json, FIRST_DATA_SIZE, appInfo->fastTransDataSize)) {
        TRANS_LOGE(TRANS_CTRL, "Failed to add trans data size");
        goto EXIT_FAIL;
    }
    if (appInfo->myData.apiVersion != API_V1) {
        char *authState = (char *)appInfo->myData.authState;
        if (!AddStringToJsonObject(json, PKG_NAME, appInfo->myData.pkgName) ||
            !AddStringToJsonObject(json, AUTH_STATE, authState)) {
            TRANS_LOGE(TRANS_CTRL, "Failed to add pkgName or authState");
            goto EXIT_FAIL;
        }
    }
    if (!AddNumberToJsonObject(json, MY_HANDLE_ID, appInfo->myHandleId) ||
        !AddNumberToJsonObject(json, PEER_HANDLE_ID, appInfo->peerHandleId)) {
        TRANS_LOGE(TRANS_CTRL, "Failed to add items");
        goto EXIT_FAIL;
    }
    data = cJSON_PrintUnformatted(json);
    if (data == NULL) {
        TRANS_LOGW(TRANS_CTRL, "cJSON_PrintUnformatted failed");
    }
    cJSON_Delete(json);
    return data;

EXIT_FAIL:
    cJSON_Delete(json);
    return NULL;
}

int32_t UnpackReply(const cJSON *msg, AppInfo *appInfo, uint16_t *fastDataSize)
{
    if (msg == NULL || appInfo == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    char uuid[DEVICE_ID_SIZE_MAX] = { 0 };
    if (!GetJsonObjectStringItem(msg, DEVICE_ID, uuid, DEVICE_ID_SIZE_MAX)) {
        TRANS_LOGE(TRANS_CTRL, "Failed to get uuid");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    if (strcmp(uuid, appInfo->peerData.deviceId) != 0) {
        TRANS_LOGE(TRANS_CTRL, "Invalid uuid");
        return SOFTBUS_TRANS_INVALID_UUID;
    }
    if (!GetJsonObjectNumber16Item(msg, FIRST_DATA_SIZE, fastDataSize)) {
        TRANS_LOGW(TRANS_CTRL, "Failed to get fast data size");
    }

    int32_t apiVersion = API_V1;
    (void)GetJsonObjectNumberItem(msg, API_VERSION, &apiVersion);
    appInfo->peerData.apiVersion = (ApiVersion)apiVersion;
    appInfo->peerData.uid = -1;
    appInfo->peerData.pid = -1;
    (void)GetJsonObjectNumberItem(msg, UID, &appInfo->peerData.uid);
    (void)GetJsonObjectNumberItem(msg, PID, &appInfo->peerData.pid);
    if (!GetJsonObjectInt32Item(msg, MY_HANDLE_ID, &(appInfo->peerHandleId)) ||
        !GetJsonObjectInt32Item(msg, PEER_HANDLE_ID, &(appInfo->myHandleId))) {
            appInfo->myHandleId = -1;
            appInfo->peerHandleId = -1;
    }
    if (!GetJsonObjectNumberItem(msg, MTU_SIZE, (int32_t *)&(appInfo->peerData.dataConfig))) {
        TRANS_LOGW(TRANS_CTRL, "peer dataconfig is null.");
    }
    if (apiVersion != API_V1) {
        if (!GetJsonObjectStringItem(msg, PKG_NAME, (appInfo->peerData.pkgName), PKG_NAME_SIZE_MAX) ||
            !GetJsonObjectStringItem(msg, AUTH_STATE, (appInfo->peerData.authState), AUTH_STATE_SIZE_MAX)) {
            TRANS_LOGE(TRANS_CTRL, "Failed to get pkgName or authState");
            return SOFTBUS_PARSE_JSON_ERR;
        }
    }
    if (!GetJsonObjectNumberItem(msg, TRANS_CAPABILITY, (int32_t *)&(appInfo->channelCapability))) {
        appInfo->channelCapability = 0;
    }
    return SOFTBUS_OK;
}

int32_t UnpackReplyErrCode(const cJSON *msg, int32_t *errCode)
{
    if ((msg == NULL) || (errCode == NULL)) {
        TRANS_LOGW(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (!GetJsonObjectInt32Item(msg, ERR_CODE, errCode)) {
        return SOFTBUS_PARSE_JSON_ERR;
    }

    return SOFTBUS_OK;
}

static int32_t TransTdcEncrypt(const char *sessionKey, const char *in, uint32_t inLen, char *out, uint32_t *outLen)
{
    AesGcmCipherKey cipherKey = {0};
    cipherKey.keyLen = SESSION_KEY_LENGTH;
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, sessionKey, SESSION_KEY_LENGTH) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy key error.");
        return SOFTBUS_MEM_ERR;
    }
    int32_t ret = SoftBusEncryptData(&cipherKey, (unsigned char *)in, inLen, (unsigned char *)out, outLen);
    (void)memset_s(&cipherKey, sizeof(AesGcmCipherKey), 0, sizeof(AesGcmCipherKey));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "SoftBusEncryptData fail. ret=%{public}d", ret);
        return SOFTBUS_ENCRYPT_ERR;
    }
    return SOFTBUS_OK;
}

static void PackTcpFastDataPacketHead(TcpFastDataPacketHead *data)
{
    data->magicNumber = SoftBusHtoLl(data->magicNumber);
    data->seq = (int32_t)SoftBusHtoLl((uint32_t)data->seq);
    data->flags = SoftBusHtoLl(data->flags);
    data->dataLen = SoftBusHtoLl(data->dataLen);
}

char *TransTdcPackFastData(const AppInfo *appInfo, uint32_t *outLen)
{
#define MAGIC_NUMBER 0xBABEFACE
#define TDC_PKT_HEAD_SEQ_START 1024
    if ((appInfo == NULL) || (outLen == NULL)) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return NULL;
    }
    uint32_t dataLen = appInfo->fastTransDataSize + OVERHEAD_LEN;
    char *buf = (char *)SoftBusCalloc(dataLen + FAST_DATA_HEAD_SIZE);
    if (buf == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc failed.");
        return NULL;
    }
    static _Atomic int32_t tdcPktHeadSeq = TDC_PKT_HEAD_SEQ_START;
    TcpFastDataPacketHead pktHead = {
        .magicNumber = MAGIC_NUMBER,
        .seq = atomic_fetch_add_explicit(&tdcPktHeadSeq, 1, memory_order_relaxed),
        .flags = (appInfo->businessType == BUSINESS_TYPE_BYTE) ? FLAG_BYTES : FLAG_MESSAGE,
        .dataLen = dataLen,
    };
    PackTcpFastDataPacketHead(&pktHead);
    if (memcpy_s(buf, FAST_DATA_HEAD_SIZE, &pktHead, sizeof(TcpFastDataPacketHead)) != EOK) {
        SoftBusFree(buf);
        TRANS_LOGE(TRANS_CTRL, "memcpy_s error");
        return NULL;
    }
    if (TransTdcEncrypt(appInfo->sessionKey, (const char *)appInfo->fastTransData,
        appInfo->fastTransDataSize, buf + FAST_DATA_HEAD_SIZE, &dataLen) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "encrypt error");
        SoftBusFree(buf);
        return NULL;
    }
    *outLen = dataLen + FAST_DATA_HEAD_SIZE;
    return buf;
}