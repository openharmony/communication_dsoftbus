/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "auth_hichain.h"

#include <securec.h>
#include "auth_common.h"
#include "auth_hichain_adapter.h"
#include "auth_session_fsm.h"
#include "device_auth.h"
#include "bus_center_manager.h"
#include "device_auth_defines.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_json_utils.h"

#define AUTH_APPID "softbus_auth"
#define GROUPID_BUF_LEN 65
#define ONTRANSMIT_MAX_DATA_BUFFER_LEN 5120 /* 5 × 1024 */

typedef struct {
    char groupId[GROUPID_BUF_LEN];
    GroupType groupType;
} GroupInfo;

static TrustDataChangeListener g_dataChangeListener;

static char *GenDeviceLevelParam(const char *udid, const char *uid, bool isClient)
{
    cJSON *msg = cJSON_CreateObject();
    if (msg == NULL) {
        ALOGE("create json fail.");
        return NULL;
    }
    if (!AddStringToJsonObject(msg, FIELD_PEER_CONN_DEVICE_ID, udid) ||
        !AddStringToJsonObject(msg, FIELD_SERVICE_PKG_NAME, AUTH_APPID) ||
        !AddBoolToJsonObject(msg, FIELD_IS_DEVICE_LEVEL, true) ||
        !AddBoolToJsonObject(msg, FIELD_IS_CLIENT, isClient) ||
        !AddBoolToJsonObject(msg, FIELD_IS_UDID_HASH, false) ||
        !AddNumberToJsonObject(msg, FIELD_KEY_LENGTH, SESSION_KEY_LENGTH)) {
        ALOGE("add json object fail.");
        cJSON_Delete(msg);
        return NULL;
    }
#ifdef AUTH_ACCOUNT
    ALOGI("in account auth mode");
    if (!AddStringToJsonObject(msg, FIELD_UID_HASH, uid)) {
        ALOGE("add uid into json fail.");
        cJSON_Delete(msg);
        return NULL;
    }
#endif
    char *data = cJSON_PrintUnformatted(msg);
    if (data == NULL) {
        ALOGE("cJSON_PrintUnformatted fail.");
    }
    cJSON_Delete(msg);
    return data;
}

NO_SANITIZE("cfi") static bool OnTransmit(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    ALOGI("hichain OnTransmit: authSeq=%" PRId64 ", len=%u.", authSeq, len);
    if (len > ONTRANSMIT_MAX_DATA_BUFFER_LEN) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "data len is invalid, len=%u", len);
        return false;
    }
    if (AuthSessionPostAuthData(authSeq, data, len) != SOFTBUS_OK) {
        ALOGE("hichain OnTransmit fail: authSeq=%" PRId64, authSeq);
        return false;
    }
    return true;
}

NO_SANITIZE("cfi") static void OnSessionKeyReturned(int64_t authSeq, const uint8_t *sessionKey, uint32_t sessionKeyLen)
{
    ALOGI("hichain OnSessionKeyReturned: authSeq=%" PRId64 ", len=%u.", authSeq, sessionKeyLen);
    if (sessionKey == NULL || sessionKeyLen > SESSION_KEY_LENGTH) {
        ALOGE("invalid sessionKey.");
        return;
    }
    (void)AuthSessionSaveSessionKey(authSeq, sessionKey, sessionKeyLen);
}

NO_SANITIZE("cfi") static void OnFinish(int64_t authSeq, int operationCode, const char *returnData)
{
    (void)operationCode;
    (void)returnData;
    ALOGI("hichain OnFinish: authSeq=%" PRId64 ".", authSeq);
    (void)AuthSessionHandleAuthFinish(authSeq);
}

NO_SANITIZE("cfi") static void OnError(int64_t authSeq, int operationCode, int errCode, const char *errorReturn)
{
    (void)operationCode;
    (void)errorReturn;
    ALOGE("hichain OnError: authSeq=%" PRId64 ", errCode=%d.", authSeq, errCode);
    (void)AuthSessionHandleAuthError(authSeq, SOFTBUS_AUTH_HICHAIN_AUTH_ERROR);
}

NO_SANITIZE("cfi") static char *OnRequest(int64_t authSeq, int operationCode, const char *reqParams)
{
    (void)reqParams;
    ALOGI("hichain OnRequest: authSeq=%" PRId64 ", operationCode=%d.", authSeq, operationCode);
    char udid[UDID_BUF_LEN] = {0};
    if (AuthSessionGetUdid(authSeq, udid, sizeof(udid)) != SOFTBUS_OK) {
        ALOGE("get udid fail.");
        return NULL;
    }
    cJSON *msg = cJSON_CreateObject();
    if (msg == NULL) {
        return NULL;
    }
    char localUdid[UDID_BUF_LEN] = {0};
    LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, localUdid, UDID_BUF_LEN);
    if (!AddNumberToJsonObject(msg, FIELD_CONFIRMATION, REQUEST_ACCEPTED) ||
        !AddStringToJsonObject(msg, FIELD_SERVICE_PKG_NAME, AUTH_APPID) ||
        !AddStringToJsonObject(msg, FIELD_PEER_CONN_DEVICE_ID, udid) ||
        !AddStringToJsonObject(msg, FIELD_DEVICE_ID, localUdid) ||
        !AddBoolToJsonObject(msg, FIELD_IS_UDID_HASH, false)) {
        ALOGE("pack request msg fail.");
        cJSON_Delete(msg);
        return NULL;
    }
    char *msgStr = cJSON_PrintUnformatted(msg);
    if (msgStr == NULL) {
        ALOGE("cJSON_PrintUnformatted fail.");
        cJSON_Delete(msg);
        return NULL;
    }
    cJSON_Delete(msg);
    return msgStr;
}

static DeviceAuthCallback g_hichainCallback = {
    .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnRequest
};

static int32_t ParseGroupInfo(const char *groupInfoStr, GroupInfo *groupInfo)
{
    cJSON *msg = cJSON_Parse(groupInfoStr);
    if (msg == NULL) {
        ALOGE("parse json fail.");
        return SOFTBUS_ERR;
    }
    if (!GetJsonObjectStringItem(msg, FIELD_GROUP_ID, groupInfo->groupId, GROUPID_BUF_LEN)) {
        ALOGE("get FIELD_GROUP_ID fail.");
        cJSON_Delete(msg);
        return SOFTBUS_ERR;
    }
    int32_t groupType = 0;
    if (!GetJsonObjectNumberItem(msg, FIELD_GROUP_TYPE, &groupType)) {
        ALOGE("get FIELD_GROUP_TYPE fail.");
        cJSON_Delete(msg);
        return SOFTBUS_ERR;
    }
    groupInfo->groupType = (GroupType)groupType;
    cJSON_Delete(msg);
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") static void OnGroupCreated(const char *groupInfo)
{
    if (groupInfo == NULL) {
        ALOGE("invalid group info.");
        return;
    }
    GroupInfo info;
    if (ParseGroupInfo(groupInfo, &info) != SOFTBUS_OK) {
        return;
    }
    ALOGI("hichain OnGroupCreated, type=%d", info.groupType);
    if (g_dataChangeListener.onGroupCreated != NULL) {
        g_dataChangeListener.onGroupCreated(info.groupId, (int32_t)info.groupType);
    }
}

NO_SANITIZE("cfi") static void OnDeviceBound(const char *udid, const char *groupInfo)
{
    if (udid == NULL || groupInfo == NULL) {
        ALOGE("invalid udid");
        return;
    }
    ALOGI("hichain onDeviceBound");
    if (g_dataChangeListener.onDeviceBound != NULL) {
        g_dataChangeListener.onDeviceBound(udid, groupInfo);
    }
}

NO_SANITIZE("cfi") static void OnGroupDeleted(const char *groupInfo)
{
    if (groupInfo == NULL) {
        ALOGE("invalid group info.");
        return;
    }
    GroupInfo info;
    if (ParseGroupInfo(groupInfo, &info) != SOFTBUS_OK) {
        return;
    }
    ALOGI("hichain OnGroupDeleted, type=%d", info.groupType);
    if (g_dataChangeListener.onGroupDeleted != NULL) {
        g_dataChangeListener.onGroupDeleted(info.groupId);
    }
}

NO_SANITIZE("cfi") static void OnDeviceNotTrusted(const char *udid)
{
    if (udid == NULL) {
        ALOGE("hichain OnDeviceNotTrusted get invalid udid.");
        return;
    }
    char *anoyUdid = NULL;
    ALOGI("hichain OnDeviceNotTrusted, udid:%s", ToSecureStrDeviceID(udid, &anoyUdid));
    SoftBusFree(anoyUdid);
    if (g_dataChangeListener.onDeviceNotTrusted != NULL) {
        g_dataChangeListener.onDeviceNotTrusted(udid);
    }
}

NO_SANITIZE("cfi") int32_t RegTrustDataChangeListener(const TrustDataChangeListener *listener)
{
    if (listener == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    g_dataChangeListener = *listener;

    DataChangeListener hichainListener;
    (void)memset_s(&hichainListener, sizeof(DataChangeListener), 0, sizeof(DataChangeListener));
    hichainListener.onGroupCreated = OnGroupCreated;
    hichainListener.onGroupDeleted = OnGroupDeleted;
    hichainListener.onDeviceNotTrusted = OnDeviceNotTrusted;
    hichainListener.onDeviceBound = OnDeviceBound;
    if (RegChangeListener(AUTH_APPID, &hichainListener) != SOFTBUS_OK) {
        ALOGE("hichain regDataChangeListener fail.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") void UnregTrustDataChangeListener(void)
{
    int32_t ret = UnregChangeListener(AUTH_APPID);
    if (ret != 0) {
        ALOGE("hichain unRegDataChangeListener fail(err=%d).", ret);
    }
    (void)memset_s(&g_dataChangeListener, sizeof(TrustDataChangeListener), 0, sizeof(TrustDataChangeListener));
}

NO_SANITIZE("cfi") int32_t HichainStartAuth(int64_t authSeq, const char *udid, const char *uid)
{
    if (udid == NULL || uid == NULL) {
        ALOGE("udid/uid is invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    char *authParams = GenDeviceLevelParam(udid, uid, true);
    if (authParams == NULL) {
        ALOGE("generate auth param fail.");
        return SOFTBUS_ERR;
    }
    if (AuthDevice(authSeq, authParams, &g_hichainCallback) == SOFTBUS_OK) {
        ALOGI("hichain call authDevice succ");
        cJSON_free(authParams);
        return SOFTBUS_OK;
    }
    ALOGE("hichain call authDevice failed");
    cJSON_free(authParams);
    return SOFTBUS_ERR;
}

NO_SANITIZE("cfi") int32_t HichainProcessData(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    if (data == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = ProcessAuthData(authSeq, data, len, &g_hichainCallback);
    if (ret != SOFTBUS_OK) {
        ALOGE("hichain processData fail(err = %d).", ret);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") void HichainDestroy(void)
{
    UnregTrustDataChangeListener();
    DestroyDeviceAuth();
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "hichain destroy succ.");
}
