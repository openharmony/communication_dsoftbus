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
#include "auth_session_fsm.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "softbus_json_utils.h"

#define AUTH_APPID "softbus_auth"
#define GROUPID_BUF_LEN 65
#define RETRY_TIMES 16
#define RETRY_MILLSECONDS 500

typedef struct {
    char groupId[GROUPID_BUF_LEN];
    GroupType groupType;
    GroupVisibility groupVisibility;
} GroupInfo;

static const GroupAuthManager *g_hichain = NULL;
static TrustDataChangeListener g_dataChangeListener = {0};

static char *GenDeviceLevelParam(const char *udid, const char *uid, bool isClient)
{
    cJSON *msg = cJSON_CreateObject();
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "create json fail.");
        return NULL;
    }
    if (!AddStringToJsonObject(msg, FIELD_PEER_CONN_DEVICE_ID, udid) ||
        !AddStringToJsonObject(msg, FIELD_SERVICE_PKG_NAME, AUTH_APPID) ||
        !AddBoolToJsonObject(msg, FIELD_IS_CLIENT, isClient) ||
        !AddNumberToJsonObject(msg, FIELD_KEY_LENGTH, SESSION_KEY_LENGTH)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "add json object fail.");
        cJSON_Delete(msg);
        return NULL;
    }
#ifdef AUTH_ACCOUNT
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "in account auth mode");
    if (!AddStringToJsonObject(msg, FIELD_UID_HASH, uid)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "add uid into json fail.");
        cJSON_Delete(msg);
        return NULL;
    }
#endif
    char *data = cJSON_PrintUnformatted(msg);
    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "cJSON_PrintUnformatted fail.");
    }
    cJSON_Delete(msg);
    return data;
}

static bool OnTransmit(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "hichain OnTransmit: authSeq=%" PRId64 ", len=%u.", authSeq, len);
    if (AuthSessionPostAuthData(authSeq, data, len) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "hichain OnTransmit fail: authSeq=%" PRId64, authSeq);
        return false;
    }
    return true;
}

static void OnSessionKeyReturned(int64_t authSeq, const uint8_t *sessionKey, uint32_t sessionKeyLen)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "hichain OnSessionKeyReturned: authSeq=%" PRId64 ", len=%u.", authSeq, sessionKeyLen);
    if (sessionKey == NULL || sessionKeyLen > SESSION_KEY_LENGTH) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid sessionKey.");
        return;
    }
    (void)AuthSessionSaveSessionKey(authSeq, sessionKey, sessionKeyLen);
}

static void OnFinish(int64_t authSeq, int operationCode, const char *returnData)
{
    (void)operationCode;
    (void)returnData;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "hichain OnFinish: authSeq=%" PRId64 ".", authSeq);
    (void)AuthSessionHandleAuthResult(authSeq, SOFTBUS_OK);
}

static void OnError(int64_t authSeq, int operationCode, int errCode, const char *errorReturn)
{
    (void)operationCode;
    (void)errorReturn;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
        "hichain OnError: authSeq=%" PRId64 ", errCode=%d.", authSeq, errCode);
    (void)AuthSessionHandleAuthResult(authSeq, SOFTBUS_AUTH_HICHAIN_AUTH_ERROR);
}

static char *OnRequest(int64_t authSeq, int operationCode, const char *reqParams)
{
    (void)reqParams;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "hichain OnRequest: authSeq=%" PRId64 ", operationCode=%d.", authSeq, operationCode);
    char udid[UDID_BUF_LEN] = {0};
    if (AuthSessionGetUdid(authSeq, udid, sizeof(udid)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "get udid fail.");
        return NULL;
    }
    cJSON *msg = cJSON_CreateObject();
    if (msg == NULL) {
        return NULL;
    }
    if (!AddNumberToJsonObject(msg, FIELD_CONFIRMATION, REQUEST_ACCEPTED) ||
        !AddStringToJsonObject(msg, FIELD_SERVICE_PKG_NAME, AUTH_APPID) ||
        !AddStringToJsonObject(msg, FIELD_PEER_CONN_DEVICE_ID, udid)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "pack request msg fail.");
        cJSON_Delete(msg);
        return NULL;
    }
    char *msgStr = cJSON_PrintUnformatted(msg);
    if (msgStr == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "cJSON_PrintUnformatted fail.");
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
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "parse json fail.");
        return SOFTBUS_ERR;
    }
    if (!GetJsonObjectStringItem(msg, FIELD_GROUP_ID, groupInfo->groupId, GROUPID_BUF_LEN)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "get FIELD_GROUP_ID fail.");
        cJSON_Delete(msg);
        return SOFTBUS_ERR;
    }
    int32_t groupType = 0;
    if (!GetJsonObjectNumberItem(msg, FIELD_GROUP_TYPE, &groupType)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "get FIELD_GROUP_TYPE fail.");
        cJSON_Delete(msg);
        return SOFTBUS_ERR;
    }
    groupInfo->groupType = (GroupType)groupType;
    cJSON_Delete(msg);
    return SOFTBUS_OK;
}

static void OnGroupCreated(const char *groupInfo)
{
    if (groupInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid group info.");
        return;
    }
    GroupInfo info;
    if (ParseGroupInfo(groupInfo, &info) != SOFTBUS_OK) {
        return;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "hichain OnGroupCreated, type=%d", info.groupType);
    if (g_dataChangeListener.onGroupCreated != NULL) {
        g_dataChangeListener.onGroupCreated(info.groupId);
    }
}

static void OnGroupDeleted(const char *groupInfo)
{
    if (groupInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid group info.");
        return;
    }
    GroupInfo info;
    if (ParseGroupInfo(groupInfo, &info) != SOFTBUS_OK) {
        return;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "hichain OnGroupDeleted, type=%d", info.groupType);
    if (g_dataChangeListener.onGroupDeleted != NULL) {
        g_dataChangeListener.onGroupDeleted(info.groupId);
    }
}

static void OnDeviceNotTrusted(const char *udid)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "hichain OnDeviceNotTrusted.");
    if (udid == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid udid.");
        return;
    }
    if (g_dataChangeListener.onDeviceNotTrusted != NULL) {
        g_dataChangeListener.onDeviceNotTrusted(udid);
    }
}

static const GroupAuthManager *InitHichain(void)
{
    int32_t ret = InitDeviceAuthService();
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "hichain InitDeviceAuthService fail(err = %d).", ret);
        return NULL;
    }
    const GroupAuthManager *gaIns = GetGaInstance();
    if (gaIns == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "hichain GetGaInstance fail.");
        DestroyDeviceAuthService();
        return NULL;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "hichain init succ.");
    return gaIns;
}

int32_t RegTrustDataChangeListener(const TrustDataChangeListener *listener)
{
    if (listener == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_hichain == NULL) {
        g_hichain = InitHichain();
    }
    if (g_hichain == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "hichain not initialized.");
        return SOFTBUS_ERR;
    }

    if (memcpy_s(&g_dataChangeListener, sizeof(g_dataChangeListener),
        listener, sizeof(TrustDataChangeListener)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "copy data change listener fail.");
        return SOFTBUS_MEM_ERR;
    }

    DataChangeListener hichainListener;
    (void)memset_s(&hichainListener, sizeof(DataChangeListener), 0, sizeof(DataChangeListener));
    hichainListener.onGroupCreated = OnGroupCreated;
    hichainListener.onGroupDeleted = OnGroupDeleted;
    hichainListener.onDeviceNotTrusted = OnDeviceNotTrusted;
    const DeviceGroupManager *gmInstance = GetGmInstance();
    if (gmInstance == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "hichain GetGmInstance fail.");
        return SOFTBUS_ERR;
    }
    if (gmInstance->regDataChangeListener(AUTH_APPID, &hichainListener) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "hichain regDataChangeListener fail.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void UnregTrustDataChangeListener(void)
{
    const DeviceGroupManager *gmInstance = GetGmInstance();
    if (gmInstance == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "hichain GetGmInstance fail.");
        (void)memset_s(&g_dataChangeListener, sizeof(TrustDataChangeListener), 0,
            sizeof(TrustDataChangeListener));
        return;
    }
    int32_t ret = gmInstance->unRegDataChangeListener(AUTH_APPID);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "hichain unRegDataChangeListener fail(err=%d).", ret);
    }
    (void)memset_s(&g_dataChangeListener, sizeof(TrustDataChangeListener), 0, sizeof(TrustDataChangeListener));
}

int32_t HichainStartAuth(int64_t authSeq, const char *udid, const char *uid)
{
    if (udid == NULL || uid == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "udid/uid is invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_hichain == NULL) {
        g_hichain = InitHichain();
    }
    if (g_hichain == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "hichain not initialized.");
        return SOFTBUS_ERR;
    }
    char *authParams = GenDeviceLevelParam(udid, uid, true);
    if (authParams == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "generate auth param fail.");
        return SOFTBUS_ERR;
    }
    int32_t ret;
    for (int i = 0; i < RETRY_TIMES; i++) {
        ret = g_hichain->authDevice(ANY_OS_ACCOUNT, authSeq, authParams, &g_hichainCallback);
        if (ret == HC_SUCCESS) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "hichain authDevice sucess, time = %d", i + 1);
            cJSON_free(authParams);
            return SOFTBUS_OK;
        }
        if (ret == HC_ERR_INVALID_PARAMS) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
                "hichain authDevice need to retry, current retry time = %d, err = %d", i + 1, ret);
            (void)SoftBusSleepMs(RETRY_MILLSECONDS);
        } else {
            break;
        }
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "hichain authDevice fail, err = %d", ret);
    cJSON_free(authParams);
    return SOFTBUS_ERR;
}

int32_t HichainProcessData(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    if (data == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_hichain == NULL) {
        g_hichain = InitHichain();
    }
    if (g_hichain == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "hichain not initialized.");
        return SOFTBUS_ERR;
    }
    int32_t ret = g_hichain->processData(authSeq, data, len, &g_hichainCallback);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "hichain processData fail(err = %d).", ret);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void HichainDestroy(void)
{
    UnregTrustDataChangeListener();
    DestroyDeviceAuthService();
    g_hichain = NULL;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "hichain destroy succ.");
}
