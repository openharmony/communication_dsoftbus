/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "anonymizer.h"
#include "auth_common.h"
#include "auth_hichain_adapter.h"
#include "auth_log.h"
#include "auth_session_fsm.h"
#include "bus_center_manager.h"
#include "device_auth.h"
#include "lnn_event.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_json_utils.h"

#define AUTH_APPID "softbus_auth"
#define GROUPID_BUF_LEN 65
#define KEY_LENGTH 16 /* Note: WinPc's special nearby only support 128 bits key */
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
        AUTH_LOGE(AUTH_HICHAIN, "create json fail");
        return NULL;
    }
    if (!AddStringToJsonObject(msg, FIELD_PEER_CONN_DEVICE_ID, udid) ||
        !AddStringToJsonObject(msg, FIELD_SERVICE_PKG_NAME, AUTH_APPID) ||
        !AddBoolToJsonObject(msg, FIELD_IS_DEVICE_LEVEL, true) ||
        !AddBoolToJsonObject(msg, FIELD_IS_CLIENT, isClient) ||
        !AddBoolToJsonObject(msg, FIELD_IS_UDID_HASH, false) ||
        !AddNumberToJsonObject(msg, FIELD_KEY_LENGTH, KEY_LENGTH)) {
        AUTH_LOGE(AUTH_HICHAIN, "add json object fail");
        cJSON_Delete(msg);
        return NULL;
    }
#ifdef AUTH_ACCOUNT
    AUTH_LOGI(AUTH_HICHAIN, "in account auth mode");
    if (!AddStringToJsonObject(msg, FIELD_UID_HASH, uid)) {
        AUTH_LOGE(AUTH_HICHAIN, "add uid into json fail");
        cJSON_Delete(msg);
        return NULL;
    }
#endif
    char *data = cJSON_PrintUnformatted(msg);
    if (data == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "cJSON_PrintUnformatted fail");
    }
    cJSON_Delete(msg);
    return data;
}

static bool OnTransmit(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(len <= ONTRANSMIT_MAX_DATA_BUFFER_LEN, false, AUTH_HICHAIN,
        "data len is invalid, len=%{public}u", len);
    AUTH_LOGI(AUTH_HICHAIN, "hichain OnTransmit: authSeq=%{public}" PRId64 ", len=%{public}u", authSeq, len);
    if (AuthSessionPostAuthData(authSeq, data, len) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_HICHAIN, "hichain OnTransmit fail: authSeq=%{public}" PRId64, authSeq);
        return false;
    }
    return true;
}

static void DfxRecordLnnExchangekeyEnd(int64_t authSeq, int32_t reason)
{
    LnnEventExtra extra = { 0 };
    LnnEventExtraInit(&extra);
    extra.authId = (int32_t)authSeq;
    extra.errcode = reason;
    extra.result = (reason == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED;
    LNN_EVENT(EVENT_SCENE_JOIN_LNN, EVENT_STAGE_AUTH_EXCHANGE_CIPHER, extra);
}

static void OnSessionKeyReturned(int64_t authSeq, const uint8_t *sessionKey, uint32_t sessionKeyLen)
{
    AUTH_LOGI(AUTH_HICHAIN, "hichain OnSessionKeyReturned: authSeq=%{public}" PRId64 ", len=%{public}u", authSeq,
        sessionKeyLen);
    if (sessionKey == NULL || sessionKeyLen > SESSION_KEY_LENGTH) {
        DfxRecordLnnExchangekeyEnd(authSeq, SOFTBUS_AUTH_GET_SESSION_KEY_FAIL);
        AUTH_LOGW(AUTH_HICHAIN, "invalid sessionKey");
        return;
    }
    DfxRecordLnnExchangekeyEnd(authSeq, SOFTBUS_OK);
    (void)AuthSessionSaveSessionKey(authSeq, sessionKey, sessionKeyLen);
}

static void DfxRecordLnnEndHichainEnd(int64_t authSeq, int32_t reason)
{
    LnnEventExtra extra = { 0 };
    LnnEventExtraInit(&extra);
    extra.authId = (int32_t)authSeq;
    extra.errcode = reason;
    extra.result = (reason == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED;
    LNN_EVENT(EVENT_SCENE_JOIN_LNN, EVENT_STAGE_AUTH_HICHAIN_END, extra);
}

static void OnFinish(int64_t authSeq, int operationCode, const char *returnData)
{
    (void)operationCode;
    (void)returnData;
    DfxRecordLnnEndHichainEnd(authSeq, SOFTBUS_OK);
    AUTH_LOGI(AUTH_HICHAIN, "hichain OnFinish: authSeq=%{public}" PRId64, authSeq);
    (void)AuthSessionHandleAuthFinish(authSeq);
}

static void OnError(int64_t authSeq, int operationCode, int errCode, const char *errorReturn)
{
    (void)operationCode;
    (void)errorReturn;
    DfxRecordLnnEndHichainEnd(authSeq, errCode);
    AUTH_LOGE(AUTH_HICHAIN, "hichain OnError: authSeq=%{public}" PRId64 ", errCode=%{public}d", authSeq, errCode);
    (void)AuthSessionHandleAuthError(authSeq, SOFTBUS_AUTH_HICHAIN_AUTH_ERROR);
}

static char *OnRequest(int64_t authSeq, int operationCode, const char *reqParams)
{
    (void)reqParams;
    AUTH_LOGI(AUTH_HICHAIN, "hichain OnRequest: authSeq=%{public}" PRId64 ", operationCode=%{public}d", authSeq,
        operationCode);
    char udid[UDID_BUF_LEN] = {0};
    if (AuthSessionGetUdid(authSeq, udid, sizeof(udid)) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_HICHAIN, "get udid fail");
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
        AUTH_LOGE(AUTH_HICHAIN, "pack request msg fail");
        cJSON_Delete(msg);
        return NULL;
    }
    char *msgStr = cJSON_PrintUnformatted(msg);
    if (msgStr == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "cJSON_PrintUnformatted fail");
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
        AUTH_LOGE(AUTH_HICHAIN, "parse json fail");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    if (!GetJsonObjectStringItem(msg, FIELD_GROUP_ID, groupInfo->groupId, GROUPID_BUF_LEN)) {
        AUTH_LOGE(AUTH_HICHAIN, "get FIELD_GROUP_ID fail");
        cJSON_Delete(msg);
        return SOFTBUS_ERR;
    }
    int32_t groupType = 0;
    if (!GetJsonObjectNumberItem(msg, FIELD_GROUP_TYPE, &groupType)) {
        AUTH_LOGE(AUTH_HICHAIN, "get FIELD_GROUP_TYPE fail");
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
        AUTH_LOGW(AUTH_HICHAIN, "invalid group info");
        return;
    }
    GroupInfo info;
    (void)memset_s(&info, sizeof(GroupInfo), 0, sizeof(GroupInfo));
    if (ParseGroupInfo(groupInfo, &info) != SOFTBUS_OK) {
        return;
    }
    AUTH_LOGI(AUTH_HICHAIN, "hichain OnGroupCreated, type=%{public}d", info.groupType);
    if (g_dataChangeListener.onGroupCreated != NULL) {
        g_dataChangeListener.onGroupCreated(info.groupId, (int32_t)info.groupType);
    }
}

static void OnDeviceBound(const char *udid, const char *groupInfo)
{
    if (udid == NULL || groupInfo == NULL) {
        AUTH_LOGW(AUTH_HICHAIN, "invalid udid");
        return;
    }
    AUTH_LOGI(AUTH_HICHAIN, "hichain onDeviceBound");
    if (g_dataChangeListener.onDeviceBound != NULL) {
        g_dataChangeListener.onDeviceBound(udid, groupInfo);
    }
}

static void OnGroupDeleted(const char *groupInfo)
{
    if (groupInfo == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "invalid group info");
        return;
    }
    GroupInfo info;
    (void)memset_s(&info, sizeof(GroupInfo), 0, sizeof(GroupInfo));
    if (ParseGroupInfo(groupInfo, &info) != SOFTBUS_OK) {
        return;
    }
    AUTH_LOGI(AUTH_HICHAIN, "hichain OnGroupDeleted, type=%{public}d", info.groupType);
    if (g_dataChangeListener.onGroupDeleted != NULL) {
        g_dataChangeListener.onGroupDeleted(info.groupId);
    }
}

static void OnDeviceNotTrusted(const char *udid)
{
    if (udid == NULL) {
        AUTH_LOGW(AUTH_HICHAIN, "hichain get invalid udid");
        return;
    }
    char *anonyUdid = NULL;
    Anonymize(udid, &anonyUdid);
    AUTH_LOGI(AUTH_HICHAIN, "hichain OnDeviceNotTrusted, udid=%{public}s", anonyUdid);
    AnonymizeFree(anonyUdid);
    if (g_dataChangeListener.onDeviceNotTrusted != NULL) {
        g_dataChangeListener.onDeviceNotTrusted(udid);
    }
}

int32_t RegTrustDataChangeListener(const TrustDataChangeListener *listener)
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
        AUTH_LOGE(AUTH_HICHAIN, "hichain regDataChangeListener fail");
        return SOFTBUS_AUTH_REG_DATA_FAIL;
    }
    return SOFTBUS_OK;
}

void UnregTrustDataChangeListener(void)
{
    int32_t ret = UnregChangeListener(AUTH_APPID);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_HICHAIN, "hichain unRegDataChangeListener err=%{public}d", ret);
    }
    (void)memset_s(&g_dataChangeListener, sizeof(TrustDataChangeListener), 0, sizeof(TrustDataChangeListener));
}

int32_t HichainStartAuth(int64_t authSeq, const char *udid, const char *uid)
{
    if (udid == NULL || uid == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "udid/uid is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    char *authParams = GenDeviceLevelParam(udid, uid, true);
    if (authParams == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "generate auth param fail");
        return SOFTBUS_ERR;
    }
    if (AuthDevice(authSeq, authParams, &g_hichainCallback) == SOFTBUS_OK) {
        AUTH_LOGI(AUTH_HICHAIN, "hichain call authDevice succ");
        cJSON_free(authParams);
        return SOFTBUS_OK;
    }
    AUTH_LOGE(AUTH_HICHAIN, "hichain call authDevice failed");
    cJSON_free(authParams);
    return SOFTBUS_AUTH_START_ERR;
}

int32_t HichainProcessData(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    if (data == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "data is null");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = ProcessAuthData(authSeq, data, len, &g_hichainCallback);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_HICHAIN, "hichain processData err=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

void HichainDestroy(void)
{
    UnregTrustDataChangeListener();
    DestroyDeviceAuth();
    AUTH_LOGI(AUTH_HICHAIN, "hichain destroy succ");
}

void HichainCancelRequest(int64_t authReqId)
{
    CancelRequest(authReqId, AUTH_APPID);
}