/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "auth_hichain_adapter.h"

#include <string.h>

#include "auth_common.h"
#include "auth_log.h"
#include "auth_session_fsm.h"
#include "bus_center_manager.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "lnn_ohos_account_adapter.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"

#define AUTH_APPID "softbus_auth"
#define GROUP_ID "groupId"
#define GROUP_TYPE "groupType"
#define AUTH_ID "authId"
#define RETRY_TIMES 16
#define RETRY_MILLSECONDS 500
#define SAME_ACCOUNT_GROUY_TYPE 1
static const GroupAuthManager *g_hichain = NULL;
#define CUST_UDID_LEN 16
#define KEY_LENGTH 16 /* Note: WinPc's special nearby only support 128 bits key */
#define FIELD_META_NODE_TYPE "metaNodeType"
#define META_NODE_TYPE_PC "0x0C"

char *GenDeviceLevelParam(HiChainAuthParam *hiChainParam)
{
    if (hiChainParam == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "parameter is null");
        return NULL;
    }

    cJSON *msg = cJSON_CreateObject();
    if (msg == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "create json fail");
        return NULL;
    }
    if (!AddStringToJsonObject(msg, FIELD_PEER_CONN_DEVICE_ID, hiChainParam->udid) ||
        !AddStringToJsonObject(msg, FIELD_SERVICE_PKG_NAME, AUTH_APPID) ||
        !AddBoolToJsonObject(msg, FIELD_IS_DEVICE_LEVEL, true) ||
        !AddBoolToJsonObject(msg, FIELD_IS_CLIENT, true) ||
        !AddBoolToJsonObject(msg, FIELD_IS_UDID_HASH, false) ||
        !AddNumberToJsonObject(msg, FIELD_KEY_LENGTH, KEY_LENGTH)) {
        AUTH_LOGE(AUTH_HICHAIN, "add json object fail");
        cJSON_Delete(msg);
        return NULL;
    }
    if (hiChainParam->deviceTypeId == TYPE_PC_ID) {
        if (!AddStringToJsonObject(msg, FIELD_META_NODE_TYPE, META_NODE_TYPE_PC)) {
            AUTH_LOGE(AUTH_HICHAIN, "add json meta node fail");
        }
    }
    if (hiChainParam->userId != 0 && !AddNumberToJsonObject(msg, "peerOsAccountId", hiChainParam->userId)) {
        AUTH_LOGE(AUTH_HICHAIN, "add json userId fail");
    }
#ifdef AUTH_ACCOUNT
    AUTH_LOGI(AUTH_HICHAIN, "in account auth mode");
    if (!AddStringToJsonObject(msg, FIELD_UID_HASH, hiChainParam->uid)) {
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

static const GroupAuthManager *InitHichain(void)
{
    int32_t ret = InitDeviceAuthService();
    if (ret != 0) {
        AUTH_LOGE(AUTH_INIT, "hichain InitDeviceAuthService failed err=%{public}d", ret);
        return NULL;
    }
    const GroupAuthManager *gaIns = GetGaInstance();
    if (gaIns == NULL) {
        AUTH_LOGE(AUTH_INIT, "hichain GetGaInstance failed");
        DestroyDeviceAuthService();
        return NULL;
    }
    AUTH_LOGI(AUTH_INIT, "hichain init succ");
    return gaIns;
}

int32_t RegChangeListener(const char *appId, DataChangeListener *listener)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(appId != NULL, SOFTBUS_INVALID_PARAM, AUTH_HICHAIN,
        "appId is null");
    AUTH_CHECK_AND_RETURN_RET_LOGE(listener != NULL, SOFTBUS_INVALID_PARAM, AUTH_HICHAIN,
        "listener is null");
    if (g_hichain == NULL) {
        g_hichain = InitHichain();
    }
    AUTH_CHECK_AND_RETURN_RET_LOGE(g_hichain != NULL, SOFTBUS_AUTH_HICHAIN_INIT_FAIL, AUTH_HICHAIN,
        "hichain not initialized");

    const DeviceGroupManager *gmInstance = GetGmInstance();
    AUTH_CHECK_AND_RETURN_RET_LOGE(gmInstance != NULL, SOFTBUS_AUTH_HICHAIN_INIT_FAIL, AUTH_HICHAIN,
        "hichain GetGmInstance failed");

    int32_t ret = gmInstance->regDataChangeListener(appId, listener);
    AUTH_CHECK_AND_RETURN_RET_LOGE(ret == 0, SOFTBUS_AUTH_REG_DATA_FAIL, AUTH_HICHAIN,
        "hichain regDataChangeListener failed=%{public}d", ret);

    return SOFTBUS_OK;
}

int32_t UnregChangeListener(const char *appId)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(appId != NULL, SOFTBUS_INVALID_PARAM, AUTH_HICHAIN,
        "appId is null");
    const DeviceGroupManager *gmInstance = GetGmInstance();
    AUTH_CHECK_AND_RETURN_RET_LOGE(gmInstance != NULL, SOFTBUS_AUTH_HICHAIN_INIT_FAIL, AUTH_HICHAIN,
        "hichain GetGmInstance failed");
    int32_t ret = gmInstance->unRegDataChangeListener(appId);
    AUTH_CHECK_AND_RETURN_RET_LOGE(ret == 0, SOFTBUS_AUTH_UNREG_DATA_FAIL, AUTH_HICHAIN,
        "hichain unRegDataChangeListener failed=%{public}d", ret);

    return SOFTBUS_OK;
}

int32_t AuthDevice(int32_t userId, int64_t authReqId, const char *authParams, const DeviceAuthCallback *cb)
{
    (void)userId;

    AUTH_CHECK_AND_RETURN_RET_LOGE(authParams != NULL && cb != NULL, SOFTBUS_INVALID_PARAM,
        AUTH_HICHAIN, "authParams or cb is null");
    if (g_hichain == NULL) {
        g_hichain = InitHichain();
    }
    AUTH_CHECK_AND_RETURN_RET_LOGE(g_hichain != NULL, SOFTBUS_AUTH_HICHAIN_INIT_FAIL,
        AUTH_HICHAIN, "hichain not initialized");

    uint32_t authErrCode = 0;
    for (int32_t i = 1; i < RETRY_TIMES; i++) {
        int32_t ret = g_hichain->authDevice(ANY_OS_ACCOUNT, authReqId, authParams, cb);
        if (ret == HC_SUCCESS) {
            AUTH_LOGI(AUTH_HICHAIN, "hichain call authDevice success, times=%{public}d", i);
            return SOFTBUS_OK;
        }
        (void)GetSoftbusHichainAuthErrorCode((uint32_t)ret, &authErrCode);
        if (ret != HC_ERR_INVALID_PARAMS) {
            AUTH_LOGE(AUTH_HICHAIN, "hichain call authDevice failed, err=%{public}d, authErrCode=%{public}d", ret,
                authErrCode);
            return authErrCode;
        }
        AUTH_LOGW(AUTH_HICHAIN,
            "hichain retry call authDevice, current retry times=%{public}d, err=%{public}d", i, ret);
        (void)SoftBusSleepMs(RETRY_MILLSECONDS);
    }
    return authErrCode;
}

int32_t ProcessAuthData(int64_t authSeq, const uint8_t *data, uint32_t len, DeviceAuthCallback *cb)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(data != NULL && cb != NULL, SOFTBUS_INVALID_PARAM, AUTH_HICHAIN,
        "data or cb is null");
    if (g_hichain == NULL) {
        g_hichain = InitHichain();
    }
    AUTH_CHECK_AND_RETURN_RET_LOGE(g_hichain != NULL, SOFTBUS_AUTH_HICHAIN_INIT_FAIL,
        AUTH_HICHAIN, "hichain not initialized");

    int32_t ret = g_hichain->processData(authSeq, data, len, cb);
    if (ret != HC_SUCCESS) {
        AUTH_LOGE(AUTH_HICHAIN, "hichain processData failed. ret=%{public}d", ret);
        uint32_t authErrCode = 0;
        (void)GetSoftbusHichainAuthErrorCode((uint32_t)ret, &authErrCode);
        return authErrCode;
    }

    return SOFTBUS_OK;
}

bool CheckDeviceInGroupByType(const char *udid, const char *uuid, HichainGroup groupType)
{
    (void)udid;
    (void)uuid;
    (void)groupType;
    return false;
}

void DestroyDeviceAuth(void)
{
    DestroyDeviceAuthService();
    g_hichain = NULL;
    AUTH_LOGI(AUTH_HICHAIN, "hichain destroy succ");
}

static bool IsTrustedDeviceInAGroup(const DeviceGroupManager *gmInstance, int32_t accountId,
    const char *groupId, const char *deviceId)
{
    uint32_t deviceNum = 0;
    char *returnDevInfoVec = NULL;
    if (gmInstance->getTrustedDevices(accountId, AUTH_APPID, groupId, &returnDevInfoVec, &deviceNum) != SOFTBUS_OK) {
        gmInstance->destroyInfo(&returnDevInfoVec);
        AUTH_LOGE(AUTH_HICHAIN, "GetTrustedDevices fail");
        return false;
    }
    if (deviceNum == 0) {
        gmInstance->destroyInfo(&returnDevInfoVec);
        AUTH_LOGI(AUTH_HICHAIN, "GetTrustedDevices zero");
        return false;
    }
    cJSON *devJson = cJSON_Parse(returnDevInfoVec);
    if (devJson == NULL) {
        gmInstance->destroyInfo(&returnDevInfoVec);
        AUTH_LOGE(AUTH_HICHAIN, "parse json fail");
        return false;
    }
    int32_t devArraySize = cJSON_GetArraySize(devJson);
    for (int32_t j = 0; j < devArraySize; j++) {
        cJSON *devItem = cJSON_GetArrayItem(devJson, j);
        char authId[UDID_BUF_LEN] = {0};
        if (!GetJsonObjectStringItem(devItem, AUTH_ID, authId, UDID_BUF_LEN)) {
            AUTH_LOGE(AUTH_HICHAIN, "AUTH_ID not found");
            continue;
        }
        uint8_t udidHash[SHA_256_HASH_LEN] = {0};
        char hashStr[CUST_UDID_LEN + 1] = {0};
        if (SoftBusGenerateStrHash((const unsigned char *)authId, strlen(authId), udidHash) != SOFTBUS_OK) {
            continue;
        }
        if (ConvertBytesToHexString(hashStr, CUST_UDID_LEN + 1, udidHash,
            CUST_UDID_LEN / HEXIFY_UNIT_LEN) != SOFTBUS_OK) {
            continue;
        }
        if (strncmp(hashStr, deviceId, strlen(deviceId)) == 0) {
            cJSON_Delete(devJson);
            gmInstance->destroyInfo(&returnDevInfoVec);
            return true;
        }
    }
    cJSON_Delete(devJson);
    gmInstance->destroyInfo(&returnDevInfoVec);
    return false;
}

static bool HasTrustedRelationWithLocalDevice(const DeviceGroupManager *gmInstance, int32_t accountId,
    char *localUdid, const char *deviceId, bool isPointToPoint)
{
    uint32_t groupNum = 0;
    char *returnGroupVec = NULL;
    if (gmInstance->getRelatedGroups(accountId, AUTH_APPID, localUdid, &returnGroupVec, &groupNum) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_HICHAIN, "GetRelatedGroups fail, accountId=%{public}d", accountId);
        gmInstance->destroyInfo(&returnGroupVec);
        return false;
    }
    if (groupNum == 0) {
        AUTH_LOGI(AUTH_HICHAIN, "GetRelatedGroups zero");
        gmInstance->destroyInfo(&returnGroupVec);
        return false;
    }
    cJSON *groupJson = cJSON_Parse(returnGroupVec);
    if (groupJson == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "parse json fail");
        gmInstance->destroyInfo(&returnGroupVec);
        return false;
    }
    int32_t groupArraySize = cJSON_GetArraySize(groupJson);
    for (int32_t i = 0; i < groupArraySize; i++) {
        cJSON *groupItem = cJSON_GetArrayItem(groupJson, i);
        char groupId[UDID_BUF_LEN] = {0};
        if (isPointToPoint) {
            int groupType = 0;
            if ((GetJsonObjectNumberItem(groupItem, GROUP_TYPE, &groupType) && groupType == SAME_ACCOUNT_GROUY_TYPE)) {
                AUTH_LOGD(AUTH_HICHAIN, "ignore same account group");
                continue;
            }
        }
        if (!GetJsonObjectStringItem(groupItem, GROUP_ID, groupId, UDID_BUF_LEN)) {
            AUTH_LOGE(AUTH_HICHAIN, "GROUP_ID not found");
            continue;
        }
        if (IsTrustedDeviceInAGroup(gmInstance, accountId, groupId, deviceId)) {
            cJSON_Delete(groupJson);
            gmInstance->destroyInfo(&returnGroupVec);
            return true;
        }
    }
    cJSON_Delete(groupJson);
    gmInstance->destroyInfo(&returnGroupVec);
    return false;
}

bool IsPotentialTrustedDevice(TrustedRelationIdType idType, const char *deviceId, bool isPrecise, bool isPointToPoint)
{
    (void)idType;
    (void)isPrecise;
    if (deviceId == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "deviceId is null");
        return false;
    }
    const DeviceGroupManager *gmInstance = GetGmInstance();
    if (gmInstance == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "hichain GetGmInstance failed");
        return false;
    }

    int32_t accountId = JudgeDeviceTypeAndGetOsAccountIds();
    if (accountId <= 0) {
        AUTH_LOGE(AUTH_HICHAIN, "accountId is invalid");
        return false;
    }

    char localUdid[UDID_BUF_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, localUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_HICHAIN, "get udid fail");
        return false;
    }
    return HasTrustedRelationWithLocalDevice(gmInstance, accountId, localUdid, deviceId, isPointToPoint);
}

uint32_t HichainGetJoinedGroups(int32_t groupType)
{
    uint32_t groupCnt = 0;
    char *accountGroups = NULL;

    const DeviceGroupManager *gmInstance = GetGmInstance();
    AUTH_CHECK_AND_RETURN_RET_LOGE(gmInstance != NULL, groupCnt, AUTH_HICHAIN, "hichain GetGmInstance failed");

    if (gmInstance->getJoinedGroups(0, AUTH_APPID, (GroupType)groupType, &accountGroups, &groupCnt) != 0) {
        AUTH_LOGE(AUTH_HICHAIN, "hichain getJoinedGroups groupCnt fail");
        groupCnt = 0;
    }
    if (accountGroups != NULL) {
        SoftBusFree(accountGroups);
    }
    return groupCnt;
}

bool IsSameAccountGroupDevice(void)
{
    uint32_t groupNum = 0;
    char *returnGroupVec = NULL;

    const DeviceGroupManager *gmInstance = GetGmInstance();
    if (gmInstance == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "hichain GetGmInstance failed");
        return false;
    }
    int32_t accountId = JudgeDeviceTypeAndGetOsAccountIds();
    if (accountId <= 0) {
        AUTH_LOGE(AUTH_HICHAIN, "accountId is invalid");
        return false;
    }

    if (gmInstance->getJoinedGroups(accountId, AUTH_APPID, SAME_ACCOUNT_GROUY_TYPE, &returnGroupVec, &groupNum) !=
        SOFTBUS_OK) {
        AUTH_LOGE(AUTH_HICHAIN, "getJoinedGroups fail, accountId=%{public}d", accountId);
        gmInstance->destroyInfo(&returnGroupVec);
        return false;
    }
    if (groupNum == 0) {
        AUTH_LOGE(AUTH_HICHAIN, "getJoinedGroups zero");
        gmInstance->destroyInfo(&returnGroupVec);
        return false;
    } else {
        AUTH_LOGI(AUTH_HICHAIN, "getJoinedGroups: %{public}d", groupNum);
        gmInstance->destroyInfo(&returnGroupVec);
        return true;
    }
}

void CancelRequest(int64_t authReqId, const char *appId)
{
    AUTH_CHECK_AND_RETURN_LOGE(appId != NULL, AUTH_HICHAIN, "appId is null");
    if (g_hichain == NULL) {
        g_hichain = InitHichain();
    }
    AUTH_CHECK_AND_RETURN_LOGE(g_hichain != NULL, AUTH_HICHAIN, "hichain not initialized");
    g_hichain->cancelRequest(authReqId, appId);
}