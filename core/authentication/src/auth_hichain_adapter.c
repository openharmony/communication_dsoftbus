/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <stdlib.h>
#include <string.h>
#include <securec.h>

#include "auth_common.h"
#include "auth_hichain.h"
#include "auth_session_fsm.h"
#include "bus_center_manager.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "lnn_ohos_account_adapter.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"

#define AUTH_APPID "softbus_auth"
#define GROUP_ID "groupId"
#define GROUP_TYPE "groupType"
#define AUTH_ID "authId"
#define RETRY_TIMES 16
#define RETRY_MILLSECONDS 500
#define SAME_ACCOUNT_GROUY_TYPE 1
static const GroupAuthManager *g_hichain = NULL;
#define CUST_UDID_LEN 16

static const GroupAuthManager *InitHichain(void)
{
    int32_t ret = InitDeviceAuthService();
    if (ret != 0) {
        ALOGE("hichain InitDeviceAuthService failed(err = %d)", ret);
        return NULL;
    }
    const GroupAuthManager *gaIns = GetGaInstance();
    if (gaIns == NULL) {
        ALOGE("hichain GetGaInstance failed");
        DestroyDeviceAuthService();
        return NULL;
    }
    ALOGI("hichain init succ");
    return gaIns;
}

int32_t RegChangeListener(const char *appId, DataChangeListener *listener)
{
    AUTH_CHECK_AND_RETURN_RET_LOG(listener != NULL, SOFTBUS_ERR, "listener is null");
    if (g_hichain == NULL) {
        g_hichain = InitHichain();
    }
    AUTH_CHECK_AND_RETURN_RET_LOG(g_hichain != NULL, SOFTBUS_ERR, "hichain not initialized");

    const DeviceGroupManager *gmInstance = GetGmInstance();
    AUTH_CHECK_AND_RETURN_RET_LOG(gmInstance != NULL, SOFTBUS_ERR, "hichain GetGmInstance failed");

    int32_t ret = gmInstance->regDataChangeListener(appId, listener);
    AUTH_CHECK_AND_RETURN_RET_LOG(ret == 0, SOFTBUS_ERR, "hichain regDataChangeListener failed: %d", ret);

    return SOFTBUS_OK;
}

int32_t UnregChangeListener(const char *appId)
{
    const DeviceGroupManager *gmInstance = GetGmInstance();
    AUTH_CHECK_AND_RETURN_RET_LOG(gmInstance != NULL, SOFTBUS_ERR, "hichain GetGmInstance failed");

    int32_t ret = gmInstance->unRegDataChangeListener(appId);
    AUTH_CHECK_AND_RETURN_RET_LOG(ret == 0, SOFTBUS_ERR, "hichain unRegDataChangeListener failed: %d", ret);

    return SOFTBUS_OK;
}

int32_t AuthDevice(int64_t authReqId, const char *authParams, const DeviceAuthCallback *cb)
{
    AUTH_CHECK_AND_RETURN_RET_LOG(authParams != NULL && cb != NULL, SOFTBUS_INVALID_PARAM, "authParams or cb is null");
    if (g_hichain == NULL) {
        g_hichain = InitHichain();
    }
    AUTH_CHECK_AND_RETURN_RET_LOG(g_hichain != NULL, SOFTBUS_ERR, "hichain not initialized");

    for (int32_t i = 1; i < RETRY_TIMES; i++) {
        int32_t ret = g_hichain->authDevice(ANY_OS_ACCOUNT, authReqId, authParams, cb);
        if (ret == HC_SUCCESS) {
            ALOGI("hichain call authDevice success, times = %d", i);
            return SOFTBUS_OK;
        }
        if (ret != HC_ERR_INVALID_PARAMS) {
            ALOGE("hichain call authDevice failed, err = %d", ret);
            return SOFTBUS_ERR;
        }
        ALOGW("hichain retry call authDevice, current retry times = %d, err = %d", i, ret);
        (void)SoftBusSleepMs(RETRY_MILLSECONDS);
    }
    return SOFTBUS_ERR;
}

int32_t ProcessAuthData(int64_t authSeq, const uint8_t *data, uint32_t len, DeviceAuthCallback *cb)
{
    AUTH_CHECK_AND_RETURN_RET_LOG(data != NULL && cb != NULL, SOFTBUS_INVALID_PARAM, "data or cb is null");
    if (g_hichain == NULL) {
        g_hichain = InitHichain();
    }
    AUTH_CHECK_AND_RETURN_RET_LOG(g_hichain != NULL, SOFTBUS_ERR, "hichain not initialized");

    int32_t ret = g_hichain->processData(authSeq, data, len, cb);
    AUTH_CHECK_AND_RETURN_RET_LOG(ret == 0, SOFTBUS_ERR, "hichain processData failed: %d", ret);

    return SOFTBUS_OK;
}

bool CheckDeviceInGroupByType(const char *udid, const char *uuid, HichainGroup groupType)
{
    (void)udid;
    (void)uuid;
    (void)groupType;
    return true;
}

void DestroyDeviceAuth(void)
{
    DestroyDeviceAuthService();
    g_hichain = NULL;
    ALOGI("hichain destroy succ");
}

static bool IsTrustedDeviceInAGroup(const DeviceGroupManager *gmInstance, int32_t accountId,
    const char *groupId, const char *deviceId)
{
    uint32_t deviceNum = 0;
    char *returnDevInfoVec = NULL;
    if (gmInstance->getTrustedDevices(accountId, AUTH_APPID, groupId, &returnDevInfoVec, &deviceNum) != SOFTBUS_OK) {
        gmInstance->destroyInfo(&returnDevInfoVec);
        ALOGE("GetTrustedDevices fail");
        return false;
    }
    if (deviceNum == 0) {
        gmInstance->destroyInfo(&returnDevInfoVec);
        ALOGI("GetTrustedDevices zero");
        return false;
    }
    cJSON *devJson = cJSON_Parse(returnDevInfoVec);
    if (devJson == NULL) {
        gmInstance->destroyInfo(&returnDevInfoVec);
        ALOGE("parse json fail");
        return false;
    }
    int32_t devArraySize = cJSON_GetArraySize(devJson);
    for (int32_t j = 0; j < devArraySize; j++) {
        cJSON *devItem = cJSON_GetArrayItem(devJson, j);
        char authId[UDID_BUF_LEN] = {0};
        if (!GetJsonObjectStringItem(devItem, AUTH_ID, authId, UDID_BUF_LEN)) {
            ALOGE("AUTH_ID not found");
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
        ALOGE("GetRelatedGroups fail");
        gmInstance->destroyInfo(&returnGroupVec);
        return false;
    }
    if (groupNum == 0) {
        ALOGI("GetRelatedGroups zero");
        gmInstance->destroyInfo(&returnGroupVec);
        return false;
    }
    cJSON *groupJson = cJSON_Parse(returnGroupVec);
    if (groupJson == NULL) {
        ALOGE("parse json fail");
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
                ALOGI("ignore same account group");
                continue;
            }
        }
        if (!GetJsonObjectStringItem(groupItem, GROUP_ID, groupId, UDID_BUF_LEN)) {
            ALOGE("GROUP_ID not found");
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
    const DeviceGroupManager *gmInstance = GetGmInstance();
    if (gmInstance == NULL) {
        ALOGE("hichain GetGmInstance failed");
        return false;
    }

    int32_t accountId = GetActiveOsAccountIds();
    if (accountId <= 0) {
        ALOGE("accountId is invalid");
        return false;
    }

    char localUdid[UDID_BUF_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, localUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        ALOGE("get udid fail");
        return false;
    }
    return HasTrustedRelationWithLocalDevice(gmInstance, accountId, localUdid, deviceId, isPointToPoint);
}

uint32_t HichainGetJoinedGroups(int32_t groupType)
{
    uint32_t groupCnt = 0;
    char *accountGroups = NULL;

    const DeviceGroupManager *gmInstance = GetGmInstance();
    AUTH_CHECK_AND_RETURN_RET_LOG(gmInstance != NULL, groupCnt, "hichain GetGmInstance failed");

    if (gmInstance->getJoinedGroups(0, AUTH_APPID, (GroupType)groupType, &accountGroups, &groupCnt) != 0) {
        ALOGE("hichain getJoinedGroups groupCnt fail.");
        groupCnt = 0;
    }
    if (accountGroups != NULL) {
        SoftBusFree(accountGroups);
    }
    return groupCnt;
}

void CancelRequest(int64_t authReqId, const char *appId)
{
    if (g_hichain == NULL) {
        g_hichain = InitHichain();
    }
    AUTH_CHECK_AND_RETURN_LOG(g_hichain != NULL, "hichain not initialized");
    g_hichain->cancelRequest(authReqId, appId);
}