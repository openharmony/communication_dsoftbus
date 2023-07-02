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
#include "auth_session_fsm.h"
#include "device_auth.h"
#include "device_auth_defines.h"

#include "auth_hichain.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

#define AUTH_APPID "softbus_auth"
#define RETRY_TIMES 16
#define RETRY_MILLSECONDS 500
static const GroupAuthManager *g_hichain = NULL;

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

bool IsPotentialTrustedDevice(TrustedRelationIdType idType, const char *deviceId, bool isPrecise)
{
    (void)idType;
    (void)deviceId;
    (void)isPrecise;
    return true;
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
