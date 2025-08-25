/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <dlfcn.h>
#include <securec.h>
#include <cstring>
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "lnn_ohos_account_adapter.h"
#include "softbus_error_code.h"
#include "trans_log.h"

#ifdef __aarch64__
#define BR_PROXY_ADAPTER_PATH "/system/lib64/libbr_proxy_adapter.z.so"
#else
#define BR_PROXY_ADAPTER_PATH "/system/lib/libbr_proxy_adapter.z.so"
#endif

 
using namespace OHOS;

typedef int32_t (*GetAbilityNameFunc)(char *abilityName, int32_t userId, uint32_t abilityNameLen,
    std::string bundleName);
typedef int32_t (*StartAbilityFunc)(const char *bundleName, const char *abilityName);
static void* g_abilityMgrHandle = nullptr;
static StartAbilityFunc g_startAbilityFunc = nullptr;
static GetAbilityNameFunc g_getAbilityName = nullptr;

static int32_t AbilityManagerClientDynamicLoader(const char *bundleName, const char *abilityName)
{
    if (bundleName == nullptr || abilityName == nullptr) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    g_abilityMgrHandle = dlopen(BR_PROXY_ADAPTER_PATH, RTLD_LAZY);
    if (g_abilityMgrHandle == nullptr) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] dlopen failed!");
        return SOFTBUS_INVALID_PARAM;
    }

    g_startAbilityFunc = (StartAbilityFunc)dlsym(g_abilityMgrHandle, "StartAbility");
    if (g_startAbilityFunc == nullptr) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] dlsym failed!");
        dlclose(g_abilityMgrHandle);
        g_abilityMgrHandle = nullptr;
        return SOFTBUS_INVALID_PARAM;
    }

    return g_startAbilityFunc(bundleName, abilityName);
}

static int32_t GetAbilityName(char *abilityName, int32_t userId, uint32_t abilityNameLen, std::string bundleName)
{
    if (abilityName == nullptr) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    g_abilityMgrHandle = dlopen(BR_PROXY_ADAPTER_PATH, RTLD_LAZY);
    if (g_abilityMgrHandle == nullptr) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] dlopen failed!");
        return SOFTBUS_INVALID_PARAM;
    }

    g_getAbilityName = (GetAbilityNameFunc)dlsym(g_abilityMgrHandle, "ProxyChannelMgrGetAbilityName");
    if (g_getAbilityName == nullptr) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] dlsym failed!");
        dlclose(g_abilityMgrHandle);
        g_abilityMgrHandle = nullptr;
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = g_getAbilityName(abilityName, userId, abilityNameLen, bundleName);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] failed, ret = %{public}d", ret);
        return ret;
    }
    if (g_abilityMgrHandle != nullptr) {
        dlclose(g_abilityMgrHandle);
        g_abilityMgrHandle = nullptr;
    }
    return SOFTBUS_OK;
}

void BrProxyDynamicLoaderDeInit()
{
    if (g_abilityMgrHandle != nullptr) {
        dlclose(g_abilityMgrHandle);
        g_abilityMgrHandle = nullptr;
    }
}

extern "C" int32_t PullUpHap(const char *bundleName, const char *abilityName)
{
    int32_t ret = AbilityManagerClientDynamicLoader(bundleName, abilityName);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] failed, ret = %{public}d", ret);
        return ret;
    }
    BrProxyDynamicLoaderDeInit();
    return SOFTBUS_OK;
}

extern "C" pid_t GetCallerPid()
{
    return IPCSkeleton::GetCallingPid();
}

extern "C" pid_t GetCallerUid()
{
    return IPCSkeleton::GetCallingUid();
}

extern "C" uint32_t GetCallerTokenId()
{
    return IPCSkeleton::GetCallingTokenID();
}

extern "C" int32_t GetCallerHapInfo(char *bundleName, uint32_t bundleNamelen,
    char *abilityName, uint32_t abilityNameLen)
{
    auto callerToken = IPCSkeleton::GetCallingTokenID();
    auto type = Security::AccessToken::AccessTokenKit::GetTokenType(callerToken);
    if (type != Security::AccessToken::ATokenTypeEnum::TOKEN_HAP) {
        return SOFTBUS_TRANS_TOKEN_HAP_ERR;
    }
    Security::AccessToken::HapTokenInfo hapTokenInfoRes;
    Security::AccessToken::AccessTokenKit::GetHapTokenInfo(callerToken, hapTokenInfoRes);

    if (strcpy_s(bundleName, bundleNamelen, hapTokenInfoRes.bundleName.c_str()) != EOK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] copy bundleName or abilityName failed");
        return SOFTBUS_STRCPY_ERR;
    }
    int32_t userId = GetActiveOsAccountIds();
    int32_t ret = GetAbilityName(abilityName, userId, abilityNameLen, hapTokenInfoRes.bundleName);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] get abilityName failed, ret=%{public}d", ret);
        return ret;
    }

    return SOFTBUS_OK;
}

extern "C" int32_t CheckPushPermission()
{
    auto callerToken = IPCSkeleton::GetCallingTokenID();
    auto type = Security::AccessToken::AccessTokenKit::GetTokenType(callerToken);
    if (type != Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] push must be native sa");
        return SOFTBUS_TRANS_TOKEN_HAP_ERR;
    }
    TRANS_LOGI(TRANS_SVC, "[br_proxy] The push identity passes the authentication.");
    return SOFTBUS_OK;
}