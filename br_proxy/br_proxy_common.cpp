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
#include <atomic>
#include <cstring>
#include <dlfcn.h>
#include <securec.h>
#include <mutex>
#include "accesstoken_kit.h"
#include "br_proxy_common.h"
#include "br_proxy_server_manager.h"
#include "ipc_skeleton.h"
#include "lnn_ohos_account_adapter.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "trans_log.h"

#ifdef __aarch64__
#define BR_PROXY_ADAPTER_PATH "/system/lib64/libbr_proxy_adapter.z.so"
#else
#define BR_PROXY_ADAPTER_PATH "/system/lib/libbr_proxy_adapter.z.so"
#endif
 
using namespace OHOS;

typedef int32_t (*GetAbilityNameFunc)(char *abilityName, int32_t userId, uint32_t abilityNameLen,
    std::string bundleName, int32_t *appIndex);
typedef int32_t (*StartAbilityFunc)(const char *bundleName, const char *abilityName, int32_t appIndex);
static void* g_abilityMgrHandle = nullptr;
static StartAbilityFunc g_startAbilityFunc = nullptr;
static GetAbilityNameFunc g_getAbilityName = nullptr;
static int32_t BrProxyLoopInit(void);

static int32_t AbilityManagerClientDynamicLoader(const char *bundleName, const char *abilityName, int32_t appIndex)
{
    if (bundleName == nullptr || abilityName == nullptr) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = BrProxyLoopInit();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] BrProxyLoopInit failed! ret=%{public}d", ret);
        return ret;
    }
    if (g_abilityMgrHandle == nullptr) {
        g_abilityMgrHandle = dlopen(BR_PROXY_ADAPTER_PATH, RTLD_LAZY);
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

    return g_startAbilityFunc(bundleName, abilityName, appIndex);
}

static int32_t GetAbilityName(char *abilityName, int32_t userId, uint32_t abilityNameLen,
    std::string bundleName, int32_t *appIndex)
{
    if (abilityName == nullptr || appIndex == nullptr) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_abilityMgrHandle == nullptr) {
        g_abilityMgrHandle = dlopen(BR_PROXY_ADAPTER_PATH, RTLD_LAZY);
    }
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

    int32_t ret = g_getAbilityName(abilityName, userId, abilityNameLen, bundleName, appIndex);
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

extern "C" int32_t PullUpHap(const char *bundleName, const char *abilityName, int32_t appIndex)
{
    #define CLOSE_DELAY_TIME 3000
    int32_t ret = AbilityManagerClientDynamicLoader(bundleName, abilityName, appIndex);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] failed, ret = %{public}d", ret);
        return ret;
    }
    BrProxyPostDcloseMsgToLooperDelay(CLOSE_DELAY_TIME);
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
    char *abilityName, uint32_t abilityNameLen, int32_t *appIndex)
{
    if (bundleName == nullptr || abilityName == nullptr || appIndex == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
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
    int32_t ret = GetAbilityName(abilityName, userId, abilityNameLen, hapTokenInfoRes.bundleName, appIndex);
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

SoftBusHandler g_brProxyLooperHandler = { 0 };
typedef enum {
    LOOP_DCLOSE_MSG,
} BrProxyLoopMsg;
 
static void BrProxyFreeLoopMsg(SoftBusMessage *msg)
{
    if (msg != nullptr) {
        if (msg->obj != nullptr) {
            SoftBusFree(msg->obj);
        }
        SoftBusFree((void *)msg);
    }
}
 
static SoftBusMessage *BrProxyCreateLoopMsg(int32_t what, uint64_t arg1, uint64_t arg2, char *data)
{
    SoftBusMessage *msg = (SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == nullptr) {
        TRANS_LOGE(TRANS_MSG, "[br_proxy] msg calloc failed");
        return nullptr;
    }
    msg->what = what;
    msg->arg1 = arg1;
    msg->arg2 = arg2;
    msg->handler = &g_brProxyLooperHandler;
    msg->FreeMessage = BrProxyFreeLoopMsg;
    msg->obj = (void *)data;
    return msg;
}
 
void BrProxyPostDcloseMsgToLooperDelay(uint32_t delayTime)
{
    SoftBusMessage *msg  = BrProxyCreateLoopMsg(LOOP_DCLOSE_MSG, 0, 0, nullptr);
    TRANS_CHECK_AND_RETURN_LOGE(msg != nullptr, TRANS_CTRL, "[br_proxy] msg create failed");
 
    g_brProxyLooperHandler.looper->PostMessageDelay(g_brProxyLooperHandler.looper, msg, delayTime);
}
 
static void BrProxyLoopMsgHandler(SoftBusMessage *msg)
{
    TRANS_CHECK_AND_RETURN_LOGE(msg != nullptr, TRANS_CTRL, "[br_proxy] param invalid");
    TRANS_LOGI(TRANS_CTRL, "[br_proxy] trans loop process msgType=%{public}d", msg->what);
    switch (msg->what) {
        case LOOP_DCLOSE_MSG: {
            BrProxyDynamicLoaderDeInit();
            break;
        }
        default:
            break;
    }
}
 
static std::atomic<bool> g_hasInit(false);
static std::mutex g_initMutex;
 
static int32_t BrProxyLoopInit(void)
{
    if (g_hasInit.load()) {
        return SOFTBUS_OK;
    }
 
    std::lock_guard<std::mutex> lock(g_initMutex);
    if (g_hasInit.load()) {
        return SOFTBUS_OK;
    }
    g_brProxyLooperHandler.name = (char *)"brProxyHandlerName";
    g_brProxyLooperHandler.looper = GetLooper(LOOP_TYPE_DEFAULT);
    if (g_brProxyLooperHandler.looper == nullptr) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] loop init failed");
        return SOFTBUS_TRANS_INIT_FAILED;
    }
    g_brProxyLooperHandler.HandleMessage = BrProxyLoopMsgHandler;
    g_hasInit.store(true);
    return SOFTBUS_OK;
}