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
#include "power_mgr_client.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_error_code.h"
#include "trans_event.h"
#include "trans_event_form.h"
#include "trans_log.h"

#ifdef __aarch64__
#define BR_PROXY_ADAPTER_PATH "/system/lib64/libbr_proxy_adapter.z.so"
#else
#define BR_PROXY_ADAPTER_PATH "/system/lib/libbr_proxy_adapter.z.so"
#endif
#define COMPARE_SUCCESS 0
#define COMPARE_FAILED  1

using namespace OHOS;
typedef int32_t (*GetAbilityNameFunc)(char *abilityName, int32_t userId, uint32_t abilityNameLen,
    std::string bundleName, int32_t *appIndex);
typedef int32_t (*StartAbilityFunc)(const char *bundleName, const char *abilityName,
    int32_t appIndex, int32_t userId);
typedef int32_t (*UnrestrictedFunc)(const char *bundleName, pid_t pid, pid_t uid, bool isThaw);
typedef bool (*GetRunningProcessInformationFunc)(const std::string bundleName, int32_t userId, pid_t uid, pid_t *pid);

struct SymbolLoader {
    void *handle;
    StartAbilityFunc startAbility;
    GetAbilityNameFunc getAbilityName;
    UnrestrictedFunc unrestricted;
    GetRunningProcessInformationFunc getRunningProcessInformation;
};

static SoftBusMutex g_lock;
static std::shared_ptr<OHOS::PowerMgr::RunningLock> g_powerMgr;
static SymbolLoader g_symbolLoader = { 0 };

static int32_t LoadSymbol(SymbolLoader *loader, bool *load)
{
    if (loader->handle != nullptr) {
        *load = false;
        return SOFTBUS_OK;
    }
    void *handle = dlopen(BR_PROXY_ADAPTER_PATH, RTLD_LAZY);
    if (handle == nullptr) {
        return SOFTBUS_NETWORK_DLOPEN_FAILED;
    }

    StartAbilityFunc startAbility = (StartAbilityFunc)dlsym(handle, "StartAbility");
    GetAbilityNameFunc getAbilityName = (GetAbilityNameFunc)dlsym(handle, "ProxyChannelMgrGetAbilityName");
    UnrestrictedFunc unrestricted = (UnrestrictedFunc)dlsym(handle, "Unrestricted");
    GetRunningProcessInformationFunc getRunningProcessInformation =
        (GetRunningProcessInformationFunc)dlsym(handle, "GetRunningProcessInformation");
    if (startAbility == nullptr || getAbilityName == nullptr || unrestricted == nullptr ||
        getRunningProcessInformation == nullptr) {
        dlclose(handle);
        return SOFTBUS_NETWORK_DLSYM_FAILED;
    }

    loader->handle = handle;
    loader->getAbilityName = getAbilityName;
    loader->startAbility = startAbility;
    loader->unrestricted = unrestricted;
    loader->getRunningProcessInformation = getRunningProcessInformation;

    *load = true;
    return SOFTBUS_OK;
}

static void CleanupSymbolIfNeed(SymbolLoader *loader, bool load)
{
    (void)loader;
    (void)load;
    TRANS_LOGI(TRANS_SVC, "[br_proxy] can ignore");
}

static int32_t AbilityManagerClientDynamicLoader(const char *bundleName, const char *abilityName, int32_t appIndex)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(bundleName != nullptr, SOFTBUS_INVALID_PARAM,
        TRANS_SVC, "[br_proxy] bundle name is invalid");
    TRANS_CHECK_AND_RETURN_RET_LOGE(abilityName != nullptr, SOFTBUS_INVALID_PARAM,
        TRANS_SVC, "[br_proxy] ability name is invalid");

    int32_t ret = BrProxyLoopInit();
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret,
        TRANS_SVC, "[br_proxy] BrProxyLoopInit failed! ret=%{public}d", ret);

    ret = SoftBusMutexLock(&g_lock);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        TRANS_SVC, "[br_proxy] lock failed! ret=%{public}d", ret);
    bool load = false;
    ret = LoadSymbol(&g_symbolLoader, &load);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] load sysmbol failed, ret=%{public}d", ret);
        (void)SoftBusMutexUnlock(&g_lock);
        return ret;
    }
    int32_t userId =  JudgeDeviceTypeAndGetOsAccountIds();
    ret = g_symbolLoader.startAbility(bundleName, abilityName, appIndex, userId);
    if (ret != SOFTBUS_OK) {
        CleanupSymbolIfNeed(&g_symbolLoader, load);
        TRANS_LOGE(TRANS_SVC, "[br_proxy] startAbility failed, ret=%{public}d", ret);
        TransEventExtra extra = {
            .result = EVENT_STAGE_RESULT_FAILED,
            .errcode = ret,
            .userId = userId,
            .appIndex = appIndex,
        };
        TRANS_EVENT(EVENT_SCENE_TRANS_BR_PROXY, EVENT_STAGE_INTERNAL_STATE, extra);
    }
    // ATTENTION: symbol will be cleanup  delay as callback is needed
    (void)SoftBusMutexUnlock(&g_lock);
    return ret;
}

static int32_t GetAbilityName(char *abilityName, int32_t userId, uint32_t abilityNameLen,
    std::string bundleName, int32_t *appIndex)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(abilityName != nullptr, SOFTBUS_INVALID_PARAM,
        TRANS_SVC, "[br_proxy] ability name is invalid");
    TRANS_CHECK_AND_RETURN_RET_LOGE(appIndex != nullptr, SOFTBUS_INVALID_PARAM,
        TRANS_SVC, "[br_proxy] app index is invalid");

    int32_t ret = SoftBusMutexLock(&g_lock);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        TRANS_SVC, "[br_proxy] lock failed! ret=%{public}d", ret);

    bool load = false;
    ret = LoadSymbol(&g_symbolLoader, &load);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] load sysmbol failed, error=%{public}d", ret);
        (void)SoftBusMutexUnlock(&g_lock);
        return ret;
    }

    ret = g_symbolLoader.getAbilityName(abilityName, userId, abilityNameLen, bundleName, appIndex);
    CleanupSymbolIfNeed(&g_symbolLoader, load);
    (void)SoftBusMutexUnlock(&g_lock);
    return ret;
}

void BrProxyDynamicLoaderDeInit()
{
    int32_t ret = SoftBusMutexLock(&g_lock);
    TRANS_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, TRANS_SVC, "[br_proxy] lock failed! ret=%{public}d", ret);
    CleanupSymbolIfNeed(&g_symbolLoader, true);
    (void)SoftBusMutexUnlock(&g_lock);
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
    int32_t uid = GetCallerUid();
    int32_t userId = 0;
    int32_t ret = GetOsAccountLocalIdFromUid(uid, &userId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] get userId failed, ret=%{public}d", ret);
        return ret;
    }
    ret = GetAbilityName(abilityName, userId, abilityNameLen, hapTokenInfoRes.bundleName, appIndex);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] get abilityName failed, ret=%{public}d", ret);
        TransEventExtra extra = {
            .result = EVENT_STAGE_RESULT_FAILED,
            .errcode = ret,
            .userId = userId,
            .appIndex = *appIndex,
        };
        TRANS_EVENT(EVENT_SCENE_TRANS_BR_PROXY, EVENT_STAGE_INTERNAL_STATE, extra);
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

static void BrProxyFreeLoopMsg(SoftBusMessage *msg)
{
    if (msg != nullptr) {
        if (msg->obj != nullptr) {
            SoftBusFree(msg->obj);
        }
        SoftBusFree((void *)msg);
    }
}

static SoftBusMessage *BrProxyCreateLoopMsg(int32_t what, uint64_t arg1, uint64_t arg2, void *data)
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
    msg->obj = data;
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
        case LOOP_STOP_APP_MSG: {
            if (msg->obj == nullptr) {
                return;
            }
            StopAppInfo *info = (StopAppInfo *)msg->obj;
            (void)BrProxyUnrestricted(info->bundleName, info->pid, info->uid, false);
            break;
        }
        case LOOP_BR_PROXY_OPENED_MSG: {
            if (msg->obj == nullptr) {
                TRANS_LOGE(TRANS_CTRL, "[br_proxy] LOOP_BR_PROXY_OPENED_MSG msg is nullptr.");
                return;
            }
            BrProxyOpenedInfo *info = static_cast<BrProxyOpenedInfo *>(msg->obj);
            TransOnBrProxyOpened(info->pid, info->channelId,
                static_cast<const char *>(info->brMac), static_cast<const char *>(info->uuid));
            break;
        }
        default:
            break;
    }
}

static int BrProxyLooperEventCmpFunc(const SoftBusMessage *msg, void *args)
{
    SoftBusMessage *ctx = (SoftBusMessage *)args;
    if (msg->what != ctx->what) {
        return COMPARE_FAILED;
    }
    switch (msg->what) {
        case LOOP_STOP_APP_MSG: {
            TRANS_LOGD(TRANS_CTRL, "[br_proxy] romove stop app msg");
            return COMPARE_SUCCESS;
        }
        default:
            break;
    }
    return COMPARE_FAILED;
}

int32_t BrProxyPostMsgToLooper(int32_t what, uint64_t arg1, uint64_t arg2, void *obj, uint64_t delayMillis)
{
    SoftBusMessage *msg = BrProxyCreateLoopMsg(what, arg1, arg2, obj);
    TRANS_CHECK_AND_RETURN_RET_LOGE(msg != nullptr, SOFTBUS_MALLOC_ERR, TRANS_CTRL, "[br_proxy] msg create failed");
    g_brProxyLooperHandler.looper->PostMessageDelay(g_brProxyLooperHandler.looper, msg, delayMillis);
    return SOFTBUS_OK;
}

void BrProxyRemoveMsgFromLooper(int32_t what, uint64_t arg1, uint64_t arg2, void *obj)
{
    SoftBusMessage ctx = {
        .what = what,
        .arg1 = arg1,
        .arg2 = arg2,
        .obj = obj,
    };
    g_brProxyLooperHandler.looper->RemoveMessageCustom(
        g_brProxyLooperHandler.looper, &g_brProxyLooperHandler, BrProxyLooperEventCmpFunc, &ctx);
}

static std::atomic<bool> g_hasInit(false);
static std::mutex g_initMutex;
 
int32_t BrProxyLoopInit(void)
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

int32_t DynamicLoadInit()
{
    static bool flag = false;
    if (flag) {
        return SOFTBUS_OK;
    }
    SoftBusMutexAttr mutexAttr;
    mutexAttr.type = SOFTBUS_MUTEX_RECURSIVE;
    if (SoftBusMutexInit(&g_lock, &mutexAttr) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "[br_proxy] init lock failed");
        return SOFTBUS_TRANS_INIT_FAILED;
    }
    g_powerMgr = OHOS::PowerMgr::PowerMgrClient::GetInstance().CreateRunningLock("softbus_server_brproxy",
        OHOS::PowerMgr::RunningLockType::RUNNINGLOCK_BACKGROUND);
    flag = true;
    return SOFTBUS_OK;
}

int32_t BrProxyUnrestricted(const char *bundleName, pid_t pid, pid_t uid, bool isThaw)
{
    TRANS_LOGI(TRANS_SVC, "[br_proxy] pid:%{public}d, uid:%{public}d, %{public}s",
        pid, uid, isThaw ? "BrProxyThaw" : "BrProxyFreeze");
    TRANS_CHECK_AND_RETURN_RET_LOGE(bundleName != nullptr, SOFTBUS_INVALID_PARAM,
        TRANS_SVC, "[br_proxy] bundle name is invalid");

    int32_t ret = SoftBusMutexLock(&g_lock);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        TRANS_SVC, "[br_proxy] lock failed! ret=%{public}d", ret);
    bool load = false;
    ret = LoadSymbol(&g_symbolLoader, &load);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] load sysmbol failed, error=%{public}d", ret);
        (void)SoftBusMutexUnlock(&g_lock);
        return ret;
    }
    ret = g_symbolLoader.unrestricted(bundleName, pid, uid, isThaw);
    CleanupSymbolIfNeed(&g_symbolLoader, load);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] unrestricted failed, error=%{public}d", ret);
        (void)SoftBusMutexUnlock(&g_lock);
        TransEventExtra extra = {
            .result = EVENT_STAGE_RESULT_FAILED,
            .errcode = ret,
        };
        TRANS_EVENT(EVENT_SCENE_TRANS_BR_PROXY, EVENT_STAGE_INTERNAL_STATE, extra);
        return ret;
    }
    if (!isThaw) {
        (void)SoftBusMutexUnlock(&g_lock);
        return SOFTBUS_OK;
    }
    if (g_powerMgr == nullptr) {
        g_powerMgr = OHOS::PowerMgr::PowerMgrClient::GetInstance().CreateRunningLock("softbus_server_brproxy",
            OHOS::PowerMgr::RunningLockType::RUNNINGLOCK_BACKGROUND_TASK);
    }
    if (g_powerMgr != nullptr) {
        TRANS_LOGI(TRANS_SVC, "[br_proxy] Anti-sleep begin");
        g_powerMgr->Lock(5000); // 5000ms
    } else {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] get g_powerMgr failed");
    }
    (void)SoftBusMutexUnlock(&g_lock);
    return SOFTBUS_OK;
}

bool CommonGetRunningProcessInformation(const char *bundleName, int32_t userId, pid_t uid, pid_t *pid)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(bundleName != nullptr && pid != nullptr, false,
        TRANS_SVC, "[br_proxy] bundle name is invalid");
    int32_t ret = SoftBusMutexLock(&g_lock);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, false,
        TRANS_SVC, "[br_proxy] lock failed! ret=%{public}d", ret);
    bool load = false;
    ret = LoadSymbol(&g_symbolLoader, &load);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] load sysmbol failed, error=%{public}d", ret);
        (void)SoftBusMutexUnlock(&g_lock);
        return false;
    }
    const std::string stlbundleName = bundleName;
    bool checkRes = g_symbolLoader.getRunningProcessInformation(stlbundleName, userId, uid, pid);
    CleanupSymbolIfNeed(&g_symbolLoader, load);
    (void)SoftBusMutexUnlock(&g_lock);
    return checkRes;
}