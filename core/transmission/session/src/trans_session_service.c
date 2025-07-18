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

#include "trans_session_service.h"

#include "securec.h"
#include <stdatomic.h>

#include "anonymizer.h"
#include "lnn_ohos_account_adapter.h"
#include "g_enhance_trans_func.h"
#include "g_enhance_trans_func_pack.h"
#include "softbus_access_token_adapter.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_permission.h"
#include "softbus_scenario_manager.h"
#include "softbus_utils.h"
#include "softbus_init_common.h"
#include "trans_channel_manager.h"
#include "trans_client_proxy.h"
#include "trans_event.h"
#include "trans_inner.h"
#include "trans_log.h"
#include "trans_session_account_adapter.h"
#include "trans_session_ipc_adapter.h"
#include "trans_session_manager.h"

static _Atomic bool g_transSessionInitFlag = false;

int32_t TransServerInit(void)
{
    if (atomic_load_explicit(&g_transSessionInitFlag, memory_order_acquire)) {
        return SOFTBUS_OK;
    }
    int32_t ret = TransPermissionInit();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "Init trans permission failed");
        return ret;
    }
    ret = TransSessionMgrInit();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "TransSessionMgrInit failed");
        return ret;
    }
    ret = TransChannelInit();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "TransChannelInit failed");
        return ret;
    }
    ret = InitQosPacked();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "QosInit Failed");
        return ret;
    }
    ret = InnerListInit();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "InnerListInit Failed");
        return ret;
    }
    ret = ScenarioManagerGetInstance();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "ScenarioManager init Failed");
        return ret;
    }
    if (InitSoftbusPagingPacked() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "InitSoftbusPagingPacked Failed");
    }
    if (InitSoftbusPagingResPullPacked() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "InitSoftbusPagingResPullPacked Failed");
    }
    RegisterPermissionChangeCallback();
    atomic_store_explicit(&g_transSessionInitFlag, true, memory_order_release);
    TRANS_LOGI(TRANS_INIT, "trans session server list init succ");
    return SOFTBUS_OK;
}

void TransServerDeinit(void)
{
    if (!atomic_load_explicit(&g_transSessionInitFlag, memory_order_acquire)) {
        return;
    }

    TransSessionMgrDeinit();
    TransChannelDeinit();
    InnerListDeinit();
    TransPermissionDeinit();
    ScenarioManagerdestroyInstance();
    DeInitSoftbusPagingPacked();
    DeInitSoftbusPagingResPullPacked();
    atomic_store_explicit(&g_transSessionInitFlag, false, memory_order_release);
}

void TransServerDeathCallback(const char *pkgName, int32_t pid)
{
    TransChannelDeathCallback(pkgName, pid);
    TransDelItemByPackageName(pkgName, pid);
    TransPagingDeathCallbackPacked(pkgName, pid);
    TransProcessGroupTalkieInfoPacked(pkgName);
}

static void TransSetUserId(CallerType callerType, SessionServer *newNode)
{
    if (callerType == CALLER_TYPE_FEATURE_ABILITY) {
        newNode->accessInfo.userId = TransGetUserIdFromUid(newNode->uid);
        if (newNode->accessInfo.userId == INVALID_USER_ID) {
            TRANS_LOGE(TRANS_CTRL, "TransGetUserIdFromUid failed");
            return;
        }
    } else {
        newNode->accessInfo.userId = INVALID_USER_ID;
    }
}

static void PrintSessionInfo(const char *pkgName, const char *sessionName, int32_t uid, int32_t pid)
{
    char *tmpName = NULL;
    Anonymize(sessionName, &tmpName);
    TRANS_LOGI(TRANS_CTRL, "pkgName=%{public}s, sessionName=%{public}s, uid=%{public}d, pid=%{public}d",
        pkgName, AnonymizeWrapper(tmpName), uid, pid);
    AnonymizeFree(tmpName);
}

int32_t TransCreateSessionServer(const char *pkgName, const char *sessionName, int32_t uid, int32_t pid)
{
    if (!IsValidString(pkgName, PKG_NAME_SIZE_MAX - 1) || !IsValidString(sessionName, SESSION_NAME_SIZE_MAX - 1)) {
        return SOFTBUS_INVALID_PARAM;
    }
    PrintSessionInfo(pkgName, sessionName, uid, pid);
    SessionServer *newNode = (SessionServer *)SoftBusCalloc(sizeof(SessionServer));
    TRANS_CHECK_AND_RETURN_RET_LOGE(newNode != NULL, SOFTBUS_MALLOC_ERR, TRANS_CTRL, "malloc failed");
    if (strcpy_s(newNode->pkgName, sizeof(newNode->pkgName), pkgName) != EOK) {
        SoftBusFree(newNode);
        return SOFTBUS_STRCPY_ERR;
    }
    if (strcpy_s(newNode->sessionName, sizeof(newNode->sessionName), sessionName) != EOK) {
        SoftBusFree(newNode);
        return SOFTBUS_STRCPY_ERR;
    }
    newNode->type = SEC_TYPE_CIPHERTEXT;
    newNode->uid = uid;
    newNode->pid = pid;

    int32_t ret = TransGetCallingFullTokenId(&newNode->tokenId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get callingTokenId failed, ret=%{public}d", ret);
        SoftBusFree(newNode);
        return ret;
    }
    newNode->accessInfo.localTokenId = newNode->tokenId;
    int32_t tokenType = SoftBusGetAccessTokenType(newNode->tokenId);
    newNode->callerType = (SoftBusAccessTokenType)tokenType == ACCESS_TOKEN_TYPE_HAP ?
        CALLER_TYPE_FEATURE_ABILITY : CALLER_TYPE_SERVICE_ABILITY;
    newNode->tokenType = tokenType;
    TransSetUserId(newNode->callerType, newNode);
    ret = TransSessionServerAddItem(newNode);
    TransEventExtra extra = {
        .socketName = sessionName,
        .callerPkg = pkgName,
        .errcode = ret,
        .result = ret == SOFTBUS_OK ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED
    };
    if (ret != SOFTBUS_OK) {
        SoftBusFree(newNode);
        if (ret == SOFTBUS_SERVER_NAME_REPEATED) {
            TRANS_LOGD(TRANS_CTRL, "session server is already created");
        }
        TRANS_EVENT(EVENT_SCENE_TRANS_CREATE_SESS_SERVER, EVENT_STAGE_TRANS_COMMON_ONE, extra);
        return ret;
    }
    TRANS_EVENT(EVENT_SCENE_TRANS_CREATE_SESS_SERVER, EVENT_STAGE_TRANS_COMMON_ONE, extra);
    TRANS_LOGD(TRANS_CTRL, "ok");
    return SOFTBUS_OK;
}

int32_t TransRemoveSessionServer(const char *pkgName, const char *sessionName)
{
    if (!IsValidString(pkgName, PKG_NAME_SIZE_MAX - 1) ||
        !IsValidString(sessionName, SESSION_NAME_SIZE_MAX - 1)) {
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = TransSessionServerDelItem(sessionName);
    TransEventExtra extra = {
        .socketName = sessionName,
        .callerPkg = pkgName,
        .errcode = ret,
        .result = ret == SOFTBUS_OK ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED
    };
    TRANS_EVENT(EVENT_SCENE_TRANS_REMOVE_SESS_SERVER, EVENT_STAGE_TRANS_COMMON_ONE, extra);
    return ret;
}

int32_t TransOpenSession(const SessionParam *param, TransInfo *info)
{
    if (!IsValidString(param->sessionName, SESSION_NAME_SIZE_MAX) ||
        !IsValidString(param->peerSessionName, SESSION_NAME_SIZE_MAX) ||
        !IsValidString(param->peerDeviceId, DEVICE_ID_SIZE_MAX) ||
        (param->isQosLane && param->qosCount > QOS_TYPE_BUTT)) {
        TRANS_LOGE(TRANS_CTRL, "SessionParam check failed");
        return SOFTBUS_INVALID_PARAM;
    }
    if (param->groupId == NULL || strlen(param->groupId) >= GROUP_ID_SIZE_MAX) {
        TRANS_LOGE(TRANS_CTRL, "invalid groupId");
        return SOFTBUS_TRANS_SESSION_GROUP_INVALID;
    }

    if (!TransSessionServerIsExist(param->sessionName)) {
        TRANS_LOGE(TRANS_CTRL, "session server invalid");
        return SOFTBUS_TRANS_SESSION_NAME_NO_EXIST;
    }

    return TransOpenChannel(param, info);
}