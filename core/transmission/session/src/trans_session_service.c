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
#include "softbus_access_token_adapter.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_permission.h"
#include "softbus_qos.h"
#include "softbus_scenario_manager.h"
#include "softbus_utils.h"
#include "trans_channel_manager.h"
#include "trans_client_proxy.h"
#include "trans_event.h"
#include "trans_log.h"
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
    ret = InitQos();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "QosInit Failed");
        return ret;
    }
    ret = ScenarioManagerGetInstance();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "ScenarioManager init Failed");
        return ret;
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
    TransPermissionDeinit();
    ScenarioManagerdestroyInstance();
    atomic_store_explicit(&g_transSessionInitFlag, false, memory_order_release);
}

void TransServerDeathCallback(const char *pkgName, int32_t pid)
{
    TransChannelDeathCallback(pkgName, pid);
    TransDelItemByPackageName(pkgName, pid);
}

int32_t TransCreateSessionServer(const char *pkgName, const char *sessionName, int32_t uid, int32_t pid)
{
    if (!IsValidString(pkgName, PKG_NAME_SIZE_MAX - 1) || !IsValidString(sessionName, SESSION_NAME_SIZE_MAX - 1)) {
        return SOFTBUS_INVALID_PARAM;
    }
    char *tmpName = NULL;
    Anonymize(sessionName, &tmpName);
    TRANS_LOGI(TRANS_CTRL, "pkgName=%{public}s, sessionName=%{public}s, uid=%{public}d, pid=%{public}d",
        pkgName, AnonymizeWrapper(tmpName), uid, pid);
    AnonymizeFree(tmpName);
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
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "get callingTokenId failed");
    int32_t tokenType = SoftBusGetAccessTokenType(newNode->tokenId);
    newNode->callerType = (SoftBusAccessTokenType)tokenType == ACCESS_TOKEN_TYPE_HAP ?
        CALLER_TYPE_FEATURE_ABILITY : CALLER_TYPE_SERVICE_ABILITY;
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
