/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "anonymizer.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_permission.h"
#include "softbus_qos.h"
#include "softbus_scenario_manager.h"
#include "softbus_utils.h"
#include "trans_channel_manager.h"
#include "trans_log.h"
#include "trans_session_manager.h"

static bool g_transSessionInitFlag = false;

int32_t TransServerInit(void)
{
    if (g_transSessionInitFlag) {
        return SOFTBUS_OK;
    }
    if (TransPermissionInit() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "Init trans permission failed");
        return SOFTBUS_ERR;
    }
    if (TransSessionMgrInit() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "TransSessionMgrInit failed");
        return SOFTBUS_ERR;
    }
    if (TransChannelInit() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "TransChannelInit failed");
        return SOFTBUS_ERR;
    }
    if (InitQos() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "QosInit Failed");
        return SOFTBUS_ERR;
    }
    if (ScenarioManagerGetInstance() == NULL) {
        TRANS_LOGE(TRANS_INIT, "ScenarioManager init Failed");
        return SOFTBUS_ERR;
    }
    g_transSessionInitFlag = true;
    TRANS_LOGI(TRANS_INIT, "trans session server list init succ");
    return SOFTBUS_OK;
}

void TransServerDeinit(void)
{
    if (!g_transSessionInitFlag) {
        return;
    }

    TransSessionMgrDeinit();
    TransChannelDeinit();
    TransPermissionDeinit();
    ScenarioManagerdestroyInstance();
    g_transSessionInitFlag = false;
}

void TransServerDeathCallback(const char *pkgName, int32_t pid)
{
    TransChannelDeathCallback(pkgName, pid);
    TransDelItemByPackageName(pkgName, pid);
}

int32_t TransCreateSessionServer(const char *pkgName, const char *sessionName, int32_t uid, int32_t pid)
{
    if (!IsValidString(pkgName, PKG_NAME_SIZE_MAX - 1) ||
        !IsValidString(sessionName, SESSION_NAME_SIZE_MAX - 1)) {
        return SOFTBUS_INVALID_PARAM;
    }
    char *tmpName = NULL;
    Anonymize(sessionName, &tmpName);
    TRANS_LOGI(TRANS_CTRL, "pkgName=%{public}s, sessionName=%{public}s, uid=%{public}d, pid=%{public}d",
        pkgName, tmpName, uid, pid);
    AnonymizeFree(tmpName);
    SessionServer *newNode = (SessionServer *)SoftBusCalloc(sizeof(SessionServer));
    if (newNode == NULL) {
        return SOFTBUS_ERR;
    }
    if (strcpy_s(newNode->pkgName, sizeof(newNode->pkgName), pkgName) != EOK) {
        SoftBusFree(newNode);
        return SOFTBUS_ERR;
    }
    if (strcpy_s(newNode->sessionName, sizeof(newNode->sessionName), sessionName) != EOK) {
        SoftBusFree(newNode);
        return SOFTBUS_ERR;
    }
    newNode->type = SEC_TYPE_CIPHERTEXT;
    newNode->uid = uid;
    newNode->pid = pid;

    int32_t ret = TransSessionServerAddItem(newNode);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(newNode);
        if (ret == SOFTBUS_SERVER_NAME_REPEATED) {
            TRANS_LOGW(TRANS_CTRL, "session server is already created");
        }
        return ret;
    }
    TRANS_LOGD(TRANS_CTRL, "ok");
    return SOFTBUS_OK;
}

int32_t TransRemoveSessionServer(const char *pkgName, const char *sessionName)
{
    if (!IsValidString(pkgName, PKG_NAME_SIZE_MAX - 1) ||
        !IsValidString(sessionName, SESSION_NAME_SIZE_MAX - 1)) {
        return SOFTBUS_INVALID_PARAM;
    }
    return TransSessionServerDelItem(sessionName);
}

int32_t TransOpenSession(const SessionParam *param, TransInfo *info)
{
    TRANS_LOGI(TRANS_CTRL, "trans server opensession.");
    if (!IsValidString(param->sessionName, SESSION_NAME_SIZE_MAX) ||
        !IsValidString(param->peerSessionName, SESSION_NAME_SIZE_MAX) ||
        !IsValidString(param->peerDeviceId, DEVICE_ID_SIZE_MAX) ||
        (param->isQosLane && param->qosCount > QOS_TYPE_BUTT)) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (param->groupId == NULL || strlen(param->groupId) >= GROUP_ID_SIZE_MAX) {
        return SOFTBUS_TRANS_SESSION_GROUP_INVALID;
    }

    if (!TransSessionServerIsExist(param->sessionName)) {
        TRANS_LOGE(TRANS_CTRL, "session server invalid");
        return SOFTBUS_TRANS_SESSION_NAME_NO_EXIST;
    }

    return TransOpenChannel(param, info);
}
