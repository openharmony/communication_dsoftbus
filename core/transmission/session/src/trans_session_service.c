/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"
#include "softbus_permission.h"
#include "softbus_utils.h"
#include "trans_channel_manager.h"
#include "trans_session_manager.h"

static bool g_transSessionInitFlag = false;

int TransServerInit(void)
{
    if (g_transSessionInitFlag) {
        return SOFTBUS_OK;
    }
    if (TransPermissionInit() != SOFTBUS_OK) {
        LOG_ERR("Init trans permission failed");
        return SOFTBUS_ERR;
    }
    if (TransSessionMgrInit() != SOFTBUS_OK) {
        LOG_ERR("TransSessionMgrInit failed");
        return SOFTBUS_ERR;
    }
    if (TransChannelInit() != SOFTBUS_OK) {
        LOG_ERR("TransChannelInit failed");
        return SOFTBUS_ERR;
    }
    g_transSessionInitFlag = true;
    LOG_INFO("trans session server list init succ");
    return SOFTBUS_OK;
}

void TransServerDeinit(void)
{
    if (g_transSessionInitFlag == false) {
        return;
    }

    TransSessionMgrDeinit();
    TransChannelDeinit();
    TransPermissionDeinit();
    g_transSessionInitFlag = false;
}

void TransServerDeathCallback(const char *pkgName)
{
    TransDelItemByPackageName(pkgName);
    TransChannelDeathCallback(pkgName);
}

int32_t TransCreateSessionServer(const char *pkgName, const char *sessionName)
{
    if (!IsValidString(pkgName, PKG_NAME_SIZE_MAX) ||
        !IsValidString(sessionName, SESSION_NAME_SIZE_MAX)) {
        return SOFTBUS_INVALID_PARAM;
    }

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

    int ret = TransSessionServerAddItem(newNode);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(newNode);
        if (ret == SOFTBUS_SERVER_NAME_REPEATED) {
            LOG_INFO("SessionServer is already created [%s]", sessionName);
            return SOFTBUS_SERVER_NAME_REPEATED;
        }
        return ret;
    }
    LOG_INFO("CreateSessionServer OK, pkg name: [%s], session name: [%s]", pkgName, sessionName);
    return SOFTBUS_OK;
}

int32_t TransRemoveSessionServer(const char *pkgName, const char *sessionName)
{
    if (!IsValidString(pkgName, PKG_NAME_SIZE_MAX) ||
        !IsValidString(sessionName, SESSION_NAME_SIZE_MAX)) {
        return SOFTBUS_INVALID_PARAM;
    }
    return TransSessionServerDelItem(sessionName);
}

int32_t TransOpenSession(const char *mySessionName, const char *peerSessionName,
    const char *peerDeviceId, const char *groupId, int32_t flags)
{
    LOG_INFO("trans server opensession.");
    if (!IsValidString(mySessionName, SESSION_NAME_SIZE_MAX) ||
        !IsValidString(peerSessionName, SESSION_NAME_SIZE_MAX) ||
        !IsValidString(peerDeviceId, DEVICE_ID_SIZE_MAX) ||
        !IsValidString(groupId, GROUP_ID_SIZE_MAX)) {
        return INVALID_CHANNEL_ID;
    }

    if (!TransSessionServerIsExist(mySessionName)) {
        LOG_ERR("session server invalid");
        return INVALID_CHANNEL_ID;
    }

    return TransOpenChannel(mySessionName, peerSessionName, peerDeviceId, groupId, flags);
}