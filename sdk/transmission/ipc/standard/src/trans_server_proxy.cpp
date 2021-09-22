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

#include "trans_server_proxy.h"
#include "trans_server_proxy_standard.h"

#include <mutex>
#include "ipc_skeleton.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "system_ability_definition.h"

using namespace OHOS;

namespace {
sptr<TransServerProxy> g_serverProxy = nullptr;
uint32_t g_getSystemAbilityId = 2;
std::mutex g_mutex;
}

static sptr<IRemoteObject> GetSystemAbility()
{
    MessageParcel data;
    data.WriteInt32(SOFTBUS_SERVER_SA_ID);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> samgr = IPCSkeleton::GetContextObject();
    int32_t err = samgr->SendRequest(g_getSystemAbilityId, data, reply, option);
    if (err != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Get GetSystemAbility failed!\n");
        return nullptr;
    }
    return reply.ReadRemoteObject();
}

int32_t TransServerProxyInit(void)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    sptr<IRemoteObject> object = GetSystemAbility();
    g_serverProxy = new (std::nothrow) TransServerProxy(object);
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Get remote softbus object failed!\n");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ServerIpcCreateSessionServer(const char *pkgName, const char *sessionName)
{
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "softbus server g_serverProxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    if ((pkgName == nullptr) || (sessionName == nullptr)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pkgName or sessionName is nullptr!\n");
        return SOFTBUS_ERR;
    }
    return g_serverProxy->CreateSessionServer(pkgName, sessionName);
}

int32_t ServerIpcRemoveSessionServer(const char *pkgName, const char *sessionName)
{
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "softbus server g_serverProxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    if ((pkgName == nullptr) || (sessionName == nullptr)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pkgName or sessionName is nullptr!\n");
        return SOFTBUS_ERR;
    }
    return g_serverProxy->RemoveSessionServer(pkgName, sessionName);
}

int32_t ServerIpcOpenSession(const SessionParam* param, TransInfo* info)
{
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "softbus server g_serverProxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    if ((param->sessionName == nullptr) || (param->peerSessionName == nullptr) ||
        (param->peerDeviceId == nullptr) || (param->groupId == nullptr) || (param->attr == nullptr)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "parameter is nullptr!\n");
        return SOFTBUS_ERR;
    }
    int ret = g_serverProxy->OpenSession(param, info);
    if (ret < SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenSession failed!\n");
        return SOFTBUS_ERR;
    }
    return ret;
}

int32_t ServerIpcOpenAuthSession(const char *sessionName, const ConnectionAddr *addrInfo)
{
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "softbus server g_serverProxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    if ((sessionName == nullptr) || (addrInfo == nullptr)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "parameter is nullptr!\n");
        return SOFTBUS_ERR;
    }
    int channelId = g_serverProxy->OpenAuthSession(sessionName, addrInfo);
    if (channelId < SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenAuthSession failed!\n");
        return SOFTBUS_ERR;
    }
    return channelId;
}

int32_t ServerIpcNotifyAuthSuccess(int channelId)
{
    return g_serverProxy->NotifyAuthSuccess(channelId);
}

int32_t ServerIpcCloseChannel(int32_t channelId, int32_t channelType)
{
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "softbus server g_serverProxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    if (channelId < SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid channel Id!\n");
        return SOFTBUS_ERR;
    }
    return g_serverProxy->CloseChannel(channelId, channelType);
}

int32_t ServerIpcSendMessage(int32_t channelId, int32_t channelType, const void *data, uint32_t len, int32_t msgType)
{
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "softbus server g_serverProxy is nullptr!\n");
        return SOFTBUS_ERR;
    }

    return g_serverProxy->SendMessage(channelId, channelType, data, len, msgType);
}