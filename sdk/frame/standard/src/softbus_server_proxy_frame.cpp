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

#include "softbus_server_proxy_frame.h"

#include <mutex>
#include <unistd.h>
#include "ipc_skeleton.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "softbus_client_death_recipient.h"
#include "softbus_client_frame_manager.h"
#include "softbus_client_stub_interface.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_server_proxy_standard.h"
#include "system_ability_definition.h"

using namespace OHOS;

namespace {
sptr<IRemoteObject> g_serverProxy = nullptr;
sptr<IRemoteObject::DeathRecipient> g_clientDeath = nullptr;
std::mutex g_mutex;
uint32_t g_waitServerInterval = 2;
uint32_t g_getSystemAbilityId = 2;
}

static int InnerRegisterService(void)
{
    if (g_serverProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "g_serverProxy is nullptr!");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<SoftBusServerProxyFrame> serverProxyFrame = new (std::nothrow) SoftBusServerProxyFrame(g_serverProxy);
    if (serverProxyFrame == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "serverProxyFrame is nullptr!");
        return SOFTBUS_INVALID_PARAM;
    }
    char clientName[PKG_NAME_SIZE_MAX] = {0};
    if (GetSoftBusClientName(clientName, sizeof(clientName)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "get client name failed");
        return SOFTBUS_ERR;
    }
    int ret = serverProxyFrame->SoftbusRegisterService(clientName, nullptr);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerIpcRegisterService failed!\n");
        return ret;
    }
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "softbus server register service success!\n");
    return SOFTBUS_OK;
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
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "Get GetSystemAbility failed!\n");
        return nullptr;
    }
    return reply.ReadRemoteObject();
}

static int32_t ServerProxyInit(void)
{
    if (g_serverProxy == nullptr) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_serverProxy == nullptr) {
            g_serverProxy = GetSystemAbility();
            if (g_serverProxy == nullptr) {
                SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "Get remote softbus object failed!\n");
                return SOFTBUS_ERR;
            }
            g_clientDeath = sptr<IRemoteObject::DeathRecipient>(new (std::nothrow) SoftBusClientDeathRecipient());
            if (g_clientDeath == nullptr) {
                SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "DeathRecipient object is nullptr\n");
                return SOFTBUS_ERR;
            }
            if (!g_serverProxy->AddDeathRecipient(g_clientDeath)) {
                SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "AddDeathRecipient failed\n");
                return SOFTBUS_ERR;
            }
        }
    }
    return SOFTBUS_OK;
}

void ClientDeathProcTask(void)
{
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_serverProxy != nullptr && g_clientDeath != nullptr) {
            g_serverProxy->RemoveDeathRecipient(g_clientDeath);
        }
        g_serverProxy = nullptr;
    }

    while (g_serverProxy == nullptr) {
        sleep(g_waitServerInterval);
        ServerProxyInit();
        if (g_serverProxy != nullptr) {
            break;
        }
    }
    InnerRegisterService();
}

int32_t ClientStubInit(void)
{
    if (ServerProxyInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerProxyInit failed\n");
        return SOFTBUS_ERR;
    }
    if (InnerRegisterService() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "register service failed\n");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}