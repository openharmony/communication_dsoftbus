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
#include "client_trans_session_manager.h"
#include "ipc_skeleton.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "softbus_client_death_recipient.h"
#include "softbus_client_frame_manager.h"
#include "softbus_client_stub_interface.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_ipc_def.h"
#include "softbus_log.h"
#include "softbus_server_proxy_standard.h"

using namespace OHOS;

namespace {
sptr<IRemoteObject> g_serverProxy = nullptr;
sptr<IRemoteObject::DeathRecipient> g_clientDeath = nullptr;
std::mutex g_mutex;
uint32_t g_waitServerInterval = 2;
uint32_t g_getSystemAbilityId = 2;
const std::u16string SAMANAGER_INTERFACE_TOKEN = u"ohos.samgr.accessToken";
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
    char *clientName[SOFTBUS_PKGNAME_MAX_NUM] = {0};
    uint32_t clientNameNum = GetSoftBusClientNameList(clientName, SOFTBUS_PKGNAME_MAX_NUM);
    if (clientNameNum == 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "get client name failed");
        return SOFTBUS_ERR;
    }
    for (uint32_t i = 0; i < clientNameNum; i++) {
        while (serverProxyFrame->SoftbusRegisterService(clientName[i], nullptr) != SOFTBUS_OK) {
            SoftBusSleepMs(WAIT_SERVER_READY_INTERVAL);
        }
        SoftBusFree(clientName[i]);
    }
    int32_t ret = ReCreateSessionServerToServer();
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ReCreateSessionServerToServer failed!\n");
        return ret;
    }
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "softbus server register service success!\n");
    return SOFTBUS_OK;
}

static sptr<IRemoteObject> GetSystemAbility()
{
    MessageParcel data;

    if (!data.WriteInterfaceToken(SAMANAGER_INTERFACE_TOKEN)) {
        return nullptr;
    }

    data.WriteInt32(SOFTBUS_SERVER_SA_ID_INNER);
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
    ClientCleanAllSessionWhenServerDeath();

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
    return SOFTBUS_OK;
}

int ClientRegisterService(const char *pkgName)
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
    while (serverProxyFrame->SoftbusRegisterService(pkgName, nullptr) != SOFTBUS_OK) {
        SoftBusSleepMs(WAIT_SERVER_READY_INTERVAL);
    }

    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "%s softbus server register service success!\n", pkgName);
    return SOFTBUS_OK;
}