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

#include "softbus_server_proxy_frame.h"

#include <chrono>
#include <cstdlib>
#include <ctime>
#include <mutex>
#include <thread>
#include "client_trans_session_manager.h"
#include "bus_center_server_proxy.h"
#include "comm_log.h"
#include "disc_server_proxy.h"
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
#include "softbus_server_ipc_interface_code.h"
#include "softbus_server_proxy_standard.h"
#include "trans_server_proxy.h"

namespace {
OHOS::sptr<OHOS::IRemoteObject> g_serverProxy = nullptr;
OHOS::sptr<OHOS::IRemoteObject::DeathRecipient> g_clientDeath = nullptr;
std::mutex g_mutex;
uint32_t g_waitServerInterval = 2;
uint32_t g_getSystemAbilityId = 2;
uint32_t g_printRequestFailedCount = 0;
int32_t g_randomMax = 501; // range of random numbers is (0, 500ms)
constexpr uint32_t g_printInterval = 200;
const std::u16string SAMANAGER_INTERFACE_TOKEN = u"ohos.samgr.accessToken";
}

static int InnerRegisterService(void)
{
    srand(time(nullptr));
    int32_t randomNum = rand();
    int32_t scaledNum = randomNum % g_randomMax;

    // Prevent high-concurrency conflicts
    std::this_thread::sleep_for(std::chrono::milliseconds(scaledNum));
    if (g_serverProxy == nullptr) {
        COMM_LOGE(COMM_SDK, "g_serverProxy is nullptr!");
        return SOFTBUS_INVALID_PARAM;
    }
    OHOS::sptr<OHOS::SoftBusServerProxyFrame> serverProxyFrame =
        new (std::nothrow) OHOS::SoftBusServerProxyFrame(g_serverProxy);
    if (serverProxyFrame == nullptr) {
        COMM_LOGE(COMM_SDK, "serverProxyFrame is nullptr!");
        return SOFTBUS_INVALID_PARAM;
    }
    char *clientName[SOFTBUS_PKGNAME_MAX_NUM] = {0};
    uint32_t clientNameNum = GetSoftBusClientNameList(clientName, SOFTBUS_PKGNAME_MAX_NUM);
    if (clientNameNum == 0) {
        COMM_LOGE(COMM_SDK, "get client name failed");
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
        COMM_LOGE(COMM_SDK, "ReCreateSessionServerToServer failed!\n");
        return ret;
    }
    COMM_LOGI(COMM_SDK, "softbus server register service success!\n");
    return SOFTBUS_OK;
}

static OHOS::sptr<OHOS::IRemoteObject> GetSystemAbility()
{
    OHOS::MessageParcel data;
    if (!data.WriteInterfaceToken(SAMANAGER_INTERFACE_TOKEN)) {
        COMM_LOGE(COMM_EVENT, "write interface token failed!");
        return nullptr;
    }

    data.WriteInt32(SOFTBUS_SERVER_SA_ID_INNER);
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    OHOS::sptr<OHOS::IRemoteObject> samgr = OHOS::IPCSkeleton::GetContextObject();
    if (samgr == nullptr) {
        COMM_LOGE(COMM_EVENT, "Get samgr failed!");
        return nullptr;
    }
    int32_t err = samgr->SendRequest(g_getSystemAbilityId, data, reply, option);
    if (err != 0) {
        if ((++g_printRequestFailedCount) % g_printInterval == 0) {
            COMM_LOGD(COMM_EVENT, "Get GetSystemAbility failed!");
        }
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
            return SOFTBUS_ERR;
        }
        g_clientDeath =
            OHOS::sptr<OHOS::IRemoteObject::DeathRecipient>(new (std::nothrow) OHOS::SoftBusClientDeathRecipient());
        if (g_clientDeath == nullptr) {
            COMM_LOGE(COMM_SDK, "DeathRecipient object is nullptr\n");
            return SOFTBUS_ERR;
        }
        if (!g_serverProxy->AddDeathRecipient(g_clientDeath)) {
            COMM_LOGE(COMM_SDK, "AddDeathRecipient failed\n");
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
        g_serverProxy.clear();
    }
    DiscServerProxyDeInit();
    TransServerProxyDeInit();
    BusCenterServerProxyDeInit();

    ClientCleanAllSessionWhenServerDeath();

    while (true) {
        if (ServerProxyInit() == SOFTBUS_OK) {
            break;
        }
        SoftBusSleepMs(g_waitServerInterval);
    }
    DiscServerProxyInit();
    TransServerProxyInit();
    BusCenterServerProxyInit();
    InnerRegisterService();
    TransBroadCastReInit();
}

int32_t ClientStubInit(void)
{
    if (ServerProxyInit() != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "ServerProxyInit failed\n");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int ClientRegisterService(const char *pkgName)
{
    if (g_serverProxy == nullptr) {
        COMM_LOGE(COMM_SDK, "g_serverProxy is nullptr!");
        return SOFTBUS_INVALID_PARAM;
    }
    OHOS::sptr<OHOS::SoftBusServerProxyFrame> serverProxyFrame =
        new (std::nothrow) OHOS::SoftBusServerProxyFrame(g_serverProxy);
    if (serverProxyFrame == nullptr) {
        COMM_LOGE(COMM_SDK, "serverProxyFrame is nullptr!");
        return SOFTBUS_INVALID_PARAM;
    }
    while (serverProxyFrame->SoftbusRegisterService(pkgName, nullptr) != SOFTBUS_OK) {
        SoftBusSleepMs(WAIT_SERVER_READY_INTERVAL);
    }

    COMM_LOGI(COMM_SDK, "softbus server register service success! pkgName=%{public}s\n", pkgName);
    return SOFTBUS_OK;
}
