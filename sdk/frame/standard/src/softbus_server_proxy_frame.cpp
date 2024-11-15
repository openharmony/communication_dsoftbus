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

#include "softbus_server_proxy_frame.h"

#include <chrono>
#include <cstdlib>
#include <ctime>
#include <mutex>
#include <thread>
#include "client_bus_center_manager.h"
#include "client_trans_session_manager.h"
#include "client_trans_socket_manager.h"
#include "bus_center_server_proxy.h"
#include "comm_log.h"
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
#include "softbus_error_code.h"
#include "softbus_server_ipc_interface_code.h"
#include "softbus_server_proxy_standard.h"
#include "trans_server_proxy.h"

namespace {
OHOS::sptr<OHOS::IRemoteObject> g_serverProxy = nullptr;
OHOS::sptr<OHOS::IRemoteObject> g_oldServerProxy = nullptr;
OHOS::sptr<OHOS::IRemoteObject::DeathRecipient> g_clientDeath = nullptr;
std::mutex g_mutex;
constexpr uint32_t WAIT_SERVER_INTERVAL = 50;
constexpr uint32_t SOFTBUS_MAX_RETRY_TIMES = 25;
uint32_t g_getSystemAbilityId = 2;
uint32_t g_printRequestFailedCount = 0;
constexpr int32_t RANDOM_RANGE_MAX = 501; // range of random numbers is (0, 500ms)
constexpr uint32_t PRINT_INTERVAL = 200;
constexpr int32_t CYCLE_NUMBER_MAX = 100;
const std::u16string SAMANAGER_INTERFACE_TOKEN = u"ohos.samgr.accessToken";
}

static int InnerRegisterService(ListNode *sessionServerInfoList)
{
    srand(time(nullptr));
    int32_t randomNum = rand();
    int32_t scaledNum = randomNum % RANDOM_RANGE_MAX;

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
        return SOFTBUS_TRANS_GET_CLIENT_NAME_FAILED;
    }
    for (uint32_t i = 0; i < clientNameNum; i++) {
        while (serverProxyFrame->SoftbusRegisterService(clientName[i], nullptr) != SOFTBUS_OK) {
            SoftBusSleepMs(WAIT_SERVER_READY_INTERVAL);
        }
        SoftBusFree(clientName[i]);
    }
    int32_t ret = ReCreateSessionServerToServer(sessionServerInfoList);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "ReCreateSessionServerToServer failed!");
        return ret;
    }
    COMM_LOGD(COMM_SDK, "softbus server register service success!");
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
        if ((++g_printRequestFailedCount) % PRINT_INTERVAL == 0) {
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
            return SOFTBUS_IPC_ERR;
        }

        if (g_serverProxy == g_oldServerProxy) {
            g_serverProxy = nullptr;
            COMM_LOGE(COMM_SDK, "g_serverProxy not update");
            return SOFTBUS_IPC_ERR;
        }

        g_clientDeath =
            OHOS::sptr<OHOS::IRemoteObject::DeathRecipient>(new (std::nothrow) OHOS::SoftBusClientDeathRecipient());
        if (g_clientDeath == nullptr) {
            COMM_LOGE(COMM_SDK, "DeathRecipient object is nullptr");
            return SOFTBUS_TRANS_DEATH_RECIPIENT_INVALID;
        }
        if (!g_serverProxy->AddDeathRecipient(g_clientDeath)) {
            COMM_LOGE(COMM_SDK, "AddDeathRecipient failed");
            return SOFTBUS_TRANS_ADD_DEATH_RECIPIENT_FAILED;
        }
    }
    return SOFTBUS_OK;
}

static RestartEventCallback g_restartAuthParaCallback = nullptr;

static void RestartAuthParaNotify(void)
{
    if (g_restartAuthParaCallback == nullptr) {
        COMM_LOGI(COMM_SDK, "Restart AuthPara notify is not used");
        return;
    }
    if (g_restartAuthParaCallback() != SOFTBUS_OK) {
        RestartAuthParaCallbackUnregister();
        COMM_LOGE(COMM_SDK, "Restart AuthPara notify failed!");
        return;
    }
    COMM_LOGI(COMM_SDK, "Restart AuthPara notify success!");
}

void ClientDeathProcTask(void)
{
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_oldServerProxy = g_serverProxy;
        if (g_serverProxy != nullptr && g_clientDeath != nullptr) {
            g_serverProxy->RemoveDeathRecipient(g_clientDeath);
        }
        g_serverProxy.clear();
    }
    TransServerProxyDeInit();
    BusCenterServerProxyDeInit();

    ListNode sessionServerInfoList;
    ListInit(&sessionServerInfoList);
    ClientCleanAllSessionWhenServerDeath(&sessionServerInfoList);

    int32_t cnt = 0;
    for (cnt = 0; cnt < CYCLE_NUMBER_MAX; cnt++) {
        if (ServerProxyInit() == SOFTBUS_OK) {
            break;
        }
        SoftBusSleepMs(WAIT_SERVER_INTERVAL);
    }
    if (cnt == CYCLE_NUMBER_MAX) {
        COMM_LOGE(COMM_SDK, "server proxy init reached the maximum count=%{public}d", cnt);
        return;
    }
    TransServerProxyInit();
    BusCenterServerProxyInit();
    InnerRegisterService(&sessionServerInfoList);
    RestartAuthParaNotify();
    DiscRecoveryPublish();
    DiscRecoverySubscribe();
    DiscRecoveryPolicy();
    RestartRegDataLevelChange();
}

void RestartAuthParaCallbackUnregister(void)
{
    g_restartAuthParaCallback = nullptr;
}

int32_t RestartAuthParaCallbackRegister(RestartEventCallback callback)
{
    if (callback == nullptr) {
        COMM_LOGE(COMM_SDK, "Restart OpenAuthSessionWithPara callback register param is invalid!");
        return SOFTBUS_INVALID_PARAM;
    }
    g_restartAuthParaCallback = callback;
    COMM_LOGI(COMM_SDK, "Restart event callback register success!");
    return SOFTBUS_OK;
}

int32_t ClientStubInit(void)
{
    if (ServerProxyInit() != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "ServerProxyInit failed");
        return SOFTBUS_NO_INIT;
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
    uint32_t sleepCnt = 0;
    while (serverProxyFrame->SoftbusRegisterService(pkgName, nullptr) != SOFTBUS_OK) {
        SoftBusSleepMs(WAIT_SERVER_READY_INTERVAL);
        sleepCnt++;
        if (sleepCnt >= SOFTBUS_MAX_RETRY_TIMES) {
            return SOFTBUS_SERVER_NOT_INIT;
        }
    }

    COMM_LOGD(COMM_SDK, "softbus server register service success! pkgName=%{public}s", pkgName);
    return SOFTBUS_OK;
}
