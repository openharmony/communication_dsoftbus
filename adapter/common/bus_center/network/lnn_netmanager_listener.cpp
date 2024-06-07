/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permission and
 * limitations under the License.
 */

#include "lnn_event_monitor_impl.h"

#include <cstdint>
#include <string>

#include "anonymizer.h"
#include "bus_center_manager.h"
#include "lnn_async_callback_utils.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_net_capability.h"
#include "net_conn_client.h"
#include "net_interface_callback_stub.h"
#include "net_manager_constants.h"
#include "singleton.h"
#include "softbus_adapter_thread.h"
#include "softbus_bus_center.h"
#include "softbus_config_type.h"
#include "softbus_errcode.h"

namespace OHOS {
namespace LnnNetManager {
using namespace OHOS::NetManagerStandard;

class LnnNetManagerListener : public NetInterfaceStateCallbackStub {
public:
    LnnNetManagerListener() = default;
    ~LnnNetManagerListener() = default;
    LnnNetManagerListener(const LnnNetManagerListener &) = delete;
    LnnNetManagerListener &operator=(const LnnNetManagerListener &) = delete;

    int32_t OnInterfaceAdded(const std::string &ifName) override;
    int32_t OnInterfaceRemoved(const std::string &ifName) override;
    int32_t OnInterfaceChanged(const std::string &ifName, bool up) override;
    int32_t OnInterfaceLinkStateChanged(const std::string &ifName, bool up) override;
    int32_t OnInterfaceAddressUpdated(
        const std::string &addr, const std::string &ifName, int32_t flags, int32_t scope) override;
    int32_t OnInterfaceAddressRemoved(
        const std::string &addr, const std::string &ifName, int32_t flags, int32_t scope) override;
};

static int32_t g_ethCount;
static SoftBusMutex g_ethCountLock;
static OHOS::sptr<OHOS::NetManagerStandard::NetInterfaceStateCallbackStub> g_lnnNetManagerListener = nullptr;

int32_t LnnNetManagerListener::OnInterfaceAdded(const std::string &ifName)
{
    LNN_LOGI(LNN_BUILDER, "ifName=%{public}s", ifName.c_str());
    return SOFTBUS_OK;
}

int32_t LnnNetManagerListener::OnInterfaceRemoved(const std::string &ifName)
{
    LNN_LOGI(LNN_BUILDER, "ifName=%{public}s", ifName.c_str());
    return SOFTBUS_OK;
}

int32_t LnnNetManagerListener::OnInterfaceChanged(const std::string &ifName, bool isUp)
{
    LNN_LOGI(LNN_BUILDER, "ifName=%{public}s, isUp=%{public}s", ifName.c_str(), isUp ? "true" : "false");
    return SOFTBUS_OK;
}

int32_t LnnNetManagerListener::OnInterfaceLinkStateChanged(const std::string &ifName, bool isUp)
{
    LNN_LOGI(LNN_BUILDER, "ifName=%{public}s, isUp=%{public}s", ifName.c_str(), isUp ? "true" : "false");
    uint32_t netCapability = 0;
    int32_t ret = LnnGetLocalNumInfo(NUM_KEY_NET_CAP, (int32_t *)&netCapability);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get cap from local ledger fail");
        return ret;
    }
    if (SoftBusMutexLock(&g_ethCountLock) != 0) {
        LNN_LOGE(LNN_BUILDER, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    if (isUp) {
        // update eth
        if (g_ethCount == 0) {
            LNN_LOGI(LNN_BUILDER, "LnnSetNetCapability");
            (void)LnnSetNetCapability(&netCapability, BIT_ETH);
        }
        ++g_ethCount;
    } else {
        // remove eth
        if (g_ethCount == 0) {
            LNN_LOGI(LNN_BUILDER, "do not have eth to be removed");
            (void)SoftBusMutexUnlock(&g_ethCountLock);
            return SOFTBUS_INVALID_NUM;
        }
        --g_ethCount;
        if (g_ethCount == 0) {
            LNN_LOGI(LNN_BUILDER, "LnnClearNetCapability");
            (void)LnnClearNetCapability(&netCapability, BIT_ETH);
        }
    }
    (void)SoftBusMutexUnlock(&g_ethCountLock);
    ret = LnnSetLocalNumInfo(NUM_KEY_NET_CAP, netCapability);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "set cap to local ledger fail");
        return ret;
    }
    LNN_LOGI(LNN_BUILDER, "local ledger netCapability=%{public}u", netCapability);
    return SOFTBUS_OK;
}

int32_t LnnNetManagerListener::OnInterfaceAddressUpdated(
    const std::string &addr, const std::string &ifName, int32_t flags, int32_t scope)
{
    char *anonyAddr = NULL;
    Anonymize(addr.c_str(), &anonyAddr);
    LNN_LOGI(LNN_BUILDER, "ifName=%{public}s, addr=%{public}s", ifName.c_str(), anonyAddr);
    AnonymizeFree(anonyAddr);
    return SOFTBUS_OK;
}
int32_t LnnNetManagerListener::OnInterfaceAddressRemoved(
    const std::string &addr, const std::string &ifName, int32_t flags, int32_t scope)
{
    char *anonyAddr = NULL;
    Anonymize(addr.c_str(), &anonyAddr);
    LNN_LOGI(LNN_BUILDER, "ifName=%{public}s, addr=%{public}s", ifName.c_str(), anonyAddr);
    AnonymizeFree(anonyAddr);
    return SOFTBUS_OK;
}

} // namespace LnnNetManager
} // namespace OHOS
static void RegEthernetEvent(void *para)
{
    (void)para;
    OHOS::LnnNetManager::g_lnnNetManagerListener = new (std::nothrow) OHOS::LnnNetManager::LnnNetManagerListener;
    if (OHOS::LnnNetManager::g_lnnNetManagerListener == nullptr) {
        LNN_LOGE(LNN_BUILDER, "new lnnNetManagerListener fail");
        return;
    }
    OHOS::LnnNetManager::g_ethCount = 0;
    if (SoftBusMutexInit(&OHOS::LnnNetManager::g_ethCountLock, nullptr) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "init g_ethCountLock fail");
        delete (OHOS::LnnNetManager::g_lnnNetManagerListener);
        return;
    }
    int32_t ret = OHOS::NetManagerStandard::NetConnClient::GetInstance().RegisterNetInterfaceCallback(
        OHOS::LnnNetManager::g_lnnNetManagerListener);
    if (ret != OHOS::NetManagerStandard::NETMANAGER_EXT_SUCCESS) {
        LNN_LOGE(LNN_BUILDER, "RegisterIfacesStateChanged fail, ret=%{public}d", ret);
        SoftBusMutexDestroy(&OHOS::LnnNetManager::g_ethCountLock);
        delete (OHOS::LnnNetManager::g_lnnNetManagerListener);
        return;
    }
    LNN_LOGI(LNN_BUILDER, "RegisterIfacesStateChanged succ");
}

int32_t LnnInitNetManagerMonitorImpl(void)
{
    const int32_t DELAY_LEN = 1000;
    SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
    int32_t ret = LnnAsyncCallbackDelayHelper(looper, RegEthernetEvent, NULL, DELAY_LEN);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "LnnAsyncCallbackDelayHelper fail. ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

void LnnDeinitNetManagerMonitorImpl(void)
{
    if (OHOS::LnnNetManager::g_lnnNetManagerListener != nullptr) {
        delete (OHOS::LnnNetManager::g_lnnNetManagerListener);
        OHOS::LnnNetManager::g_lnnNetManagerListener = nullptr;
    }
    (void)SoftBusMutexDestroy(&OHOS::LnnNetManager::g_ethCountLock);
}