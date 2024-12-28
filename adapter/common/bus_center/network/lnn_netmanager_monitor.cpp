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
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "lnn_netmanager_monitor.h"

#include <cstring>
#include <ctime>
#include <regex>
#include <securec.h>

#include "anonymizer.h"
#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "lnn_async_callback_utils.h"
#include "lnn_event_monitor_impl.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_net_capability.h"
#include "net_conn_client.h"
#include "net_interface_callback_stub.h"
#include "softbus_adapter_file.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_bus_center.h"
#include "softbus_config_type.h"
#include "softbus_error_code.h"

static const int32_t DELAY_LEN = 1000;
static const int32_t NETMANAGER_OK = 0;
static const int32_t DUPLICATE_ROUTE = -17;
static const int32_t MAX_RETRY_COUNT = 20;

namespace OHOS {
namespace BusCenter {
class NetInterfaceStateMonitor : public OHOS::NetManagerStandard::NetInterfaceStateCallbackStub {
public:
    explicit NetInterfaceStateMonitor();
    virtual ~NetInterfaceStateMonitor() = default;

public:
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
static int32_t g_retry = 0;
static OHOS::sptr<OHOS::NetManagerStandard::INetInterfaceStateCallback> g_netlinkCallback = nullptr;

NetInterfaceStateMonitor::NetInterfaceStateMonitor()
{}

int32_t NetInterfaceStateMonitor::OnInterfaceAdded(const std::string &ifName)
{
    LnnNotifyNetlinkStateChangeEvent(SOFTBUS_NETMANAGER_IFNAME_ADDED, ifName.c_str());
    return SOFTBUS_OK;
}

int32_t NetInterfaceStateMonitor::OnInterfaceRemoved(const std::string &ifName)
{
    LnnNotifyNetlinkStateChangeEvent(SOFTBUS_NETMANAGER_IFNAME_REMOVED, ifName.c_str());
    return SOFTBUS_OK;
}

int32_t NetInterfaceStateMonitor::OnInterfaceChanged(const std::string &ifName, bool isUp)
{
    return SOFTBUS_OK;
}

int32_t NetInterfaceStateMonitor::OnInterfaceLinkStateChanged(const std::string &ifName, bool isUp)
{
    if (strstr(ifName.c_str(), "eth") == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
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

int32_t NetInterfaceStateMonitor::OnInterfaceAddressUpdated(
    const std::string &addr, const std::string &ifName, int32_t flags, int32_t scope)
{
    char *anonyAddr = nullptr;
    Anonymize(addr.c_str(), &anonyAddr);
    LNN_LOGI(LNN_BUILDER, "ifName=%{public}s, addr=%{public}s", ifName.c_str(), AnonymizeWrapper(anonyAddr));
    AnonymizeFree(anonyAddr);
    if (strstr(ifName.c_str(), "eth") == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_ethCountLock) != 0) {
        LNN_LOGE(LNN_BUILDER, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    if (g_ethCount != 0) {
        (void)SoftBusMutexUnlock(&g_ethCountLock);
        return SOFTBUS_OK;
    }

    uint32_t netCapability = 0;
    int32_t ret = LnnGetLocalNumU32Info(NUM_KEY_NET_CAP, &netCapability);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get cap from local ledger fail");
        (void)SoftBusMutexUnlock(&g_ethCountLock);
        return ret;
    }

    (void)LnnSetNetCapability(&netCapability, BIT_ETH);
    ret = LnnSetLocalNumU32Info(NUM_KEY_NET_CAP, netCapability);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "set cap to local ledger fail");
        (void)SoftBusMutexUnlock(&g_ethCountLock);
        return ret;
    }
    ++g_ethCount;
    (void)SoftBusMutexUnlock(&g_ethCountLock);
    LNN_LOGI(LNN_BUILDER, "local ledger netCapability=%{public}u", netCapability);
    return SOFTBUS_OK;
}

int32_t NetInterfaceStateMonitor::OnInterfaceAddressRemoved(
    const std::string &addr, const std::string &ifName, int32_t flags, int32_t scope)
{
    return SOFTBUS_OK;
}
} // namespace BusCenter
} // namespace OHOS

int32_t ConfigNetLinkUp(const char *ifName)
{
    if (ifName == nullptr) {
        LNN_LOGE(LNN_BUILDER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret =
        OHOS::NetManagerStandard::NetConnClient::GetInstance().SetInterfaceUp(ifName);
    if (ret != NETMANAGER_OK) {
        LNN_LOGE(LNN_BUILDER, "up net interface %{public}s failed with ret=%{public}d", ifName, ret);
        return SOFTBUS_NETWORK_CONFIG_NETLINK_UP_FAIL;
    }
    return SOFTBUS_OK;
}

int32_t ConfigLocalIp(const char *ifName, const char *localIp)
{
    if (ifName == nullptr || localIp == nullptr) {
        LNN_LOGE(LNN_BUILDER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret =
        OHOS::NetManagerStandard::NetConnClient::GetInstance().SetNetInterfaceIpAddress(ifName, localIp);
    if (ret != NETMANAGER_OK) {
        LNN_LOGE(LNN_BUILDER, "config net interface %{public}s ip failed with ret=%{public}d", ifName, ret);
        return SOFTBUS_NETWORK_CONFIG_NETLINK_IP_FAIL;
    }
    return SOFTBUS_OK;
}

int32_t ConfigRoute(const int32_t id, const char *ifName, const char *destination, const char *gateway)
{
    if (ifName == nullptr || destination == nullptr || gateway == nullptr) {
        LNN_LOGE(LNN_BUILDER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret =
        OHOS::NetManagerStandard::NetConnClient::GetInstance().AddNetworkRoute(id, ifName, destination, gateway);
    if (ret != NETMANAGER_OK && ret != DUPLICATE_ROUTE) {
        LNN_LOGE(LNN_BUILDER, "config net interface %{public}s route failed with ret=%{public}d", ifName, ret);
        return SOFTBUS_NETWORK_CONFIG_NETLINK_ROUTE_FAIL;
    }
    return SOFTBUS_OK;
}

static void LnnRegisterNetManager(void *param)
{
    (void)param;
    if (OHOS::BusCenter::g_retry >= MAX_RETRY_COUNT) {
        LNN_LOGE(LNN_INIT, "retry is max size");
        if (OHOS::BusCenter::g_netlinkCallback != nullptr) {
            delete (OHOS::BusCenter::g_netlinkCallback);
            OHOS::BusCenter::g_netlinkCallback = nullptr;
        }
        return;
    }
    if (OHOS::BusCenter::g_netlinkCallback == nullptr) {
        OHOS::BusCenter::g_netlinkCallback = new (std::nothrow) OHOS::BusCenter::NetInterfaceStateMonitor();
    }
    if (OHOS::BusCenter::g_netlinkCallback == nullptr) {
        LNN_LOGE(LNN_INIT, "new NetInterfaceStateMonitor failed");
        LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), LnnRegisterNetManager, NULL, DELAY_LEN);
        ++OHOS::BusCenter::g_retry;
        return;
    }
    OHOS::BusCenter::g_ethCount = 0;
    if (SoftBusMutexInit(&OHOS::BusCenter::g_ethCountLock, nullptr) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "init g_ethCountLock fail");
        LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), LnnRegisterNetManager, NULL, DELAY_LEN);
        ++OHOS::BusCenter::g_retry;
        return;
    }
    int32_t ret = OHOS::NetManagerStandard::NetConnClient::GetInstance().RegisterNetInterfaceCallback(
        OHOS::BusCenter::g_netlinkCallback);
    if (ret != NETMANAGER_OK) {
        SoftBusMutexDestroy(&OHOS::BusCenter::g_ethCountLock);
        LNN_LOGE(LNN_INIT, "register netmanager callback failed with ret=%{public}d", ret);
        LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), LnnRegisterNetManager, NULL, DELAY_LEN);
        ++OHOS::BusCenter::g_retry;
        return;
    }
    LNN_LOGI(LNN_INIT, "LnnRegisterNetManager succ");
}

int32_t LnnInitNetManagerMonitorImpl(void)
{
    SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
    int32_t ret = LnnAsyncCallbackDelayHelper(looper, LnnRegisterNetManager, NULL, DELAY_LEN);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "LnnAsyncCallbackDelayHelper fail");
        return SOFTBUS_NETWORK_MONITOR_INIT_FAIL;
    }
    return SOFTBUS_OK;
}

void LnnDeinitNetManagerMonitorImpl(void)
{
    if (OHOS::BusCenter::g_netlinkCallback != nullptr) {
        delete (OHOS::BusCenter::g_netlinkCallback);
        OHOS::BusCenter::g_netlinkCallback = nullptr;
    }
    (void)SoftBusMutexDestroy(&OHOS::BusCenter::g_ethCountLock);
}