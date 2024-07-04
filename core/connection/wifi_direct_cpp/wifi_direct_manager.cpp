/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "wifi_direct_manager.h"
#include <atomic>
#include <list>
#include <mutex>
#include <securec.h>
#include "conn_log.h"
#include "softbus_error_code.h"
#include "wifi_direct_initiator.h"
#include "wifi_direct_scheduler_factory.h"
#include "data/link_manager.h"
#include "utils/wifi_direct_utils.h"
#include "utils/wifi_direct_anonymous.h"
#include "adapter/p2p_adapter.h"
#include "utils/duration_statistic.h"
#include "conn_event.h"
#include "wifi_direct_role_option.h"
#include "command/processor_selector_factory.h"

static std::atomic<uint32_t> g_requestId = 0;
static std::list<WifiDirectStatusListener> g_listeners;
static std::recursive_mutex g_listenerModuleIdLock;
static bool g_listenerModuleIds[AUTH_ENHANCED_P2P_NUM];
static WifiDirectEnhanceManager g_enhanceManager;
static SyncPtkListener g_syncPtkListener;

static uint32_t GetRequestId(void)
{
    return g_requestId++;
}

static void SetElementTypeExtra(struct WifiDirectConnectInfo *info, ConnEventExtra *extra)
{
    extra->requestId = static_cast<int32_t>(info->requestId);
    extra->linkType = info->connectType;
    extra->expectRole = static_cast<int32_t>(info->expectApiRole);
    extra->peerIp = info->remoteMac;

    if (info->connectType == WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P) {
        info->dfxInfo.linkType = STATISTIC_P2P;
    } else if (info->connectType == WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML) {
        info->dfxInfo.linkType = STATISTIC_HML;
    } else if (info->connectType == WIFI_DIRECT_CONNECT_TYPE_BLE_TRIGGER_HML) {
        info->dfxInfo.linkType = STATISTIC_TRIGGER_HML;
        info->dfxInfo.bootLinkType = STATISTIC_NONE;
    } else if (info->connectType == WIFI_DIRECT_CONNECT_TYPE_AUTH_TRIGGER_HML) {
        info->dfxInfo.linkType = STATISTIC_TRIGGER_HML;
    }

    WifiDirectNegoChannelType type = info->negoChannel.type;
    if (type == NEGO_CHANNEL_AUTH) {
        info->dfxInfo.bootLinkType = STATISTIC_WLAN;
    } else if (type == NEGO_CHANNEL_COC) {
        info->dfxInfo.bootLinkType = STATISTIC_COC;
    }
}

static int32_t AllocateListenerModuleId(void)
{
    CONN_LOGD(CONN_WIFI_DIRECT, "enter");
    std::lock_guard lock(g_listenerModuleIdLock);
    ListenerModule moduleId = UNUSE_BUTT;
    for (int32_t i = 0; i < AUTH_ENHANCED_P2P_NUM; i++) {
        if (!g_listenerModuleIds[i]) {
            g_listenerModuleIds[i] = true;
            moduleId = static_cast<ListenerModule>(AUTH_ENHANCED_P2P_START + i);
            break;
        }
    }

    uint32_t bitmap = 0;
    for (int32_t i = 0; i < AUTH_ENHANCED_P2P_NUM; i++) {
        if (g_listenerModuleIds[i]) {
            bitmap |= (1 << i);
        }
    }
    CONN_LOGD(CONN_WIFI_DIRECT, "moduleId=%{public}d bitmap=0x%{public}x", moduleId, bitmap);
    return moduleId;
}

static bool IsEnhanceP2pModuleId(int32_t moduleId)
{
    return moduleId >= AUTH_ENHANCED_P2P_START && moduleId <= AUTH_ENHANCED_P2P_END;
}

static void FreeListenerModuleId(int32_t moduleId)
{
    CONN_LOGD(CONN_WIFI_DIRECT, "enter");
    std::lock_guard lock(g_listenerModuleIdLock);
    if (IsEnhanceP2pModuleId(moduleId)) {
        g_listenerModuleIds[moduleId - AUTH_ENHANCED_P2P_START] = false;
    }

    uint32_t bitmap = 0;
    for (int32_t i = 0; i < AUTH_ENHANCED_P2P_NUM; i++) {
        if (g_listenerModuleIds[i]) {
            bitmap |= (1 << i);
        }
    }
    CONN_LOGD(CONN_WIFI_DIRECT, "moduleId=%{public}d bitmap=0x%{public}x", moduleId, bitmap);
}

static int32_t ConnectDevice(struct WifiDirectConnectInfo *info, struct WifiDirectConnectCallback *callback)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(info != nullptr, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "info is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(callback != nullptr, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "callback is null");

    OHOS::SoftBus::DurationStatistic::GetInstance().Start(info->requestId,
        OHOS::SoftBus::DurationStatisticCalculatorFactory::GetInstance().NewInstance(info->connectType));
    OHOS::SoftBus::DurationStatistic::GetInstance().Record(info->requestId, OHOS::SoftBus::TotalStart);

    ConnEventExtra extra;
    SetElementTypeExtra(info, &extra);
    CONN_EVENT(EVENT_SCENE_CONNECT, EVENT_STAGE_CONNECT_START, extra);

    int32_t ret = OHOS::SoftBus::WifiDirectRoleOption::GetInstance().GetExpectedRole(
        info->remoteNetworkId, info->connectType, info->expectApiRole, info->isStrict);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get expected role failed");
    ret = OHOS::SoftBus::WifiDirectSchedulerFactory::GetInstance().GetScheduler().ConnectDevice(*info, *callback);

    extra.errcode = ret;
    extra.result = (ret == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED;
    CONN_EVENT(EVENT_SCENE_CONNECT, EVENT_STAGE_CONNECT_INVOKE_PROTOCOL, extra);
    return ret;
}

static int32_t CancelConnectDevice(const struct WifiDirectConnectInfo *info)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(info != nullptr, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "info is null");
    return OHOS::SoftBus::WifiDirectSchedulerFactory::GetInstance().GetScheduler().CancelConnectDevice(*info);
}

static int32_t DisconnectDevice(struct WifiDirectDisconnectInfo *info, struct WifiDirectDisconnectCallback *callback)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(info != nullptr, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "info is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(callback != nullptr, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "callback is null");
    return OHOS::SoftBus::WifiDirectSchedulerFactory::GetInstance().GetScheduler().DisconnectDevice(*info, *callback);
}

static void RegisterStatusListener(struct WifiDirectStatusListener *listener)
{
    g_listeners.push_back(*listener);
}

static int32_t PrejudgeAvailability(const char *remoteNetworkId, enum WifiDirectLinkType connectType)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    CONN_CHECK_AND_RETURN_RET_LOGE(
        remoteNetworkId != nullptr, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "remote networkid is null");
    auto selector = OHOS::SoftBus::ProcessorSelectorFactory::GetInstance().NewSelector();
    auto processor = (*selector)(remoteNetworkId, connectType);
    return processor->PrejudgeAvailability(connectType);
}

static void RefreshRelationShip(const char *remoteUuid, const char *remoteMac)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "remoteUuid=%{public}s, remoteMac=%{public}s",
              OHOS::SoftBus::WifiDirectAnonymizeDeviceId(remoteUuid).c_str(),
              OHOS::SoftBus::WifiDirectAnonymizeMac(remoteMac).c_str());
    OHOS::SoftBus::LinkManager::GetInstance().RefreshRelationShip(remoteUuid, remoteMac);
    OHOS::SoftBus::LinkManager::GetInstance().Dump();
}

static bool LinkHasPtk(const char *remoteDeviceId)
{
    bool hasPtk = false;
    OHOS::SoftBus::LinkManager::GetInstance()
        .ProcessIfPresent(OHOS::SoftBus::InnerLink::LinkType::HML, remoteDeviceId,
                          [&hasPtk] (OHOS::SoftBus::InnerLink &innerLink) {
                              hasPtk = innerLink.HasPtk();
                          });
    CONN_LOGI(CONN_WIFI_DIRECT, "hasPtk=%{public}d", hasPtk);
    return hasPtk;
}

static int32_t SavePtk(const char *remoteDeviceId, const char *ptk)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(remoteDeviceId != nullptr && ptk != nullptr, SOFTBUS_INVALID_PARAM,
                                   CONN_WIFI_DIRECT, "nullptr");
    if (g_enhanceManager.savePTK == nullptr) {
        CONN_LOGE(CONN_WIFI_DIRECT, "not implement");
        return SOFTBUS_NOT_IMPLEMENT;
    }
    return g_enhanceManager.savePTK(remoteDeviceId, ptk);
}

static int32_t SyncPtk(const char *remoteDeviceId)
{
    if (g_enhanceManager.syncPTK == nullptr) {
        CONN_LOGE(CONN_WIFI_DIRECT, "not implement");
        return SOFTBUS_NOT_IMPLEMENT;
    }

    return g_enhanceManager.syncPTK(remoteDeviceId);
}

static void AddSyncPtkListener(SyncPtkListener listener)
{
    g_syncPtkListener = listener;
}

static bool IsDeviceOnline(const char *remoteMac)
{
    bool isOnline = false;
    auto found = OHOS::SoftBus::LinkManager::GetInstance().ProcessIfPresent(remoteMac,
        [&isOnline] (OHOS::SoftBus::InnerLink &innerLink) {
            isOnline = innerLink.GetState() == OHOS::SoftBus::InnerLink::LinkState::CONNECTED;
        });
    if (!found) {
        CONN_LOGI(CONN_WIFI_DIRECT, "not found %{public}s", OHOS::SoftBus::WifiDirectAnonymizeMac(remoteMac).c_str());
        return false;
    }
    CONN_LOGI(CONN_WIFI_DIRECT, "isOnline=%{public}d", isOnline);
    return isOnline;
}

static int32_t GetLocalIpByUuid(const char *uuid, char *localIp, int32_t localIpSize)
{
    bool found = false;
    OHOS::SoftBus::LinkManager::GetInstance().ForEach([&] (const OHOS::SoftBus::InnerLink &innerLink) {
        if (innerLink.GetRemoteDeviceId() == uuid &&
            innerLink.GetState() == OHOS::SoftBus::InnerLink::LinkState::CONNECTED) {
            found = true;
            if (strcpy_s(localIp, localIpSize, innerLink.GetLocalIpv4().c_str()) != EOK) {
                found = false;
            }
            return true;
        }
        return false;
    });

    if (!found) {
        CONN_LOGI(CONN_WIFI_DIRECT, "not found %{public}s", OHOS::SoftBus::WifiDirectAnonymizeDeviceId(uuid).c_str());
        return SOFTBUS_CONN_NOT_FOUND_FAILED;
    }
    CONN_LOGI(CONN_WIFI_DIRECT, "uuid=%{public}s localIp=%{public}s",
              OHOS::SoftBus::WifiDirectAnonymizeDeviceId(uuid).c_str(),
              OHOS::SoftBus::WifiDirectAnonymizeIp(localIp).c_str());
    return SOFTBUS_OK;
}

static int32_t GetLocalIpByRemoteIpOnce(const char *remoteIp, char *localIp, int32_t localIpSize)
{
    bool found = false;
    OHOS::SoftBus::LinkManager::GetInstance().ForEach([&] (const OHOS::SoftBus::InnerLink &innerLink) {
        if (innerLink.GetRemoteIpv4() == remoteIp) {
            found = true;
            if (strcpy_s(localIp, localIpSize, innerLink.GetLocalIpv4().c_str()) != EOK) {
                found = false;
            }
            return true;
        }
        if (innerLink.GetRemoteIpv6() == remoteIp) {
            found = true;
            if (strcpy_s(localIp, localIpSize, innerLink.GetLocalIpv6().c_str()) != EOK) {
                found = false;
            }
            return true;
        }
        return false;
    });

    if (!found) {
        CONN_LOGI(CONN_WIFI_DIRECT, "not found %{public}s", OHOS::SoftBus::WifiDirectAnonymizeIp(remoteIp).c_str());
        return SOFTBUS_CONN_NOT_FOUND_FAILED;
    }
    CONN_LOGI(CONN_WIFI_DIRECT, "remoteIp=%{public}s localIp=%{public}s",
              OHOS::SoftBus::WifiDirectAnonymizeIp(remoteIp).c_str(),
              OHOS::SoftBus::WifiDirectAnonymizeIp(localIp).c_str());
    return SOFTBUS_OK;
}

static constexpr int LOOKUP_TIMES = 10;
static constexpr int LOOKUP_INTERVAL = 20;
static int32_t GetLocalIpByRemoteIp(const char *remoteIp, char *localIp, int32_t localIpSize)
{
    int times = 0;
    while (times < LOOKUP_TIMES) {
        if (GetLocalIpByRemoteIpOnce(remoteIp, localIp, localIpSize) != SOFTBUS_OK) {
            times++;
            CONN_LOGD(CONN_WIFI_DIRECT, "times=%{public}d", times);
            std::this_thread::sleep_for(std::chrono::milliseconds(LOOKUP_INTERVAL));
            continue;
        }
        return SOFTBUS_OK;
    }
    return SOFTBUS_CONN_GET_LOCAL_IP_BY_REMOTE_IP_FAILED;
}

static int32_t GetRemoteUuidByIp(const char *remoteIp, char *uuid, int32_t uuidSize)
{
    bool found = false;
    OHOS::SoftBus::LinkManager::GetInstance().ForEach([&] (const OHOS::SoftBus::InnerLink &innerLink) {
        if (innerLink.GetRemoteIpv4() == remoteIp || innerLink.GetRemoteIpv6() == remoteIp) {
            found = true;
            if (strcpy_s(uuid, uuidSize, innerLink.GetRemoteDeviceId().c_str()) != EOK) {
                found = false;
            }
            return true;
        }
        return false;
    });

    if (!found) {
        CONN_LOGI(CONN_WIFI_DIRECT, "not found %{public}s", OHOS::SoftBus::WifiDirectAnonymizeIp(remoteIp).c_str());
        return SOFTBUS_CONN_NOT_FOUND_FAILED;
    }
    CONN_LOGI(CONN_WIFI_DIRECT, "remoteIp=%{public}s uuid=%{public}s",
              OHOS::SoftBus::WifiDirectAnonymizeIp(remoteIp).c_str(),
              OHOS::SoftBus::WifiDirectAnonymizeDeviceId(uuid).c_str());
    return SOFTBUS_OK;
}

static int32_t GetLocalAndRemoteMacByLocalIp(const char *localIp, char *localMac, size_t localMacSize, char *remoteMac,
    size_t remoteMacSize)
{
    bool found = false;
    OHOS::SoftBus::LinkManager::GetInstance().ForEach([&] (const OHOS::SoftBus::InnerLink &innerLink) {
        if (innerLink.GetLocalIpv4() == localIp || innerLink.GetLocalIpv6() == localIp) {
            found = true;
            if (strcpy_s(localMac, localMacSize, innerLink.GetLocalDynamicMac().c_str()) != EOK) {
                found = false;
            }
            if (strcpy_s(remoteMac, remoteMacSize, innerLink.GetRemoteDynamicMac().c_str()) != EOK) {
                found = false;
            }
            return true;
        } else {
            return false;
        }
    });

    if (!found) {
        CONN_LOGI(CONN_WIFI_DIRECT, "not found %{public}s", OHOS::SoftBus::WifiDirectAnonymizeIp(localIp).c_str());
        return SOFTBUS_CONN_NOT_FOUND_FAILED;
    }
    CONN_LOGI(CONN_WIFI_DIRECT, "localIp=%{public}s localMac=%{public}s remoteMac=%{public}s",
        OHOS::SoftBus::WifiDirectAnonymizeIp(localIp).c_str(), OHOS::SoftBus::WifiDirectAnonymizeMac(localMac).c_str(),
        OHOS::SoftBus::WifiDirectAnonymizeMac(remoteMac).c_str());
    return SOFTBUS_OK;
}

static void NotifyOnline(const char *remoteMac, const char *remoteIp, const char *remoteUuid, bool isSource)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "remoteMac=%{public}s, remoteIp=%{public}s remoteUuid=%{public}s",
              OHOS::SoftBus::WifiDirectAnonymizeMac(remoteMac).c_str(),
              OHOS::SoftBus::WifiDirectAnonymizeIp(remoteIp).c_str(),
              OHOS::SoftBus::WifiDirectAnonymizeDeviceId(remoteUuid).c_str());
    for (auto listener : g_listeners) {
        if (listener.onDeviceOnLine != nullptr) {
            listener.onDeviceOnLine(remoteMac, remoteIp, remoteUuid, isSource);
        }
    }
}

static void NotifyOffline(const char *remoteMac, const char *remoteIp, const char *remoteUuid, const char *localIp)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "remoteMac=%{public}s, remoteIp=%{public}s remoteUuid=%{public}s, localIp=%{public}s",
              OHOS::SoftBus::WifiDirectAnonymizeMac(remoteMac).c_str(),
              OHOS::SoftBus::WifiDirectAnonymizeIp(remoteIp).c_str(),
              OHOS::SoftBus::WifiDirectAnonymizeDeviceId(remoteUuid).c_str(),
              OHOS::SoftBus::WifiDirectAnonymizeIp(localIp).c_str());
    for (auto listener : g_listeners) {
        if (listener.onDeviceOffLine != nullptr) {
            listener.onDeviceOffLine(remoteMac, remoteIp, remoteUuid, localIp);
        }
    }
}

static void NotifyRoleChange(enum WifiDirectRole oldRole, enum WifiDirectRole newRole)
{
    CONN_LOGD(CONN_WIFI_DIRECT, "enter");
    for (auto listener : g_listeners) {
        if (listener.onLocalRoleChange != nullptr) {
            listener.onLocalRoleChange(oldRole, newRole);
        }
    }
}

static void NotifyConnectedForSink(const struct WifiDirectSinkLink *link)
{
    CONN_LOGI(CONN_WIFI_DIRECT,
        "remoteUuid=%{public}s, localIp=%{public}s, remoteIp=%{public}s remoteMac=%{public}s bandWidth=%{public}d",
        OHOS::SoftBus::WifiDirectAnonymizeDeviceId(link->remoteUuid).c_str(),
        OHOS::SoftBus::WifiDirectAnonymizeIp(link->localIp).c_str(),
        OHOS::SoftBus::WifiDirectAnonymizeIp(link->remoteIp).c_str(),
        OHOS::SoftBus::WifiDirectAnonymizeMac(link->remoteMac).c_str(), link->bandWidth);
    for (auto listener : g_listeners) {
        if (listener.onConnectedForSink != nullptr) {
            listener.onConnectedForSink(link);
        }
    }
}

static void NotifyDisconnectedForSink(const struct WifiDirectSinkLink *link)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    for (auto listener : g_listeners) {
        if (listener.onDisconnectedForSink != nullptr) {
            listener.onDisconnectedForSink(link);
        }
    }
}

static bool IsNegotiateChannelNeeded(const char *remoteNetworkId, enum WifiDirectLinkType linkType)
{
    CONN_LOGD(CONN_WIFI_DIRECT, "enter");
    CONN_CHECK_AND_RETURN_RET_LOGE(remoteNetworkId != nullptr, true, CONN_WIFI_DIRECT, "remote networkid is null");
    auto remoteUuid = OHOS::SoftBus::WifiDirectUtils::NetworkIdToUuid(remoteNetworkId);
    CONN_CHECK_AND_RETURN_RET_LOGE(!remoteUuid.empty(), true, CONN_WIFI_DIRECT, "get remote uuid failed");

    auto link = OHOS::SoftBus::LinkManager::GetInstance().GetReuseLink(linkType, remoteUuid);
    if (link == nullptr) {
        CONN_LOGI(CONN_WIFI_DIRECT, "no inner link");
        return true;
    }
    if (link->GetNegotiateChannel() == nullptr) {
        CONN_LOGI(CONN_WIFI_DIRECT, "need negotiate channel");
        return true;
    }
    CONN_LOGI(CONN_WIFI_DIRECT, "no need negotiate channel");
    return false;
}

static bool SupportHmlTwo(void)
{
    return OHOS::SoftBus::WifiDirectUtils::SupportHmlTwo();
}

static bool IsWifiP2pEnabled(void)
{
    return OHOS::SoftBus::P2pAdapter::IsWifiP2pEnabled();
}

static int GetStationFrequency(void)
{
    return OHOS::SoftBus::P2pAdapter::GetStationFrequency();
}

static void RegisterEnhanceManager(WifiDirectEnhanceManager *manager)
{
    CONN_CHECK_AND_RETURN_LOGE(manager != nullptr, CONN_WIFI_DIRECT, "manager is null");
    g_enhanceManager = *manager;
}

static void NotifyPtkSyncResult(const char *remoteDeviceId, int result)
{
    if (g_syncPtkListener == nullptr) {
        CONN_LOGE(CONN_WIFI_DIRECT, "listener is null.");
        return;
    }
    g_syncPtkListener(remoteDeviceId, result);
}

static int32_t Init(void)
{
    CONN_LOGI(CONN_INIT, "init enter");
    OHOS::SoftBus::WifiDirectInitiator::GetInstance().Init();
    return SOFTBUS_OK;
}

static struct WifiDirectManager g_manager = {
    .getRequestId = GetRequestId,
    .allocateListenerModuleId = AllocateListenerModuleId,
    .freeListenerModuleId = FreeListenerModuleId,
    .connectDevice = ConnectDevice,
    .cancelConnectDevice = CancelConnectDevice,
    .disconnectDevice = DisconnectDevice,
    .registerStatusListener = RegisterStatusListener,
    .prejudgeAvailability = PrejudgeAvailability,

    .isNegotiateChannelNeeded = IsNegotiateChannelNeeded,
    .refreshRelationShip = RefreshRelationShip,
    .linkHasPtk = LinkHasPtk,
    .savePTK = SavePtk,
    .syncPTK = SyncPtk,
    .addSyncPtkListener = AddSyncPtkListener,

    .isDeviceOnline = IsDeviceOnline,
    .getLocalIpByUuid = GetLocalIpByUuid,
    .getLocalIpByRemoteIp = GetLocalIpByRemoteIp,
    .getRemoteUuidByIp = GetRemoteUuidByIp,
    .getLocalAndRemoteMacByLocalIp = GetLocalAndRemoteMacByLocalIp,

    .supportHmlTwo = SupportHmlTwo,
    .isWifiP2pEnabled = IsWifiP2pEnabled,
    .getStationFrequency = GetStationFrequency,

    .init = Init,
    .notifyOnline = NotifyOnline,
    .notifyOffline = NotifyOffline,
    .notifyRoleChange = NotifyRoleChange,
    .notifyConnectedForSink = NotifyConnectedForSink,
    .notifyDisconnectedForSink = NotifyDisconnectedForSink,
    .registerEnhanceManager = RegisterEnhanceManager,
    .notifyPtkSyncResult = NotifyPtkSyncResult,
};

struct WifiDirectManager *GetWifiDirectManager(void)
{
    return &g_manager;
}
