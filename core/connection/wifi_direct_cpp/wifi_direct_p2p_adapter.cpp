/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "wifi_direct_p2p_adapter.h"

#include "securec.h"

#include "conn_log.h"
#include "softbus_error_code.h"

#include "data/interface_info.h"
#include "data/interface_manager.h"
#include "entity/p2p_entity.h"
#include "utils/wifi_direct_anonymous.h"
#include "utils/wifi_direct_utils.h"

namespace OHOS::SoftBus {
WifiDirectP2pAdapter *WifiDirectP2pAdapter::GetInstance()
{
    static WifiDirectP2pAdapter instance;
    return &instance;
}

void WifiDirectP2pAdapter::Listener(BroadcastReceiverAction action, const struct BroadcastParam &param)
{
    if (param.p2pLinkInfo.connectState == P2pConnectionState::P2P_DISCONNECTED) {
        CONN_LOGI(CONN_WIFI_DIRECT, "enter");
        CONN_CHECK_AND_RETURN_LOGE(groupOwnerDestroyListener_ != nullptr, CONN_WIFI_DIRECT, "listener is null");
        CONN_CHECK_AND_RETURN_LOGE(isCreateGroup_, CONN_WIFI_DIRECT, "not create group");
        groupOwnerDestroyListener_(SOFTBUS_CONN_P2P_GO_NO_EXIST);
        std::lock_guard lock(mutex_);
        groupOwnerDestroyListener_ = nullptr;
        isCreateGroup_ = false;
    }
}

static bool g_wifiDirectP2pAdapterInit = false;
void WifiDirectP2pAdapter::Init()
{
    if (g_wifiDirectP2pAdapterInit) {
        return;
    }
    g_wifiDirectP2pAdapterInit = true;
    BroadcastReceiverAction actions[1] = {
        BroadcastReceiverAction::WIFI_P2P_CONNECTION_CHANGED_ACTION,
    };
    P2pBroadcast::GetInstance()->RegisterBroadcastListener(actions, ARRAY_SIZE(actions),
        "wifiDirectP2pAdapter", ListenerPriority::LISTENER_PRIORITY_HIGH, WifiDirectP2pAdapter::Listener);
}

int WifiDirectP2pAdapter::SetGroupOwnerResult(std::string groupConfig, struct GroupOwnerResult *result)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(result != nullptr, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "result is null");

    std::vector<std::string> configs = WifiDirectUtils::SplitString(groupConfig, "\n");
    CONN_CHECK_AND_RETURN_RET_LOGW(configs.size() >= P2P_GROUP_CONFIG_INDEX_MODE, SOFTBUS_CONN_REMOTE_CONFIG_NULL,
        CONN_WIFI_DIRECT, "remote group config info is empty");

    auto ret = strcpy_s(result->ssid, sizeof(result->ssid), configs[P2P_GROUP_CONFIG_INDEX_SSID].c_str());
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_MEM_ERR, CONN_WIFI_DIRECT, "copy ssid fail");

    std::vector<uint8_t> bssid = WifiDirectUtils::MacStringToArray(configs[P2P_GROUP_CONFIG_INDEX_BSSID]);
    ret = memcpy_s(result->bssid, sizeof(result->bssid), bssid.data(), bssid.size());
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_MEM_ERR, CONN_WIFI_DIRECT, "copy bssid fail");

    ret = strcpy_s(result->preSharedKey, sizeof(result->preSharedKey),
        configs[P2P_GROUP_CONFIG_INDEX_SHARE_KEY].c_str());
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_MEM_ERR, CONN_WIFI_DIRECT, "copy share key fail");

    bool res = WifiDirectUtils::StringToInt(configs[P2P_GROUP_CONFIG_INDEX_FREQ], result->frequency);
    CONN_CHECK_AND_RETURN_RET_LOGE(res, SOFTBUS_MEM_ERR, CONN_WIFI_DIRECT,
        "freq in group config is invalid number string");
    CONN_LOGI(CONN_WIFI_DIRECT, "connect config freq=%{public}d", result->frequency);

    std::string localIp;
    ret = P2pAdapter::GetIpAddress(localIp);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get ip address failed");
    ret = strcpy_s(result->localIp, sizeof(result->localIp), localIp.c_str());
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_MEM_ERR, CONN_WIFI_DIRECT, "copy ip fail");
    return SOFTBUS_OK;
}

int WifiDirectP2pAdapter::CreateGroup(struct GroupOwnerResult *result)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(result != nullptr, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "result is null");
    bool p2pEnable = false;
    InterfaceManager::GetInstance().ReadInterface(InterfaceInfo::P2P, [&p2pEnable](const InterfaceInfo &interface) {
        p2pEnable = interface.IsEnable();
        return SOFTBUS_OK;
    });
    CONN_CHECK_AND_RETURN_RET_LOGE(p2pEnable, SOFTBUS_P2P_NOT_SUPPORT, CONN_WIFI_DIRECT, "p2p is not enable");

    auto freq = WifiDirectUtils::ChannelToFrequency(P2pAdapter::GetRecommendChannel());
    CONN_CHECK_AND_RETURN_RET_LOGE(freq != FREQUENCY_INVALID, freq, CONN_WIFI_DIRECT, "get frequency failed");
    int coexCode = P2pAdapter::GetCoexConflictCode(IF_NAME_P2P, freq);
    CONN_CHECK_AND_RETURN_RET_LOGE(
        coexCode == SOFTBUS_OK, coexCode, CONN_WIFI_DIRECT, "coex conflict, ret=%{public}d", coexCode);
    
    P2pAdapter::CreateGroupParam param {};
    param.frequency = freq;
    auto res = P2pEntity::GetInstance().CreateGroup(param);
    CONN_CHECK_AND_RETURN_RET_LOGE(res.errorCode_ == SOFTBUS_OK, res.errorCode_, CONN_WIFI_DIRECT,
        "create group failed, errorCode=%{public}d", res.errorCode_);
    std::string groupConfig;
    auto ret = P2pAdapter::GetGroupConfig(groupConfig);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "get group config fail, error=%{public}d", ret);
        (void)RemoveGroupNotAddReuse();
        return ret;
    }
    ret = InterfaceManager::GetInstance().UpdateInterface(
        InterfaceInfo::P2P, [groupConfig](InterfaceInfo &interface) {
            interface.SetP2pGroupConfig(groupConfig);
            int32_t reuseCount = interface.GetReuseCount();
            interface.SetReuseCount(reuseCount + 1);
            CONN_LOGI(CONN_WIFI_DIRECT, "reuseCnt=%{public}d", interface.GetReuseCount());
            return SOFTBUS_OK;
        });
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "update interface failed, ret=%{public}d", ret);
        (void)RemoveGroup();
        return ret;
    }
    ret = SetGroupOwnerResult(groupConfig, result);
    if (ret != SOFTBUS_OK) {
        (void)RemoveGroup();
    }
    return ret;
}

int WifiDirectP2pAdapter::RemoveGroupNotAddReuse()
{
    P2pAdapter::DestroyGroupParam param { IF_NAME_P2P };
    auto result = P2pEntity::GetInstance().Disconnect(param);
    CONN_CHECK_AND_RETURN_RET_LOGE(result.errorCode_ == SOFTBUS_OK, result.errorCode_, CONN_WIFI_DIRECT,
        "entity disconnect failed, error=%{public}d", result.errorCode_);
    return SOFTBUS_OK;
}

int WifiDirectP2pAdapter::RemoveGroup()
{
    int reuseCount = 0;
    auto ret = InterfaceManager::GetInstance().ReadInterface(
        InterfaceInfo::P2P, [&reuseCount](const InterfaceInfo &interface) {
            reuseCount = interface.GetReuseCount();
            return SOFTBUS_OK;
        });
    CONN_CHECK_AND_RETURN_RET_LOGE(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get reuse count failed, ret=%{public}d", ret);

    CONN_LOGI(CONN_WIFI_DIRECT, "reuseCnt=%{public}d", reuseCount);
    if (reuseCount == 0) {
        CONN_LOGI(CONN_WIFI_DIRECT, "reuseCnt already 0, do not call entity disconnect");
        return SOFTBUS_OK;
    }
    P2pAdapter::DestroyGroupParam param { IF_NAME_P2P };
    auto result = P2pEntity::GetInstance().Disconnect(param);
    CONN_CHECK_AND_RETURN_RET_LOGE(result.errorCode_ == SOFTBUS_OK, result.errorCode_, CONN_WIFI_DIRECT,
        "entity disconnect failed, error=%{public}d", result.errorCode_);

    return InterfaceManager::GetInstance().UpdateInterface(InterfaceInfo::P2P, [](InterfaceInfo &interface) {
        auto reuseCount = interface.GetReuseCount();
        if (reuseCount == 0) {
            CONN_LOGW(CONN_WIFI_DIRECT, "reuseCnt already 0 and can not be reduced");
            return SOFTBUS_OK;
        }
        interface.SetReuseCount(reuseCount - 1);
        CONN_LOGI(CONN_WIFI_DIRECT, "reuseCnt=%{public}d", interface.GetReuseCount());
        return SOFTBUS_OK;
    });
}

int WifiDirectP2pAdapter::ReuseP2p()
{
    auto ret = P2pEntity::GetInstance().ReuseLink();
    CONN_CHECK_AND_RETURN_RET_LOGE(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "reuse p2p group failed, ret=%{public}d", ret);
    return InterfaceManager::GetInstance().UpdateInterface(InterfaceInfo::P2P, [](InterfaceInfo &interface) {
        auto reuseCnt = interface.GetReuseCount();
        interface.SetReuseCount(reuseCnt + 1);
        CONN_LOGI(CONN_WIFI_DIRECT, "reuseCnt=%{public}d", interface.GetReuseCount());
        return SOFTBUS_OK;
    });
}

int WifiDirectP2pAdapter::ReuseGroup(struct GroupOwnerResult *result)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(result != nullptr, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "result is null");
    auto isCreateGo = false;
    auto ret = InterfaceManager::GetInstance().ReadInterface(
        InterfaceInfo::P2P, [&isCreateGo](const InterfaceInfo &interface) {
            isCreateGo = interface.GetIsCreateGo();
            return SOFTBUS_OK;
        });
    CONN_CHECK_AND_RETURN_RET_LOGE(
        isCreateGo, SOFTBUS_CONN_GO_IS_NOT_CREATED_SOFTBUS, CONN_WIFI_DIRECT, "go is not created by softbus");
    ret = ReuseP2p();
    CONN_CHECK_AND_RETURN_RET_LOGE(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "reuse p2p group failed, ret=%{public}d", ret);
    std::string groupConfig;
    ret = P2pAdapter::GetGroupConfig(groupConfig);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "get group config fail, error=%{public}d", ret);
        RemoveGroup();
        return ret;
    }
    ret = SetGroupOwnerResult(groupConfig, result);
    if (ret != SOFTBUS_OK) {
        RemoveGroup();
    }
    return ret;
}

int32_t WifiDirectP2pAdapter::ConnCreateGoOwner(const char *pkgName, const struct GroupOwnerConfig *config,
    struct GroupOwnerResult *result, GroupOwnerDestroyListener listener)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(pkgName != nullptr, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "pkgName is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(config != nullptr, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "config is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(result != nullptr, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "result is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(listener != nullptr, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "listener is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(
        !isCreateGroup_, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "Duplicate group creation is not allowed");
    InterfaceManager::GetInstance().LockInterface(InterfaceInfo::P2P, GROUP_OWNER);
    auto role = LinkInfo::LinkMode::NONE;
    auto ret = InterfaceManager::GetInstance().ReadInterface(
        InterfaceInfo::P2P, [&role](const InterfaceInfo &interface) {
            role = interface.GetRole();
            return SOFTBUS_OK;
        });
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "get current p2p role failed, ret=%{public}d", ret);
        InterfaceManager::GetInstance().UnlockInterface(InterfaceInfo::P2P);
        return ret;
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "myRole=%{public}d", WifiDirectUtils::ToWifiDirectRole(role));
    switch (role) {
        case LinkInfo::LinkMode::NONE:
            ret = CreateGroup(result);
            break;
        case LinkInfo::LinkMode::GO:
            ret = ReuseGroup(result);
            break;
        case LinkInfo::LinkMode::GC:
            CONN_LOGI(CONN_WIFI_DIRECT, "role is p2p gc, not create group");
            InterfaceManager::GetInstance().UnlockInterface(InterfaceInfo::P2P);
            return SOFTBUS_CONN_P2P_ROLE_IS_GC;
        default:
            CONN_LOGI(CONN_WIFI_DIRECT, "not create or reuse p2p go");
            InterfaceManager::GetInstance().UnlockInterface(InterfaceInfo::P2P);
            return SOFTBUS_CONN_P2P_ROLE_INVALID;
    }
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "create or reuse group failed, ret=%{public}d", ret);
        InterfaceManager::GetInstance().UnlockInterface(InterfaceInfo::P2P);
        return ret;
    }
    InterfaceManager::GetInstance().UnlockInterface(InterfaceInfo::P2P);
    std::lock_guard lock(mutex_);
    if (groupOwnerDestroyListener_ == nullptr) {
        groupOwnerDestroyListener_ = listener;
    }
    isCreateGroup_ = true;
    return SOFTBUS_OK;
}

void WifiDirectP2pAdapter::ConnDestroyGoOwner(const char *pkgName)
{
    CONN_CHECK_AND_RETURN_LOGE(pkgName != nullptr, CONN_WIFI_DIRECT, "pkgName is null");
    {
        std::lock_guard lock(mutex_);
        CONN_CHECK_AND_RETURN_LOGE(groupOwnerDestroyListener_ != nullptr, CONN_WIFI_DIRECT, "listener is null");
        CONN_CHECK_AND_RETURN_LOGE(isCreateGroup_, CONN_WIFI_DIRECT, "not use group");
        isCreateGroup_ = false;
    }
    InterfaceManager::GetInstance().LockInterface(InterfaceInfo::P2P, GROUP_OWNER);
    RemoveGroup();
    InterfaceManager::GetInstance().UnlockInterface(InterfaceInfo::P2P);
}
} // namespace OHOS::SoftBus
