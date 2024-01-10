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

#include <gtest/gtest.h>
#include <securec.h>

#include "broadcast_receiver.h"
#include "channel/default_negotiate_channel.h"
#include "data/resource_manager.h"
#include "resource_manager_broadcast_handler.h"
#include "resource_manager_broadcast_handler.c"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "wifi_direct_p2p_adapter.h"
#include "wifi_p2p.h"
#include "wifi_p2p_config.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

class ResourceManagerBroadcastTest : public testing::Test {
public:
    ResourceManagerBroadcastTest()
    {}
    ~ResourceManagerBroadcastTest()
    {}
    void SetUp();
    void TearDown();
};

void ResourceManagerBroadcastTest::SetUp(void) {}
void ResourceManagerBroadcastTest::TearDown(void) {}

int32_t GetInt(struct InterfaceInfo *self, size_t key, int32_t defaultValue)
{
    (void)self;
    (void)key;
    (void)defaultValue;
    static int32_t temp = 0;
    return temp++;
}

int32_t GetMacAddress(char *macString, size_t macStringSize)
{
    (void)macString;
    (void)macStringSize;
    return 0;
}

void NotifyInterfaceInfoChange(struct InterfaceInfo *info)
{
    (void)info;
    return;
}

int32_t GetDynamicMacAddress(char *macString, size_t macStringSize)
{
    (void)macString;
    (void)macStringSize;
    static int32_t temp = 0;
    return temp++;
}

int32_t GetIpAddress(char *ipString, int32_t ipStringSize)
{
    (void)ipString;
    (void)ipStringSize;
    static int32_t temp = 0;
    return temp++;
}

void RegisterBroadcastListener(const enum BroadcastReceiverAction *actionArray, size_t actionSize,
    const char *name, BroadcastListener listener)
{
    (void)actionArray;
    (void)actionSize;
    (void)name;
    (void)listener;
    return;
}

int32_t GetGroupConfig(char *groupConfigString, size_t *groupConfigStringSize)
{
    (void)groupConfigString;
    (void)groupConfigStringSize;
    static int32_t temp = 0;
    return temp++;
}

struct InterfaceInfo* GetInterfaceInfo(const char *interface)
{
    (void)interface;
    struct InterfaceInfo *info = nullptr;
    info = static_cast<struct InterfaceInfo *>(SoftBusMalloc(sizeof(InterfaceInfo)));
    EXPECT_TRUE(info != nullptr);
    info->getInt = GetInt;
    return info;
}

HWTEST_F(ResourceManagerBroadcastTest, BroadcastTest001, TestSize.Level1)
{
    enum P2pState state = P2P_STATE_NONE;
    (void)HandleP2pStateChanged(state);

    state = P2P_STATE_STARTED;
    (void)HandleP2pStateChanged(state);

    GetResourceManager()->getInterfaceInfo = GetInterfaceInfo;
    (void)HandleP2pStateChanged(state);
};

HWTEST_F(ResourceManagerBroadcastTest, BroadcastTest002, TestSize.Level1)
{
    GetResourceManager()->getInterfaceInfo = GetInterfaceInfo;
    GetWifiDirectP2pAdapter()->getMacAddress = GetMacAddress;
    GetResourceManager()->notifyInterfaceInfoChange = NotifyInterfaceInfoChange;
    (void)ResetInterfaceInfo();

    GetResourceManager()->getInterfaceInfo = GetInterfaceInfo;
    (void)ResetInterfaceInfo();
};

HWTEST_F(ResourceManagerBroadcastTest, BroadcastTest003, TestSize.Level1)
{
    struct WifiDirectP2pGroupInfo groupInfo;

    GetWifiDirectP2pAdapter()->getMacAddress = GetMacAddress;
    GetWifiDirectP2pAdapter()->getDynamicMacAddress = GetDynamicMacAddress;
    GetWifiDirectP2pAdapter()->getIpAddress = GetIpAddress;
    groupInfo.isGroupOwner = true;
    GetWifiDirectP2pAdapter()->getGroupConfig = GetGroupConfig;
    GetResourceManager()->notifyInterfaceInfoChange = NotifyInterfaceInfoChange;
    (void)UpdateInterfaceInfo(&groupInfo);

    GetWifiDirectP2pAdapter()->getGroupConfig = GetGroupConfig;
    (void)UpdateInterfaceInfo(&groupInfo);

    groupInfo.isGroupOwner = false;
    (void)UpdateInterfaceInfo(&groupInfo);

    GetWifiDirectP2pAdapter()->getIpAddress = GetIpAddress;
    (void)UpdateInterfaceInfo(&groupInfo);

    GetWifiDirectP2pAdapter()->getDynamicMacAddress = GetDynamicMacAddress;
    (void)UpdateInterfaceInfo(&groupInfo);
};

HWTEST_F(ResourceManagerBroadcastTest, BroadcastTest004, TestSize.Level1)
{
    struct P2pConnChangedInfo changedInfo;
    struct WifiDirectP2pGroupInfo groupInfo;

    changedInfo.p2pLinkInfo.connectState = P2P_DISCONNECTED;
    (void)HandleP2pConnectionChanged(&changedInfo);

    changedInfo.p2pLinkInfo.connectState = P2P_CONNECTED;
    changedInfo.groupInfo = &groupInfo;
    (void)HandleP2pConnectionChanged(&changedInfo);
};

HWTEST_F(ResourceManagerBroadcastTest, BroadcastTest005, TestSize.Level1)
{
    enum BroadcastReceiverAction action = WIFI_P2P_STATE_CHANGED_ACTION;
    struct BroadcastParam param;
    (void)Listener(action, &param);

    action = WIFI_P2P_CONNECTION_CHANGED_ACTION;
    (void)Listener(action, &param);

    action = BROADCAST_RECEIVER_ACTION_MAX;
    (void)Listener(action, &param);
};

HWTEST_F(ResourceManagerBroadcastTest, BroadcastTest006, TestSize.Level1)
{
    GetBroadcastReceiver()->registerBroadcastListener = RegisterBroadcastListener;
    (void)ResourceManagerBroadcastHandlerInit();
};
} // namespace OHOS
