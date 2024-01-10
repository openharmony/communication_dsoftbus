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
#include "data/link_manager.h"
#include "data/resource_manager.h"
#include "link_manager_broadcast_handler.h"
#include "link_manager_broadcast_handler.c"
#include "softbus_error_code.h"
#include "utils/wifi_direct_anonymous.h"
#include "utils/wifi_direct_ipv4_info.h"
#include "utils/wifi_direct_network_utils.h"
#include "wifi_direct_decision_center.h"
#include "wifi_direct_p2p_adapter.h"

#define CONNECTED_DEVICE_COUNT_ONE  1
#define CONNECTED_DEVICE_COUNT_FIVE 5

namespace OHOS {
using namespace testing::ext;
using namespace testing;

class LinkManagerBroadcastTest : public testing::Test {
public:
    LinkManagerBroadcastTest()
    {}
    ~LinkManagerBroadcastTest()
    {}
    void SetUp();
    void TearDown();
};

void LinkManagerBroadcastTest::SetUp(void) {}
void LinkManagerBroadcastTest::TearDown(void) {}

void* GetRawData(struct InterfaceInfo *self, size_t key, size_t *size, void *defaultValue)
{
    (void)self;
    (void)key;
    (void)size;
    (void)defaultValue;
    return nullptr;
}

int32_t MacArrayToString(const uint8_t *array, size_t arraySize, char *macString, size_t macStringSize)
{
    (void)array;
    (void)arraySize;
    (void)macString;
    (void)macStringSize;
    static int32_t temp = 0;
    return temp++;
}

void NotifyLinkChange(struct InnerLink *link)
{
    (void)link;
    return;
}

void RefreshLinks(enum WifiDirectConnectType connectType, int32_t clientDeviceSize, char *clientDevices[])
{
    (void)connectType;
    (void)clientDeviceSize;
    (void)clientDevices;
    return;
}

void RemoveLinksByConnectType(enum WifiDirectConnectType connectType)
{
    (void)connectType;
    return;
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

struct InterfaceInfo* GetInterfaceInfo(const char *interface)
{
    (void)interface;
    struct InterfaceInfo *info = nullptr;
    info = static_cast<struct InterfaceInfo *>(SoftBusMalloc(sizeof(InterfaceInfo)));
    EXPECT_TRUE(info != nullptr);
    info->getRawData = GetRawData;
    return info;
}

HWTEST_F(LinkManagerBroadcastTest, LinkManagerBroadcastTest001, TestSize.Level1)
{
    struct WifiDirectP2pGroupInfo groupInfo;
    GetResourceManager()->getInterfaceInfo = GetInterfaceInfo;
    groupInfo.isGroupOwner = false;
    GetWifiDirectNetWorkUtils()->macArrayToString = MacArrayToString;
    GetLinkManager()->notifyLinkChange = NotifyLinkChange;
    (void)UpdateInnerLink(&groupInfo);

    GetWifiDirectNetWorkUtils()->macArrayToString = MacArrayToString;
    (void)UpdateInnerLink(&groupInfo);

    groupInfo.isGroupOwner = true;
    groupInfo.clientDeviceSize = CONNECTED_DEVICE_COUNT_ONE;
    GetLinkManager()->refreshLinks = RefreshLinks;
    (void)UpdateInnerLink(&groupInfo);

    groupInfo.clientDeviceSize = CONNECTED_DEVICE_COUNT_FIVE;
    (void)UpdateInnerLink(&groupInfo);


};

HWTEST_F(LinkManagerBroadcastTest, LinkManagerBroadcastTest002, TestSize.Level1)
{
    struct P2pConnChangedInfo changedInfo;
    changedInfo.p2pLinkInfo.connectState = P2P_DISCONNECTED;
    GetLinkManager()->removeLinksByConnectType = RemoveLinksByConnectType;
    (void)HandleP2pConnectionChanged(&changedInfo);

    changedInfo.p2pLinkInfo.connectState = P2P_CONNECTED;
    changedInfo.groupInfo = nullptr;
    (void)HandleP2pConnectionChanged(&changedInfo);

    changedInfo.groupInfo =
        reinterpret_cast<struct WifiDirectP2pGroupInfo *>(SoftBusMalloc(sizeof(WifiDirectP2pGroupInfo)));
    EXPECT_TRUE(changedInfo.groupInfo != nullptr);
    (void)HandleP2pConnectionChanged(&changedInfo);
    SoftBusFree(changedInfo.groupInfo);
};

HWTEST_F(LinkManagerBroadcastTest, LinkManagerBroadcastTest003, TestSize.Level1)
{
    enum BroadcastReceiverAction action = WIFI_P2P_CONNECTION_CHANGED_ACTION;
    struct BroadcastParam param;
    (void)Listener(action, &param);

    action = BROADCAST_RECEIVER_ACTION_MAX;
    (void)Listener(action, &param);
};

HWTEST_F(LinkManagerBroadcastTest, LinkManagerBroadcastTest004, TestSize.Level1)
{
    GetBroadcastReceiver()->registerBroadcastListener = RegisterBroadcastListener;
    (void)LinkManagerBroadcastHandlerInit();
};
}
