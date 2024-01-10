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
#include <cstring>

#include "broadcast_receiver.h"
#include "broadcast_receiver.c"
#include "common_list.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "utils/wifi_direct_work_queue.h"
#include "wifi_direct_p2p_adapter.h"
#include "wifi_direct_p2p_adapter_mock.h"
#include "wifi_p2p.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

class BroadcastReceiverTest : public testing::Test {
public:
    BroadcastReceiverTest()
    {}
    ~BroadcastReceiverTest()
    {}
    void SetUp();
    void TearDown();
};

void BroadcastReceiverTest::SetUp(void) {}
void BroadcastReceiverTest::TearDown(void) {}

int32_t GetGroupInfo(struct WifiDirectP2pGroupInfo **groupInfo)
{
    (void)groupInfo;
    return SOFTBUS_OK;
}

void BroadcastListener(enum BroadcastReceiverAction action, const struct BroadcastParam *param)
{
    (void)action;
    (void)param;
    return;
}

HWTEST_F(BroadcastReceiverTest, BroadcastReceiverTest001, TestSize.Level1)
{
    struct ActionListenerNode actionListener;
    struct BroadcastParam *param = nullptr;

    struct BroadcastReceiver *receiver = nullptr;
    receiver = GetBroadcastReceiver();
    EXPECT_TRUE(receiver != nullptr);
    ListInit(&receiver->listeners[WIFI_P2P_CONNECTION_CHANGED_ACTION]);
    actionListener.listener = BroadcastListener;
    ListTailInsert(&receiver->listeners[WIFI_P2P_CONNECTION_CHANGED_ACTION], &actionListener.node);

    param = reinterpret_cast<struct BroadcastParam *>(SoftBusMalloc(sizeof(*param)));
    EXPECT_TRUE(param != nullptr);
    param->action = WIFI_P2P_CONNECTION_CHANGED_ACTION;
    param->changedInfo.groupInfo =
        reinterpret_cast<struct WifiDirectP2pGroupInfo *>(SoftBusMalloc(sizeof(WifiDirectP2pGroupInfo)));
    EXPECT_TRUE(param->changedInfo.groupInfo != nullptr);
    (void)DispatchWorkHandler(param);
};

HWTEST_F(BroadcastReceiverTest, BroadcastReceiverTest002, TestSize.Level1)
{
    P2pState state = P2P_STATE_NONE;
    NiceMock<WifiDirectP2PAdapterInterfaceMock> wifiDirectP2PAdapterInterfaceMock;
    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock, CallMethodAsync).WillRepeatedly(Return(SOFTBUS_ERR));
    (void)P2pStateChangeHandler(state);

    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock, CallMethodAsync).WillRepeatedly(Return(SOFTBUS_OK));
    (void)P2pStateChangeHandler(state);
};

HWTEST_F(BroadcastReceiverTest, BroadcastReceiverTest003, TestSize.Level1)
{
    WifiP2pLinkedInfo info;
    GetWifiDirectP2pAdapter()->getGroupInfo = GetGroupInfo;
    NiceMock<WifiDirectP2PAdapterInterfaceMock> wifiDirectP2PAdapterInterfaceMock;
    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock, CallMethodAsync).WillRepeatedly(Return(SOFTBUS_ERR));
    (void)P2pConnectionChangeHandler(info);

    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock, CallMethodAsync).WillRepeatedly(Return(SOFTBUS_OK));
    (void)P2pConnectionChangeHandler(info);
};

HWTEST_F(BroadcastReceiverTest, BroadcastReceiverTest004, TestSize.Level1)
{
    NiceMock<WifiDirectP2PAdapterInterfaceMock> wifiDirectP2PAdapterInterfaceMock;
    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock,
        RegisterP2pStateChangedCallback).WillRepeatedly(Return(ERROR_WIFI_INVALID_ARGS));
    int32_t ret = BroadcastReceiverInit();
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock,
        RegisterP2pStateChangedCallback).WillRepeatedly(Return(WIFI_SUCCESS));
    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock,
        RegisterP2pConnectionChangedCallback).WillRepeatedly(Return(ERROR_WIFI_INVALID_ARGS));
    ret = BroadcastReceiverInit();
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock,
        RegisterP2pConnectionChangedCallback).WillRepeatedly(Return(WIFI_SUCCESS));
    ret = BroadcastReceiverInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
};
}
