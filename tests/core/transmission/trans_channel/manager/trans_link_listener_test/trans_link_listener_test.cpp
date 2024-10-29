/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"

#include "trans_channel_manager.h"
#include "trans_link_listener.c"
#include "trans_manager_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

class TransLinkListenerTest : public testing::Test {
public:
    TransLinkListenerTest()
    {}
    ~TransLinkListenerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransLinkListenerTest::SetUpTestCase(void)
{}

void TransLinkListenerTest::TearDownTestCase(void)
{}

/**
 * @tc.name: ClearIpInfo Test
 * @tc.desc: ClearIpInfo001, void return
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLinkListenerTest, ClearIpInfo001, TestSize.Level1)
{
    int32_t ret = TransChannelInit();
    const char *peerUuid = "11223344";
    ClearIpInfo(peerUuid);
    EXPECT_NE(SOFTBUS_OK, ret);
    TransChannelDeinit();
}

/**
 * @tc.name: OnWifiDirectDeviceOffLine Test
 * @tc.desc: OnWifiDirectDeviceOffLine001, void return
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLinkListenerTest, OnWifiDirectDeviceOffLine001, TestSize.Level1)
{
    const char *peerMac = "11:33:44:22:33:56";
    const char *localIp = "172.30.";
    const char *peerIp = "192.168.11.33";
    const char *peerUuid = "11223344";
    TransManagerInterfaceMock mock;
    int32_t ret = TransChannelInit();
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillOnce(Return(SOFTBUS_OK));
    OnWifiDirectDeviceOffLine(peerMac, peerIp, peerUuid, localIp);
    EXPECT_NE(SOFTBUS_OK, ret);
    TransChannelDeinit();
}

/**
 * @tc.name: OnWifiDirectDeviceOffLine Test
 * @tc.desc: OnWifiDirectDeviceOffLine002, void return
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLinkListenerTest, OnWifiDirectDeviceOffLine002, TestSize.Level1)
{
    const char *peerMac = "11:33:44:22:33:56";
    const char *peerIp = "192.168.11.33";
    const char *peerUuid = "11223344";
    TransManagerInterfaceMock mock;
    int32_t ret = TransChannelInit();
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillOnce(Return(SOFTBUS_OK));
    OnWifiDirectDeviceOffLine(peerMac, peerIp, peerUuid, peerIp);
    EXPECT_NE(SOFTBUS_OK, ret);
    TransChannelDeinit();
}

/**
 * @tc.name: OnWifiDirectRoleChange Test
 * @tc.desc: OnWifiDirectRoleChange, void return
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLinkListenerTest, OnWifiDirectRoleChange001, TestSize.Level1)
{
    int32_t ret = P2pDirectChannelInit();
    OnWifiDirectRoleChange(WIFI_DIRECT_ROLE_NONE, WIFI_DIRECT_ROLE_NONE);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: OnWifiDirectDeviceOnLine Test
 * @tc.desc: OnWifiDirectDeviceOnLine, void return
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLinkListenerTest, OnWifiDirectDeviceOnLine001, TestSize.Level1)
{
    const char *peerMac = "11:33:44:22:33:56";
    const char *peerIp = "192.168.11.33";
    const char *peerUuid = "11223344";
    bool isSource = false;
    TransManagerInterfaceMock mock;
    int32_t ret = TransChannelInit();
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillOnce(Return(SOFTBUS_OK));
    OnWifiDirectDeviceOnLine(peerMac, peerIp, peerUuid, isSource);
    EXPECT_NE(SOFTBUS_OK, ret);
    TransChannelDeinit();
}
} // OHOS