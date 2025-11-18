/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
    TransLinkListenerTest() { }
    ~TransLinkListenerTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void TransLinkListenerTest::SetUpTestCase(void) { }

void TransLinkListenerTest::TearDownTestCase(void) { }

/*
 * @tc.name: ClearIpInfo001
 * @tc.desc: ClearIpInfo test, void return
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

/*
 * @tc.name: OnWifiDirectDeviceOffline001
 * @tc.desc: OnWifiDirectDeviceOffline test, void return
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLinkListenerTest, OnWifiDirectDeviceOffline001, TestSize.Level1)
{
    const char *peerMac = "11:33:44:22:33:56";
    const char *localIp = "172.30.";
    const char *peerIp = "192.168.11.33";
    const char *peerUuid = "11223344";
    TransManagerInterfaceMock mock;
    int32_t ret = TransChannelInit();
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillOnce(Return(SOFTBUS_OK));
    OnWifiDirectDeviceOffline(peerMac, peerIp, peerUuid, localIp);
    EXPECT_NE(SOFTBUS_OK, ret);
    TransChannelDeinit();
}

/*
 * @tc.name: OnWifiDirectDeviceOffline002
 * @tc.desc: OnWifiDirectDeviceOffline test, void return
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLinkListenerTest, OnWifiDirectDeviceOffline002, TestSize.Level1)
{
    const char *peerMac = "11:33:44:22:33:56";
    const char *peerIp = "192.168.11.33";
    const char *peerUuid = "11223344";
    TransManagerInterfaceMock mock;
    int32_t ret = TransChannelInit();
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillOnce(Return(SOFTBUS_OK));
    OnWifiDirectDeviceOffline(peerMac, peerIp, peerUuid, peerIp);
    EXPECT_NE(SOFTBUS_OK, ret);
    TransChannelDeinit();

    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillOnce(Return(SOFTBUS_NETWORK_GET_NODE_INFO_ERR));
    EXPECT_CALL(mock, LnnGetOsTypeByNetworkId).WillOnce(Return(SOFTBUS_NOT_FIND));
    EXPECT_NO_FATAL_FAILURE(OnWifiDirectDeviceOffline(peerMac, peerIp, peerUuid, peerIp));
}

/*
 * @tc.name: OnWifiDirectRoleChange001
 * @tc.desc: OnWifiDirectRoleChange test, void return
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLinkListenerTest, OnWifiDirectRoleChange001, TestSize.Level1)
{
    int32_t ret = P2pDirectChannelInit();
    OnWifiDirectRoleChange(WIFI_DIRECT_ROLE_NONE, WIFI_DIRECT_ROLE_NONE);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: OnWifiDirectDeviceOnline001
 * @tc.desc: OnWifiDirectDeviceOnline test, void return
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLinkListenerTest, OnWifiDirectDeviceOnline001, TestSize.Level1)
{
    const char *peerMac = "11:33:44:22:33:56";
    const char *peerIp = "192.168.11.33";
    const char *peerUuid = "11223344";
    bool isSource = false;
    TransManagerInterfaceMock mock;
    int32_t ret = TransChannelInit();
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillOnce(Return(SOFTBUS_OK));
    OnWifiDirectDeviceOnline(peerMac, peerIp, peerUuid, isSource);
    EXPECT_NE(SOFTBUS_OK, ret);
    TransChannelDeinit();
}

/**
 * @tc.name: FillNodeInfoAsMeta001
 * @tc.desc: FillNodeInfoAsMetaTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLinkListenerTest, FillNodeInfoAsMeta001, TestSize.Level1)
{
    NodeInfo nodeInfo;
    int32_t ret = FillNodeInfoAsMeta(nullptr, &nodeInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = FillNodeInfoAsMeta("666", nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    TransManagerInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetOsTypeByNetworkId).WillOnce(Return(SOFTBUS_NOT_FIND));
    ret = FillNodeInfoAsMeta("4546", &nodeInfo);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);

    int32_t osType = OH_OS_TYPE;
    EXPECT_CALL(mock, LnnGetOsTypeByNetworkId).WillOnce(DoAll(SetArgPointee<1>(osType), Return(SOFTBUS_OK)));
    ret = FillNodeInfoAsMeta("1230", &nodeInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    osType = OTHER_OS_TYPE;
    EXPECT_CALL(mock, LnnGetOsTypeByNetworkId).WillOnce(DoAll(SetArgPointee<1>(osType), Return(SOFTBUS_OK)));
    ret = FillNodeInfoAsMeta("1230", &nodeInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
} // namespace OHOS
