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

#include <csignal>
#include <gtest/gtest.h>
#include "data/inner_link.h"

using namespace testing::ext;

namespace OHOS::SoftBus {
class InnerLinkTest : public testing::Test {
public:
    static void SetUpTestCase() { }
    static void TearDownTestCase() { }
    void SetUp() override { }
    void TearDown() override { }
};

/*
 * @tc.name: SetAndGetEnum
 * @tc.desc: check set and get methods of enum
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, SetAndGetEnum, TestSize.Level1)
{
    InnerLink info("");
    EXPECT_EQ(info.GetLinkType(), InnerLink::LinkType::INVALID_TYPE);
    info.SetLinkType(InnerLink::LinkType::HML);
    EXPECT_EQ(info.GetLinkType(), InnerLink::LinkType::HML);

    EXPECT_EQ(info.GetState(), InnerLink::LinkState::INVALID_STATE);
    info.SetState(InnerLink::LinkState::CONNECTING);
    EXPECT_EQ(info.GetState(), InnerLink::LinkState::CONNECTING);

    EXPECT_EQ(info.GetListenerModule(), static_cast<ListenerModule>(UNUSE_BUTT));
    info.SetListenerModule(ListenerModule::LISTENER_MODULE_DYNAMIC_START);
    EXPECT_EQ(info.GetListenerModule(), ListenerModule::LISTENER_MODULE_DYNAMIC_START);
}

/*
 * @tc.name: SetAndGetString
 * @tc.desc: check set and get methods if string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, SetAndGetString, TestSize.Level1)
{
    InnerLink info("");
    EXPECT_EQ(info.GetLocalInterface(), "");
    info.SetLocalInterface(IF_NAME_P2P);
    EXPECT_EQ(info.GetLocalInterface(), IF_NAME_P2P);

    EXPECT_EQ(info.GetLocalBaseMac(), "");
    info.SetLocalBaseMac("00:11:22:33:44:55");
    EXPECT_EQ(info.GetLocalBaseMac(), "00:11:22:33:44:55");

    EXPECT_EQ(info.GetLocalDynamicMac(), "");
    info.SetLocalDynamicMac("00:01:02:03:04:05");
    EXPECT_EQ(info.GetLocalDynamicMac(), "00:01:02:03:04:05");

    EXPECT_EQ(info.GetLocalIpv4(), "");
    info.SetLocalIpv4("127.0.0.1");
    EXPECT_EQ(info.GetLocalIpv4(), "127.0.0.1");

    EXPECT_EQ(info.GetRemoteInterface(), "");
    info.SetRemoteInterface("p2p0-1");
    EXPECT_EQ(info.GetRemoteInterface(), "p2p0-1");

    EXPECT_EQ(info.GetRemoteBaseMac(), "");
    info.SetRemoteBaseMac("AA:BB:CC:DD:EE:FF");
    EXPECT_EQ(info.GetRemoteBaseMac(), "AA:BB:CC:DD:EE:FF");

    EXPECT_EQ(info.GetRemoteDynamicMac(), "");
    info.SetRemoteDynamicMac("A0:A1:A2:A3:A4:A5");
    EXPECT_EQ(info.GetRemoteDynamicMac(), "A0:A1:A2:A3:A4:A5");

    EXPECT_EQ(info.GetRemoteIpv4(), "");
    info.SetRemoteIpv4("10.0.0.1");
    EXPECT_EQ(info.GetRemoteIpv4(), "10.0.0.1");

    EXPECT_EQ(info.GetRemoteDeviceId(), "");
    info.SetRemoteDeviceId("0123456789ABCDEF");
    EXPECT_EQ(info.GetRemoteDeviceId(), "0123456789ABCDEF");
}

/*
 * @tc.name: SetAndGetBool
 * @tc.desc: check set and get methods of boolean
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, SetAndGetBool, TestSize.Level1)
{
    InnerLink info("");
    EXPECT_EQ(info.IsBeingUsedByLocal(), false);
    WifiDirectLink link {};
    info.GenerateLink(6, 8, link, false);
    EXPECT_EQ(info.IsBeingUsedByLocal(), true);

    EXPECT_EQ(info.IsBeingUsedByRemote(), false);
    info.SetBeingUsedByRemote(true);
    EXPECT_EQ(info.IsBeingUsedByRemote(), true);
}

/*
 * @tc.name: SetAndGetInt
 * @tc.desc: check set and get methods of int
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, SetAndGetInt, TestSize.Level1)
{
    InnerLink info("");
    EXPECT_EQ(info.GetFrequency(), -1);
    info.SetFrequency(149);
    EXPECT_EQ(info.GetFrequency(), 149);

    EXPECT_EQ(info.GetLocalPort(), -1);
    info.SetLocalPort(443);
    EXPECT_EQ(info.GetLocalPort(), 443);

    EXPECT_EQ(info.GetReference(), 0);
    WifiDirectLink link {};
    info.GenerateLink(1, 2, link, false);
    EXPECT_EQ(info.GetReference(), 1);
    info.RemoveId(link.linkId);
    EXPECT_EQ(info.GetReference(), 0);
}

/*
 * @tc.name: SetAndGetGrocery
 * @tc.desc: check set and get methods of int
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, SetAndGetGrocery, TestSize.Level1)
{
    InnerLink info("");

    WifiDirectLink link {};
    info.GenerateLink(888, 666, link, false);
    EXPECT_EQ(info.IsContainId(link.linkId), true) << "IsContainId done";
    info.RemoveId(link.linkId);
    EXPECT_EQ(info.IsContainId(link.linkId), false) << "IsContainId done";

    EXPECT_EQ(info.IsProtected(), false);
    info.SetState(InnerLink::LinkState::CONNECTING);
    EXPECT_EQ(info.IsProtected(), false);
    info.SetState(InnerLink::LinkState::CONNECTED);
    EXPECT_EQ(info.IsProtected(), true);
    // the unit of sleep parameter is second
    sleep(PROTECT_DURATION_MS / 1000 + 1);
    EXPECT_EQ(info.IsProtected(), false);
}

/*
 * @tc.name: ToString
 * @tc.desc: test the to string method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InnerLinkTest, TypeToString, TestSize.Level1)
{
    InnerLink info("");
    EXPECT_EQ(info.ToString(InnerLink::LinkType::INVALID_TYPE), "INVALID_TYPE");
    EXPECT_EQ(info.ToString(InnerLink::LinkType::HML), "HML");
    EXPECT_EQ(info.ToString(InnerLink::LinkType::P2P), "P2P");
    EXPECT_EQ(info.ToString(InnerLink::LinkState::INVALID_STATE), "INVALID_STATE");
    EXPECT_EQ(info.ToString(InnerLink::LinkState::DISCONNECTED), "DISCONNECTED");
    EXPECT_EQ(info.ToString(InnerLink::LinkState::CONNECTED), "CONNECTED");
    EXPECT_EQ(info.ToString(InnerLink::LinkState::CONNECTING), "CONNECTING");
    EXPECT_EQ(info.ToString(InnerLink::LinkState::DISCONNECTING), "DISCONNECTING");
}
} // namespace OHOS::SoftBus