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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "lnn_lane_communication_capability.h"
#include "lnn_lane_comm_capa_deps_mock.h"
#include "softbus_bus_center.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr char NETWORK_ID[] = "123456789";

class LNNLaneCommCapaTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNLaneCommCapaTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "LNNLaneCommCapaTest start";
}

void LNNLaneCommCapaTest::TearDownTestCase()
{
    GTEST_LOG_(INFO) << "LNNLaneCommCapaTest end";
}

void LNNLaneCommCapaTest::SetUp()
{
}

void LNNLaneCommCapaTest::TearDown()
{
}

/*
* @tc.name: LNNLaneCommCapaTest
* @tc.desc: br communication capability exception test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneCommCapaTest, LNN_BR_COMM_CAPA_001, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_BR);
    EXPECT_TRUE(commCapaInterface != nullptr);
    bool ret = commCapaInterface->getDynamicCommCapa(nullptr);
    EXPECT_FALSE(ret);
    ret = commCapaInterface->getStaticCommCapa(nullptr);
    EXPECT_FALSE(ret);
}

/*
* @tc.name: LNNLaneCommCapaTest
* @tc.desc: br communication capability func test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneCommCapaTest, LNN_BR_COMM_CAPA_002, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_BR);
    EXPECT_TRUE(commCapaInterface != nullptr);
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    uint64_t localCapa = 1 << BIT_BR;
    uint64_t remoteCapa = 1 << BIT_BR;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(localCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(remoteCapa), Return(SOFTBUS_OK)));
    bool ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_TRUE(ret);
    ret = commCapaInterface->getStaticCommCapa(NETWORK_ID);
    EXPECT_TRUE(ret);
}

/*
* @tc.name: LNNLaneCommCapaTest
* @tc.desc: ble communication capability test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneCommCapaTest, LNN_BLE_COMM_CAPA_001, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_BLE);
    EXPECT_TRUE(commCapaInterface != nullptr);
    bool ret = commCapaInterface->getDynamicCommCapa(nullptr);
    EXPECT_FALSE(ret);
    ret = commCapaInterface->getStaticCommCapa(nullptr);
    EXPECT_FALSE(ret);
}

/*
* @tc.name: LNNLaneCommCapaTest
* @tc.desc: ble communication capability test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneCommCapaTest, LNN_BLE_COMM_CAPA_002, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_BLE);
    EXPECT_TRUE(commCapaInterface != nullptr);
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    uint64_t localCapa = 1 << BIT_BLE;
    uint64_t remoteCapa = 1 << BIT_BLE;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(localCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(remoteCapa), Return(SOFTBUS_OK)));
    bool ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_TRUE(ret);
    ret = commCapaInterface->getStaticCommCapa(NETWORK_ID);
    EXPECT_TRUE(ret);
}

/*
* @tc.name: LNNLaneCommCapaTest
* @tc.desc: Coc communication capability test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneCommCapaTest, LNN_COC_COMM_CAPA_001, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_BLE);
    EXPECT_TRUE(commCapaInterface != nullptr);
    bool ret = commCapaInterface->getDynamicCommCapa(nullptr);
    EXPECT_FALSE(ret);
    ret = commCapaInterface->getStaticCommCapa(nullptr);
    EXPECT_FALSE(ret);
}

/*
* @tc.name: LNNLaneCommCapaTest
* @tc.desc: Coc communication capability test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneCommCapaTest, LNN_COC_COMM_CAPA_002, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_BLE);
    EXPECT_TRUE(commCapaInterface != nullptr);
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    uint64_t localCapa = 1 << BIT_BLE;
    uint64_t remoteCapa = 1 << BIT_BLE;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(localCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(remoteCapa), Return(SOFTBUS_OK)));
    bool ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_TRUE(ret);
    ret = commCapaInterface->getStaticCommCapa(NETWORK_ID);
    EXPECT_TRUE(ret);
}

/*
* @tc.name: LNNLaneCommCapaTest
* @tc.desc: wlan communication capability test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneCommCapaTest, LNN_WLAN_COMM_CAPA_001, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_WLAN_5G);
    EXPECT_TRUE(commCapaInterface != nullptr);
    bool ret = commCapaInterface->getDynamicCommCapa(nullptr);
    EXPECT_FALSE(ret);
    ret = commCapaInterface->getStaticCommCapa(nullptr);
    EXPECT_FALSE(ret);
}

/*
* @tc.name: LNNLaneCommCapaTest
* @tc.desc: wlan communication capability test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneCommCapaTest, LNN_WLAN_COMM_CAPA_002, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_WLAN_5G);
    EXPECT_TRUE(commCapaInterface != nullptr);
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    uint64_t localCapa = 1 << BIT_WIFI_5G;
    uint64_t remoteCapa = 1 << BIT_WIFI_5G;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(localCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(remoteCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(commCapaMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    bool ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_TRUE(ret);
    ret = commCapaInterface->getStaticCommCapa(NETWORK_ID);
    EXPECT_TRUE(ret);
}

/*
* @tc.name: LNNLaneCommCapaTest
* @tc.desc: wifi direct communication capability test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneCommCapaTest, LNN_WIFI_DIRECT_COMM_CAPA_001, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_P2P);
    EXPECT_TRUE(commCapaInterface != nullptr);
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    uint64_t localCapa = 1 << BIT_WIFI_P2P;
    uint64_t remoteCapa = 1 << BIT_WIFI_P2P;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(localCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(remoteCapa), Return(SOFTBUS_OK)));
    bool ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_TRUE(ret);
    ret = commCapaInterface->getStaticCommCapa(NETWORK_ID);
    EXPECT_TRUE(ret);
}
} // namespace OHOS
