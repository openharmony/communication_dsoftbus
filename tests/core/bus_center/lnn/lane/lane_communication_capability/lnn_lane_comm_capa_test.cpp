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
    ASSERT_TRUE(commCapaInterface != nullptr);
    int32_t ret = commCapaInterface->getDynamicCommCapa(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = commCapaInterface->getStaticCommCapa(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
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
    ASSERT_TRUE(commCapaInterface != nullptr);
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    uint64_t localCapa = 1 << BIT_BR;
    uint64_t remoteCapa = 1 << BIT_BR;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(localCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(remoteCapa), Return(SOFTBUS_OK)));
    int32_t ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = commCapaInterface->getStaticCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNNLaneCommCapaTest
 * @tc.desc: br communication capability fail func test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_BR_COMM_CAPA_INVALID_CASE, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_BR);
    ASSERT_TRUE(commCapaInterface != nullptr);
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = commCapaInterface->getStaticCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    uint64_t localCapa = 1 << STATIC_CAP_BIT_BR;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(localCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(0), Return(SOFTBUS_OK)));
    ret = commCapaInterface->getStaticCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_LANE_REMOTE_NO_BR_STATIC_CAP);

    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(0), Return(SOFTBUS_OK)));
    ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_BR_CAP);

    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(1 << BIT_BR), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
         .WillRepeatedly(DoAll(SetArgPointee<2>(0), Return(SOFTBUS_OK)));
    ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_LANE_REMOTE_NO_BR_CAP);
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
    ASSERT_TRUE(commCapaInterface != nullptr);
    int32_t ret = commCapaInterface->getDynamicCommCapa(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = commCapaInterface->getStaticCommCapa(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
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
    ASSERT_TRUE(commCapaInterface != nullptr);
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    uint64_t localCapa = 1 << BIT_BLE;
    uint64_t remoteCapa = 1 << BIT_BLE;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(localCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(remoteCapa), Return(SOFTBUS_OK)));
    int32_t ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = commCapaInterface->getStaticCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNNLaneCommCapaTest
 * @tc.desc: ble communication capability test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_BLE_COMM_CAPA_003, TestSize.Level1)
{
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_BLE);
    ASSERT_TRUE(commCapaInterface != nullptr);
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info).WillRepeatedly(Return(SOFTBUS_OK));
    ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_BLE_CAP);

    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(1 << BIT_BLE), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(0), Return(SOFTBUS_OK)));
    ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_LANE_REMOTE_NO_BLE_CAP);
}

/*
* @tc.name: LNNLaneCommCapaTest
* @tc.desc: Coc communication capability test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneCommCapaTest, LNN_COC_COMM_CAPA_001, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_P2P);
    ASSERT_TRUE(commCapaInterface != nullptr);
    int32_t ret = commCapaInterface->getDynamicCommCapa(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = commCapaInterface->getStaticCommCapa(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
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
    ASSERT_TRUE(commCapaInterface != nullptr);
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    uint64_t localCapa = 1 << BIT_WIFI_P2P;
    uint64_t remoteCapa = 1 << BIT_WIFI_P2P;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(localCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(remoteCapa), Return(SOFTBUS_OK)));
    int32_t ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = commCapaInterface->getStaticCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNNLaneCommCapaTest
 * @tc.desc: wlan communication capability test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_WLAN_COMM_CAPA_001, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_HML);
    ASSERT_TRUE(commCapaInterface != nullptr);
    int32_t ret = commCapaInterface->getDynamicCommCapa(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = commCapaInterface->getStaticCommCapa(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNNLaneCommCapaTest
 * @tc.desc: Coc communication capability test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_COC_COMM_CAPA_002, TestSize.Level1)
{
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_HML);
    ASSERT_TRUE(commCapaInterface != nullptr);
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info).WillRepeatedly(DoAll(SetArgPointee<1>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(commCapaMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_INACTIVE));
    ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_WIFI_DIRECT_CAP);

    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(1 << BIT_WIFI_P2P), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info).WillRepeatedly(DoAll(SetArgPointee<2>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_ACTIVED));
    ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_LANE_REMOTE_NO_WIFI_DIRECT_CAP);
}

/*
 * @tc.name: LNNLaneCommCapaTest
 * @tc.desc: Coc communication capability test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_COC_COMM_CAPA_003, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_HML);
    ASSERT_TRUE(commCapaInterface != nullptr);
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    uint64_t localCapa = 1 << BIT_WIFI_P2P;
    uint64_t remoteCapa = 1 << BIT_WIFI_P2P;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(localCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(remoteCapa), Return(SOFTBUS_OK)));
    int32_t ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);

    localCapa = 1 << STATIC_CAP_BIT_ENHANCED_P2P;
    remoteCapa = 1 << STATIC_CAP_BIT_ENHANCED_P2P;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(localCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(remoteCapa), Return(SOFTBUS_OK)));
    ret = commCapaInterface->getStaticCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNNLaneCommCapaTest
* @tc.desc: wlan communication capability test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneCommCapaTest, LNN_WLAN_2P4G_CAPA_001, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_WLAN_2P4G);
    ASSERT_TRUE(commCapaInterface != nullptr);
    int32_t ret = commCapaInterface->getDynamicCommCapa(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = commCapaInterface->getStaticCommCapa(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNNLaneCommCapaTest
 * @tc.desc: Coc communication capability test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_WLAN_2P4G_CAPA_002, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_WLAN_2P4G);
    ASSERT_TRUE(commCapaInterface != nullptr);
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    uint64_t localCapa = 1 << BIT_WIFI_24G;
    uint64_t remoteCapa = 1 << BIT_WIFI_24G;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(localCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(remoteCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(commCapaMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    int32_t ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);

    localCapa = 1 << STATIC_CAP_BIT_WIFI;
    remoteCapa = 1 << STATIC_CAP_BIT_WIFI;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(localCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(remoteCapa), Return(SOFTBUS_OK)));
    ret = commCapaInterface->getStaticCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNNLaneCommCapaTest
 * @tc.desc: Coc communication capability test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_WLAN_2P4G_CAPA_003, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_WLAN_2P4G);
    ASSERT_TRUE(commCapaInterface != nullptr);
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    EXPECT_CALL(commCapaMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(commCapaMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNNLaneCommCapaTest
 * @tc.desc: wlan communication capability test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_WLAN_5G_CAPA_001, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_WLAN_5G);
    ASSERT_TRUE(commCapaInterface != nullptr);
    int32_t ret = commCapaInterface->getDynamicCommCapa(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = commCapaInterface->getStaticCommCapa(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNNLaneCommCapaTest
 * @tc.desc: Coc communication capability test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_WLAN_5G_CAPA_002, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_WLAN_5G);
    ASSERT_TRUE(commCapaInterface != nullptr);
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    uint64_t localCapa = 1 << BIT_WIFI_5G;
    uint64_t remoteCapa = 1 << BIT_WIFI_5G;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(localCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(remoteCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(commCapaMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    int32_t ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = commCapaInterface->getStaticCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNNLaneCommCapaTest
 * @tc.desc: wlan communication capability test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_WLAN_5G_CAPA_003, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_WLAN_5G);
    ASSERT_TRUE(commCapaInterface != nullptr);
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    EXPECT_CALL(commCapaMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(commCapaMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNNLaneCommCapaTest
 * @tc.desc: wlan communication capability test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_ETH_COMM_CAPA_001, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_ETH);
    ASSERT_TRUE(commCapaInterface != nullptr);
    int32_t ret = commCapaInterface->getDynamicCommCapa(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = commCapaInterface->getStaticCommCapa(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNNLaneCommCapaTest
 * @tc.desc: Coc communication capability test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_ETH_COMM_CAPA_002, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_ETH);
    ASSERT_TRUE(commCapaInterface != nullptr);
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    uint64_t localCapa = 1 << BIT_ETH;
    uint64_t remoteCapa = 1 << BIT_ETH;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(localCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(remoteCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(commCapaMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    int32_t ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);

    localCapa = 1 << STATIC_CAP_BIT_ETH;
    remoteCapa = 1 << STATIC_CAP_BIT_ETH;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(localCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(remoteCapa), Return(SOFTBUS_OK)));
    ret = commCapaInterface->getStaticCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNNLaneCommCapaTest
 * @tc.desc: Coc communication capability test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_LANE_ETH_CAPA_003, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_ETH);
    ASSERT_TRUE(commCapaInterface != nullptr);
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    uint64_t localCapa = 1 << STATIC_CAP_BIT_ETH;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(localCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(0), Return(SOFTBUS_OK)));
    int32_t ret = commCapaInterface->getStaticCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_LANE_REMOTE_NO_ETH_STATIC_CAP);
}

/*
 * @tc.name: LNNLaneCommCapaTest
 * @tc.desc: wlan communication capability test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_LANE_P2P_REUSE_CAPA_001, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_P2P_REUSE);
    ASSERT_TRUE(commCapaInterface != nullptr);
    int32_t ret = commCapaInterface->getDynamicCommCapa(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = commCapaInterface->getStaticCommCapa(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNNLaneCommCapaTest
 * @tc.desc: Coc communication capability test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_LANE_P2P_REUSE_CAPA_002, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_P2P_REUSE);
    ASSERT_TRUE(commCapaInterface != nullptr);
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    uint64_t localCapa = 1 << BIT_WIFI_P2P;
    uint64_t remoteCapa = 1 << BIT_WIFI_P2P;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(localCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(remoteCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(commCapaMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    int32_t ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = commCapaInterface->getStaticCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNNLaneCommCapaTest
 * @tc.desc: Coc communication capability test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_LANE_P2P_REUSE_CAPA_003, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_P2P_REUSE);
    ASSERT_TRUE(commCapaInterface != nullptr);
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(commCapaMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_INACTIVE));
    ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_WIFI_DIRECT_CAP);

    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(1 << BIT_WIFI_P2P), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_ACTIVED));
    ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_LANE_REMOTE_NO_WIFI_DIRECT_CAP);
}

/*
 * @tc.name: LNNLaneCommCapaTest
 * @tc.desc: wlan communication capability test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_LANE_BLE_DIRECT_CAPA_001, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_BLE_DIRECT);
    ASSERT_TRUE(commCapaInterface != nullptr);
    int32_t ret = commCapaInterface->getDynamicCommCapa(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = commCapaInterface->getStaticCommCapa(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNNLaneCommCapaTest
 * @tc.desc: Coc communication capability test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_LANE_BLE_DIRECT_CAPA_002, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_BLE_DIRECT);
    ASSERT_TRUE(commCapaInterface != nullptr);
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    uint64_t localCapa = 1 << BIT_BLE;
    uint64_t remoteCapa = 1 << BIT_BLE;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(localCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(remoteCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(commCapaMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    int32_t ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = commCapaInterface->getStaticCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNNLaneCommCapaTest
 * @tc.desc: wlan communication capability test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_LANE_BLE_REUSE_CAPA_001, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_BLE_REUSE);
    ASSERT_TRUE(commCapaInterface != nullptr);
    int32_t ret = commCapaInterface->getDynamicCommCapa(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = commCapaInterface->getStaticCommCapa(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNNLaneCommCapaTest
 * @tc.desc: Coc communication capability test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_LANE_BLE_REUSE_CAPA_002, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_BLE_REUSE);
    ASSERT_TRUE(commCapaInterface != nullptr);
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    uint64_t localCapa = 1 << BIT_BLE;
    uint64_t remoteCapa = 1 << BIT_BLE;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(localCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(remoteCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(commCapaMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    int32_t ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = commCapaInterface->getStaticCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNNLaneCommCapaTest
 * @tc.desc: wlan communication capability test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_LANE_COC_CAPA_001, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_COC);
    ASSERT_TRUE(commCapaInterface != nullptr);
    int32_t ret = commCapaInterface->getDynamicCommCapa(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = commCapaInterface->getStaticCommCapa(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNNLaneCommCapaTest
 * @tc.desc: Coc communication capability test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_LANE_COC_CAPA_002, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_COC);
    ASSERT_TRUE(commCapaInterface != nullptr);
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    uint64_t localCapa = 1 << BIT_BLE;
    uint64_t remoteCapa = 1 << BIT_BLE;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(localCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(remoteCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(commCapaMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    int32_t ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = commCapaInterface->getStaticCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNNLaneCommCapaTest
 * @tc.desc: Coc communication capability test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_LANE_COC_CAPA_003, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_COC);
    ASSERT_TRUE(commCapaInterface != nullptr);
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    uint64_t localCapa = 1 << STATIC_CAP_BIT_BLE;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(localCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(0), Return(SOFTBUS_OK)));
    int32_t ret = commCapaInterface->getStaticCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_LANE_REMOTE_NO_BLE_STATIC_CAP);
}

/*
 * @tc.name: LNNLaneCommCapaTest
 * @tc.desc: Coc communication capability test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_LANE_COC_CAPA_004, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_COC);
    ASSERT_TRUE(commCapaInterface != nullptr);
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info).WillRepeatedly(Return(SOFTBUS_OK));
    ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_BLE_CAP);

    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(1 << BIT_BLE), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(0), Return(SOFTBUS_OK)));
    ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_LANE_REMOTE_NO_BLE_CAP);
}

/*
 * @tc.name: LNNLaneCommCapaTest
 * @tc.desc: wlan communication capability test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_LANE_COC_DIRECT_CAPA_001, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_COC_DIRECT);
    ASSERT_TRUE(commCapaInterface != nullptr);
    int32_t ret = commCapaInterface->getDynamicCommCapa(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = commCapaInterface->getStaticCommCapa(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNNLaneCommCapaTest
 * @tc.desc: Coc communication capability test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_LANE_COC_DIRECT_CAPA_002, TestSize.Level1)
{
    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_COC_DIRECT);
    ASSERT_TRUE(commCapaInterface != nullptr);
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    uint64_t localCapa = 1 << BIT_BLE;
    uint64_t remoteCapa = 1 << BIT_BLE;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(localCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(remoteCapa), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(commCapaMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    int32_t ret = commCapaInterface->getDynamicCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = commCapaInterface->getStaticCommCapa(NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNNLaneCommCapaTest
* @tc.desc: Coc communication capability test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneCommCapaTest, GetLinkCapaByLinkTypeTest, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(SetRemoteDynamicNetCap(nullptr, BIT_WIFI));
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;

    EXPECT_CALL(commCapaMock, LnnGetNetworkIdByUdid).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_NO_FATAL_FAILURE(SetRemoteDynamicNetCap("test_udid1", BIT_WIFI));
    EXPECT_CALL(commCapaMock, LnnGetNetworkIdByUdid).WillRepeatedly(Return(SOFTBUS_OK));

    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_NO_FATAL_FAILURE(SetRemoteDynamicNetCap("test_udid1", BIT_WIFI));

    LaneCommCapa *commCapaInterface = GetLinkCapaByLinkType(LANE_LINK_TYPE_BUTT);
    EXPECT_EQ(commCapaInterface, nullptr);
}
} // namespace OHOS
