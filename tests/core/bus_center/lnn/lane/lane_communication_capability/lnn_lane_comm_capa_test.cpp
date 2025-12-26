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
* @tc.name: LnnCommCapaTest001
* @tc.desc: Verify whether the method can correctly return the expected error code
*           when invalid parameters are passed
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneCommCapaTest, LNN_COMM_CAPA_001, TestSize.Level1)
{
    int32_t ret = CheckStaticNetCap(nullptr, LANE_BR);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = CheckStaticNetCap(NETWORK_ID, LANE_LINK_TYPE_BUTT);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = CheckDynamicNetCap(nullptr, LANE_BR);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LnnCommCapaTest002
* @tc.desc: Tested the verification logic for static and dynamic network capabilities
*           under different link types
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneCommCapaTest, LNN_COMM_CAPA_002, TestSize.Level1)
{
    LaneLinkType typeList[] = {
        LANE_BR, LANE_BLE, LANE_P2P, LANE_HML, LANE_WLAN_2P4G, LANE_WLAN_5G, LANE_ETH, LANE_P2P_REUSE, LANE_BLE_DIRECT,
        LANE_BLE_REUSE, LANE_COC, LANE_COC_DIRECT
    };
    uint32_t size = sizeof(typeList) / sizeof(LaneLinkType);
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(commCapaMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    for (uint32_t i = LANE_BR; i < size; i++) {
        GTEST_LOG_(INFO) << "type=" << typeList[i];
        int32_t ret = CheckStaticNetCap(NETWORK_ID, typeList[i]);
        EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
        ret = CheckDynamicNetCap(NETWORK_ID, typeList[i]);
        EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    }

    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    for (uint32_t i = LANE_BR; i < size; i++) {
        int32_t ret = CheckStaticNetCap(NETWORK_ID, typeList[i]);
        EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
        ret = CheckDynamicNetCap(NETWORK_ID, typeList[i]);
        EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    }
}

/*
 * @tc.name: LnnBrCommCapaCheckTest001
 * @tc.desc: Verify that the return results of static and dynamic network capability check functions meet expectations
 *           under different network capability configurations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_BR_COMM_CAPA_CHECK_001, TestSize.Level1)
{
    LaneLinkType type = LANE_BR;
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(0), Return(SOFTBUS_OK)));
    int32_t ret = CheckStaticNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_BR_STATIC_CAP);
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_BR_CAP);

    uint32_t staticCap = 1 << STATIC_CAP_BIT_BR;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(staticCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(0), Return(SOFTBUS_OK)));
    ret = CheckStaticNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_REMOTE_NO_BR_STATIC_CAP);

    uint32_t dynamicCap = 1 << BIT_BR;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(dynamicCap), Return(SOFTBUS_OK)));
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_REMOTE_NO_BR_CAP);

    uint32_t allNetCap = (staticCap | dynamicCap);
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(allNetCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(allNetCap), Return(SOFTBUS_OK)));
    ret = CheckStaticNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnSleCommCapaCheckTest001
 * @tc.desc: Verify that the return results of the check fucntion meet expectations
 *           under different network capability configurations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_SLE_COMM_CAPA_CHECK_001, TestSize.Level1)
{
    LaneLinkType type = LANE_SLE;
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(0), Return(SOFTBUS_OK)));
    int32_t ret = CheckStaticNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_SLE_STATIC_CAP);
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_SLE_CAP);

    uint32_t staticCap = 1 << STATIC_CAP_BIT_SLE;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(staticCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(0), Return(SOFTBUS_OK)));
    ret = CheckStaticNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_REMOTE_NO_SLE_STATIC_CAP);

    uint32_t dynamicCap = 1 << BIT_SLE;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(dynamicCap), Return(SOFTBUS_OK)));
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_REMOTE_NO_SLE_CAP);

    uint32_t allNetCap = (staticCap | dynamicCap);
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(allNetCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(allNetCap), Return(SOFTBUS_OK)));
    ret = CheckStaticNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnBleCommCapaCheckTest001
 * @tc.desc: Verify that the return results of static and dynamic network capability check functions meet expectations
 *           under different network capability configurations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_BLE_COMM_CAPA_CHECK_001, TestSize.Level1)
{
    LaneLinkType type = LANE_BLE;
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(0), Return(SOFTBUS_OK)));
    int32_t ret = CheckStaticNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_BLE_STATIC_CAP);
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_BLE_CAP);

    uint32_t staticCap = 1 << STATIC_CAP_BIT_BLE;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(staticCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(0), Return(SOFTBUS_OK)));
    ret = CheckStaticNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_REMOTE_NO_BLE_STATIC_CAP);

    uint32_t dynamicCap = 1 << BIT_BLE;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(dynamicCap), Return(SOFTBUS_OK)));
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_REMOTE_NO_BLE_CAP);

    uint32_t allNetCap = (staticCap | dynamicCap);
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(allNetCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(allNetCap), Return(SOFTBUS_OK)));
    ret = CheckStaticNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnP2PCommCapaCheckTest001
 * @tc.desc: Verify that the return results of static and dynamic network capability check functions meet expectations
 *           under different network capability configurations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_P2P_COMM_CAPA_CHECK_001, TestSize.Level1)
{
    LaneLinkType type = LANE_P2P;
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(0), Return(SOFTBUS_OK)));\
    EXPECT_CALL(commCapaMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_INACTIVE));
    int32_t ret = CheckStaticNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_P2P_STATIC_CAP);
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_WIFI_DIRECT_CAP);
    EXPECT_CALL(commCapaMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_SEMIACTIVE));
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_REMOTE_NO_WIFI_DIRECT_CAP);

    uint32_t staticCap = 1 << STATIC_CAP_BIT_P2P;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(staticCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(0), Return(SOFTBUS_OK)));
    ret = CheckStaticNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_REMOTE_NO_P2P_STATIC_CAP);

    uint32_t dynamicCap = 1 << BIT_WIFI_P2P;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(dynamicCap), Return(SOFTBUS_OK)));
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_REMOTE_NO_WIFI_DIRECT_CAP);

    uint32_t allNetCap = (staticCap | dynamicCap);
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(allNetCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(allNetCap), Return(SOFTBUS_OK)));
    ret = CheckStaticNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnHMLCommCapaCheckTest001
 * @tc.desc: Test the communication capability check function related to HML in the LNN module
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_HML_COMM_CAPA_CHECK_001, TestSize.Level1)
{
    LaneLinkType type = LANE_HML;
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_DEACTIVATING));
    int32_t ret = CheckStaticNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_ENHANCED_P2P_STATIC_CAP);
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_WIFI_DIRECT_CAP);
    EXPECT_CALL(commCapaMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_SEMIACTIVE));
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_REMOTE_NO_WIFI_DIRECT_CAP);

    uint32_t staticCap = 1 << STATIC_CAP_BIT_ENHANCED_P2P;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(staticCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(0), Return(SOFTBUS_OK)));
    ret = CheckStaticNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_REMOTE_NO_ENHANCED_P2P_STATIC_CAP);

    uint32_t dynamicCap = 1 << BIT_WIFI_P2P;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(dynamicCap), Return(SOFTBUS_OK)));
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_REMOTE_NO_WIFI_DIRECT_CAP);

    uint32_t allNetCap = (staticCap | dynamicCap);
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(allNetCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(allNetCap), Return(SOFTBUS_OK)));
    ret = CheckStaticNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: Lnn24GCommCapaCheckTest001
 * @tc.desc: Test the 2.4G wifi network communication capability check function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_24G_COMM_CAPA_CHECK_001, TestSize.Level1)
{
    LaneLinkType type = LANE_WLAN_2P4G;
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    EXPECT_CALL(commCapaMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_NOT_ONLINE);

    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(commCapaMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    ret = CheckStaticNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_WIFI_STATIC_CAP);
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_BAND_ERR);

    uint32_t staticCap = 1 << STATIC_CAP_BIT_WIFI;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(staticCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(0), Return(SOFTBUS_OK)));
    ret = CheckStaticNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_REMOTE_NO_WIFI_STATIC_CAP);

    uint32_t dynamicCap = 1 << BIT_WIFI_24G;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(dynamicCap), Return(SOFTBUS_OK)));
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_OK);
    dynamicCap = 1 << BIT_ETH;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(dynamicCap), Return(SOFTBUS_OK)));
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_OK);

    uint32_t allNetCap = (staticCap | dynamicCap);
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(allNetCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(allNetCap), Return(SOFTBUS_OK)));
    ret = CheckStaticNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: Lnn5GCommCapaCheckTest001
 * @tc.desc: Test the 5G wifi network communication capability check function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_5G_COMM_CAPA_CHECK_001, TestSize.Level1)
{
    LaneLinkType type = LANE_WLAN_5G;
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    EXPECT_CALL(commCapaMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_NOT_ONLINE);

    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(commCapaMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    ret = CheckStaticNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_WIFI_STATIC_CAP);
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_BAND_ERR);

    uint32_t staticCap = 1 << STATIC_CAP_BIT_WIFI;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(staticCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(0), Return(SOFTBUS_OK)));
    ret = CheckStaticNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_REMOTE_NO_WIFI_STATIC_CAP);

    uint32_t dynamicCap = 1 << BIT_WIFI_5G;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(dynamicCap), Return(SOFTBUS_OK)));
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_OK);
    dynamicCap = 1 << BIT_ETH;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(dynamicCap), Return(SOFTBUS_OK)));
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_OK);

    uint32_t allNetCap = (staticCap | dynamicCap);
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(allNetCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(allNetCap), Return(SOFTBUS_OK)));
    ret = CheckStaticNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnETHCommCapaCheckTest001
 * @tc.desc: Test the ETH network communication capability check function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_ETH_COMM_CAPA_CHECK_001, TestSize.Level1)
{
    LaneLinkType type = LANE_ETH;
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    EXPECT_CALL(commCapaMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_NOT_ONLINE);

    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(commCapaMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    ret = CheckStaticNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_ETH_STATIC_CAP);
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_ETH_CAP);

    uint32_t staticCap = 1 << STATIC_CAP_BIT_ETH;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(staticCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(0), Return(SOFTBUS_OK)));
    ret = CheckStaticNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_REMOTE_NO_ETH_STATIC_CAP);

    uint32_t dynamicCap = 1 << BIT_ETH;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(dynamicCap), Return(SOFTBUS_OK)));
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_REMOTE_NO_ETH_CAP);

    uint32_t allNetCap = (staticCap | dynamicCap);
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(allNetCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(allNetCap), Return(SOFTBUS_OK)));
    ret = CheckStaticNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnCocCommCapaCheckTest001
 * @tc.desc: Test the COC network communication capability check function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_COC_COMM_CAPA_CHECK_001, TestSize.Level1)
{
    LaneLinkType type = LANE_COC;
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(commCapaMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    int32_t ret = CheckStaticNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_BLE_STATIC_CAP);
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_BLE_CAP);

    uint32_t staticCap = 1 << STATIC_CAP_BIT_BLE;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(staticCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(0), Return(SOFTBUS_OK)));
    ret = CheckStaticNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_REMOTE_NO_BLE_STATIC_CAP);

    uint32_t dynamicCap = 1 << BIT_BLE;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(dynamicCap), Return(SOFTBUS_OK)));
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_REMOTE_NO_BLE_CAP);

    uint32_t allNetCap = (staticCap | dynamicCap);
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(allNetCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(allNetCap), Return(SOFTBUS_OK)));
    ret = CheckStaticNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: SetRemoteDynamicNetCapTest001
* @tc.desc: Verify that the function can correctly handle various scenarios without crashing
*           under different input conditions and depending on the return values of the function
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneCommCapaTest, SetRemoteDynamicNetCapTest001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(SetRemoteDynamicNetCap(nullptr, LANE_HML));
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;

    EXPECT_CALL(commCapaMock, LnnGetNetworkIdByUdid).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_NO_FATAL_FAILURE(SetRemoteDynamicNetCap("test_udid1", LANE_HML));
    EXPECT_CALL(commCapaMock, LnnGetNetworkIdByUdid).WillRepeatedly(Return(SOFTBUS_OK));

    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_NO_FATAL_FAILURE(SetRemoteDynamicNetCap("test_udid1", LANE_HML));

    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(SetRemoteDynamicNetCap("test_udid1", LANE_HML));

    uint32_t netCap = 1 << BIT_WIFI_P2P;
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(netCap), Return(SOFTBUS_OK)));
    EXPECT_NO_FATAL_FAILURE(SetRemoteDynamicNetCap("test_udid1", LANE_HML));
    netCap = 1 << BIT_BLE;
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(netCap), Return(SOFTBUS_OK)));
    EXPECT_NO_FATAL_FAILURE(SetRemoteDynamicNetCap("test_udid1", LANE_HML));
}

/*
 * @tc.name: LnnUSBCommCapaCheckTest001
 * @tc.desc: Test the network capability check function related to USB communication
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLaneCommCapaTest, LNN_USB_COMM_CAPA_CHECK_001, TestSize.Level1)
{
    LaneLinkType type = LANE_USB;
    NiceMock<LaneCommCapaDepsInterfaceMock> commCapaMock;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(0), Return(SOFTBUS_OK)));
    int32_t ret = CheckStaticNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_USB_STATIC_CAP);
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NODE_OFFLINE);

    uint32_t staticCap = 1 << STATIC_CAP_BIT_USB;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(staticCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(0), Return(SOFTBUS_OK)));
    ret = CheckStaticNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_LANE_REMOTE_NO_USB_STATIC_CAP);

    uint32_t dynamicCap = 1 << BIT_USB;
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(dynamicCap), Return(SOFTBUS_OK)));
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NODE_OFFLINE);

    uint32_t allNetCap = (staticCap | dynamicCap);
    EXPECT_CALL(commCapaMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(allNetCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(commCapaMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(allNetCap), Return(SOFTBUS_OK)));
    ret = CheckStaticNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = CheckDynamicNetCap(NETWORK_ID, type);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NODE_OFFLINE);
}
} // namespace OHOS
