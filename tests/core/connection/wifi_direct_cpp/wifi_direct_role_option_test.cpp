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

#include "softbus_error_code.h"
#include "wifi_direct_role_option.h"
#include "wifi_direct_mock.h"
#include <gtest/gtest.h>

using namespace testing::ext;
using testing::_;
using ::testing::Return;

namespace OHOS::SoftBus {
class WifiDirectRoleOptionTest : public testing::Test {
public:
    static void SetUpTestCase() { }
    static void TearDownTestCase() { }
    void SetUp() override { }
    void TearDown() override { }
};

/*
 * @tc.name: TestWDConnectTypeNegoP2p
 * @tc.desc: check GetExpectedRole method,when type is WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectRoleOptionTest, TestWDConnectTypeNegoP2p, TestSize.Level1)
{
    std::string netWorkId = "12345";
    uint32_t expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    bool isStrict = true;

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetLocalNumInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GC | WIFI_DIRECT_API_ROLE_GO);

    expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    isStrict = true;
    EXPECT_CALL(mock, LnnGetLocalNumInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GC | WIFI_DIRECT_API_ROLE_GO);

    expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    isStrict = true;
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(TYPE_TV_ID), Return(SOFTBUS_OK)));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GO);

    expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    isStrict = true;
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(TYPE_UNKNOW_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, _, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<2>(TYPE_TV_ID), Return(SOFTBUS_OK)));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GC);
}

/*
 * @tc.name: TestWDConnectTypeNegoP2pForWatch
 * @tc.desc: check GetExpectedRole method,when type is WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P and devType is watch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectRoleOptionTest, TestWDConnectTypeNegoP2pForPad, TestSize.Level1)
{
    std::string netWorkId = "12345";
    uint32_t expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    bool isStrict = true;
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(TYPE_PAD_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, _, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<2>(TYPE_PHONE_ID), Return(SOFTBUS_OK)));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GO);

    expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    isStrict = true;
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(TYPE_UNKNOW_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, _, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<2>(TYPE_PAD_ID), Return(SOFTBUS_OK)));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GC);
}

/*
 * @tc.name: TestWDConnectTypeNegoP2pForWatch
 * @tc.desc: check GetExpectedRole method,when type is WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P and devType is watch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectRoleOptionTest, TestWDConnectTypeNegoP2pForWatch, TestSize.Level1)
{
    std::string netWorkId = "12345";
    uint32_t expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    bool isStrict = true;

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(TYPE_UNKNOW_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, _, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<2>(TYPE_WATCH_ID), Return(SOFTBUS_OK)));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GO);

    expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    isStrict = true;
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(TYPE_WATCH_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, _, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<2>(TYPE_UNKNOW_ID), Return(SOFTBUS_OK)));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GC);
}

/*
 * @tc.name: TestWDConnectTypeNegoHML
 * @tc.desc: check GetExpectedRole method,when type is WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectRoleOptionTest, TestWDConnectTypeNegoHML, TestSize.Level1)
{
    std::string netWorkId = "12345";
    uint32_t expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    bool isStrict = true;

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetLocalNumInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo).WillOnce(Return(SOFTBUS_OK));

    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GC | WIFI_DIRECT_API_ROLE_GO | WIFI_DIRECT_API_ROLE_HML);

    expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    isStrict = true;
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(TYPE_PAD_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, _, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<2>(TYPE_PAD_ID), Return(SOFTBUS_OK)));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GO | WIFI_DIRECT_API_ROLE_HML);

    expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    isStrict = true;
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(TYPE_UNKNOW_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, _, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<2>(TYPE_PAD_ID), Return(SOFTBUS_OK)));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GC | WIFI_DIRECT_API_ROLE_HML);
}

/*
 * @tc.name: TestWDConnectTypeInvalid
 * @tc.desc: check GetExpectedRole method,when type is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectRoleOptionTest, TestWDConnectTypeInvalid, TestSize.Level1)
{
    std::string netWorkId = "12345";
    uint32_t expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    bool isStrict = true;

    auto ret = WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, static_cast<WifiDirectConnectType>(-1), expectedRole, isStrict);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TestWDConnectTypeBLETriggerHML
 * @tc.desc: check GetExpectedRole method,when type is WIFI_DIRECT_CONNECT_TYPE_BLE_TRIGGER_HML
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectRoleOptionTest, TestWDConnectTypeBLETriggerHML, TestSize.Level1)
{
    std::string netWorkId = "12345";
    uint32_t expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    bool isStrict = false;

    auto ret = WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_BLE_TRIGGER_HML, expectedRole, isStrict);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(isStrict, true);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_HML);
}

/*
 * @tc.name: TestWDConnectTypeAuthTriggerHML
 * @tc.desc: check GetExpectedRole method,when type is WIFI_DIRECT_CONNECT_TYPE_AUTH_TRIGGER_HML
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectRoleOptionTest, TestWDConnectTypeAuthTriggerHML, TestSize.Level1)
{
    std::string netWorkId = "12345";
    uint32_t expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    bool isStrict = false;

    auto ret = WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_TRIGGER_HML, expectedRole, isStrict);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(isStrict, true);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_HML);
}

/*
 * @tc.name: TestWDConnectTypeActionTriggerHML
 * @tc.desc: check GetExpectedRole method,when type is WIFI_DIRECT_CONNECT_TYPE_ACTION_TRIGGER_HML
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectRoleOptionTest, TestWDConnectTypeActionTriggerHML, TestSize.Level1)
{
    std::string netWorkId = "12345";
    uint32_t expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    bool isStrict = false;

    auto ret = WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_ACTION_TRIGGER_HML, expectedRole, isStrict);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(isStrict, true);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_HML);
}

/*
 * @tc.name: TestWDConnectTypeSparklinkTriggerHML
 * @tc.desc: check GetExpectedRole method,when type is WIFI_DIRECT_CONNECT_TYPE_SPARKLINK_TRIGGER_HML
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectRoleOptionTest, TestWDConnectTypeSparklinkTriggerHML, TestSize.Level1)
{
    std::string netWorkId = "12345";
    uint32_t expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    bool isStrict = false;

    auto ret = WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_SPARKLINK_TRIGGER_HML, expectedRole, isStrict);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(isStrict, true);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_HML);
}

/*
 * @tc.name: TestWDConnectTypeNegoP2pForPC
 * @tc.desc: check GetExpectedRole method,when type is WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P and devType is PC
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectRoleOptionTest, TestWDConnectTypeNegoP2pForPC, TestSize.Level1)
{
    std::string netWorkId = "12345";
    uint32_t expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    bool isStrict = true;

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(TYPE_PC_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, _, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<2>(TYPE_PHONE_ID), Return(SOFTBUS_OK)));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GO);

    expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    isStrict = true;
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(TYPE_UNKNOW_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, _, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<2>(TYPE_PC_ID), Return(SOFTBUS_OK)));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GC);
}

/*
 * @tc.name: TestWDConnectTypeNegoP2pFor2IN1
 * @tc.desc: check GetExpectedRole method,when type is WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P and devType is 2IN1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectRoleOptionTest, TestWDConnectTypeNegoP2pFor2IN1, TestSize.Level1)
{
    std::string netWorkId = "12345";
    uint32_t expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    bool isStrict = true;

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(TYPE_2IN1_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, _, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<2>(TYPE_PHONE_ID), Return(SOFTBUS_OK)));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GO);

    expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    isStrict = true;
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(TYPE_UNKNOW_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, _, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<2>(TYPE_2IN1_ID), Return(SOFTBUS_OK)));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GC);
}

/*
 * @tc.name: TestWDConnectTypeNegoP2pForCAR
 * @tc.desc: check GetExpectedRole method,when type is WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P and devType is CAR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectRoleOptionTest, TestWDConnectTypeNegoP2pForCAR, TestSize.Level1)
{
    std::string netWorkId = "12345";
    uint32_t expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    bool isStrict = true;

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(TYPE_CAR_ID), Return(SOFTBUS_OK)));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GO);

    expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    isStrict = true;
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(TYPE_UNKNOW_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, _, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<2>(TYPE_CAR_ID), Return(SOFTBUS_OK)));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GC);
}

/*
 * @tc.name: TestWDConnectTypeNegoP2pForSmartDisplay
 * @tc.desc: check GetExpectedRole method,when type is WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P and devType is
 * SmartDisplay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectRoleOptionTest, TestWDConnectTypeNegoP2pForSmartDisplay, TestSize.Level1)
{
    std::string netWorkId = "12345";
    uint32_t expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    bool isStrict = true;

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(TYPE_SMART_DISPLAY_ID), Return(SOFTBUS_OK)));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GO);

    expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    isStrict = true;
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(TYPE_UNKNOW_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, _, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<2>(TYPE_SMART_DISPLAY_ID), Return(SOFTBUS_OK)));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GC);
}

/*
 * @tc.name: TestWDConnectTypeNegoP2pBothUnknown
 * @tc.desc: check GetExpectedRole method,when type is WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P and both devices are
 * unknown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectRoleOptionTest, TestWDConnectTypeNegoP2pBothUnknown, TestSize.Level1)
{
    std::string netWorkId = "12345";
    uint32_t expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    bool isStrict = true;

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(TYPE_UNKNOW_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, _, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<2>(TYPE_UNKNOW_ID), Return(SOFTBUS_OK)));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GC | WIFI_DIRECT_API_ROLE_GO);
}

/*
 * @tc.name: TestWDConnectTypeNegoHMLForPC
 * @tc.desc: check GetExpectedRole method,when type is WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML and devType is PC
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectRoleOptionTest, TestWDConnectTypeNegoHMLForPC, TestSize.Level1)
{
    std::string netWorkId = "12345";
    uint32_t expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    bool isStrict = true;

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(TYPE_PC_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, _, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<2>(TYPE_PHONE_ID), Return(SOFTBUS_OK)));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GO | WIFI_DIRECT_API_ROLE_HML);

    expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    isStrict = true;
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(TYPE_UNKNOW_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, _, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<2>(TYPE_PC_ID), Return(SOFTBUS_OK)));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GC | WIFI_DIRECT_API_ROLE_HML);
}

/*
 * @tc.name: TestWDConnectTypeNegoHMLFor2IN1
 * @tc.desc: check GetExpectedRole method,when type is WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML and devType is 2IN1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectRoleOptionTest, TestWDConnectTypeNegoHMLFor2IN1, TestSize.Level1)
{
    std::string netWorkId = "12345";
    uint32_t expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    bool isStrict = true;

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(TYPE_2IN1_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, _, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<2>(TYPE_PHONE_ID), Return(SOFTBUS_OK)));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GO | WIFI_DIRECT_API_ROLE_HML);

    expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    isStrict = true;
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(TYPE_UNKNOW_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, _, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<2>(TYPE_2IN1_ID), Return(SOFTBUS_OK)));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GC | WIFI_DIRECT_API_ROLE_HML);
}

/*
 * @tc.name: TestWDConnectTypeNegoHMLForCAR
 * @tc.desc: check GetExpectedRole method,when type is WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML and devType is CAR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectRoleOptionTest, TestWDConnectTypeNegoHMLForCAR, TestSize.Level1)
{
    std::string netWorkId = "12345";
    uint32_t expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    bool isStrict = true;

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(TYPE_CAR_ID), Return(SOFTBUS_OK)));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GO | WIFI_DIRECT_API_ROLE_HML);

    expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    isStrict = true;
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(TYPE_UNKNOW_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, _, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<2>(TYPE_CAR_ID), Return(SOFTBUS_OK)));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GC | WIFI_DIRECT_API_ROLE_HML);
}

/*
 * @tc.name: TestWDConnectTypeNegoHMLForSmartDisplay
 * @tc.desc: check GetExpectedRole method,when type is WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML and devType is
 * SmartDisplay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectRoleOptionTest, TestWDConnectTypeNegoHMLForSmartDisplay, TestSize.Level1)
{
    std::string netWorkId = "12345";
    uint32_t expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    bool isStrict = true;

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(TYPE_SMART_DISPLAY_ID), Return(SOFTBUS_OK)));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GO | WIFI_DIRECT_API_ROLE_HML);

    expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    isStrict = true;
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(TYPE_UNKNOW_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, _, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<2>(TYPE_SMART_DISPLAY_ID), Return(SOFTBUS_OK)));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GC | WIFI_DIRECT_API_ROLE_HML);
}

/*
 * @tc.name: TestWDConnectTypeNegoHMLForWatch
 * @tc.desc: check GetExpectedRole method,when type is WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML and devType is Watch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectRoleOptionTest, TestWDConnectTypeNegoHMLForWatch, TestSize.Level1)
{
    std::string netWorkId = "12345";
    uint32_t expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    bool isStrict = true;

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(TYPE_UNKNOW_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, _, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<2>(TYPE_WATCH_ID), Return(SOFTBUS_OK)));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GO | WIFI_DIRECT_API_ROLE_HML);

    expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    isStrict = true;
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(TYPE_WATCH_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, _, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<2>(TYPE_UNKNOW_ID), Return(SOFTBUS_OK)));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GC | WIFI_DIRECT_API_ROLE_HML);
}

/*
 * @tc.name: TestWDConnectTypeNegoHMLBothUnknown
 * @tc.desc: check GetExpectedRole method,when type is WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML and both devices are
 * unknown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectRoleOptionTest, TestWDConnectTypeNegoHMLBothUnknown, TestSize.Level1)
{
    std::string netWorkId = "12345";
    uint32_t expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    bool isStrict = true;

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(TYPE_UNKNOW_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, _, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<2>(TYPE_UNKNOW_ID), Return(SOFTBUS_OK)));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GC | WIFI_DIRECT_API_ROLE_GO | WIFI_DIRECT_API_ROLE_HML);
}

/*
 * @tc.name: TestWDConnectTypeNegoHMLBothPhone
 * @tc.desc: check GetExpectedRole method,when type is WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML and both devices are phone
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectRoleOptionTest, TestWDConnectTypeNegoHMLBothPhone, TestSize.Level1)
{
    std::string netWorkId = "12345";
    uint32_t expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    bool isStrict = true;

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(TYPE_PHONE_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, _, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<2>(TYPE_PHONE_ID), Return(SOFTBUS_OK)));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GC | WIFI_DIRECT_API_ROLE_GO | WIFI_DIRECT_API_ROLE_HML);
}

/*
 * @tc.name: TestWDConnectTypeNegoP2pLocalGcPrefRemoteGoPref
 * @tc.desc: check GetExpectedRole method when local prefers GC and remote prefers GO
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectRoleOptionTest, TestWDConnectTypeNegoP2pLocalGcPrefRemoteGoPref, TestSize.Level1)
{
    std::string netWorkId = "12345";
    uint32_t expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    bool isStrict = true;

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(TYPE_WATCH_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, _, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<2>(TYPE_PAD_ID), Return(SOFTBUS_OK)));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GC);
}

/*
 * @tc.name: TestWDConnectTypeNegoP2pLocalGoPrefRemoteGcPref
 * @tc.desc: check GetExpectedRole method when local prefers GO and remote prefers GC
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectRoleOptionTest, TestWDConnectTypeNegoP2pLocalGoPrefRemoteGcPref, TestSize.Level1)
{
    std::string netWorkId = "12345";
    uint32_t expectedRole = WIFI_DIRECT_API_ROLE_NONE;
    bool isStrict = true;

    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<1>(TYPE_PAD_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, _, _))
        .WillOnce(testing::DoAll(testing::SetArgPointee<2>(TYPE_WATCH_ID), Return(SOFTBUS_OK)));
    WifiDirectRoleOption::GetInstance().GetExpectedRole(
        netWorkId, WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P, expectedRole, isStrict);
    EXPECT_EQ(isStrict, false);
    EXPECT_EQ(expectedRole, WIFI_DIRECT_API_ROLE_GO);
}
} // namespace OHOS::SoftBus