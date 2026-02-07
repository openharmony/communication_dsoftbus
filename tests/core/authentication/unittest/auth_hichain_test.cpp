/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cinttypes>
#include <gtest/gtest.h>
#include <securec.h>
#include <sys/time.h>

#include "auth_common_mock.h"
#include "auth_hichain.c"
#include "auth_hichain.h"
#include "auth_hichain_adapter.h"
#include "auth_log.h"
#include "auth_net_ledger_mock.h"
#include "lnn_hichain_mock.h"
#include "softbus_app_info.h"
#include "softbus_error_code.h"
#include "softbus_socket.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;

constexpr int64_t TEST_AUTH_SEQ = 1;
constexpr uint32_t TMP_DATA_LEN = 10;
constexpr uint8_t TMP_DATA[TMP_DATA_LEN] = "tmpInData";

class AuthHichainTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthHichainTest::SetUpTestCase() { }

void AuthHichainTest::TearDownTestCase() { }

void AuthHichainTest::SetUp()
{
    AUTH_LOGI(AUTH_TEST, "AuthHichainTest start");
}

void AuthHichainTest::TearDown() { }

void OnDeviceNotTrustedTest(const char *peerUdid, int32_t localUserId)
{
    (void)localUserId;
    (void)peerUdid;
}

void OnGroupCreatedTest(const char *groupId, int32_t groupType)
{
    (void)groupId;
    (void)groupType;
}

void OnGroupDeletedTest(const char *groupId, int32_t groupType)
{
    (void)groupId;
    (void)groupType;
}

void OnDeviceBound(const char *udid, const char *groupInfo)
{
    (void)udid;
    (void)groupInfo;
}
/*
 * @tc.name: ON_DEVICE_NOT_TRUSTED_TEST_001
 * @tc.desc: Verify that OnGroupCreated, OnGroupDeleted, and OnDeviceNotTrusted callbacks are
 *           correctly invoked and handle various input scenarios, including null and valid group
 *           information.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthHichainTest, ON_DEVICE_NOT_TRUSTED_TEST_001, TestSize.Level1)
{
    const char *groupInfo = "testdata";
    const char *groupInfoStr = "{\"groupId\":\"1111\", \"groupType\":1}";
    const char *udid = "000";
    GroupInfo info;
    int32_t accountId = 100;
    NiceMock<AuthCommonInterfaceMock> authCommMock;
    EXPECT_CALL(authCommMock, JudgeDeviceTypeAndGetOsAccountIds).WillRepeatedly(Return(accountId));
    NodeInfo node;
    (void)memset_s(&node, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    AuthNetLedgertInterfaceMock ledgermock;
    EXPECT_CALL(ledgermock, GetJsonObjectStringItem).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(ledgermock, LnnGetRemoteNodeInfoById)
        .WillRepeatedly(DoAll(SetArgPointee<2>(node), Return(SOFTBUS_OK)));

    OnGroupCreated(nullptr);
    OnGroupCreated(groupInfo);
    g_dataChangeListener.onGroupCreated = nullptr;
    OnGroupCreated(groupInfoStr);
    g_dataChangeListener.onGroupCreated = OnGroupCreatedTest;
    OnGroupCreated(groupInfoStr);

    OnGroupDeleted(nullptr);
    OnGroupDeleted(groupInfo);
    g_dataChangeListener.onGroupDeleted = nullptr;
    OnGroupDeleted(groupInfoStr);
    g_dataChangeListener.onGroupDeleted = OnGroupDeletedTest;
    OnGroupDeleted(groupInfoStr);

    OnDeviceNotTrusted(nullptr);
    g_dataChangeListener.onDeviceNotTrusted = nullptr;
    OnDeviceNotTrusted(udid);
    g_dataChangeListener.onDeviceNotTrusted = OnDeviceNotTrustedTest;
    OnDeviceNotTrusted(udid);

    (void)memset_s(&info, sizeof(GroupInfo), 0, sizeof(GroupInfo));
    int32_t ret = ParseGroupInfo(nullptr, &info);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = ParseGroupInfo(groupInfoStr, &info);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = ParseGroupInfo(groupInfoStr, &info);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    int64_t authSeq = 0;
    uint8_t sessionKey[SESSION_KEY_LENGTH] = { 0 };
    OnSessionKeyReturned(authSeq, nullptr, SESSION_KEY_LENGTH + 1);
    OnSessionKeyReturned(authSeq, nullptr, SESSION_KEY_LENGTH);
    OnSessionKeyReturned(authSeq, sessionKey, SESSION_KEY_LENGTH + 1);

    uint32_t softbusErrCode = 0;
    GetSoftbusHichainAuthErrorCode(HICHAIN_DAS_ERRCODE_MIN, &softbusErrCode);
    GetSoftbusHichainAuthErrorCode(0, &softbusErrCode);
}

/*
 * @tc.name: ON_REQUEST_TEST_001
 * @tc.desc: Verify that OnRequest handles various input parameters and that
 *           DfxRecordLnnExchangekeyEnd and DfxRecordLnnEndHichainEnd are called correctly.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthHichainTest, ON_REQUEST_TEST_001, TestSize.Level1)
{
    int64_t authSeq = 0;
    int32_t operationCode = 0;
    const char *reqParams = "testdata";

    char *msgStr = OnRequest(authSeq, operationCode, reqParams);
    EXPECT_TRUE(msgStr == nullptr);

    const char *udid = "111";
    const char *groupInfo = "{\"groupId\":\"1111\", \"groupType\":1}";
    OnDeviceBound(udid, nullptr);
    OnDeviceBound(nullptr, groupInfo);
    OnDeviceBound(nullptr, nullptr);
    g_dataChangeListener.onDeviceBound = OnDeviceBound;
    OnDeviceBound(udid, groupInfo);

    DfxRecordLnnExchangekeyEnd(authSeq, SOFTBUS_OK);
    DfxRecordLnnEndHichainEnd(authSeq, SOFTBUS_OK);
}

/*
 * @tc.name: IS_POTENTIAL_TRUSTED_DEVICE_TEST_001
 * @tc.desc: Verify that IsPotentialTrustedDevice correctly identifies potential trusted devices,
 *           handling various scenarios including failures in retrieving local string information
 *           and group manager instance.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthHichainTest, IS_POTENTIAL_TRUSTED_DEVICE_TEST_001, TestSize.Level1)
{
    TrustedRelationIdType idType = ID_TYPE_UID;
    const char *deviceId = "test123456";
    bool isPrecise = false;
    DeviceGroupManager grounpManager;
    LnnHichainInterfaceMock hichainMock;
    grounpManager.regDataChangeListener = LnnHichainInterfaceMock::InvokeDataChangeListener;
    grounpManager.unRegDataChangeListener = LnnHichainInterfaceMock::ActionofunRegDataChangeListener;
    grounpManager.getRelatedGroups = LnnHichainInterfaceMock::getRelatedGroups;
    grounpManager.destroyInfo = LnnHichainInterfaceMock::destroyInfo;
    EXPECT_CALL(hichainMock, GetGmInstance).WillOnce(Return(nullptr)).WillRepeatedly(Return(&grounpManager));
    AuthNetLedgertInterfaceMock ledgermock;
    EXPECT_CALL(ledgermock, LnnGetLocalStrInfo)
        .WillOnce(Return(SOFTBUS_NETWORK_NOT_FOUND))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t accountId = 100;
    NiceMock<AuthCommonInterfaceMock> authCommMock;
    EXPECT_CALL(authCommMock, JudgeDeviceTypeAndGetOsAccountIds).WillRepeatedly(Return(accountId));
    bool ret = IsPotentialTrustedDevice(idType, deviceId, isPrecise, false);
    EXPECT_TRUE(ret == false);
    ret = IsPotentialTrustedDevice(idType, deviceId, isPrecise, false);
    EXPECT_TRUE(ret == false);
    ret = IsPotentialTrustedDevice(idType, deviceId, isPrecise, true);
    EXPECT_TRUE(ret == false);
    ret = IsPotentialTrustedDevice(idType, deviceId, isPrecise, true);
    EXPECT_TRUE(ret == false);
    ret = IsPotentialTrustedDevice(idType, deviceId, isPrecise, true);
    EXPECT_TRUE(ret == false);
}

/*
 * @tc.name: IS_POTENTIAL_TRUSTED_DEVICE_TEST_002
 * @tc.desc: Verify that IsPotentialTrustedDevice correctly identifies potential trusted devices
 *           under various conditions, including different group manager configurations and JSON
 *           parsing outcomes.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthHichainTest, IS_POTENTIAL_TRUSTED_DEVICE_TEST_002, TestSize.Level1)
{
    TrustedRelationIdType idType = ID_TYPE_UID;
    const char *deviceId = "1122";
    bool isPrecise = false;
    DeviceGroupManager grounpManager;
    NiceMock<LnnHichainInterfaceMock> hichainMock;
    grounpManager.regDataChangeListener = LnnHichainInterfaceMock::InvokeDataChangeListener;
    grounpManager.unRegDataChangeListener = LnnHichainInterfaceMock::ActionofunRegDataChangeListener;
    grounpManager.getRelatedGroups = LnnHichainInterfaceMock::getRelatedGroups1;
    grounpManager.destroyInfo = LnnHichainInterfaceMock::destroyInfo;
    grounpManager.getTrustedDevices = LnnHichainInterfaceMock::getTrustedDevices;
    EXPECT_CALL(hichainMock, GetGmInstance).WillRepeatedly(Return(&grounpManager));
    NiceMock<AuthNetLedgertInterfaceMock> ledgermock;
    EXPECT_CALL(ledgermock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgermock, GetJsonObjectStringItem).WillOnce(Return(false)).WillRepeatedly(Return(true));
    int32_t accountId = 100;
    NiceMock<AuthCommonInterfaceMock> authCommMock;
    EXPECT_CALL(authCommMock, JudgeDeviceTypeAndGetOsAccountIds).WillRepeatedly(Return(accountId));
    bool ret = IsPotentialTrustedDevice(idType, deviceId, isPrecise, true);
    EXPECT_TRUE(ret == false);
    ret = IsPotentialTrustedDevice(idType, deviceId, isPrecise, true);
    EXPECT_TRUE(ret == false);
    ret = IsPotentialTrustedDevice(idType, deviceId, isPrecise, false);
    EXPECT_TRUE(ret == false);
    ret = IsPotentialTrustedDevice(idType, deviceId, isPrecise, false);
    EXPECT_TRUE(ret == false);
    ret = IsPotentialTrustedDevice(idType, deviceId, isPrecise, false);
    EXPECT_TRUE(ret == false);
    grounpManager.getTrustedDevices = LnnHichainInterfaceMock::getTrustedDevices1;
    ret = IsPotentialTrustedDevice(idType, deviceId, isPrecise, false);
    EXPECT_TRUE(ret == false);
    ret = IsPotentialTrustedDevice(idType, deviceId, isPrecise, false);
    EXPECT_TRUE(ret == false);
}

/*
 * @tc.name: HI_CHAIN_GET_JOINED_GROUPS_TEST_001
 * @tc.desc: Verify that HichainGetJoinedGroups correctly retrieves the number of joined groups
 *           for various group types and handles request cancellations.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthHichainTest, HI_CHAIN_GET_JOINED_GROUPS_TEST_001, TestSize.Level1)
{
    NiceMock<LnnHichainInterfaceMock> hichainMock;
    DeviceGroupManager grounpManager;
    grounpManager.regDataChangeListener = LnnHichainInterfaceMock::InvokeDataChangeListener;
    grounpManager.unRegDataChangeListener = LnnHichainInterfaceMock::ActionofunRegDataChangeListener;
    grounpManager.getJoinedGroups = LnnHichainInterfaceMock::InvokeGetJoinedGroups1;
    EXPECT_CALL(hichainMock, GetGmInstance).WillRepeatedly(Return(&grounpManager));
    int32_t groupType = 0;
    uint32_t ret = HichainGetJoinedGroups(groupType);
    EXPECT_TRUE(ret == 1);
    groupType = 99;
    grounpManager.getJoinedGroups = LnnHichainInterfaceMock::InvokeGetJoinedGroups2;
    ret = HichainGetJoinedGroups(groupType);
    EXPECT_TRUE(ret == 0);
    int64_t authReqId = 32;
    const char *appId = "111";
    CancelRequest(authReqId, appId);
}

/*
 * @tc.name: IS_SAME_ACCOUNT_GROUP_DEVICE_TEST_001
 * @tc.desc: Verify that IsSameAccountGroupDevice correctly determines if a device belongs to the
 *           same account group under various group manager configurations.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthHichainTest, IS_SAME_ACCOUNT_GROUP_DEVICE_TEST_001, TestSize.Level1)
{
    NiceMock<LnnHichainInterfaceMock> hichainMock;
    DeviceGroupManager grounpManager;
    grounpManager.regDataChangeListener = LnnHichainInterfaceMock::InvokeDataChangeListener;
    grounpManager.unRegDataChangeListener = LnnHichainInterfaceMock::ActionofunRegDataChangeListener;
    grounpManager.getJoinedGroups = LnnHichainInterfaceMock::InvokeGetJoinedGroups2;
    grounpManager.destroyInfo = LnnHichainInterfaceMock::destroyInfo;
    EXPECT_CALL(hichainMock, GetGmInstance).WillOnce(Return(nullptr)).WillRepeatedly(Return(&grounpManager));

    int32_t invalidAccountId = 0;
    int32_t accountId = 100;
    NiceMock<AuthCommonInterfaceMock> authCommMock;
    EXPECT_CALL(authCommMock, JudgeDeviceTypeAndGetOsAccountIds)
        .WillOnce(Return(invalidAccountId))
        .WillRepeatedly(Return(accountId));

    bool ret = IsSameAccountGroupDevice();
    EXPECT_TRUE(ret == false);
    ret = IsSameAccountGroupDevice();
    EXPECT_TRUE(ret == false);
    grounpManager.getJoinedGroups = LnnHichainInterfaceMock::InvokeGetJoinedGroups3;
    EXPECT_CALL(hichainMock, GetGmInstance).WillRepeatedly(Return(&grounpManager));
    ret = IsSameAccountGroupDevice();
    EXPECT_TRUE(ret == false);
    grounpManager.getJoinedGroups = LnnHichainInterfaceMock::InvokeGetJoinedGroups1;
    EXPECT_CALL(hichainMock, GetGmInstance).WillRepeatedly(Return(&grounpManager));
    ret = IsSameAccountGroupDevice();
    EXPECT_TRUE(ret == true);
}

/*
 * @tc.name: HICHAIN_PROCESS_UK_NEGO_DATA_TEST_001
 * @tc.desc: Verify that HichainProcessUkNegoData handles invalid parameters when processing
 *           unique key negotiation data.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthHichainTest, HICHAIN_PROCESS_UK_NEGO_DATA_TEST_001, TestSize.Level1)
{
    int64_t authSeq = TEST_AUTH_SEQ;
    const uint8_t *data = reinterpret_cast<const unsigned char *>(TMP_DATA);
    uint32_t len = TMP_DATA_LEN;
    HiChainAuthMode authMode = HICHAIN_AUTH_DEVICE;
    DeviceAuthCallback cb;
    (void)memset_s(&cb, sizeof(DeviceAuthCallback), 0, sizeof(DeviceAuthCallback));

    int32_t ret = HichainProcessUkNegoData(authSeq, data, len, authMode, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = HichainProcessUkNegoData(authSeq, nullptr, len, authMode, &cb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
} // namespace OHOS
