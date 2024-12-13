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
 * @tc.desc: on device not trusted test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthHichainTest, ON_DEVICE_NOT_TRUSTED_TEST_001, TestSize.Level1)
{
    const char *groupInfo = "testdata";
    const char *groupInfoStr = "{\"groupId\":\"1111\", \"groupType\":1}";
    const char *udid = "000";
    GroupInfo info;
    AuthNetLedgertInterfaceMock ledgermock;
    EXPECT_CALL(ledgermock, GetJsonObjectStringItem).WillOnce(Return(false)).WillRepeatedly(Return(true));
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
 * @tc.desc: on request test
 * @tc.type: FUNC
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
 * @tc.desc: is potential trusted device test
 * @tc.type: FUNC
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
    EXPECT_CALL(hichainMock, GetGmInstance).WillOnce(Return(NULL)).WillRepeatedly(Return(&grounpManager));
    AuthNetLedgertInterfaceMock ledgermock;
    EXPECT_CALL(ledgermock, LnnGetLocalStrInfo)
        .WillOnce(Return(SOFTBUS_NETWORK_NOT_FOUND))
        .WillRepeatedly(Return(SOFTBUS_OK));
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
 * @tc.desc: is potential trusted device test
 * @tc.type: FUNC
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
 * @tc.desc: hichain get joined groups test
 * @tc.type: FUNC
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
 * @tc.desc: is potential trusted device test
 * @tc.type: FUNC
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
    EXPECT_CALL(hichainMock, GetGmInstance).WillOnce(Return(NULL)).WillRepeatedly(Return(&grounpManager));
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
} // namespace OHOS
