/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "bus_center_ipc_mock.h"
#include "lnn_bus_center_ipc.cpp"
#include "softbus_bus_center.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

#define TEST_PKGNAME       "testname"
#define TEST_PKGNAME2      "testname2"
#define TEST_ADDR          "1111222233334444"
#define TEST_NETWORK_ID    "6542316a57d"
#define TEST_NETWORK_ID2   "6542316a544"
#define TEST_ADDR_TYPE_LEN 17
#define TEST_RET_CODE      0
#define TEST_TYPE          1
#define TEST_MSDP_PKGNAME  "ohos.msdp.spatialawareness"

constexpr char TEST_MSG[] = "testmsg";

class BusCenterIpcTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BusCenterIpcTest::SetUpTestCase() { }

void BusCenterIpcTest::TearDownTestCase()
{
    g_joinLNNRequestInfo.clear();
    g_leaveLNNRequestInfo.clear();
}

void BusCenterIpcTest::SetUp() { }

void BusCenterIpcTest::TearDown() { }

/*
 * @tc.name: LnnIpcServerJoin
 * @tc.desc: buscenter ipc test.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(BusCenterIpcTest, LnnIpcServerJoinTest_01, TestSize.Level1)
{
    NiceMock<BusCenterIpcInterfaceMock> busCenterIpcMock;
    ConnectionAddr addr;
    EXPECT_CALL(busCenterIpcMock, LnnIsSameConnectionAddr).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(busCenterIpcMock, LnnServerJoin).WillRepeatedly(Return(SOFTBUS_OK));
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    AddJoinLNNInfo(TEST_PKGNAME, 0, &addr);
    int32_t ret = LnnIpcServerJoin(nullptr, 0, &addr, TEST_ADDR_TYPE_LEN, false);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnIpcServerJoin(TEST_PKGNAME, 0, nullptr, TEST_ADDR_TYPE_LEN, false);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnIpcServerJoin(TEST_PKGNAME, 0, &addr, sizeof(ConnectionAddr), false);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnIpcServerJoin(TEST_PKGNAME, 0, &addr, sizeof(ConnectionAddr), false);
    EXPECT_TRUE(ret == SOFTBUS_ALREADY_EXISTED);
}

/*
 * @tc.name: LnnIpcServerLeave
 * @tc.desc: buscenter ipc test.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(BusCenterIpcTest, LnnIpcServerLeaveTest_01, TestSize.Level1)
{
    NiceMock<BusCenterIpcInterfaceMock> busCenterIpcMock;
    ON_CALL(busCenterIpcMock, LnnServerLeave).WillByDefault(Return(SOFTBUS_OK));
    int32_t ret = LnnIpcServerLeave(nullptr, 0, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnIpcServerLeave(TEST_PKGNAME, 0, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnIpcServerLeave(TEST_PKGNAME, 0, TEST_NETWORK_ID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnIpcServerLeave(TEST_PKGNAME, 0, TEST_NETWORK_ID);
    EXPECT_TRUE(ret == SOFTBUS_ALREADY_EXISTED);
}

/*
 * @tc.name: LnnIpcGetAllOnlineNodeInfo
 * @tc.desc: buscenter ipc test.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(BusCenterIpcTest, LnnIpcGetAllOnlineNodeInfoTest_01, TestSize.Level1)
{
    NiceMock<BusCenterIpcInterfaceMock> busCenterIpcMock;
    ON_CALL(busCenterIpcMock, LnnGetAllOnlineNodeInfo).WillByDefault(Return(SOFTBUS_OK));
    int32_t ret = LnnIpcGetAllOnlineNodeInfo(TEST_PKGNAME, nullptr, TEST_RET_CODE, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnIpcGetAllOnlineNodeInfo(TEST_PKGNAME, nullptr, sizeof(NodeBasicInfo), nullptr);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LnnIpcNotifyJoinResult
 * @tc.desc: buscenter ipc test.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(BusCenterIpcTest, LnnIpcNotifyJoinResultTest_01, TestSize.Level1)
{
    NiceMock<BusCenterIpcInterfaceMock> busCenterIpcMock;
    ConnectionAddr addr;
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    AddJoinLNNInfo(TEST_PKGNAME, 0, &addr);
    AddJoinLNNInfo(TEST_PKGNAME2, 0, &addr);
    EXPECT_CALL(busCenterIpcMock, LnnIsSameConnectionAddr).WillOnce(Return(true)).WillRepeatedly(Return(false));
    int32_t ret =
        LnnIpcNotifyJoinResult(reinterpret_cast<void *>(&addr), TEST_ADDR_TYPE_LEN, TEST_NETWORK_ID, TEST_RET_CODE);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LnnIpcNotifyLeaveResult
 * @tc.desc: buscenter ipc test.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(BusCenterIpcTest, LnnIpcNotifyLeaveResultTest_01, TestSize.Level1)
{
    NiceMock<BusCenterIpcInterfaceMock> busCenterIpcMock;
    AddLeaveLNNInfo(TEST_PKGNAME, 0, TEST_NETWORK_ID);
    AddLeaveLNNInfo(TEST_PKGNAME2, 0, TEST_NETWORK_ID);
    int32_t ret = LnnIpcNotifyLeaveResult(nullptr, TEST_RET_CODE);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnIpcNotifyLeaveResult(TEST_NETWORK_ID, TEST_RET_CODE);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LnnIpcServerLeave
 * @tc.desc: buscenter ipc test.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(BusCenterIpcTest, LnnIpcServerLeaveTest_02, TestSize.Level1)
{
    NiceMock<BusCenterIpcInterfaceMock> busCenterIpcMock;
    ConnectionAddr addr;
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    AddJoinLNNInfo(TEST_PKGNAME, 0, &addr);
    AddJoinLNNInfo(TEST_PKGNAME2, 0, &addr);
    RemoveJoinRequestInfoByPkgName(TEST_PKGNAME);
    RemoveJoinRequestInfoByPkgName(TEST_PKGNAME2);

    ON_CALL(busCenterIpcMock, LnnServerLeave).WillByDefault(Return(SOFTBUS_OK));
    int32_t ret = LnnIpcServerLeave(nullptr, 0, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnIpcServerLeave
 * @tc.desc: buscenter ipc test.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(BusCenterIpcTest, LnnIpcServerLeaveTest_03, TestSize.Level1)
{
    NiceMock<BusCenterIpcInterfaceMock> busCenterIpcMock;
    ConnectionAddr addr;
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    AddLeaveLNNInfo(TEST_PKGNAME, 0, TEST_NETWORK_ID);
    AddLeaveLNNInfo(TEST_PKGNAME2, 0, TEST_NETWORK_ID);
    RemoveLeaveRequestInfoByPkgName(TEST_PKGNAME);
    BusCenterServerDeathCallback(nullptr);
    BusCenterServerDeathCallback(TEST_PKGNAME);

    ON_CALL(busCenterIpcMock, LnnServerLeave).WillByDefault(Return(SOFTBUS_OK));
    int32_t ret = LnnIpcServerLeave(nullptr, 0, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: RemoveRangeRequestInfoByPkgName
 * @tc.desc: buscenter ipc test.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(BusCenterIpcTest, RemoveRangeRequestInfoByPkgNameTest_01, TestSize.Level1)
{
    NiceMock<BusCenterIpcInterfaceMock> busCenterIpcMock;
    int32_t ret = LnnIpcRegRangeCbForMsdp(TEST_MSDP_PKGNAME, 0);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    RemoveRangeRequestInfoByPkgName(TEST_MSDP_PKGNAME);
    ret = LnnIpcUnregRangeCbForMsdp(TEST_MSDP_PKGNAME, 0);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: RemoveRangeRequestInfoByPkgName
 * @tc.desc: buscenter ipc test.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(BusCenterIpcTest, RemoveRangeRequestInfoByPkgNameTest_02, TestSize.Level1)
{
    NiceMock<BusCenterIpcInterfaceMock> busCenterIpcMock;
    int32_t ret = LnnIpcRegRangeCbForMsdp(TEST_MSDP_PKGNAME, 0);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    RemoveRangeRequestInfoByPkgName(TEST_PKGNAME);
    ret = LnnIpcUnregRangeCbForMsdp(TEST_MSDP_PKGNAME, 0);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: RemoveRangeRequestInfoByPkgName
 * @tc.desc: buscenter ipc test.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(BusCenterIpcTest, RemoveRangeRequestInfoByPkgNameTest_03, TestSize.Level1)
{
    NiceMock<BusCenterIpcInterfaceMock> busCenterIpcMock;
    int32_t ret = LnnIpcRegRangeCbForMsdp(TEST_PKGNAME, 0);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnIpcRegRangeCbForMsdp(TEST_MSDP_PKGNAME, 0);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    RemoveRangeRequestInfoByPkgName(TEST_MSDP_PKGNAME);
    ret = LnnIpcUnregRangeCbForMsdp(TEST_PKGNAME, 0);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnIpcUnregRangeCbForMsdp(TEST_MSDP_PKGNAME, 0);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: RemoveAccountAuthInfoByPkgName_01
 * @tc.desc: buscenter ipc test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterIpcTest, RemoveAccountAuthInfoByPkgName_01, TestSize.Level1)
{
    PkgNameAndPidInfo info = {
        .pkgName = "default",
        .pid = -1,
    };
    int32_t ret = AddAccountAuthInfo(TEST_PKGNAME, 0, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);
    bool repeatRet = IsRepeatAccountAuthRequest(TEST_PKGNAME2, 0);
    EXPECT_EQ(repeatRet, false);
    ret = AddAccountAuthInfo(TEST_PKGNAME2, 0, 1);
    EXPECT_EQ(ret, SOFTBUS_OK);
    repeatRet = IsRepeatAccountAuthRequest(TEST_PKGNAME, 0);
    EXPECT_EQ(repeatRet, true);
    ret = GetAccountAuthInfo(-1, &info);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = GetAccountAuthInfo(0, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(RemoveAccountAuthInfoByPkgName(TEST_PKGNAME2));
    EXPECT_NO_FATAL_FAILURE(RemoveAccountAuthInfoByPkgName(TEST_PKGNAME));
}

/*
 * @tc.name: RemoveAccountAuthInfoByRequestId_01
 * @tc.desc: buscenter ipc test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterIpcTest, RemoveAccountAuthInfoByRequestId_01, TestSize.Level1)
{
    PkgNameAndPidInfo info = {
        .pkgName = "default",
        .pid = -1,
    };
    int32_t ret = AddAccountAuthInfo(TEST_PKGNAME, 0, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);
    bool repeatRet = IsRepeatAccountAuthRequest(TEST_PKGNAME2, 0);
    EXPECT_EQ(repeatRet, false);
    ret = AddAccountAuthInfo(TEST_PKGNAME2, 0, 1);
    EXPECT_EQ(ret, SOFTBUS_OK);
    repeatRet = IsRepeatAccountAuthRequest(TEST_PKGNAME, 0);
    EXPECT_EQ(repeatRet, true);
    ret = GetAccountAuthInfo(-1, &info);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = GetAccountAuthInfo(0, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(RemoveAccountAuthInfoByRequestId(1));
    EXPECT_NO_FATAL_FAILURE(RemoveAccountAuthInfoByRequestId(0));
}

/*
 * @tc.name: OnTransmitAuthResult_01
 * @tc.desc: buscenter ipc test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterIpcTest, OnTransmitAuthResult_01, TestSize.Level1)
{
    bool ret = OnTransmitAuthResult(0, nullptr, 0);
    EXPECT_EQ(ret, false);
    ret = OnTransmitAuthResult(0, (uint8_t*)TEST_MSG, strlen(TEST_MSG) + 1);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: OnSessionKeyAuthResult_01
 * @tc.desc: buscenter ipc test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterIpcTest, OnSessionKeyAuthResult_01, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(OnSessionKeyAuthResult(0, nullptr, 0));
    EXPECT_NO_FATAL_FAILURE(OnSessionKeyAuthResult(0, (uint8_t*)TEST_MSG, strlen(TEST_MSG) + 1));
}

/*
 * @tc.name: OnFinishAuthResult_01
 * @tc.desc: buscenter ipc test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterIpcTest, OnFinishAuthResult_01, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(OnFinishAuthResult(0, 0, nullptr));
    EXPECT_NO_FATAL_FAILURE(OnFinishAuthResult(0, 0, TEST_MSG));
}

/*
 * @tc.name: OnErrorAuthResult_01
 * @tc.desc: buscenter ipc test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterIpcTest, OnErrorAuthResult_01, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(OnErrorAuthResult(0, 0, 0, nullptr));
    EXPECT_NO_FATAL_FAILURE(OnErrorAuthResult(0, 0, 0, TEST_MSG));
}

/*
 * @tc.name: LnnIpcStartAccountAuth_01
 * @tc.desc: buscenter ipc test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterIpcTest, LnnIpcStartAccountAuth_01, TestSize.Level1)
{
    int32_t ret = LnnIpcStartAccountAuth(nullptr, 0, 0, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnIpcStartAccountAuth(TEST_PKGNAME, 0, 0, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnIpcStartAccountAuth(nullptr, 0, 0, TEST_MSG);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnIpcStartAccountAuth(TEST_PKGNAME, 0, 0, TEST_MSG);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ret = LnnIpcStartAccountAuth(TEST_PKGNAME, 0, 0, TEST_MSG);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    RemoveAccountAuthInfoByPkgName(TEST_PKGNAME);
}

/*
 * @tc.name: LnnIpcProcessAccountAuth_01
 * @tc.desc: buscenter ipc test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterIpcTest, LnnIpcProcessAccountAuth_01, TestSize.Level1)
{
    int32_t ret = LnnIpcProcessAccountAuth(nullptr, 0, 0, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnIpcProcessAccountAuth(TEST_PKGNAME, 0, 0, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnIpcProcessAccountAuth(nullptr, 0, 0, (uint8_t*)TEST_MSG, strlen(TEST_MSG) + 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnIpcProcessAccountAuth(TEST_PKGNAME, 0, 0, (uint8_t*)TEST_MSG, strlen(TEST_MSG) + 1);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ret = LnnIpcProcessAccountAuth(TEST_PKGNAME, 0, 0, (uint8_t*)TEST_MSG, strlen(TEST_MSG) + 1);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    RemoveAccountAuthInfoByPkgName(TEST_PKGNAME);
}

/*
 * @tc.name: LnnIpcCreateGroupOwnerTest_001
 * @tc.desc: Test the behavior of LnnIpcCreateGroupOwner when pkgName is nullptr.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(BusCenterIpcTest, LnnIpcCreateGroupOwnerTest_001, TestSize.Level0)
{
    int32_t callingPid = 1234;
    GroupOwnerConfig config = {};
    GroupOwnerResult result = {};

    int32_t ret = LnnIpcCreateGroupOwner(nullptr, callingPid, &config, &result);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnIpcCreateGroupOwnerTest_002
 * @tc.desc: Test the behavior of LnnIpcCreateGroupOwner when config is nullptr.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(BusCenterIpcTest, LnnIpcCreateGroupOwnerTest_002, TestSize.Level0)
{
    const char *pkgName = "testPkgName";
    int32_t callingPid = 1234;
    GroupOwnerResult result = {};

    int32_t ret = LnnIpcCreateGroupOwner(pkgName, callingPid, nullptr, &result);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnIpcCreateGroupOwnerTest_003
 * @tc.desc: Test the behavior of LnnIpcCreateGroupOwner when result is nullptr.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(BusCenterIpcTest, LnnIpcCreateGroupOwnerTest_003, TestSize.Level0)
{
    const char *pkgName = "testPkgName";
    int32_t callingPid = 1234;
    GroupOwnerConfig config = {};

    int32_t ret = LnnIpcCreateGroupOwner(pkgName, callingPid, &config, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}
} // namespace OHOS