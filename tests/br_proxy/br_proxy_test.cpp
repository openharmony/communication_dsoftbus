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

#include <securec.h>
#include <cstring>

#include "gtest/gtest.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_def.h"
#include "br_proxy_test_mock.h"
#include "br_proxy.h"
#include "softbus_common.h"
#include "nativetoken_kit.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"
#include "softbus_conn_interface.h"
#include "message_handler.h"
#include "br_proxy.c"
#include "br_proxy_server_manager.c"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
#define CHANNEL_ID 5
#define CHANNEL_ID_ERR 0
#define SESSION_ID 2
const char *TEST_UUID = "0000FEEA-0000-1000-8000-00805F9B34FB";
const char *VALID_BR_MAC = "F0:FA:C7:13:56:BC";
const char *INVALID_BR_MAC = "F0:FA:C7:13:56:AB";
class BrProxyTest : public testing::Test {
public:
    BrProxyTest()
    {}
    ~BrProxyTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

static void AddPermission()
{
    uint64_t tokenId;
    const char *perms[1];
    perms[0] = OHOS_PERMISSION_ACCESS_BLUETOOTH;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 1,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "BrProxyTest",
        .aplStr = "system_basic",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

void BrProxyTest::SetUpTestCase(void)
{
    AddPermission();
}

void BrProxyTest::TearDownTestCase(void)
{
}

BrProxyChannelInfo g_channelInfo = {
    .peerBRMacAddr = "F0:FA:C7:13:56:BC",
    .peerBRUuid = "0000FEEA-0000-1000-8000-00805F9B34FB",
    .recvPri = 1,
    .recvPriSet = true,
};

static int32_t onChannelOpened(int32_t sessionId, int32_t channelId, int32_t result)
{
    return SOFTBUS_OK;
}

static void onDataReceived(int32_t channelId, const char *data, uint32_t dataLen)
{
}

static void onChannelStatusChanged(int32_t channelId, int32_t state)
{
}

static IBrProxyListener g_listener = {
    .onChannelOpened = onChannelOpened,
    .onDataReceived = onDataReceived,
    .onChannelStatusChanged = onChannelStatusChanged,
};

static int32_t g_validChannelId = 1;
static uint32_t g_validRequestId = 1;
static int32_t g_invalidChannelId = 2;
static uint32_t g_invalidRequestId = 2;
static int32_t g_sessionId = 1;
static int32_t g_appIndex = 1;

HWTEST_F(BrProxyTest, BrProxyTest000, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(BrProxyTest, BrProxyTest001, TestSize.Level1)
{
    int32_t ret = ClientAddChannelToList(g_sessionId, nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    BrProxyChannelInfo info = {
        .peerBRMacAddr = "F0:FA:C7:13:56:BC",
        .peerBRUuid = "0000FEEA-0000-1000-8000-00805F9B34FB",
    };
    ret = ClientAddChannelToList(g_sessionId, &info, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientAddChannelToList(g_sessionId, nullptr, &g_listener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientAddChannelToList(g_sessionId, &info, &g_listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(BrProxyTest, BrProxyTest002, TestSize.Level1)
{
    int32_t ret = ClientUpdateList(INVALID_BR_MAC, TEST_UUID, g_validChannelId);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = ClientUpdateList(VALID_BR_MAC, TEST_UUID, g_validChannelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(BrProxyTest, BrProxyTest003, TestSize.Level1)
{
    ClientBrProxyChannelInfo info;
    int32_t ret = ClientQueryList(DEFAULT_CHANNEL_ID, nullptr, nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientQueryList(DEFAULT_CHANNEL_ID, nullptr, nullptr, &info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientQueryList(DEFAULT_CHANNEL_ID, INVALID_BR_MAC, TEST_UUID, &info);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = ClientQueryList(g_invalidChannelId, nullptr, nullptr, &info);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = ClientQueryList(DEFAULT_CHANNEL_ID, VALID_BR_MAC, TEST_UUID, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ClientQueryList(g_validChannelId, nullptr, nullptr, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(BrProxyTest, BrProxyTest004, TestSize.Level1)
{
    int32_t ret = ClientRecordListenerState(g_invalidChannelId, DATA_RECEIVE, true);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = ClientRecordListenerState(g_invalidChannelId, LISTENER_TYPE_MAX, true);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientRecordListenerState(g_validChannelId, DATA_RECEIVE, true);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ClientRecordListenerState(g_validChannelId, CHANNEL_STATE, true);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(BrProxyTest, BrProxyTest005, TestSize.Level1)
{
    bool ret = IsChannelValid(g_invalidChannelId);
    EXPECT_EQ(false, ret);
    ret = IsChannelValid(g_validChannelId);
    EXPECT_EQ(true, ret);
}

HWTEST_F(BrProxyTest, BrProxyTest006, TestSize.Level1)
{
    int32_t ret = ClientDeleteChannelFromList(g_invalidChannelId, nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = ClientDeleteChannelFromList(g_validChannelId, nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(BrProxyTest, BrProxyTest007, TestSize.Level1)
{
    int32_t ret = OpenBrProxy(g_sessionId, nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = OpenBrProxy(g_sessionId, &g_channelInfo, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = OpenBrProxy(g_sessionId, nullptr, &g_listener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    NiceMock<BrProxyInterfaceMock> BrProxyMock;
    EXPECT_CALL(BrProxyMock, GetCallerHapInfo).WillRepeatedly(Return(SOFTBUS_TRANS_TOKEN_HAP_ERR));
    ret = OpenBrProxy(g_sessionId, &g_channelInfo, &g_listener);
    EXPECT_EQ(SOFTBUS_TRANS_TOKEN_HAP_ERR, ret);
    ClientBrProxyChannelInfo info;
    ret = ClientQueryList(DEFAULT_CHANNEL_ID, VALID_BR_MAC, TEST_UUID, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
}


HWTEST_F(BrProxyTest, BrProxyTest008, TestSize.Level1)
{
    int32_t ret = ClientTransOnBrProxyOpened(g_validChannelId, nullptr, nullptr, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransOnBrProxyOpened(g_validChannelId, INVALID_BR_MAC, TEST_UUID, 0);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = ClientTransOnBrProxyOpened(g_validChannelId, VALID_BR_MAC, TEST_UUID, 0);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientBrProxyChannelInfo info;
    ret = ClientQueryList(DEFAULT_CHANNEL_ID, VALID_BR_MAC, TEST_UUID, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ClientQueryList(g_validChannelId, nullptr, nullptr, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(BrProxyTest, BrProxyTest009, TestSize.Level1)
{
    int32_t ret = BrProxyServerInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(BrProxyTest, BrProxyTest0010, TestSize.Level1)
{
    ProxyBaseInfo baseInfo;
    int32_t ret = strcpy_s(baseInfo.brMac, sizeof(baseInfo.brMac), VALID_BR_MAC);
    EXPECT_EQ(EOK, ret);
    ret = strcpy_s(baseInfo.uuid, sizeof(baseInfo.uuid), TEST_UUID);
    EXPECT_EQ(EOK, ret);
    const char *data = "test";
    uint32_t dataLen = strlen(data);
    ret = ServerAddDataToList(nullptr, nullptr, dataLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ServerAddDataToList(&baseInfo, nullptr, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ServerAddDataToList(&baseInfo, (const uint8_t *)data, dataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    uint8_t *qData = nullptr;
    uint32_t realLen = 0;
    bool isEmpty;
    GetDataFromList(&baseInfo, &qData, &realLen, &isEmpty);
    if (qData != nullptr) {
        SoftBusFree(qData);
        qData = nullptr;
    }
    EXPECT_EQ(true, dataLen == realLen);
    EXPECT_EQ(false, isEmpty);
    GetDataFromList(&baseInfo, &qData, &realLen, &isEmpty);
    if (qData != nullptr) {
        SoftBusFree(qData);
        qData = nullptr;
    }
    EXPECT_EQ(true, isEmpty);
}

HWTEST_F(BrProxyTest, BrProxyTest0011, TestSize.Level1)
{
    int32_t ret = ServerAddChannelToList(nullptr, nullptr, g_validChannelId, g_validRequestId, g_appIndex);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ServerAddChannelToList(VALID_BR_MAC, TEST_UUID, g_validChannelId, g_validRequestId, g_appIndex);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ServerDeleteChannelFromList(g_invalidChannelId);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = ServerDeleteChannelFromList(g_validChannelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(BrProxyTest, BrProxyTest0012, TestSize.Level1)
{
    int32_t ret = ServerAddChannelToList(VALID_BR_MAC, TEST_UUID, g_validChannelId, g_validRequestId, g_appIndex);
    EXPECT_EQ(SOFTBUS_OK, ret);
    struct ProxyChannel channel = {
        .requestId = g_validRequestId,
    };
    ret = UpdateProxyChannel(INVALID_BR_MAC, TEST_UUID, &channel);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = UpdateProxyChannel(VALID_BR_MAC, TEST_UUID, &channel);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ServerDeleteChannelFromList(g_validChannelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(BrProxyTest, BrProxyTest0013, TestSize.Level1)
{
    ServerBrProxyChannelInfo info;
    int32_t ret = ServerAddChannelToList(VALID_BR_MAC, TEST_UUID, g_validChannelId, g_validRequestId, g_appIndex);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = GetChannelInfo(INVALID_BR_MAC, TEST_UUID, DEFAULT_INVALID_CHANNEL_ID, DEFAULT_INVALID_REQ_ID, &info);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = GetChannelInfo(VALID_BR_MAC, TEST_UUID, DEFAULT_INVALID_CHANNEL_ID, DEFAULT_INVALID_REQ_ID, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = GetChannelInfo(nullptr, nullptr, g_invalidChannelId, DEFAULT_INVALID_REQ_ID, &info);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_ID, ret);
    ret = GetChannelInfo(nullptr, nullptr, g_validChannelId, DEFAULT_INVALID_REQ_ID, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = GetChannelInfo(nullptr, nullptr, DEFAULT_INVALID_CHANNEL_ID, g_invalidRequestId, &info);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = GetChannelInfo(nullptr, nullptr, DEFAULT_INVALID_CHANNEL_ID, g_validRequestId, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ServerDeleteChannelFromList(g_validChannelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(BrProxyTest, BrProxyTest0014, TestSize.Level1)
{
    int32_t ret = ServerAddChannelToList(VALID_BR_MAC, TEST_UUID, g_validChannelId, g_validRequestId, g_appIndex);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<BrProxyInterfaceMock> BrProxyMock;
    EXPECT_CALL(BrProxyMock, ClientIpcBrProxyOpened).WillRepeatedly(Return(SOFTBUS_OK));
    struct ProxyChannel channel = {
        .brMac = "F0:FA:C7:13:56:AB",
    };
    onOpenSuccess(g_validRequestId, &channel);
    ServerBrProxyChannelInfo info;
    ret = GetChannelInfo(VALID_BR_MAC, TEST_UUID, DEFAULT_INVALID_CHANNEL_ID, DEFAULT_INVALID_REQ_ID, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = strcmp(info.channel.brMac, "F0:FA:C7:13:56:AB");
    EXPECT_NE(EOK, ret);
    ret = memcpy_s(channel.brMac, sizeof(channel.brMac), "F0:FA:C7:13:56:BC", strlen("F0:FA:C7:13:56:BC"));
    EXPECT_EQ(EOK, ret);
    onOpenSuccess(g_validRequestId, &channel);
    ret = GetChannelInfo(VALID_BR_MAC, TEST_UUID, DEFAULT_INVALID_CHANNEL_ID, DEFAULT_INVALID_REQ_ID, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ServerDeleteChannelFromList(g_validChannelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(BrProxyTest, BrProxyTest0015, TestSize.Level1)
{
    ServerBrProxyChannelInfo info;
    int32_t ret = ServerAddChannelToList(VALID_BR_MAC, TEST_UUID, g_validChannelId, g_validRequestId, g_appIndex);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<BrProxyInterfaceMock> BrProxyMock;
    EXPECT_CALL(BrProxyMock, ClientIpcBrProxyOpened).WillRepeatedly(Return(SOFTBUS_OK));
    onOpenFail(g_invalidRequestId, 0, nullptr);
    ret = GetChannelInfo(nullptr, nullptr, g_validChannelId, DEFAULT_INVALID_REQ_ID, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    onOpenFail(g_validRequestId, 0, nullptr);
    ret = GetChannelInfo(nullptr, nullptr, g_validChannelId, DEFAULT_INVALID_REQ_ID, &info);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_ID, ret);
    ret = ServerDeleteChannelFromList(g_validChannelId);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}

HWTEST_F(BrProxyTest, BrProxyTest0016, TestSize.Level1)
{
    int32_t ret = TransCloseBrProxy(-1, false);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}

HWTEST_F(BrProxyTest, BrProxyTest0017, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    ret = ClientAddChannelToList(SESSION_ID, &g_channelInfo, &g_listener);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    ret = ClientUpdateList(g_channelInfo.peerBRMacAddr, g_channelInfo.peerBRUuid, CHANNEL_ID);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    ret = ClientTransBrProxyChannelChange(CHANNEL_ID, 0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(BrProxyTest, BrProxyTest0018, TestSize.Level1)
{
    int32_t ret = ClientTransBrProxyDataReceived(CHANNEL_ID_ERR, nullptr, 0);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = ClientTransBrProxyDataReceived(CHANNEL_ID, nullptr, 0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: IsValidSha256Test001
 * @tc.desc: IsValidSha256Test001, when given invalid param should return false
 * @tc.desc: IsValidSha256Test001, when given strlen(param) not euqal to 32 should return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyTest, IsValidSha256Test001, TestSize.Level1)
{
    const char *testBrMac = "testBrMac";
    const char *testUuid = "testUuid111111111111111111111111";
    bool ret = IsValidSha256(nullptr);
    EXPECT_FALSE(ret);
    ret = IsValidSha256(testBrMac);
    EXPECT_FALSE(ret);
    ret = IsValidSha256(testUuid);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: IsPeerDevAddrValidTest001
 * @tc.desc: IsPeerDevAddrValidTest001, when given invalid param should return false
 * @tc.desc: IsValidSha256Test001, when given strlen(param) not euqal to 32 should return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyTest, IsPeerDevAddrValidTest001, TestSize.Level1)
{
    const char *testUuid = "testUuid111111111111111111111111";
    bool ret = IsPeerDevAddrValid(nullptr);
    EXPECT_FALSE(ret);
    ret = IsPeerDevAddrValid(testUuid);
    EXPECT_FALSE(ret);
    ret = IsUuidValid(nullptr);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: ClientTransBrProxyQueryPermissionTest001
 * @tc.desc: ClientTransBrProxyQueryPermissionTest001, when given invalid param should return SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyTest, ClientTransBrProxyQueryPermissionTest001, TestSize.Level1)
{
    const char *bundleName = "testBundleName";
    bool isEmpowered = true;
    int32_t ret = ClientTransBrProxyQueryPermission(nullptr, &isEmpowered);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransBrProxyQueryPermission(bundleName, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = RegisterAccessHook(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}
}