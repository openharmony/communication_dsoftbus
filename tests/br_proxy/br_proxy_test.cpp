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
const char *TEST_UUID = "0000FEEA-0000-1000-8000-00805F9B34FB";
const char *VALID_BR_MAC = "F0:FA:C7:13:56:BC";
const char *INVALID_BR_MAC = "F0:FA:C7:13:56:AB";
static pid_t g_testPid = 1000;
static uint32_t g_testCallTokenId = 999;
static int32_t g_testPri = 2;
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
        .dcaps = NULL,
        .perms = perms,
        .acls = NULL,
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
    .peerBRUuid = "8888FEEA-0000-1000-8000-00805F9B8888",
    .recvPri = 1,
    .recvPriSet = true,
};

static int32_t onChannelOpened(int32_t channelId, int32_t result)
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

HWTEST_F(BrProxyTest, BrProxyTest000, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(BrProxyTest, BrProxyTest001, TestSize.Level1)
{
    int32_t ret = ClientAddChannelToList(NULL, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    BrProxyChannelInfo info = {
        .peerBRMacAddr = "F0:FA:C7:13:56:BC",
    };
    ret = ClientAddChannelToList(&info, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientAddChannelToList(NULL, &g_listener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientAddChannelToList(&info, &g_listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(BrProxyTest, BrProxyTest002, TestSize.Level1)
{
    int32_t ret = ClientUpdateList(INVALID_BR_MAC, g_validChannelId);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = ClientUpdateList(VALID_BR_MAC, g_validChannelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(BrProxyTest, BrProxyTest003, TestSize.Level1)
{
    ClientBrProxyChannelInfo info;
    int32_t ret = ClientQueryList(DEFAULT_CHANNEL_ID, NULL, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientQueryList(DEFAULT_CHANNEL_ID, NULL, &info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientQueryList(DEFAULT_CHANNEL_ID, INVALID_BR_MAC, &info);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = ClientQueryList(g_invalidChannelId, NULL, &info);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = ClientQueryList(DEFAULT_CHANNEL_ID, VALID_BR_MAC, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ClientQueryList(g_validChannelId, NULL, &info);
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
    int32_t ret = ClientDeleteChannelFromList(g_invalidChannelId);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = ClientDeleteChannelFromList(g_validChannelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(BrProxyTest, BrProxyTest007, TestSize.Level1)
{
    int32_t ret = OpenBrProxy(NULL, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = OpenBrProxy(&g_channelInfo, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = OpenBrProxy(NULL, &g_listener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = OpenBrProxy(&g_channelInfo, &g_listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientBrProxyChannelInfo info;
    ret = ClientQueryList(DEFAULT_CHANNEL_ID, VALID_BR_MAC, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
}


HWTEST_F(BrProxyTest, BrProxyTest008, TestSize.Level1)
{
    int32_t ret = ClientTransOnBrProxyOpened(g_validChannelId, NULL, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransOnBrProxyOpened(g_validChannelId, INVALID_BR_MAC, 0);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = ClientTransOnBrProxyOpened(g_validChannelId, VALID_BR_MAC, 0);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientBrProxyChannelInfo info;
    ret = ClientQueryList(DEFAULT_CHANNEL_ID, VALID_BR_MAC, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ClientQueryList(g_validChannelId, NULL, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(BrProxyTest, BrProxyTest009, TestSize.Level1)
{
    int32_t ret = BrProxyServerInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(BrProxyTest, BrProxyTest0010, TestSize.Level1)
{
    const char *data = "test";
    uint32_t dataLen = strlen(data);
    int32_t ret = ServerAddDataToList(NULL, NULL, dataLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ServerAddDataToList(INVALID_BR_MAC, NULL, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ServerAddDataToList(INVALID_BR_MAC, (const uint8_t *)data, dataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    uint8_t qdata[10];
    uint32_t realLen = 0;
    bool isEmpty;
    GetDataFromList(INVALID_BR_MAC, qdata, sizeof(qdata), &realLen, &isEmpty);
    EXPECT_EQ(true, dataLen == realLen);
    EXPECT_EQ(false, isEmpty);
    GetDataFromList(INVALID_BR_MAC, qdata, sizeof(qdata), &realLen, &isEmpty);
    EXPECT_EQ(true, isEmpty);
}

HWTEST_F(BrProxyTest, BrProxyTest0011, TestSize.Level1)
{
    int32_t ret = ServerAddChannelToList(NULL, g_validChannelId, g_validRequestId,
        g_testPid, g_testCallTokenId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ServerAddChannelToList(&g_channelInfo, g_validChannelId, g_validRequestId,
        g_testPid, g_testCallTokenId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ServerDeleteChannelFromList(g_invalidChannelId);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = ServerDeleteChannelFromList(g_validChannelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(BrProxyTest, BrProxyTest0012, TestSize.Level1)
{
    int32_t ret = ServerAddChannelToList(&g_channelInfo, g_validChannelId, g_validRequestId,
        g_testPid, g_testCallTokenId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    struct ProxyChannel channel;
    ret = UpdateProxyChannel(INVALID_BR_MAC, &channel, false);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = UpdateProxyChannel(VALID_BR_MAC, &channel, false);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ServerDeleteChannelFromList(g_validChannelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(BrProxyTest, BrProxyTest0013, TestSize.Level1)
{
    ServerBrProxyChannelInfo info;
    int32_t ret = ServerAddChannelToList(&g_channelInfo, g_validChannelId, g_validRequestId,
        g_testPid, g_testCallTokenId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = GetChannelInfo(INVALID_BR_MAC, DEFAULT_INVALID_CHANNEL_ID, DEFAULT_INVALID_REQ_ID, &info);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = GetChannelInfo(VALID_BR_MAC, DEFAULT_INVALID_CHANNEL_ID, DEFAULT_INVALID_REQ_ID, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = GetChannelInfo(NULL, g_invalidChannelId, DEFAULT_INVALID_REQ_ID, &info);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = GetChannelInfo(NULL, g_validChannelId, DEFAULT_INVALID_REQ_ID, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = GetChannelInfo(NULL, DEFAULT_INVALID_CHANNEL_ID, g_invalidRequestId, &info);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = GetChannelInfo(NULL, DEFAULT_INVALID_CHANNEL_ID, g_validRequestId, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ServerDeleteChannelFromList(g_validChannelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(BrProxyTest, BrProxyTest0014, TestSize.Level1)
{
    int32_t ret = ServerAddChannelToList(&g_channelInfo, g_validChannelId, g_validRequestId,
        g_testPid, g_testCallTokenId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<BrProxyInterfaceMock> BrProxyMock;
    EXPECT_CALL(BrProxyMock, ClientIpcBrProxyOpened).WillRepeatedly(Return(SOFTBUS_OK));
    struct ProxyChannel channel = {
        .brMac = "F0:FA:C7:13:56:AB",
    };
    onOpenSuccess(g_validRequestId, &channel);
    ServerBrProxyChannelInfo info;
    ret = GetChannelInfo(VALID_BR_MAC, DEFAULT_INVALID_CHANNEL_ID, DEFAULT_INVALID_REQ_ID, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = strcmp(info.channel->brMac, "F0:FA:C7:13:56:AB");
    EXPECT_NE(EOK, ret);
    ret = memcpy_s(channel.brMac, sizeof(channel.brMac), "F0:FA:C7:13:56:BC", strlen("F0:FA:C7:13:56:BC"));
    EXPECT_EQ(EOK, ret);
    onOpenSuccess(g_validRequestId, &channel);
    ret = GetChannelInfo(VALID_BR_MAC, DEFAULT_INVALID_CHANNEL_ID, DEFAULT_INVALID_REQ_ID, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = strcmp(info.channel->brMac, "F0:FA:C7:13:56:BC");
    EXPECT_EQ(EOK, ret);
    ret = ServerDeleteChannelFromList(g_validChannelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(BrProxyTest, BrProxyTest0015, TestSize.Level1)
{
    ServerBrProxyChannelInfo info;
    int32_t ret = ServerAddChannelToList(&g_channelInfo, g_validChannelId, g_validRequestId,
        g_testPid, g_testCallTokenId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<BrProxyInterfaceMock> BrProxyMock;
    EXPECT_CALL(BrProxyMock, ClientIpcBrProxyOpened).WillRepeatedly(Return(SOFTBUS_OK));
    onOpenFail(g_invalidRequestId, 0);
    ret = GetChannelInfo(NULL, g_validChannelId, DEFAULT_INVALID_REQ_ID, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    onOpenFail(g_validRequestId, 0);
    ret = GetChannelInfo(NULL, g_validChannelId, DEFAULT_INVALID_REQ_ID, &info);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = ServerDeleteChannelFromList(g_validChannelId);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}

HWTEST_F(BrProxyTest, BrProxyTest0016, TestSize.Level1)
{
    int32_t ret =LooperInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ConnServerInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ServerBrProxyChannelInfo info;
    TransOpenBrProxy(g_testCallTokenId, g_testPid, VALID_BR_MAC, TEST_UUID, g_testPri);
    ret = GetChannelInfo(VALID_BR_MAC, DEFAULT_INVALID_CHANNEL_ID, DEFAULT_INVALID_REQ_ID, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ServerDeleteChannelFromList(info.channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ConnServerDeinit();
    LooperDeinit();
}

HWTEST_F(BrProxyTest, BrProxyTest0017, TestSize.Level1)
{
    int32_t ret =LooperInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ConnServerInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ServerBrProxyChannelInfo info;
    TransOpenBrProxy(g_testCallTokenId, g_testPid, VALID_BR_MAC, TEST_UUID, g_testPri);
    ret = GetChannelInfo(VALID_BR_MAC, DEFAULT_INVALID_CHANNEL_ID, DEFAULT_INVALID_REQ_ID, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransCloseBrProxy(info.channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ConnServerDeinit();
    LooperDeinit();
}

HWTEST_F(BrProxyTest, BrProxyTest0018, TestSize.Level1)
{
    int32_t ret =LooperInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ConnServerInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransOpenBrProxy(g_testCallTokenId, g_testPid, VALID_BR_MAC, TEST_UUID, g_testPri);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ServerBrProxyChannelInfo info;
    ret = GetChannelInfo(VALID_BR_MAC, DEFAULT_INVALID_CHANNEL_ID, DEFAULT_INVALID_REQ_ID, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SetListenerStateByChannelId(info.channelId + 1, DATA_RECEIVE, true);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = SetListenerStateByChannelId(info.channelId, DATA_RECEIVE, true);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SetListenerStateByChannelId(info.channelId, CHANNEL_STATE, true);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ConnServerDeinit();
    LooperDeinit();
}

HWTEST_F(BrProxyTest, BrProxyTest0019, TestSize.Level1)
{
    int32_t ret =LooperInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ConnServerInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransOpenBrProxy(g_testCallTokenId, g_testPid, VALID_BR_MAC, TEST_UUID, 2);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ServerBrProxyChannelInfo info_lowpri;
    ret = GetChannelInfo(VALID_BR_MAC, DEFAULT_INVALID_CHANNEL_ID, DEFAULT_INVALID_REQ_ID, &info_lowpri);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SetListenerStateByChannelId(info_lowpri.channelId, DATA_RECEIVE, true);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SetListenerStateByChannelId(info_lowpri.channelId, CHANNEL_STATE, true);
    pid_t pid;
    int32_t pri;
    int32_t channelId;
    ret = SelectClient(VALID_BR_MAC, &pid, &pri, &channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(true, channelId == info_lowpri.channelId);
    printf("%d\n", channelId);
    ret = TransOpenBrProxy(g_testCallTokenId, g_testPid, VALID_BR_MAC, TEST_UUID, g_testPri);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ServerBrProxyChannelInfo info_highpri;
    ret = GetChannelInfo(VALID_BR_MAC, DEFAULT_INVALID_CHANNEL_ID, DEFAULT_INVALID_REQ_ID, &info_highpri);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SetListenerStateByChannelId(info_highpri.channelId, DATA_RECEIVE, true);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SetListenerStateByChannelId(info_highpri.channelId, CHANNEL_STATE, true);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SelectClient(VALID_BR_MAC, &pid, &pri, &channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(true, channelId == info_highpri.channelId);
    printf("%d\n", channelId);
    ConnServerDeinit();
    LooperDeinit();
}

}