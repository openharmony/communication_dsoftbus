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

#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>

#include "br_proxy_common.h"
#include "br_proxy_ext_test_mock.h"
#include "br_proxy_server_manager.c"
#include "message_handler.h"
#include "nativetoken_kit.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "token_setproc.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
#define CHANNEL_ID 5
#define CHANNEL_ID_ERR 0
#define SESSION_ID 2
const char *bundleName = "testbundlename";

class BrProxyServerManagerExtTest : public testing::Test {
public:
    BrProxyServerManagerExtTest()
    {}
    ~BrProxyServerManagerExtTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void BrProxyServerManagerExtTest::SetUpTestCase(void)
{
}

void BrProxyServerManagerExtTest::TearDownTestCase(void)
{
}

/**
 * @tc.name: SetCurrentConnect001
 * @tc.desc: SetCurrentConnect001, when g_proxyList is nullptr should return SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerExtTest, SetCurrentConnect001, TestSize.Level1)
{
    const char *testBrMac = "testBrMac";
    const char *testUuid = "testUuid";
    int32_t appIndex = DEFAULT_APPINDEX;
    int32_t ret = SetCurrentConnect(testBrMac, testUuid, appIndex, true);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: BrProxyServerManagerExtTest000
 * @tc.desc: BrProxyServerManagerExtTest000, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerExtTest, BrProxyServerManagerExtTest000, TestSize.Level1)
{
    NiceMock<BrProxyExtInterfaceMock> brProxyExtMock;
    EXPECT_CALL(brProxyExtMock, CreateSoftBusList).WillRepeatedly(Return(nullptr));
    bool ret1 = IsBrProxy(bundleName);
    EXPECT_EQ(false, ret1);
    int32_t ret = GetServerListCount(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    int32_t count = 0;
    int32_t channelId = CHANNEL_ID;
    ret = GetServerListCount(&count);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
    ret = GetChannelIdFromServerList(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = GetChannelIdFromServerList(&channelId);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
    ret = CloseAllBrProxy();
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
    int32_t appIndex = DEFAULT_APPINDEX;
    CloseAllConnect();
    UserSwitchedHandler(nullptr);
    RegisterUserSwitchEvent();
    ret1 = PermissionCheckPass(nullptr);
    EXPECT_EQ(false, ret1);
    ret = GetNewChannelId(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = BrProxyServerInit();
    EXPECT_EQ(SOFTBUS_CREATE_LIST_ERR, ret);
    ret = ServerAddDataToList(nullptr, nullptr, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    uint32_t requeset = 1;
    ret = GetBrProxy(nullptr, nullptr, requeset, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = UpdateBrProxy(nullptr, appIndex, nullptr, false, channelId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    struct ProxyChannel channel = {0};
    ret = UpdateConnectState(nullptr, nullptr, &channel, true);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret1 = TryToUpdateBrProxy(nullptr, nullptr, nullptr);
    EXPECT_EQ(false, ret1);
    ret = GetCallerInfoAndVerifyPermission(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ServerAddProxyToList(nullptr, nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ServerDisableProxyFromList(0);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
    ret1 = IsSessionExist(nullptr, nullptr, 0, false);
    EXPECT_EQ(false, ret1);
    ret = ServerAddChannelToList(nullptr, nullptr, CHANNEL_ID, 0, appIndex);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: BrProxyServerManagerExtTest001
 * @tc.desc: BrProxyServerManagerExtTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerExtTest, BrProxyServerManagerExtTest001, TestSize.Level1)
{
    NiceMock<BrProxyExtInterfaceMock> brProxyExtMock;
    EXPECT_CALL(brProxyExtMock, CreateSoftBusList).WillRepeatedly(Return(nullptr));
    int32_t ret = ServerDeleteChannelFromList(CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
    ret = UpdateProxyChannel(nullptr, nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
    ret = GetChannelInfo(nullptr, nullptr, CHANNEL_ID, 0, nullptr);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
    onOpenSuccess(0, nullptr);
    ret = GetChannelId(nullptr, nullptr, nullptr, DEFAULT_APPINDEX);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransOpenBrProxy(nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransCloseBrProxy(CHANNEL_ID, false);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
    ret = TransSendBrProxyData(CHANNEL_ID, nullptr, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SetListenerStateByChannelId(CHANNEL_ID, CHANNEL_STATE, false);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
    ret = SelectClient(nullptr, nullptr, nullptr, 0);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
    GetDataFromList(nullptr, nullptr, nullptr, nullptr);
    bool ret1 = IsForegroundProcess(nullptr, 0);
    EXPECT_EQ(false, ret1);
    DealDataWhenForeground(nullptr, nullptr, 0, 0);
    DealWithDataRecv(nullptr, nullptr, 0, 0);
    OnDataReceived(nullptr, nullptr, 0);
    OnDisconnected(nullptr, 0);
    OnReconnected(nullptr, nullptr);
    SendDataIfExistsInList(CHANNEL_ID);
    TransSetListenerState(CHANNEL_ID, 0, false);
    ServerDeleteChannelByPid(0);
    BrProxyClientDeathClearResource(0);
    ret1 = CheckSessionExistByUid(0);
    EXPECT_EQ(false, ret1);
    ret = RetryListInit();
    EXPECT_EQ(SOFTBUS_CREATE_LIST_ERR, ret);
    ret1 = IsUidExist(0);
    EXPECT_EQ(false, ret1);
    ret = AddToRetryList(0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = GetCountFromRetryList(0, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ClearCountInRetryList(0);
    ret1 = TransIsProxyChannelEnabled(0);
    EXPECT_EQ(false, ret1);
    TransRegisterPushHook();
}

/**
 * @tc.name: OnDataReceivedTest001
 * @tc.desc: return when given invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerExtTest, OnDataReceivedTest001, TestSize.Level1)
{
    ProxyChannel *channel = reinterpret_cast<ProxyChannel *>(SoftBusCalloc(sizeof(ProxyChannel)));
    ASSERT_NE(channel, nullptr);
    uint8_t *data = reinterpret_cast<uint8_t *>(SoftBusCalloc(sizeof(ProxyChannel)));
    ASSERT_NE(data, nullptr);
    char *addr = reinterpret_cast<char *>(SoftBusCalloc(sizeof(ProxyChannel)));
    ASSERT_NE(addr, nullptr);
    uint32_t dataLen = 0;
    EXPECT_NO_FATAL_FAILURE(OnDataReceived(nullptr, nullptr, 0));
    EXPECT_NO_FATAL_FAILURE(OnDataReceived(channel, nullptr, 0));
    EXPECT_NO_FATAL_FAILURE(OnDataReceived(channel, data, 0));
    dataLen = BR_PROXY_SEND_MAX_LEN + 1;
    EXPECT_NO_FATAL_FAILURE(OnReconnected(addr, nullptr));
    EXPECT_NO_FATAL_FAILURE(OnDataReceived(channel, data, dataLen));
    SoftBusFree(channel);
    SoftBusFree(data);
    SoftBusFree(addr);
}

/**
 * @tc.name: SetCurrentConnect002
 * @tc.desc: SetCurrentConnect002, when given invalid param should return SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerExtTest, SetCurrentConnect002, TestSize.Level1)
{
    const char *testBrMac = "testBrMac";
    const char *testUuid = "testUuid";
    uint32_t requeset = 1;
    int32_t appIndex = DEFAULT_APPINDEX;
    PrintSession(testBrMac, testUuid);
    PrintSession(nullptr, testUuid);
    PrintSession(testBrMac, nullptr);
    int32_t ret = SetCurrentConnect(testBrMac, nullptr, appIndex, true);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SetCurrentConnect(nullptr, testUuid, appIndex, true);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SetCurrentConnect(testBrMac, testUuid, appIndex, true);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ConnectPeerDevice(testBrMac, testUuid, &requeset, appIndex);
    EXPECT_NE(SOFTBUS_OK, ret);
}
}