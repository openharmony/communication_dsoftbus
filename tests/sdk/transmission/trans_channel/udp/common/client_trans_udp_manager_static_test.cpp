/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include "securec.h"
#include <gtest/gtest.h>

#include "client_trans_channel_manager.h"
#include "client_trans_session_callback.h"
#include "client_trans_udp_manager.c"
#include "session.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "trans_udp_channel_manager.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
#define TEST_CHANNELID   1030
#define TEST_SESSIONID   1
#define ERR_CHANNELID    (-1)
#define TEST_COUNT       2
#define TEST_ERRCODE     426442703
#define TEST_CHANNELTYPE 2
#define TEST_CLOSEID     1088

class ClientTransUdpManagerStaticTest : public testing::Test {
public:
    ClientTransUdpManagerStaticTest(void) { }
    ~ClientTransUdpManagerStaticTest(void) { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override { }
    void TearDown(void) override { }
};

void ClientTransUdpManagerStaticTest::SetUpTestCase(void) { }

void ClientTransUdpManagerStaticTest::TearDownTestCase(void) { }

/*
 * @tc.name: ClientTransUdpMgrInitTest001
 * @tc.desc: client trans udp mgr init with null callback returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, ClientTransUdpMgrInitTest001, TestSize.Level1)
{
    ClientTransUdpMgrDeinit();
    g_sessionCb = nullptr;
    int32_t ret = ClientTransUdpMgrInit(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ClientTransUdpMgrDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: ClientTransUdpMgrInitTest002
 * @tc.desc: client trans udp mgr init with valid callback returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, ClientTransUdpMgrInitTest002, TestSize.Level1)
{
    ClientTransUdpMgrDeinit();
    g_sessionCb = nullptr;
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientTransUdpMgrDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: TransOnUdpChannelBindTest001
 * @tc.desc: trans on udp channel bind without init returns no init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, TransOnUdpChannelBindTest001, TestSize.Level1)
{
    ClientTransUdpMgrDeinit();
    g_sessionCb = nullptr;
    int32_t ret = TransOnUdpChannelBind(TEST_CHANNELID, TEST_CHANNELTYPE);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    ClientTransUdpMgrDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: OnIdleTimeoutResetTest001
 * @tc.desc: on idle timeout reset without init returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, OnIdleTimeoutResetTest001, TestSize.Level1)
{
    ClientTransUdpMgrDeinit();
    g_sessionCb = nullptr;
    int32_t ret = OnIdleTimeoutReset(TEST_CHANNELID);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ClientTransUdpMgrDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: OnIdleTimeoutResetTest002
 * @tc.desc: on idle timeout reset after init returns session server noinit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, OnIdleTimeoutResetTest002, TestSize.Level1)
{
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    ret = OnIdleTimeoutReset(TEST_CHANNELID);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: OnRawStreamEncryptOptGetTest001
 * @tc.desc: on raw stream encrypt opt get without init returns no init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, OnRawStreamEncryptOptGetTest001, TestSize.Level1)
{
    ClientTransUdpMgrDeinit();
    g_sessionCb = nullptr;
    int32_t channelId = TEST_CHANNELID;
    int32_t sessionId = TEST_SESSIONID;
    bool encrypt = true;
    int32_t ret = OnRawStreamEncryptOptGet(sessionId, channelId, &encrypt);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    ClientTransUdpMgrDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: OnRawStreamEncryptOptGetTest002
 * @tc.desc: on raw stream encrypt opt get with null encrypt param returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, OnRawStreamEncryptOptGetTest002, TestSize.Level1)
{
    ClientTransUdpMgrDeinit();
    g_sessionCb = nullptr;
    int32_t channelId = TEST_CHANNELID;
    int32_t sessionId = TEST_SESSIONID;
    int32_t ret = OnRawStreamEncryptOptGet(sessionId, channelId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ClientTransUdpMgrDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: OnRawStreamEncryptOptGetTest003
 * @tc.desc: on raw stream encrypt opt get with invalid channel id returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, OnRawStreamEncryptOptGetTest003, TestSize.Level1)
{
    ClientTransUdpMgrDeinit();
    g_sessionCb = nullptr;
    int32_t channelId = ERR_CHANNELID;
    int32_t sessionId = TEST_SESSIONID;
    bool encrypt = true;
    int32_t ret = OnRawStreamEncryptOptGet(sessionId, channelId, &encrypt);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ClientTransUdpMgrDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: OnRawStreamEncryptOptGetTest004
 * @tc.desc: on raw stream encrypt opt get with channel not found returns udp channel not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, OnRawStreamEncryptOptGetTest004, TestSize.Level1)
{
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    int32_t channelId = TEST_CHANNELID;
    int32_t sessionId = TEST_SESSIONID;
    bool encrypt = true;
    ret = OnRawStreamEncryptOptGet(sessionId, channelId, &encrypt);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND, ret);
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: OnRawStreamEncryptOptGetTest005
 * @tc.desc: on raw stream encrypt opt get with isServer true channel returns session server noinit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, OnRawStreamEncryptOptGetTest005, TestSize.Level1)
{
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    UdpChannel *udpChannel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_TRUE(udpChannel != nullptr);
    udpChannel->channelId = TEST_CHANNELID;
    udpChannel->info.isServer = true;
    ret = ClientTransAddUdpChannel(udpChannel);
    ASSERT_EQ(SOFTBUS_OK, ret);
    int32_t channelId = TEST_CHANNELID;
    int32_t sessionId = TEST_SESSIONID;
    bool encrypt = true;
    ret = OnRawStreamEncryptOptGet(sessionId, channelId, &encrypt);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
    (void)TransDeleteUdpChannel(udpChannel->channelId);
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: OnFileGetSessionIdTest001
 * @tc.desc: on file get session id without init returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, OnFileGetSessionIdTest001, TestSize.Level1)
{
    ClientTransUdpMgrDeinit();
    g_sessionCb = nullptr;
    int32_t sessionId = 0;
    int32_t ret = OnFileGetSessionId(TEST_CHANNELID, &sessionId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ClientTransUdpMgrDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: OnFileGetSessionIdTest002
 * @tc.desc: on file get session id after init without channel returns session server noinit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, OnFileGetSessionIdTest002, TestSize.Level1)
{
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    int32_t sessionId = 0;
    ret = OnFileGetSessionId(TEST_CHANNELID, &sessionId);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: TransSetUdpChannelEnableTest001
 * @tc.desc: trans set udp channel enable without init returns no init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, TransSetUdpChannelEnableTest001, TestSize.Level1)
{
    ClientTransUdpMgrDeinit();
    g_sessionCb = nullptr;
    int32_t ret = TransSetUdpChannelEnable(TEST_CHANNELID, false);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    ClientTransUdpMgrDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: TransSetUdpChannelEnableTest002
 * @tc.desc: trans set udp channel enable with valid channel id returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, TransSetUdpChannelEnableTest002, TestSize.Level1)
{
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    UdpChannel *udpChannel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_TRUE(udpChannel != nullptr);
    udpChannel->channelId = TEST_CHANNELID;
    udpChannel->businessType = BUSINESS_TYPE_FILE;
    ret = ClientTransAddUdpChannel(udpChannel);
    ASSERT_EQ(SOFTBUS_OK, ret);
    ret = TransSetUdpChannelEnable(TEST_CHANNELID, false);
    EXPECT_EQ(SOFTBUS_OK, ret);
    (void)TransDeleteUdpChannel(udpChannel->channelId);
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: TransSetUdpChannelEnableTest003
 * @tc.desc: trans set udp channel enable with channel not found returns udp channel not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, TransSetUdpChannelEnableTest003, TestSize.Level1)
{
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    ret = TransSetUdpChannelEnable(ERR_CHANNELID, false);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND, ret);
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: TransDeleteUdpChannelTest001
 * @tc.desc: trans delete udp channel without init returns no init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, TransDeleteUdpChannelTest001, TestSize.Level1)
{
    ClientTransUdpMgrDeinit();
    g_sessionCb = nullptr;
    int32_t ret = TransDeleteUdpChannel(TEST_CHANNELID);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    ClientTransUdpMgrDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: TransGetUdpChannelTest001
 * @tc.desc: trans get udp channel without init returns no init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, TransGetUdpChannelTest001, TestSize.Level1)
{
    ClientTransUdpMgrDeinit();
    g_sessionCb = nullptr;
    UdpChannel channel = { };
    int32_t ret = TransGetUdpChannel(TEST_CHANNELID, &channel);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    ClientTransUdpMgrDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: TransGetUdpChannelTest002
 * @tc.desc: trans get udp channel with null param returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, TransGetUdpChannelTest002, TestSize.Level1)
{
    ClientTransUdpMgrDeinit();
    g_sessionCb = nullptr;
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    ASSERT_EQ(SOFTBUS_OK, ret);
    ret = TransGetUdpChannel(TEST_CHANNELID, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ClientTransUdpMgrDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: TransGetUdpChannelTest003
 * @tc.desc: trans get udp channel with channel found returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, TransGetUdpChannelTest003, TestSize.Level1)
{
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    UdpChannel *udpChannel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_TRUE(udpChannel != nullptr);
    udpChannel->channelId = TEST_CHANNELID;
    udpChannel->businessType = BUSINESS_TYPE_FILE;
    ret = ClientTransAddUdpChannel(udpChannel);
    ASSERT_EQ(SOFTBUS_OK, ret);
    UdpChannel channel = { };
    ret = TransGetUdpChannel(TEST_CHANNELID, &channel);
    EXPECT_EQ(SOFTBUS_OK, ret);
    (void)TransDeleteUdpChannel(udpChannel->channelId);
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: TransSetdFileIdByChannelIdTest001
 * @tc.desc: trans set dfile id by channel id without init returns no init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, TransSetdFileIdByChannelIdTest001, TestSize.Level1)
{
    ClientTransUdpMgrDeinit();
    g_sessionCb = nullptr;
    int32_t ret = TransSetdFileIdByChannelId(TEST_CHANNELID, TEST_COUNT);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    ClientTransUdpMgrDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: TransSetdFileIdByChannelIdTest002
 * @tc.desc: trans set dfile id by channel id with channel not found returns udp channel not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, TransSetdFileIdByChannelIdTest002, TestSize.Level1)
{
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    ret = TransSetdFileIdByChannelId(TEST_CHANNELID, TEST_COUNT);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND, ret);
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: TransSetdFileIdByChannelIdTest003
 * @tc.desc: trans set dfile id by channel id with channel found returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, TransSetdFileIdByChannelIdTest003, TestSize.Level1)
{
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    UdpChannel *udpChannel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_TRUE(udpChannel != nullptr);
    udpChannel->channelId = TEST_CHANNELID;
    ret = ClientTransAddUdpChannel(udpChannel);
    ASSERT_EQ(SOFTBUS_OK, ret);
    ret = TransSetdFileIdByChannelId(TEST_CHANNELID, TEST_COUNT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    (void)TransDeleteUdpChannel(udpChannel->channelId);
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: OnUdpChannelOpenedTest001
 * @tc.desc: on udp channel opened without init returns get channel failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, OnUdpChannelOpenedTest001, TestSize.Level1)
{
    ClientTransUdpMgrDeinit();
    g_sessionCb = nullptr;
    int32_t ret = OnUdpChannelOpened(TEST_CHANNELID, nullptr);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);
    ClientTransUdpMgrDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: ClosePeerUdpChannelTest001
 * @tc.desc: close peer udp channel returns access token denied
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, ClosePeerUdpChannelTest001, TestSize.Level1)
{
    ClientTransUdpMgrDeinit();
    g_sessionCb = nullptr;
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    ASSERT_EQ(SOFTBUS_OK, ret);
    ret = ClosePeerUdpChannel(TEST_CHANNELID);
    EXPECT_EQ(SOFTBUS_ACCESS_TOKEN_DENIED, ret);
    ClientTransUdpMgrDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: ClientTransAddUdpChannelTest001
 * @tc.desc: client trans add udp channel with null param returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, ClientTransAddUdpChannelTest001, TestSize.Level1)
{
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    ret = ClientTransAddUdpChannel(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: ClientTransAddUdpChannelTest002
 * @tc.desc: client trans add udp channel valid add returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, ClientTransAddUdpChannelTest002, TestSize.Level1)
{
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    UdpChannel *udpChannel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_TRUE(udpChannel != nullptr);
    udpChannel->channelId = TEST_CHANNELID;
    udpChannel->businessType = BUSINESS_TYPE_FILE;
    ret = ClientTransAddUdpChannel(udpChannel);
    EXPECT_EQ(SOFTBUS_OK, ret);
    (void)TransDeleteUdpChannel(udpChannel->channelId);
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: ClientTransAddUdpChannelTest003
 * @tc.desc: client trans add udp channel duplicate add returns channel already exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, ClientTransAddUdpChannelTest003, TestSize.Level1)
{
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    UdpChannel *udpChannel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_TRUE(udpChannel != nullptr);
    udpChannel->channelId = TEST_CHANNELID;
    udpChannel->businessType = BUSINESS_TYPE_FILE;
    ret = ClientTransAddUdpChannel(udpChannel);
    ASSERT_EQ(SOFTBUS_OK, ret);
    ret = ClientTransAddUdpChannel(udpChannel);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_ALREADY_EXIST, ret);
    (void)TransDeleteUdpChannel(udpChannel->channelId);
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: TransDeleteBusinnessChannelTest001
 * @tc.desc: trans delete business channel with stream type returns close udp channel failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, TransDeleteBusinnessChannelTest001, TestSize.Level1)
{
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    UdpChannel channel = { };
    channel.businessType = BUSINESS_TYPE_STREAM;
    channel.channelId = ERR_CHANNELID;
    ret = TransDeleteBusinnessChannel(&channel);
    EXPECT_EQ(SOFTBUS_TRANS_CLOSE_UDP_CHANNEL_FAILED, ret);
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: TransDeleteBusinnessChannelTest002
 * @tc.desc: trans delete business channel with file type returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, TransDeleteBusinnessChannelTest002, TestSize.Level1)
{
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    UdpChannel channel = { };
    channel.businessType = BUSINESS_TYPE_FILE;
    channel.channelId = TEST_CHANNELID;
    channel.dfileId = TEST_CHANNELID;
    ret = TransDeleteBusinnessChannel(&channel);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: TransDeleteBusinnessChannelTest003
 * @tc.desc: trans delete business channel with unknown type returns business type not match
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, TransDeleteBusinnessChannelTest003, TestSize.Level1)
{
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    UdpChannel channel = { };
    channel.businessType = TEST_CHANNELID;
    ret = TransDeleteBusinnessChannel(&channel);
    EXPECT_EQ(SOFTBUS_TRANS_BUSINESS_TYPE_NOT_MATCH, ret);
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: TransOnUdpChannelOpenFailedTest001
 * @tc.desc: trans on udp channel open failed after init without channel returns session server noinit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, TransOnUdpChannelOpenFailedTest001, TestSize.Level1)
{
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    ret = TransOnUdpChannelOpenFailed(TEST_CHANNELID, TEST_ERRCODE);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: CloseUdpChannelProcTest001
 * @tc.desc: close udp channel proc with shutdown reason peer returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, CloseUdpChannelProcTest001, TestSize.Level1)
{
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    UdpChannel udpChannel = { };
    udpChannel.businessType = BUSINESS_TYPE_FILE;
    ret = CloseUdpChannelProc(&udpChannel, TEST_CLOSEID, SHUTDOWN_REASON_PEER);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: CloseUdpChannelProcTest002
 * @tc.desc: close udp channel proc with shutdown reason send file err returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, CloseUdpChannelProcTest002, TestSize.Level1)
{
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    UdpChannel udpChannel = { };
    udpChannel.businessType = BUSINESS_TYPE_FILE;
    ret = CloseUdpChannelProc(&udpChannel, TEST_CLOSEID, SHUTDOWN_REASON_SEND_FILE_ERR);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: CloseUdpChannelProcTest003
 * @tc.desc: close udp channel proc with shutdown reason local returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, CloseUdpChannelProcTest003, TestSize.Level1)
{
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    UdpChannel udpChannel = { };
    udpChannel.businessType = BUSINESS_TYPE_FILE;
    ret = CloseUdpChannelProc(&udpChannel, TEST_CLOSEID, SHUTDOWN_REASON_LOCAL);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: CloseUdpChannelProcTest004
 * @tc.desc: close udp channel proc with null channel returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, CloseUdpChannelProcTest004, TestSize.Level1)
{
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    ret = CloseUdpChannelProc(nullptr, TEST_CLOSEID, SHUTDOWN_REASON_PEER);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: CloseUdpChannelTest001
 * @tc.desc: close udp channel without channel returns udp get channel failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, CloseUdpChannelTest001, TestSize.Level1)
{
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    ret = CloseUdpChannel(TEST_CLOSEID, SHUTDOWN_REASON_PEER);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: TransUdpChannelSetStreamMultiLayerTest001
 * @tc.desc: trans udp channel set stream multi layer with disabled channel returns udp channel disable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, TransUdpChannelSetStreamMultiLayerTest001, TestSize.Level1)
{
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    UdpChannel *udpChannel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_TRUE(udpChannel != nullptr);
    udpChannel->channelId = TEST_CHANNELID;
    udpChannel->isEnable = false;
    ret = ClientTransAddUdpChannel(udpChannel);
    ASSERT_EQ(SOFTBUS_OK, ret);
    ret = TransUdpChannelSetStreamMultiLayer(TEST_CHANNELID, nullptr);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_DISABLE, ret);
    (void)TransDeleteUdpChannel(udpChannel->channelId);
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: TransUdpChannelSetStreamMultiLayerTest002
 * @tc.desc: trans udp channel set stream multi layer with enabled channel and null opt value returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, TransUdpChannelSetStreamMultiLayerTest002, TestSize.Level1)
{
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    UdpChannel *udpChannel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_TRUE(udpChannel != nullptr);
    udpChannel->channelId = TEST_CHANNELID;
    udpChannel->isEnable = true;
    ret = ClientTransAddUdpChannel(udpChannel);
    ASSERT_EQ(SOFTBUS_OK, ret);
    ret = TransUdpChannelSetStreamMultiLayer(TEST_CHANNELID, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    (void)TransDeleteUdpChannel(udpChannel->channelId);
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: TransSendLimitChangeDataToCoreTest001
 * @tc.desc: trans send limit change data to core returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, TransSendLimitChangeDataToCoreTest001, TestSize.Level1)
{
    int32_t ret = TransSendLimitChangeDataToCore(TEST_CHANNELID, FILE_PRIORITY_BK, NSTACKX_EOK);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransCheckIsSecondPathTest001
 * @tc.desc: trans check is second path with channel not found returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, TransCheckIsSecondPathTest001, TestSize.Level1)
{
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    int32_t routeType = -1;
    bool isSecondPath = TransCheckIsSecondPath(TEST_CHANNELID, &routeType);
    EXPECT_FALSE(isSecondPath);
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: TransCheckIsSecondPathTest002
 * @tc.desc: trans check is second path with reserve channel returns true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, TransCheckIsSecondPathTest002, TestSize.Level1)
{
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    UdpChannel *udpChannel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_TRUE(udpChannel != nullptr);
    udpChannel->channelId = TEST_CHANNELID;
    udpChannel->routeType = WIFI_USB;
    udpChannel->isReserveChannel = true;
    ret = ClientTransAddUdpChannel(udpChannel);
    ASSERT_EQ(SOFTBUS_OK, ret);
    int32_t routeType = -1;
    bool isSecondPath = TransCheckIsSecondPath(TEST_CHANNELID, &routeType);
    EXPECT_TRUE(isSecondPath);
    EXPECT_EQ(WIFI_USB, routeType);
    (void)TransDeleteUdpChannel(udpChannel->channelId);
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: TransAddSecondPathFailTest001
 * @tc.desc: trans add second path fail with invalid channel id returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, TransAddSecondPathFailTest001, TestSize.Level1)
{
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    ret = TransAddSecondPathFail(INVALID_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: TransAddSecondPathFailTest002
 * @tc.desc: trans add second path fail with reserve channel returns access token denied
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, TransAddSecondPathFailTest002, TestSize.Level1)
{
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    UdpChannel *udpChannel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_TRUE(udpChannel != nullptr);
    udpChannel->channelId = TEST_CHANNELID;
    udpChannel->isReserveChannel = true;
    ret = ClientTransAddUdpChannel(udpChannel);
    ASSERT_EQ(SOFTBUS_OK, ret);
    ret = TransAddSecondPathFail(udpChannel->channelId);
    EXPECT_EQ(SOFTBUS_ACCESS_TOKEN_DENIED, ret);
    (void)TransDeleteUdpChannel(udpChannel->channelId);
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: GetChannelTypeByChannelIdTest001
 * @tc.desc: get channel type by channel id with channel not found returns udp channel not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, GetChannelTypeByChannelIdTest001, TestSize.Level1)
{
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    int32_t channelId = 1000;
    int32_t channelType = CHANNEL_TYPE_BUTT;
    ret = GetChannelTypeByChannelId(channelId, &channelType);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND, ret);
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
}

/*
 * @tc.name: GetChannelTypeByChannelIdTest002
 * @tc.desc: get channel type by channel id with null channel type param returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, GetChannelTypeByChannelIdTest002, TestSize.Level1)
{
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
    int32_t ret = ClientTransChannelInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    UdpChannel *channel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_TRUE(channel != nullptr);
    channel->channelId = 1;
    ret = ClientTransAddUdpChannel(channel);
    ASSERT_EQ(SOFTBUS_OK, ret);
    ret = GetChannelTypeByChannelId(channel->channelId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    (void)TransDeleteUdpChannel(channel->channelId);
    ClientTransChannelDeinit();
    g_sessionCb = nullptr;
}
} // namespace OHOS
