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

#include "gtest/gtest.h"
#include <securec.h>

#include "softbus_adapter_mem.h"
#include "softbus_app_info.h"
#include "trans_channel_callback.h"
#include "trans_udp_negotiation.c"

using namespace testing::ext;

namespace OHOS {
#define TEST_RET 2
#define TEST_AUTH_ID 1
#define TEST_CHANNEL_ID 100
#define TEST_PID 10
#define TEST_SEQ 100
#define TEST_SIZE 64
#define TEST_TYPE 10

static IServerChannelCallBack g_testchannelCallBack;

class TransUdpStaticTest : public testing::Test {
public:
    TransUdpStaticTest()
    {}
    ~TransUdpStaticTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransUdpStaticTest::SetUpTestCase(void) { }

void TransUdpStaticTest::TearDownTestCase(void) { }

static int32_t TransServerOnChannelClosed(
    const char *pkgName, int32_t pid, int32_t channelId, int32_t channelType, int32_t messageType)
{
    return SOFTBUS_OK;
}

IServerChannelCallBack *TestTransServerGetChannelCb(void)
{
    g_testchannelCallBack.OnChannelClosed = TransServerOnChannelClosed;
    return &g_testchannelCallBack;
}

/**
 * @tc.name: TransUdpStaticTest001
 * @tc.desc: NotifyUdpChannelBind test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticTest, TransUdpStaticTest001, TestSize.Level1)
{
    AppInfo *info = nullptr;
    int32_t ret = NotifyUdpChannelBind(info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = NotifyUdpChannelClosed(info, TEST_TYPE);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    IServerChannelCallBack *cb = TransServerGetChannelCb();
    ret = TransUdpChannelInit(cb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_NE(nullptr, info);
    (void)strcpy_s(info->myData.pkgName, sizeof(info->myData.pkgName), "IShare");
    info->myData.pid = TEST_PID;
    info->myData.channelId = TEST_CHANNEL_ID;
    ret = NotifyUdpChannelBind(info);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_REMOTE_NULL, ret);
    SoftBusFree(info);
    TransUdpChannelDeinit();
}

/**
 * @tc.name: TransUdpStaticTest002
 * @tc.desc: ProcessUdpChannelState test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticTest, TransUdpStaticTest002, TestSize.Level1)
{
    IServerChannelCallBack *cb = TestTransServerGetChannelCb();
    int32_t ret = TransUdpChannelInit(cb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_NE(nullptr, appInfo);
    appInfo->streamType = COMMON_AUDIO_STREAM;
    appInfo->myData.pid = TEST_PID;
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_CLOSE;
    AuthHandle authHandle = { .authId = 1, .type = AUTH_LINK_TYPE_WIFI };
    int64_t seq = 1;
    ret = ProcessUdpChannelState(appInfo, true, &authHandle, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransUdpChannelDeinit();
}

/**
 * @tc.name: TransUdpStaticTest003
 * @tc.desc: CloseUdpChannel test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticTest, TransUdpStaticTest003, TestSize.Level1)
{
    IServerChannelCallBack *cb = TestTransServerGetChannelCb();
    int32_t ret = TransUdpChannelInit(cb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_NE(nullptr, appInfo);
    appInfo->myData.channelId = TEST_CHANNEL_ID;
    ret = CloseUdpChannel(appInfo, false);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(appInfo);
    TransUdpChannelDeinit();
}

/**
 * @tc.name: TransUdpStaticTest004
 * @tc.desc: TransSetUdpConnectTypeByAuthType test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticTest, TransUdpStaticTest004, TestSize.Level1)
{
    int32_t connectType = 0;
    AuthHandle authHandle;
    authHandle.type = AUTH_LINK_TYPE_P2P;
    TransSetUdpConnectTypeByAuthType(&connectType, authHandle);
    EXPECT_EQ(CONNECT_P2P, connectType);

    authHandle.type = AUTH_LINK_TYPE_ENHANCED_P2P;
    TransSetUdpConnectTypeByAuthType(&connectType, authHandle);
    EXPECT_EQ(CONNECT_HML, connectType);

    authHandle.type = AUTH_LINK_TYPE_MAX;
    TransSetUdpConnectTypeByAuthType(&connectType, authHandle);
    EXPECT_EQ(CONNECT_HML, connectType);
}

/**
 * @tc.name: TransUdpStaticTest005
 * @tc.desc: CheckAuthConnStatus test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticTest, TransUdpStaticTest005, TestSize.Level1)
{
    TransUdpChannelMgrInit();
    uint32_t requestId = 0;
    int32_t ret = CheckAuthConnStatus(requestId);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);

    UdpChannelInfo *channel = (UdpChannelInfo *)SoftBusCalloc(sizeof(UdpChannelInfo));
    ASSERT_NE(nullptr, channel);
    channel->seq = TEST_SEQ;
    ret = TransAddUdpChannel(channel);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = CheckAuthConnStatus(requestId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransDelUdpChannel(channel->info.myData.channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransUdpChannelMgrDeinit();
}

/**
 * @tc.name: TransUdpStaticTest006
 * @tc.desc: UpdOpenAuthConn test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticTest, TransUdpStaticTest006, TestSize.Level1)
{
    const char *peerUdid = "1234"; // test value
    uint32_t requestId = TEST_SEQ;
    bool isMeta = true;
    int32_t linkType = LANE_P2P_REUSE;
    int32_t ret = UdpOpenAuthConn(peerUdid, requestId, isMeta, linkType);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransUdpStaticTest007
 * @tc.desc: ReportUdpRequestHandShakeReplyEvent test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticTest, TransUdpStaticTest007, TestSize.Level1)
{
    AppInfo info;
    (void)memset_s(&info, sizeof(AppInfo), 0, sizeof(AppInfo));
    info.udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;

    TransEventExtra extra;
    (void)memset_s(&extra, sizeof(TransEventExtra), 0, sizeof(TransEventExtra));
    extra.socketName = "iShare";
    int32_t result = EVENT_STAGE_RESULT_OK;
    int32_t errCode = SOFTBUS_OK;

    ReportUdpRequestHandShakeReplyEvent(&info, &extra, result, errCode);
    EXPECT_EQ(result, extra.result);
    EXPECT_EQ(errCode, extra.errcode);
}

/**
 * @tc.name: TransUdpStaticTest008
 * @tc.desc: ReportUdpRequestHandShakeStartEvent test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticTest, TransUdpStaticTest008, TestSize.Level1)
{
    AppInfo *info = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_NE(nullptr, info);
    info->peerData.channelId = TEST_CHANNEL_ID;
    info->udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;

    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    TransEventExtra extra;
    (void)memset_s(&extra, sizeof(TransEventExtra), 0, sizeof(TransEventExtra));

    int64_t authId = TEST_AUTH_ID;
    ReportUdpRequestHandShakeStartEvent(info, &nodeInfo, &extra, authId);
    EXPECT_EQ(extra.peerChannelId, info->peerData.channelId);
    EXPECT_EQ(extra.result, EVENT_STAGE_RESULT_OK);

    info->udpChannelOptType = TYPE_UDP_CHANNEL_CLOSE;
    (void)memset_s(&extra, sizeof(TransEventExtra), 0, sizeof(TransEventExtra));
    ReportUdpRequestHandShakeStartEvent(info, &nodeInfo, &extra, authId);
    EXPECT_NE(extra.result, EVENT_STAGE_RESULT_OK);

    SoftBusFree(info);
    info = nullptr;
}

/**
 * @tc.name: TransUdpStaticTest009
 * @tc.desc: CopyAppInfoFastTransData test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticTest, TransUdpStaticTest009, TestSize.Level1)
{
    AppInfo *appInfo = static_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_NE(nullptr, appInfo);
    appInfo->fastTransDataSize = TEST_SIZE;

    UdpChannelInfo *newChannel = static_cast<UdpChannelInfo *>(SoftBusCalloc(sizeof(UdpChannelInfo)));
    ASSERT_NE(nullptr, newChannel);

    int32_t ret = CopyAppInfoFastTransData(newChannel, appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(appInfo);
    SoftBusFree(newChannel);
    newChannel = nullptr;
}

/**
 * @tc.name: TransUdpStaticTest010
 * @tc.desc: CopyAppInfoFastTransData test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticTest, TransUdpStaticTest010, TestSize.Level1)
{
    g_seq = INT64_MAX;
    GenerateSeq(true);
    EXPECT_EQ(TEST_RET, g_seq);
}
}
