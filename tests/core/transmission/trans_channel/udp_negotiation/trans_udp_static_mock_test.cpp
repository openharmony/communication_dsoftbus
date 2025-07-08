/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include "trans_udp_nego_static_test_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
static int32_t DefaultOnChannelOpened(const char *, int32_t, const char *, const ChannelInfo *) {
    return SOFTBUS_OK;
}

static int32_t DefaultOnChannelClosed(const char *, int32_t, int32_t, int32_t, int32_t) {
    return SOFTBUS_OK;
}

static int32_t DefaultOnChannelOpenFailed(const char *, int32_t, int32_t, int32_t, int32_t) {
    return SOFTBUS_OK;
}

static int32_t DefaultOnDataReceived(const char *, int32_t, int32_t, int32_t, TransReceiveData *) {
    return SOFTBUS_OK;
}

static int32_t DefaultOnQosEvent(const char *, const QosParam *) {
    return SOFTBUS_OK;
}

static int32_t DefaultGetPkgNameBySessionName(const char *, char *, uint16_t) {
    return SOFTBUS_OK;
}

static int32_t DefaultGetUidAndPidBySessionName(const char *, int32_t *, int32_t *) {
    return SOFTBUS_OK;
}

static int32_t DefaultOnChannelBind(const char *, int32_t, int32_t, int32_t) {
    return SOFTBUS_OK;
}

IServerChannelCallBack g_callbacks = {
    .OnChannelOpened = DefaultOnChannelOpened,
    .OnChannelClosed = DefaultOnChannelClosed,
    .OnChannelOpenFailed = DefaultOnChannelOpenFailed,
    .OnDataReceived = DefaultOnDataReceived,
    .OnQosEvent = DefaultOnQosEvent,
    .GetPkgNameBySessionName = DefaultGetPkgNameBySessionName,
    .GetUidAndPidBySessionName = DefaultGetUidAndPidBySessionName,
    .OnChannelBind = DefaultOnChannelBind
};


class TransUdpStaticMockTest : public testing::Test {
public:
    TransUdpStaticMockTest()
    {}
    ~TransUdpStaticMockTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransUdpStaticMockTest::SetUpTestCase(void) { }

void TransUdpStaticMockTest::TearDownTestCase(void) { }


/**
 * @tc.name: AppendIpv6WithIfnameTest001
 * @tc.desc: use abnomal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticMockTest, AppendIpv6WithIfnameTest001, TestSize.Level1)
{
    int32_t ret = 0;
    char ip[] = "1234567890:1234567890:1234567890:1234567890:1234567890";
    int32_t ifIdx = 0;
    NiceMock<TransUdpNegoStaticInterfaceMock> TransUdpStaticMock;
    EXPECT_CALL(TransUdpStaticMock, LnnGetLocalStrInfoByIfnameIdx).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = AppendIpv6WithIfname(ip, ifIdx);
    EXPECT_EQ(SOFTBUS_NETWORK_GET_NODE_INFO_ERR, ret);

    EXPECT_CALL(TransUdpStaticMock, LnnGetLocalStrInfoByIfnameIdx).WillOnce(Return(SOFTBUS_OK));
    ret = AppendIpv6WithIfname(ip, ifIdx);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    char newIp[] = "192.168.1,1";
    EXPECT_CALL(TransUdpStaticMock, LnnGetLocalStrInfoByIfnameIdx).WillOnce(Return(SOFTBUS_OK));
    ret = AppendIpv6WithIfname(newIp, ifIdx);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SetChannelInfoBySideTest001
 * @tc.desc: use abnomal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticMockTest, SetChannelInfoBySideTest001, TestSize.Level1)
{
    int32_t ret = 0;
    ChannelInfo *info = reinterpret_cast<ChannelInfo*>(SoftBusCalloc(sizeof(ChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    bool isServerSide = false;
    AppInfo *appInfo = reinterpret_cast<AppInfo*>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(info != nullptr);

    ret = SetChannelInfoBySide(NULL, isServerSide, appInfo);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    ret = SetChannelInfoBySide(info, isServerSide, NULL);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    SoftBusFree(info);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: SetChannelInfoBySideTest002
 * @tc.desc: use nomal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticMockTest, SetChannelInfoBySideTest002, TestSize.Level1)
{
    int32_t ret = 0;
    ChannelInfo *info = reinterpret_cast<ChannelInfo*>(SoftBusCalloc(sizeof(ChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    bool isServerSide = false;
    AppInfo *appInfo = reinterpret_cast<AppInfo*>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(info != nullptr);
    char ip[] = "192.168.1,1";

    NiceMock<TransUdpNegoStaticInterfaceMock> TransUdpStaticMock;
    EXPECT_CALL(TransUdpStaticMock, LnnGetLocalStrInfoByIfnameIdx).WillRepeatedly(Return(SOFTBUS_ERR));

    appInfo->udpConnType = UDP_CONN_TYPE_USB;
    appInfo->routeType = WIFI_USB;
    strcpy_s(info->peerIp, sizeof(info->peerIp), ip);
    ret = SetChannelInfoBySide(info, isServerSide, appInfo);
    EXPECT_EQ(SOFTBUS_NETWORK_GET_NODE_INFO_ERR, ret);

    appInfo->udpConnType = UDP_CONN_TYPE_WIFI;
    appInfo->routeType = WIFI_USB;
    ret = SetChannelInfoBySide(info, isServerSide, appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    appInfo->udpConnType = UDP_CONN_TYPE_USB;
    appInfo->routeType = WIFI_P2P;
    ret = SetChannelInfoBySide(info, isServerSide, appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SoftBusFree(info);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: SetChannelInfoBySideTest003
 * @tc.desc: use nomal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticMockTest, SetChannelInfoBySideTest003, TestSize.Level1)
{
    int32_t ret = 0;
    ChannelInfo *info = reinterpret_cast<ChannelInfo*>(SoftBusCalloc(sizeof(ChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    bool isServerSide = true;
    AppInfo *appInfo = reinterpret_cast<AppInfo*>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(info != nullptr);
    char ip[] = "192.168.1,1";

    NiceMock<TransUdpNegoStaticInterfaceMock> TransUdpStaticMock;
    EXPECT_CALL(TransUdpStaticMock, LnnGetLocalStrInfoByIfnameIdx).WillRepeatedly(Return(SOFTBUS_ERR));

    appInfo->myData.tokenType = ACEESS_TOKEN_TYPE_INVALID;
    appInfo->udpConnType = UDP_CONN_TYPE_WIFI;
    appInfo->routeType = WIFI_P2P;
    ret = SetChannelInfoBySide(info, isServerSide, appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    appInfo->myData.tokenType = ACEESS_TOKEN_TYPE_INVALID;
    appInfo->udpConnType = UDP_CONN_TYPE_USB;
    appInfo->routeType = WIFI_P2P;
    ret = SetChannelInfoBySide(info, isServerSide, appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    appInfo->myData.tokenType = ACEESS_TOKEN_TYPE_INVALID;
    appInfo->udpConnType = UDP_CONN_TYPE_WIFI;
    appInfo->routeType = WIFI_USB;
    ret = SetChannelInfoBySide(info, isServerSide, appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    appInfo->myData.tokenType = ACCESS_TOKEN_TYPE_SHELL;
    appInfo->udpConnType = UDP_CONN_TYPE_USB;
    appInfo->routeType = WIFI_USB;
    strcpy_s(info->myIp, sizeof(info->myIp), ip);
    ret = SetChannelInfoBySide(info, isServerSide, appInfo);
    EXPECT_EQ(SOFTBUSOFTBUS_NETWORK_GET_NODE_INFO_ERRS_OK, ret);

    SoftBusFree(info);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: NotifyWifiByAddScenarioTest001
 * @tc.desc: use nomal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticMockTest, NotifyWifiByAddScenarioTest001, TestSize.Level1)
{
    int32_t pid = 0;
    StreamType streamType = COMMON_AUDIO_STREAM;

    NiceMock<TransUdpNegoStaticInterfaceMock> TransUdpStaticMock;

    EXPECT_CALL(TransUdpStaticMock, AddScenario).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    NotifyWifiByAddScenario(streamType, pid);
    EXPECT_EQ(SOFTBUS_OK, pid);

    EXPECT_CALL(TransUdpStaticMock, AddScenario).WillOnce(Return(SOFTBUS_OK));
    streamType = COMMON_VIDEO_STREAM;
    NotifyWifiByAddScenario(streamType, pid);
    EXPECT_EQ(SOFTBUS_OK, pid);
}

/**
 * @tc.name: ParseRequestAppInfoTest001
 * @tc.desc: use abnomal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticMockTest, ParseRequestAppInfoTest001, TestSize.Level1)
{
    int32_t ret = 0;
    AuthHandle *authHandle = reinterpret_cast<AuthHandle*>(SoftBusCalloc(sizeof(AuthHandle)));
    ASSERT_TRUE(authHandle != nullptr);
    AppInfo *appInfo = reinterpret_cast<AppInfo*>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);

    (void)TransUdpChannelInit(&g_callbacks);
    NiceMock<TransUdpNegoStaticInterfaceMock> TransUdpStaticMock;
    EXPECT_CALL(TransUdpStaticMock, TransUnpackRequestUdpInfo).WillRepeatedly(Return(SOFTBUS_OK));

    appInfo->callingTokenId = 1;
    strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName), "123");
    strcpy_s(appInfo->peerData.sessionName, sizeof(appInfo->peerData.sessionName), "");
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_CLOSE;
    ret = ParseRequestAppInfo(*authHandle, NULL, appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    EXPECT_CALL(TransUdpStaticMock, AuthGetDeviceUuid).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUdpStaticMock, LnnGetLocalStrInfoByIfnameIdx).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    appInfo->callingTokenId = TOKENID_NOT_SET;
    authHandle->type = AUTH_LINK_TYPE_P2P;
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;
    appInfo->udpConnType = UDP_CONN_TYPE_WIFI;
    ret = ParseRequestAppInfo(*authHandle, NULL, appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    EXPECT_CALL(TransUdpStaticMock, AuthGetDeviceUuid).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUdpStaticMock, LnnGetLocalStrInfoByIfnameIdx).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    appInfo->udpConnType = UDP_CONN_TYPE_USB;
    ret = ParseRequestAppInfo(*authHandle, NULL, appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftBusFree(authHandle);
    SoftBusFree(appInfo);
    TransUdpChannelDeinit();
}

/**
 * @tc.name: TransOnExchangeUdpInfoReplyTest001
 * @tc.desc: use abnomal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticMockTest, TransOnExchangeUdpInfoReplyTest001, TestSize.Level1)
{
    int64_t seq = 0;
    AuthHandle *authHandle = reinterpret_cast<AuthHandle*>(SoftBusCalloc(sizeof(AuthHandle)));
    ASSERT_TRUE(authHandle != nullptr);

    NiceMock<TransUdpNegoStaticInterfaceMock> TransUdpStaticMock;
    EXPECT_CALL(TransUdpStaticMock, TransSetUdpChannelStatus).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUdpStaticMock, TransGetUdpChannelBySeq).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    TransOnExchangeUdpInfoReply(*authHandle, seq, NULL);

    EXPECT_CALL(TransUdpStaticMock, TransSetUdpChannelStatus).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    TransOnExchangeUdpInfoReply(*authHandle, seq, NULL);

    SoftBusFree(authHandle);
}

/**
 * @tc.name: ReportUdpRequestHandShakeStartEventTest001
 * @tc.desc: use abnomal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticMockTest, ReportUdpRequestHandShakeStartEventTest001, TestSize.Level1)
{
    AppInfo *info = reinterpret_cast<AppInfo*>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(info != nullptr);
    NodeInfo *nodeInfo = reinterpret_cast<NodeInfo*>(SoftBusCalloc(sizeof(NodeInfo)));
    ASSERT_TRUE(nodeInfo != nullptr);
    TransEventExtra *extra = reinterpret_cast<TransEventExtra*>(SoftBusCalloc(sizeof(TransEventExtra)));
    ASSERT_TRUE(extra != nullptr);
    int64_t authId = 0;

    NiceMock<TransUdpNegoStaticInterfaceMock> TransUdpStaticMock;
    info->udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;
    EXPECT_CALL(TransUdpStaticMock, LnnGetRemoteNodeInfoById).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUdpStaticMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_OK));
    ReportUdpRequestHandShakeStartEvent(info, nodeInfo, extra, authId);

    SoftBusFree(info);
    SoftBusFree(nodeInfo);
    SoftBusFree(extra);
}

/**
 * @tc.name: UdpOpenAuthConnTest001
 * @tc.desc: use abnomal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticMockTest, UdpOpenAuthConnTest001, TestSize.Level1)
{
    int32_t ret = 0;
    const char *peerUdid = "";
    uint32_t requestId = 0;
    bool isMeta = true;
    int32_t linkType = LANE_USB;
    bool isClient = true;

    NiceMock<TransUdpNegoStaticInterfaceMock> TransUdpStaticMock;
    EXPECT_CALL(TransUdpStaticMock, AuthGetUsbConnInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUdpStaticMock, AuthOpenConn).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUdpStaticMock, TransGetUdpChannelByRequestId).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = UdpOpenAuthConn(peerUdid, requestId, isMeta, linkType, isClient);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);
}

/**
 * @tc.name: TransDealUdpCheckCollabResultTest001
 * @tc.desc: use abnomal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticMockTest, TransDealUdpCheckCollabResultTest001, TestSize.Level1)
{
    int32_t ret = 0;
    int32_t channelId = 0;
    int32_t checkResult = 0;
    pid_t callingPid = 0;

    NiceMock<TransUdpNegoStaticInterfaceMock> TransUdpStaticMock;
    EXPECT_CALL(TransUdpStaticMock, TransGetUdpChannelById).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TransDealUdpCheckCollabResult(channelId, checkResult, callingPid);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}
}
