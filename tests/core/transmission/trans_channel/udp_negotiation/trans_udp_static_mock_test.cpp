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

#include "gtest/gtest.h"
#include <securec.h>

#include "softbus_adapter_mem.h"
#include "softbus_app_info.h"
#include "softbus_proxychannel_manager.c"
#include "trans_channel_callback.h"
#include "trans_udp_nego_static_test_mock.h"
#include "trans_udp_negotiation.c"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
static int32_t DefaultOnChannelOpened(
    const char *pkgName, int32_t pid, const char *sessionName, const ChannelInfo *channel)
{
    (void)pkgName;
    (void)pid;
    (void)sessionName;
    (void)channel;
    return SOFTBUS_OK;
}

static int32_t DefaultOnChannelClosed(
    const char *pkgName, int32_t pid, int32_t channelId, int32_t channelType, int32_t messageType)
{
    (void)pkgName;
    (void)pid;
    (void)channelId;
    (void)channelType;
    (void)messageType;
    return SOFTBUS_OK;
}

static int32_t DefaultOnChannelOpenFailed(
    const char *pkgName, int32_t pid, int32_t channelId, int32_t channelType, int32_t errCode)
{
    (void)pkgName;
    (void)pid;
    (void)channelId;
    (void)channelType;
    (void)errCode;
    return SOFTBUS_OK;
}

static int32_t DefaultOnDataReceived(const char *pkgName, int32_t pid, int32_t channelId, int32_t channelType,
    TransReceiveData* receiveData)
{
    (void)pkgName;
    (void)pid;
    (void)channelId;
    (void)channelType;
    (void)receiveData;
    return SOFTBUS_OK;
}

static int32_t DefaultOnQosEvent(const char *pkgName, const QosParam *param)
{
    (void)pkgName;
    (void)param;
    return SOFTBUS_OK;
}

static int32_t DefaultGetPkgNameBySessionName(const char *sessionName, char *pkgName, uint16_t len)
{
    (void)sessionName;
    (void)pkgName;
    (void)len;
    return SOFTBUS_OK;
}

static int32_t DefaultGetUidAndPidBySessionName(const char *sessionName, int32_t *uid, int32_t *pid)
{
    (void)sessionName;
    (void)uid;
    (void)pid;
    return SOFTBUS_OK;
}

static int32_t DefaultOnChannelBind(const char *pkgName, int32_t pid, int32_t channelId, int32_t channelType)
{
    (void)pkgName;
    (void)pid;
    (void)channelId;
    (void)channelType;
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

static int32_t GetLocalIpByRemoteIpTrue(const char *remoteIp, char *localIp, int32_t localIpSize)
{
    GTEST_LOG_(INFO) << "GetLocalIpByRemoteIpTrue enter";
    (void)remoteIp;
    (void)localIpSize;
    (void)strcpy_s(localIp, IP_LEN, "43.28.11.425");
    return SOFTBUS_OK;
}

static int32_t GetLocalIpByRemoteIpFalse(const char *remoteIp, char *localIp, int32_t localIpSize)
{
    GTEST_LOG_(INFO) << "GetLocalIpByRemoteIpFalse enter";
    (void)remoteIp;
    (void)localIp;
    (void)localIpSize;
    return SOFTBUS_CONN_GET_LOCAL_IP_BY_REMOTE_IP_FAILED;
}

static struct WifiDirectManager g_manager1 = {
    .getLocalIpByRemoteIp = GetLocalIpByRemoteIpTrue,
};

static struct WifiDirectManager g_manager2 = {
    .getLocalIpByRemoteIp = GetLocalIpByRemoteIpFalse,
};

static struct WifiDirectManager g_manager3 = {
    .getLocalIpByRemoteIp = nullptr,
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
    ASSERT_TRUE(appInfo != nullptr);

    ret = SetChannelInfoBySide(nullptr, isServerSide, appInfo);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    ret = SetChannelInfoBySide(info, isServerSide, nullptr);
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
    ASSERT_TRUE(appInfo != nullptr);
    char ip[] = "192.168.1,1";

    NiceMock<TransUdpNegoStaticInterfaceMock> TransUdpStaticMock;
    EXPECT_CALL(TransUdpStaticMock, LnnGetLocalStrInfoByIfnameIdx).WillRepeatedly(Return(SOFTBUS_ERR));

    appInfo->udpConnType = UDP_CONN_TYPE_USB;
    appInfo->routeType = WIFI_USB;
    (void)strcpy_s(info->peerIp, sizeof(info->peerIp), ip);
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
    ASSERT_TRUE(appInfo != nullptr);
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
    (void)strcpy_s(info->myIp, sizeof(info->myIp), ip);
    ret = SetChannelInfoBySide(info, isServerSide, appInfo);
    EXPECT_EQ(SOFTBUS_NETWORK_GET_NODE_INFO_ERR, ret);

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
    (void)strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName), "123");
    (void)strcpy_s(appInfo->peerData.sessionName, sizeof(appInfo->peerData.sessionName), "");
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_CLOSE;
    ret = ParseRequestAppInfo(*authHandle, nullptr, appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    EXPECT_CALL(TransUdpStaticMock, AuthGetDeviceUuid).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUdpStaticMock, LnnGetLocalStrInfoByIfnameIdx).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    appInfo->callingTokenId = TOKENID_NOT_SET;
    authHandle->type = AUTH_LINK_TYPE_P2P;
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;
    appInfo->udpConnType = UDP_CONN_TYPE_WIFI;
    ret = ParseRequestAppInfo(*authHandle, nullptr, appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    EXPECT_CALL(TransUdpStaticMock, AuthGetDeviceUuid).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUdpStaticMock, LnnGetLocalStrInfoByIfnameIdx).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    appInfo->udpConnType = UDP_CONN_TYPE_USB;
    ret = ParseRequestAppInfo(*authHandle, nullptr, appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftBusFree(authHandle);
    SoftBusFree(appInfo);
    TransUdpChannelDeinit();
}

/**
 * @tc.name: ParseRequestAppInfoTest002
 * @tc.desc: use abnomal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticMockTest, ParseRequestAppInfoTest002, TestSize.Level1)
{
    AuthHandle authHandle = {
        .authId = 6859453
    };
    cJSON *cJson = cJSON_CreateObject();
    ASSERT_TRUE(cJson != nullptr);
    AppInfo appInfo = {
        .udpChannelOptType = TYPE_INVALID_CHANNEL
    };

    int32_t ret = ParseRequestAppInfo(authHandle, cJson, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    NiceMock<TransUdpNegoStaticInterfaceMock> TransUdpStaticMock;
    EXPECT_CALL(TransUdpStaticMock, AuthGetDeviceUuid).WillOnce(Return(SOFTBUS_AUTH_NOT_FOUND));
    ret = ParseRequestAppInfo(authHandle, cJson, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_PEER_PROC_ERR);

    int32_t osType = OTHER_OS_TYPE;
    char peerUuid[UUID_BUF_LEN] = "test.peer.uid123";
    (void)strcpy_s(appInfo.peerData.deviceId, DEVICE_ID_SIZE_MAX, "7645723048r4h20test");
    EXPECT_CALL(TransUdpStaticMock, AuthGetDeviceUuid)
        .WillOnce(DoAll(SetArrayArgument<1>(peerUuid, peerUuid + 32), Return(SOFTBUS_OK)));
    EXPECT_CALL(TransUdpStaticMock, LnnGetOsTypeByNetworkId)
        .WillOnce(DoAll(SetArgPointee<1>(osType), Return(SOFTBUS_OK)));
    bool tmp = AddNumberToJsonObject(cJson, "CHANNEL_TYPE", appInfo.udpChannelOptType);
    EXPECT_EQ(tmp, true);

    ret = ParseRequestAppInfo(authHandle, cJson, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_CHANNEL_TYPE);

    cJSON_Delete(cJson);
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
    TransOnExchangeUdpInfoReply(*authHandle, seq, nullptr);

    EXPECT_CALL(TransUdpStaticMock, TransSetUdpChannelStatus).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    TransOnExchangeUdpInfoReply(*authHandle, seq, nullptr);

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

/**
 * @tc.name: NotifyUdpChannelOpenedTest001
 * @tc.desc: use nomal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticMockTest, NotifyUdpChannelOpenedTest001, TestSize.Level1)
{
    int32_t ret = 0;
    AppInfo *appInfo = reinterpret_cast<AppInfo*>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    bool isServerSide = false;
    (void)TransUdpChannelInit(&g_callbacks);

    NiceMock<TransUdpNegoStaticInterfaceMock> TransUdpStaticMock;
    EXPECT_CALL(TransUdpStaticMock, LnnGetNetworkIdByUuid).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUdpStaticMock, TransGetLaneIdByChannelId).WillOnce(Return(SOFTBUS_OK));
    ret = NotifyUdpChannelOpened(appInfo, isServerSide);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SoftBusFree(appInfo);
    TransUdpChannelDeinit();
}

/**
 * @tc.name: NotifyUdpChannelOpenedTest002
 * @tc.desc: use abnomal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticMockTest, NotifyUdpChannelOpenedTest002, TestSize.Level1)
{
    int32_t ret = 0;
    AppInfo *appInfo = reinterpret_cast<AppInfo*>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    bool isServerSide = false;
    IServerChannelCallBack temCallbacks = g_callbacks;
    temCallbacks.GetPkgNameBySessionName = [](const char *sessionName, char *pkgName, uint16_t len) -> int32_t {
        return SOFTBUS_INVALID_PARAM;
    };
    (void)TransUdpChannelInit(&temCallbacks);

    NiceMock<TransUdpNegoStaticInterfaceMock> TransUdpStaticMock;
    EXPECT_CALL(TransUdpStaticMock, LnnGetNetworkIdByUuid).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUdpStaticMock, TransGetLaneIdByChannelId).WillOnce(Return(SOFTBUS_OK));
    ret = NotifyUdpChannelOpened(appInfo, isServerSide);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    EXPECT_CALL(TransUdpStaticMock, LnnGetNetworkIdByUuid).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUdpStaticMock, LnnGetLocalStrInfoByIfnameIdx).WillOnce(Return(SOFTBUS_ERR));
    appInfo->udpConnType = UDP_CONN_TYPE_USB;
    appInfo->routeType = WIFI_USB;
    ret = NotifyUdpChannelOpened(appInfo, isServerSide);
    EXPECT_EQ(SOFTBUS_NETWORK_GET_NODE_INFO_ERR, ret);

    SoftBusFree(appInfo);
    TransUdpChannelDeinit();
}

/**
 * @tc.name: NotifyUdpChannelBindTest001
 * @tc.desc: use nomal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticMockTest, NotifyUdpChannelBindTest001, TestSize.Level1)
{
    int32_t ret = 0;
    AppInfo *info = reinterpret_cast<AppInfo*>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(info != nullptr);
    (void)TransUdpChannelInit(&g_callbacks);

    ret = NotifyUdpChannelBind(info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SoftBusFree(info);
    TransUdpChannelDeinit();
}

/**
 * @tc.name: NotifyUdpChannelOpenFailedTest001
 * @tc.desc: use abnomal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticMockTest, NotifyUdpChannelOpenFailedTest001, TestSize.Level1)
{
    int32_t ret = 0;
    AppInfo *info = reinterpret_cast<AppInfo*>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(info != nullptr);
    int32_t errCode = 0;
    IServerChannelCallBack temCallbacks = g_callbacks;
    temCallbacks.OnChannelOpenFailed = [](
        const char *pkgName, int32_t pid, int32_t channelId, int32_t channelType, int32_t errCode) -> int32_t {
            return SOFTBUS_INVALID_PARAM;
        };
    (void)TransUdpChannelInit(&temCallbacks);

    NiceMock<TransUdpNegoStaticInterfaceMock> TransUdpStaticMock;
    EXPECT_CALL(TransUdpStaticMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUdpStaticMock, TransGetDeviceState).WillOnce(Return(DEVICE_STATE_BUTT));
    info->isClient = true;
    ret = NotifyUdpChannelOpenFailed(info, errCode);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftBusFree(info);
    TransUdpChannelDeinit();
}

/**
 * @tc.name: AcceptUdpChannelAsServerTest001
 * @tc.desc: use abnomal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticMockTest, AcceptUdpChannelAsServerTest001, TestSize.Level1)
{
    int32_t ret = 0;
    AppInfo *appInfo = reinterpret_cast<AppInfo*>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    AuthHandle *authHandle = reinterpret_cast<AuthHandle*>(SoftBusCalloc(sizeof(AuthHandle)));
    ASSERT_TRUE(authHandle != nullptr);
    int64_t seq = 0;
    (void)TransUdpChannelInit(&g_callbacks);

    NiceMock<TransUdpNegoStaticInterfaceMock> TransUdpStaticMock;
    g_channelIdFlagBitsMap = 0xFFFFFFFFFFFFFFFF;
    ret = AcceptUdpChannelAsServer(appInfo, authHandle, seq);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_INVALID_CHANNEL_ID, ret);
    g_channelIdFlagBitsMap = 0;

    EXPECT_CALL(TransUdpStaticMock, LnnGetNetworkIdByUuid).WillOnce(Return(SOFTBUS_OK));
    appInfo->channelCapability = 0xFFFFFFFF;
    ret = AcceptUdpChannelAsServer(appInfo, authHandle, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
    appInfo->channelCapability = 0;

    EXPECT_CALL(TransUdpStaticMock, LnnGetNetworkIdByUuid).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUdpStaticMock, SoftBusGenerateSessionKey).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUdpStaticMock, TransAddUdpChannel).WillOnce(Return(SOFTBUS_ERR));
    ret = AcceptUdpChannelAsServer(appInfo, authHandle, seq);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_SERVER_ADD_CHANNEL_FAILED, ret);

    EXPECT_CALL(TransUdpStaticMock, LnnGetNetworkIdByUuid).WillOnce(Return(SOFTBUS_OK)).WillOnce(Return(SOFTBUS_ERR));
    EXPECT_CALL(TransUdpStaticMock, SoftBusGenerateSessionKey).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUdpStaticMock, TransAddUdpChannel).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUdpStaticMock, CheckCollabRelation).WillOnce(Return(SOFTBUS_TRANS_NOT_NEED_CHECK_RELATION));
    ret = AcceptUdpChannelAsServer(appInfo, authHandle, seq);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    
    SoftBusFree(appInfo);
    SoftBusFree(authHandle);
    TransUdpChannelDeinit();
}

/**
 * @tc.name: NotifyWifiByDelScenarioTest001
 * @tc.desc: use nomal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticMockTest, NotifyWifiByDelScenarioTest001, TestSize.Level1)
{
    int32_t pid = 0;
    StreamType streamType = COMMON_VIDEO_STREAM;

    NiceMock<TransUdpNegoStaticInterfaceMock> TransUdpStaticMock;
    EXPECT_CALL(TransUdpStaticMock, DelScenario).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    NotifyWifiByDelScenario(streamType, pid);
    EXPECT_EQ(SOFTBUS_OK, pid);

    EXPECT_CALL(TransUdpStaticMock, DelScenario).WillOnce(Return(SOFTBUS_OK));
    streamType = COMMON_VIDEO_STREAM;
    NotifyWifiByDelScenario(streamType, pid);
}

/**
 * @tc.name: UdpModuleCbTest001
 * @tc.desc: use abnomal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticMockTest, UdpModuleCbTest001, TestSize.Level1)
{
    AuthHandle authHandle = {0};
    authHandle.type = 0;
    AuthTransData *data = reinterpret_cast<AuthTransData*>(SoftBusCalloc(sizeof(AuthTransData)));
    ASSERT_TRUE(data != nullptr);
    data->data = (const uint8_t *)"{\"name\":\"John\", \"age\":30}";
    data->len = 24;
    UdpModuleCb(authHandle, data);

    authHandle.type = 16;
    UdpModuleCb(authHandle, data);
    SoftBusFree(data);
}


/**
 * @tc.name: UdpModuleCbTest002
 * @tc.desc: use abnomal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticMockTest, UdpModuleCbTest002, TestSize.Level1)
{
    AuthHandle authHandle = {0};
    authHandle.type = AUTH_LINK_TYPE_P2P;
    const char *temStr = "{\"key1\": \"value1\", \"key2\": 12345}";
    const uint8_t *str = (const uint8_t *)temStr;

    AuthTransData *data = reinterpret_cast<AuthTransData*>(SoftBusCalloc(sizeof(AuthTransData)));
    ASSERT_TRUE(data != nullptr);
    data->data = str;
    data->len = strlen(temStr);
    data->flag = 1;

    NiceMock<TransUdpNegoStaticInterfaceMock> TransUdpStaticMock;
    EXPECT_CALL(TransUdpStaticMock, TransSetUdpChannelStatus).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    UdpModuleCb(authHandle, data);

    data->flag = 0;
    EXPECT_CALL(TransUdpStaticMock, TransUnpackRequestUdpInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    UdpModuleCb(authHandle, data);

    SoftBusFree(data);
}

/**
 * @tc.name: TransProcessAsyncOpenUdpChannelSuccessTest001
 * @tc.desc: use abnomal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticMockTest, TransProcessAsyncOpenUdpChannelSuccessTest001, TestSize.Level1)
{
    int32_t ret = 0;
    int32_t channelId = 0;
    UdpChannelInfo *channel = reinterpret_cast<UdpChannelInfo*>(SoftBusCalloc(sizeof(UdpChannelInfo)));
    ASSERT_TRUE(channel != nullptr);
    channel->info.udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;
    (void)TransUdpChannelInit(&g_callbacks);

    NiceMock<TransUdpNegoStaticInterfaceMock> TransUdpStaticMock;
    EXPECT_CALL(TransUdpStaticMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUdpStaticMock, TransGetDeviceState).WillOnce(Return(DEVICE_STATE_BUTT));
    EXPECT_CALL(TransUdpStaticMock, TransDelUdpChannel).WillOnce(Return(SOFTBUS_OK));
    ret = TransProcessAsyncOpenUdpChannelSuccess(channel, channelId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftBusFree(channel);
    TransUdpChannelDeinit();
}

/**
 * @tc.name: HandleUdpGenUkResultTest001
 * @tc.desc: use nomal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticMockTest, HandleUdpGenUkResultTest001, TestSize.Level1)
{
    uint32_t requestId = 0;
    int32_t ukId = 0;
    int32_t reason = SOFTBUS_OK;
    (void)TransUdpChannelInit(&g_callbacks);

    NiceMock<TransUdpNegoStaticInterfaceMock> TransUdpStaticMock;
    EXPECT_CALL(TransUdpStaticMock, TransUkRequestGetRequestInfoByRequestId).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUdpStaticMock, TransGetUdpChannelById).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUdpStaticMock, TransUkRequestDeleteItem).WillRepeatedly(Return(SOFTBUS_OK));
    HandleUdpGenUkResult(requestId, ukId, reason);
    EXPECT_EQ(SOFTBUS_OK, reason);

    TransUdpChannelDeinit();
}

/**
 * @tc.name: HandleUdpGenUkResultTest002
 * @tc.desc: use abnomal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticMockTest, HandleUdpGenUkResultTest002, TestSize.Level1)
{
    uint32_t requestId = 0;
    int32_t ukId = 0;
    int32_t reason = SOFTBUS_OK;
    (void)TransUdpChannelInit(&g_callbacks);

    NiceMock<TransUdpNegoStaticInterfaceMock> TransUdpStaticMock;
    EXPECT_CALL(TransUdpStaticMock, TransUkRequestGetRequestInfoByRequestId).WillOnce(Return(SOFTBUS_ERR));
    EXPECT_CALL(TransUdpStaticMock, TransUkRequestDeleteItem).WillRepeatedly(Return(SOFTBUS_OK));
    HandleUdpGenUkResult(requestId, ukId, reason);

    EXPECT_CALL(TransUdpStaticMock, TransUkRequestGetRequestInfoByRequestId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUdpStaticMock, TransGetUdpChannelById).WillOnce(Return(SOFTBUS_ERR));
    HandleUdpGenUkResult(requestId, ukId, reason);
    EXPECT_EQ(SOFTBUS_OK, reason);

    TransUdpChannelDeinit();
}

/**
 * @tc.name: TransDealUdpChannelOpenResultTest001
 * @tc.desc: use abnomal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticMockTest, TransDealUdpChannelOpenResultTest001, TestSize.Level1)
{
    int32_t ret = 0;
    int32_t channelId = 0;
    int32_t openResult = SOFTBUS_OK;
    int32_t udpPort = 0;
    AccessInfo *accessInfo = reinterpret_cast<AccessInfo*>(SoftBusCalloc(sizeof(AccessInfo)));
    ASSERT_TRUE(accessInfo != nullptr);
    pid_t callingPid = 0;
    (void)TransUdpChannelInit(&g_callbacks);

    NiceMock<TransUdpNegoStaticInterfaceMock> TransUdpStaticMock;
    EXPECT_CALL(TransUdpStaticMock, TransGetUdpChannelById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUdpStaticMock, TransUdpUpdateUdpPort).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUdpStaticMock, TransUdpUpdateReplyCnt).WillOnce(Return(SOFTBUS_OK));
    ret = TransDealUdpChannelOpenResult(channelId, openResult, udpPort, accessInfo, callingPid);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);

    TransUdpChannelDeinit();
}

/**
 * @tc.name: TransDealUdpChannelOpenResultTest002
 * @tc.desc: use abnomal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticMockTest, TransDealUdpChannelOpenResultTest002, TestSize.Level1)
{
    int32_t ret = 0;
    int32_t channelId = 0;
    int32_t openResult = SOFTBUS_INVALID_PARAM;
    int32_t udpPort = 0;
    AccessInfo *accessInfo = reinterpret_cast<AccessInfo*>(SoftBusCalloc(sizeof(AccessInfo)));
    ASSERT_TRUE(accessInfo != nullptr);
    pid_t callingPid = 0;
    (void)TransUdpChannelInit(&g_callbacks);

    NiceMock<TransUdpNegoStaticInterfaceMock> TransUdpStaticMock;
    EXPECT_CALL(TransUdpStaticMock, TransGetUdpChannelById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUdpStaticMock, TransUdpUpdateUdpPort).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUdpStaticMock, TransUdpUpdateReplyCnt).WillOnce(Return(SOFTBUS_OK));
    ret = TransDealUdpChannelOpenResult(channelId, openResult, udpPort, accessInfo, callingPid);
    EXPECT_EQ(SOFTBUS_OK, ret);

    TransUdpChannelDeinit();
}

/**
 * @tc.name: TransGetRemoteUuidByAuthHandle001
 * @tc.desc: TransGetRemoteUuidByAuthHandle test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticMockTest, TransGetRemoteUuidByAuthHandle001, TestSize.Level1)
{
    AuthHandle authHandle = {
        .authId = 4848448,
        .type = AUTH_LINK_TYPE_BLE
    };
    char peerUid[UUID_BUF_LEN];

    g_proxyChannelList = CreateSoftBusList();
    ASSERT_TRUE(g_proxyChannelList != nullptr);

    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(proxyChannelInfo != nullptr);
    proxyChannelInfo->authHandle = authHandle;
    proxyChannelInfo->channelId = 1234;
    ListAdd(&(g_proxyChannelList->list), &(proxyChannelInfo->node));

    NiceMock<TransUdpNegoStaticInterfaceMock> TransUdpStaticMock;
    EXPECT_CALL(TransUdpStaticMock, AuthGetDeviceUuid).WillOnce(Return(SOFTBUS_NOT_FIND));
    int32_t ret = TransGetRemoteUuidByAuthHandle(authHandle, peerUid);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);

    EXPECT_CALL(TransUdpStaticMock, AuthGetDeviceUuid).WillOnce(Return(SOFTBUS_OK));
    ret = TransGetRemoteUuidByAuthHandle(authHandle, peerUid);
    EXPECT_EQ(ret, SOFTBUS_OK);

    authHandle.type = AUTH_LINK_TYPE_WIFI;
    EXPECT_CALL(TransUdpStaticMock, AuthGetDeviceUuid).WillOnce(Return(SOFTBUS_NOT_FIND));
    ret = TransGetRemoteUuidByAuthHandle(authHandle, peerUid);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);

    EXPECT_CALL(TransUdpStaticMock, AuthGetDeviceUuid).WillOnce(Return(SOFTBUS_OK));
    ret = TransGetRemoteUuidByAuthHandle(authHandle, peerUid);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ListDelete(&(proxyChannelInfo->node));
    SoftBusFree(proxyChannelInfo);
    DestroySoftBusList(g_proxyChannelList);
    g_proxyChannelList = nullptr;
}

/**
 * @tc.name: TransGetRemoteUuidByAuthHandle002
 * @tc.desc: TransGetRemoteUuidByAuthHandle test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticMockTest, TransGetRemoteUuidByAuthHandle002, TestSize.Level1)
{
    AuthHandle authHandle = {
        .authId = 6666,
        .type = AUTH_LINK_TYPE_BLE
    };
    char peerUid[UUID_BUF_LEN];

    g_proxyChannelList = CreateSoftBusList();
    ASSERT_TRUE(g_proxyChannelList != nullptr);

    ProxyChannelInfo *proxyChannelInfo = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(proxyChannelInfo != nullptr);
    proxyChannelInfo->authHandle = authHandle;
    proxyChannelInfo->channelId = 6666;
    ListAdd(&(g_proxyChannelList->list), &(proxyChannelInfo->node));

    NiceMock<TransUdpNegoStaticInterfaceMock> TransUdpStaticMock;
    EXPECT_CALL(TransUdpStaticMock, AuthGetDeviceUuid).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransGetRemoteUuidByAuthHandle(authHandle, peerUid);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ListDelete(&(proxyChannelInfo->node));
    SoftBusFree(proxyChannelInfo);
    DestroySoftBusList(g_proxyChannelList);
    g_proxyChannelList = nullptr;
}

/**
 * @tc.name: TransGetUdpChannelLocalIp001
 * @tc.desc: TransGetUdpChannelLocalIp test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticMockTest, TransGetUdpChannelLocalIp001, TestSize.Level1)
{
    AuthHandle authHandle = {
        .type = AUTH_LINK_TYPE_ENHANCED_P2P
    };
    AppInfo appInfo = {
        .osType = OTHER_OS_TYPE,
        .routeType = WIFI_P2P,
        .metaType = META_HA
    };

    int32_t ret = TransGetUdpChannelLocalIp(authHandle, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    NiceMock<TransUdpNegoStaticInterfaceMock> TransUdpStaticMock;
    EXPECT_CALL(TransUdpStaticMock, AuthGetDeviceUuid).WillOnce(Return(SOFTBUS_NOT_FIND));
    ret = TransGetUdpChannelLocalIp(authHandle, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);

    EXPECT_CALL(TransUdpStaticMock, AuthGetDeviceUuid).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransUdpStaticMock, AuthMetaGetLocalIpByMetaNodeIdPacked)
        .WillOnce(Return(SOFTBUS_TRANS_GET_LOCAL_IP_FAILED));
    ret = TransGetUdpChannelLocalIp(authHandle, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_LANE_GET_LEDGER_INFO_ERR);

    char localIp[IP_LEN] = "00.11.22.34";
    EXPECT_CALL(TransUdpStaticMock, AuthMetaGetLocalIpByMetaNodeIdPacked)
        .WillOnce(DoAll(SetArrayArgument<1>(localIp, localIp + 15), Return(SOFTBUS_OK)));
    ret = TransGetUdpChannelLocalIp(authHandle, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransGetUdpChannelLocalIp002
 * @tc.desc: TransGetUdpChannelLocalIp test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticMockTest, TransGetUdpChannelLocalIp002, TestSize.Level1)
{
    AppInfo appInfo = {
        .osType = OH_OS_TYPE,
        .udpConnType = UDP_CONN_TYPE_WIFI,
        .routeType = WIFI_P2P
    };
    AuthHandle authHandle;

    NiceMock<TransUdpNegoStaticInterfaceMock> TransUdpStaticMock;
    EXPECT_CALL(TransUdpStaticMock, LnnGetLocalStrInfoByIfnameIdx).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransGetUdpChannelLocalIp(authHandle, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    char localIp[IP_LEN] = "44.33.22.11";
    EXPECT_CALL(TransUdpStaticMock, LnnGetLocalStrInfoByIfnameIdx)
        .WillOnce(DoAll(SetArrayArgument<1>(localIp, localIp + 15), Return(SOFTBUS_OK)));
    ret = TransGetUdpChannelLocalIp(authHandle, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    appInfo.udpConnType = UDP_CONN_TYPE_USB;
    EXPECT_CALL(TransUdpStaticMock, LnnGetLocalStrInfoByIfnameIdx).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TransGetUdpChannelLocalIp(authHandle, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    EXPECT_CALL(TransUdpStaticMock, LnnGetLocalStrInfoByIfnameIdx)
        .WillOnce(DoAll(SetArrayArgument<1>(localIp, localIp + 15), Return(SOFTBUS_OK)));
    ret = TransGetUdpChannelLocalIp(authHandle, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    appInfo.udpConnType = UDP_CONN_TYPE_P2P;
    EXPECT_CALL(TransUdpStaticMock, GetWifiDirectManager).WillOnce(Return(nullptr));
    ret = TransGetUdpChannelLocalIp(authHandle, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_INIT_FAILED);

    EXPECT_CALL(TransUdpStaticMock, GetWifiDirectManager).WillOnce(Return(&g_manager3));
    ret = TransGetUdpChannelLocalIp(authHandle, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_INIT_FAILED);

    (void)strcpy_s(appInfo.peerData.addr, IP_LEN, "77.48.52.11");
    EXPECT_CALL(TransUdpStaticMock, GetWifiDirectManager).WillOnce(Return(&g_manager2));
    ret = TransGetUdpChannelLocalIp(authHandle, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_CONN_GET_LOCAL_IP_BY_REMOTE_IP_FAILED);

    EXPECT_CALL(TransUdpStaticMock, GetWifiDirectManager).WillOnce(Return(&g_manager1));
    ret = TransGetUdpChannelLocalIp(authHandle, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: BuildUdpReplyExtra001
 * @tc.desc: BuildUdpReplyExtra test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpStaticMockTest, BuildUdpReplyExtra001, TestSize.Level1)
{
    int64_t authId = 123456789;
    int64_t channelId = 987654321;

    TransEventExtra extra = BuildUdpReplyExtra(authId, channelId);
    EXPECT_EQ(extra.socketName, nullptr);
    EXPECT_EQ(extra.peerNetworkId, nullptr);
    EXPECT_EQ(extra.calleePkg, nullptr);
    EXPECT_EQ(extra.callerPkg, nullptr);
    EXPECT_EQ(extra.channelId, (int32_t)channelId);
    EXPECT_EQ(extra.authId, (int32_t)authId);
    EXPECT_EQ(extra.result, EVENT_STAGE_RESULT_OK);

    authId = -123456789;
    channelId = -987654321;
    extra = BuildUdpReplyExtra(authId, channelId);
    EXPECT_EQ(extra.socketName, nullptr);
    EXPECT_EQ(extra.peerNetworkId, nullptr);
    EXPECT_EQ(extra.calleePkg, nullptr);
    EXPECT_EQ(extra.callerPkg, nullptr);
    EXPECT_EQ(extra.channelId, (int32_t)channelId);
    EXPECT_EQ(extra.authId, (int32_t)authId);
    EXPECT_EQ(extra.result, EVENT_STAGE_RESULT_OK);
}
}
