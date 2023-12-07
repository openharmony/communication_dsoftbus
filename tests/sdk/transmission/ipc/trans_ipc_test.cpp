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
#include <sys/socket.h>

#include "iremote_broker.h"
#include "message_parcel.h"
#include "peer_holder.h"
#include "softbus_errcode.h"
#include "softbus_server_ipc_interface_code.h"
#include "softbus_common.h"
#include "softbus_trans_def.h"
#include "softbus_def.h"
#include "softbus_adapter_mem.h"
#include "softbus_feature_config.h"
#include "softbus_access_token_test.h"
#include "session.h"
#include "trans_server_proxy.h"
#include "trans_server_proxy_standard.h"
#include "trans_server_proxy_standard.cpp"
#include "client_trans_session_manager.h"
#include "client_trans_session_service.h"

using namespace testing::ext;

namespace OHOS {
#define INVALID_VALUE (-1)
#define SESSIONKEY_LEN 32
#define LEN 32
static const int32_t UUID = 0;
static const int32_t PID = 0;
static const char *g_sessionName = "ohos.distributedschedule.dms.test";
static const char *g_peerSessionName = "ohos.distributedschedule.dms.test";
static const char *g_peerDeviceId = "1000";
static const char *g_pkgName = "com.test.trans.session";
static const char *g_addr = "192.168.8.1";
static const uint16_t PORT = 10;
static const char *g_networkId = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";
static const char *g_groupId = "TEST_GROUP_ID";

class TransIpcStandardTest : public testing::Test {
public:
    TransIpcStandardTest()
    {
    }
    ~TransIpcStandardTest()
    {
    }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {
    }
    void TearDown() override
    {
    }
};

void TransIpcStandardTest::SetUpTestCase(void)
{
}

void TransIpcStandardTest::TearDownTestCase(void)
{
}

/**
 * @tc.name: SoftbusRegisterServiceTest001
 * @tc.desc: SoftbusRegisterService, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransIpcStandardTest, SoftbusRegisterServiceTest001, TestSize.Level0)
{
    int subscribeId = 1;
    int publishId = 1;
    SubscribeInfo* subInfo = (SubscribeInfo*)SoftBusCalloc(sizeof(SubscribeInfo));
    ASSERT_TRUE(subInfo != nullptr);
    (void)memset_s(subInfo, sizeof(SubscribeInfo), 0, sizeof(SubscribeInfo));
    PublishInfo* pubInfo = (PublishInfo*)SoftBusCalloc(sizeof(PublishInfo));
    ASSERT_TRUE(pubInfo != nullptr);
    (void)memset_s(pubInfo, sizeof(PublishInfo), 0, sizeof(PublishInfo));
    TransServerProxy transServerProxy(nullptr);

    int32_t ret = transServerProxy.StartDiscovery(g_pkgName, subInfo);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = transServerProxy.StopDiscovery(g_pkgName, subscribeId);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = transServerProxy.PublishService(g_pkgName, pubInfo);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = transServerProxy.UnPublishService(g_pkgName, publishId);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = transServerProxy.SoftbusRegisterService(g_pkgName, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    SoftBusFree(subInfo);
    SoftBusFree(pubInfo);
}

/**
 * @tc.name: SoftbusRegisterServiceTest002
 * @tc.desc: SoftbusRegisterService, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransIpcStandardTest, SoftbusRegisterServiceTest002, TestSize.Level0)
{
    uint32_t addrTypeLen = 1;
    void *info = nullptr;
    uint32_t infoTypeLen = 1;
    int infoNum = 1;
    int key = 1;
    unsigned char *buf = nullptr;
    uint16_t dataChangeFlag = 1;
    int32_t accuracy = 1;
    int32_t period = 1;
    TransServerProxy transServerProxy(nullptr);

    int32_t ret = transServerProxy.JoinLNN(g_pkgName, (void *)g_addr, addrTypeLen);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = transServerProxy.LeaveLNN(g_pkgName, g_networkId);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = transServerProxy.GetAllOnlineNodeInfo(g_pkgName, &info, infoTypeLen, &infoNum);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = transServerProxy.GetLocalDeviceInfo(g_pkgName, info, infoTypeLen);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = transServerProxy.GetNodeKeyInfo(g_pkgName, g_networkId, key, buf, infoTypeLen);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = transServerProxy.SetNodeDataChangeFlag(g_pkgName, g_networkId, dataChangeFlag);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = transServerProxy.StartTimeSync(g_pkgName, g_networkId,  accuracy, period);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = transServerProxy.StopTimeSync(g_pkgName, g_networkId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/**
 * @tc.name: CreateSessionServerTest001
 * @tc.desc: CreateSessionServer, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransIpcStandardTest, CreateSessionServerTest001, TestSize.Level0)
{
    TransServerProxy transServerProxy(nullptr);
    int32_t ret = transServerProxy.CreateSessionServer(nullptr, g_sessionName);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    ret = transServerProxy.CreateSessionServer(g_pkgName, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    ret = transServerProxy.CreateSessionServer(g_pkgName, g_sessionName);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/**
 * @tc.name: RemoveSessionServerTest001
 * @tc.desc: RemoveSessionServer, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransIpcStandardTest, RemoveSessionServerTest001, TestSize.Level0)
{
    TransServerProxy transServerProxy(nullptr);
    int32_t ret = transServerProxy.RemoveSessionServer(nullptr, g_sessionName);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    ret = transServerProxy.RemoveSessionServer(g_pkgName, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    ret = transServerProxy.RemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_TRUE(ret == SOFTBUS_TRANS_PROXY_SEND_REQUEST_FAILED);
}

/**
 * @tc.name: OpenSessionTest001
 * @tc.desc: OpenSession, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransIpcStandardTest, OpenSessionTest001, TestSize.Level0)
{
    TransServerProxy transServerProxy(nullptr);
    SessionParam *param = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    TransInfo *info = (TransInfo*)SoftBusCalloc(sizeof(TransInfo));
    ASSERT_TRUE(param != nullptr);
    ASSERT_TRUE(info != nullptr);
    (void)memset_s(param, sizeof(SessionParam), 0, sizeof(SessionParam));
    (void)memset_s(info, sizeof(TransInfo), 0, sizeof(TransInfo));
    param->sessionName = nullptr;
    param->peerSessionName = nullptr;
    param->peerDeviceId = nullptr;
    param->groupId = nullptr;

    int32_t ret = transServerProxy.OpenSession(param, info);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    param->sessionName = g_sessionName;
    ret = transServerProxy.OpenSession(param, info);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    param->peerSessionName = g_peerSessionName;
    ret = transServerProxy.OpenSession(param, info);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    param->peerDeviceId = g_peerDeviceId;
    ret = transServerProxy.OpenSession(param, info);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    param->groupId = g_groupId;
    ret = transServerProxy.OpenSession(param, info);
    EXPECT_TRUE(ret == SOFTBUS_TRANS_PROXY_WRITERAWDATA_FAILED);

    SessionAttribute sessionAttribute;
    sessionAttribute.dataType = 1;
    sessionAttribute.linkTypeNum= 1;
    param->attr = &sessionAttribute;
    ret = transServerProxy.OpenSession(param, info);
    EXPECT_TRUE(ret == SOFTBUS_TRANS_PROXY_SEND_REQUEST_FAILED);
    SoftBusFree(param);
    SoftBusFree(info);
}

/**
 * @tc.name: OpenAuthSessionTest001
 * @tc.desc: OpenAuthSession, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransIpcStandardTest, OpenAuthSessionTest001, TestSize.Level0)
{
    TransServerProxy transServerProxy(nullptr);
    ConnectionAddr *addrInfo = (ConnectionAddr*)SoftBusCalloc(sizeof(ConnectionAddr));
    ASSERT_TRUE(addrInfo != nullptr);
    (void)memset_s(addrInfo, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    addrInfo->type = CONNECTION_ADDR_WLAN;
    (void)memcpy_s(addrInfo->info.ip.ip, strlen(addrInfo->info.ip.ip), g_addr, strlen(g_addr));
    addrInfo->info.ip.port = PORT;
    int32_t ret = transServerProxy.OpenAuthSession(nullptr, addrInfo);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    ret = transServerProxy.OpenAuthSession(g_sessionName, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    ret = transServerProxy.OpenAuthSession(g_sessionName, addrInfo);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    SoftBusFree(addrInfo);
}

/**
 * @tc.name: NotifyAuthSuccessTest001
 * @tc.desc: NotifyAuthSuccess, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransIpcStandardTest, NotifyAuthSuccessTest001, TestSize.Level0)
{
    TransServerProxy transServerProxy(nullptr);
    int32_t channelId = 0;
    int32_t channelType = CHANNEL_TYPE_AUTH;
    int32_t ret = transServerProxy.NotifyAuthSuccess(channelId, channelType);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    channelId = INVALID_VALUE;
    ret = transServerProxy.NotifyAuthSuccess(channelId, channelType);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/**
 * @tc.name: CloseChannelTest001
 * @tc.desc: CloseChannel, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransIpcStandardTest, CloseChannelTest001, TestSize.Level0)
{
    TransServerProxy transServerProxy(nullptr);
    int32_t channelId = -1;
    int32_t channelType = CHANNEL_TYPE_AUTH;
    int32_t ret = transServerProxy.CloseChannel(channelId, channelType);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/**
 * @tc.name: SendMessageTest001
 * @tc.desc: SendMessage, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransIpcStandardTest, SendMessageTest001, TestSize.Level0)
{
    TransServerProxy transServerProxy(nullptr);
    int32_t channelId = 0;
    int32_t channelType = CHANNEL_TYPE_AUTH;
    const char *dataInfo = "datainfo";
    uint32_t len = LEN;
    int32_t msgType = TRANS_SESSION_BYTES;
    int32_t ret = transServerProxy.SendMessage(channelId, channelType, (const void *)dataInfo, len, msgType);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    ret = transServerProxy.SendMessage(channelId, channelType, nullptr, len, msgType);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/**
 * @tc.name: QosReportTest001
 * @tc.desc: SendMessage, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransIpcStandardTest, QosReportTest001, TestSize.Level0)
{
    TransServerProxy transServerProxy(nullptr);
    int32_t channelId = 1;
    int32_t channelType = CHANNEL_TYPE_BUTT;
    int32_t appType = 0;
    int32_t quality = QOS_IMPROVE;
    int32_t ret = transServerProxy.QosReport(channelId, channelType, appType, quality);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    channelId = INVALID_VALUE;
    ret = transServerProxy.QosReport(channelId, channelType, appType, quality);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/**
 * @tc.name: StreamStatsTest001
 * @tc.desc: StreamStats, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransIpcStandardTest, StreamStatsTest001, TestSize.Level0)
{
    TransServerProxy transServerProxy(nullptr);
    int32_t channelId = INVALID_VALUE;
    int32_t channelType = CHANNEL_TYPE_BUTT;
    StreamSendStats *statsData = (StreamSendStats*)SoftBusCalloc(sizeof(StreamSendStats));
    ASSERT_TRUE(statsData != nullptr);
    (void)memset_s(statsData, sizeof(StreamSendStats), 0, sizeof(StreamSendStats));

    int32_t ret = transServerProxy.StreamStats(channelId, channelType, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    channelId = INVALID_VALUE;
    ret = transServerProxy.StreamStats(channelId, channelType, statsData);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    SoftBusFree(statsData);
}

/**
 * @tc.name: RippleStatsTest0011
 * @tc.desc: RippleStats, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransIpcStandardTest, RippleStatsTest0011, TestSize.Level0)
{
    TransServerProxy transServerProxy(nullptr);
    int32_t channelId = INVALID_VALUE;
    int32_t channelType = CHANNEL_TYPE_BUTT;
    TrafficStats *statsData = (TrafficStats*)SoftBusCalloc(sizeof(TrafficStats));
    ASSERT_TRUE(statsData != nullptr);
    (void)memset_s(statsData, sizeof(TrafficStats), 0, sizeof(TrafficStats));

    int32_t ret = transServerProxy.RippleStats(channelId, channelType, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    channelId = INVALID_VALUE;
    ret = transServerProxy.RippleStats(channelId, channelType, statsData);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    SoftBusFree(statsData);
}

/**
 * @tc.name: GrantPermissionTest001
 * @tc.desc: GrantPermission, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransIpcStandardTest, GrantPermissionTest001, TestSize.Level0)
{
    TransServerProxy transServerProxy(nullptr);
    int32_t ret = transServerProxy.GrantPermission(UUID, PID, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    ret = transServerProxy.GrantPermission(UUID, PID, g_sessionName);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/**
 * @tc.name: RemovePermissionTest001
 * @tc.desc: RemovePermission, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransIpcStandardTest, RemovePermissionTest001, TestSize.Level0)
{
    TransServerProxy transServerProxy(nullptr);
    int32_t ret = transServerProxy.RemovePermission(g_sessionName);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    ret = transServerProxy.RemovePermission(g_sessionName);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/**
 * @tc.name: TransServerProxyInitTest001
 * @tc.desc: TransServerProxyInit, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransIpcStandardTest, TransServerProxyInitTest001, TestSize.Level0)
{
    int32_t ret = TransServerProxyInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    TransClientDeinit();

    ret = TransServerProxyInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    TransClientDeinit();
}

/**
 * @tc.name: ServerIpcCreateSessionServerTest001
 * @tc.desc: ServerIpcCreateSessionServer, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransIpcStandardTest, ServerIpcCreateSessionServerTest001, TestSize.Level0)
{
    int32_t ret = ServerIpcCreateSessionServer(g_pkgName, g_sessionName);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransServerProxyInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = ServerIpcCreateSessionServer(nullptr, g_sessionName);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = ServerIpcCreateSessionServer(g_pkgName, nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = ServerIpcCreateSessionServer(g_pkgName, g_sessionName);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    TransClientDeinit();
}

/**
 * @tc.name: ServerIpcRemoveSessionServerTest001
 * @tc.desc: ServerIpcRemoveSessionServer, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransIpcStandardTest, ServerIpcRemoveSessionServerTest001, TestSize.Level0)
{
    int32_t ret = ServerIpcRemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransServerProxyInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = ServerIpcRemoveSessionServer(nullptr, g_sessionName);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = ServerIpcRemoveSessionServer(g_pkgName, nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = ServerIpcRemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    TransClientDeinit();
}

/**
 * @tc.name: ServerIpcOpenSessionTest001
 * @tc.desc: ServerIpcOpenSession, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransIpcStandardTest, ServerIpcOpenSessionTest001, TestSize.Level0)
{
    TransInfo* info = (TransInfo*)SoftBusCalloc(sizeof(TransInfo));
    ASSERT_TRUE(info != nullptr);
    (void)memset_s(info, sizeof(TransInfo), 0, sizeof(TransInfo));
    SessionParam* param = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(param != nullptr);
    (void)memset_s(param, sizeof(SessionParam), 0, sizeof(SessionParam));
    param->sessionName = nullptr;
    param->peerSessionName = nullptr;
    param->peerDeviceId = nullptr;
    param->groupId = nullptr;
    param->attr = nullptr;

    int32_t sessionId = INVALID_SESSION_ID;
    int32_t ret = ServerIpcOpenSession(param, info);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    TransClientDeinit();
    ret = TransServerProxyInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    param->sessionName = g_sessionName;
    ret = ServerIpcOpenSession(param, info);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    (void)ClientDeleteSession(sessionId);

    param->peerSessionName = g_peerSessionName;
    ret = ServerIpcOpenSession(param, info);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    (void)ClientDeleteSession(sessionId);

    param->peerDeviceId = g_peerDeviceId;
    ret = ServerIpcOpenSession(param, info);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    (void)ClientDeleteSession(sessionId);

    param->groupId = g_groupId;
    ret = ServerIpcOpenSession(param, info);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    (void)ClientDeleteSession(sessionId);

    SessionAttribute sessionAttribute;
    sessionAttribute.dataType = 1;
    sessionAttribute.linkTypeNum = 1;
    param->attr = &sessionAttribute;
    ret = ServerIpcOpenSession(param, info);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    (void)ClientDeleteSession(sessionId);

    TransClientDeinit();
    SoftBusFree(param);
    SoftBusFree(info);
}

/**
 * @tc.name: ServerIpcOpenAuthSessionTest001
 * @tc.desc: ServerIpcOpenAuthSession, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransIpcStandardTest, ServerIpcOpenAuthSessionTest001, TestSize.Level0)
{
    ConnectionAddr* addrInfo = (ConnectionAddr*)SoftBusCalloc(sizeof(ConnectionAddr));
    ASSERT_TRUE(addrInfo != nullptr);
    (void)memset_s(addrInfo, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    addrInfo->type = CONNECTION_ADDR_BR;
    int32_t ret = ServerIpcOpenAuthSession(g_sessionName, addrInfo);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransServerProxyInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = ServerIpcOpenAuthSession(nullptr, addrInfo);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = ServerIpcOpenAuthSession(g_sessionName, nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = ServerIpcOpenAuthSession(g_sessionName, addrInfo);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    TransClientDeinit();
    SoftBusFree(addrInfo);
}

/**
 * @tc.name: ServerIpcNotifyAuthSuccessTest001
 * @tc.desc: ServerIpcNotifyAuthSuccess, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransIpcStandardTest, ServerIpcNotifyAuthSuccessTest001, TestSize.Level0)
{
    int32_t ret = TransServerProxyInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    int32_t channelId = 0;
    int32_t channelType = CHANNEL_TYPE_AUTH;
    ret = ServerIpcNotifyAuthSuccess(channelId, channelType);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    TransClientDeinit();
}

/**
 * @tc.name: ServerIpcCloseChannelTest001
 * @tc.desc: ServerIpcCloseChannel, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransIpcStandardTest, ServerIpcCloseChannelTest001, TestSize.Level0)
{
    int32_t channelId = 0;
    int32_t chanType = CHANNEL_TYPE_AUTH;
    int32_t ret = ServerIpcCloseChannel(channelId, chanType);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    ret = TransServerProxyInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = ServerIpcCloseChannel(-1, chanType);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    ret = ServerIpcCloseChannel(channelId, chanType);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    TransClientDeinit();
}

/**
 * @tc.name: ServerIpcSendMessageTest001
 * @tc.desc: ServerIpcSendMessage, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransIpcStandardTest, ServerIpcSendMessageTest001, TestSize.Level0)
{
    int32_t channelId = 0;
    int32_t chanType = CHANNEL_TYPE_AUTH;
    int32_t ret = ServerIpcSendMessage(channelId, chanType, nullptr, 0, 0);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    ret = TransServerProxyInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = ServerIpcSendMessage(channelId, chanType, nullptr, 0, 0);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    TransClientDeinit();
}

/**
 * @tc.name: ServerIpcQosReportTest001
 * @tc.desc: ServerIpcQosReport, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransIpcStandardTest, ServerIpcQosReportTest001, TestSize.Level0)
{
    int32_t channelId = 0;
    int32_t chanType = CHANNEL_TYPE_AUTH;
    int32_t appType = 0;
    int32_t quality = QOS_IMPROVE;
    int32_t ret = ServerIpcQosReport(channelId, chanType, appType, quality);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    ret = TransServerProxyInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = ServerIpcQosReport(channelId, chanType, appType, quality);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    TransClientDeinit();
}

/**
 * @tc.name: ServerIpcStreamStatsTest001
 * @tc.desc: ServerIpcStreamStats, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransIpcStandardTest, ServerIpcStreamStatsTest001, TestSize.Level0)
{
    int32_t channelId = 0;
    int32_t chanType = CHANNEL_TYPE_AUTH;
    int32_t ret = ServerIpcStreamStats(channelId, chanType, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    ret = TransServerProxyInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = ServerIpcStreamStats(channelId, chanType, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    TransClientDeinit();
}

/**
 * @tc.name: ServerIpcRippleStatsTest001
 * @tc.desc: ServerIpcRippleStats, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransIpcStandardTest, ServerIpcRippleStatsTest001, TestSize.Level0)
{
    int32_t channelId = 0;
    int32_t chanType = CHANNEL_TYPE_AUTH;
    int32_t ret = ServerIpcRippleStats(channelId, chanType, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    ret = TransServerProxyInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = ServerIpcRippleStats(channelId, chanType, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    TransClientDeinit();
}

/**
 * @tc.name: ServerIpcGrantPermissionTest001
 * @tc.desc: ServerIpcGrantPermission, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransIpcStandardTest, ServerIpcGrantPermissionTest001, TestSize.Level0)
{
    int uid = 1;
    int pid = 1;
    int32_t ret = ServerIpcGrantPermission(uid, pid, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    ret = TransServerProxyInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = ServerIpcGrantPermission(uid, pid, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    ret = ServerIpcGrantPermission(uid, pid, g_sessionName);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    TransClientDeinit();
}

/**
 * @tc.name: ServerIpcRemovePermissionTest001
 * @tc.desc: ServerIpcRemovePermission, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransIpcStandardTest, ServerIpcRemovePermissionTest001, TestSize.Level0)
{
    int32_t ret = ServerIpcRemovePermission(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    ret = TransServerProxyInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = ServerIpcRemovePermission(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    ret = ServerIpcRemovePermission(g_sessionName);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    TransClientDeinit();
}
}
