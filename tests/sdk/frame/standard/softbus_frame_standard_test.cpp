/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "softbus_client_death_recipient.cpp"
#include "softbus_client_frame_manager.h"
#define private   public
#define protected public
#include "softbus_client_stub.cpp"
#include "softbus_client_stub.h"
#undef private
#undef protected
#include "softbus_server_proxy_frame.cpp"
#include "softbus_server_proxy_standard.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
class SoftBusServerProxyFrameTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
};

class SoftBusClientDeathRecipientMock : public SoftBusClientDeathRecipient {
public:
    void OnRemoteDied(const wptr<IRemoteObject> &remote) override { }
};

class SoftBusClientStubMock : public SoftBusClientStub {
public:
    void OnPublishLNNResult(int32_t publishId, int32_t reason) override { }
    void OnRefreshLNNResult(int32_t refreshId, int32_t reason) override { }
    void OnRefreshDeviceFound(const void *device, uint32_t deviceLen) override { }
    void OnDataLevelChanged(const char *networkId, const DataLevelInfo *dataLevelInfo) override { }
    int32_t OnChannelQosEvent(int32_t channelId, int32_t channelType, int32_t eventId, int32_t tvCount,
        const QosTv *tvList) override
    {
        return SOFTBUS_OK;
    }
    int32_t OnChannelOpened(const char *sessionName, const ChannelInfo *info) override
    {
        return SOFTBUS_OK;
    }
    int32_t OnJoinLNNResult(void *addr, uint32_t addrTypeLen, const char *networkId, int retCode) override
    {
        return SOFTBUS_OK;
    }
    int32_t OnNodeOnlineStateChanged(const char *pkgName, bool isOnline, void *info, uint32_t infoTypeLen) override
    {
        return SOFTBUS_OK;
    }
    int32_t OnNodeBasicInfoChanged(const char *pkgName, void *info, uint32_t infoTypeLen, int32_t type) override
    {
        return SOFTBUS_OK;
    }
    int32_t OnLocalNetworkIdChanged(const char *pkgName) override
    {
        return SOFTBUS_OK;
    }
    int32_t OnTimeSyncResult(const void *info, uint32_t infoTypeLen, int32_t retCode) override
    {
        return SOFTBUS_OK;
    }
    int32_t OnClientTransLimitChange(int32_t channelId, uint8_t tos) override
    {
        return SOFTBUS_OK;
    }
    int32_t OnChannelOpenFailed([[maybe_unused]] int32_t channelId, [[maybe_unused]] int32_t channelType,
        [[maybe_unused]] int32_t errCode) override
    {
        return SOFTBUS_OK;
    }
    int32_t OnChannelBind([[maybe_unused]] int32_t channelId, [[maybe_unused]] int32_t channelType) override
    {
        return SOFTBUS_OK;
    }
    int32_t OnChannelLinkDown([[maybe_unused]] const char *networkId, [[maybe_unused]] int32_t routeType) override
    {
        return SOFTBUS_OK;
    }
    int32_t OnChannelClosed([[maybe_unused]] int32_t channelId, [[maybe_unused]] int32_t channelType,
        [[maybe_unused]] int32_t messageType) override
    {
        return SOFTBUS_OK;
    }
    int32_t OnChannelMsgReceived([[maybe_unused]] int32_t channelId, [[maybe_unused]] int32_t channelType,
        [[maybe_unused]] const void *data, [[maybe_unused]] uint32_t len, [[maybe_unused]] int32_t type) override
    {
        return SOFTBUS_OK;
    }
    int32_t SetChannelInfo([[maybe_unused]]const char *sessionName, [[maybe_unused]] int32_t sessionId,
        [[maybe_unused]] int32_t channelId, [[maybe_unused]] int32_t channelType) override
    {
        return SOFTBUS_OK;
    }
    int32_t OnClientChannelOnQos([[maybe_unused]] int32_t channelId, [[maybe_unused]] int32_t channelType,
        [[maybe_unused]] QoSEvent event, [[maybe_unused]] const QosTV *qos, [[maybe_unused]] uint32_t count) override
    {
        return SOFTBUS_OK;
    }
};

namespace {
sptr<SoftBusClientStubMock> g_stub = nullptr;
sptr<SoftBusClientDeathRecipientMock> g_mock = nullptr;
}

void SoftBusServerProxyFrameTest::SetUpTestCase()
{
    g_stub = new (std::nothrow) SoftBusClientStubMock();
    g_mock = new (std::nothrow) SoftBusClientDeathRecipientMock();
}

void SoftBusServerProxyFrameTest::TearDownTestCase()
{
    g_stub = nullptr;
    g_mock = nullptr;
}

/**
 * @tc.name: InnerRegisterServiceTest
 * @tc.desc: InnerRegisterServiceTest, Initialization failure
 * @tc.desc: InnerRegisterServiceTest, Successful initialization
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, InnerRegisterServiceTest, TestSize.Level1)
{
    EXPECT_EQ(InnerRegisterService(NULL), SOFTBUS_INVALID_PARAM);

    EXPECT_EQ(ServerProxyInit(), SOFTBUS_OK);
    EXPECT_EQ(InitSoftBus("SoftBusServerProxyFrameTest"), SOFTBUS_NO_INIT);
    EXPECT_EQ(InnerRegisterService(NULL), SOFTBUS_TRANS_GET_CLIENT_NAME_FAILED);

    ListNode sessionServerList;
    ListInit(&sessionServerList);
    EXPECT_EQ(InnerRegisterService(&sessionServerList), SOFTBUS_TRANS_GET_CLIENT_NAME_FAILED);
}

/**
 * @tc.name: GetSystemAbilityTest
 * @tc.desc: GetSystemAbilityTest, Get interface return is not empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, GetSystemAbilityTest, TestSize.Level1)
{
    EXPECT_TRUE(GetSystemAbility() != nullptr);
}

/**
 * @tc.name: ClientRegisterServiceTest
 * @tc.desc: ClientRegisterServiceTest, Initializing registration succeeded. Procedure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, ClientRegisterServiceTest, TestSize.Level1)
{
    EXPECT_EQ(ServerProxyInit(), SOFTBUS_OK);
    EXPECT_EQ(ClientRegisterService("ClientRegisterServiceTest"), SOFTBUS_SERVER_NOT_INIT);
}

/**
 * @tc.name: ClientStubInitTest
 * @tc.desc: ClientStubInitTest, Successful initialization
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, ClientStubInitTest, TestSize.Level1)
{
    EXPECT_EQ(ClientStubInit(), SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusRegisterServiceTest
 * @tc.desc: SoftbusRegisterServiceTest, remote is nullptr return SOFTBUS_ERR
 * @tc.desc: SoftbusRegisterServiceTest, SoftbusRegisterService success return SOFTBUS_OK
 * @tc.desc: SoftbusRegisterServiceTest, clientPkgName is nullptr return SOFTBUS_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, SoftbusRegisterServiceTest, TestSize.Level1)
{
    sptr<SoftBusServerProxyFrame> serverProxyFrame = new (std::nothrow) SoftBusServerProxyFrame(nullptr);
    ASSERT_TRUE(serverProxyFrame != nullptr);
    EXPECT_EQ(serverProxyFrame->SoftbusRegisterService("SoftbusRegisterServiceTest", nullptr), SOFTBUS_IPC_ERR);

    sptr<IRemoteObject> serverProxy = GetSystemAbility();
    ASSERT_TRUE(serverProxy != nullptr);
    serverProxyFrame = new (std::nothrow) SoftBusServerProxyFrame(serverProxy);
    ASSERT_TRUE(serverProxyFrame != nullptr);
    EXPECT_EQ(serverProxyFrame->SoftbusRegisterService("SoftbusRegisterServiceTest", nullptr), SOFTBUS_IPC_ERR);

    EXPECT_EQ(serverProxyFrame->SoftbusRegisterService(nullptr, nullptr), SOFTBUS_TRANS_PROXY_WRITECSTRING_FAILED);
}

/**
 * @tc.name: OnRemoteRequestTest
 * @tc.desc: OnRemoteRequestTest, ReadInterfaceToken faild return SOFTBUS_ERR
 * @tc.desc: OnRemoteRequestTest, OnRemoteRequest Call default return IPC_STUB_UNKNOW_TRANS_ERR
 * @tc.desc: OnRemoteRequestTest, OnRemoteRequest Call CLIENT_ON_PERMISSION_CHANGE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, OnRemoteRequestTest, TestSize.Level1)
{
    ASSERT_TRUE(g_stub != nullptr);
    uint32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    EXPECT_EQ(g_stub->OnRemoteRequest(code, data, reply, option), SOFTBUS_TRANS_PROXY_READTOKEN_FAILED);

    data.WriteInterfaceToken(g_stub->GetDescriptor());
    EXPECT_EQ(g_stub->OnRemoteRequest(code, data, reply, option), IPC_STUB_UNKNOW_TRANS_ERR);

    code = CLIENT_ON_PERMISSION_CHANGE;
    data.WriteInterfaceToken(g_stub->GetDescriptor());
    data.WriteInt32(0);
    data.WriteCString("OnRemoteRequestTest");
    EXPECT_EQ(g_stub->OnRemoteRequest(code, data, reply, option), SOFTBUS_OK);
}

/**
 * @tc.name: OnClientPermissonChangeInnerTest
 * @tc.desc: OnClientPermissonChangeInnerTest, ReadInt32 faild return SOFTBUS_ERR
 * @tc.desc: OnClientPermissonChangeInnerTest, ReadCString faild return SOFTBUS_ERR
 * @tc.desc: OnClientPermissonChangeInnerTest, success return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, OnClientPermissonChangeInnerTest, TestSize.Level1)
{
    ASSERT_TRUE(g_stub != nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(g_stub->OnClientPermissonChangeInner(data, reply), SOFTBUS_TRANS_PROXY_READINT_FAILED);

    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnClientPermissonChangeInner(data, reply), SOFTBUS_TRANS_PROXY_READCSTRING_FAILED);

    data.WriteInt32(0);
    data.WriteCString("OnClientPermissonChangeInnerTest");
    EXPECT_EQ(g_stub->OnClientPermissonChangeInner(data, reply), SOFTBUS_OK);
}

/**
 * @tc.name: OnChannelOpenedInnerTest001
 * @tc.desc: OnChannelOpenedInnerTest001, MessageParcel read failed return SOFTBUS_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, OnChannelOpenedInnerTest001, TestSize.Level1)
{
    ASSERT_TRUE(g_stub != nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageParcel tempData;
    EXPECT_EQ(g_stub->OnChannelOpenedInner(data, reply), SOFTBUS_IPC_ERR);

    data.WriteCString("OnChannelOpenedInnerTest");
    EXPECT_EQ(g_stub->OnChannelOpenedInner(data, reply), SOFTBUS_IPC_ERR);

    data.WriteCString("OnChannelOpenedInnerTest");
    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnChannelOpenedInner(data, reply), SOFTBUS_IPC_ERR);

    data.WriteCString("OnChannelOpenedInnerTest");
    data.WriteInt32(0);
    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnChannelOpenedInner(data, reply), SOFTBUS_IPC_ERR);

    data.WriteCString("OnChannelOpenedInnerTest");
    data.WriteInt32(0);
    data.WriteInt32(0);
    data.WriteBool(false);
    EXPECT_EQ(g_stub->OnChannelOpenedInner(data, reply), SOFTBUS_IPC_ERR);

    data.WriteCString("OnChannelOpenedInnerTest");
    data.WriteInt32(0);
    data.WriteInt32(0);
    data.WriteBool(false);
    data.WriteBool(true);
    EXPECT_EQ(g_stub->OnChannelOpenedInner(data, reply), SOFTBUS_IPC_ERR);

    data.WriteCString("OnChannelOpenedInnerTest");
    data.WriteInt32(0);
    data.WriteInt32(0);
    data.WriteBool(false);
    data.WriteBool(true);
    data.WriteBool(false);
    EXPECT_EQ(g_stub->OnChannelOpenedInner(data, reply), SOFTBUS_IPC_ERR);
}

/**
 * @tc.name: OnChannelOpenedInnerTest002
 * @tc.desc: OnChannelOpenedInnerTest002, MessageParcel read failed return SOFTBUS_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, OnChannelOpenedInnerTest002, TestSize.Level1)
{
    ASSERT_TRUE(g_stub != nullptr);
    MessageParcel data;
    MessageParcel reply;

    data.WriteCString("OnChannelOpenedInnerTest");
    data.WriteInt32(0);
    data.WriteInt32(0);
    data.WriteBool(false);
    data.WriteBool(true);
    data.WriteBool(false);
    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnChannelOpenedInner(data, reply), SOFTBUS_IPC_ERR);

    data.WriteCString("OnChannelOpenedInnerTest");
    data.WriteInt32(0);
    data.WriteInt32(0);
    data.WriteBool(false);
    data.WriteBool(true);
    data.WriteBool(false);
    data.WriteInt32(0);
    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnChannelOpenedInner(data, reply), SOFTBUS_IPC_ERR);

    data.WriteCString("OnChannelOpenedInnerTest");
    data.WriteInt32(0);
    data.WriteInt32(0);
    data.WriteBool(false);
    data.WriteBool(true);
    data.WriteBool(false);
    data.WriteInt32(0);
    data.WriteInt32(0);
    data.WriteCString("OnChannelOpenedInnerTest");
    EXPECT_EQ(g_stub->OnChannelOpenedInner(data, reply), SOFTBUS_IPC_ERR);
}

/**
 * @tc.name: OnChannelOpenFailedInnerTest
 * @tc.desc: OnChannelOpenFailedInnerTest, ReadInt32 failed return SOFTBUS_ERR
 * @tc.desc: OnChannelOpenFailedInnerTest, success return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, OnChannelOpenFailedInnerTest, TestSize.Level1)
{
    ASSERT_TRUE(g_stub != nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(g_stub->OnChannelOpenFailedInner(data, reply), SOFTBUS_TRANS_PROXY_READINT_FAILED);

    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnChannelOpenFailedInner(data, reply), SOFTBUS_TRANS_PROXY_READINT_FAILED);

    data.WriteInt32(0);
    data.WriteInt32(99);
    EXPECT_EQ(g_stub->OnChannelOpenFailedInner(data, reply), SOFTBUS_TRANS_PROXY_READINT_FAILED);

    data.WriteInt32(0);
    data.WriteInt32(0);
    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnChannelOpenFailedInner(data, reply), SOFTBUS_OK);
}

/**
 * @tc.name: OnChannelLinkDownInnerTest
 * @tc.desc: OnChannelLinkDownInnerTest, ReadCString failed return SOFTBUS_ERR
 * @tc.desc: OnChannelLinkDownInnerTest, ReadInt32 failed return SOFTBUS_ERR
 * @tc.desc: OnChannelLinkDownInnerTest, success return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, OnChannelLinkDownInnerTest, TestSize.Level1)
{
    ASSERT_TRUE(g_stub != nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(g_stub->OnChannelLinkDownInner(data, reply), SOFTBUS_TRANS_PROXY_READCSTRING_FAILED);

    data.WriteCString("OnChannelLinkDownInnerTest");
    EXPECT_EQ(g_stub->OnChannelLinkDownInner(data, reply), SOFTBUS_TRANS_PROXY_READINT_FAILED);

    data.WriteCString("OnChannelLinkDownInnerTest");
    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnChannelLinkDownInner(data, reply), SOFTBUS_OK);
}

/**
 * @tc.name: OnChannelClosedInnerTest
 * @tc.desc: OnChannelClosedInnerTest, ReadInt32 failed return SOFTBUS_ERR
 * @tc.desc: OnChannelClosedInnerTest, success return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, OnChannelClosedInnerTest, TestSize.Level1)
{
    ASSERT_TRUE(g_stub != nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(g_stub->OnChannelClosedInner(data, reply), SOFTBUS_IPC_ERR);

    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnChannelClosedInner(data, reply), SOFTBUS_IPC_ERR);

    data.WriteInt32(0);
    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnChannelClosedInner(data, reply), SOFTBUS_IPC_ERR);
}

/**
 * @tc.name: OnChannelMsgReceivedInnerTest
 * @tc.desc: OnChannelMsgReceivedInnerTest, MessageParcel failed return SOFTBUS_ERR
 * @tc.desc: OnChannelMsgReceivedInnerTest, success return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, OnChannelMsgReceivedInnerTest, TestSize.Level1)
{
    ASSERT_TRUE(g_stub != nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(g_stub->OnChannelMsgReceivedInner(data, reply), SOFTBUS_TRANS_PROXY_READINT_FAILED);

    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnChannelMsgReceivedInner(data, reply), SOFTBUS_TRANS_PROXY_READINT_FAILED);

    data.WriteInt32(0);
    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnChannelMsgReceivedInner(data, reply), SOFTBUS_TRANS_PROXY_READUINT_FAILED);

    data.WriteInt32(0);
    data.WriteInt32(0);
    data.WriteUint32(0);
    EXPECT_EQ(g_stub->OnChannelMsgReceivedInner(data, reply), SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED);

    std::string buffer = "OnChannelMsgReceivedInnerTest";
    data.WriteInt32(0);
    data.WriteInt32(0);
    data.WriteUint32(buffer.size());
    data.WriteRawData(buffer.c_str(), buffer.size());
    EXPECT_EQ(g_stub->OnChannelMsgReceivedInner(data, reply), SOFTBUS_TRANS_PROXY_READINT_FAILED);

    data.WriteInt32(0);
    data.WriteInt32(0);
    data.WriteUint32(buffer.size());
    data.WriteRawData(buffer.c_str(), buffer.size());
    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnChannelMsgReceivedInner(data, reply), SOFTBUS_OK);
}

/**
 * @tc.name: ISoftBusClientTest001
 * @tc.desc: ISoftBusClientTest, use normal or wrong param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, ISoftBusClientTest001, TestSize.Level1)
{
    ASSERT_TRUE(g_stub != nullptr);
    int32_t testInt = 0;
    uint32_t testUint = 0;
    g_stub->OnPublishLNNResult(testInt, testInt);
    g_stub->OnRefreshLNNResult(testInt, testInt);
    g_stub->OnRefreshDeviceFound(nullptr, testUint);
    g_stub->OnDataLevelChanged(nullptr, nullptr);
    int32_t ret = g_stub->OnChannelOpened(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_stub->OnChannelOpenFailed(testInt, testInt, testInt);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_stub->OnChannelLinkDown(nullptr, testInt);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_stub->OnChannelMsgReceived(testInt, testInt, nullptr, testUint, testInt);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_stub->OnChannelClosed(testInt, testInt, testInt);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_stub->OnChannelQosEvent(testInt, testInt, testInt, testInt, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_stub->SetChannelInfo(nullptr, testInt, testInt, testInt);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_stub->OnJoinLNNResult(nullptr, testUint, nullptr, testInt);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_stub->OnNodeOnlineStateChanged(nullptr, true, nullptr, testUint);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_stub->OnNodeBasicInfoChanged(nullptr, nullptr, testUint, testInt);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_stub->OnLocalNetworkIdChanged(nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_stub->OnTimeSyncResult(nullptr, testUint, testInt);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_stub->OnClientTransLimitChange(testInt, testUint);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_stub->OnChannelBind(testInt, testInt);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = g_stub->OnClientChannelOnQos(testInt, testInt, QOS_SATISFIED, nullptr, testUint);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: OnRemoteDiedTest
 * @tc.desc: OnRemoteDiedTest, use normal or wrong param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, OnRemoteDiedTest, TestSize.Level1)
{
    ASSERT_TRUE(g_mock != nullptr);
    g_mock->OnRemoteDied(nullptr);
}
} // namespace OHOS
