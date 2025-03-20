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
    EXPECT_EQ(InnerRegisterService(nullptr), SOFTBUS_INVALID_PARAM);

    EXPECT_EQ(ServerProxyInit(), SOFTBUS_OK);
    EXPECT_EQ(InitSoftBus("SoftBusServerProxyFrameTest"), SOFTBUS_NO_INIT);
    EXPECT_EQ(InnerRegisterService(nullptr), SOFTBUS_TRANS_GET_CLIENT_NAME_FAILED);

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
 * @tc.name: OnClientTransLimitChangeInnerTest
 * @tc.desc: OnClientTransLimitChangeInnerTest, ReadInt32 faild return SOFTBUS_ERR
 * @tc.desc: OnClientTransLimitChangeInnerTest, ReadCString faild return SOFTBUS_ERR
 * @tc.desc: OnClientTransLimitChangeInnerTest, success return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, OnClientTransLimitChangeInnerTest, TestSize.Level1)
{
    ASSERT_TRUE(g_stub != nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(g_stub->OnClientTransLimitChangeInner(data, reply), SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED);

    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnClientTransLimitChangeInner(data, reply), SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED);

    data.WriteInt32(0);
    data.WriteUint8(0);
    EXPECT_EQ(g_stub->OnClientTransLimitChangeInner(data, reply), SOFTBUS_OK);

    int32_t ret = g_stub->OnClientTransLimitChange(0, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: OnChannelQosEventInnerTest
 * @tc.desc: OnChannelQosEventInnerTest, ReadInt32 faild return SOFTBUS_ERR
 * @tc.desc: OnChannelQosEventInnerTest, ReadCString faild return SOFTBUS_ERR
 * @tc.desc: OnChannelQosEventInnerTest, success return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, OnChannelQosEventInnerTest, TestSize.Level1)
{
    ASSERT_TRUE(g_stub != nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(g_stub->OnChannelQosEventInner(data, reply), SOFTBUS_TRANS_PROXY_READINT_FAILED);

    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnChannelQosEventInner(data, reply), SOFTBUS_TRANS_PROXY_READINT_FAILED);

    data.WriteInt32(0);
    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnChannelQosEventInner(data, reply), SOFTBUS_TRANS_PROXY_READINT_FAILED);

    data.WriteInt32(0);
    data.WriteInt32(0);
    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnChannelQosEventInner(data, reply), SOFTBUS_TRANS_PROXY_READINT_FAILED);

    std::string buffer = "OnChannelQosEventInnerTest";
    data.WriteInt32(0);
    data.WriteInt32(0);
    data.WriteInt32(0);
    data.WriteInt32(1); // test value
    data.WriteRawData(buffer.c_str(), buffer.size());
    EXPECT_EQ(g_stub->OnChannelQosEventInner(data, reply), SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED);

    data.WriteInt32(0);
    data.WriteInt32(0);
    data.WriteInt32(0);
    data.WriteInt32(1); // test value
    data.WriteRawData(buffer.c_str(), buffer.size());
    data.WriteInt32(0);
    EXPECT_NE(g_stub->OnChannelQosEventInner(data, reply), SOFTBUS_OK);
}

/**
 * @tc.name: OnChannelOnQosInnerTest
 * @tc.desc: OnChannelOnQosInnerTest, ReadInt32 faild return SOFTBUS_ERR
 * @tc.desc: OnChannelOnQosInnerTest, ReadCString faild return SOFTBUS_ERR
 * @tc.desc: OnChannelOnQosInnerTest, success return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, OnChannelOnQosInnerTest, TestSize.Level1)
{
    ASSERT_TRUE(g_stub != nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(g_stub->OnChannelOnQosInner(data, reply), SOFTBUS_TRANS_PROXY_READINT_FAILED);

    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnChannelOnQosInner(data, reply), SOFTBUS_TRANS_PROXY_READINT_FAILED);

    data.WriteInt32(0);
    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnChannelOnQosInner(data, reply), SOFTBUS_TRANS_PROXY_READINT_FAILED);

    data.WriteInt32(0);
    data.WriteInt32(0);
    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnChannelOnQosInner(data, reply), SOFTBUS_TRANS_PROXY_READINT_FAILED);

    data.WriteInt32(0);
    data.WriteInt32(0);
    data.WriteInt32(0);
    data.WriteUint32(11); // test value
    EXPECT_EQ(g_stub->OnChannelOnQosInner(data, reply), SOFTBUS_INVALID_PARAM);

    data.WriteInt32(0);
    data.WriteInt32(0);
    data.WriteInt32(0);
    data.WriteUint32(1); // test value
    EXPECT_EQ(g_stub->OnChannelOnQosInner(data, reply), SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED);

    std::string buffer = "OnChannelOnQosInnerTest";
    data.WriteInt32(0);
    data.WriteInt32(0);
    data.WriteInt32(0);
    data.WriteUint32(1); // test value
    data.WriteRawData(buffer.c_str(), buffer.size());
    EXPECT_EQ(g_stub->OnChannelOnQosInner(data, reply), SOFTBUS_OK);
}

/**
 * @tc.name: SetChannelInfoInnerTest
 * @tc.desc: SetChannelInfoInnerTest, ReadInt32 faild return SOFTBUS_ERR
 * @tc.desc: SetChannelInfoInnerTest, ReadCString faild return SOFTBUS_ERR
 * @tc.desc: SetChannelInfoInnerTest, success return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, SetChannelInfoInnerTest, TestSize.Level1)
{
    ASSERT_TRUE(g_stub != nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(g_stub->SetChannelInfoInner(data, reply), SOFTBUS_IPC_ERR);

    data.WriteCString("SetChannelInfoInnerTest");
    EXPECT_EQ(g_stub->SetChannelInfoInner(data, reply), SOFTBUS_IPC_ERR);

    data.WriteCString("SetChannelInfoInnerTest");
    data.WriteInt32(0);
    EXPECT_EQ(g_stub->SetChannelInfoInner(data, reply), SOFTBUS_IPC_ERR);

    data.WriteCString("SetChannelInfoInnerTest");
    data.WriteInt32(0);
    data.WriteInt32(0);
    EXPECT_EQ(g_stub->SetChannelInfoInner(data, reply), SOFTBUS_IPC_ERR);

    data.WriteCString("SetChannelInfoInnerTest");
    data.WriteInt32(0);
    data.WriteInt32(0);
    data.WriteInt32(0);
    EXPECT_EQ(g_stub->SetChannelInfoInner(data, reply), SOFTBUS_OK);
}

/**
 * @tc.name: OnLeaveLNNResultInnerTest
 * @tc.desc: OnLeaveLNNResultInnerTest, ReadInt32 faild return SOFTBUS_ERR
 * @tc.desc: OnLeaveLNNResultInnerTest, ReadCString faild return SOFTBUS_ERR
 * @tc.desc: OnLeaveLNNResultInnerTest, success return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, OnLeaveLNNResultInnerTest, TestSize.Level1)
{
    ASSERT_TRUE(g_stub != nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(g_stub->OnLeaveLNNResultInner(data, reply), SOFTBUS_TRANS_PROXY_READCSTRING_FAILED);

    data.WriteCString("OnLeaveLNNResultInnerTest");
    EXPECT_EQ(g_stub->OnLeaveLNNResultInner(data, reply), SOFTBUS_TRANS_PROXY_READINT_FAILED);

    data.WriteCString("OnLeaveLNNResultInnerTest");
    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnLeaveLNNResultInner(data, reply), SOFTBUS_OK);
}

/**
 * @tc.name: OnNodeOnlineStateChangedInnerTest
 * @tc.desc: OnNodeOnlineStateChangedInnerTest, ReadInt32 faild return SOFTBUS_ERR
 * @tc.desc: OnNodeOnlineStateChangedInnerTest, ReadCString faild return SOFTBUS_ERR
 * @tc.desc: OnNodeOnlineStateChangedInnerTest, success return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, OnNodeOnlineStateChangedInnerTest, TestSize.Level1)
{
    ASSERT_TRUE(g_stub != nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(g_stub->OnNodeOnlineStateChangedInner(data, reply), SOFTBUS_TRANS_PROXY_READCSTRING_FAILED);

    data.WriteCString("OnNodeOnlineStateChangedInnerTest");
    EXPECT_EQ(g_stub->OnNodeOnlineStateChangedInner(data, reply), SOFTBUS_TRANS_PROXY_READBOOL_FAILED);

    data.WriteCString("OnNodeOnlineStateChangedInnerTest");
    data.WriteBool(false);
    EXPECT_EQ(g_stub->OnNodeOnlineStateChangedInner(data, reply), SOFTBUS_TRANS_PROXY_READUINT_FAILED);

    data.WriteCString("OnNodeOnlineStateChangedInnerTest");
    data.WriteBool(false);
    data.WriteUint32(sizeof(NodeBasicInfo));
    EXPECT_EQ(g_stub->OnNodeOnlineStateChangedInner(data, reply), SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED);

    std::string buffer = "OnNodeOnlineStateChangedInnerTest";
    data.WriteCString("OnNodeOnlineStateChangedInnerTest");
    data.WriteBool(false);
    data.WriteUint32(sizeof(NodeBasicInfo));
    data.WriteRawData(buffer.c_str(), buffer.size());
    EXPECT_EQ(g_stub->OnNodeOnlineStateChangedInner(data, reply), SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED);
}

/**
 * @tc.name: OnNodeStatusChangedInnerTest
 * @tc.desc: OnNodeStatusChangedInnerTest, ReadInt32 faild return SOFTBUS_ERR
 * @tc.desc: OnNodeStatusChangedInnerTest, ReadCString faild return SOFTBUS_ERR
 * @tc.desc: OnNodeStatusChangedInnerTest, success return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, OnNodeStatusChangedInnerTest, TestSize.Level1)
{
    ASSERT_TRUE(g_stub != nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(g_stub->OnNodeStatusChangedInner(data, reply), SOFTBUS_INVALID_PARAM);

    data.WriteCString("OnNodeStatusChangedInnerTest");
    EXPECT_EQ(g_stub->OnNodeStatusChangedInner(data, reply), SOFTBUS_NETWORK_READINT32_FAILED);

    data.WriteCString("OnNodeStatusChangedInnerTest");
    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnNodeStatusChangedInner(data, reply), SOFTBUS_NETWORK_READINT32_FAILED);

    data.WriteCString("OnNodeStatusChangedInnerTest");
    data.WriteInt32(0);
    data.WriteUint32(sizeof(NodeStatus));
    EXPECT_EQ(g_stub->OnNodeStatusChangedInner(data, reply), SOFTBUS_NETWORK_READRAWDATA_FAILED);

    std::string buffer = "OnNodeStatusChangedInnerTest";
    data.WriteCString("OnNodeStatusChangedInnerTest");
    data.WriteInt32(0);
    data.WriteUint32(sizeof(NodeStatus));
    data.WriteRawData(buffer.c_str(), buffer.size());
    EXPECT_EQ(g_stub->OnNodeStatusChangedInner(data, reply), SOFTBUS_NETWORK_READINT32_FAILED);
}

/**
 * @tc.name: OnNodeBasicInfoChangedInnerTest
 * @tc.desc: OnNodeBasicInfoChangedInnerTest, ReadInt32 faild return SOFTBUS_ERR
 * @tc.desc: OnNodeBasicInfoChangedInnerTest, ReadCString faild return SOFTBUS_ERR
 * @tc.desc: OnNodeBasicInfoChangedInnerTest, success return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, OnNodeBasicInfoChangedInnerTest, TestSize.Level1)
{
    ASSERT_TRUE(g_stub != nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(g_stub->OnNodeBasicInfoChangedInner(data, reply), SOFTBUS_TRANS_PROXY_READCSTRING_FAILED);

    data.WriteCString("OnNodeBasicInfoChangedInnerTest");
    EXPECT_EQ(g_stub->OnNodeBasicInfoChangedInner(data, reply), SOFTBUS_TRANS_PROXY_READINT_FAILED);

    data.WriteCString("OnNodeBasicInfoChangedInnerTest");
    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnNodeBasicInfoChangedInner(data, reply), SOFTBUS_TRANS_PROXY_READUINT_FAILED);

    data.WriteCString("OnNodeBasicInfoChangedInnerTest");
    data.WriteInt32(0);
    data.WriteUint32(sizeof(NodeBasicInfo));
    EXPECT_EQ(g_stub->OnNodeBasicInfoChangedInner(data, reply), SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED);

    std::string buffer = "OnNodeBasicInfoChangedInnerTest";
    data.WriteCString("OnNodeBasicInfoChangedInnerTest");
    data.WriteInt32(0);
    data.WriteUint32(sizeof(NodeBasicInfo));
    data.WriteRawData(buffer.c_str(), buffer.size());
    EXPECT_EQ(g_stub->OnNodeBasicInfoChangedInner(data, reply), SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED);
}

/**
 * @tc.name: OnLocalNetworkIdChangedInnerTest
 * @tc.desc: OnLocalNetworkIdChangedInnerTest, ReadInt32 faild return SOFTBUS_ERR
 * @tc.desc: OnLocalNetworkIdChangedInnerTest, ReadCString faild return SOFTBUS_ERR
 * @tc.desc: OnLocalNetworkIdChangedInnerTest, success return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, OnLocalNetworkIdChangedInnerTest, TestSize.Level1)
{
    ASSERT_TRUE(g_stub != nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(g_stub->OnLocalNetworkIdChangedInner(data, reply), SOFTBUS_INVALID_PARAM);

    data.WriteCString("OnLocalNetworkIdChangedInnerTest");
    EXPECT_EQ(g_stub->OnLocalNetworkIdChangedInner(data, reply), SOFTBUS_OK);

    data.WriteCString("OnLocalNetworkIdChangedInnerTest");
    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnLocalNetworkIdChangedInner(data, reply), SOFTBUS_OK);
}

/**
 * @tc.name: OnNodeDeviceTrustedChangeInnerTest
 * @tc.desc: OnNodeDeviceTrustedChangeInnerTest, ReadInt32 faild return SOFTBUS_ERR
 * @tc.desc: OnNodeDeviceTrustedChangeInnerTest, ReadCString faild return SOFTBUS_ERR
 * @tc.desc: OnNodeDeviceTrustedChangeInnerTest, success return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, OnNodeDeviceTrustedChangeInnerTest, TestSize.Level1)
{
    ASSERT_TRUE(g_stub != nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(g_stub->OnNodeDeviceTrustedChangeInner(data, reply), SOFTBUS_INVALID_PARAM);

    data.WriteCString("OnNodeDeviceTrustedChangeInnerTest");
    EXPECT_EQ(g_stub->OnNodeDeviceTrustedChangeInner(data, reply), SOFTBUS_TRANS_PROXY_READINT_FAILED);

    data.WriteCString("OnNodeDeviceTrustedChangeInnerTest");
    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnNodeDeviceTrustedChangeInner(data, reply), SOFTBUS_TRANS_PROXY_READCSTRING_FAILED);

    data.WriteCString("OnNodeDeviceTrustedChangeInnerTest");
    data.WriteInt32(0);
    data.WriteCString("OnNodeDeviceTrustedChangeInnerTest1");
    EXPECT_EQ(g_stub->OnNodeDeviceTrustedChangeInner(data, reply), SOFTBUS_TRANS_PROXY_READINT_FAILED);

    data.WriteCString("OnNodeDeviceTrustedChangeInnerTest");
    data.WriteInt32(0);
    data.WriteCString("OnNodeDeviceTrustedChangeInnerTest1");
    data.WriteUint32(0);
    EXPECT_EQ(g_stub->OnNodeDeviceTrustedChangeInner(data, reply), SOFTBUS_OK);

    data.WriteCString("OnNodeDeviceTrustedChangeInnerTest");
    data.WriteInt32(0);
    data.WriteCString("OnNodeDeviceTrustedChangeInnerTest1");
    data.WriteUint32(0);
    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnNodeDeviceTrustedChangeInner(data, reply), SOFTBUS_OK);
}

/**
 * @tc.name: OnHichainProofExceptionInnerTest
 * @tc.desc: OnHichainProofExceptionInnerTest, ReadInt32 faild return SOFTBUS_ERR
 * @tc.desc: OnHichainProofExceptionInnerTest, ReadCString faild return SOFTBUS_ERR
 * @tc.desc: OnHichainProofExceptionInnerTest, success return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, OnHichainProofExceptionInnerTest, TestSize.Level1)
{
    ASSERT_TRUE(g_stub != nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(g_stub->OnHichainProofExceptionInner(data, reply), SOFTBUS_INVALID_PARAM);

    data.WriteCString("OnHichainProofExceptionInnerTest");
    EXPECT_EQ(g_stub->OnHichainProofExceptionInner(data, reply), SOFTBUS_NETWORK_PROXY_READINT_FAILED);

    data.WriteCString("OnHichainProofExceptionInnerTest");
    data.WriteUint32(1);
    EXPECT_EQ(g_stub->OnHichainProofExceptionInner(data, reply), SOFTBUS_NETWORK_READRAWDATA_FAILED);

    std::string buffer = "OnHichainProofExceptionInnerTest";
    data.WriteCString("OnHichainProofExceptionInnerTest");
    data.WriteUint32(1);
    data.WriteRawData(buffer.c_str(), 1);
    EXPECT_EQ(g_stub->OnHichainProofExceptionInner(data, reply), SOFTBUS_NETWORK_PROXY_READINT_FAILED);

    buffer = "OnHichainProofExceptionInnerTest";
    data.WriteCString("OnHichainProofExceptionInnerTest");
    data.WriteUint32(1);
    data.WriteRawData(buffer.c_str(), 1);
    data.WriteUint16(0);
    EXPECT_EQ(g_stub->OnHichainProofExceptionInner(data, reply), SOFTBUS_NETWORK_PROXY_READINT_FAILED);

    buffer = "OnHichainProofExceptionInnerTest";
    data.WriteCString("OnHichainProofExceptionInnerTest");
    data.WriteUint32(1);
    data.WriteRawData(buffer.c_str(), 1);
    data.WriteUint16(0);
    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnHichainProofExceptionInner(data, reply), SOFTBUS_OK);
}

/**
 * @tc.name: OnTimeSyncResultInnerTest
 * @tc.desc: OnTimeSyncResultInnerTest, ReadInt32 faild return SOFTBUS_ERR
 * @tc.desc: OnTimeSyncResultInnerTest, ReadCString faild return SOFTBUS_ERR
 * @tc.desc: OnTimeSyncResultInnerTest, success return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, OnTimeSyncResultInnerTest, TestSize.Level1)
{
    ASSERT_TRUE(g_stub != nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(g_stub->OnTimeSyncResultInner(data, reply), SOFTBUS_TRANS_PROXY_READUINT_FAILED);

    data.WriteInt32(sizeof(TimeSyncResultInfo));
    EXPECT_EQ(g_stub->OnTimeSyncResultInner(data, reply), SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED);

    std::string buffer = "OnTimeSyncResultInnerTest";
    data.WriteInt32(sizeof(TimeSyncResultInfo));
    data.WriteRawData(buffer.c_str(), sizeof(TimeSyncResultInfo));
    EXPECT_EQ(g_stub->OnTimeSyncResultInner(data, reply), SOFTBUS_TRANS_PROXY_READINT_FAILED);

    buffer = "OnTimeSyncResultInnerTest";
    data.WriteInt32(sizeof(TimeSyncResultInfo));
    data.WriteRawData(buffer.c_str(), sizeof(TimeSyncResultInfo));
    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnTimeSyncResultInner(data, reply), SOFTBUS_OK);
}

/**
 * @tc.name: OnPublishLNNResultInnerTest
 * @tc.desc: OnPublishLNNResultInnerTest, ReadInt32 faild return SOFTBUS_ERR
 * @tc.desc: OnPublishLNNResultInnerTest, ReadCString faild return SOFTBUS_ERR
 * @tc.desc: OnPublishLNNResultInnerTest, success return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, OnPublishLNNResultInnerTest, TestSize.Level1)
{
    ASSERT_TRUE(g_stub != nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(g_stub->OnPublishLNNResultInner(data, reply), SOFTBUS_TRANS_PROXY_READINT_FAILED);

    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnPublishLNNResultInner(data, reply), SOFTBUS_TRANS_PROXY_READINT_FAILED);

    std::string buffer = "OnPublishLNNResultInnerTest";
    data.WriteInt32(0);
    data.WriteRawData(buffer.c_str(), buffer.size());
    EXPECT_EQ(g_stub->OnPublishLNNResultInner(data, reply), SOFTBUS_OK);
}

/**
 * @tc.name: OnRefreshLNNResultInnerTest
 * @tc.desc: OnRefreshLNNResultInnerTest, ReadInt32 faild return SOFTBUS_ERR
 * @tc.desc: OnRefreshLNNResultInnerTest, ReadCString faild return SOFTBUS_ERR
 * @tc.desc: OnRefreshLNNResultInnerTest, success return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, OnRefreshLNNResultInnerTest, TestSize.Level1)
{
    ASSERT_TRUE(g_stub != nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(g_stub->OnRefreshLNNResultInner(data, reply), SOFTBUS_TRANS_PROXY_READINT_FAILED);

    data.WriteInt32(sizeof(DeviceInfo));
    EXPECT_EQ(g_stub->OnRefreshLNNResultInner(data, reply), SOFTBUS_TRANS_PROXY_READINT_FAILED);

    data.WriteInt32(0);
    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnRefreshLNNResultInner(data, reply), SOFTBUS_OK);
}

/**
 * @tc.name: OnRefreshDeviceFoundInnerTest
 * @tc.desc: OnRefreshDeviceFoundInnerTest, ReadInt32 faild return SOFTBUS_ERR
 * @tc.desc: OnRefreshDeviceFoundInnerTest, ReadCString faild return SOFTBUS_ERR
 * @tc.desc: OnRefreshDeviceFoundInnerTest, success return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, OnRefreshDeviceFoundInnerTest, TestSize.Level1)
{
    ASSERT_TRUE(g_stub != nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(g_stub->OnRefreshDeviceFoundInner(data, reply), SOFTBUS_TRANS_PROXY_READUINT_FAILED);

    data.WriteInt32(sizeof(DeviceInfo));
    EXPECT_EQ(g_stub->OnRefreshDeviceFoundInner(data, reply), SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED);

    std::string buffer = "OnRefreshDeviceFoundInnerTest";
    data.WriteInt32(sizeof(DeviceInfo));
    data.WriteRawData(buffer.c_str(), sizeof(DeviceInfo));
    EXPECT_EQ(g_stub->OnRefreshDeviceFoundInner(data, reply), SOFTBUS_OK);
}

/**
 * @tc.name: OnDataLevelChangedInnerTest
 * @tc.desc: OnDataLevelChangedInnerTest, ReadInt32 faild return SOFTBUS_ERR
 * @tc.desc: OnDataLevelChangedInnerTest, ReadCString faild return SOFTBUS_ERR
 * @tc.desc: OnDataLevelChangedInnerTest, success return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, OnDataLevelChangedInnerTest, TestSize.Level1)
{
    ASSERT_TRUE(g_stub != nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(g_stub->OnDataLevelChangedInner(data, reply), SOFTBUS_TRANS_PROXY_READCSTRING_FAILED);

    data.WriteCString("OnDataLevelChangedInnerTest");
    EXPECT_EQ(g_stub->OnDataLevelChangedInner(data, reply), SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED);

    std::string buffer = "OnDataLevelChangedInnerTest";
    data.WriteCString("OnDataLevelChangedInnerTest");
    data.WriteRawData(buffer.c_str(), sizeof(DataLevelInfo));
    EXPECT_EQ(g_stub->OnDataLevelChangedInner(data, reply), SOFTBUS_OK);
}

/**
 * @tc.name: OnRangeResultInnerTest
 * @tc.desc: OnRangeResultInnerTest, ReadInt32 faild return SOFTBUS_ERR
 * @tc.desc: OnRangeResultInnerTest, ReadCString faild return SOFTBUS_ERR
 * @tc.desc: OnRangeResultInnerTest, success return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, OnRangeResultInnerTest, TestSize.Level1)
{
    ASSERT_TRUE(g_stub != nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(g_stub->OnMsdpRangeResultInner(data, reply), SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED);

    RangeResultInnerInfo innerIInnfo1 = { .length = 0, };
    data.WriteRawData(&innerIInnfo1, sizeof(RangeResultInnerInfo));
    EXPECT_EQ(g_stub->OnMsdpRangeResultInner(data, reply), SOFTBUS_OK);

    RangeResultInnerInfo temp;
    RangeResultInnerInfo innerIInnfo2 = { .length = sizeof(temp), .addition = (uint8_t *)&temp };
    data.WriteRawData(&innerIInnfo2, sizeof(RangeResultInnerInfo));
    data.WriteRawData(&temp, sizeof(temp));
    EXPECT_EQ(g_stub->OnMsdpRangeResultInner(data, reply), SOFTBUS_OK);
}

/**
 * @tc.name: OnChannelBindInnerTest
 * @tc.desc: OnChannelBindInnerTest, ReadInt32 faild return SOFTBUS_ERR
 * @tc.desc: OnChannelBindInnerTest, ReadCString faild return SOFTBUS_ERR
 * @tc.desc: OnChannelBindInnerTest, success return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, OnChannelBindInnerTest, TestSize.Level1)
{
    ASSERT_TRUE(g_stub != nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(g_stub->OnChannelBindInner(data, reply), SOFTBUS_IPC_ERR);

    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnChannelBindInner(data, reply), SOFTBUS_IPC_ERR);

    data.WriteInt32(0);
    data.WriteInt32(0);
    EXPECT_EQ(g_stub->OnChannelBindInner(data, reply), SOFTBUS_OK);
}

/**
 * @tc.name: OnCheckCollabRelationTest
 * @tc.desc: OnCheckCollabRelationTest, ReadInt32 faild return SOFTBUS_ERR
 * @tc.desc: OnCheckCollabRelationTest, ReadCString faild return SOFTBUS_ERR
 * @tc.desc: OnCheckCollabRelationTest, success return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, OnCheckCollabRelationTest, TestSize.Level1)
{
    ASSERT_TRUE(g_stub != nullptr);
    int32_t ret = g_stub->OnCheckCollabRelation(nullptr, true, nullptr, 0, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    CollabInfo *sourceInfo = static_cast<CollabInfo *>(SoftBusCalloc(sizeof(CollabInfo)));
    EXPECT_NE(nullptr, sourceInfo);

    CollabInfo *sinkInfo = static_cast<CollabInfo *>(SoftBusCalloc(sizeof(CollabInfo)));
    EXPECT_NE(nullptr, sinkInfo);

    ret = g_stub->OnCheckCollabRelation(sourceInfo, true, sinkInfo, 0, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sourceInfo);
    SoftBusFree(sinkInfo);
}

/**
 * @tc.name: OnClientChannelOnQosTest
 * @tc.desc: OnClientChannelOnQosTest, ReadInt32 faild return SOFTBUS_ERR
 * @tc.desc: OnClientChannelOnQosTest, ReadCString faild return SOFTBUS_ERR
 * @tc.desc: OnClientChannelOnQosTest, success return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusServerProxyFrameTest, OnClientChannelOnQosTest, TestSize.Level1)
{
    ASSERT_TRUE(g_stub != nullptr);
    int32_t ret = g_stub->OnClientChannelOnQos(0, 0, static_cast<QoSEvent>(-1), nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = g_stub->OnClientChannelOnQos(0, 0, static_cast<QoSEvent>(5), nullptr, 0); // test value
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = g_stub->OnClientChannelOnQos(0, 0, QOS_SATISFIED, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    QosTV *qos = static_cast<QosTV *>(SoftBusCalloc(sizeof(QosTV)));
    EXPECT_NE(nullptr, qos);

    ret = g_stub->OnClientChannelOnQos(0, 0, QOS_SATISFIED, qos, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = g_stub->OnClientChannelOnQos(0, 0, QOS_SATISFIED, qos, 1);
    EXPECT_NE(ret, SOFTBUS_OK);
    SoftBusFree(qos);
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
