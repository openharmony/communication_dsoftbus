/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

#define protected public
#define private public
#include "i_stream.h"
#include "softbus_stream_test_mock.h"
#include "stream_common.h"
#include "vtp_stream_socket.h"
#include "vtp_stream_socket.cpp"
#undef private
#undef protected

using namespace Communication;
using namespace SoftBus;
using namespace testing::ext;
namespace OHOS {
#define TEST_SESSION_NAME "com.softbus.transmission.test"
#define TEST_CONN_IP "192.168.8.1"
#define TEST_AUTH_PORT 6000
#define TEST_AUTH_DATA "test auth message data"
#define TEST_MESSAGE "testMessage"
#define DEVICE_ID "DEVICE_ID"
#define STREAM_DATA_LENGTH   10
#define SESSION_NAME_MAX_LEN 256
#define PKG_NAME_SIZE_MAX_LEN 65
#define FRAME_HEADER_LEN 4

Communication::SoftBus::StreamData streamData = {
    .buffer = std::make_unique<char[]>(1),
    .bufLen = 1,
    .extBuffer = nullptr,
    .extLen = 0,
};

Communication::SoftBus::StreamFrameInfo frameInfo = {
    .streamId = 1,
    .seqNum = 1,
    .level = 1,
    .frameType = FrameType::RADIO_MAX,
    .seqSubNum = 1,
    .bitMap = 1,
    .bitrate = 0,
};

class VtpStreamSocketTest : public testing::Test {
public:
    VtpStreamSocketTest()
    {}
    ~VtpStreamSocketTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void VtpStreamSocketTest::SetUpTestCase(void)
{}

void VtpStreamSocketTest::TearDownTestCase(void)
{}

/**
 * @tc.name: CreateClient001
 * @tc.desc: CreateClient, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, CreateClient001, TestSize.Level1)
{
    Communication::SoftBus::IpAndPort *local =
        (Communication::SoftBus::IpAndPort *)SoftBusCalloc(sizeof(Communication::SoftBus::IpAndPort));
    ASSERT_TRUE(local != nullptr);

    std::pair<uint8_t*, uint32_t> sessionKey = std::make_pair(nullptr, 0);

    int32_t streamType = 2112;

    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();

    bool ret = vtpStreamSocket->CreateClient(*local, streamType, sessionKey);
    EXPECT_EQ(false, ret);

    local->ip = "10.50.140.1";
    local->port = 1000;
    ret = vtpStreamSocket->CreateClient(*local, streamType, sessionKey);
    vtpStreamSocket->DestroyStreamSocket();
    EXPECT_EQ(false, ret);

    if (local != nullptr) {
        SoftBusFree(local);
    }
}

/**
 * @tc.name: CreateClient002
 * @tc.desc: CreateClient002, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, CreateClient002, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();

    Communication::SoftBus::IpAndPort *local =
        (Communication::SoftBus::IpAndPort *)SoftBusCalloc(sizeof(Communication::SoftBus::IpAndPort));
    ASSERT_TRUE(local != nullptr);

    Communication::SoftBus::IpAndPort *remote =
        (Communication::SoftBus::IpAndPort *)SoftBusCalloc(sizeof(Communication::SoftBus::IpAndPort));
    ASSERT_TRUE(remote != nullptr);

    int32_t streamType = 2112;
    std::pair<uint8_t*, uint32_t> sessionKey = std::make_pair(nullptr, 0);
    local->ip = "1111";

    bool ret = vtpStreamSocket->CreateClient(*local, *remote, streamType, sessionKey);
    EXPECT_EQ(false, ret);

    if (local != nullptr) {
        SoftBusFree(local);
    }
    if (remote != nullptr) {
        SoftBusFree(remote);
    }
}

/**
 * @tc.name: CreateServer001
 * @tc.desc: CreateServer001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, CreateServer001, TestSize.Level1)
{
    Communication::SoftBus::IpAndPort *local =
        (Communication::SoftBus::IpAndPort *)SoftBusCalloc(sizeof(Communication::SoftBus::IpAndPort));
    ASSERT_TRUE(local != nullptr);
    int32_t streamType = 1;
    std::pair<uint8_t*, uint32_t> sessionKey;

    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();
    bool ret = vtpStreamSocket->CreateServer(*local, streamType, sessionKey);
    EXPECT_EQ(false, ret);
    vtpStreamSocket->DestroyStreamSocket();

    local->ip = "10.50.140.1";
    local->port = 1002;
    ret = vtpStreamSocket->CreateServer(*local, streamType, sessionKey);
    EXPECT_EQ(false, ret);

    vtpStreamSocket->isDestroyed_ = true;
    vtpStreamSocket->DestroyStreamSocket();

    vtpStreamSocket->isDestroyed_ = false;
    vtpStreamSocket->listenFd_ = 2;
    vtpStreamSocket->streamFd_ = 2;
    vtpStreamSocket->epollFd_ = 2;
    vtpStreamSocket->DestroyStreamSocket();

    vtpStreamSocket->listenFd_ = -1;
    vtpStreamSocket->streamFd_ = -1;
    vtpStreamSocket->epollFd_ = -1;
    vtpStreamSocket->DestroyStreamSocket();

    EXPECT_EQ(true, vtpStreamSocket->isDestroyed_);

    if (local != nullptr) {
        SoftBusFree(local);
    }
}

/**
 * @tc.name: Connect001
 * @tc.desc: Connect001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, Connect001, TestSize.Level1)
{
    IpAndPort *remote = (IpAndPort *)SoftBusCalloc(sizeof(IpAndPort));
    ASSERT_TRUE(remote != nullptr);

    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();

    bool ret = vtpStreamSocket->Connect(*remote);
    EXPECT_EQ(false, ret);

    remote->ip = "10.50.170.123";
    remote->port = 1002;
    ret = vtpStreamSocket->Connect(*remote);
    EXPECT_EQ(false, ret);
    if (remote != nullptr) {
        SoftBusFree(remote);
    }
}

/**
 * @tc.name: GetOption001
 * @tc.desc: GetOption001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, GetOption001, TestSize.Level1)
{
    int32_t type = 12;
    StreamAttr *value = (StreamAttr *)SoftBusCalloc(sizeof(StreamAttr));
    ASSERT_TRUE(value != nullptr);

    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();

    vtpStreamSocket->optFuncMap_.clear();
    *value = vtpStreamSocket->GetOption(type);
    value->GetIntValue();
    EXPECT_TRUE(value != NULL);

    Communication::SoftBus::VtpStreamSocket::OptionFunc fun = {
    };
    type = 2;
    vtpStreamSocket->optFuncMap_.insert(std::pair<int, Communication::SoftBus::VtpStreamSocket::OptionFunc>(type, fun));
    *value = vtpStreamSocket->GetOption(type);
    EXPECT_TRUE(value != NULL);

    if (value != nullptr) {
        SoftBusFree(value);
    }
}

/**
 * @tc.name: SetOption001
 * @tc.desc: SetOption001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, SetOption001, TestSize.Level1)
{
    int32_t type = 12;
    StreamAttr *value = (StreamAttr *)SoftBusCalloc(sizeof(StreamAttr));
    ASSERT_TRUE(value != nullptr);

    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
    std::make_shared<Communication::SoftBus::VtpStreamSocket>();

    bool ret = vtpStreamSocket->SetOption(type, *value);
    EXPECT_EQ(false, ret);

    type = BOOL_TYPE;
    ret = vtpStreamSocket->SetOption(BOOL_TYPE, *value);
    EXPECT_EQ(false, ret);

    type = STRING_TYPE;
    ret = vtpStreamSocket->SetOption(BOOL_TYPE, *value);
    EXPECT_EQ(false, ret);

    type = STRING_TYPE + 1;
    ret = vtpStreamSocket->SetOption(BOOL_TYPE, *value);
    EXPECT_EQ(false, ret);

    type = BOOL_TYPE;
    ret = vtpStreamSocket->SetOption(type, *value);
    EXPECT_EQ(false, ret);

    Communication::SoftBus::VtpStreamSocket::OptionFunc fun = {
    };
    type = 2;
    vtpStreamSocket->optFuncMap_.insert(std::pair<int, Communication::SoftBus::VtpStreamSocket::OptionFunc>(type, fun));
    type = 1000;
    ret = vtpStreamSocket->SetOption(type, *value);
    EXPECT_EQ(false, ret);

    if (value != nullptr) {
        SoftBusFree(value);
    }
}

/**
 * @tc.name: GetOption002
 * @tc.desc: GetOption002, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, GetOption002, TestSize.Level1)
{
    int32_t type = 1001;
    StreamAttr *value = (StreamAttr *)SoftBusCalloc(sizeof(StreamAttr));
    ASSERT_TRUE(value != nullptr);

    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();

    *value = vtpStreamSocket->GetOption(type);
    int32_t ret = value->GetIntValue();
    if (value != NULL) {
        ret = true;
    }
    EXPECT_EQ(1, ret);

    if (value != nullptr) {
        SoftBusFree(value);
    }
}

/**
 * @tc.name: SetStreamListener001
 * @tc.desc: SetStreamListener001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, SetStreamListener001, TestSize.Level1)
{
    std::shared_ptr<IStreamSocketListener> receiver = nullptr;
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();
    bool ret = vtpStreamSocket->SetStreamListener(nullptr);
    EXPECT_EQ(false, ret);

    ret = vtpStreamSocket->SetStreamListener(receiver);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.name: GetIpType001
 * @tc.desc: GetIpType001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, GetIpType001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();

    StreamAttr *value = (StreamAttr *)SoftBusCalloc(sizeof(StreamAttr));
    ASSERT_TRUE(value != nullptr);
    int32_t type = IP_TYPE + 2;
    *value = vtpStreamSocket->GetIpType(type);
    EXPECT_TRUE(value != NULL);

    type = IP_TYPE;
    *value = vtpStreamSocket->GetIpType(type);
    EXPECT_TRUE(value != NULL);

    if (value != nullptr) {
        SoftBusFree(value);
    }
}

/**
 * @tc.name: GetRemoteScopeId001
 * @tc.desc: GetRemoteScopeId001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, GetRemoteScopeId001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();

    StreamAttr *value = (StreamAttr *)SoftBusCalloc(sizeof(StreamAttr));
    ASSERT_TRUE(value != nullptr);

    int32_t type = REMOTE_SCOPE_ID + 2;
    *value = vtpStreamSocket->GetRemoteScopeId(type);
    int32_t ret = ret = value->intVal_;
    EXPECT_EQ(-1, ret);

    type = REMOTE_SCOPE_ID;
    *value = vtpStreamSocket->GetRemoteScopeId(type);
    ret = value->intVal_;
    EXPECT_EQ(false, ret);

    if (value != nullptr) {
        SoftBusFree(value);
    }
}

/**
 * @tc.name: IsServer001
 * @tc.desc: IsServer001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, IsServer001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();

    StreamAttr *value = (StreamAttr *)SoftBusCalloc(sizeof(StreamAttr));
    ASSERT_TRUE(value != nullptr);

    int32_t type = IS_SERVER + 2;
    *value = vtpStreamSocket->IsServer(type);
    EXPECT_TRUE(value != NULL);

    type = IS_SERVER;
    *value = vtpStreamSocket->IsServer(type);
    EXPECT_TRUE(value != NULL);

    if (value != nullptr) {
        SoftBusFree(value);
    }
}

/**
 * @tc.name: SetStreamScene001
 * @tc.desc: SetStreamScene001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, SetStreamScene001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();

    StreamAttr *value = (StreamAttr *)SoftBusCalloc(sizeof(StreamAttr));
    ASSERT_TRUE(value != nullptr);
    int32_t type = IS_SERVER + 2;
    bool ret = vtpStreamSocket->SetStreamScene(type, *value);
    EXPECT_EQ(false, ret);

    value->type_ = INT_TYPE;
    ret = vtpStreamSocket->SetStreamScene(type, *value);
    EXPECT_EQ(true, ret);

    if (value != nullptr) {
        SoftBusFree(value);
    }
}

/**
 * @tc.name: SetStreamHeaderSize001
 * @tc.desc: SetStreamHeaderSize001, use the wrong parameter.
 * @tc.desc: PrintOptionInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, SetStreamHeaderSize001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();

    StreamAttr *value = (StreamAttr *)SoftBusCalloc(sizeof(StreamAttr));
    ASSERT_TRUE(value != nullptr);

    int32_t type = IS_SERVER + 2;
    bool ret = vtpStreamSocket->SetStreamHeaderSize(type, *value);
    EXPECT_EQ(false, ret);

    value->type_ = INT_TYPE;
    ret = vtpStreamSocket->SetStreamHeaderSize(type, *value);
    EXPECT_EQ(true, ret);

    value->type_ = BOOL_TYPE;
    PrintOptionInfo(type, *value);

    value->type_ = STRING_TYPE;
    PrintOptionInfo(type, *value);

    value->type_ = UNKNOWN;
    PrintOptionInfo(type, *value);

    if (value != nullptr) {
        SoftBusFree(value);
    }
}

/**
 * @tc.name: NotifyStreamListener001
 * @tc.desc: NotifyStreamListener001, use the wrong parameter.
 * @tc.desc: EnableBwEstimationAlgo001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, NotifyStreamListener001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();

    bool isServer = false;
    int32_t type = IS_SERVER + 2;
    vtpStreamSocket->NotifyStreamListener();
    bool ret = vtpStreamSocket->EnableBwEstimationAlgo(type, isServer);
    EXPECT_EQ(true, ret);
}

/**
 * @tc.name: EnableJitterDetectionAlgo001
 * @tc.desc: EnableJitterDetectionAlgo001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, EnableJitterDetectionAlgo001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();

    int32_t type = IS_SERVER + 2;
    bool ret = vtpStreamSocket->EnableJitterDetectionAlgo(type);
    EXPECT_EQ(true, ret);
}

/**
 * @tc.name: EnableDirectlySend001
 * @tc.desc: EnableDirectlySend001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, EnableDirectlySend001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();

    int32_t type = IS_SERVER + 2;
    bool ret = vtpStreamSocket->EnableDirectlySend(type);
    EXPECT_EQ(false, ret);
    ret = vtpStreamSocket->EnableDirectlySend(type);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.name: EnableSemiReliable001
 * @tc.desc: EnableSemiReliable001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, EnableSemiReliable001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();

    int32_t type = IS_SERVER + 2;
    bool ret = vtpStreamSocket->EnableSemiReliable(type);
    EXPECT_EQ(false, ret);
    ret = vtpStreamSocket->EnableSemiReliable(type);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.name: FillpStatistics001
 * @tc.desc: FillpStatistics001, use the wrong parameter.
 * @tc.desc: FillpAppStatistics, use the wrong parameter.
 * @tc.desc: FillSupportDet, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, FillpStatistics001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();

    FtEventCbkInfo *info = (FtEventCbkInfo *)SoftBusCalloc(sizeof(FtEventCbkInfo));
    ASSERT_TRUE(info != nullptr);

    int32_t fd = 2;
    int32_t ret = vtpStreamSocket->FillpStatistics(fd, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    info->evt = FT_EVT_FRAME_STATS;
    ret = vtpStreamSocket->FillpStatistics(fd, info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    info->evt = FT_EVT_TRAFFIC_DATA;
    ret = vtpStreamSocket->FillpStatistics(fd, info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    info->evt = FT_EVT_MAX;
    ret = vtpStreamSocket->FillpStatistics(fd, info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    vtpStreamSocket->FillpAppStatistics();

    if (info != NULL) {
        SoftBusFree(info);
    }
}

/**
 * @tc.name: RegisterMetricCallback001
 * @tc.desc: RegisterMetricCallback001, use the wrong parameter.
 * @tc.desc: AddStreamSocketLock, use the wrong parameter.
 * @tc.desc: AddStreamSocketListener, use the wrong parameter.
 * @tc.desc: RemoveStreamSocketLock, use the wrong parameter.
 * @tc.desc: RemoveStreamSocketListener, use the wrong parameter.
 * @tc.desc: HandleFillpFrameStats, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, RegisterMetricCallback001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();

    bool isServer = false;
    vtpStreamSocket->RegisterMetricCallback(isServer);

    int32_t fd = 3;
    std::mutex streamSocketLock_;

    std::shared_ptr<VtpStreamSocket> streamreceiver;
    vtpStreamSocket->AddStreamSocketListener(fd, streamreceiver);

    vtpStreamSocket->g_streamSocketLockMap.insert(std::pair<int, std::mutex &>(fd, streamSocketLock_));
    vtpStreamSocket->AddStreamSocketLock(fd, streamSocketLock_);

    vtpStreamSocket->RemoveStreamSocketLock(fd);

    vtpStreamSocket->RemoveStreamSocketListener(fd);

    FtEventCbkInfo *info = (FtEventCbkInfo *)SoftBusCalloc(sizeof(FtEventCbkInfo));
    ASSERT_TRUE(info != nullptr);

    int32_t ret = vtpStreamSocket->HandleFillpFrameStats(fd, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = vtpStreamSocket->HandleFillpFrameStats(fd, info);
    EXPECT_EQ(0, ret);

    auto self = vtpStreamSocket->GetSelf();
    EXPECT_TRUE(self != nullptr);
    vtpStreamSocket->g_streamSocketMap[0] = self;
    vtpStreamSocket->g_streamSocketMap[1] = self;
    vtpStreamSocket->g_streamSocketMap[2] = self;
    vtpStreamSocket->g_streamSocketMap[3] = self;
    ret = vtpStreamSocket->HandleFillpFrameStats(fd, info);
    EXPECT_EQ(0, ret);

    if (info != nullptr) {
        SoftBusFree(info);
    }
}

/**
 * @tc.name: RegisterMetricCallback002
 * @tc.desc: RegisterMetricCallback002, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, RegisterMetricCallback002, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();

    int32_t fd = 1;
    std::mutex streamSocketLock_;
    auto self = vtpStreamSocket->GetSelf();
    EXPECT_TRUE(self != nullptr);

    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> tmpvtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();
    vtpStreamSocket->g_streamSocketMap[0] = self;
    vtpStreamSocket->g_streamSocketMap[1] = self;
    vtpStreamSocket->g_streamSocketMap[2] = self;
    vtpStreamSocket->g_streamSocketMap[3] = self;

    int32_t tmpFd = 1;
    ASSERT_TRUE(!vtpStreamSocket->g_streamSocketMap.empty());

    vtpStreamSocket->AddStreamSocketLock(tmpFd, streamSocketLock_);

    ASSERT_TRUE(!vtpStreamSocket->g_streamSocketMap.empty());
    vtpStreamSocket->AddStreamSocketListener(fd, self);;

    ASSERT_TRUE(!vtpStreamSocket->g_streamSocketMap.empty());
    vtpStreamSocket->RemoveStreamSocketLock(fd);
    fd = 3;

    ASSERT_TRUE(!vtpStreamSocket->g_streamSocketMap.empty());
    vtpStreamSocket->RemoveStreamSocketLock(fd);

    fd = 100;
    vtpStreamSocket->RemoveStreamSocketListener(fd);
}

/**
 * @tc.name: Accept001
 * @tc.desc: Accept, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, Accept001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();
    SoftBusStreamTestInterfaceMock streamMock;
    EXPECT_CALL(streamMock, FtAccept).WillOnce(testing::Return(-1));
    bool ret = vtpStreamSocket->Accept();
    EXPECT_EQ(false, ret);
}

/**
 * @tc.name: EpollTimeout001
 * @tc.desc: EpollTimeout, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, EpollTimeout001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
    std::make_shared<Communication::SoftBus::VtpStreamSocket>();
    int32_t fd = 2;
    int32_t timeout = 5;
    SoftBusStreamTestInterfaceMock streamMock;
    EXPECT_CALL(streamMock, FtEpollWait).WillOnce(testing::Return(-1));
    int32_t ret = vtpStreamSocket->EpollTimeout(fd, timeout);
    EXPECT_EQ(-9, ret);
}

/**
 * @tc.name: MakeStreamData001
 * @tc.desc: MakeStreamData, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, MakeStreamData001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();
    std::unique_ptr<char[]> dataBuffer = std::make_unique<char[]>(1);
    std::unique_ptr<char[]> extBuffer = std::make_unique<char[]>(1);
    int32_t dataLength = 2;
    int32_t extLen = 2;
    Communication::SoftBus::StreamData data = { std::move(dataBuffer), dataLength, std::move(extBuffer), extLen };
    std::unique_ptr<IStream> stream = vtpStreamSocket->MakeStreamData(data, frameInfo);
    EXPECT_TRUE(stream == nullptr);

    vtpStreamSocket->streamType_ = Communication::SoftBus::VIDEO_SLICE_STREAM;
    stream = vtpStreamSocket->MakeStreamData(data, frameInfo);

    vtpStreamSocket->streamType_ = Communication::SoftBus::COMMON_VIDEO_STREAM;
    stream = vtpStreamSocket->MakeStreamData(data, frameInfo);

    vtpStreamSocket->streamType_ = Communication::SoftBus::COMMON_AUDIO_STREAM;
    stream = vtpStreamSocket->MakeStreamData(data, frameInfo);

    vtpStreamSocket->streamType_ = Communication::SoftBus::RAW_STREAM;
    stream = vtpStreamSocket->MakeStreamData(data, frameInfo);

    vtpStreamSocket->streamType_ = Communication::SoftBus::INVALID;
    stream = vtpStreamSocket->MakeStreamData(data, frameInfo);
}

/**
 * @tc.name: Decrypt001
 * @tc.desc: Encrypt, use the wrong parameter.
 * @tc.desc: Decrypt, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, Decrypt001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();
    ASSERT_TRUE(vtpStreamSocket != nullptr);
    ssize_t inLen = 50;
    ssize_t outLen = 21;
    const void *in = "in";

    std::unique_ptr<char[]> data = nullptr;
    ssize_t len = 2;
    data = std::make_unique<char[]>(len + FRAME_HEADER_LEN);

    ssize_t ret = vtpStreamSocket->Encrypt(nullptr, inLen, data.get() + FRAME_HEADER_LEN, outLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = vtpStreamSocket->Encrypt(in, inLen, nullptr, outLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = vtpStreamSocket->Encrypt(in, inLen, data.get() + FRAME_HEADER_LEN, outLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ssize_t res = vtpStreamSocket->Decrypt(nullptr, inLen, data.get(), outLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, res);
    res = vtpStreamSocket->Decrypt(in, inLen, nullptr, outLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, res);
    res = vtpStreamSocket->Decrypt(in, inLen, data.get(), outLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, res);

    outLen = 23;
    ret = vtpStreamSocket->Encrypt(in, inLen, data.get() + FRAME_HEADER_LEN, outLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, res);

    res = vtpStreamSocket->Decrypt(in, inLen, data.get(), outLen);
    EXPECT_EQ(SOFTBUS_MEM_ERR, res);
}

/**
 * @tc.name: GetVtpStackConfig001
 * @tc.desc: GetVtpStackConfig, use the wrong parameter.

 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, GetVtpStackConfig001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();

    StreamAttr *value = (StreamAttr *)SoftBusCalloc(sizeof(StreamAttr));
    ASSERT_TRUE(value != nullptr);
    SoftBusStreamTestInterfaceMock streamMock;
    EXPECT_CALL(streamMock, FtConfigGet).WillOnce(testing::Return(ERR_NULLPTR));
    int32_t type = STREAM_TYPE_INT + 1;
    *value = vtpStreamSocket->GetVtpStackConfig(type);
    SoftBusFree(value);
}

/**
 * @tc.name: GetStreamType001
 * @tc.desc: SetStreamType, use the wrong parameter.
 * @tc.desc: GetStreamType, use the wrong parameter.
 * @tc.desc: GetIp, use the wrong parameter.
 * @tc.desc: GetPort, use the wrong parameter.
 * @tc.desc: GetNonBlockMode, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, GetStreamType001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();

    StreamAttr *value = (StreamAttr *)SoftBusCalloc(sizeof(StreamAttr));
    ASSERT_TRUE(value != nullptr);

    int32_t type = STREAM_TYPE_INT + 1;
    *value = vtpStreamSocket->GetStreamType(type);
    value->GetIntValue();
    EXPECT_TRUE(value != NULL);

    bool ret = vtpStreamSocket->SetStreamType(type, *value);
    EXPECT_TRUE(!ret);

    type = STREAM_TYPE_INT;
    *value = vtpStreamSocket->GetStreamType(type);
    value->GetIntValue();
    EXPECT_TRUE(value != NULL);

    ret = vtpStreamSocket->SetStreamType(type, *value);
    EXPECT_TRUE(ret);

    type = LOCAL_IP;
    *value = vtpStreamSocket->GetIp(type);
    value->GetIntValue();
    EXPECT_TRUE(value != NULL);

    type = LOCAL_IP + 1;
    *value = vtpStreamSocket->GetIp(type);
    value->GetIntValue();
    EXPECT_TRUE(value != NULL);

    type = LOCAL_PORT;
    *value = vtpStreamSocket->GetPort(type);
    value->GetIntValue();
    EXPECT_TRUE(value != NULL);

    type = LOCAL_PORT + 1;
    *value = vtpStreamSocket->GetPort(type);
    value->GetIntValue();
    EXPECT_TRUE(value != NULL);

    int32_t fd = 2;
    *value = vtpStreamSocket->GetNonBlockMode(fd);
    value->GetIntValue();
    EXPECT_TRUE(value != NULL);

    if (value != nullptr) {
        SoftBusFree(value);
    }
}

/**
 * @tc.name: DoStreamRecv001
 * @tc.desc: DoStreamRecv, use the wrong parameter.
 * @tc.desc: RecvStreamLen, use the wrong parameter.
 * @tc.desc: SetDefaultConfig, use the wrong parameter.
 * @tc.desc: SetIpTos, use the wrong parameter.
 * @tc.desc: GetIpTos, use the wrong parameter.
 * @tc.desc: GetStreamSocketFd, use the wrong parameter.
 * @tc.desc: GetListenSocketFd, use the wrong parameter.
 * @tc.desc: SetSocketBoundInner, use the wrong parameter.
 * @tc.desc: SetSocketBindToDevices, use the wrong parameter.
 * @tc.desc: SetVtpStackConfigDelayed, use the wrong parameter.
 * @tc.desc: SetVtpStackConfig, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, DoStreamRecv001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();
    vtpStreamSocket->isStreamRecv_ = false;
    vtpStreamSocket->DoStreamRecv();

    int32_t fd = 2;
    StreamAttr *value = (StreamAttr *)SoftBusCalloc(sizeof(StreamAttr));
    ASSERT_TRUE(value != nullptr);
    value->intVal_ = 2;
    bool res = vtpStreamSocket->SetIpTos(fd, *value);
    EXPECT_TRUE(!res);

    StreamAttr *values = (StreamAttr *)SoftBusCalloc(sizeof(StreamAttr));
    ASSERT_TRUE(values != nullptr);
    int32_t type = 2;
    *values = vtpStreamSocket->GetIpTos(type);
    EXPECT_TRUE(values != nullptr);

    *values = vtpStreamSocket->GetStreamSocketFd(type);
    EXPECT_TRUE(values != nullptr);

    *values = vtpStreamSocket->GetListenSocketFd(type);
    EXPECT_TRUE(values != nullptr);

    std::string ip = "10.50.11.12";
    res = vtpStreamSocket->SetSocketBoundInner(fd, ip);
    EXPECT_TRUE(res);

    res = vtpStreamSocket->SetSocketBindToDevices(fd, *value);
    EXPECT_TRUE(res);

    res = vtpStreamSocket->SetVtpStackConfig(fd, *value);
    EXPECT_TRUE(res);

    vtpStreamSocket->streamFd_ = 1;
    res = vtpStreamSocket->SetVtpStackConfig(fd, *value);
    EXPECT_TRUE(!res);

    if (value != nullptr) {
        SoftBusFree(value);
    }
    if (values != nullptr) {
        SoftBusFree(values);
    }
}

/**
 * @tc.name: HandleRipplePolicy001
 * @tc.desc: HandleRipplePolicy, use the wrong parameter.
 * @tc.desc: RecvStreamLen, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, HandleRipplePolicy001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();

    int32_t fd = 1;
    FtEventCbkInfo *info = (FtEventCbkInfo *)SoftBusCalloc(sizeof(FtEventCbkInfo));
    ASSERT_TRUE(info != nullptr);

    ASSERT_TRUE(!vtpStreamSocket->g_streamSocketMap.empty());
    int32_t ret = vtpStreamSocket->HandleRipplePolicy(fd, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = vtpStreamSocket->HandleRipplePolicy(fd, info);
    EXPECT_EQ(0, ret);

    fd = 10;
    ret = vtpStreamSocket->HandleRipplePolicy(fd, info);
    EXPECT_NE(fd, ret);

    if (info != nullptr) {
        SoftBusFree(info);
    }
}

/**
 * @tc.name: HandleFillpFrameEvt001
 * @tc.desc: HandleFillpFrameEvt, use the wrong parameter.
 * @tc.desc: RecvStreamLen, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, HandleFillpFrameEvt001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();
    ASSERT_TRUE(vtpStreamSocket != nullptr);

    int32_t fd = 1;
    FtEventCbkInfo *info = (FtEventCbkInfo *)SoftBusCalloc(sizeof(FtEventCbkInfo));
    ASSERT_TRUE(info != nullptr);

    ASSERT_TRUE(!vtpStreamSocket->g_streamSocketMap.empty());
    int32_t ret = vtpStreamSocket->HandleFillpFrameEvt(fd, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = vtpStreamSocket->HandleFillpFrameEvt(fd, info);
    EXPECT_EQ(0, ret);
    ret = vtpStreamSocket->HandleFillpFrameEvtInner(fd, info);
    EXPECT_EQ(0, ret);

    fd = 10;
    ret = vtpStreamSocket->HandleFillpFrameEvt(fd, info);
    EXPECT_NE(fd, ret);

    if (info != nullptr) {
        SoftBusFree(info);
    }
}

/**
 * @tc.name: InsertBufferLength001
 * @tc.desc: SetSocketEpollMode, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, InsertBufferLength001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();

    int32_t fd = 2;
    vtpStreamSocket->epollFd_ = 2;
    ASSERT_TRUE(vtpStreamSocket != nullptr);
    int32_t ret = vtpStreamSocket->SetSocketEpollMode(fd);
    EXPECT_EQ(-1, ret);

    int32_t num = 2;
    int32_t length = 2;
    ASSERT_TRUE(vtpStreamSocket != nullptr);
    std::unique_ptr<char[]> data = nullptr;
    data = std::make_unique<char[]>(length);
    ASSERT_TRUE(data != nullptr);
    vtpStreamSocket->InsertBufferLength(num, length, reinterpret_cast<uint8_t *>(data.get()));

    length = 0;
    vtpStreamSocket->InsertBufferLength(num, length, reinterpret_cast<uint8_t *>(data.get()));

    vtpStreamSocket->InsertBufferLength(num, length, nullptr);
}

/**
 * @tc.name: SetSocketEpollMode001
 * @tc.desc: EpollTimeout, use the wrong parameter.
 * @tc.desc: SetSocketEpollMode, use the wrong parameter.
 * @tc.desc: InsertBufferLength, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, SetSocketEpollMode001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();
    int32_t fd = 2;
    int32_t ret  = vtpStreamSocket->SetSocketEpollMode(fd);
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: ConvertStreamFrameInfo2FrameInfoTest001
 * @tc.desc: ConvertStreamFrameInfo2FrameInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, ConvertStreamFrameInfo2FrameInfoTest001, TestSize.Level1)
{
    FrameInfo Info;
    Communication::SoftBus::StreamFrameInfo streamFrameInfo = {
        .streamId = 0,
        .seqNum = 1,
        .level = 1,
        .frameType = FrameType::RADIO_MAX,
        .seqSubNum = 1,
        .bitMap = 1,
        .bitrate = 0,
    };

    ConvertStreamFrameInfo2FrameInfo(&Info, &streamFrameInfo);
    EXPECT_TRUE(1);
}

/**
 * @tc.name: AddStreamSocketLockTest001
 * @tc.desc: AddStreamSocketLock
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, AddStreamSocketLockTest001, TestSize.Level1)
{
    std::mutex streamLock;

    VtpStreamSocket::AddStreamSocketLock(1, streamLock); // test add
    VtpStreamSocket::AddStreamSocketLock(1, streamLock); // test find exist

    VtpStreamSocket::RemoveStreamSocketLock(1); // test find case
    VtpStreamSocket::RemoveStreamSocketLock(1); // test removed case
    EXPECT_TRUE(1);
}

/**
 * @tc.name: AddStreamSocketListenerTest001
 * @tc.desc: AddStreamSocketListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, AddStreamSocketListenerTest001, TestSize.Level1)
{
    std::shared_ptr<VtpStreamSocket> streamListener = std::make_shared<VtpStreamSocket>();

    VtpStreamSocket::AddStreamSocketListener(1, streamListener); // test add
    VtpStreamSocket::AddStreamSocketListener(1, streamListener); // test find exist

    VtpStreamSocket::RemoveStreamSocketListener(1); // test find case
    VtpStreamSocket::RemoveStreamSocketListener(1); // test removed case
    EXPECT_TRUE(1);
}

/**
 * @tc.name: ProcessCommonDataStream001
 * @tc.desc: ProcessCommonDataStream
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, ProcessCommonDataStream001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();
    Communication::SoftBus::StreamFrameInfo streamFrameInfo = {
        .streamId = 1,
        .seqNum = 2,
        .level = 1,
        .frameType = FrameType::VIDEO_I,
        .seqSubNum = 2,
        .bitMap = 1,
        .bitrate = 0,
    };
    std::unique_ptr<char[]> dataBuffer = std::make_unique<char[]>(1);
    std::unique_ptr<char[]> extBuffer = std::make_unique<char[]>(1);
    int32_t dataLength = 4;
    int32_t extLen = 3;
    bool ret = vtpStreamSocket->ProcessCommonDataStream(dataBuffer, dataLength, extBuffer, extLen, streamFrameInfo);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.name: Accept002
 * @tc.desc: Accept
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, Accept002, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();
    SoftBusStreamTestInterfaceMock streamMock;
    EXPECT_CALL(streamMock, FtAccept).WillOnce(testing::Return(0));
    EXPECT_CALL(streamMock, FtGetPeerName).WillOnce(testing::Return(-1));
    bool ret = vtpStreamSocket->Accept();
    EXPECT_EQ(false, ret);
}

/**
 * @tc.name: Accept003
 * @tc.desc: Accept
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, Accept003, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();
    SoftBusStreamTestInterfaceMock streamMock;
    EXPECT_CALL(streamMock, FtAccept).WillOnce(testing::Return(0));
    EXPECT_CALL(streamMock, FtGetPeerName).WillOnce(testing::Return(0));
    bool ret = vtpStreamSocket->Accept();
    EXPECT_EQ(false, ret);
}

/**
 * @tc.name: EpollTimeout002
 * @tc.desc: EpollTimeout, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, EpollTimeout002, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();
    int32_t fd = 1;
    int32_t timeout = 5;
    SoftBusStreamTestInterfaceMock streamMock;
    EXPECT_CALL(streamMock, FtEpollWait).WillOnce(testing::Return(2)).WillRepeatedly(testing::Return(-1));
    int32_t ret = vtpStreamSocket->EpollTimeout(fd, timeout);
    EXPECT_EQ(-9, ret);
}

/**
 * @tc.name: SetVtpStackConfig001
 * @tc.desc: SetVtpStackConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, SetVtpStackConfig001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();
    vtpStreamSocket->streamFd_ = 1;
    int32_t fd = 2;
    StreamAttr *values = (StreamAttr *)SoftBusCalloc(sizeof(StreamAttr));
    ASSERT_TRUE(values != nullptr);
    values->type_ = BOOL_TYPE;
    SoftBusStreamTestInterfaceMock streamMock;
    EXPECT_CALL(streamMock, FtConfigSet).WillOnce(testing::Return(SOFTBUS_OK));
    bool res = vtpStreamSocket->SetVtpStackConfig(fd, *values);
    EXPECT_EQ(true, res);
    EXPECT_CALL(streamMock, FtConfigSet).WillOnce(testing::Return(ERR_NULLPTR));
    res = vtpStreamSocket->SetVtpStackConfig(fd, *values);
    EXPECT_EQ(false, res);

    values->type_ = INT_TYPE;
    EXPECT_CALL(streamMock, FtConfigSet).WillOnce(testing::Return(ERR_NULLPTR));
    res = vtpStreamSocket->SetVtpStackConfig(fd, *values);
    EXPECT_EQ(false, res);
    SoftBusFree(values);
}

/**
 * @tc.name: SetDefaultConfig001
 * @tc.desc: SetDefaultConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, SetDefaultConfig001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();
    int32_t fd = 2;
    StreamAttr *values = (StreamAttr *)SoftBusCalloc(sizeof(StreamAttr));
    ASSERT_TRUE(values != nullptr);
    values->intVal_ = 2;
    SoftBusStreamTestInterfaceMock streamMock;
    EXPECT_CALL(streamMock, FtConfigSet).WillOnce(testing::Return(SOFTBUS_OK));
    vtpStreamSocket->SetDefaultConfig(fd);
    SoftBusFree(values);
}

/**
 * @tc.name: GetVtpStackConfig002
 * @tc.desc: GetVtpStackConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, SetVtpStackConfig002, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();

    StreamAttr *value = (StreamAttr *)SoftBusCalloc(sizeof(StreamAttr));
    ASSERT_TRUE(value != nullptr);

    SoftBusStreamTestInterfaceMock streamMock;
    EXPECT_CALL(streamMock, FtConfigGet).WillOnce(testing::Return(SOFTBUS_OK));

    int32_t type = FT_CONF_TIMER_KEEP_ALIVE;
    value->type_ = BOOL_TYPE;
    *value = vtpStreamSocket->GetVtpStackConfig(type);
    EXPECT_TRUE(value != nullptr);
    SoftBusFree(value);
}

/**
 * @tc.name: Send001
 * @tc.desc: Send
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, Send001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();
    std::unique_ptr<IStream> stream = IStream::MakeRawStream(streamData, frameInfo);
    IStreamSocket *streamSocket = (IStreamSocket *)SoftBusCalloc(sizeof(IStreamSocket));
    ASSERT_TRUE(streamSocket != nullptr);
    streamSocket->isBlocked_ = true;
    streamSocket->streamType_ = Communication::SoftBus::RAW_STREAM;
    SoftBusStreamTestInterfaceMock streamMock;
    EXPECT_CALL(streamMock, FtSend).WillRepeatedly(testing::Return(-1));
    bool res = vtpStreamSocket->Send(std::move(stream));
    EXPECT_EQ(false, res);
    SoftBusFree(streamSocket);
}
/**
 * @tc.name: Send002
 * @tc.desc: Send
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, Send002, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();
    std::unique_ptr<IStream> stream = IStream::MakeCommonStream(streamData, frameInfo);
    IStreamSocket *streamSocket = (IStreamSocket *)SoftBusCalloc(sizeof(IStreamSocket));
    ASSERT_TRUE(streamSocket != nullptr);
    streamSocket->isBlocked_ = true;
    streamSocket->streamType_ = Communication::SoftBus::COMMON_VIDEO_STREAM;
    bool res = vtpStreamSocket->Send(std::move(stream));
    EXPECT_EQ(false, res);
    SoftBusFree(streamSocket);
}
} // OHOS
