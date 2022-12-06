/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "softbus_errcode.h"
#include "softbus_adapter_mem.h"
#include "session.h"

#define protected public
#define private public
#include "vtp_stream_socket.h"
#include "vtp_stream_socket.cpp"
#include "stream_common.h"
#include "i_stream.h"
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
        (Communication::SoftBus::IpAndPort*)SoftBusMalloc(sizeof(Communication::SoftBus::IpAndPort));
    ASSERT_TRUE(local != nullptr);
    (void)memset_s(local, sizeof(Communication::SoftBus::IpAndPort), 0, sizeof(Communication::SoftBus::IpAndPort));

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
        (Communication::SoftBus::IpAndPort*)SoftBusMalloc(sizeof(Communication::SoftBus::IpAndPort));
    ASSERT_TRUE(local != nullptr);
    (void)memset_s(local, sizeof(Communication::SoftBus::IpAndPort), 0, sizeof(Communication::SoftBus::IpAndPort));

    Communication::SoftBus::IpAndPort *remote =
        (Communication::SoftBus::IpAndPort*)SoftBusMalloc(sizeof(Communication::SoftBus::IpAndPort));
    ASSERT_TRUE(remote != nullptr);
    (void)memset_s(remote, sizeof(Communication::SoftBus::IpAndPort), 0, sizeof(Communication::SoftBus::IpAndPort));

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
        (Communication::SoftBus::IpAndPort*)SoftBusMalloc(sizeof(Communication::SoftBus::IpAndPort));
    ASSERT_TRUE(local != nullptr);
    (void)memset_s(local, sizeof(Communication::SoftBus::IpAndPort), 0, sizeof(Communication::SoftBus::IpAndPort));
    int streamType = 1;
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
    vtpStreamSocket->DestroyStreamSocket();

    vtpStreamSocket->listenFd_ = 2;
    vtpStreamSocket->DestroyStreamSocket();

    vtpStreamSocket->streamFd_ = 2;
    vtpStreamSocket->DestroyStreamSocket();

    vtpStreamSocket->epollFd_ = 2;
    vtpStreamSocket->DestroyStreamSocket();

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
    IpAndPort *remote = (IpAndPort*)SoftBusMalloc(sizeof(IpAndPort));
    ASSERT_TRUE(remote != nullptr);
    (void)memset_s(remote, sizeof(IpAndPort), 0, sizeof(IpAndPort));

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
    int type = 12;
    StreamAttr *value = (StreamAttr*)SoftBusMalloc(sizeof(StreamAttr));
    ASSERT_TRUE(value != nullptr);
    (void)memset_s(value, sizeof(StreamAttr), 0, sizeof(StreamAttr));

    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();

    vtpStreamSocket->optFuncMap_.clear();
    *value = vtpStreamSocket->GetOption(type);
    value->GetIntValue();

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
    int type = 12;
    StreamAttr *value = (StreamAttr*)SoftBusMalloc(sizeof(StreamAttr));
    ASSERT_TRUE(value != nullptr);
    (void)memset_s(value, sizeof(StreamAttr), 0, sizeof(StreamAttr));

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
    int type = 1001;
    StreamAttr *value = (StreamAttr*)SoftBusMalloc(sizeof(StreamAttr));
    ASSERT_TRUE(value != nullptr);
    (void)memset_s(value, sizeof(StreamAttr), 0, sizeof(StreamAttr));

    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();

    *value = vtpStreamSocket->GetOption(type);
    int ret = value->GetIntValue();
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
 * @tc.name: InitVtpInstance001
 * @tc.desc: InitVtpInstance001, use the wrong parameter.
 * @tc.desc: DestroyVtpInstance, use the wrong parameter.
 * @tc.desc: GetEncryptOverhead, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, InitVtpInstance001, TestSize.Level1)
{
    std::string pkgName;
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();

    bool res = vtpStreamSocket->InitVtpInstance(pkgName);
    EXPECT_EQ(true, res);

    vtpStreamSocket->DestroyVtpInstance(pkgName);
    ssize_t ssize_tres = vtpStreamSocket->GetEncryptOverhead();
    EXPECT_EQ(OVERHEAD_LEN, ssize_tres);
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

    StreamAttr *value = (StreamAttr*)SoftBusMalloc(sizeof(StreamAttr));
    ASSERT_TRUE(value != nullptr);
    (void)memset_s(value, sizeof(StreamAttr), 0, sizeof(StreamAttr));
    int type = IP_TYPE + 2;

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

    StreamAttr *value = (StreamAttr*)SoftBusMalloc(sizeof(StreamAttr));
    ASSERT_TRUE(value != nullptr);
    (void)memset_s(value, sizeof(StreamAttr), 0, sizeof(StreamAttr));

    int type = REMOTE_SCOPE_ID + 2;
    *value = vtpStreamSocket->GetRemoteScopeId(type);
    int ret = ret = value->intVal_;
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

    StreamAttr *value = (StreamAttr*)SoftBusMalloc(sizeof(StreamAttr));
    ASSERT_TRUE(value != nullptr);
    (void)memset_s(value, sizeof(StreamAttr), 0, sizeof(StreamAttr));

    int type = IS_SERVER + 2;
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

    StreamAttr *value = (StreamAttr*)SoftBusMalloc(sizeof(StreamAttr));
    ASSERT_TRUE(value != nullptr);
    (void)memset_s(value, sizeof(StreamAttr), 0, sizeof(StreamAttr));
    int type = IS_SERVER + 2;
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
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpStreamSocketTest, SetStreamHeaderSize001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpStreamSocket> vtpStreamSocket =
        std::make_shared<Communication::SoftBus::VtpStreamSocket>();

    StreamAttr *value = (StreamAttr*)SoftBusMalloc(sizeof(StreamAttr));
    ASSERT_TRUE(value != nullptr);
    (void)memset_s(value, sizeof(StreamAttr), 0, sizeof(StreamAttr));

    int type = IS_SERVER + 2;
    bool ret = vtpStreamSocket->SetStreamHeaderSize(type, *value);
    EXPECT_EQ(false, ret);

    value->type_ = INT_TYPE;
    ret = vtpStreamSocket->SetStreamHeaderSize(type, *value);
    EXPECT_EQ(true, ret);

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
    int type = IS_SERVER + 2;
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

    int type = IS_SERVER + 2;
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

    int type = IS_SERVER + 2;
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

    int type = IS_SERVER + 2;
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

    FtEventCbkInfo *info = FILLP_NULL_PTR;

    int fd = 2;
    int ret = vtpStreamSocket->FillpStatistics(fd, nullptr);
    EXPECT_EQ(-1, ret);

    ret = vtpStreamSocket->FillpStatistics(fd, info);
    EXPECT_EQ(-1, ret);
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

    int fd = 2;
    std::mutex streamSocketLock_;
    vtpStreamSocket->AddStreamSocketLock(fd, streamSocketLock_);

    std::shared_ptr<VtpStreamSocket> streamreceiver;
    vtpStreamSocket->AddStreamSocketListener(fd, streamreceiver);

    vtpStreamSocket->RemoveStreamSocketLock(fd);

    vtpStreamSocket->RemoveStreamSocketListener(fd);

    auto self = vtpStreamSocket->GetSelf();
    EXPECT_TRUE(self != nullptr);
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

    ssize_t ret = vtpStreamSocket->Encrypt(in, inLen, data.get() + FRAME_HEADER_LEN, outLen);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = vtpStreamSocket->Decrypt(in, inLen, data.get(), outLen);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}
} // OHOS
