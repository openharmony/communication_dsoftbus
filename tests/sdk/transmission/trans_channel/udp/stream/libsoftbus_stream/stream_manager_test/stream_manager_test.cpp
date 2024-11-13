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

#include "common_inner.h"
#include "i_stream.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "stream_common.h"
#include "softbus_adapter_crypto.h"
#include "stream_depacketizer.h"
#include "vtp_stream_socket.h"

#define private public
#include "stream_manager.h"
#include "stream_manager.cpp"
#include "stream_adaptor.h"
#undef private

#include <cstddef>
#include <cstdint>
#include <securec.h>
#include <map>

using namespace testing::ext;
namespace OHOS {
#define DEVICE_ID "DEVICE_ID"

class StreamManagerTest : public testing::Test {
public:
    StreamManagerTest()
    {}
    ~StreamManagerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void StreamManagerTest::SetUpTestCase(void)
{}

void StreamManagerTest::TearDownTestCase(void)
{}

/**
 * @tc.name: CreateStreamClientChannel001
 * @tc.desc: CreateStreamClientChannel, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamManagerTest, CreateStreamClientChannel001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::IStreamManagerListener> streamListener;
    auto streamSocketListener = std::make_shared<Communication::SoftBus::StreamManager>(streamListener);

    std::string pkgName = "test";
    Communication::SoftBus::IpAndPort *local =
        (Communication::SoftBus::IpAndPort*)SoftBusMalloc(sizeof(Communication::SoftBus::IpAndPort));
    (void)memset_s(local, sizeof(Communication::SoftBus::IpAndPort), 0, sizeof(Communication::SoftBus::IpAndPort));
    Communication::SoftBus::IpAndPort *remote =
        (Communication::SoftBus::IpAndPort*)SoftBusMalloc(sizeof(Communication::SoftBus::IpAndPort));
    (void)memset_s(remote, sizeof(Communication::SoftBus::IpAndPort), 0, sizeof(Communication::SoftBus::IpAndPort));

    remote->ip = "10.50.170.123";
    remote->port = 1002;

    std::pair<uint8_t*, uint32_t> sessionKey = std::make_pair(nullptr, 0);
    int32_t streamType = 12;
    int32_t ret = streamSocketListener->CreateStreamClientChannel(*local, *remote,
                                                                  Communication::SoftBus::VTP,
                                                                  streamType, sessionKey);
    EXPECT_EQ(0, ret);

    ret = streamSocketListener->CreateStreamClientChannel(*local, *remote, Communication::SoftBus::TCP, streamType,
        sessionKey);
    EXPECT_EQ(-1, ret);
    streamSocketListener->DestroyEnvironment(pkgName);
}

/**
 * @tc.name: CreateStreamServerChannel001
 * @tc.desc: CreateStreamServerChannel001, use the wrong parameter.
 * @tc.desc: DestroyEnvironment, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamManagerTest, CreateStreamServerChannel001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::IStreamManagerListener> streamListener;
    auto streamSocketListener = std::make_shared<Communication::SoftBus::StreamManager>(streamListener);

    std::string pkgName = "test";
    Communication::SoftBus::IpAndPort *local =
        (Communication::SoftBus::IpAndPort*)SoftBusMalloc(sizeof(Communication::SoftBus::IpAndPort));
    (void)memset_s(local, sizeof(Communication::SoftBus::IpAndPort), 0, sizeof(Communication::SoftBus::IpAndPort));

    Communication::SoftBus::Proto *protocol =
        (Communication::SoftBus::Proto*)SoftBusMalloc(sizeof(Communication::SoftBus::Proto));
    (void)memset_s(protocol, sizeof(Communication::SoftBus::Proto), 0, sizeof(Communication::SoftBus::Proto));


    std::pair<uint8_t*, uint32_t> sessionKey = std::make_pair(nullptr, 0);
    int32_t streamType = 12;
    int32_t ret = streamSocketListener->CreateStreamServerChannel(*local, *protocol, streamType, sessionKey);
    EXPECT_EQ(-1, ret);

    (void)memset_s(protocol, sizeof(Communication::SoftBus::Proto), 1, sizeof(Communication::SoftBus::Proto));
    ret = streamSocketListener->CreateStreamServerChannel(*local, *protocol, streamType, sessionKey);
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: DestroyStreamDataChannel001
 * @tc.desc: DestroyStreamDataChannel001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamManagerTest, DestroyStreamDataChannel001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::IStreamManagerListener> streamListener;
    auto streamSocketListener = std::make_shared<Communication::SoftBus::StreamManager>(streamListener);

    bool ret = streamSocketListener->DestroyStreamDataChannel();

    EXPECT_EQ(false, ret);
}

/**
 * @tc.name: Send001
 * @tc.desc: Send001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamManagerTest, Send001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::IStreamManagerListener> streamListener;
    auto streamSocketListener = std::make_shared<Communication::SoftBus::StreamManager>(streamListener);
    bool ret = streamSocketListener->Send(nullptr);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.name: SetOption001
 * @tc.desc: SetOption001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamManagerTest, SetOption001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::IStreamManagerListener> streamListener;
    auto streamSocketListener = std::make_shared<Communication::SoftBus::StreamManager>(streamListener);

    int32_t type = 1;
    Communication::SoftBus::StreamAttr *value =
        (Communication::SoftBus::StreamAttr*)SoftBusMalloc(sizeof(Communication::SoftBus::StreamAttr));
    (void)memset_s(value, sizeof(Communication::SoftBus::StreamAttr), 0, sizeof(Communication::SoftBus::StreamAttr));

    Communication::SoftBus::StreamAttr *values =
        (Communication::SoftBus::StreamAttr*)SoftBusMalloc(sizeof(Communication::SoftBus::StreamAttr));
    (void)memset_s(values, sizeof(Communication::SoftBus::StreamAttr), 0, sizeof(Communication::SoftBus::StreamAttr));

    bool ret = streamSocketListener->SetOption(type, *value);
    EXPECT_EQ(false, ret);

    *values = streamSocketListener->GetOption(type);
    EXPECT_NE(value, values);

    std::shared_ptr<Communication::SoftBus::IStreamManagerListener> recvListener;
    streamSocketListener->SetStreamRecvListener(recvListener);
    streamSocketListener->SetStreamRecvListener(nullptr);
}

/**
 * @tc.name: SetMultiLayer001
 * @tc.desc: SetMultiLayer, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamManagerTest, SetMultiLayer001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::IStreamManagerListener> streamListener;
    auto streamSocketListener = std::make_shared<Communication::SoftBus::StreamManager>(streamListener);
    ASSERT_TRUE(streamSocketListener != nullptr);

    int32_t para = 0;
    int32_t ret = streamSocketListener->SetMultiLayer((void *)&para);
    EXPECT_NE(SOFTBUS_OK, ret);
}
} // OHOS
