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
#include <gtest/gtest.h>

#include "common_inner.h"
#include "i_stream.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "stream_common.h"
#include "stream_depacketizer.h"
#include "vtp_stream_socket.h"

#define private public
#include "stream_adaptor.h"
#include "stream_manager.cpp"
#include "stream_manager.h"
#undef private

#include <cstddef>
#include <cstdint>
#include <map>
#include <securec.h>

using namespace testing::ext;
namespace OHOS {
#define DEVICE_ID "DEVICE_ID"

class StreamManagerTest : public testing::Test {
public:
    StreamManagerTest() { }
    ~StreamManagerTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void StreamManagerTest::SetUpTestCase(void) { }

void StreamManagerTest::TearDownTestCase(void) { }

/*
 * @tc.name: CreateStreamClientChannel001
 * @tc.desc: test CreateStreamClientChannel with VTP protocol returns 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamManagerTest, CreateStreamClientChannel001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::IStreamManagerListener> streamListener;
    auto streamSocketListener = std::make_shared<Communication::SoftBus::StreamManager>(streamListener);
    auto remote =
        reinterpret_cast<Communication::SoftBus::IpAndPort *>(SoftBusCalloc(sizeof(Communication::SoftBus::IpAndPort)));
    ASSERT_TRUE(remote != nullptr);
    remote->ip = "10.50.170.123";
    remote->port = 1002;
    auto local =
        reinterpret_cast<Communication::SoftBus::IpAndPort *>(SoftBusCalloc(sizeof(Communication::SoftBus::IpAndPort)));
    ASSERT_TRUE(local != nullptr);
    std::pair<uint8_t *, uint32_t> sessionKey = std::make_pair(nullptr, 0);
    int32_t streamType = 12;
    int32_t ret = streamSocketListener->CreateStreamClientChannel(
        *local, *remote, Communication::SoftBus::VTP, streamType, sessionKey);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(local);
    SoftBusFree(remote);
    streamSocketListener->DestroyEnvironment("test");
}

/*
 * @tc.name: CreateStreamClientChannel002
 * @tc.desc: test CreateStreamClientChannel with TCP protocol returns -1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamManagerTest, CreateStreamClientChannel002, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::IStreamManagerListener> streamListener;
    auto streamSocketListener = std::make_shared<Communication::SoftBus::StreamManager>(streamListener);
    auto remote =
        reinterpret_cast<Communication::SoftBus::IpAndPort *>(SoftBusCalloc(sizeof(Communication::SoftBus::IpAndPort)));
    ASSERT_TRUE(remote != nullptr);
    remote->ip = "10.50.170.123";
    remote->port = 1002;
    auto local =
        reinterpret_cast<Communication::SoftBus::IpAndPort *>(SoftBusCalloc(sizeof(Communication::SoftBus::IpAndPort)));
    ASSERT_TRUE(local != nullptr);
    std::pair<uint8_t *, uint32_t> sessionKey = std::make_pair(nullptr, 0);
    int32_t streamType = 12;
    int32_t ret = streamSocketListener->CreateStreamClientChannel(
        *local, *remote, Communication::SoftBus::TCP, streamType, sessionKey);
    EXPECT_EQ(-1, ret);
    SoftBusFree(local);
    SoftBusFree(remote);
    streamSocketListener->DestroyEnvironment("test");
}

/*
 * @tc.name: CreateStreamServerChannel001
 * @tc.desc: test CreateStreamServerChannel with protocol initialized to 0 returns -1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamManagerTest, CreateStreamServerChannel001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::IStreamManagerListener> streamListener;
    auto streamSocketListener = std::make_shared<Communication::SoftBus::StreamManager>(streamListener);
    auto local =
        reinterpret_cast<Communication::SoftBus::IpAndPort *>(SoftBusCalloc(sizeof(Communication::SoftBus::IpAndPort)));
    ASSERT_TRUE(local != nullptr);
    auto protocol =
        reinterpret_cast<Communication::SoftBus::Proto *>(SoftBusCalloc(sizeof(Communication::SoftBus::Proto)));
    ASSERT_TRUE(protocol != nullptr);
    std::pair<uint8_t *, uint32_t> sessionKey = std::make_pair(nullptr, 0);
    int32_t streamType = 12;
    int32_t ret = streamSocketListener->CreateStreamServerChannel(*local, *protocol, streamType, sessionKey);
    EXPECT_EQ(-1, ret);
    SoftBusFree(local);
    SoftBusFree(protocol);
}

/*
 * @tc.name: CreateStreamServerChannel002
 * @tc.desc: test CreateStreamServerChannel with protocol initialized to 1 returns -1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamManagerTest, CreateStreamServerChannel002, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::IStreamManagerListener> streamListener;
    auto streamSocketListener = std::make_shared<Communication::SoftBus::StreamManager>(streamListener);
    auto local =
        reinterpret_cast<Communication::SoftBus::IpAndPort *>(SoftBusCalloc(sizeof(Communication::SoftBus::IpAndPort)));
    ASSERT_TRUE(local != nullptr);
    auto protocol =
        reinterpret_cast<Communication::SoftBus::Proto *>(SoftBusCalloc(sizeof(Communication::SoftBus::Proto)));
    ASSERT_TRUE(protocol != nullptr);
    (void)memset_s(protocol, sizeof(Communication::SoftBus::Proto), 1, sizeof(Communication::SoftBus::Proto));
    std::pair<uint8_t *, uint32_t> sessionKey = std::make_pair(nullptr, 0);
    int32_t streamType = 12;
    int32_t ret = streamSocketListener->CreateStreamServerChannel(*local, *protocol, streamType, sessionKey);
    EXPECT_EQ(-1, ret);
    SoftBusFree(local);
    SoftBusFree(protocol);
}

/*
 * @tc.name: DestroyStreamDataChannel001
 * @tc.desc: test DestroyStreamDataChannel returns false when no channel exists
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

/*
 * @tc.name: Send001
 * @tc.desc: test Send returns false with nullptr stream data
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

/*
 * @tc.name: SetOptionTest001
 * @tc.desc: test SetOption returns false when no channel exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamManagerTest, SetOptionTest001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::IStreamManagerListener> streamListener;
    auto streamSocketListener = std::make_shared<Communication::SoftBus::StreamManager>(streamListener);
    auto value = reinterpret_cast<Communication::SoftBus::StreamAttr *>(
        SoftBusCalloc(sizeof(Communication::SoftBus::StreamAttr)));
    ASSERT_TRUE(value != nullptr);
    int32_t type = 1;
    bool ret = streamSocketListener->SetOption(type, *value);
    EXPECT_EQ(false, ret);
    SoftBusFree(value);
}

/*
 * @tc.name: GetOptionTest001
 * @tc.desc: test GetOption returns different object from original
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamManagerTest, GetOptionTest001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::IStreamManagerListener> streamListener;
    auto streamSocketListener = std::make_shared<Communication::SoftBus::StreamManager>(streamListener);
    auto value = reinterpret_cast<Communication::SoftBus::StreamAttr *>(
        SoftBusCalloc(sizeof(Communication::SoftBus::StreamAttr)));
    ASSERT_TRUE(value != nullptr);
    auto values = reinterpret_cast<Communication::SoftBus::StreamAttr *>(
        SoftBusCalloc(sizeof(Communication::SoftBus::StreamAttr)));
    ASSERT_TRUE(values != nullptr);
    int32_t type = 1;
    *values = streamSocketListener->GetOption(type);
    EXPECT_NE(value, values);
    SoftBusFree(value);
    SoftBusFree(values);
}

/*
 * @tc.name: SetStreamRecvListenerTest001
 * @tc.desc: test SetStreamRecvListener with valid listener and nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamManagerTest, SetStreamRecvListenerTest001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::IStreamManagerListener> streamListener;
    auto streamSocketListener = std::make_shared<Communication::SoftBus::StreamManager>(streamListener);
    std::shared_ptr<Communication::SoftBus::IStreamManagerListener> recvListener;
    EXPECT_NO_FATAL_FAILURE(streamSocketListener->SetStreamRecvListener(recvListener));
    EXPECT_NO_FATAL_FAILURE(streamSocketListener->SetStreamRecvListener(nullptr));
}

/*
 * @tc.name: SetMultiLayer001
 * @tc.desc: test SetMultiLayer returns non-SOFTBUS_OK when no channel exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamManagerTest, SetMultiLayer001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::IStreamManagerListener> streamListener;
    auto streamSocketListener = std::make_shared<Communication::SoftBus::StreamManager>(streamListener);
    int32_t para = 0;
    int32_t ret = streamSocketListener->SetMultiLayer(reinterpret_cast<void *>(&para));
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ClearSocketMap001
 * @tc.desc: test ClearSocketMap returns false when no channel exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamManagerTest, ClearSocketMap001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::IStreamManagerListener> streamListener;
    auto streamSocketListener = std::make_shared<Communication::SoftBus::StreamManager>(streamListener);

    bool ret = streamSocketListener->ClearSocketMap();

    EXPECT_EQ(false, ret);
}
} // namespace OHOS
