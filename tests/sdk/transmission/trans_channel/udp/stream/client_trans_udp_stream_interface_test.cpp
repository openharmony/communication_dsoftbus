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
#include <iostream>

#include "client_trans_udp_stream_interface.h"
#include "session.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

#define CLIENT_STREAM_DATA_LENGTH 10

using namespace testing::ext;
namespace OHOS {
class ClientTransUdpStreamInterfaceTest : public testing::Test {
public:
    ClientTransUdpStreamInterfaceTest() { }
    ~ClientTransUdpStreamInterfaceTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void ClientTransUdpStreamInterfaceTest::SetUpTestCase(void) { }

void ClientTransUdpStreamInterfaceTest::TearDownTestCase(void) { }

void ClientSetStatus(int32_t channelId, int32_t status)
{
    std::cout << "ClientSetStatus, channelId=" << channelId << ", status=" << status << std::endl;
}

static IStreamListener g_callback = {
    .OnStatusChange = ClientSetStatus,
};
static char g_pkgName[] = "test";
static char g_ip[] = "127.0.0.1";
static char g_sessionKeyData[] = "abcdef@ghabcdefghabcdefghfgdabc";

static VtpStreamOpenParam g_serverParam = {
    g_pkgName,
    g_ip,
    nullptr,
    -1,
    RAW_STREAM,
    reinterpret_cast<uint8_t *>(g_sessionKeyData),
    SESSION_KEY_LENGTH,
};

static VtpStreamOpenParam g_clientParam = {
    g_pkgName,
    g_ip,
    g_ip,
    1,
    RAW_STREAM,
    reinterpret_cast<uint8_t *>(g_sessionKeyData),
    SESSION_KEY_LENGTH,
};

/*
 * @tc.name: StartVtpStreamChannelServerTest01
 * @tc.desc: test StartVtpStreamChannelServer with channelId < 0 and null param
 *           Transmission sdk udp stream start server with invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpStreamInterfaceTest, StartVtpStreamChannelServerTest01, TestSize.Level1)
{
    int32_t channelId = -1;
    int32_t ret = StartVtpStreamChannelServer(channelId, &g_serverParam, &g_callback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = StartVtpStreamChannelServer(1, nullptr, &g_callback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: StartVtpStreamChannelServerTest02
 * @tc.desc: test StartVtpStreamChannelServer with adaptor already existed
 *           Transmission sdk udp stream start server duplicated
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpStreamInterfaceTest, StartVtpStreamChannelServerTest02, TestSize.Level1)
{
    int32_t channelId = 1;
    StartVtpStreamChannelServer(channelId, &g_serverParam, &g_callback);
    int32_t ret = StartVtpStreamChannelServer(channelId, &g_serverParam, &g_callback);
    EXPECT_EQ(SOFTBUS_TRANS_ADAPTOR_ALREADY_EXISTED, ret);
    CloseVtpStreamChannel(channelId, g_pkgName);
}

/*
 * @tc.name: StartVtpStreamChannelClientTest01
 * @tc.desc: test StartVtpStreamChannelClient with channelId < 0 and null callback
 *           Transmission sdk udp stream start client with invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpStreamInterfaceTest, StartVtpStreamChannelClientTest01, TestSize.Level1)
{
    int32_t channelId = -1;
    int32_t ret = StartVtpStreamChannelClient(channelId, &g_clientParam, &g_callback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = StartVtpStreamChannelClient(1, &g_clientParam, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: StartVtpStreamChannelClientTest02
 * @tc.desc: test StartVtpStreamChannelClient with null param and null pkgName
 *           Transmission sdk udp stream start client with invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpStreamInterfaceTest, StartVtpStreamChannelClientTest02, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = StartVtpStreamChannelClient(channelId, nullptr, &g_callback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    VtpStreamOpenParam clientParam = {
        nullptr,
        g_ip,
        g_ip,
        1,
        RAW_STREAM,
        reinterpret_cast<uint8_t *>(g_sessionKeyData),
        SESSION_KEY_LENGTH,
    };
    ret = StartVtpStreamChannelClient(channelId, &clientParam, &g_callback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: StartVtpStreamChannelClientTest03
 * @tc.desc: test StartVtpStreamChannelClient success and CloseVtpStreamChannel after client closed
 *           Transmission sdk udp stream start client then close
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpStreamInterfaceTest, StartVtpStreamChannelClientTest03, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = StartVtpStreamChannelClient(channelId, &g_clientParam, &g_callback);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = CloseVtpStreamChannel(channelId, g_pkgName);
    EXPECT_EQ(SOFTBUS_TRANS_ADAPTOR_NOT_EXISTED, ret);
}

/*
 * @tc.name: CloseVtpStreamChannelTest01
 * @tc.desc: test CloseVtpStreamChannel with channelId < 0 and null pkgName
 *           Transmission sdk udp stream close with invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpStreamInterfaceTest, CloseVtpStreamChannelTest01, TestSize.Level1)
{
    int32_t channelId = -1;
    int32_t ret = CloseVtpStreamChannel(channelId, g_pkgName);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = CloseVtpStreamChannel(1, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: CloseVtpStreamChannelTest02
 * @tc.desc: test CloseVtpStreamChannel with adaptor not existed
 *           Transmission sdk udp stream close with non-existent adaptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpStreamInterfaceTest, CloseVtpStreamChannelTest02, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = CloseVtpStreamChannel(channelId, g_pkgName);
    EXPECT_EQ(SOFTBUS_TRANS_ADAPTOR_NOT_EXISTED, ret);
    ret = CloseVtpStreamChannel(channelId, g_pkgName);
    EXPECT_EQ(SOFTBUS_TRANS_ADAPTOR_NOT_EXISTED, ret);
}

/*
 * @tc.name: DeleteVtpStreamAdaptorTest01
 * @tc.desc: test DeleteVtpStreamAdaptor with non-existent adaptor
 *           Transmission sdk udp stream delete adaptor no crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpStreamInterfaceTest, DeleteVtpStreamAdaptorTest01, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t channelIdNeg = -1;
    EXPECT_NO_FATAL_FAILURE(DeleteVtpStreamAdaptor(channelId));
    EXPECT_NO_FATAL_FAILURE(DeleteVtpStreamAdaptor(channelIdNeg));
    EXPECT_NO_FATAL_FAILURE(DeleteVtpStreamAdaptor(9999));
}

/*
 * @tc.name: DeleteVtpStreamAdaptorTest02
 * @tc.desc: test DeleteVtpStreamAdaptor after StartVtpStreamChannelClient
 *           Transmission sdk udp stream delete adaptor after client start
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpStreamInterfaceTest, DeleteVtpStreamAdaptorTest02, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = 0;
    ret = StartVtpStreamChannelClient(channelId, &g_clientParam, &g_callback);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_NO_FATAL_FAILURE(DeleteVtpStreamAdaptor(channelId));
}

/*
 * @tc.name: SendVtpStreamTest01
 * @tc.desc: test SendVtpStream with null inData
 *           Transmission sdk udp stream send with null data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpStreamInterfaceTest, SendVtpStreamTest01, TestSize.Level1)
{
    int32_t channelId = 1;
    const StreamData extData = { nullptr, 0 };
    const StreamFrameInfo frameInfo = { 0 };
    int32_t ret = SendVtpStream(channelId, nullptr, &extData, &frameInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SendVtpStreamTest02
 * @tc.desc: test SendVtpStream with adaptor not existed
 *           Transmission sdk udp stream send with non-existent adaptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpStreamInterfaceTest, SendVtpStreamTest02, TestSize.Level1)
{
    int32_t channelId = 1;
    StreamData streamData = { const_cast<char *>("diudiudiu"), CLIENT_STREAM_DATA_LENGTH };
    const StreamData extData = { nullptr, 0 };
    const StreamFrameInfo frameInfo = { 0 };
    int32_t ret = SendVtpStream(channelId, &streamData, &extData, &frameInfo);
    EXPECT_EQ(SOFTBUS_TRANS_ADAPTOR_NOT_EXISTED, ret);
}

/*
 * @tc.name: SendVtpStreamTest03
 * @tc.desc: test SendVtpStream with RAW_STREAM type and null ext
 *           Transmission sdk udp stream send raw stream make stream failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpStreamInterfaceTest, SendVtpStreamTest03, TestSize.Level1)
{
    int32_t channelId = 1;
    StreamData streamData = { const_cast<char *>("diudiudiu"), CLIENT_STREAM_DATA_LENGTH };
    const StreamFrameInfo frameInfo = { 0 };
    StartVtpStreamChannelServer(channelId, &g_serverParam, &g_callback);
    int32_t ret = SendVtpStream(channelId, &streamData, nullptr, &frameInfo);
    EXPECT_EQ(SOFTBUS_TRANS_MAKE_STREAM_FAILED, ret);
    CloseVtpStreamChannel(channelId, g_pkgName);
}

/*
 * @tc.name: SendVtpStreamTest04
 * @tc.desc: test SendVtpStream with INVALID stream type
 *           Transmission sdk udp stream send invalid stream type not supported
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpStreamInterfaceTest, SendVtpStreamTest04, TestSize.Level1)
{
    int32_t channelId = 1;
    StreamData streamData = { const_cast<char *>("diudiudiu"), CLIENT_STREAM_DATA_LENGTH };
    const StreamFrameInfo frameInfo = { 0 };
    VtpStreamOpenParam invalidTypeParam = {
        g_pkgName,
        g_ip,
        nullptr,
        -1,
        INVALID,
        reinterpret_cast<uint8_t *>(g_sessionKeyData),
        SESSION_KEY_LENGTH,
    };
    StartVtpStreamChannelServer(channelId, &invalidTypeParam, &g_callback);
    int32_t ret = SendVtpStream(channelId, &streamData, nullptr, &frameInfo);
    EXPECT_EQ(SOFTBUS_FUNC_NOT_SUPPORT, ret);
    CloseVtpStreamChannel(channelId, g_pkgName);
}

/*
 * @tc.name: SendVtpStreamTest05
 * @tc.desc: test SendVtpStream with COMMON_VIDEO_STREAM type and null ext
 *           Transmission sdk udp stream send video stream make stream failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpStreamInterfaceTest, SendVtpStreamTest05, TestSize.Level1)
{
    int32_t channelId = 1;
    StreamData streamData = { const_cast<char *>("diudiudiu"), CLIENT_STREAM_DATA_LENGTH };
    const StreamFrameInfo frameInfo = { 0 };
    VtpStreamOpenParam videoTypeParam = {
        g_pkgName,
        g_ip,
        nullptr,
        -1,
        COMMON_VIDEO_STREAM,
        reinterpret_cast<uint8_t *>(g_sessionKeyData),
        SESSION_KEY_LENGTH,
    };
    StartVtpStreamChannelServer(channelId, &videoTypeParam, &g_callback);
    int32_t ret = SendVtpStream(channelId, &streamData, nullptr, &frameInfo);
    EXPECT_EQ(SOFTBUS_TRANS_MAKE_STREAM_FAILED, ret);
    CloseVtpStreamChannel(channelId, g_pkgName);
}

/*
 * @tc.name: SendVtpStreamTest06
 * @tc.desc: test SendVtpStream with COMMON_VIDEO_STREAM type and bufLen < 0
 *           Transmission sdk udp stream send video stream invalid data length
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpStreamInterfaceTest, SendVtpStreamTest06, TestSize.Level1)
{
    int32_t channelId = 1;
    StreamData streamData = { const_cast<char *>(""), -1 };
    const StreamFrameInfo frameInfo = { 0 };
    VtpStreamOpenParam videoTypeParam = {
        g_pkgName,
        g_ip,
        nullptr,
        -1,
        COMMON_VIDEO_STREAM,
        reinterpret_cast<uint8_t *>(g_sessionKeyData),
        SESSION_KEY_LENGTH,
    };
    StartVtpStreamChannelServer(channelId, &videoTypeParam, &g_callback);
    int32_t ret = SendVtpStream(channelId, &streamData, nullptr, &frameInfo);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
    CloseVtpStreamChannel(channelId, g_pkgName);
}

/*
 * @tc.name: SendVtpStreamTest07
 * @tc.desc: test SendVtpStream with COMMON_VIDEO_STREAM type and ext same as data
 *           Transmission sdk udp stream send video stream make stream failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpStreamInterfaceTest, SendVtpStreamTest07, TestSize.Level1)
{
    int32_t channelId = 1;
    StreamData streamData = { const_cast<char *>("diudiudiu"), CLIENT_STREAM_DATA_LENGTH };
    const StreamFrameInfo frameInfo = { 0 };
    VtpStreamOpenParam videoTypeParam = {
        g_pkgName,
        g_ip,
        nullptr,
        -1,
        COMMON_VIDEO_STREAM,
        reinterpret_cast<uint8_t *>(g_sessionKeyData),
        SESSION_KEY_LENGTH,
    };
    StartVtpStreamChannelServer(channelId, &videoTypeParam, &g_callback);
    int32_t ret = SendVtpStream(channelId, &streamData, &streamData, &frameInfo);
    EXPECT_EQ(SOFTBUS_TRANS_MAKE_STREAM_FAILED, ret);
    CloseVtpStreamChannel(channelId, g_pkgName);
}

/*
 * @tc.name: SetVtpStreamMultiLayerOptTest01
 * @tc.desc: test SetVtpStreamMultiLayerOpt with adaptor not existed and null optValue
 *           Transmission sdk udp stream set multi layer opt invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpStreamInterfaceTest, SetVtpStreamMultiLayerOptTest01, TestSize.Level1)
{
    int32_t channelId = 1;
    StreamData streamData = { const_cast<char *>(""), -1 };
    int32_t ret = SetVtpStreamMultiLayerOpt(channelId, &streamData);
    EXPECT_EQ(SOFTBUS_TRANS_ADAPTOR_NOT_EXISTED, ret);
    ret = SetVtpStreamMultiLayerOpt(channelId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}
} // namespace OHOS
