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
#include <iostream>
#include <gtest/gtest.h>

#include "session.h"
#include "softbus_error_code.h"
#include "softbus_def.h"
#include "client_trans_udp_stream_interface.h"

#define CLIENT_STREAM_DATA_LENGTH 10
#define CLIENT_LOOP_ROUND 10
#define CLIENT_LONG_SLEEP 3

using namespace testing::ext;
namespace OHOS {
class ClientTransUdpStreamInterfaceTest : public testing::Test {
public:
    ClientTransUdpStreamInterfaceTest()
    {}
    ~ClientTransUdpStreamInterfaceTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void ClientTransUdpStreamInterfaceTest::SetUpTestCase(void)
{}

void ClientTransUdpStreamInterfaceTest::TearDownTestCase(void)
{}

void ClientSetStatus(int32_t channelId, int32_t status)
{
    std::cout << "[server]:channelID:" << channelId << ", status:" << status << std::endl;
}

static IStreamListener g_callback = {
    .OnStatusChange = ClientSetStatus,
};
static char g_pkgName[] = "test";
static char g_ip[] = "127.0.0.1";
static VtpStreamOpenParam g_serverParam1 = {
    g_pkgName,
    g_ip,
    NULL,
    -1,
    RAW_STREAM,
    (uint8_t*)"abcdef@ghabcdefghabcdefghfgdabc",
    SESSION_KEY_LENGTH,
};

static VtpStreamOpenParam g_clientParam1 = {
    g_pkgName,
    g_ip,
    g_ip,
    1,
    RAW_STREAM,
    (uint8_t*)"abcdef@ghabcdefghabcdefghfgdabc",
    SESSION_KEY_LENGTH,
};

/**
 * @tc.name: StartVtpStreamChannelServerTest001
 * @tc.desc: StartVtpStreamChannelServer error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpStreamInterfaceTest, StartVtpStreamChannelServerTest001, TestSize.Level0)
{
    int32_t channelId = -1;
    int32_t ret = StartVtpStreamChannelServer(channelId, &g_serverParam1, &g_callback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = CloseVtpStreamChannel(channelId, g_pkgName);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: StartVtpStreamChannelServerTest002
 * @tc.desc: StartVtpStreamChannelServer error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpStreamInterfaceTest, StartVtpStreamChannelServerTest002, TestSize.Level0)
{
    int32_t channelId = 1;
    int32_t ret = StartVtpStreamChannelServer(channelId, &g_serverParam1, &g_callback);
    EXPECT_NE(SOFTBUS_TRANS_ADAPTOR_ALREADY_EXISTED, ret);
    ret = StartVtpStreamChannelServer(channelId, &g_serverParam1, &g_callback);
    EXPECT_EQ(SOFTBUS_TRANS_ADAPTOR_ALREADY_EXISTED, ret);
    CloseVtpStreamChannel(channelId, g_pkgName);
}

/**
 * @tc.name: StartVtpStreamChannelClientTest001
 * @tc.desc: StartVtpStreamChannelClient error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpStreamInterfaceTest, StartVtpStreamChannelClientTest001, TestSize.Level0)
{
    int32_t channelId = -1;
    int32_t ret = StartVtpStreamChannelClient(channelId, &g_clientParam1, &g_callback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    CloseVtpStreamChannel(channelId, g_pkgName);
}

/**
 * @tc.name: StartVtpStreamChannelClientTest002
 * @tc.desc: StartVtpStreamChannelClient success CloseVtpStreamChannel error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpStreamInterfaceTest, StartVtpStreamChannelClientTest002, TestSize.Level0)
{
    int32_t channelId = 1;
    int32_t ret = StartVtpStreamChannelClient(channelId, &g_clientParam1, &g_callback);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = CloseVtpStreamChannel(channelId, g_pkgName);
    EXPECT_EQ(SOFTBUS_TRANS_ADAPTOR_NOT_EXISTED, ret);
}

/**
 * @tc.name: CloseVtpStreamChannelTest001
 * @tc.desc: CloseVtpStreamChannel error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpStreamInterfaceTest, CloseVtpStreamChannelTest001, TestSize.Level0)
{
    int32_t channelId = 1;
    int32_t ret =  CloseVtpStreamChannel(channelId, g_pkgName);
    EXPECT_EQ(SOFTBUS_TRANS_ADAPTOR_NOT_EXISTED, ret);
}

/**
 * @tc.name: SendVtpStreamTest001
 * @tc.desc: SendVtpStreamTest error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpStreamInterfaceTest, SendVtpStreamTest001, TestSize.Level0)
{
    int32_t channelId = 1;
    StreamData streamData = {
        (char *)"diudiudiu\0",
        CLIENT_STREAM_DATA_LENGTH,
    };
    const StreamData extData = {0};
    const StreamFrameInfo frameInfo = {0};
    int32_t ret = SendVtpStream(channelId, nullptr, &extData, &frameInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = SendVtpStream(channelId, &streamData, &extData, &frameInfo);
    EXPECT_EQ(SOFTBUS_TRANS_ADAPTOR_NOT_EXISTED, ret);
}

/**
 * @tc.name: SendVtpStreamTest002
 * @tc.desc: SendVtpStreamTest error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpStreamInterfaceTest, SendVtpStreamTest002, TestSize.Level0)
{
    int32_t channelId = 1;
    StreamData streamData = {
        (char *)"diudiudiu\0",
        CLIENT_STREAM_DATA_LENGTH,
    };
    const StreamFrameInfo frameInfo = {};
    int32_t ret = StartVtpStreamChannelServer(channelId, &g_serverParam1, &g_callback);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = SendVtpStream(channelId, &streamData, NULL, &frameInfo);
    EXPECT_EQ(SOFTBUS_TRANS_MAKE_STREAM_FAILED, ret);
    CloseVtpStreamChannel(channelId, g_pkgName);

    g_serverParam1.type = INVALID;
    ret = StartVtpStreamChannelServer(channelId, &g_serverParam1, &g_callback);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = SendVtpStream(channelId, &streamData, NULL, &frameInfo);
    EXPECT_EQ(SOFTBUS_FUNC_NOT_SUPPORT, ret);
    CloseVtpStreamChannel(channelId, g_pkgName);

    g_serverParam1.type = COMMON_VIDEO_STREAM;
    ret = StartVtpStreamChannelServer(channelId, &g_serverParam1, &g_callback);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = SendVtpStream(channelId, &streamData, NULL, &frameInfo);
    EXPECT_EQ(SOFTBUS_TRANS_MAKE_STREAM_FAILED, ret);
    CloseVtpStreamChannel(channelId, g_pkgName);
}

/**
 * @tc.name: SendVtpStreamTest003
 * @tc.desc: SendVtpStreamTest error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpStreamInterfaceTest, SendVtpStreamTest003, TestSize.Level0)
{
    int32_t channelId = 1;
    StreamData streamData1 = {
        (char *)"",
        -1,
    };
    StreamData streamData2 = {
        (char *)"diudiudiu\0",
        CLIENT_STREAM_DATA_LENGTH,
    };
    const StreamFrameInfo frameInfo = {};
    g_serverParam1.type = COMMON_VIDEO_STREAM;

    int32_t ret = StartVtpStreamChannelServer(channelId, &g_serverParam1, &g_callback);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = SendVtpStream(channelId, &streamData1, NULL, &frameInfo);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
    CloseVtpStreamChannel(channelId, g_pkgName);

    ret = StartVtpStreamChannelServer(channelId, &g_serverParam1, &g_callback);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = SendVtpStream(channelId, &streamData2, &streamData2, &frameInfo);
    EXPECT_EQ(SOFTBUS_TRANS_MAKE_STREAM_FAILED, ret);
    CloseVtpStreamChannel(channelId, g_pkgName);
}
}