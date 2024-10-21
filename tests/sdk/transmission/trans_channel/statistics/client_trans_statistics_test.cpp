/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "client_trans_statistics.c"
#include "softbus_adapter_mem.h"
#include "trans_network_statistics.h"

using namespace testing::ext;

namespace OHOS {

ConnectionAddr g_addrInfo;

#define INVALID_VALUE (-1)
#define SESSIONKEY_LEN 46
#define SESSION_KEY_LEN 46
static const char *g_sessionName = "ohos.distributedschedule.dms.test";
char g_peerSessionName[SESSIONKEY_LEN] = "ohos.distributedschedule.dms.test";
char g_peerSessionKey[SESSION_KEY_LEN] = "clientkey";
static int32_t g_fd = 0;
std::string g_testData = "TransSessionTest_GetSessionKeyTestData";

#define TEST_FILE_NAME "test.filename.01"
#define TEST_PKG_NAME_LEN (64)
#define TEST_SESSION_NAME_LEN (64)
#define TEST_NETWORK_ID_LEN (64)
#define TEST_GROUP_ID_LEN (64)

class ClientTransStatisticsTest : public testing::Test {
public:
    ClientTransStatisticsTest()
    {}
    ~ClientTransStatisticsTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void ClientTransStatisticsTest::SetUpTestCase(void)
{
}

void ClientTransStatisticsTest::TearDownTestCase(void)
{
}

ChannelInfo *TestGetErrorChannelInfo(void)
{
    ChannelInfo *info = (ChannelInfo *)SoftBusMalloc(sizeof(ChannelInfo));
    (void)memset_s(info, sizeof(ChannelInfo), 0, sizeof(ChannelInfo));
    info->peerSessionName = g_peerSessionName;
    info->channelId = 1;
    info->channelType = CHANNEL_TYPE_TCP_DIRECT;
    info->sessionKey = g_peerSessionKey;
    info->fd = g_fd;
    return info;
}

ChannelInfo *TestGetServerChannelInfo(void)
{
    ChannelInfo *info = (ChannelInfo *)SoftBusMalloc(sizeof(ChannelInfo));
    (void)memset_s(info, sizeof(ChannelInfo), 0, sizeof(ChannelInfo));
    info->peerSessionName = g_peerSessionName;
    info->channelId = 1;
    info->channelType = CHANNEL_TYPE_TCP_DIRECT;
    info->sessionKey = g_peerSessionKey;
    info->fd = g_fd;
    info->connectType = CONNECT_BR;
    info->isServer = true;
    return info;
}

ChannelInfo *TestGetRightChannelInfo(void)
{
    ChannelInfo *info = (ChannelInfo *)SoftBusMalloc(sizeof(ChannelInfo));
    (void)memset_s(info, sizeof(ChannelInfo), 0, sizeof(ChannelInfo));
    info->peerSessionName = g_peerSessionName;
    info->channelId = 1;
    info->channelType = CHANNEL_TYPE_TCP_DIRECT;
    info->sessionKey = g_peerSessionKey;
    info->fd = g_fd;
    info->connectType = CONNECT_BR;
    info->isServer = false;
    return info;
}

/**
 * @tc.name: AddSocketResourceTest001
 * @tc.desc: AddSocketResource, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require: I5HZ6N
 */
HWTEST_F(ClientTransStatisticsTest, AddSocketResourceTest001, TestSize.Level0)
{
    AddSocketResource(g_sessionName, nullptr);

    ChannelInfo *errChannel = TestGetErrorChannelInfo();
    AddSocketResource(NULL, errChannel);

    AddSocketResource(g_sessionName, errChannel);
    SoftBusFree(errChannel);

    ChannelInfo *serverChannel = TestGetServerChannelInfo();
    AddSocketResource(g_sessionName, serverChannel);
    SoftBusFree(serverChannel);

    ChannelInfo *rightChannel = TestGetRightChannelInfo();
    AddSocketResource(g_sessionName, rightChannel);
    SoftBusFree(rightChannel);
}

/**
 * @tc.name: UpdateChannelStatisticsTest001
 * @tc.desc: UpdateChannelStatistics, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require: I5HZ6N
 */
HWTEST_F(ClientTransStatisticsTest, UpdateChannelStatisticsTest001, TestSize.Level0)
{
    int32_t ret = ClientTransStatisticsInit();
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t socketId = 1;
    int64_t len = 1;
    UpdateChannelStatistics(socketId, len);

    int32_t channelId = 1;
    int32_t channelType = CHANNEL_TYPE_UDP;
    DeleteSocketResourceByChannelId(channelId, channelType);

    ClientTransStatisticsDeinit();
}
} // namespace OHOS
