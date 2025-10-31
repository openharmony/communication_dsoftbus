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
#define TRANS_TEST_ID 1

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
    info->channelId = TRANS_TEST_ID;
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
    info->channelId = TRANS_TEST_ID;
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
    info->channelId = TRANS_TEST_ID;
    info->channelType = CHANNEL_TYPE_TCP_DIRECT;
    info->sessionKey = g_peerSessionKey;
    info->fd = g_fd;
    info->connectType = CONNECT_BR;
    info->isServer = false;
    return info;
}

/*
 * @tc.name: AddSocketResourceTest001
 * @tc.desc: test AddSocketResource
 *           use the wrong or normal parameter
 * @tc.type: FUNC
 * @tc.require: I5HZ6N
 */
HWTEST_F(ClientTransStatisticsTest, AddSocketResourceTest001, TestSize.Level1)
{
    EXPECT_NO_THROW(AddSocketResource(g_sessionName, nullptr));

    ChannelInfo *errChannel = TestGetErrorChannelInfo();
    EXPECT_NO_THROW(AddSocketResource(nullptr, errChannel));

    EXPECT_NO_THROW(AddSocketResource(g_sessionName, errChannel));
    SoftBusFree(errChannel);

    ChannelInfo *serverChannel = TestGetServerChannelInfo();
    EXPECT_NO_THROW(AddSocketResource(g_sessionName, serverChannel));
    SoftBusFree(serverChannel);

    ChannelInfo *rightChannel = TestGetRightChannelInfo();
    EXPECT_NO_THROW(AddSocketResource(g_sessionName, rightChannel));
    SoftBusFree(rightChannel);
}

/*
 * @tc.name: UpdateChannelStatisticsTest001
 * @tc.desc: test UpdateChannelStatistics
 *           use the wrong or normal parameter
 * @tc.type: FUNC
 * @tc.require: I5HZ6N
 */
HWTEST_F(ClientTransStatisticsTest, UpdateChannelStatisticsTest001, TestSize.Level1)
{
    int32_t ret = ClientTransStatisticsInit();
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t socketId = TRANS_TEST_ID;
    int64_t len = TRANS_TEST_ID;
    UpdateChannelStatistics(socketId, len);

    int32_t channelId = TRANS_TEST_ID;
    int32_t channelType = CHANNEL_TYPE_UDP;
    DeleteSocketResourceByChannelId(channelId, channelType);

    ClientTransStatisticsDeinit();
}

/*
 * @tc.name: CreateSocketResourceTest001
 * @tc.desc: test CreateSocketResource
 *           use the wrong or normal parameter
 * @tc.type: FUNC
 * @tc.require: I5HZ6N
 */
HWTEST_F(ClientTransStatisticsTest, CreateSocketResourceTest001, TestSize.Level1)
{
    SocketResource *item = nullptr;
    const char *sessionName = "sessionName";
    ChannelInfo *channel = TestGetRightChannelInfo();
    CreateSocketResource(item, sessionName, channel);
    EXPECT_EQ(item, nullptr);
    item = reinterpret_cast<SocketResource *>(SoftBusCalloc(sizeof(SocketResource)));
    uint64_t laneId = TRANS_TEST_ID;
    int32_t channelId = TRANS_TEST_ID;
    int32_t channelType = CHANNEL_TYPE_UDP;
    channel->laneId = laneId;
    channel->channelId = channelId;
    channel->channelType = channelType;
    CreateSocketResource(item, sessionName, channel);
    EXPECT_NE(item, nullptr);
    SoftBusFree(item);
}

/*
 * @tc.name: AddSocketResourceTest002
 * @tc.desc: test AddSocketResource
 *           use the wrong or normal parameter
 * @tc.type: FUNC
 * @tc.require: I5HZ6N
 */
HWTEST_F(ClientTransStatisticsTest, AddSocketResourceTest002, TestSize.Level1)
{
    int32_t ret = ClientTransStatisticsInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    SocketResource *newItem = reinterpret_cast<SocketResource *>(SoftBusCalloc(sizeof(SocketResource)));
    ASSERT_NE(newItem, nullptr);
    newItem->socketId = TRANS_TEST_ID;
    ListInit(&newItem->node);
    ListAdd(&g_channelStatisticsList->list, &newItem->node);

    g_channelStatisticsList->cnt = static_cast<int32_t>(MAX_SOCKET_RESOURCE_NUM);
    ChannelInfo *rightChannel = TestGetRightChannelInfo();
    AddSocketResource(g_sessionName, rightChannel);

    g_channelStatisticsList->cnt = static_cast<int32_t>(MAX_SOCKET_RESOURCE_NUM - TRANS_TEST_ID);
    rightChannel->channelId = INVALID_VALUE;
    AddSocketResource(g_sessionName, rightChannel);
    EXPECT_NE(g_channelStatisticsList, nullptr);
    SoftBusFree(rightChannel);
    ClientTransStatisticsDeinit();
}

/*
 * @tc.name: UpdateChannelStatisticsTest002
 * @tc.desc: test UpdateChannelStatistics
 *           use the wrong or normal parameter
 * @tc.type: FUNC
 * @tc.require: I5HZ6N
 */
HWTEST_F(ClientTransStatisticsTest, UpdateChannelStatisticsTest002, TestSize.Level1)
{
    int32_t socketId = TRANS_TEST_ID;
    int64_t len = TRANS_TEST_ID;
    UpdateChannelStatistics(socketId, len);
    EXPECT_EQ(g_channelStatisticsList, nullptr);

    int32_t ret = ClientTransStatisticsInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    SocketResource *newItem = reinterpret_cast<SocketResource *>(SoftBusCalloc(sizeof(SocketResource)));
    ASSERT_NE(newItem, nullptr);
    newItem->socketId = socketId;
    newItem->traffic = 0;
    ListInit(&newItem->node);
    ListAdd(&g_channelStatisticsList->list, &newItem->node);

    UpdateChannelStatistics(socketId, len);
    EXPECT_EQ(newItem->traffic, len);

    ClientTransStatisticsDeinit();
}

/*
 * @tc.name: PackStatisticsTest001
 * @tc.desc: test PackStatistics
 *           use the wrong or normal parameter
 * @tc.type: FUNC
 * @tc.require: I5HZ6N
 */
HWTEST_F(ClientTransStatisticsTest, PackStatisticsTest001, TestSize.Level1)
{
    int32_t ret = PackStatistics(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    cJSON *json = cJSON_CreateObject();
    SocketResource *resource = reinterpret_cast<SocketResource *>(SoftBusCalloc(sizeof(SocketResource)));
    ret = PackStatistics(json, resource);
    EXPECT_EQ(ret, SOFTBUS_OK);
    cJSON_Delete(json);
    SoftBusFree(resource);
}

/*
 * @tc.name: CloseChannelAndSendStatisticsTest001
 * @tc.desc: test CloseChannelAndSendStatistics
 *           use the wrong or normal parameter
 * @tc.type: FUNC
 * @tc.require: I5HZ6N
 */
HWTEST_F(ClientTransStatisticsTest, CloseChannelAndSendStatisticsTest001, TestSize.Level1)
{
    CloseChannelAndSendStatistics(nullptr);
    SocketResource *resource = reinterpret_cast<SocketResource *>(SoftBusCalloc(sizeof(SocketResource)));
    CloseChannelAndSendStatistics(resource);
    EXPECT_NE(resource, nullptr);
    SoftBusFree(resource);
}

/*
 * @tc.name: DeleteSocketResourceByChannelIdTest002
 * @tc.desc: test DeleteSocketResourceByChannelId
 *           use the wrong or normal parameter
 * @tc.type: FUNC
 * @tc.require: I5HZ6N
 */
HWTEST_F(ClientTransStatisticsTest, DeleteSocketResourceByChannelIdTest002, TestSize.Level1)
{
    int32_t channelId = INVALID_VALUE;
    int32_t channelType = CHANNEL_TYPE_UDP;
    int32_t socketId = TRANS_TEST_ID;
    int64_t len = TRANS_TEST_ID;
    DeleteSocketResourceByChannelId(channelId, channelType);
    channelId = TRANS_TEST_ID;
    DeleteSocketResourceByChannelId(channelId, channelType);
    EXPECT_EQ(g_channelStatisticsList, nullptr);

    int32_t ret = ClientTransStatisticsInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    SocketResource *newItem = reinterpret_cast<SocketResource *>(SoftBusCalloc(sizeof(SocketResource)));
    ASSERT_NE(newItem, nullptr);
    newItem->channelId = channelId;
    newItem->channelType = channelType;
    newItem->socketId = socketId;
    ListInit(&newItem->node);
    ListAdd(&g_channelStatisticsList->list, &newItem->node);
    g_channelStatisticsList->cnt = TRANS_TEST_ID;

    UpdateChannelStatistics(socketId, len);
    DeleteSocketResourceByChannelId(channelId, channelType);
    EXPECT_EQ(g_channelStatisticsList->cnt, TRANS_TEST_ID);

    ClientTransStatisticsDeinit();
}

/*
 * @tc.name: ClientTransStatisticsDeinitTest001
 * @tc.desc: test ClientTransStatisticsDeinit
 *           use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require: I5HZ6N
 */
HWTEST_F(ClientTransStatisticsTest, ClientTransStatisticsDeinitTest001, TestSize.Level1)
{
    g_channelStatisticsList = nullptr;
    ClientTransStatisticsDeinit();

    int32_t ret = ClientTransStatisticsInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    SocketResource *newItem = reinterpret_cast<SocketResource *>(SoftBusCalloc(sizeof(SocketResource)));
    ASSERT_NE(newItem, nullptr);
    newItem->channelId = TRANS_TEST_ID;
    ListInit(&newItem->node);
    ListAdd(&g_channelStatisticsList->list, &newItem->node);

    ClientTransStatisticsDeinit();
    EXPECT_EQ(g_channelStatisticsList, nullptr);
}

/*
 * @tc.name: DeleteSocketResourceBySocketIdTest002
 * @tc.desc: test DeleteSocketResourceBySocketId
 *           use the wrong or normal parameter
 * @tc.type: FUNC
 * @tc.require: I5HZ6N
 */
HWTEST_F(ClientTransStatisticsTest, DeleteSocketResourceBySocketIdTest002, TestSize.Level1)
{
    int32_t socketId = TRANS_TEST_ID;
    int64_t len = TRANS_TEST_ID;
    DeleteSocketResourceBySocketId(socketId);
    EXPECT_EQ(g_channelStatisticsList, nullptr);

    int32_t ret = ClientTransStatisticsInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    SocketResource *newItem = reinterpret_cast<SocketResource *>(SoftBusCalloc(sizeof(SocketResource)));
    ASSERT_NE(newItem, nullptr);
    newItem->socketId = socketId;
    ListInit(&newItem->node);
    ListAdd(&g_channelStatisticsList->list, &newItem->node);
    g_channelStatisticsList->cnt = TRANS_TEST_ID;

    UpdateChannelStatistics(socketId, len);
    DeleteSocketResourceBySocketId(socketId);
    EXPECT_EQ(g_channelStatisticsList->cnt, 0);

    ClientTransStatisticsDeinit();
}
} // namespace OHOS
