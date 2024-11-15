/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "session.h"
#include "softbus_error_code.h"

using namespace testing::ext;
namespace OHOS {
static const char *UDP_TEST_PKG_NAME = "com.plrdtest.dsoftbus.server";
static const char *UDP_TEST_SESSION_NAME = "com.plrdtest.dsoftbus.JtSendRawStream_0";
int32_t g_testWay = 0;
class TransQosStatServerTest : public testing::Test {
public:
    TransQosStatServerTest()
    {}
    ~TransQosStatServerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransQosStatServerTest::SetUpTestCase(void)
{
    printf("********Qos Test Begin*********\r\n");
    printf("*   0.with onQosEvent  *\r\n");
    printf("*   1.without onQosEvent   *\r\n");
    printf("********************************\r\n");
    printf("input the num:");
    std::cin >> g_testWay;
}

void TransQosStatServerTest::TearDownTestCase(void)
{}

static int32_t OnSessionOpend(int32_t sessionId, int32_t result)
{
    printf("on session opened[sessionId = %d, result = %d]\n", sessionId, result);
    return 0;
}

static void OnSessionClosed(int32_t sessionId)
{
    printf("on session closed[sessionId = %d]\n", sessionId);
}

static void OnStreamReceived(int32_t sessionId, const StreamData *data,
                             const StreamData *ext, const StreamFrameInfo *param)
{}

static void OnBytesReceived(int32_t sessionId, const void *data, unsigned int dataLen)
{}

static void OnMessageReceived(int32_t sessionId, const void *data, unsigned int dataLen)
{}

static void OnQosEvent(int32_t sessionId, int32_t eventId, int32_t tvCount, const QosTv *tvList)
{
    printf("on QoS metric retrieved [sessionId = %d] [eventId=%d]!!!!!!\n", sessionId, eventId);
    printf("pktNum:%u\n", tvList->info.appStatistics.pktNum);
    printf("periodRecvPkts:%u\n", tvList->info.appStatistics.periodRecvPkts);
    printf("periodRecvPktLoss:%u\n", tvList->info.appStatistics.periodRecvPktLoss);
    printf("periodRecvRate:%u\n", tvList->info.appStatistics.periodRecvRate);
    printf("periodRecvRateBps:%" PRIu64 "\n", tvList->info.appStatistics.periodRecvRateBps);
    printf("periodRtt:%u\n", tvList->info.appStatistics.periodRtt);
    printf("periodRecvPktLossHighPrecision:%u\n", tvList->info.appStatistics.periodRecvPktLossHighPrecision);
    printf("periodSendLostPkts:%u\n", tvList->info.appStatistics.periodSendLostPkts);
    printf("periodSendPkts:%u\n", tvList->info.appStatistics.periodSendPkts);
    printf("periodSendPktLossHighPrecision:%u\n", tvList->info.appStatistics.periodSendPktLossHighPrecision);
    printf("periodSendBits:%" PRIu64 "\n", tvList->info.appStatistics.periodSendBits);
    printf("periodSendRateBps:%" PRIu64 "\n", tvList->info.appStatistics.periodSendRateBps);
}

static ISessionListener g_hasQosCb = {
    .OnSessionOpened = OnSessionOpend,
    .OnSessionClosed = OnSessionClosed,
    .OnStreamReceived = OnStreamReceived,
    .OnBytesReceived = OnBytesReceived,
    .OnMessageReceived = OnMessageReceived,
    .OnQosEvent = OnQosEvent,
};

static ISessionListener g_noQosCb = {
    .OnSessionOpened = OnSessionOpend,
    .OnSessionClosed = OnSessionClosed,
    .OnStreamReceived = OnStreamReceived,
    .OnBytesReceived = OnBytesReceived,
    .OnMessageReceived = OnMessageReceived,
    .OnQosEvent = NULL,
};

/**
 * @tc.name: TransQosStatServerTest001
 * @tc.desc: receive with onQosEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransQosStatServerTest, QosStatServerTest001, TestSize.Level0)
{
    int32_t ret;
    if (g_testWay == 0) {
        ret = CreateSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME, &g_hasQosCb);
    } else {
        ret = CreateSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME, &g_noQosCb);
    }
    EXPECT_EQ(ret, SOFTBUS_OK);
    if (ret == SOFTBUS_OK) {
        while (1) {
            sleep(3);
        }
    }
}
} // namespace OHOS
