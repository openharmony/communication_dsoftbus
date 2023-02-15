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

#include <cstdio>
#include <gtest/gtest.h>
#include <map>
#include <vector>
#include "securec.h"
#include "session.h"
#include "softbus_bus_center.h"
#include "softbus_errcode.h"

#define TEST_TMP_BUF "tmpBuf"
#define TEST_TMP_BUF_LEN 10
#define STR_LEN 100000
#define TMP_NUM 97

using namespace testing::ext;
namespace OHOS {
static const char *UDP_TEST_PKG_NAME = "com.plrdtest.dsoftbus.client";
static const char *UDP_TEST_SESSION_NAME = "com.plrdtest.dsoftbus.JtSendRawStream_0";
const int32_t PERIOD_MS = 1000;
std::map<int, int> g_qosEventCount;
std::map<int, uint64_t> g_timeDiff;
std::map<int, uint64_t> g_lastTimeStamp;
std::map<int, std::vector<uint64_t>> g_speedStat;

class TransQosStatClientTest : public testing::Test {
public:
    TransQosStatClientTest()
    {}
    ~TransQosStatClientTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {
        g_timeDiff.clear();
        g_speedStat.clear();
        g_lastTimeStamp.clear();
        g_qosEventCount.clear();
    }
    void TearDown() override
    {
        g_timeDiff.clear();
        g_speedStat.clear();
        g_lastTimeStamp.clear();
        g_qosEventCount.clear();
    }
};

void TransQosStatClientTest::SetUpTestCase(void)
{
    g_timeDiff.clear();
    g_speedStat.clear();
    g_lastTimeStamp.clear();
    g_qosEventCount.clear();
}

void TransQosStatClientTest::TearDownTestCase(void)
{
    g_timeDiff.clear();
    g_speedStat.clear();
    g_lastTimeStamp.clear();
    g_qosEventCount.clear();
}

static int OnSessionOpend(int sessionId, int result)
{
    printf("on session opened[sessionId = %d, result = %d]\n", sessionId, result);
    g_qosEventCount[sessionId] = 0;
    g_timeDiff[sessionId] = 0;
    g_speedStat[sessionId] = std::vector<uint64_t>();
    return 0;
}

static void OnSessionClosed(int sessionId)
{
    printf("on session closed[sessionId = %d]\n", sessionId);
}

static void OnStreamReceived(int sessionId, const StreamData *data, const StreamData *ext, const StreamFrameInfo *param)
{}

static void OnBytesReceived(int sessionId, const void *data, unsigned int dataLen)
{}

static void OnMessageReceived(int sessionId, const void *data, unsigned int dataLen)
{}

static void OnQosEvent(int sessionId, int eventId, int tvCount, const QosTv *tvList)
{
    if (eventId == TRANS_STREAM_QUALITY_EVENT && tvCount == 1 && tvList[0].type == STREAM_TRAFFIC_STASTICS) {
        if (g_qosEventCount.find(sessionId) != g_qosEventCount.end()) {
            g_qosEventCount[sessionId]++;
        }
        if (g_timeDiff.find(sessionId) == g_timeDiff.end()) {
            g_timeDiff[sessionId] = 0;
        }
        if (g_speedStat.find(sessionId) != g_speedStat.end()) {
            g_speedStat[sessionId].push_back(tvList[0].info.appStatistics.periodSendBits);
        } else {
            g_speedStat[sessionId] = std::vector<uint64_t>();
        }
        if (g_lastTimeStamp.find(sessionId) != g_lastTimeStamp.end()) {
            g_timeDiff[sessionId] +=
                tvList[0].info.appStatistics.statisticsGotTime - g_lastTimeStamp[sessionId] - PERIOD_MS;
        }
        g_lastTimeStamp[sessionId] = tvList[0].info.appStatistics.statisticsGotTime;
    }
}

static uint64_t CalSendBits(const std::vector<uint64_t> &rateList)
{
    uint64_t sum = 0;
    if (rateList.size() > 0) {
        return rateList[rateList.size() - 1];
    }
    return 0;
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
 * @tc.name: TransQosStatClientTest001
 * @tc.desc: null sessionListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransQosStatClientTest, QosStatClientTest001, TestSize.Level0)
{
    int32_t ret = CreateSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME, NULL);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransQosStatClientTest002
 * @tc.desc: sessionListener without onQosEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransQosStatClientTest, QosStatClientTest002, TestSize.Level0)
{
    int32_t sendTimes = 10;
    int32_t ret = CreateSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME, &g_noQosCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    NodeBasicInfo *info;
    int32_t infoNum;
    ret = GetAllNodeDeviceInfo(UDP_TEST_PKG_NAME, &info, &infoNum);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionAttribute attr = {0};
    attr.dataType = TYPE_STREAM;
    attr.attr.streamAttr.streamType = RAW_STREAM;
    int32_t sessionId = OpenSession(UDP_TEST_SESSION_NAME, UDP_TEST_SESSION_NAME,
        info[0].networkId, "0", &attr);
    EXPECT_NE(-1, sessionId);
    sleep(2);

    char sendStringData[STR_LEN];
    memset_s(sendStringData, sizeof(sendStringData), TMP_NUM, sizeof(sendStringData));
    StreamData d1 = {
        sendStringData,
        STR_LEN,
    };
    StreamData d2 = {
        TEST_TMP_BUF,
        TEST_TMP_BUF_LEN,
    };
    StreamFrameInfo tmpf = {};
    for (int32_t times = 0; times < sendTimes; times++) {
        ret = SendStream(sessionId, &d1, &d2, &tmpf);
        EXPECT_EQ(ret, SOFTBUS_OK);
        sleep(1);
    }
    EXPECT_EQ(g_qosEventCount[sessionId], 0);
    CloseSession(sessionId);
    sleep(1);
    ret = RemoveSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransQosStatClientTest003
 * @tc.desc: sessionListener with onQosEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransQosStatClientTest, QosStatClientTest003, TestSize.Level0)
{
    int32_t sendTimes = 10;
    int32_t ret = CreateSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME, &g_hasQosCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    NodeBasicInfo *info;
    int32_t infoNum;
    ret = GetAllNodeDeviceInfo(UDP_TEST_PKG_NAME, &info, &infoNum);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionAttribute attr = {0};
    attr.dataType = TYPE_STREAM;
    attr.attr.streamAttr.streamType = RAW_STREAM;
    int32_t sessionId = OpenSession(UDP_TEST_SESSION_NAME, UDP_TEST_SESSION_NAME,
        info[0].networkId, "0", &attr);
    EXPECT_NE(-1, sessionId);
    sleep(2);

    char sendStringData[STR_LEN];
    memset_s(sendStringData, sizeof(sendStringData), TMP_NUM, sizeof(sendStringData));
    StreamData d1 = {
        sendStringData,
        STR_LEN,
    };
    StreamData d2 = {
        TEST_TMP_BUF,
        TEST_TMP_BUF_LEN,
    };
    StreamFrameInfo tmpf = {};
    for (int32_t times = 0; times < sendTimes; times++) {
        ret = SendStream(sessionId, &d1, &d2, &tmpf);
        EXPECT_EQ(ret, SOFTBUS_OK);
        sleep(1);
    }
    EXPECT_GT(g_qosEventCount[sessionId], 0);
    CloseSession(sessionId);
    sleep(1);
    EXPECT_LE(g_timeDiff[sessionId], 100);
    ret = RemoveSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransQosStatClientTest004
 * @tc.desc: sessionListener with onQosEvent multichannel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransQosStatClientTest, QosStatClientTest004, TestSize.Level0)
{
    int32_t sendTimes = 10;
    int32_t numChannels = 5;
    int32_t ret = CreateSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME, &g_hasQosCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    NodeBasicInfo *info;
    int32_t infoNum;
    ret = GetAllNodeDeviceInfo(UDP_TEST_PKG_NAME, &info, &infoNum);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionAttribute attr = {0};
    attr.dataType = TYPE_STREAM;
    attr.attr.streamAttr.streamType = RAW_STREAM;
    for (int32_t index = 0; index < numChannels; index++) {
        std::string groupId = std::to_string(index);
        int32_t sessionId = OpenSession(UDP_TEST_SESSION_NAME, UDP_TEST_SESSION_NAME,
            info[0].networkId, groupId.c_str(), &attr);
        EXPECT_NE(-1, sessionId);
    }
    sleep(2);
    char sendStringData[STR_LEN];
    memset_s(sendStringData, sizeof(sendStringData), TMP_NUM, sizeof(sendStringData));
    StreamData d1 = {
        sendStringData,
        STR_LEN,
    };
    StreamData d2 = {
        TEST_TMP_BUF,
        TEST_TMP_BUF_LEN,
    };
    StreamFrameInfo tmpf = {};
    std::map<int, int>::iterator iter;
    for (int32_t times = 0; times < sendTimes; times++) {
        iter = g_qosEventCount.begin();
        while (iter != g_qosEventCount.end()) {
            ret = SendStream(iter->first, &d1, &d2, &tmpf);
            EXPECT_EQ(ret, SOFTBUS_OK);
            iter++;
        }
        sleep(1);
    }
    iter = g_qosEventCount.begin();
    while (iter != g_qosEventCount.end()) {
        EXPECT_GT(iter->second, 0);
        CloseSession(iter->second);
        iter++;
    }
    sleep(1);
    ret = RemoveSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransQosStatClientTest005
 * @tc.desc: sessionListener with onQosEvent speedUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransQosStatClientTest, QosStatClientTest005, TestSize.Level0)
{
    int32_t sendTimes = 10;
    uint64_t bigSpeed = 0;
    uint64_t smallSpeed = 0;
    int32_t ret = CreateSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME, &g_hasQosCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    NodeBasicInfo *info;
    int32_t infoNum;
    ret = GetAllNodeDeviceInfo(UDP_TEST_PKG_NAME, &info, &infoNum);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionAttribute attr = {0};
    attr.dataType = TYPE_STREAM;
    attr.attr.streamAttr.streamType = RAW_STREAM;
    int32_t sessionId = OpenSession(UDP_TEST_SESSION_NAME, UDP_TEST_SESSION_NAME,
        info[0].networkId, "0", &attr);
    EXPECT_NE(-1, sessionId);
    sleep(2);

    // big speed
    char sendStringData[STR_LEN];
    memset_s(sendStringData, sizeof(sendStringData), TMP_NUM, sizeof(sendStringData));
    StreamData d1 = {
        sendStringData,
        STR_LEN,
    };
    StreamData d2 = {
        TEST_TMP_BUF,
        TEST_TMP_BUF_LEN,
    };
    StreamFrameInfo tmpf = {};
    for (int32_t times = 0; times < sendTimes; times++) {
        ret = SendStream(sessionId, &d1, &d2, &tmpf);
        EXPECT_EQ(ret, SOFTBUS_OK);
        sleep(1);
    }
    bigSpeed = CalSendBits(g_speedStat[sessionId]);
    g_speedStat[sessionId].clear();

    // small speed
    d1.bufLen = 1000;
    for (int32_t times = 0; times < sendTimes; times++) {
        ret = SendStream(sessionId, &d1, &d2, &tmpf);
        EXPECT_EQ(ret, SOFTBUS_OK);
        sleep(1);
    }
    smallSpeed = CalSendBits(g_speedStat[sessionId]) - bigSpeed;
    EXPECT_LE(smallSpeed, bigSpeed);
    CloseSession(sessionId);
    sleep(1);
    ret = RemoveSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransQosStatClientTest006
 * @tc.desc: sessionListener with onQosEvent speedDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransQosStatClientTest, QosStatClientTest006, TestSize.Level0)
{
    int32_t sendTimes = 10;
    uint64_t bigSpeed = 0;
    uint64_t smallSpeed = 0;
    int32_t ret = CreateSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME, &g_hasQosCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    NodeBasicInfo *info;
    int32_t infoNum;
    ret = GetAllNodeDeviceInfo(UDP_TEST_PKG_NAME, &info, &infoNum);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionAttribute attr = {0};
    attr.dataType = TYPE_STREAM;
    attr.attr.streamAttr.streamType = RAW_STREAM;
    int32_t sessionId = OpenSession(UDP_TEST_SESSION_NAME, UDP_TEST_SESSION_NAME,
        info[0].networkId, "0", &attr);
    EXPECT_NE(-1, sessionId);
    sleep(2);

    // small speed
    char sendStringData[STR_LEN];
    memset_s(sendStringData, sizeof(sendStringData), TMP_NUM, sizeof(sendStringData));
    StreamData d1 = {
        sendStringData,
        STR_LEN,
    };
    StreamData d2 = {
        TEST_TMP_BUF,
        TEST_TMP_BUF_LEN,
    };
    StreamFrameInfo tmpf = {};
    for (int32_t times = 0; times < sendTimes; times++) {
        ret = SendStream(sessionId, &d1, &d2, &tmpf);
        EXPECT_EQ(ret, SOFTBUS_OK);
        sleep(1);
    }
    bigSpeed = CalSendBits(g_speedStat[sessionId]);
    g_speedStat[sessionId].clear();

    // small speed
    d1.bufLen = 1000;
    for (int32_t times = 0; times < sendTimes; times++) {
        ret = SendStream(sessionId, &d1, &d2, &tmpf);
        EXPECT_EQ(ret, SOFTBUS_OK);
        sleep(1);
    }
    smallSpeed = CalSendBits(g_speedStat[sessionId]) - bigSpeed;
    EXPECT_LE(smallSpeed, bigSpeed);
    CloseSession(sessionId);
    sleep(1);
    ret = RemoveSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
} // namespace OHOS
