/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include "softbus_error_code.h"

#define TEST_TMP_BUF "tmpBuf"
#define TEST_TMP_BUF_LEN 10
#define STR_LEN 100000
#define TMP_NUM 97

char g_tmpBuf[] = "tmpBuf";

using namespace testing::ext;
namespace OHOS {
static const char *UDP_TEST_PKG_NAME = "com.plrdtest.dsoftbus.client";
static const char *UDP_TEST_SESSION_NAME = "com.plrdtest.dsoftbus.JtSendRawStream_0";
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

static uint64_t CalSendBits(const std::vector<uint64_t> &rateList)
{
    if (rateList.size() > 0) {
        return rateList[rateList.size() - 1];
    }
    return 0;
}

/**
 * @tc.name: TransQosStatClientTest001
 * @tc.desc: null sessionListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransQosStatClientTest, QosStatClientTest001, TestSize.Level0)
{
    int32_t ret = CreateSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
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
    ISessionListener *g_noQosCb = nullptr;
    int32_t ret = CreateSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME, g_noQosCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    NodeBasicInfo *info;
    int32_t infoNum;
    ret = GetAllNodeDeviceInfo(UDP_TEST_PKG_NAME, &info, &infoNum);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NOT_INIT);
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
        g_tmpBuf,
        TEST_TMP_BUF_LEN,
    };
    StreamFrameInfo tmpf = {};
    for (int32_t times = 0; times < sendTimes; times++) {
        ret = SendStream(sessionId, &d1, &d2, &tmpf);
        EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
        sleep(1);
    }
    EXPECT_EQ(g_qosEventCount[sessionId], 0);
    CloseSession(sessionId);
    sleep(1);
    ret = RemoveSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME);
    EXPECT_EQ(ret, SOFTBUS_ACCESS_TOKEN_DENIED);
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
    ISessionListener *g_hasQosCb = nullptr;
    int32_t ret = CreateSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME, g_hasQosCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    NodeBasicInfo *info;
    int32_t infoNum;
    ret = GetAllNodeDeviceInfo(UDP_TEST_PKG_NAME, &info, &infoNum);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NOT_INIT);
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
        g_tmpBuf,
        TEST_TMP_BUF_LEN,
    };
    StreamFrameInfo tmpf = {};
    for (int32_t times = 0; times < sendTimes; times++) {
        ret = SendStream(sessionId, &d1, &d2, &tmpf);
        EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
        sleep(1);
    }
    EXPECT_EQ(g_qosEventCount[sessionId], 0);
    CloseSession(sessionId);
    sleep(1);
    EXPECT_LE(g_timeDiff[sessionId], 100);
    ret = RemoveSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME);
    EXPECT_EQ(ret, SOFTBUS_ACCESS_TOKEN_DENIED);
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
    ISessionListener *g_hasQosCb = nullptr;
    int32_t ret = CreateSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME, g_hasQosCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    NodeBasicInfo *info;
    int32_t infoNum;
    ret = GetAllNodeDeviceInfo(UDP_TEST_PKG_NAME, &info, &infoNum);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NOT_INIT);
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
    StreamData d1 = { sendStringData, STR_LEN };
    StreamData d2 = { g_tmpBuf, TEST_TMP_BUF_LEN };
    StreamFrameInfo tmpf = {};
    std::map<int32_t, int32_t>::iterator iter;
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
    EXPECT_EQ(ret, SOFTBUS_ACCESS_TOKEN_DENIED);
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
    ISessionListener *g_hasQosCb = nullptr;
    int32_t ret = CreateSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME, g_hasQosCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    NodeBasicInfo *info;
    int32_t infoNum;
    ret = GetAllNodeDeviceInfo(UDP_TEST_PKG_NAME, &info, &infoNum);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NOT_INIT);
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
        g_tmpBuf,
        TEST_TMP_BUF_LEN,
    };
    StreamFrameInfo tmpf = {};
    for (int32_t times = 0; times < sendTimes; times++) {
        ret = SendStream(sessionId, &d1, &d2, &tmpf);
        EXPECT_NE(ret, SOFTBUS_OK);
        sleep(1);
    }
    bigSpeed = CalSendBits(g_speedStat[sessionId]);
    g_speedStat[sessionId].clear();

    // small speed
    d1.bufLen = 1000;
    for (int32_t times = 0; times < sendTimes; times++) {
        ret = SendStream(sessionId, &d1, &d2, &tmpf);
        EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
        sleep(1);
    }
    smallSpeed = CalSendBits(g_speedStat[sessionId]) - bigSpeed;
    EXPECT_LE(smallSpeed, bigSpeed);
    CloseSession(sessionId);
    sleep(1);
    ret = RemoveSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME);
    EXPECT_EQ(ret, SOFTBUS_ACCESS_TOKEN_DENIED);
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
    ISessionListener *g_hasQosCb = nullptr;
    int32_t ret = CreateSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME, g_hasQosCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    NodeBasicInfo *info;
    int32_t infoNum;
    ret = GetAllNodeDeviceInfo(UDP_TEST_PKG_NAME, &info, &infoNum);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NOT_INIT);
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
        g_tmpBuf,
        TEST_TMP_BUF_LEN,
    };
    StreamFrameInfo tmpf = {};
    for (int32_t times = 0; times < sendTimes; times++) {
        ret = SendStream(sessionId, &d1, &d2, &tmpf);
        EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
        sleep(1);
    }
    bigSpeed = CalSendBits(g_speedStat[sessionId]);
    g_speedStat[sessionId].clear();

    // small speed
    d1.bufLen = 1000;
    for (int32_t times = 0; times < sendTimes; times++) {
        ret = SendStream(sessionId, &d1, &d2, &tmpf);
        EXPECT_NE(ret, SOFTBUS_OK);
        sleep(1);
    }
    smallSpeed = CalSendBits(g_speedStat[sessionId]) - bigSpeed;
    EXPECT_LE(smallSpeed, bigSpeed);
    CloseSession(sessionId);
    sleep(1);
    ret = RemoveSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME);
    EXPECT_EQ(ret, SOFTBUS_ACCESS_TOKEN_DENIED);
}
} // namespace OHOS
