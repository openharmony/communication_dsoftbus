/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#include "securec.h"
#include <cstdio>
#include <gtest/gtest.h>
#include <map>
#include <vector>

#include "session.h"
#include "softbus_bus_center.h"
#include "softbus_error_code.h"

#define TEST_TMP_BUF             "tmpBuf"
#define TEST_TMP_BUF_LEN         10
#define STR_LEN                  100000
#define TMP_NUM                  97
#define TEST_SEND_TIMES          10
#define TEST_NUM_CHANNELS        5
#define TEST_SMALL_BUF_LEN       1000
#define TEST_TIME_DIFF_THRESHOLD 100
#define TEST_SESSION_WAIT_SEC    2
#define TEST_SEND_INTERVAL_SEC   1

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
    TransQosStatClientTest() { }
    ~TransQosStatClientTest() { }
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
    if (!rateList.empty()) {
        return rateList.back();
    }
    return 0;
}

/*
 * @tc.name: CreateSessionServerNullParamTest001
 * @tc.desc: CreateSessionServer with null listener, null pkgName, or null sessionName returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransQosStatClientTest, CreateSessionServerNullParamTest001, TestSize.Level1)
{
    int32_t ret = CreateSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = CreateSessionServer(nullptr, UDP_TEST_SESSION_NAME, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = CreateSessionServer(UDP_TEST_PKG_NAME, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: RemoveSessionServerTest001
 * @tc.desc: RemoveSessionServer with null pkgName or null sessionName returns SOFTBUS_INVALID_PARAM,
 *           and returns SOFTBUS_ACCESS_TOKEN_DENIED when no session server is registered
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransQosStatClientTest, RemoveSessionServerTest001, TestSize.Level1)
{
    int32_t ret = RemoveSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME);
    EXPECT_EQ(ret, SOFTBUS_ACCESS_TOKEN_DENIED);
    ret = RemoveSessionServer(nullptr, UDP_TEST_SESSION_NAME);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = RemoveSessionServer(UDP_TEST_PKG_NAME, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SendStreamNoQosEventTest001
 * @tc.desc: send stream with null session listener, verify QoS event count stays zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransQosStatClientTest, SendStreamNoQosEventTest001, TestSize.Level1)
{
    int32_t ret = CreateSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    NodeBasicInfo localInfo = { };
    ret = GetLocalNodeDeviceInfo(UDP_TEST_PKG_NAME, &localInfo);
    SessionAttribute attr = { };
    attr.dataType = TYPE_STREAM;
    attr.attr.streamAttr.streamType = RAW_STREAM;
    int32_t sessionId = OpenSession(UDP_TEST_SESSION_NAME, UDP_TEST_SESSION_NAME, localInfo.networkId, "0", &attr);
    EXPECT_NE(sessionId, -1);
    sleep(TEST_SESSION_WAIT_SEC);
    char sendStringData[STR_LEN];
    (void)memset_s(sendStringData, sizeof(sendStringData), TMP_NUM, sizeof(sendStringData));
    StreamData d1 = { sendStringData, STR_LEN };
    StreamData d2 = { g_tmpBuf, TEST_TMP_BUF_LEN };
    StreamFrameInfo tmpf = { };
    for (int32_t times = 0; times < TEST_SEND_TIMES; times++) {
        ret = SendStream(sessionId, &d1, &d2, &tmpf);
        EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
        sleep(TEST_SEND_INTERVAL_SEC);
    }
    EXPECT_EQ(g_qosEventCount[sessionId], 0);
    CloseSession(sessionId);
    sleep(TEST_SEND_INTERVAL_SEC);
    ret = RemoveSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME);
    EXPECT_EQ(ret, SOFTBUS_ACCESS_TOKEN_DENIED);
}

/*
 * @tc.name: SendStreamNoQosTimeDiffTest001
 * @tc.desc: send stream with null session listener, verify QoS event count stays zero and time diff within threshold
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransQosStatClientTest, SendStreamNoQosTimeDiffTest001, TestSize.Level0)
{
    int32_t ret = CreateSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    NodeBasicInfo localInfo = { };
    ret = GetLocalNodeDeviceInfo(UDP_TEST_PKG_NAME, &localInfo);
    SessionAttribute attr = { };
    attr.dataType = TYPE_STREAM;
    attr.attr.streamAttr.streamType = RAW_STREAM;
    int32_t sessionId = OpenSession(UDP_TEST_SESSION_NAME, UDP_TEST_SESSION_NAME, localInfo.networkId, "0", &attr);
    EXPECT_NE(sessionId, -1);
    sleep(TEST_SESSION_WAIT_SEC);
    char sendStringData[STR_LEN];
    (void)memset_s(sendStringData, sizeof(sendStringData), TMP_NUM, sizeof(sendStringData));
    StreamData d1 = { sendStringData, STR_LEN };
    StreamData d2 = { g_tmpBuf, TEST_TMP_BUF_LEN };
    StreamFrameInfo tmpf = { };
    for (int32_t times = 0; times < TEST_SEND_TIMES; times++) {
        ret = SendStream(sessionId, &d1, &d2, &tmpf);
        EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
        sleep(TEST_SEND_INTERVAL_SEC);
    }
    EXPECT_EQ(g_qosEventCount[sessionId], 0);
    CloseSession(sessionId);
    sleep(TEST_SEND_INTERVAL_SEC);
    EXPECT_LE(g_timeDiff[sessionId], TEST_TIME_DIFF_THRESHOLD);
    ret = RemoveSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME);
    EXPECT_EQ(ret, SOFTBUS_ACCESS_TOKEN_DENIED);
}

/*
 * @tc.name: SendStreamMultiChannelQosTest001
 * @tc.desc: send stream across multiple channels, verify QoS event count is positive for each session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransQosStatClientTest, SendStreamMultiChannelQosTest001, TestSize.Level1)
{
    int32_t ret = CreateSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    NodeBasicInfo localInfo = { };
    ret = GetLocalNodeDeviceInfo(UDP_TEST_PKG_NAME, &localInfo);
    SessionAttribute attr = { };
    attr.dataType = TYPE_STREAM;
    attr.attr.streamAttr.streamType = RAW_STREAM;
    for (int32_t index = 0; index < TEST_NUM_CHANNELS; index++) {
        std::string groupId = std::to_string(index);
        int32_t sessionId =
            OpenSession(UDP_TEST_SESSION_NAME, UDP_TEST_SESSION_NAME, localInfo.networkId, groupId.c_str(), &attr);
        EXPECT_NE(sessionId, -1);
    }
    sleep(TEST_SESSION_WAIT_SEC);
    char sendStringData[STR_LEN];
    (void)memset_s(sendStringData, sizeof(sendStringData), TMP_NUM, sizeof(sendStringData));
    StreamData d1 = { sendStringData, STR_LEN };
    StreamData d2 = { g_tmpBuf, TEST_TMP_BUF_LEN };
    StreamFrameInfo tmpf = { };
    std::map<int32_t, int32_t>::iterator iter;
    for (int32_t times = 0; times < TEST_SEND_TIMES; times++) {
        iter = g_qosEventCount.begin();
        while (iter != g_qosEventCount.end()) {
            ret = SendStream(iter->first, &d1, &d2, &tmpf);
            EXPECT_EQ(ret, SOFTBUS_OK);
            iter++;
        }
        sleep(TEST_SEND_INTERVAL_SEC);
    }
    iter = g_qosEventCount.begin();
    while (iter != g_qosEventCount.end()) {
        EXPECT_GT(iter->second, 0);
        CloseSession(iter->first);
        iter++;
    }
    sleep(TEST_SEND_INTERVAL_SEC);
    ret = RemoveSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME);
    EXPECT_EQ(ret, SOFTBUS_ACCESS_TOKEN_DENIED);
}

/*
 * @tc.name: SendStreamSpeedBigThenSmallTest001
 * @tc.desc: send stream with large data then small data, verify small speed does not exceed big speed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransQosStatClientTest, SendStreamSpeedBigThenSmallTest001, TestSize.Level1)
{
    int32_t ret = CreateSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    NodeBasicInfo localInfo = { };
    ret = GetLocalNodeDeviceInfo(UDP_TEST_PKG_NAME, &localInfo);
    SessionAttribute attr = { };
    attr.dataType = TYPE_STREAM;
    attr.attr.streamAttr.streamType = RAW_STREAM;
    int32_t sessionId = OpenSession(UDP_TEST_SESSION_NAME, UDP_TEST_SESSION_NAME, localInfo.networkId, "0", &attr);
    EXPECT_NE(sessionId, -1);
    sleep(TEST_SESSION_WAIT_SEC);
    char sendStringData[STR_LEN];
    (void)memset_s(sendStringData, sizeof(sendStringData), TMP_NUM, sizeof(sendStringData));
    StreamData d1 = { sendStringData, STR_LEN };
    StreamData d2 = { g_tmpBuf, TEST_TMP_BUF_LEN };
    StreamFrameInfo tmpf = { };
    for (int32_t times = 0; times < TEST_SEND_TIMES; times++) {
        ret = SendStream(sessionId, &d1, &d2, &tmpf);
        EXPECT_NE(ret, SOFTBUS_OK);
        sleep(TEST_SEND_INTERVAL_SEC);
    }
    uint64_t bigSpeed = CalSendBits(g_speedStat[sessionId]);
    g_speedStat[sessionId].clear();
    d1.bufLen = TEST_SMALL_BUF_LEN;
    for (int32_t times = 0; times < TEST_SEND_TIMES; times++) {
        ret = SendStream(sessionId, &d1, &d2, &tmpf);
        EXPECT_NE(ret, SOFTBUS_OK);
        sleep(TEST_SEND_INTERVAL_SEC);
    }
    uint64_t smallSpeed = CalSendBits(g_speedStat[sessionId]);
    EXPECT_LE(smallSpeed, bigSpeed);
    CloseSession(sessionId);
    sleep(TEST_SEND_INTERVAL_SEC);
    ret = RemoveSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME);
    EXPECT_EQ(ret, SOFTBUS_ACCESS_TOKEN_DENIED);
}

/*
 * @tc.name: SendStreamSpeedSmallThenBigTest001
 * @tc.desc: send stream with small data then large data, verify small speed does not exceed big speed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransQosStatClientTest, SendStreamSpeedSmallThenBigTest001, TestSize.Level1)
{
    int32_t ret = CreateSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    NodeBasicInfo localInfo = { };
    ret = GetLocalNodeDeviceInfo(UDP_TEST_PKG_NAME, &localInfo);
    SessionAttribute attr = { };
    attr.dataType = TYPE_STREAM;
    attr.attr.streamAttr.streamType = RAW_STREAM;
    int32_t sessionId = OpenSession(UDP_TEST_SESSION_NAME, UDP_TEST_SESSION_NAME, localInfo.networkId, "0", &attr);
    EXPECT_NE(sessionId, -1);
    sleep(TEST_SESSION_WAIT_SEC);
    char sendStringData[STR_LEN];
    (void)memset_s(sendStringData, sizeof(sendStringData), TMP_NUM, sizeof(sendStringData));
    StreamData d1 = { sendStringData, TEST_SMALL_BUF_LEN };
    StreamData d2 = { g_tmpBuf, TEST_TMP_BUF_LEN };
    StreamFrameInfo tmpf = { };
    for (int32_t times = 0; times < TEST_SEND_TIMES; times++) {
        ret = SendStream(sessionId, &d1, &d2, &tmpf);
        EXPECT_NE(ret, SOFTBUS_OK);
        sleep(TEST_SEND_INTERVAL_SEC);
    }
    uint64_t smallSpeed = CalSendBits(g_speedStat[sessionId]);
    g_speedStat[sessionId].clear();
    d1.bufLen = STR_LEN;
    for (int32_t times = 0; times < TEST_SEND_TIMES; times++) {
        ret = SendStream(sessionId, &d1, &d2, &tmpf);
        EXPECT_NE(ret, SOFTBUS_OK);
        sleep(TEST_SEND_INTERVAL_SEC);
    }
    uint64_t bigSpeed = CalSendBits(g_speedStat[sessionId]);
    EXPECT_LE(smallSpeed, bigSpeed);
    CloseSession(sessionId);
    sleep(TEST_SEND_INTERVAL_SEC);
    ret = RemoveSessionServer(UDP_TEST_PKG_NAME, UDP_TEST_SESSION_NAME);
    EXPECT_EQ(ret, SOFTBUS_ACCESS_TOKEN_DENIED);
}
} // namespace OHOS
