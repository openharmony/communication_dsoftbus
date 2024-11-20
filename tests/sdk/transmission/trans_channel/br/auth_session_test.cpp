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
#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>
#include <unistd.h>

#include "common_list.h"
#include "inner_session.h"
#include "session.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "softbus_bus_center.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_utils.h"

using namespace testing::ext;

namespace OHOS {
enum TEST_WAY {
    PASSIVE_OPENAUTHSESSION_WAY = 0,
    ACTIVE_OPENAUTHSESSION_WAY
};

const int32_t CONN_SINGLE_WAIT_TIMEOUT = 5;
const int32_t CONN_SLEEP_TIME = 1;
const int32_t CLOSE_DELAY_TIME = 500;
const int32_t INPUT_ERR = (-1);

const int32_t SEND_DATA_SIZE_1K = 1024;
const int32_t SEND_DATA_SIZE_4K = 4 * 1024;
const int32_t SEND_DATA_SIZE_40K = 40 * 1000 - 8;

const int32_t CONN_ADDR_INFO_COUNT = 5;
ConnectionAddr g_addrInfo[CONN_ADDR_INFO_COUNT];

ISessionListener g_sessionlistener;
int32_t g_openCount = 0;
const char *g_testModuleName = "com.plrdtest";
const char *g_testSessionName   = "com.plrdtest.dsoftbus";
const char *g_testData = "{\"data\":\"open auth session test!!!\"}";

int32_t g_sessionId = -1;
int32_t g_sessionIdTwo = -1;
bool g_successFlag = false;
int32_t g_testWay = -1;

int32_t TestSendBytesData(int32_t sessionId, const char *data)
{
    int32_t ret = SendBytes(sessionId, data, SEND_DATA_SIZE_1K);
    if (ret != SOFTBUS_OK) {
        printf("SendBytes 1K err.\n");
        return ret;
    }
    ret = SendBytes(sessionId, data, SEND_DATA_SIZE_4K);
    if (ret != SOFTBUS_OK) {
        printf("SendBytes 4K err.\n");
        return ret;
    }
    ret = SendBytes(sessionId, data, SEND_DATA_SIZE_40K);
    if (ret != SOFTBUS_OK) {
        printf("SendBytes 40000 err.\n");
        return ret;
    }
    ret = SendBytes(sessionId, data, SEND_DATA_SIZE_40K + 1);
    if (ret == SOFTBUS_OK) {
        printf("SendBytes 40001 err.\n");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t TestSendMessageData(int32_t sessionId, const char *data)
{
    int32_t ret = SendMessage(sessionId, data, SEND_DATA_SIZE_1K);
    if (ret != SOFTBUS_OK) {
        printf("SendMessage 1K err.\n");
        return ret;
    }
    ret = SendMessage(sessionId, data, SEND_DATA_SIZE_4K);
    if (ret != SOFTBUS_OK) {
        printf("SendMessage 4K err.\n");
        return ret;
    }
    ret = SendMessage(sessionId, data, SEND_DATA_SIZE_4K + 1);
    if (ret == SOFTBUS_OK) {
        printf("SendMessage 4K + 1 err.\n");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t TestSendData(int32_t sessionId, const char *data, int32_t len)
{
    int32_t ret;
    if (len <= SEND_DATA_SIZE_40K) {
        ret = SendBytes(sessionId, data, len);
        if (ret != SOFTBUS_OK) {
            return ret;
        }
    } else {
        ret = TestSendBytesData(sessionId, data);
        if (ret != SOFTBUS_OK) {
            return ret;
        }
        ret = TestSendMessageData(sessionId, data);
        if (ret != SOFTBUS_OK) {
            return ret;
        }
    }
    return SOFTBUS_OK;
}

int32_t OnSessionOpened(int32_t sessionId, int32_t result)
{
    printf("############# session opened,sesison id[%d] result[%d]\n", sessionId, result);
    if (result == SOFTBUS_OK) {
        if (g_sessionId == -1) {
            g_sessionId = sessionId;
        }
        g_successFlag = true;
        g_openCount++;
    }
    return result;
}

void OnSessionClosed(int32_t sessionId)
{
    printf("############# session closed, session id = %d\n", sessionId);
    g_sessionId = -1;
    g_successFlag = false;
}

void OnBytesReceived(int32_t sessionId, const void *data, unsigned int len)
{
    if (g_testWay == PASSIVE_OPENAUTHSESSION_WAY) {
        SendBytes(sessionId, "{\"received ok\"}", strlen("{\"received ok\"}"));
    }
    printf("bytes received, sessionid[%d], data[%s], dataLen[%u]\n", sessionId, data, len);
}

void OnMessageReceived(int32_t sessionId, const void *data, unsigned int len)
{
    printf("msg received, sessionid[%d], data[%s], dataLen[%u]\n", sessionId, data, len);
}

void TestSessionListenerInit(void)
{
    g_sessionlistener.OnSessionOpened = OnSessionOpened;
    g_sessionlistener.OnSessionClosed = OnSessionClosed;
    g_sessionlistener.OnBytesReceived = OnBytesReceived;
    g_sessionlistener.OnMessageReceived = OnMessageReceived;
}

int32_t TestCreateSessionServer(void)
{
    int32_t ret = CreateSessionServer(g_testModuleName, g_testSessionName, &g_sessionlistener);
    if (ret != SOFTBUS_SERVER_NAME_REPEATED && ret != SOFTBUS_OK) { // -986: SOFTBUS_SERVER_NAME_REPEATED
        printf("CreateSessionServer ret: %d \n", ret);
        return ret;
    }
    printf("CreateSessionServer ret: %d \n", ret);
    return SOFTBUS_OK;
}

int32_t TestOpenAuthSession(const ConnectionAddr *addrInfo, bool two)
{
    g_sessionId = OpenAuthSession(g_testSessionName, addrInfo, 1, NULL);
    if (g_sessionId < 0) {
        printf("OpenAuthSession ret[%d]", g_sessionId);
        return SOFTBUS_INVALID_SESSION_ID;
    }
    if (two) {
        g_sessionIdTwo = OpenAuthSession(g_testSessionName, addrInfo, 1, NULL);
        if (g_sessionIdTwo < 0) {
            printf("OpenAuthSession ret[%d]", g_sessionIdTwo);
            return SOFTBUS_INVALID_SESSION_ID;
        }
    }
    int32_t timeout = 0;
    while (!g_successFlag) {
        timeout++;
        if (timeout > CONN_SINGLE_WAIT_TIMEOUT) {
            printf("wait [%ds] timeout!!\n", CONN_SINGLE_WAIT_TIMEOUT);
            return SOFTBUS_TIMOUT;
        }
        sleep(CONN_SLEEP_TIME);
    }
    return SOFTBUS_OK;
}

void TestCloseSession(void)
{
    printf("TestCloseSession exit\n");
    if (g_sessionId > 0) {
        CloseSession(g_sessionId);
        g_sessionId = -1;
        g_successFlag = false;
    }
}

void TestCloseSessionTwo(void)
{
    printf("TestCloseSessionTwo exit\n");
    if (g_sessionIdTwo > 0) {
        CloseSession(g_sessionIdTwo);
        g_sessionIdTwo = -1;
    }
}

class AuthSessionTest : public testing::Test {
public:
    AuthSessionTest()
    {}
    ~AuthSessionTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    int32_t TestWaitOpenSession(int32_t count);
};

void AuthSessionTest::SetUpTestCase(void)
{
    SoftbusConfigInit();
    TestSessionListenerInit();
    printf("********Disc Test Begin*********\r\n");
    printf("*   0.passive openAuthSession  *\r\n");
    printf("*   1.active openAuthSession   *\r\n");
    printf("********************************\r\n");
    printf("input the num:");
    if (scanf_s("%d", &g_testWay, sizeof(g_testWay)) < 0) {
        printf("input error!\n");
    }
    getchar();
}

void AuthSessionTest::TearDownTestCase(void)
{}

void AuthSessionTest::SetUp(void)
{}

void AuthSessionTest::TearDown(void)
{
    TestCloseSession();
}

int32_t AuthSessionTest::TestWaitOpenSession(int32_t count)
{
    int32_t timeout = count * CONN_SINGLE_WAIT_TIMEOUT;
    while (g_openCount < count) {
        --timeout;
        if (!timeout) {
            printf("wait [%d] timeout!!\n", count);
            break;
        }
        sleep(CONN_SLEEP_TIME);
    }
    return (g_openCount < count) ? SOFTBUS_TIMOUT : SOFTBUS_OK;
}

/*
* @tc.name: testPassiveOpenAuthSession001
* @tc.desc: test passive open auth session
* @tc.type: FUNC
* @tc.require:AR000GIRGG
*/
HWTEST_F(AuthSessionTest, testPassiveOpenAuthSession001, TestSize.Level1)
{
    if (g_testWay != PASSIVE_OPENAUTHSESSION_WAY) {
        printf("skip testPassiveOpenAuthSession001 test.");
        return;
    }
    printf("test begin testPassiveOpenAuthSession001 \r\n");
    int32_t ret = TestCreateSessionServer();
    EXPECT_EQ(SOFTBUS_OK, ret);
    int32_t count = 10;
    printf("input the test count: \n");
    if (scanf_s("%d", &count, sizeof(count)) < 0) {
        printf("input error!\n");
        EXPECT_EQ(SOFTBUS_OK, INPUT_ERR);
        return;
    }
    getchar();
    ret = TestWaitOpenSession(count);
    EXPECT_EQ(SOFTBUS_OK, ret);
    sleep(CONN_SLEEP_TIME);
    sleep(CONN_SLEEP_TIME);
    TestCloseSession();
};

/*
* @tc.name: testActiveOpenAuthSession001
* @tc.desc: test active open auth session
* @tc.type: FUNC
* @tc.require:AR000GIRGG
*/
HWTEST_F(AuthSessionTest, testActiveOpenAuthSession001, TestSize.Level1)
{
    if (g_testWay != ACTIVE_OPENAUTHSESSION_WAY) {
        printf("skip testActiveOpenAuthSession001 test.");
        return;
    }
    printf("test begin testActiveOpenAuthSession001 \r\n");
    int32_t ret = TestCreateSessionServer();
    EXPECT_EQ(SOFTBUS_OK, ret);
    g_addrInfo[0].type = CONNECTION_ADDR_BR;
    printf("input macaddr: \n");
    if (scanf_s("%s", g_addrInfo[0].info.br.brMac, BT_MAC_LEN) < 0) {
        printf("input error!\n");
        EXPECT_EQ(SOFTBUS_OK, INPUT_ERR);
        return;
    }
    printf("brMac: %s\n", g_addrInfo[0].info.br.brMac);
    getchar();
    int32_t count = 10;
    printf("input the test count: \n");
    if (scanf_s("%d", &count, sizeof(count)) < 0) {
        printf("input error!\n");
        EXPECT_EQ(SOFTBUS_OK, INPUT_ERR);
        return;
    }
    char *testData = (char *)SoftBusCalloc(SEND_DATA_SIZE_40K + 1);
    if (testData == nullptr) {
        printf("SoftBusCalloc error!\n");
        EXPECT_EQ(SOFTBUS_OK, INPUT_ERR);
        return;
    }
    if (memcpy_s(testData, SEND_DATA_SIZE_40K + 1, g_testData, strlen(g_testData)) != EOK) {
        printf("memcpy_s g_testData failed!\n");
        SoftBusFree(testData);
        return;
    }
    for (int32_t i = 0; i < count; i++) {
        ret = TestOpenAuthSession(&(g_addrInfo[0]), false);
        EXPECT_EQ(SOFTBUS_OK, ret);
        ret = TestSendData(g_sessionId, testData, SEND_DATA_SIZE_40K + 1);
        EXPECT_EQ(SOFTBUS_OK, ret);
        sleep(CONN_SLEEP_TIME);
        TestCloseSession();
        SoftBusSleepMs(CLOSE_DELAY_TIME);
    }
    SoftBusFree(testData);
};

/*
* @tc.name: testActiveOpenAuthSession002
* @tc.desc: test active open 2 auth session
* @tc.type: FUNC
* @tc.require:AR000GIRGG
*/
HWTEST_F(AuthSessionTest, testActiveOpenAuthSession002, TestSize.Level1)
{
    if (g_testWay != ACTIVE_OPENAUTHSESSION_WAY) {
        printf("skip testActiveOpenAuthSession002 test.");
        return;
    }
    printf("test begin testActiveOpenAuthSession002 \r\n");
    int32_t ret = TestCreateSessionServer();
    EXPECT_EQ(SOFTBUS_OK, ret);
    char *testData = (char *)SoftBusCalloc(SEND_DATA_SIZE_1K);
    if (testData == nullptr) {
        printf("SoftBusCalloc error!\n");
        EXPECT_EQ(SOFTBUS_OK, INPUT_ERR);
        return;
    }
    if (memcpy_s(testData, SEND_DATA_SIZE_1K, g_testData, strlen(g_testData)) != EOK) {
        printf("memcpy_s g_testData failed!\n");
        SoftBusFree(testData);
        return;
    }
    ret = TestOpenAuthSession(&(g_addrInfo[0]), true);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TestSendData(g_sessionId, testData, SEND_DATA_SIZE_1K);
    ret = TestSendData(g_sessionIdTwo, testData, SEND_DATA_SIZE_1K);
    EXPECT_EQ(SOFTBUS_OK, ret);
    sleep(CONN_SLEEP_TIME);
    TestCloseSession();
    TestCloseSessionTwo();
    SoftBusSleepMs(CLOSE_DELAY_TIME);
    SoftBusFree(testData);
};
} // namespace OHOS