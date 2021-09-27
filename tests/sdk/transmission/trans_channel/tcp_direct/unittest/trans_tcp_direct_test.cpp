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

#include <securec.h>

#include "gtest/gtest.h"
#include "session.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"
#include "trans_tcp_direct_listener.h"
#include "trans_tcp_direct_manager.h"
#include "trans_tcp_direct_message.h"

#define TEST_ASSERT_TRUE(ret)  \
    if (ret) {                 \
        LOG_INFO("[succ]:%d\n", __LINE__);    \
        printf("[succ]:%d\n", __LINE__);    \
        g_succTestCount++;       \
    } else {                   \
        LOG_INFO("[error]:%d\n", __LINE__);    \
        printf("[error]:%d\n", __LINE__);    \
        g_failTestCount++;       \
    }

using namespace testing::ext;

namespace OHOS {
static int32_t g_succTestCount = 0;
static int32_t g_failTestCount = 0;

class TransTcpDirectTest : public testing::Test {
public:
    TransTcpDirectTest()
    {}
    ~TransTcpDirectTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransTcpDirectTest::SetUpTestCase(void)
{}

void TransTcpDirectTest::TearDownTestCase(void)
{}

static int OnSessionOpened(int sessionId, int result)
{
    LOG_INFO("session opened,sesison id = %d\r\n", sessionId);
    return SOFTBUS_OK;
}

static void OnSessionClosed(int sessionId)
{
    LOG_INFO("session closed, session id = %d\r\n", sessionId);
}

static void OnBytesReceived(int sessionId, const void *data, unsigned int len)
{
    LOG_INFO("session bytes received, session id = %d\r\n", sessionId);
}

static void OnMessageReceived(int sessionId, const void *data, unsigned int len)
{
    LOG_INFO("session msg received, session id = %d\r\n", sessionId);
}

static SessionAttribute g_sessionAttr = {
    .dataType = TYPE_BYTES
};

static ISessionListener g_sessionlistener = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnBytesReceived = OnBytesReceived,
    .OnMessageReceived = OnMessageReceived
};
char const *g_pkgName = "com.communication.demo";
char const *g_sessionName = "com.communication.demo.JtOnOpenSession";
char const *g_networkid = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";
char const *g_groupid = "TEST_GROUP_ID";
#define TEST_SESSION_KEY "TEST_SESSION_KEY"

/**
 * @tc.name: CreateSessionServerTest001
 * @tc.desc: extern module active publish, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, CreateSessionServerTest001, TestSize.Level1)
{
    int ret = 0;
    ret = CreateSessionServer(NULL, g_sessionName, &g_sessionlistener);
    TEST_ASSERT_TRUE(ret != 0);

    ret = CreateSessionServer(g_pkgName, NULL, &g_sessionlistener);
    TEST_ASSERT_TRUE(ret != 0);

    ret = CreateSessionServer(g_pkgName, g_sessionName, NULL);
    TEST_ASSERT_TRUE(ret != 0);

    ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    TEST_ASSERT_TRUE(ret == 0);

    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    TEST_ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: CreateSessionServerTest002
 * @tc.desc: extern module active publish, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, CreateSessionServerTest002, TestSize.Level1)
{
    int ret;
    ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    TEST_ASSERT_TRUE(ret == 0);

    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    TEST_ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: CreateSessionServerTest003
 * @tc.desc: extern module active publish, use the same normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, CreateSessionServerTest003, TestSize.Level1)
{
    int ret = 0;
    ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    TEST_ASSERT_TRUE(ret == 0);

    ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    TEST_ASSERT_TRUE(ret != 0);

    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    TEST_ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: CreateSessionServerTest004
 * @tc.desc: extern module active publish, create 9 sessionServer, succ 8, failed at 9th.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, CreateSessionServerTest004, TestSize.Level1)
{
    int ret, i;
    char const *sessionName[] = {
        "com.communication.demo.JtOnOpenSession0",
        "com.communication.demo.JtOnOpenSession1",
        "com.communication.demo.JtOnOpenSession2",
        "com.communication.demo.JtOnOpenSession3",
        "com.communication.demo.JtOnOpenSession4",
        "com.communication.demo.JtOnOpenSession5",
        "com.communication.demo.JtOnOpenSession6",
        "com.communication.demo.JtOnOpenSession7",
        "com.communication.demo.JtOnOpenSession8",
        "com.communication.demo.JtOnOpenSession9"
    };

    char const *pkgName[] = {
        "com.communication.demo0",
        "com.communication.demo1",
        "com.communication.demo2",
        "com.communication.demo3",
        "com.communication.demo4",
        "com.communication.demo5",
        "com.communication.demo6",
        "com.communication.demo7",
        "com.communication.demo8",
        "com.communication.demo9"
    };

    for (i = 0; i < 8; i++) {
        ret = CreateSessionServer(pkgName[i], sessionName[i], &g_sessionlistener);
        TEST_ASSERT_TRUE(ret == 0);
    }
    ret = CreateSessionServer(pkgName[i], sessionName[i], &g_sessionlistener);
    TEST_ASSERT_TRUE(ret != 0);

    for (i = 0; i < 8; i++) {
        ret = RemoveSessionServer(pkgName[i], sessionName[i]);
        TEST_ASSERT_TRUE(ret == 0);
    }
}

/**
 * @tc.name: RemoveSessionServerTest001
 * @tc.desc: extern module active publish, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, RemoveSessionServerTest001, TestSize.Level1)
{
    int ret;
    ret = RemoveSessionServer(NULL, g_sessionName);
    TEST_ASSERT_TRUE(ret != 0);

    ret = RemoveSessionServer(g_pkgName, NULL);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: RemoveSessionServerTest002
 * @tc.desc: extern module active publish, use the same parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, RemoveSessionServerTest002, TestSize.Level1)
{
    int ret;
    ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    TEST_ASSERT_TRUE(ret == 0);

    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    TEST_ASSERT_TRUE(ret == 0);

    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: OpenSessionTest001
 * @tc.desc: extern module active publish, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, OpenSessionTest001, TestSize.Level1)
{
    int ret;
    ret = OpenSession(NULL, g_sessionName, g_networkid, g_groupid, &g_sessionAttr);
    TEST_ASSERT_TRUE(ret != 0);

    ret = OpenSession(g_sessionName, NULL, g_networkid, g_groupid, &g_sessionAttr);
    TEST_ASSERT_TRUE(ret != 0);

    ret = OpenSession(g_sessionName, g_sessionName, NULL, g_groupid, &g_sessionAttr);
    TEST_ASSERT_TRUE(ret != 0);

    ret = OpenSession(g_sessionName, g_sessionName, g_networkid, NULL, &g_sessionAttr);
    TEST_ASSERT_TRUE(ret != 0);

    ret = OpenSession(g_sessionName, g_sessionName, g_networkid, g_groupid, NULL);

    g_sessionAttr.dataType = TYPE_BUTT;
    ret = OpenSession(g_sessionName, g_sessionName, g_networkid, g_groupid, &g_sessionAttr);
    g_sessionAttr.dataType = TYPE_BYTES;
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: SendMessageTest001
 * @tc.desc: extern module active publish, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, SendMessageTest001, TestSize.Level1)
{
    int ret;
    int sessionId = 1;
    char const *data = "testdata";
    uint32_t len = strlen(data);

    ret = SendMessage(-1, data, len);
    TEST_ASSERT_TRUE(ret != 0);

    ret = SendMessage(sessionId, NULL, len);
    TEST_ASSERT_TRUE(ret != 0);

    ret = SendMessage(sessionId, data, -1);
    TEST_ASSERT_TRUE(ret != 0);

    ret = SendMessage(sessionId, data, 0);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: SendBytesTest001
 * @tc.desc: extern module active publish, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, SendBytesTest001, TestSize.Level1)
{
    int ret;
    int sessionId = 1;
    char const *data = "testdata";
    uint32_t len = strlen(data);

    ret = SendBytes(-1, data, len);
    TEST_ASSERT_TRUE(ret != 0);

    ret = SendBytes(sessionId, NULL, len);
    TEST_ASSERT_TRUE(ret != 0);

    ret = SendBytes(sessionId, data, -1);
    TEST_ASSERT_TRUE(ret != 0);

    ret = SendBytes(sessionId, data, 0);
    TEST_ASSERT_TRUE(ret != 0);
}
}
