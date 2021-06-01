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

/**
 * @tc.name: StartSessionListenerTest001
 * @tc.desc: extern module active publish, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, StartSessionListenerTest001, TestSize.Level1)
{
    int ret = 0;
    char const *ip = "192.168.8.119";
    int port = 6000;
    ret = TransTdcStartSessionListener(NULL, port);
    TEST_ASSERT_TRUE(ret != 0);

    ret = TransTdcStartSessionListener(ip, -1);
    TEST_ASSERT_TRUE(ret != 0);

    ret = TransTdcStartSessionListener(NULL, -1);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: StoptSessionListenerTest001
 * @tc.desc: extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, StoptSessionListenerTest001, TestSize.Level1)
{
    int ret = 0;
    ret = TransTdcStopSessionListener();
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: OpenTcpDirectChannelTest001
 * @tc.desc: extern module active publish, start channel with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, OpenTcpDirectChannelTest001, TestSize.Level1)
{
    int ret = 0;
    AppInfo appInfo;
    ConnectOption connInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    (void)memset_s(&connInfo, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    connInfo.type = CONNECT_TCP;
    connInfo.info.ipOption.port = 6000;
    if (strcpy_s(connInfo.info.ipOption.ip, sizeof(connInfo.info.ipOption.ip), "192.168.8.1") != EOK) {
        return;
    }
    int fd = 1;

    ret = TransOpenTcpDirectChannel(NULL, &connInfo, &fd);
    TEST_ASSERT_TRUE(ret != 0);

    ret = TransOpenTcpDirectChannel(&appInfo, NULL, &fd);
    TEST_ASSERT_TRUE(ret != 0);

    ret = TransOpenTcpDirectChannel(&appInfo, &connInfo, NULL);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: CloseTcpDirectChannelTest001
 * @tc.desc: extern module active publish, close channel with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, CloseTcpDirectChannelTest001, TestSize.Level1)
{
    int ret = 0;
    ret = TransCloseDirectChannel(-1);
    TEST_ASSERT_TRUE(ret != 0);
}
}