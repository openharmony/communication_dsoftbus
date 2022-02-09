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

#include <gtest/gtest.h>
#include <string>

#include "dfs_session.h"
#include "inner_session.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

using namespace testing::ext;

namespace OHOS {
ConnectionAddr g_addrInfo;
const char *g_testSessionName = "ohos.distributedschedule.dms.test";
std::string testData = "TranSessionTest_GetSessionKeyTestData";

class TransSessionTest : public testing::Test {
public:
    TransSessionTest()
    {}
    ~TransSessionTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransSessionTest::SetUpTestCase(void)
{}

void TransSessionTest::TearDownTestCase(void)
{}

/**
 * @tc.name: GetSessionKeyTest001
 * @tc.desc: use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionTest, GetSessionKeyTest001, TestSize.Level0)
{
    int32_t ret;
    int32_t sessionId = 1;
    char *key = (char *)testData.c_str();
    unsigned int len = strlen(key);

    ret = GetSessionKey(-1, key, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = GetSessionKey(MAX_SESSION_ID + 1, key, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = GetSessionKey(sessionId, NULL, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = GetSessionKey(sessionId, key, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = GetSessionKey(sessionId, key, SESSION_KEY_LEN - 1);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: GetSessionKeyTest002
 * @tc.desc: use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionTest, GetSessionKeyTest002, TestSize.Level0)
{
    int32_t ret;
    int32_t sessionId = 1;
    char *key = (char *)testData.c_str();
    unsigned int len = strlen(key);

    ret = GetSessionKey(sessionId, key, len);
    EXPECT_EQ(SOFTBUS_TRANS_FUNC_NOT_SUPPORT, ret);
}

/**
 * @tc.name: GetSessionHandleTest001
 * @tc.desc: use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionTest, GetSessionHandleTest001, TestSize.Level0)
{
    int32_t ret;
    int32_t sessionId = 1;
    int handle = 1;

    ret = GetSessionHandle(-1, &handle);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = GetSessionHandle(MAX_SESSION_ID + 1, &handle);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = GetSessionHandle(sessionId, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: GetSessionHandleTest002
 * @tc.desc: use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionTest, GetSessionHandleTest002, TestSize.Level0)
{
    int32_t ret;
    int32_t sessionId = 1;
    int handle = 1;

    ret = GetSessionHandle(sessionId, &handle);
    EXPECT_EQ(SOFTBUS_TRANS_FUNC_NOT_SUPPORT, ret);
}

/**
 * @tc.name: DisableSessionListenerTest001
 * @tc.desc: use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionTest, DisableSessionListenerTest001, TestSize.Level0)
{
    int32_t ret;

    ret = DisableSessionListener(-1);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = DisableSessionListener(MAX_SESSION_ID + 1);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: DisableSessionListenerTest002
 * @tc.desc: use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionTest, DisableSessionListenerTest002, TestSize.Level0)
{
    int32_t ret;
    int32_t sessionId = 1;

    ret = DisableSessionListener(sessionId);
    EXPECT_EQ(SOFTBUS_TRANS_FUNC_NOT_SUPPORT, ret);
}

/**
 * @tc.name: OpenAuthSessionTest001
 * @tc.desc: use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionTest, OpenAuthSessionTest001, TestSize.Level0)
{
    int ret;

    ret = OpenAuthSession(NULL, &(g_addrInfo), 1, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = OpenAuthSession(g_testSessionName, NULL, 1, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = OpenAuthSession(g_testSessionName, &(g_addrInfo), -1, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: OpenAuthSessionTest002
 * @tc.desc: use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionTest, OpenAuthSessionTest002, TestSize.Level0)
{
    int ret;

    ret = OpenAuthSession(g_testSessionName, &(g_addrInfo), 1, NULL);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: NotifyAuthSuccessTest001
 * @tc.desc: use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSessionTest, NotifyAuthSuccessTest001, TestSize.Level0)
{
    int32_t sessionId = 1;

    NotifyAuthSuccess(sessionId);
}
}
