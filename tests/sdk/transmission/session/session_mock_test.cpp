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
#include "softbus_error_code.h"

#include "session_mock.h"
#include "session_set_timer.h"

using namespace testing::ext;
namespace OHOS {
class SessionMockTest : public testing::Test {
    public:
    SessionMockTest()
    {}
    ~SessionMockTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void SessionMockTest::SetUpTestCase(void) { }

void SessionMockTest::TearDownTestCase(void) { }
constexpr int INVALID_ID = -1;
/*
 * @tc.name: SessionMockTest
 * @tc.desc: SessionMock functions test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SessionMockTest, SessionMockTest001, TestSize.Level1)
{
    int32_t sessionId = INVALID_ID;
    char *data = NULL;
    uint16_t len = 0; // len initializes to 0
    int32_t ret = GetPkgNameInner(sessionId, data, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = GetPeerDeviceIdInner(sessionId, data, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = GetPeerSessionNameInner(sessionId, data, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = GetMySessionNameInner(sessionId, data, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    int *pData = NULL;
    ret = GetPeerPidInner(sessionId, pData);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = GetPeerUidInner(sessionId, pData);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SessionMockTest
 * @tc.desc: SetTimer test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SessionMockTest, SessionMockTest002, TestSize.Level1)
{
    const char *name = NULL;
    unsigned int timeout = 0; // timeout initializes to 0
    int ret = SetTimer(name, timeout);
    EXPECT_EQ(ret, INVALID_ID);
}
}