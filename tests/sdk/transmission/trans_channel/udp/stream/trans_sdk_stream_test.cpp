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

#include "session.h"
#include "softbus_error_code.h"

using namespace testing::ext;

namespace OHOS {
class TransSdkStreamTest : public testing::Test {
public:
    TransSdkStreamTest()
    {}
    ~TransSdkStreamTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransSdkStreamTest::SetUpTestCase(void)
{}

void TransSdkStreamTest::TearDownTestCase(void)
{}

/**
 * @tc.name: SendStreamTest001
 * @tc.desc: extern module active publish, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require: I5FG70
 */
HWTEST_F(TransSdkStreamTest, SendStreamTest001, TestSize.Level0)
{
    int32_t ret;
    int32_t sessionId = 1;
    const StreamData streamData = {0};
    const StreamData ext = {0};
    const StreamFrameInfo param = {0};

    ret = SendStream(-1, &streamData, &ext, &param);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = SendStream(sessionId, NULL, &ext, &param);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = SendStream(sessionId, &streamData, NULL, &param);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = SendStream(sessionId, &streamData, &ext, NULL);
    EXPECT_NE(SOFTBUS_OK, ret);
}
}