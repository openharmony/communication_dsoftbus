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

#include "session.h"
#include "softbus_error_code.h"

using namespace testing::ext;

namespace OHOS {
class TransSdkCommStreamTest : public testing::Test {
public:
    TransSdkCommStreamTest()
    {}
    ~TransSdkCommStreamTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransSdkCommStreamTest::SetUpTestCase(void)
{}

void TransSdkCommStreamTest::TearDownTestCase(void)
{}

/**
 * @tc.name: SendCommStreamTest001
 * @tc.desc: start common stream client, send wrong param.
 * @tc.type: FUNC
 * @tc.require: I5KRE8
 */
HWTEST_F(TransSdkCommStreamTest, SendCommStreamTest001, TestSize.Level0)
{
    int32_t sessionId = 1;
    const StreamData streamData = {0};
    const StreamData extData = {0};
    const StreamFrameInfo frameInfo = {0};

    int32_t ret = SendStream(-1, &streamData, &extData, &frameInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = SendStream(sessionId, NULL, &extData, &frameInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
}
}