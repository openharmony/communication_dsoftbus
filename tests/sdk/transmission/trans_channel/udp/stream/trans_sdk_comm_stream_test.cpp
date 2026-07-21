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

/*
 * @tc.name: SendStreamTest01
 * @tc.desc: test SendStream with null data param
 *           Transmission sdk common stream send stream
 * @tc.type: FUNC
 * @tc.require: I5KRE8
 */
HWTEST_F(TransSdkCommStreamTest, SendStreamTest01, TestSize.Level1)
{
    int32_t sessionId = 1;
    const StreamData extData = {0};
    const StreamFrameInfo frameInfo = {0};
    int32_t ret = SendStream(sessionId, nullptr, &extData, &frameInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SendStreamTest02
 * @tc.desc: test SendStream with null ext param
 *           Transmission sdk common stream send stream
 * @tc.type: FUNC
 * @tc.require: I5KRE8
 */
HWTEST_F(TransSdkCommStreamTest, SendStreamTest02, TestSize.Level1)
{
    int32_t sessionId = 1;
    const StreamData streamData = {0};
    const StreamFrameInfo frameInfo = {0};
    int32_t ret = SendStream(sessionId, &streamData, nullptr, &frameInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SendStreamTest03
 * @tc.desc: test SendStream with null StreamFrameInfo param
 *           Transmission sdk common stream send stream
 * @tc.type: FUNC
 * @tc.require: I5KRE8
 */
HWTEST_F(TransSdkCommStreamTest, SendStreamTest03, TestSize.Level1)
{
    int32_t sessionId = 1;
    const StreamData streamData = {0};
    const StreamData extData = {0};
    int32_t ret = SendStream(sessionId, &streamData, &extData, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SendStreamTest04
 * @tc.desc: test SendStream with ext bufLen greater than UINT16_MAX
 *           Transmission sdk common stream send stream
 * @tc.type: FUNC
 * @tc.require: I5KRE8
 */
HWTEST_F(TransSdkCommStreamTest, SendStreamTest04, TestSize.Level1)
{
    int32_t sessionId = 1;
    const StreamData streamData = {0};
    StreamData extData = {nullptr, UINT16_MAX + 1};
    const StreamFrameInfo frameInfo = {0};
    int32_t ret = SendStream(sessionId, &streamData, &extData, &frameInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SendStreamTest05
 * @tc.desc: test SendStream with invalid sessionId
 *           Transmission sdk common stream send stream
 * @tc.type: FUNC
 * @tc.require: I5KRE8
 */
HWTEST_F(TransSdkCommStreamTest, SendStreamTest05, TestSize.Level1)
{
    const StreamData streamData = {0};
    const StreamData extData = {0};
    const StreamFrameInfo frameInfo = {0};
    int32_t ret = SendStream(-1, &streamData, &extData, &frameInfo);
    EXPECT_NE(ret, SOFTBUS_OK);
}
}
