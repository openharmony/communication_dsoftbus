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

#include <gtest/gtest.h>

#include "session.h"
#include "softbus_error_code.h"

using namespace testing::ext;

namespace OHOS {
class TransSdkStreamTest : public testing::Test {
public:
    TransSdkStreamTest() { }
    ~TransSdkStreamTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void TransSdkStreamTest::SetUpTestCase(void) { }

void TransSdkStreamTest::TearDownTestCase(void) { }

/*
 * @tc.name: SendStreamTest01
 * @tc.desc: test SendStream with null data param
 *           Transmission sdk stream send stream
 * @tc.type: FUNC
 * @tc.require: I5FG70
 */
HWTEST_F(TransSdkStreamTest, SendStreamTest01, TestSize.Level1)
{
    int32_t sessionId = 1;
    const StreamData ext = { 0 };
    const StreamFrameInfo param = { 0 };
    int32_t ret = SendStream(sessionId, nullptr, &ext, &param);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SendStreamTest02
 * @tc.desc: test SendStream with null ext param
 *           Transmission sdk stream send stream
 * @tc.type: FUNC
 * @tc.require: I5FG70
 */
HWTEST_F(TransSdkStreamTest, SendStreamTest02, TestSize.Level1)
{
    int32_t sessionId = 1;
    const StreamData streamData = { 0 };
    const StreamFrameInfo param = { 0 };
    int32_t ret = SendStream(sessionId, &streamData, nullptr, &param);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SendStreamTest03
 * @tc.desc: test SendStream with null StreamFrameInfo param
 *           Transmission sdk stream send stream
 * @tc.type: FUNC
 * @tc.require: I5FG70
 */
HWTEST_F(TransSdkStreamTest, SendStreamTest03, TestSize.Level1)
{
    int32_t sessionId = 1;
    const StreamData streamData = { 0 };
    const StreamData ext = { 0 };
    int32_t ret = SendStream(sessionId, &streamData, &ext, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SendStreamTest04
 * @tc.desc: test SendStream with ext bufLen greater than UINT16_MAX
 *           Transmission sdk stream send stream
 * @tc.type: FUNC
 * @tc.require: I5FG70
 */
HWTEST_F(TransSdkStreamTest, SendStreamTest04, TestSize.Level1)
{
    int32_t sessionId = 1;
    const StreamData streamData = { 0 };
    StreamData ext = { nullptr, UINT16_MAX + 1 };
    const StreamFrameInfo param = { 0 };
    int32_t ret = SendStream(sessionId, &streamData, &ext, &param);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SendStreamTest05
 * @tc.desc: test SendStream with invalid sessionId
 *           Transmission sdk stream send stream
 * @tc.type: FUNC
 * @tc.require: I5FG70
 */
HWTEST_F(TransSdkStreamTest, SendStreamTest05, TestSize.Level1)
{
    const StreamData streamData = { 0 };
    const StreamData ext = { 0 };
    const StreamFrameInfo param = { 0 };
    int32_t ret = SendStream(-1, &streamData, &ext, &param);
    EXPECT_NE(ret, SOFTBUS_OK);
}
} // namespace OHOS
