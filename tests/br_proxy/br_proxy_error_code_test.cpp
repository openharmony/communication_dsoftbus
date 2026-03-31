/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "br_proxy_error_code.c"
#include "softbus_error_code.h"
#include "gtest/gtest.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
#define INTERNAL_ERROR_CODE 111
class BrProxyErrorCodeTest : public testing::Test {
public:
    BrProxyErrorCodeTest() { }
    ~BrProxyErrorCodeTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void BrProxyErrorCodeTest::SetUpTestCase(void) { }

void BrProxyErrorCodeTest::TearDownTestCase(void) { }

/**
 * @tc.name: GetErrMsgByErrCode001
 * @tc.desc: GetErrMsgByErrCode001, when given valid error code should return error message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyErrorCodeTest, GetErrMsgByErrCode001, TestSize.Level1)
{
    const char *msg = GetErrMsgByErrCode(COMMON_ACCESS_TOKEN_DENIED);
    ASSERT_NE(msg, nullptr);
    EXPECT_NE(strstr(msg, "Permission denied"), nullptr);
}

/**
 * @tc.name: GetErrMsgByErrCode002
 * @tc.desc: GetErrMsgByErrCode002, when given invalid error code should return nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyErrorCodeTest, GetErrMsgByErrCode002, TestSize.Level1)
{
    const char *msg = GetErrMsgByErrCode(NAPI_SOFTBUS_UNKNOWN_ERR + 1);
    EXPECT_EQ(msg, nullptr);
}

/**
 * @tc.name: NapiTransConvertErr001
 * @tc.desc: NapiTransConvertErr001, when given valid error code should return converted error code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyErrorCodeTest, NapiTransConvertErr001, TestSize.Level1)
{
    int32_t ret = NapiTransConvertErr(SOFTBUS_ACCESS_TOKEN_DENIED);
    EXPECT_EQ(ret, COMMON_ACCESS_TOKEN_DENIED);
}

/**
 * @tc.name: NapiTransConvertErr002
 * @tc.desc: NapiTransConvertErr002, when given invalid error code should return NAPI_SOFTBUS_INTERNAL_ERROR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyErrorCodeTest, NapiTransConvertErr002, TestSize.Level1)
{
    int32_t ret = NapiTransConvertErr(INTERNAL_ERROR_CODE);
    EXPECT_EQ(ret, NAPI_SOFTBUS_INTERNAL_ERROR);
}
} // namespace OHOS