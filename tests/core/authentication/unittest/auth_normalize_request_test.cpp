/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <securec.h>

#include "auth_common.h"
#include "auth_log.h"
#include "auth_normalize_request.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;

class AuthNormalizeRequestTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthNormalizeRequestTest::SetUpTestCase() { }

void AuthNormalizeRequestTest::TearDownTestCase() { }

void AuthNormalizeRequestTest::SetUp()
{
    AUTH_LOGI(AUTH_TEST, "AuthNormalizeRequestTest start");
}

void AuthNormalizeRequestTest::TearDown() { }

/*
 * @tc.name: NOTIFY_NORMALIZE_REQUEST_SUCCESS_TEST_001
 * @tc.desc: notify normalize request success test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNormalizeRequestTest, NOTIFY_NORMALIZE_REQUEST_SUCCESS_TEST_001, TestSize.Level1)
{
    int64_t authSeq = -1;
    NormalizeRequest request;
    const char *udidHash = "testudidhash";

    (void)memset_s(&request, sizeof(NormalizeRequest), 0, sizeof(NormalizeRequest));
    EXPECT_TRUE(AuthCommonInit() == SOFTBUS_OK);
    request.authSeq = 1;
    (void)memcpy_s(request.udidHash, SHA_256_HEX_HASH_LEN, udidHash, SHA_256_HEX_HASH_LEN);
    uint32_t ret = AddNormalizeRequest(&request);
    EXPECT_TRUE(ret != 0);
    request.authSeq = 2;
    ret = AddNormalizeRequest(&request);
    EXPECT_TRUE(ret != 0);
    DelAuthNormalizeRequest(request.authSeq);
    request.authSeq = 3;
    ret = AddNormalizeRequest(&request);
    EXPECT_TRUE(ret != 0);
    bool result = AuthIsRepeatedAuthRequest(request.authSeq);
    EXPECT_TRUE(result == true);
    NotifyNormalizeRequestSuccess(authSeq, false);
    authSeq = 1;
    NotifyNormalizeRequestSuccess(authSeq, false);
    AuthCommonDeinit();
}

/*
 * @tc.name: NOTIFY_NORMALIZE_REQUEST_FAIL_TEST_001
 * @tc.desc: notify normalize request fail test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthNormalizeRequestTest, NOTIFY_NORMALIZE_REQUEST_FAIL_TEST_001, TestSize.Level1)
{
    int64_t authSeq = -1;
    NormalizeRequest request;
    const char *udidHash = "testudidhash1";

    (void)memset_s(&request, sizeof(NormalizeRequest), 0, sizeof(NormalizeRequest));
    EXPECT_TRUE(AuthCommonInit() == SOFTBUS_OK);
    request.authSeq = 1;
    (void)memcpy_s(request.udidHash, SHA_256_HEX_HASH_LEN, udidHash, SHA_256_HEX_HASH_LEN);
    uint32_t ret = AddNormalizeRequest(&request);
    EXPECT_TRUE(ret != 0);
    request.authSeq = 2;
    ret = AddNormalizeRequest(&request);
    EXPECT_TRUE(ret != 0);
    request.authSeq = 3;
    ret = AddNormalizeRequest(&request);
    EXPECT_TRUE(ret != 0);
    NotifyNormalizeRequestFail(authSeq, -1);
    authSeq = 1;
    NotifyNormalizeRequestFail(authSeq, -1);
    AuthCommonDeinit();
}
} // namespace OHOS
