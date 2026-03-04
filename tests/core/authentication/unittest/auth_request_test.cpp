/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "gmock/gmock.h"
#include <cinttypes>
#include <gtest/gtest.h>
#include <securec.h>
#include <sys/time.h>

#include "auth_request.c"

namespace OHOS {
using namespace testing;
using namespace testing::ext;
constexpr int32_t REQUST_ID = 1000;
constexpr int32_t RESULT_VAL1 = 1;
constexpr int32_t RESULT_VAL2 = 2;

class AuthRequestTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthRequestTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "AuthRequestTest start";
    AuthCommonInit();
}

void AuthRequestTest::TearDownTestCase()
{
    AuthCommonDeinit();
    GTEST_LOG_(INFO) << "AuthRequestTest end";
}

void AuthRequestTest::SetUp() { }

void AuthRequestTest::TearDown() { }

/*
 * @tc.name:GET_AUTH_REQUEST_TEST_001
 * @tc.desc: Verify that GetAuthRequestWaitNum correctly calculates the number of waiting
 *           authentication requests in the list.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, GET_AUTH_REQUEST_TEST_001, TestSize.Level1)
{
    AuthRequest *request = static_cast<AuthRequest *>(SoftBusCalloc(sizeof(AuthRequest)));
    ASSERT_TRUE(request != nullptr);
    AuthRequest *item = static_cast<AuthRequest *>(SoftBusCalloc(sizeof(AuthRequest)));
    if (item == nullptr) {
        SoftBusFree(request);
    }
    ASSERT_TRUE(item != nullptr);
    AuthVerifyCallback verifyCb;
    AuthConnCallback connCb;
    request->connCb = connCb;
    request->verifyCb = verifyCb;
    request->authId = 123;
    request->type = REQUEST_TYPE_RECONNECT;
    request->addTime = 40000;
    request->requestId = 1;
    request->connInfo.type = AUTH_LINK_TYPE_BLE;
    request->node.next = NULL;
    request->node.prev = NULL;
    item->connCb = connCb;
    item->verifyCb = verifyCb;
    item->authId = 1234;
    item->type = REQUEST_TYPE_RECONNECT;
    item->addTime = 10;
    item->requestId = 0;
    item->connInfo.type = AUTH_LINK_TYPE_BLE;
    item->node.next = NULL;
    item->node.prev = NULL;
    ListTailInsert(&g_authRequestList, &(*item).node);
    ListTailInsert(&g_authRequestList, &(*request).node);
    uint32_t ret = GetAuthRequestWaitNum((const AuthRequest *)item, &g_authRequestList);
    ClearAuthRequest();
    EXPECT_EQ(ret, RESULT_VAL1);
}

/*
 * @tc.name:GET_AUTH_REQUEST_TEST_002
 * @tc.desc: Verify that GetAuthRequestWaitNum correctly calculates the number of waiting
 *           authentication requests in the list under different conditions.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, GET_AUTH_REQUEST_TEST_002, TestSize.Level1)
{
    AuthRequest *request = static_cast<AuthRequest *>(SoftBusCalloc(sizeof(AuthRequest)));
    ASSERT_TRUE(request != nullptr);
    AuthRequest *item = static_cast<AuthRequest *>(SoftBusCalloc(sizeof(AuthRequest)));
    if (item == nullptr) {
        SoftBusFree(request);
    }
    ASSERT_TRUE(item != nullptr);
    AuthVerifyCallback verifyCb;
    AuthConnCallback connCb;
    request->connCb = connCb;
    request->verifyCb = verifyCb;
    request->authId = REQUST_ID;
    request->type = REQUEST_TYPE_RECONNECT;
    request->addTime = 3000;
    request->requestId = 1;
    request->connInfo.type = AUTH_LINK_TYPE_BLE;
    request->node.next = NULL;
    request->node.prev = NULL;
    item->connCb = connCb;
    item->verifyCb = verifyCb;
    item->authId = REQUST_ID;
    item->type = REQUEST_TYPE_RECONNECT;
    item->addTime = 10;
    item->requestId = 0;
    item->connInfo.type = AUTH_LINK_TYPE_BLE;
    item->node.next = NULL;
    item->node.prev = NULL;
    ListTailInsert(&g_authRequestList, &(*item).node);
    ListTailInsert(&g_authRequestList, &(*request).node);
    uint32_t ret = GetAuthRequestWaitNum((const AuthRequest *)request, &g_authRequestList);
    EXPECT_EQ(ret, RESULT_VAL2);
    ClearAuthRequest();
}
} // namespace OHOS