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

#include <cinttypes>
#include <gtest/gtest.h>
#include <securec.h>
#include <sys/time.h>

#include "auth_common.h"
#include "auth_session_key.h"
#include "softbus_adapter_mem.h"

namespace OHOS {
using namespace testing::ext;
constexpr uint32_t SESSIONKEY_LEN = 32;
constexpr int32_t SESSIONKEY_INDEX = 1;
constexpr int32_t SESSIONKEY_INDEX2 = 2;

class AuthSessionKeyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthSessionKeyTest::SetUpTestCase()
{
    AuthCommonInit();
}

void AuthSessionKeyTest::TearDownTestCase()
{
    AuthCommonDeinit();
}

void AuthSessionKeyTest::SetUp() { }

void AuthSessionKeyTest::TearDown() { }

/*
 * @tc.name: SESSIONKEY_USE_TIME_TEST_001
 * @tc.desc: sessionkey item useTime test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, SESSIONKEY_USE_TIME_TEST_001, TestSize.Level1)
{
    SessionKeyList clientList = { 0 };
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    ListInit(&clientList);
    int32_t ret = AddSessionKey(&clientList, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAvailable(&clientList, SESSIONKEY_INDEX);
    EXPECT_EQ(ret, SOFTBUS_OK);

    uint64_t time = GetLatestAvailableSessionKeyTime(&clientList, AUTH_LINK_TYPE_BLE);
    EXPECT_EQ(time, 0);
    time = GetLatestAvailableSessionKeyTime(&clientList, AUTH_LINK_TYPE_WIFI);
    EXPECT_NE(time, 0);
    DestroySessionKeyList(&clientList);
}

/*
 * @tc.name: SESSIONKEY_USE_TIME_TEST_002
 * @tc.desc: GetLatestSessionKey test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, SESSIONKEY_USE_TIME_TEST_002, TestSize.Level1)
{
    SessionKeyList clientList = { 0 };
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    ListInit(&clientList);
    int32_t ret = AddSessionKey(&clientList, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddSessionKey(&clientList, SESSIONKEY_INDEX2, &sessionKey, AUTH_LINK_TYPE_BLE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAvailable(&clientList, SESSIONKEY_INDEX);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAvailable(&clientList, SESSIONKEY_INDEX2);
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t index = -1;
    ret = GetLatestSessionKey(&clientList, AUTH_LINK_TYPE_BR, &index, &sessionKey);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = GetLatestSessionKey(&clientList, AUTH_LINK_TYPE_WIFI, &index, &sessionKey);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(index == SESSIONKEY_INDEX);
    ret = GetLatestSessionKey(&clientList, AUTH_LINK_TYPE_BLE, &index, &sessionKey);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(index, SESSIONKEY_INDEX2);
    DestroySessionKeyList(&clientList);
}

/*
 * @tc.name: SESSIONKEY_USE_TIME_TEST_003
 * @tc.desc: sessionkey item useTime test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, SESSIONKEY_USE_TIME_TEST_003, TestSize.Level1)
{
    SessionKeyList clientList = { 0 };
    SessionKeyList serverList = { 0 };
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    ListInit(&clientList);
    ListInit(&serverList);
    int32_t ret = AddSessionKey(&clientList, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_BLE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(100);
    ret = AddSessionKey(&serverList, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_BLE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAvailable(&clientList, SESSIONKEY_INDEX);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAvailable(&serverList, SESSIONKEY_INDEX);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(100);
    ret = SetSessionKeyAuthLinkType(&clientList, SESSIONKEY_INDEX, AUTH_LINK_TYPE_BR);
    EXPECT_EQ(ret, SOFTBUS_OK);

    uint64_t clientTime = GetLatestAvailableSessionKeyTime(&clientList, AUTH_LINK_TYPE_BR);
    uint64_t serverTime = GetLatestAvailableSessionKeyTime(&serverList, AUTH_LINK_TYPE_BLE);
    EXPECT_LE(serverTime, clientTime);
    clientTime = GetLatestAvailableSessionKeyTime(&clientList, AUTH_LINK_TYPE_BLE);
    EXPECT_GE(serverTime, clientTime);
    DestroySessionKeyList(&clientList);
    DestroySessionKeyList(&serverList);
}

/*
 * @tc.name: UPDATE_LATEST_USE_TIME_TEST_001
 * @tc.desc: UpdateLatestUseTime test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, UPDATE_LATEST_USE_TIME_TEST_001, TestSize.Level1)
{
    SessionKeyList clientList = { 0 };
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    ListInit(&clientList);
    int32_t ret = AddSessionKey(&clientList, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_BLE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAvailable(&clientList, SESSIONKEY_INDEX);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(100);
    ret = AddSessionKey(&clientList, SESSIONKEY_INDEX2, &sessionKey, AUTH_LINK_TYPE_BLE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAvailable(&clientList, SESSIONKEY_INDEX2);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(100);
    ret = SetSessionKeyAuthLinkType(&clientList, SESSIONKEY_INDEX, AUTH_LINK_TYPE_WIFI);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(100);
    ret = SetSessionKeyAuthLinkType(&clientList, SESSIONKEY_INDEX2, AUTH_LINK_TYPE_WIFI);
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t index = 0;
    ret = GetLatestSessionKey(&clientList, AUTH_LINK_TYPE_BLE, &index, &sessionKey);
    EXPECT_EQ(index, SESSIONKEY_INDEX2);
    RemoveSessionkeyByIndex(&clientList, SESSIONKEY_INDEX, AUTH_LINK_TYPE_BLE);
    ret = GetLatestSessionKey(&clientList, AUTH_LINK_TYPE_WIFI, &index, &sessionKey);
    EXPECT_EQ(index, SESSIONKEY_INDEX2);
    DestroySessionKeyList(&clientList);
}

/*
 * @tc.name: UPDATE_LATEST_USE_TIME_TEST_002
 * @tc.desc: UpdateLatestUseTime test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, UPDATE_LATEST_USE_TIME_TEST_002, TestSize.Level1)
{
    SessionKeyList clientList = { 0 };
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    ListInit(&clientList);
    int32_t ret = AddSessionKey(&clientList, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_BLE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAvailable(&clientList, SESSIONKEY_INDEX);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(100);
    ret = AddSessionKey(&clientList, SESSIONKEY_INDEX2, &sessionKey, AUTH_LINK_TYPE_BLE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAvailable(&clientList, SESSIONKEY_INDEX2);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(100);
    ret = SetSessionKeyAuthLinkType(&clientList, SESSIONKEY_INDEX2, AUTH_LINK_TYPE_WIFI);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(100);
    ret = SetSessionKeyAuthLinkType(&clientList, SESSIONKEY_INDEX, AUTH_LINK_TYPE_WIFI);
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t index = 0;
    ret = GetLatestSessionKey(&clientList, AUTH_LINK_TYPE_WIFI, &index, &sessionKey);
    EXPECT_EQ(index, SESSIONKEY_INDEX);
    ClearSessionkeyByAuthLinkType(0, &clientList, AUTH_LINK_TYPE_WIFI);
    ret = GetLatestSessionKey(&clientList, AUTH_LINK_TYPE_BLE, &index, &sessionKey);
    EXPECT_EQ(index, SESSIONKEY_INDEX2);
    DestroySessionKeyList(&clientList);
}

/*
 * @tc.name: OLD_SESSION_KEY_TEST_001
 * @tc.desc: CheckSessionKeyListHasOldKey and ClearOldKey test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, OLD_SESSION_KEY_TEST_001, TestSize.Level1)
{
    SessionKeyList clientList = { 0 };
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    ListInit(&clientList);
    int32_t ret = AddSessionKey(&clientList, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_BLE, true);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(CheckSessionKeyListHasOldKey(&clientList, AUTH_LINK_TYPE_BLE), true);
    EXPECT_EQ(ClearOldKey(&clientList, AUTH_LINK_TYPE_BLE), SOFTBUS_OK);
    EXPECT_EQ(CheckSessionKeyListHasOldKey(&clientList, AUTH_LINK_TYPE_BLE), false);
    DestroySessionKeyList(&clientList);
}
} // namespace OHOS
