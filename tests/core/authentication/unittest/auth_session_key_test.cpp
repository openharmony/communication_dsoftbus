/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include "common_list.h"

namespace OHOS {
using namespace testing::ext;
constexpr uint32_t SESSIONKEY_LEN = 32;
constexpr int32_t SESSIONKEY_INDEX = 1;
constexpr int32_t SESSIONKEY_INDEX2 = 2;

class AuthSessionKeyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

protected:
    SessionKeyList list_;
};

void AuthSessionKeyTest::SetUpTestCase()
{
    AuthCommonInit();
}

void AuthSessionKeyTest::TearDownTestCase()
{
    AuthCommonDeinit();
}

void AuthSessionKeyTest::SetUp()
{
    ListInit(&list_);
}

void AuthSessionKeyTest::TearDown()
{
    EXPECT_NO_FATAL_FAILURE(DestroySessionKeyList(&list_));
}

/*
 * @tc.name: SESSIONKEY_USE_TIME_TEST_001
 * @tc.desc: Test the use time of a session key item.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, SESSIONKEY_USE_TIME_TEST_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    int32_t type = 0;
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_MAX, false);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AuthLinkType(type), false);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAvailable(&list_, SESSIONKEY_INDEX);
    EXPECT_EQ(ret, SOFTBUS_OK);

    uint64_t time = GetLatestAvailableSessionKeyTime(&list_, AUTH_LINK_TYPE_BLE);
    EXPECT_EQ(time, 0);
    time = GetLatestAvailableSessionKeyTime(&list_, AUTH_LINK_TYPE_WIFI);
    EXPECT_NE(time, 0);
}

/*
 * @tc.name: SESSIONKEY_USE_TIME_TEST_002
 * @tc.desc: Test getting the latest session key.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, SESSIONKEY_USE_TIME_TEST_002, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddSessionKey(&list_, SESSIONKEY_INDEX2, &sessionKey, AUTH_LINK_TYPE_BLE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAvailable(&list_, SESSIONKEY_INDEX);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAvailable(&list_, SESSIONKEY_INDEX2);
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t index = -1;
    int32_t type = 0;
    ret = GetLatestSessionKey(&list_, AUTH_LINK_TYPE_MAX, &index, &sessionKey);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetLatestSessionKey(&list_, AuthLinkType(type), &index, &sessionKey);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetLatestSessionKey(&list_, AUTH_LINK_TYPE_BR, &index, &sessionKey);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = GetLatestSessionKey(&list_, AUTH_LINK_TYPE_WIFI, &index, &sessionKey);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(index == SESSIONKEY_INDEX);
    ret = GetLatestSessionKey(&list_, AUTH_LINK_TYPE_BLE, &index, &sessionKey);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(index, SESSIONKEY_INDEX2);
}

/*
 * @tc.name: SESSIONKEY_USE_TIME_TEST_003
 * @tc.desc: Test the use time of a session key item under different link types.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, SESSIONKEY_USE_TIME_TEST_003, TestSize.Level1)
{
    SessionKeyList clientList;
    SessionKeyList serverList;
    ListInit(&clientList);
    ListInit(&serverList);
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
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

    int32_t type = 0;
    ret = SetSessionKeyAuthLinkType(&clientList, SESSIONKEY_INDEX, AUTH_LINK_TYPE_MAX);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SetSessionKeyAuthLinkType(&clientList, SESSIONKEY_INDEX, AuthLinkType(type));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
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
 * @tc.desc: Test updating the latest use time of a session key.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, UPDATE_LATEST_USE_TIME_TEST_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_BLE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAvailable(&list_, SESSIONKEY_INDEX);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(100);
    ret = AddSessionKey(&list_, SESSIONKEY_INDEX2, &sessionKey, AUTH_LINK_TYPE_BLE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAvailable(&list_, SESSIONKEY_INDEX2);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(100);
    ret = SetSessionKeyAuthLinkType(&list_, SESSIONKEY_INDEX, AUTH_LINK_TYPE_WIFI);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(100);
    ret = SetSessionKeyAuthLinkType(&list_, SESSIONKEY_INDEX2, AUTH_LINK_TYPE_WIFI);
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t index = 0;
    ret = GetLatestSessionKey(&list_, AUTH_LINK_TYPE_BLE, &index, &sessionKey);
    EXPECT_EQ(index, SESSIONKEY_INDEX2);
    RemoveSessionkeyByIndex(&list_, SESSIONKEY_INDEX, AUTH_LINK_TYPE_BLE);
    ret = GetLatestSessionKey(&list_, AUTH_LINK_TYPE_WIFI, &index, &sessionKey);
    EXPECT_EQ(index, SESSIONKEY_INDEX2);
}

/*
 * @tc.name: UPDATE_LATEST_USE_TIME_TEST_002
 * @tc.desc: Test updating the latest use time of a session key under different conditions.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, UPDATE_LATEST_USE_TIME_TEST_002, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_BLE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAvailable(&list_, SESSIONKEY_INDEX);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(100);
    ret = AddSessionKey(&list_, SESSIONKEY_INDEX2, &sessionKey, AUTH_LINK_TYPE_BLE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAvailable(&list_, SESSIONKEY_INDEX2);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(100);
    ret = SetSessionKeyAuthLinkType(&list_, SESSIONKEY_INDEX2, AUTH_LINK_TYPE_WIFI);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(100);
    ret = SetSessionKeyAuthLinkType(&list_, SESSIONKEY_INDEX, AUTH_LINK_TYPE_WIFI);
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t index = 0;
    ret = GetLatestSessionKey(&list_, AUTH_LINK_TYPE_WIFI, &index, &sessionKey);
    EXPECT_EQ(index, SESSIONKEY_INDEX);
    ClearSessionkeyByAuthLinkType(0, &list_, AUTH_LINK_TYPE_WIFI);
    ret = GetLatestSessionKey(&list_, AUTH_LINK_TYPE_BLE, &index, &sessionKey);
    EXPECT_EQ(index, SESSIONKEY_INDEX2);
}

/*
 * @tc.name: OLD_SESSION_KEY_TEST_001
 * @tc.desc: Test checking for and clearing old session keys.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, OLD_SESSION_KEY_TEST_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_BLE, true);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(CheckSessionKeyListHasOldKey(&list_, AUTH_LINK_TYPE_BLE), true);
    EXPECT_EQ(ClearOldKey(&list_, AUTH_LINK_TYPE_BLE), SOFTBUS_OK);
    EXPECT_EQ(CheckSessionKeyListHasOldKey(&list_, AUTH_LINK_TYPE_BLE), false);
}

/*
 * @tc.name: INIT_SESSION_KEY_LIST_TEST_001
 * @tc.desc: Test InitSessionKeyList with normal case.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, INIT_SESSION_KEY_LIST_TEST_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    EXPECT_EQ(HasSessionKey(&list_), false);
}

/*
 * @tc.name: INIT_SESSION_KEY_LIST_TEST_002
 * @tc.desc: Test InitSessionKeyList with NULL pointer.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, INIT_SESSION_KEY_LIST_TEST_002, TestSize.Level2)
{
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(nullptr));
}

/*
 * @tc.name: HAS_SESSION_KEY_TEST_001
 * @tc.desc: Test HasSessionKey with empty list.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, HAS_SESSION_KEY_TEST_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    EXPECT_EQ(HasSessionKey(&list_), false);
}

/*
 * @tc.name: HAS_SESSION_KEY_TEST_002
 * @tc.desc: Test HasSessionKey with non-empty list.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, HAS_SESSION_KEY_TEST_002, TestSize.Level1)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(HasSessionKey(&list_), true);
}

/*
 * @tc.name: HAS_SESSION_KEY_TEST_003
 * @tc.desc: Test HasSessionKey with NULL pointer.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, HAS_SESSION_KEY_TEST_003, TestSize.Level2)
{
    EXPECT_EQ(HasSessionKey(nullptr), false);
}

/*
 * @tc.name: GET_SESSION_KEY_TYPE_BY_INDEX_TEST_001
 * @tc.desc: Test GetSessionKeyTypeByIndex with valid index.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, GET_SESSION_KEY_TYPE_BY_INDEX_TEST_001, TestSize.Level1)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    AuthLinkType type = GetSessionKeyTypeByIndex(&list_, SESSIONKEY_INDEX);
    EXPECT_EQ(type, AUTH_LINK_TYPE_WIFI);
}

/*
 * @tc.name: GET_SESSION_KEY_TYPE_BY_INDEX_TEST_002
 * @tc.desc: Test GetSessionKeyTypeByIndex with invalid index.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, GET_SESSION_KEY_TYPE_BY_INDEX_TEST_002, TestSize.Level1)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_BLE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    AuthLinkType type = GetSessionKeyTypeByIndex(&list_, 999);
    EXPECT_EQ(type, AUTH_LINK_TYPE_MAX);
}

/*
 * @tc.name: GET_SESSION_KEY_TYPE_BY_INDEX_TEST_003
 * @tc.desc: Test GetSessionKeyTypeByIndex with NULL pointer.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, GET_SESSION_KEY_TYPE_BY_INDEX_TEST_003, TestSize.Level2)
{
    AuthLinkType type = GetSessionKeyTypeByIndex(nullptr, SESSIONKEY_INDEX);
    EXPECT_EQ(type, AUTH_LINK_TYPE_MAX);
}

/*
 * @tc.name: GET_SESSION_KEY_TYPE_BY_INDEX_TEST_004
 * @tc.desc: Test GetSessionKeyTypeByIndex with multiple link types.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, GET_SESSION_KEY_TYPE_BY_INDEX_TEST_004, TestSize.Level1)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAuthLinkType(&list_, SESSIONKEY_INDEX, AUTH_LINK_TYPE_BLE);
    EXPECT_EQ(ret, SOFTBUS_OK);
    AuthLinkType type = GetSessionKeyTypeByIndex(&list_, SESSIONKEY_INDEX);
    EXPECT_NE(type, AUTH_LINK_TYPE_MAX);
}

/*
 * @tc.name: GET_SESSION_KEY_BY_INDEX_TEST_001
 * @tc.desc: Test GetSessionKeyByIndex with valid parameters.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, GET_SESSION_KEY_BY_INDEX_TEST_001, TestSize.Level1)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    uint8_t testKey[SESSION_KEY_LENGTH] = { 1, 2, 3, 4, 5 };
    int memcpyResult = memcpy_s(sessionKey.value, SESSION_KEY_LENGTH, testKey, SESSION_KEY_LENGTH);
    EXPECT_EQ(memcpyResult, 0);
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAvailable(&list_, SESSIONKEY_INDEX);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionKey outKey = { { 0 }, 0 };
    ret = GetSessionKeyByIndex(&list_, SESSIONKEY_INDEX, AUTH_LINK_TYPE_WIFI, &outKey);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(outKey.len, SESSIONKEY_LEN);
}

/*
 * @tc.name: GET_SESSION_KEY_BY_INDEX_TEST_002
 * @tc.desc: Test GetSessionKeyByIndex with invalid parameters.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, GET_SESSION_KEY_BY_INDEX_TEST_002, TestSize.Level2)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SessionKey outKey = { { 0 }, 0 };
    ret = GetSessionKeyByIndex(nullptr, SESSIONKEY_INDEX, AUTH_LINK_TYPE_WIFI, &outKey);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetSessionKeyByIndex(&list_, SESSIONKEY_INDEX, AUTH_LINK_TYPE_WIFI, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetSessionKeyByIndex(&list_, SESSIONKEY_INDEX, AUTH_LINK_TYPE_MAX, &outKey);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetSessionKeyByIndex(&list_, 999, AUTH_LINK_TYPE_WIFI, &outKey);
    EXPECT_EQ(ret, SOFTBUS_AUTH_NOT_FOUND);
}

/*
 * @tc.name: GET_SESSION_KEY_BY_INDEX_TEST_003
 * @tc.desc: Test GetSessionKeyByIndex with different link types.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, GET_SESSION_KEY_BY_INDEX_TEST_003, TestSize.Level1)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_BLE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAvailable(&list_, SESSIONKEY_INDEX);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionKey outKey = { { 0 }, 0 };
    ret = GetSessionKeyByIndex(&list_, SESSIONKEY_INDEX, AUTH_LINK_TYPE_BLE, &outKey);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetSessionKeyByIndex(&list_, SESSIONKEY_INDEX, AUTH_LINK_TYPE_WIFI, &outKey);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: CHECK_SESSION_KEY_LIST_EXIST_TYPE_TEST_001
 * @tc.desc: Test CheckSessionKeyListExistType with existing type.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, CHECK_SESSION_KEY_LIST_EXIST_TYPE_TEST_001, TestSize.Level1)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(CheckSessionKeyListExistType(&list_, AUTH_LINK_TYPE_WIFI), true);
    EXPECT_EQ(CheckSessionKeyListExistType(&list_, AUTH_LINK_TYPE_BLE), false);
}

/*
 * @tc.name: CHECK_SESSION_KEY_LIST_EXIST_TYPE_TEST_002
 * @tc.desc: Test CheckSessionKeyListExistType with NULL pointer.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, CHECK_SESSION_KEY_LIST_EXIST_TYPE_TEST_002, TestSize.Level2)
{
    EXPECT_EQ(CheckSessionKeyListExistType(nullptr, AUTH_LINK_TYPE_WIFI), false);
}

/*
 * @tc.name: CHECK_SESSION_KEY_LIST_EXIST_TYPE_TEST_003
 * @tc.desc: Test CheckSessionKeyListExistType with multiple link types.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, CHECK_SESSION_KEY_LIST_EXIST_TYPE_TEST_003, TestSize.Level1)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddSessionKey(&list_, SESSIONKEY_INDEX2, &sessionKey, AUTH_LINK_TYPE_BLE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(CheckSessionKeyListExistType(&list_, AUTH_LINK_TYPE_WIFI), true);
    EXPECT_EQ(CheckSessionKeyListExistType(&list_, AUTH_LINK_TYPE_BLE), true);
    EXPECT_EQ(CheckSessionKeyListExistType(&list_, AUTH_LINK_TYPE_BR), false);
}

/*
 * @tc.name: DUP_SESSION_KEY_LIST_TEST_001
 * @tc.desc: Test DupSessionKeyList with normal case.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, DUP_SESSION_KEY_LIST_TEST_001, TestSize.Level1)
{
    SessionKeyList srcList;
    SessionKeyList dstList;
    ListInit(&srcList);
    ListInit(&dstList);
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&srcList));
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&dstList));
    int32_t ret = AddSessionKey(&srcList, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAvailable(&srcList, SESSIONKEY_INDEX);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = DupSessionKeyList(&srcList, &dstList);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(HasSessionKey(&dstList), true);
    EXPECT_NO_FATAL_FAILURE(DestroySessionKeyList(&srcList));
    EXPECT_NO_FATAL_FAILURE(DestroySessionKeyList(&dstList));
}

/*
 * @tc.name: DUP_SESSION_KEY_LIST_TEST_002
 * @tc.desc: Test DupSessionKeyList with NULL parameters.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, DUP_SESSION_KEY_LIST_TEST_002, TestSize.Level2)
{
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t ret = DupSessionKeyList(nullptr, &list_);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DupSessionKeyList(&list_, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DupSessionKeyList(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: DUP_SESSION_KEY_LIST_TEST_003
 * @tc.desc: Test DupSessionKeyList with multiple keys.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, DUP_SESSION_KEY_LIST_TEST_003, TestSize.Level1)
{
    SessionKeyList srcList;
    SessionKeyList dstList;
    ListInit(&srcList);
    ListInit(&dstList);
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&srcList));
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&dstList));
    int32_t ret = AddSessionKey(&srcList, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddSessionKey(&srcList, SESSIONKEY_INDEX2, &sessionKey, AUTH_LINK_TYPE_BLE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = DupSessionKeyList(&srcList, &dstList);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(CheckSessionKeyListExistType(&dstList, AUTH_LINK_TYPE_WIFI), true);
    EXPECT_EQ(CheckSessionKeyListExistType(&dstList, AUTH_LINK_TYPE_BLE), true);
    EXPECT_NO_FATAL_FAILURE(DestroySessionKeyList(&srcList));
    EXPECT_NO_FATAL_FAILURE(DestroySessionKeyList(&dstList));
}

/*
 * @tc.name: REMOVE_SESSION_KEY_BY_INDEX_TEST_001
 * @tc.desc: Test RemoveSessionkeyByIndex with single link type.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, REMOVE_SESSION_KEY_BY_INDEX_TEST_001, TestSize.Level1)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(RemoveSessionkeyByIndex(&list_, SESSIONKEY_INDEX, AUTH_LINK_TYPE_WIFI));
    EXPECT_EQ(HasSessionKey(&list_), false);
}

/*
 * @tc.name: REMOVE_SESSION_KEY_BY_INDEX_TEST_002
 * @tc.desc: Test RemoveSessionkeyByIndex with multiple link types.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, REMOVE_SESSION_KEY_BY_INDEX_TEST_002, TestSize.Level1)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAuthLinkType(&list_, SESSIONKEY_INDEX, AUTH_LINK_TYPE_BLE);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(RemoveSessionkeyByIndex(&list_, SESSIONKEY_INDEX, AUTH_LINK_TYPE_WIFI));
    EXPECT_EQ(HasSessionKey(&list_), true);
    EXPECT_EQ(CheckSessionKeyListExistType(&list_, AUTH_LINK_TYPE_BLE), true);
    EXPECT_EQ(CheckSessionKeyListExistType(&list_, AUTH_LINK_TYPE_WIFI), false);
}

/*
 * @tc.name: REMOVE_SESSION_KEY_BY_INDEX_TEST_003
 * @tc.desc: Test RemoveSessionkeyByIndex with NULL pointer.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, REMOVE_SESSION_KEY_BY_INDEX_TEST_003, TestSize.Level2)
{
    EXPECT_NO_FATAL_FAILURE(RemoveSessionkeyByIndex(nullptr, SESSIONKEY_INDEX, AUTH_LINK_TYPE_WIFI));
}

/*
 * @tc.name: REMOVE_SESSION_KEY_BY_INDEX_TEST_004
 * @tc.desc: Test RemoveSessionkeyByIndex with non-existent index.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, REMOVE_SESSION_KEY_BY_INDEX_TEST_004, TestSize.Level1)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(RemoveSessionkeyByIndex(&list_, 999, AUTH_LINK_TYPE_WIFI));
    EXPECT_EQ(HasSessionKey(&list_), true);
}

/*
 * @tc.name: CLEAR_SESSION_KEY_BY_AUTH_LINK_TYPE_TEST_001
 * @tc.desc: Test ClearSessionkeyByAuthLinkType with normal case.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, CLEAR_SESSION_KEY_BY_AUTH_LINK_TYPE_TEST_001, TestSize.Level1)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddSessionKey(&list_, SESSIONKEY_INDEX2, &sessionKey, AUTH_LINK_TYPE_BLE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int64_t authId = 12345;
    EXPECT_NO_FATAL_FAILURE(ClearSessionkeyByAuthLinkType(authId, &list_, AUTH_LINK_TYPE_WIFI));
    EXPECT_EQ(CheckSessionKeyListExistType(&list_, AUTH_LINK_TYPE_WIFI), false);
    EXPECT_EQ(CheckSessionKeyListExistType(&list_, AUTH_LINK_TYPE_BLE), true);
}

/*
 * @tc.name: CLEAR_SESSION_KEY_BY_AUTH_LINK_TYPE_TEST_002
 * @tc.desc: Test ClearSessionkeyByAuthLinkType with NULL pointer.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, CLEAR_SESSION_KEY_BY_AUTH_LINK_TYPE_TEST_002, TestSize.Level2)
{
    int64_t authId = 12345;
    EXPECT_NO_FATAL_FAILURE(ClearSessionkeyByAuthLinkType(authId, nullptr, AUTH_LINK_TYPE_WIFI));
}

/*
 * @tc.name: CLEAR_SESSION_KEY_BY_AUTH_LINK_TYPE_TEST_003
 * @tc.desc: Test ClearSessionkeyByAuthLinkType clears all keys of type.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, CLEAR_SESSION_KEY_BY_AUTH_LINK_TYPE_TEST_003, TestSize.Level1)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddSessionKey(&list_, SESSIONKEY_INDEX2, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddSessionKey(&list_, SESSIONKEY_INDEX2 + 1, &sessionKey, AUTH_LINK_TYPE_BLE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int64_t authId = 12345;
    EXPECT_NO_FATAL_FAILURE(ClearSessionkeyByAuthLinkType(authId, &list_, AUTH_LINK_TYPE_WIFI));
    EXPECT_EQ(CheckSessionKeyListExistType(&list_, AUTH_LINK_TYPE_WIFI), false);
    EXPECT_EQ(CheckSessionKeyListExistType(&list_, AUTH_LINK_TYPE_BLE), true);
}

/*
 * @tc.name: ENCRYPT_DECRYPT_DATA_TEST_001
 * @tc.desc: Test EncryptData and DecryptData with valid parameters.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, ENCRYPT_DECRYPT_DATA_TEST_001, TestSize.Level1)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    uint8_t testKey[SESSION_KEY_LENGTH] = { 1, 2, 3, 4 };
    int memcpyResult = memcpy_s(sessionKey.value, SESSION_KEY_LENGTH, testKey, sizeof(testKey));
    EXPECT_EQ(memcpyResult, 0);
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAvailable(&list_, SESSIONKEY_INDEX);
    EXPECT_EQ(ret, SOFTBUS_OK);

    const char *plainText = "Hello, DSoftBus!";
    uint32_t plainLen = static_cast<uint32_t>(strlen(plainText)) + 1;
    InDataInfo inDataInfo = { reinterpret_cast<const uint8_t *>(plainText), plainLen };

    uint32_t encLen = plainLen + ENCRYPT_OVER_HEAD_LEN;
    uint8_t *encData = static_cast<uint8_t *>(SoftBusCalloc(encLen));
    ASSERT_NE(encData, nullptr);
    ret = EncryptData(&list_, AUTH_LINK_TYPE_WIFI, &inDataInfo, encData, &encLen);
    EXPECT_EQ(ret, SOFTBUS_OK);

    uint32_t decLen = plainLen;
    uint8_t *decData = static_cast<uint8_t *>(SoftBusCalloc(decLen));
    if (decData != nullptr) {
        InDataInfo encDataInfo = { encData, encLen };
        ret = DecryptData(&list_, AUTH_LINK_TYPE_WIFI, &encDataInfo, decData, &decLen);
        EXPECT_EQ(ret, SOFTBUS_OK);
        EXPECT_EQ(strcmp(reinterpret_cast<char *>(decData), plainText), 0);
        EXPECT_EQ(decLen, plainLen);
        SoftBusFree(decData);
    }
    SoftBusFree(encData);
}

/*
 * @tc.name: ENCRYPT_DECRYPT_DATA_TEST_002
 * @tc.desc: Test EncryptData with invalid parameters.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, ENCRYPT_DECRYPT_DATA_TEST_002, TestSize.Level2)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    const char *plainText = "Test";
    uint32_t plainLen = static_cast<uint32_t>(strlen(plainText)) + 1;
    InDataInfo inDataInfo = { reinterpret_cast<const uint8_t *>(plainText), plainLen };
    uint32_t encLen = plainLen + ENCRYPT_OVER_HEAD_LEN;
    uint8_t *encData = static_cast<uint8_t *>(SoftBusCalloc(encLen));
    ASSERT_NE(encData, nullptr);

    ret = EncryptData(nullptr, AUTH_LINK_TYPE_WIFI, &inDataInfo, encData, &encLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = EncryptData(&list_, AUTH_LINK_TYPE_WIFI, nullptr, encData, &encLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    InDataInfo invalidInData = { nullptr, plainLen };
    ret = EncryptData(&list_, AUTH_LINK_TYPE_WIFI, &invalidInData, encData, &encLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    InDataInfo zeroLenInData = { reinterpret_cast<const uint8_t *>(plainText), 0 };
    ret = EncryptData(&list_, AUTH_LINK_TYPE_WIFI, &zeroLenInData, encData, &encLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = EncryptData(&list_, AUTH_LINK_TYPE_WIFI, &inDataInfo, nullptr, &encLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    SoftBusFree(encData);
}

/*
 * @tc.name: ENCRYPT_DECRYPT_DATA_TEST_003
 * @tc.desc: Test DecryptData with invalid parameters.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, ENCRYPT_DECRYPT_DATA_TEST_003, TestSize.Level2)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    const char *cipherText = "TestCipherText";
    uint32_t cipherLen = 20;
    uint32_t decLen = 10;
    uint8_t *decData = static_cast<uint8_t *>(SoftBusCalloc(decLen));
    ASSERT_NE(decData, nullptr);
    InDataInfo inDataInfo = { reinterpret_cast<const uint8_t *>(cipherText), cipherLen };

    ret = DecryptData(nullptr, AUTH_LINK_TYPE_WIFI, &inDataInfo, decData, &decLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DecryptData(&list_, AUTH_LINK_TYPE_WIFI, nullptr, decData, &decLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    InDataInfo nullInData = { nullptr, cipherLen };
    ret = DecryptData(&list_, AUTH_LINK_TYPE_WIFI, &nullInData, decData, &decLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    InDataInfo shortLenData = { reinterpret_cast<const uint8_t *>(cipherText), 5 };
    ret = DecryptData(&list_, AUTH_LINK_TYPE_WIFI, &shortLenData, nullptr, &decLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    SoftBusFree(decData);
}

/*
 * @tc.name: ENCRYPT_DECRYPT_DATA_TEST_004
 * @tc.desc: Test EncryptData with insufficient output buffer.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, ENCRYPT_DECRYPT_DATA_TEST_004, TestSize.Level2)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAvailable(&list_, SESSIONKEY_INDEX);
    EXPECT_EQ(ret, SOFTBUS_OK);

    const char *plainText = "Test";
    uint32_t plainLen = static_cast<uint32_t>(strlen(plainText)) + 1;
    InDataInfo inDataInfo = { reinterpret_cast<const uint8_t *>(plainText), plainLen };
    uint32_t encLen = 5;
    uint8_t *encData = static_cast<uint8_t *>(SoftBusCalloc(encLen));
    ASSERT_NE(encData, nullptr);

    ret = EncryptData(&list_, AUTH_LINK_TYPE_WIFI, &inDataInfo, encData, &encLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    SoftBusFree(encData);
}

/*
 * @tc.name: ENCRYPT_DECRYPT_DATA_TEST_005
 * @tc.desc: Test DecryptData with no available session key.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, ENCRYPT_DECRYPT_DATA_TEST_005, TestSize.Level2)
{
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));

    const char *cipherText = "TestCipherText";
    uint32_t cipherLen = 20;
    InDataInfo inDataInfo = { reinterpret_cast<const uint8_t *>(cipherText), cipherLen };
    uint32_t decLen = 10;
    uint8_t *decData = static_cast<uint8_t *>(SoftBusCalloc(decLen));
    ASSERT_NE(decData, nullptr);

    int32_t ret = DecryptData(&list_, AUTH_LINK_TYPE_WIFI, &inDataInfo, decData, &decLen);
    EXPECT_NE(ret, SOFTBUS_OK);

    SoftBusFree(decData);
}

/*
 * @tc.name: ENCRYPT_DECRYPT_DATA_TEST_006
 * @tc.desc: Test EncryptData with different link types.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, ENCRYPT_DECRYPT_DATA_TEST_006, TestSize.Level1)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    uint8_t testKey[SESSION_KEY_LENGTH] = { 1, 2, 3, 4 };
    int memcpyResult = memcpy_s(sessionKey.value, SESSION_KEY_LENGTH, testKey, sizeof(testKey));
    EXPECT_EQ(memcpyResult, 0);
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));

    AuthLinkType types[] = { AUTH_LINK_TYPE_WIFI, AUTH_LINK_TYPE_BLE, AUTH_LINK_TYPE_BR };
    for (uint32_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX + i, &sessionKey, types[i], false);
        EXPECT_EQ(ret, SOFTBUS_OK);
        ret = SetSessionKeyAvailable(&list_, SESSIONKEY_INDEX + i);
        EXPECT_EQ(ret, SOFTBUS_OK);

        const char *plainText = "Test";
        uint32_t plainLen = static_cast<uint32_t>(strlen(plainText)) + 1;
        InDataInfo inDataInfo = { reinterpret_cast<const uint8_t *>(plainText), plainLen };
        uint32_t encLen = plainLen + ENCRYPT_OVER_HEAD_LEN;
        uint8_t *encData = static_cast<uint8_t *>(SoftBusCalloc(encLen));
        ASSERT_NE(encData, nullptr);

        ret = EncryptData(&list_, types[i], &inDataInfo, encData, &encLen);
        EXPECT_EQ(ret, SOFTBUS_OK);

        SoftBusFree(encData);
    }
}

/*
 * @tc.name: ENCRYPT_DECRYPT_INNER_TEST_001
 * @tc.desc: Test EncryptInner and DecryptInner with valid parameters.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, ENCRYPT_DECRYPT_INNER_TEST_001, TestSize.Level1)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    uint8_t testKey[SESSION_KEY_LENGTH] = { 5, 6, 7, 8 };
    int memcpyResult = memcpy_s(sessionKey.value, SESSION_KEY_LENGTH, testKey, sizeof(testKey));
    EXPECT_EQ(memcpyResult, 0);
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAvailable(&list_, SESSIONKEY_INDEX);
    EXPECT_EQ(ret, SOFTBUS_OK);

    const char *plainText = "Inner Encrypt Test";
    uint32_t plainLen = static_cast<uint32_t>(strlen(plainText)) + 1;
    InDataInfo inDataInfo = { reinterpret_cast<const uint8_t *>(plainText), plainLen };

    uint8_t *encData = nullptr;
    uint32_t encLen = 0;
    ret = EncryptInner(&list_, AUTH_LINK_TYPE_WIFI, &inDataInfo, &encData, &encLen);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NE(encData, nullptr);
    EXPECT_GT(encLen, 0);

    uint8_t *decData = nullptr;
    uint32_t decLen = 0;
    if (encData != nullptr) {
        InDataInfo encDataInfo = { encData, encLen };
        ret = DecryptInner(&list_, AUTH_LINK_TYPE_WIFI, &encDataInfo, &decData, &decLen);
        EXPECT_EQ(ret, SOFTBUS_OK);
        EXPECT_NE(decData, nullptr);
        EXPECT_GT(decLen, 0);
        if (decData != nullptr) {
            EXPECT_EQ(strcmp(reinterpret_cast<char *>(decData), plainText), 0);
        }
        SoftBusFree(decData);
    }
    SoftBusFree(encData);
}

/*
 * @tc.name: ENCRYPT_DECRYPT_INNER_TEST_002
 * @tc.desc: Test EncryptInner with invalid parameters.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, ENCRYPT_DECRYPT_INNER_TEST_002, TestSize.Level2)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    const char *plainText = "Test";
    uint32_t plainLen = static_cast<uint32_t>(strlen(plainText)) + 1;
    InDataInfo inDataInfo = { reinterpret_cast<const uint8_t *>(plainText), plainLen };

    uint8_t *encData = nullptr;
    uint32_t encLen = 0;

    ret = EncryptInner(nullptr, AUTH_LINK_TYPE_WIFI, &inDataInfo, &encData, &encLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = EncryptInner(&list_, AUTH_LINK_TYPE_WIFI, nullptr, &encData, &encLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = EncryptInner(&list_, AUTH_LINK_TYPE_WIFI, &inDataInfo, nullptr, &encLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = EncryptInner(&list_, AUTH_LINK_TYPE_WIFI, &inDataInfo, &encData, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ENCRYPT_DECRYPT_INNER_TEST_003
 * @tc.desc: Test DecryptInner with invalid parameters.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, ENCRYPT_DECRYPT_INNER_TEST_003, TestSize.Level2)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    const char *cipherText = "TestCipher";
    uint32_t cipherLen = 20;

    uint8_t *decData = nullptr;
    uint32_t decLen = 0;
    InDataInfo inDataInfo = { reinterpret_cast<const uint8_t *>(cipherText), cipherLen };

    ret = DecryptInner(nullptr, AUTH_LINK_TYPE_WIFI, &inDataInfo, &decData, &decLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DecryptInner(&list_, AUTH_LINK_TYPE_WIFI, nullptr, &decData, &decLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    InDataInfo nullInData = { nullptr, cipherLen };
    ret = DecryptInner(&list_, AUTH_LINK_TYPE_WIFI, &nullInData, &decData, &decLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    InDataInfo shortLenData = { reinterpret_cast<const uint8_t *>(cipherText), 5 };
    ret = DecryptInner(&list_, AUTH_LINK_TYPE_WIFI, &shortLenData, &decData, &decLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = DecryptInner(&list_, AUTH_LINK_TYPE_WIFI, &inDataInfo, nullptr, &decLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = DecryptInner(&list_, AUTH_LINK_TYPE_WIFI, &inDataInfo, &decData, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ENCRYPT_DECRYPT_INNER_TEST_004
 * @tc.desc: Test EncryptInner memory allocation failure handling.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, ENCRYPT_DECRYPT_INNER_TEST_004, TestSize.Level2)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));

    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    const char *plainText = "Test";
    uint32_t plainLen = static_cast<uint32_t>(strlen(plainText)) + 1;
    InDataInfo inDataInfo = { reinterpret_cast<const uint8_t *>(plainText), plainLen };

    uint8_t *encData = nullptr;
    uint32_t encLen = 0;

    ret = EncryptInner(&list_, AUTH_LINK_TYPE_WIFI, &inDataInfo, &encData, &encLen);
    EXPECT_NE(ret, SOFTBUS_OK);

    if (encData != nullptr) {
        SoftBusFree(encData);
    }
}

/*
 * @tc.name: DUMP_SESSION_KEY_LIST_TEST_001
 * @tc.desc: Test DumpSessionkeyList with normal case.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, DUMP_SESSION_KEY_LIST_TEST_001, TestSize.Level1)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddSessionKey(&list_, SESSIONKEY_INDEX2, &sessionKey, AUTH_LINK_TYPE_BLE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(DumpSessionkeyList(&list_));
}

/*
 * @tc.name: DUMP_SESSION_KEY_LIST_TEST_002
 * @tc.desc: Test DumpSessionkeyList with empty list.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, DUMP_SESSION_KEY_LIST_TEST_002, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    EXPECT_NO_FATAL_FAILURE(DumpSessionkeyList(&list_));
}

/*
 * @tc.name: DUMP_SESSION_KEY_LIST_TEST_003
 * @tc.desc: Test DumpSessionkeyList with NULL pointer.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, DUMP_SESSION_KEY_LIST_TEST_003, TestSize.Level2)
{
    EXPECT_NO_FATAL_FAILURE(DumpSessionkeyList(nullptr));
}

/*
 * @tc.name: SCHEDULE_UPDATE_SESSION_KEY_TEST_001
 * @tc.desc: Test ScheduleUpdateSessionKey with valid parameters.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, SCHEDULE_UPDATE_SESSION_KEY_TEST_001, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = 12345, .type = AUTH_LINK_TYPE_WIFI };
    EXPECT_NO_FATAL_FAILURE(ScheduleUpdateSessionKey(authHandle, 1000));
}

/*
 * @tc.name: SCHEDULE_UPDATE_SESSION_KEY_TEST_002
 * @tc.desc: Test ScheduleUpdateSessionKey with invalid link type.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, SCHEDULE_UPDATE_SESSION_KEY_TEST_002, TestSize.Level2)
{
    AuthHandle authHandle = { .authId = 12345, .type = AUTH_LINK_TYPE_MAX };
    EXPECT_NO_FATAL_FAILURE(ScheduleUpdateSessionKey(authHandle, 1000));
}

/*
 * @tc.name: SCHEDULE_UPDATE_SESSION_KEY_TEST_003
 * @tc.desc: Test ScheduleUpdateSessionKey with different link types.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, SCHEDULE_UPDATE_SESSION_KEY_TEST_003, TestSize.Level1)
{
    AuthHandle wifiHandle = { .authId = 10001, .type = AUTH_LINK_TYPE_WIFI };
    AuthHandle bleHandle = { .authId = 10002, .type = AUTH_LINK_TYPE_BLE };
    AuthHandle brHandle = { .authId = 10003, .type = AUTH_LINK_TYPE_BR };
    EXPECT_NO_FATAL_FAILURE(ScheduleUpdateSessionKey(wifiHandle, 2000));
    EXPECT_NO_FATAL_FAILURE(ScheduleUpdateSessionKey(bleHandle, 3000));
    EXPECT_NO_FATAL_FAILURE(ScheduleUpdateSessionKey(brHandle, 4000));
}

/*
 * @tc.name: CANCEL_UPDATE_SESSION_KEY_TEST_001
 * @tc.desc: Test CancelUpdateSessionKey with valid authId.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, CANCEL_UPDATE_SESSION_KEY_TEST_001, TestSize.Level1)
{
    int64_t authId = 54321;
    EXPECT_NO_FATAL_FAILURE(CancelUpdateSessionKey(authId));
}

/*
 * @tc.name: CANCEL_UPDATE_SESSION_KEY_TEST_002
 * @tc.desc: Test CancelUpdateSessionKey with zero and negative authId.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, CANCEL_UPDATE_SESSION_KEY_TEST_002, TestSize.Level2)
{
    EXPECT_NO_FATAL_FAILURE(CancelUpdateSessionKey(0));
    EXPECT_NO_FATAL_FAILURE(CancelUpdateSessionKey(-1));
}

/*
 * @tc.name: CANCEL_UPDATE_SESSION_KEY_TEST_003
 * @tc.desc: Test Schedule and Cancel update session key.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, CANCEL_UPDATE_SESSION_KEY_TEST_003, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = 99999, .type = AUTH_LINK_TYPE_WIFI };
    EXPECT_NO_FATAL_FAILURE(ScheduleUpdateSessionKey(authHandle, 5000));
    EXPECT_NO_FATAL_FAILURE(CancelUpdateSessionKey(authHandle.authId));
}

/*
 * @tc.name: SESSION_KEY_MAX_NUM_TEST_001
 * @tc.desc: Test adding session keys beyond max limit.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, SESSION_KEY_MAX_NUM_TEST_001, TestSize.Level1)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));

    for (int32_t i = 0; i < 15; i++) {
        int32_t ret = AddSessionKey(&list_, i, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
        EXPECT_EQ(ret, SOFTBUS_OK);
        SoftBusSleepMs(10);
    }

    SessionKey outKey = { { 0 }, 0 };
    int32_t ret = GetSessionKeyByIndex(&list_, 0, AUTH_LINK_TYPE_WIFI, &outKey);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = GetSessionKeyByIndex(&list_, 4, AUTH_LINK_TYPE_WIFI, &outKey);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = GetSessionKeyByIndex(&list_, 5, AUTH_LINK_TYPE_WIFI, &outKey);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetSessionKeyByIndex(&list_, 14, AUTH_LINK_TYPE_WIFI, &outKey);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SESSION_KEY_ENCRYPT_DECRYPT_STRESS_TEST_001
 * @tc.desc: Test multiple encrypt/decrypt operations.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, SESSION_KEY_ENCRYPT_DECRYPT_STRESS_TEST_001, TestSize.Level1)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    uint8_t testKey[SESSION_KEY_LENGTH] = { 9, 8, 7, 6 };
    int memcpyResult = memcpy_s(sessionKey.value, SESSION_KEY_LENGTH, testKey, sizeof(testKey));
    EXPECT_EQ(memcpyResult, 0);
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAvailable(&list_, SESSIONKEY_INDEX);
    EXPECT_EQ(ret, SOFTBUS_OK);

    for (int32_t i = 0; i < 10; i++) {
        char plainText[64];
        (void)snprintf_s(plainText, sizeof(plainText), sizeof(plainText) - 1, "Test Message %d", i);
        uint32_t plainLen = static_cast<uint32_t>(strlen(plainText)) + 1;
        InDataInfo inDataInfo = { reinterpret_cast<const uint8_t *>(plainText), plainLen };

        uint8_t *encData = nullptr;
        uint32_t encLen = 0;
        ret = EncryptInner(&list_, AUTH_LINK_TYPE_WIFI, &inDataInfo, &encData, &encLen);
        EXPECT_EQ(ret, SOFTBUS_OK);

        uint8_t *decData = nullptr;
        uint32_t decLen = 0;
        InDataInfo encDataInfo = { encData, encLen };
        ret = DecryptInner(&list_, AUTH_LINK_TYPE_WIFI, &encDataInfo, &decData, &decLen);
        EXPECT_EQ(ret, SOFTBUS_OK);
        EXPECT_EQ(strcmp(reinterpret_cast<char *>(decData), plainText), 0);

        SoftBusFree(encData);
        SoftBusFree(decData);
    }
}

/*
 * @tc.name: SESSION_KEY_MULTI_LINK_TYPE_TEST_001
 * @tc.desc: Test session key with multiple link types on same index.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, SESSION_KEY_MULTI_LINK_TYPE_TEST_001, TestSize.Level1)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAvailable(&list_, SESSIONKEY_INDEX);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = SetSessionKeyAuthLinkType(&list_, SESSIONKEY_INDEX, AUTH_LINK_TYPE_BLE);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAuthLinkType(&list_, SESSIONKEY_INDEX, AUTH_LINK_TYPE_BR);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_EQ(CheckSessionKeyListExistType(&list_, AUTH_LINK_TYPE_WIFI), true);
    EXPECT_EQ(CheckSessionKeyListExistType(&list_, AUTH_LINK_TYPE_BLE), true);
    EXPECT_EQ(CheckSessionKeyListExistType(&list_, AUTH_LINK_TYPE_BR), true);

    SessionKey outKey = { { 0 }, 0 };
    ret = GetSessionKeyByIndex(&list_, SESSIONKEY_INDEX, AUTH_LINK_TYPE_WIFI, &outKey);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetSessionKeyByIndex(&list_, SESSIONKEY_INDEX, AUTH_LINK_TYPE_BLE, &outKey);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetSessionKeyByIndex(&list_, SESSIONKEY_INDEX, AUTH_LINK_TYPE_BR, &outKey);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SESSION_KEY_REMOVE_PARTIAL_LINK_TYPE_TEST_001
 * @tc.desc: Test removing partial link types from multi-type key.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, SESSION_KEY_REMOVE_PARTIAL_LINK_TYPE_TEST_001, TestSize.Level1)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAuthLinkType(&list_, SESSIONKEY_INDEX, AUTH_LINK_TYPE_BLE);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAuthLinkType(&list_, SESSIONKEY_INDEX, AUTH_LINK_TYPE_BR);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_NO_FATAL_FAILURE(RemoveSessionkeyByIndex(&list_, SESSIONKEY_INDEX, AUTH_LINK_TYPE_WIFI));
    EXPECT_EQ(CheckSessionKeyListExistType(&list_, AUTH_LINK_TYPE_WIFI), false);
    EXPECT_EQ(CheckSessionKeyListExistType(&list_, AUTH_LINK_TYPE_BLE), true);
    EXPECT_EQ(CheckSessionKeyListExistType(&list_, AUTH_LINK_TYPE_BR), true);

    EXPECT_NO_FATAL_FAILURE(RemoveSessionkeyByIndex(&list_, SESSIONKEY_INDEX, AUTH_LINK_TYPE_BLE));
    EXPECT_EQ(CheckSessionKeyListExistType(&list_, AUTH_LINK_TYPE_BLE), false);
    EXPECT_EQ(CheckSessionKeyListExistType(&list_, AUTH_LINK_TYPE_BR), true);

    EXPECT_NO_FATAL_FAILURE(RemoveSessionkeyByIndex(&list_, SESSIONKEY_INDEX, AUTH_LINK_TYPE_BR));
    EXPECT_EQ(HasSessionKey(&list_), false);
}

/*
 * @tc.name: SESSION_KEY_GET_LATEST_TIME_TEST_001
 * @tc.desc: Test GetLatestAvailableSessionKeyTime with no available keys.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, SESSION_KEY_GET_LATEST_TIME_TEST_001, TestSize.Level2)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    uint64_t time = GetLatestAvailableSessionKeyTime(&list_, AUTH_LINK_TYPE_WIFI);
    EXPECT_EQ(time, 0);
}

/*
 * @tc.name: SESSION_KEY_GET_LATEST_TIME_TEST_002
 * @tc.desc: Test GetLatestAvailableSessionKeyTime with NULL list.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, SESSION_KEY_GET_LATEST_TIME_TEST_002, TestSize.Level2)
{
    uint64_t time = GetLatestAvailableSessionKeyTime(nullptr, AUTH_LINK_TYPE_WIFI);
    EXPECT_EQ(time, 0);
}

/*
 * @tc.name: SESSION_KEY_GET_LATEST_TEST_001
 * @tc.desc: Test GetLatestSessionKey with empty list.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, SESSION_KEY_GET_LATEST_TEST_001, TestSize.Level2)
{
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));

    int32_t index = 0;
    SessionKey sessionKey = { { 0 }, 0 };
    int32_t ret = GetLatestSessionKey(&list_, AUTH_LINK_TYPE_WIFI, &index, &sessionKey);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SESSION_KEY_GET_LATEST_TEST_002
 * @tc.desc: Test GetLatestSessionKey with NULL parameters.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, SESSION_KEY_GET_LATEST_TEST_002, TestSize.Level2)
{
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t index = 0;
    SessionKey sessionKey = { { 0 }, 0 };

    int32_t ret = GetLatestSessionKey(nullptr, AUTH_LINK_TYPE_WIFI, &index, &sessionKey);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetLatestSessionKey(&list_, AUTH_LINK_TYPE_WIFI, nullptr, &sessionKey);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetLatestSessionKey(&list_, AUTH_LINK_TYPE_WIFI, &index, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SESSION_KEY_SET_AVAILABLE_TEST_001
 * @tc.desc: Test SetSessionKeyAvailable with NULL list.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, SESSION_KEY_SET_AVAILABLE_TEST_001, TestSize.Level2)
{
    int32_t ret = SetSessionKeyAvailable(nullptr, SESSIONKEY_INDEX);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SESSION_KEY_SET_AVAILABLE_TEST_002
 * @tc.desc: Test SetSessionKeyAvailable with non-existent index.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, SESSION_KEY_SET_AVAILABLE_TEST_002, TestSize.Level2)
{
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));

    int32_t ret = SetSessionKeyAvailable(&list_, 999);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SESSION_KEY_SET_AUTH_LINK_TYPE_TEST_001
 * @tc.desc: Test SetSessionKeyAuthLinkType with non-existent index.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, SESSION_KEY_SET_AUTH_LINK_TYPE_TEST_001, TestSize.Level2)
{
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));

    int32_t ret = SetSessionKeyAuthLinkType(&list_, 999, AUTH_LINK_TYPE_WIFI);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SESSION_KEY_SET_AUTH_LINK_TYPE_TEST_002
 * @tc.desc: Test SetSessionKeyAuthLinkType with NULL list.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, SESSION_KEY_SET_AUTH_LINK_TYPE_TEST_002, TestSize.Level2)
{
    int32_t ret = SetSessionKeyAuthLinkType(nullptr, SESSIONKEY_INDEX, AUTH_LINK_TYPE_WIFI);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: CHECK_OLD_KEY_TEST_001
 * @tc.desc: Test CheckSessionKeyListHasOldKey with NULL list.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, CHECK_OLD_KEY_TEST_001, TestSize.Level2)
{
    bool hasOldKey = CheckSessionKeyListHasOldKey(nullptr, AUTH_LINK_TYPE_WIFI);
    EXPECT_EQ(hasOldKey, false);
}

/*
 * @tc.name: CLEAR_OLD_KEY_TEST_001
 * @tc.desc: Test ClearOldKey with NULL list.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, CLEAR_OLD_KEY_TEST_001, TestSize.Level2)
{
    int32_t ret = ClearOldKey(nullptr, AUTH_LINK_TYPE_WIFI);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ENCRYPT_DATA_NO_KEY_TEST_001
 * @tc.desc: Test EncryptData when no session key available.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, ENCRYPT_DATA_NO_KEY_TEST_001, TestSize.Level2)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    const char *plainText = "Test";
    uint32_t plainLen = static_cast<uint32_t>(strlen(plainText)) + 1;
    InDataInfo inDataInfo = { reinterpret_cast<const uint8_t *>(plainText), plainLen };
    uint32_t encLen = plainLen + ENCRYPT_OVER_HEAD_LEN;
    uint8_t *encData = static_cast<uint8_t *>(SoftBusCalloc(encLen));
    ASSERT_NE(encData, nullptr);

    ret = EncryptData(&list_, AUTH_LINK_TYPE_WIFI, &inDataInfo, encData, &encLen);
    EXPECT_NE(ret, SOFTBUS_OK);

    SoftBusFree(encData);
}

/*
 * @tc.name: ADD_SESSION_KEY_NULL_KEY_TEST_001
 * @tc.desc: Test AddSessionKey with NULL key parameter.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, ADD_SESSION_KEY_NULL_KEY_TEST_001, TestSize.Level2)
{
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));

    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, nullptr, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ADD_SESSION_KEY_NULL_LIST_TEST_001
 * @tc.desc: Test AddSessionKey with NULL list parameter.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, ADD_SESSION_KEY_NULL_LIST_TEST_001, TestSize.Level2)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };

    int32_t ret = AddSessionKey(nullptr, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SESSION_KEY_MULTIPLE_REMOVE_TEST_001
 * @tc.desc: Test multiple remove operations on same index.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, SESSION_KEY_MULTIPLE_REMOVE_TEST_001, TestSize.Level1)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_NO_FATAL_FAILURE(RemoveSessionkeyByIndex(&list_, SESSIONKEY_INDEX, AUTH_LINK_TYPE_WIFI));
    EXPECT_EQ(HasSessionKey(&list_), false);

    EXPECT_NO_FATAL_FAILURE(RemoveSessionkeyByIndex(&list_, SESSIONKEY_INDEX, AUTH_LINK_TYPE_WIFI));
}

/*
 * @tc.name: SESSION_KEY_TIME_UPDATE_TEST_001
 * @tc.desc: Test that session key time is updated on access.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, SESSION_KEY_TIME_UPDATE_TEST_001, TestSize.Level1)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAvailable(&list_, SESSIONKEY_INDEX);
    EXPECT_EQ(ret, SOFTBUS_OK);

    uint64_t time1 = GetLatestAvailableSessionKeyTime(&list_, AUTH_LINK_TYPE_WIFI);
    SoftBusSleepMs(50);

    int32_t index = 0;
    SessionKey outKey = { { 0 }, 0 };
    ret = GetLatestSessionKey(&list_, AUTH_LINK_TYPE_WIFI, &index, &outKey);
    EXPECT_EQ(ret, SOFTBUS_OK);

    uint64_t time2 = GetLatestAvailableSessionKeyTime(&list_, AUTH_LINK_TYPE_WIFI);
    EXPECT_GT(time2, time1);
}

/*
 * @tc.name: DESTROY_SESSION_KEY_LIST_TEST_001
 * @tc.desc: Test DestroySessionKeyList with NULL pointer.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, DESTROY_SESSION_KEY_LIST_TEST_001, TestSize.Level2)
{
    EXPECT_NO_FATAL_FAILURE(DestroySessionKeyList(nullptr));
}

/*
 * @tc.name: SESSION_KEY_LONG_ENCRYPT_DECRYPT_TEST_001
 * @tc.desc: Test encrypt/decrypt with long data.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, SESSION_KEY_LONG_ENCRYPT_DECRYPT_TEST_001, TestSize.Level1)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    uint8_t testKey[SESSION_KEY_LENGTH] = { 1, 2, 3, 4 };
    int memcpyResult = memcpy_s(sessionKey.value, SESSION_KEY_LENGTH, testKey, sizeof(testKey));
    EXPECT_EQ(memcpyResult, 0);
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAvailable(&list_, SESSIONKEY_INDEX);
    EXPECT_EQ(ret, SOFTBUS_OK);

    uint32_t longDataLen = 1024;
    uint8_t *longData = static_cast<uint8_t *>(SoftBusCalloc(longDataLen));
    ASSERT_NE(longData, nullptr);
    for (uint32_t i = 0; i < longDataLen; i++) {
        longData[i] = static_cast<uint8_t>(i % 256);
    }

    InDataInfo inDataInfo = { longData, longDataLen };
    uint8_t *encData = nullptr;
    uint32_t encLen = 0;
    ret = EncryptInner(&list_, AUTH_LINK_TYPE_WIFI, &inDataInfo, &encData, &encLen);
    EXPECT_EQ(ret, SOFTBUS_OK);

    uint8_t *decData = nullptr;
    uint32_t decLen = 0;
    InDataInfo encDataInfo = { encData, encLen };
    ret = DecryptInner(&list_, AUTH_LINK_TYPE_WIFI, &encDataInfo, &decData, &decLen);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(decLen, longDataLen);
    EXPECT_EQ(memcmp(decData, longData, longDataLen), 0);

    SoftBusFree(longData);
    SoftBusFree(encData);
    SoftBusFree(decData);
}

/*
 * @tc.name: SESSION_KEY_OLD_KEY_FLAG_TEST_001
 * @tc.desc: Test old key flag is properly set and cleared.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, SESSION_KEY_OLD_KEY_FLAG_TEST_001, TestSize.Level1)
{
    SessionKey sessionKey = { { 0 }, SESSIONKEY_LEN };
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));

    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey, AUTH_LINK_TYPE_WIFI, true);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(CheckSessionKeyListHasOldKey(&list_, AUTH_LINK_TYPE_WIFI), true);

    ret = AddSessionKey(&list_, SESSIONKEY_INDEX2, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(CheckSessionKeyListHasOldKey(&list_, AUTH_LINK_TYPE_WIFI), true);

    ret = ClearOldKey(&list_, AUTH_LINK_TYPE_WIFI);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(CheckSessionKeyListHasOldKey(&list_, AUTH_LINK_TYPE_WIFI), false);
}

/*
 * @tc.name: SESSION_KEY_ENCRYPT_DIFFERENT_KEY_TEST_001
 * @tc.desc: Test encryption with different session keys produces different ciphertext.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, SESSION_KEY_ENCRYPT_DIFFERENT_KEY_TEST_001, TestSize.Level1)
{
    SessionKey sessionKey1 = { { 0 }, SESSIONKEY_LEN };
    SessionKey sessionKey2 = { { 0 }, SESSIONKEY_LEN };
    uint8_t testKey1[SESSION_KEY_LENGTH] = { 1, 1, 1, 1 };
    uint8_t testKey2[SESSION_KEY_LENGTH] = { 2, 2, 2, 2 };
    int memcpyResult1 = memcpy_s(sessionKey1.value, SESSION_KEY_LENGTH, testKey1, sizeof(testKey1));
    EXPECT_EQ(memcpyResult1, 0);
    int memcpyResult2 = memcpy_s(sessionKey2.value, SESSION_KEY_LENGTH, testKey2, sizeof(testKey2));
    EXPECT_EQ(memcpyResult2, 0);
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));

    int32_t ret = AddSessionKey(&list_, SESSIONKEY_INDEX, &sessionKey1, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAvailable(&list_, SESSIONKEY_INDEX);
    EXPECT_EQ(ret, SOFTBUS_OK);

    const char *plainText = "Test";
    uint32_t plainLen = static_cast<uint32_t>(strlen(plainText)) + 1;
    InDataInfo inDataInfo = { reinterpret_cast<const uint8_t *>(plainText), plainLen };

    uint8_t *encData1 = nullptr;
    uint32_t encLen1 = 0;
    ret = EncryptInner(&list_, AUTH_LINK_TYPE_WIFI, &inDataInfo, &encData1, &encLen1);
    EXPECT_EQ(ret, SOFTBUS_OK);

    // Destroy the old session key to prevent memory leak
    EXPECT_NO_FATAL_FAILURE(DestroySessionKeyList(&list_));
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));
    ret = AddSessionKey(&list_, SESSIONKEY_INDEX2, &sessionKey2, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionKeyAvailable(&list_, SESSIONKEY_INDEX2);
    EXPECT_EQ(ret, SOFTBUS_OK);

    uint8_t *encData2 = nullptr;
    uint32_t encLen2 = 0;
    ret = EncryptInner(&list_, AUTH_LINK_TYPE_WIFI, &inDataInfo, &encData2, &encLen2);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_EQ(encLen1, encLen2);
    EXPECT_NE(memcmp(encData1, encData2, encLen1), 0);  // Ensure ciphertext content is different

    SoftBusFree(encData1);
    SoftBusFree(encData2);
}

/*
 * @tc.name: GET_SESSION_KEY_TYPE_EMPTY_LIST_TEST_001
 * @tc.desc: Test GetSessionKeyTypeByIndex with empty list.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthSessionKeyTest, GET_SESSION_KEY_TYPE_EMPTY_LIST_TEST_001, TestSize.Level2)
{
    EXPECT_NO_FATAL_FAILURE(InitSessionKeyList(&list_));

    AuthLinkType type = GetSessionKeyTypeByIndex(&list_, SESSIONKEY_INDEX);
    EXPECT_EQ(type, AUTH_LINK_TYPE_MAX);
}
} // namespace OHOS
