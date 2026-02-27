/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <securec.h>

#include "gtest/gtest.h"
#include <gmock/gmock-actions.h>
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "lnn_log.h"
#include "lnn_ohos_account_adapter.h"
#include "lnn_ohos_account_adapter_mock.h"
#include "softbus_adapter_mem.h"
#include "softbus_app_info.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

using namespace std;
using namespace testing::ext;

namespace OHOS::SoftBus {
#define DEFAULT_ACCOUNT_NAME "ohosAnonymousName"
#define INVALID_ACCOUNT_UID (-1)

constexpr char LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN = 10;
constexpr char TYPE_CAR_ID = 0x83;

class LnnOhosAccountAdapterTest : public testing::Test {
protected:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
void LnnOhosAccountAdapterTest::SetUpTestCase(void) { }
void LnnOhosAccountAdapterTest::TearDownTestCase(void) { }
void LnnOhosAccountAdapterTest::SetUp(void) { }
void LnnOhosAccountAdapterTest::TearDown(void) { }

/*
 * @tc.name: GetCurrentAccount_001
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when account pointer is nullptr
 *           and SOFTBUS_AUTH_INNER_ERR when not in same account group device
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetCurrentAccount_001, TestSize.Level1)
{
    int64_t account = 10;
    EXPECT_EQ(GetCurrentAccount(nullptr), SOFTBUS_INVALID_PARAM);
    OHOS::AccountSA::OhosAccountKitsMock mock;
    EXPECT_EQ(GetCurrentAccount(&account), SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED);
}

/*
 * @tc.name: GetCurrentAccount_002
 * @tc.desc: Return SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED when in
 *           same account group but querying Ohos account info fails
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetCurrentAccount_002, TestSize.Level1)
{
    int64_t account = 10;
    OHOS::AccountSA::OhosAccountInfo oh_acc_info;
    std::pair<bool, OHOS::AccountSA::OhosAccountInfo> oh_acc_info_pair = { false, oh_acc_info };
    OHOS::AccountSA::OhosAccountKitsMock mock;
    EXPECT_CALL(mock, QueryOhosAccountInfo()).Times(1).WillOnce(testing::Return(oh_acc_info_pair));
    EXPECT_EQ(GetCurrentAccount(&account), SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED);
}

/*
 * @tc.name: GetCurrentAccount_003
 * @tc.desc: Return SOFTBUS_OK when in same account group and Ohos account name is empty
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetCurrentAccount_003, TestSize.Level1)
{
    int64_t account = 10;
    OHOS::AccountSA::OhosAccountInfo oh_acc_info;
    oh_acc_info.name_ = "";
    std::pair<bool, OHOS::AccountSA::OhosAccountInfo> oh_acc_info_pair = { true, oh_acc_info };
    OHOS::AccountSA::OhosAccountKitsMock mock;
    EXPECT_CALL(mock, QueryOhosAccountInfo()).Times(1).WillOnce(testing::Return(oh_acc_info_pair));
    EXPECT_EQ(GetCurrentAccount(&account), SOFTBUS_OK);
}

/*
 * @tc.name: GetCurrentAccount_004
 * @tc.desc: Return SOFTBUS_OK when in same account group and Ohos account name is default account name
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetCurrentAccount_004, TestSize.Level1)
{
    int64_t account = 10;
    OHOS::AccountSA::OhosAccountInfo oh_acc_info;
    oh_acc_info.name_ = DEFAULT_ACCOUNT_NAME;
    std::pair<bool, OHOS::AccountSA::OhosAccountInfo> oh_acc_info_pair = { true, oh_acc_info };
    OHOS::AccountSA::OhosAccountKitsMock mock;
    EXPECT_CALL(mock, QueryOhosAccountInfo()).Times(1).WillOnce(testing::Return(oh_acc_info_pair));
    EXPECT_EQ(GetCurrentAccount(&account), SOFTBUS_OK);
}

/*
 * @tc.name: GetCurrentAccount_005
 * @tc.desc: Return SOFTBUS_OK when in same account group and Ohos account name is alphabetic string
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetCurrentAccount_005, TestSize.Level1)
{
    int64_t account = 10;
    OHOS::AccountSA::OhosAccountInfo oh_acc_info;
    oh_acc_info.name_ = "ACCOUNT_NAME";
    std::pair<bool, OHOS::AccountSA::OhosAccountInfo> oh_acc_info_pair = { true, oh_acc_info };
    OHOS::AccountSA::OhosAccountKitsMock mock;
    EXPECT_CALL(mock, QueryOhosAccountInfo()).Times(1).WillOnce(testing::Return(oh_acc_info_pair));
    EXPECT_EQ(GetCurrentAccount(&account), SOFTBUS_OK);
}

/*
 * @tc.name: GetCurrentAccount_006
 * @tc.desc: Return SOFTBUS_OK when in same account group and Ohos account name is numeric string
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetCurrentAccount_006, TestSize.Level1)
{
    int64_t account = 10;
    OHOS::AccountSA::OhosAccountInfo oh_acc_info;
    oh_acc_info.name_ = "123456";
    std::pair<bool, OHOS::AccountSA::OhosAccountInfo> oh_acc_info_pair = { true, oh_acc_info };
    OHOS::AccountSA::OhosAccountKitsMock mock;
    EXPECT_CALL(mock, QueryOhosAccountInfo()).Times(1).WillOnce(testing::Return(oh_acc_info_pair));
    EXPECT_EQ(GetCurrentAccount(&account), SOFTBUS_OK);
}

/*
 * @tc.name: GetOsAccountUid_InvalidParam01
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when accountUid buffer is nullptr
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetOsAccountUid_InvalidParam01, TestSize.Level1)
{
    uint32_t idLen = ACCOUNT_UID_STR_LEN;
    uint32_t len = 0;
    int32_t ret = GetOsAccountUid(nullptr, idLen, &len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetOsAccountUid_InvalidParam02
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when len pointer is nullptr
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetOsAccountUid_InvalidParam02, TestSize.Level1)
{
    char accountUid[ACCOUNT_UID_STR_LEN] = { 0 };
    uint32_t idLen = ACCOUNT_UID_STR_LEN;
    int32_t ret = GetOsAccountUid(accountUid, idLen, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetOsAccountUid_InvalidParam03
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when idLen is 0 and non-invalid when idLen is ACCOUNT_UID_STR_LEN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetOsAccountUid_InvalidParam03, TestSize.Level1)
{
    char accountUid[ACCOUNT_UID_STR_LEN] = { 0 };
    uint32_t idLen = 0;
    uint32_t len = 0;
    int32_t ret = GetOsAccountUid(accountUid, idLen, &len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    idLen = ACCOUNT_UID_STR_LEN;
    ret = GetOsAccountUid(accountUid, idLen, &len);
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetOsAccountUidByUserId_Test_001
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when accountUid buffer is nullptr
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetOsAccountUidByUserId_Test_001, TestSize.Level1)
{
    uint32_t idLen = ACCOUNT_UID_STR_LEN;
    uint32_t len = 0;
    int32_t userId = 100;
    int32_t ret = GetOsAccountUidByUserId(nullptr, idLen, &len, userId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetOsAccountUidByUserId_Test_002
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when len pointer is nullptr
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetOsAccountUidByUserId_Test_002, TestSize.Level1)
{
    char accountid[ACCOUNT_UID_STR_LEN] = { 0 };
    uint32_t idLen = ACCOUNT_UID_STR_LEN;
    int32_t userId = 100;
    int32_t ret = GetOsAccountUidByUserId(accountid, idLen, nullptr, userId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetOsAccountUidByUserId_Test_003
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when idLen is 0
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetOsAccountUidByUserId_Test_003, TestSize.Level1)
{
    char accountid[ACCOUNT_UID_STR_LEN] = { 0 };
    uint32_t idLen = 0;
    uint32_t len = 0;
    int32_t userId = 100;
    int32_t ret = GetOsAccountUidByUserId(accountid, idLen, &len, userId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetOsAccountUidByUserId_Test_004
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when userId is 0
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetOsAccountUidByUserId_Test_004, TestSize.Level1)
{
    char accountid[ACCOUNT_UID_STR_LEN] = { 0 };
    uint32_t idLen = ACCOUNT_UID_STR_LEN;
    uint32_t len = 0;
    int32_t userId = 0;
    int32_t ret = GetOsAccountUidByUserId(accountid, idLen, &len, userId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetOsAccountId_001
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when accountInfo buffer is nullptr idLen is 0 or len pointer is nullptr
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetOsAccountId_001, TestSize.Level1)
{
    uint32_t len = 0;
    char *accountInfo = (char *)SoftBusCalloc(LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN * HEXIFY_UNIT_LEN);
    ASSERT_NE(accountInfo, nullptr);
    EXPECT_EQ(GetOsAccountId(nullptr, LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN, &len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(GetOsAccountId(accountInfo, 0, &len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(GetOsAccountId(accountInfo, LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN, nullptr), SOFTBUS_INVALID_PARAM);
    if (accountInfo != nullptr) {
        SoftBusFree(accountInfo);
    }
}

/*
 * @tc.name: GetOsAccountId_002
 * @tc.desc: Return SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED with valid parameters for GetOsAccountId
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetOsAccountId_002, TestSize.Level1)
{
    uint32_t len = 0;
    char *accountInfo = (char *)SoftBusCalloc(LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN * HEXIFY_UNIT_LEN);
    ASSERT_NE(accountInfo, nullptr);
    EXPECT_EQ(GetOsAccountId(accountInfo, LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN, &len),
        SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED);
    if (accountInfo != nullptr) {
        SoftBusFree(accountInfo);
    }
}

/*
 * @tc.name: GetOsAccountId_003
 * @tc.desc: Return SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED when QueryOhosAccountInfo returns
 *           failure with valid parameters
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetOsAccountId_003, TestSize.Level1)
{
    char *accountInfo = (char *)SoftBusCalloc(LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN * HEXIFY_UNIT_LEN);
    ASSERT_NE(accountInfo, nullptr);
    uint32_t len = 0;
    OHOS::AccountSA::OhosAccountInfo oh_acc_info;
    std::pair<bool, OHOS::AccountSA::OhosAccountInfo> oh_acc_info_pair = { false, oh_acc_info };
    AccountSA::OhosAccountKitsMock mock;
    EXPECT_CALL(mock, QueryOhosAccountInfo()).Times(1).WillOnce(testing::Return(oh_acc_info_pair));
    EXPECT_EQ(GetOsAccountId(accountInfo, LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN, &len),
        SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED);
    if (accountInfo != nullptr) {
        SoftBusFree(accountInfo);
    }
}

/*
 * @tc.name: GetOsAccountId_004
 * @tc.desc: Return SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED when Ohos account name is empty with valid parameters
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetOsAccountId_004, TestSize.Level1)
{
    char *accountInfo = (char *)SoftBusCalloc(LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN * HEXIFY_UNIT_LEN);
    ASSERT_NE(accountInfo, nullptr);
    uint32_t len = 0;
    OHOS::AccountSA::OhosAccountInfo oh_acc_info;
    oh_acc_info.name_ = "";
    std::pair<bool, OHOS::AccountSA::OhosAccountInfo> oh_acc_info_pair = { true, oh_acc_info };
    OHOS::AccountSA::OhosAccountKitsMock mock;
    EXPECT_CALL(mock, QueryOhosAccountInfo()).Times(1).WillOnce(testing::Return(oh_acc_info_pair));
    EXPECT_EQ(GetOsAccountId(accountInfo, LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN, &len),
        SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED);

    if (accountInfo != nullptr) {
        SoftBusFree(accountInfo);
    }
}

/*
 * @tc.name: GetOsAccountId_005
 * @tc.desc: Return SOFTBUS_MEM_ERR when Ohos account name is "ohosAnonymousName" and len is 17 with
 *           valid buffer and idLen
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetOsAccountId_005, TestSize.Level1)
{
    char *accountInfo = (char *)SoftBusCalloc(LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN * HEXIFY_UNIT_LEN);
    ASSERT_NE(accountInfo, nullptr);
    uint32_t len = 17;
    OHOS::AccountSA::OhosAccountInfo oh_acc_info;
    oh_acc_info.name_ = "ohosAnonymousName";
    std::pair<bool, OHOS::AccountSA::OhosAccountInfo> oh_acc_info_pair = { true, oh_acc_info };
    OHOS::AccountSA::OhosAccountKitsMock mock;
    EXPECT_CALL(mock, QueryOhosAccountInfo()).Times(1).WillOnce(testing::Return(oh_acc_info_pair));
    EXPECT_EQ(GetOsAccountId(accountInfo, LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN, &len),
        SOFTBUS_MEM_ERR);

    if (accountInfo != nullptr) {
        SoftBusFree(accountInfo);
    }
}

/*
 * @tc.name: GetOsAccountUidByUserId_001
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when idLen is 0 with valid accountInfo buffer len pointer and userId
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetOsAccountUidByUserId_001, TestSize.Level1)
{
    int32_t userId = 123456;
    uint32_t len = LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN;
    uint32_t idLen = 0;
    char *accountInfo = (char *)SoftBusCalloc(LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN * HEXIFY_UNIT_LEN);
    ASSERT_NE(accountInfo, nullptr);
    EXPECT_EQ(GetOsAccountUidByUserId(accountInfo, idLen, &len, userId), SOFTBUS_INVALID_PARAM);
    if (accountInfo != nullptr) {
        SoftBusFree(accountInfo);
    }
}

/*
 * @tc.name: GetOsAccountUidByUserId_002
 * @tc.desc: Return -1 when Ohos account name is "teatsa" with valid userId accountInfo buffer idLen and len
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetOsAccountUidByUserId_002, TestSize.Level1)
{
    int32_t userId = 123456;
    uint32_t len = LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN;
    uint32_t idLen = LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN * HEXIFY_UNIT_LEN;
    char *accountInfo = (char *)SoftBusCalloc(LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN * HEXIFY_UNIT_LEN);
    ASSERT_NE(accountInfo, nullptr);
    OHOS::AccountSA::OhosAccountInfo oh_acc_info;
    oh_acc_info.name_ = "teatsa";
    EXPECT_EQ(GetOsAccountUidByUserId(accountInfo, idLen, &len, userId), -1);
    if (accountInfo != nullptr) {
        SoftBusFree(accountInfo);
    }
}

/*
 * @tc.name: GetOsAccountUidByUserId_003
 * @tc.desc: Return -1 when Ohos account name is "ohosAnonymousName" with
 *           valid userId accountInfo buffer idLen and len
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetOsAccountUidByUserId_003, TestSize.Level1)
{
    int32_t userId = 123456;
    uint32_t len = LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN;
    uint32_t idLen = LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN;
    char *accountInfo = (char *)SoftBusCalloc(LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN * HEXIFY_UNIT_LEN);
    ASSERT_NE(accountInfo, nullptr);
    OHOS::AccountSA::OhosAccountInfo oh_acc_info;
    oh_acc_info.name_ = "ohosAnonymousName";
    EXPECT_EQ(GetOsAccountUidByUserId(accountInfo, idLen, &len, userId), -1);
    if (accountInfo != nullptr) {
        SoftBusFree(accountInfo);
    }
}

/*
 * @tc.name: GetOsAccountIdByUserId_Test_001
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when userId is 0 with valid id buffer and len pointer
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetOsAccountIdByUserId_Test_001, TestSize.Level1)
{
    int32_t userId = 0;
    uint32_t len = 0;
    char *id = (char *)SoftBusCalloc(LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN * HEXIFY_UNIT_LEN);
    EXPECT_EQ(GetOsAccountIdByUserId(userId, &id, &len), SOFTBUS_INVALID_PARAM);
    if (id != nullptr) {
        SoftBusFree(id);
    }
}

/*
 * @tc.name: GetOsAccountIdByUserId_Test_002
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when id buffer is nullptr with valid userId and len pointer
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetOsAccountIdByUserId_Test_002, TestSize.Level1)
{
    int32_t userId = 123456;
    uint32_t len = 0;
    EXPECT_EQ(GetOsAccountIdByUserId(userId, nullptr, &len), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetOsAccountIdByUserId_Test_003
 * @tc.desc: Return SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED when getting account info fails with
 *           valid userId id buffer and len
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetOsAccountIdByUserId_Test_003, TestSize.Level1)
{
    int32_t userId = 123456;
    uint32_t len = 10;
    char *iD = (char *)SoftBusCalloc(LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN * HEXIFY_UNIT_LEN);
    ASSERT_NE(iD, nullptr);
    EXPECT_EQ(GetOsAccountIdByUserId(userId, &iD, &len), SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED);
    if (iD != nullptr) {
        SoftBusFree(iD);
    }
}

/*
 * @tc.name: GetOsAccountIdByUserId_Test_004
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when id buffer is nullptr with valid userId and len
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetOsAccountIdByUserId_Test_004, TestSize.Level1)
{
    int32_t userId = 100;
    uint32_t len = 10;
    int32_t ret = GetOsAccountIdByUserId(userId, nullptr, &len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetOsAccountIdByUserId_Test_005
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when len pointer is nullptr with valid userId and id buffer pointer
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetOsAccountIdByUserId_Test_005, TestSize.Level1)
{
    int32_t userId = 100;
    char *id = nullptr;
    int32_t ret = GetOsAccountIdByUserId(userId, &id, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetOsAccountIdByUserId_Test_006
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when userId is 0 with valid id buffer pointer and len
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetOsAccountIdByUserId_Test_006, TestSize.Level1)
{
    int32_t userId = 0;
    uint32_t len = 10;
    char *id = nullptr;
    int32_t ret = GetOsAccountIdByUserId(userId, &id, &len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GET_OS_ACCOUNT_ID_BY_USER_ID_TEST_001
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when userId is 0 and id buffer is nullptr with valid size pointer
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GET_OS_ACCOUNT_ID_BY_USER_ID_TEST_001, TestSize.Level1)
{
    uint32_t size = 0;
    int32_t ret = GetOsAccountIdByUserId(0, nullptr, &size);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GET_OS_ACCOUNT_ID_BY_USER_ID_TEST_002
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when userId is 0 and size pointer is nullptr with valid id buffer pointer
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GET_OS_ACCOUNT_ID_BY_USER_ID_TEST_002, TestSize.Level1)
{
    char *id = nullptr;
    int32_t ret = GetOsAccountIdByUserId(0, &id, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GET_OS_ACCOUNT_ID_BY_USER_ID_TEST_003
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when userId is -1 with null id buffer and valid size pointer
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GET_OS_ACCOUNT_ID_BY_USER_ID_TEST_003, TestSize.Level1)
{
    int32_t userId = -1;
    char *id = nullptr;
    uint32_t size = 0;
    int32_t ret = GetOsAccountIdByUserId(userId, &id, &size);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GET_OS_ACCOUNT_TEST_001
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when accountUid buffer is nullptr with valid idLen and size pointer
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GET_OS_ACCOUNT_TEST_001, TestSize.Level1)
{
    uint32_t size = 0;
    int32_t ret = GetOsAccountUid(nullptr, ACCOUNT_UID_STR_LEN, &size);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GET_OS_ACCOUNT_TEST_002
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when idLen is 0 with valid accountUid buffer and size pointer
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GET_OS_ACCOUNT_TEST_002, TestSize.Level1)
{
    char accountUid[ACCOUNT_UID_STR_LEN];
    uint32_t size = 0;
    (void)memset_s(accountUid, ACCOUNT_UID_STR_LEN, 0, ACCOUNT_UID_STR_LEN);
    int32_t ret = GetOsAccountUid(accountUid, 0, &size);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GET_OS_ACCOUNT_TEST_003
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when size pointer is nullptr with valid accountUid buffer and idLen
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GET_OS_ACCOUNT_TEST_003, TestSize.Level1)
{
    char accountUid[ACCOUNT_UID_STR_LEN];
    (void)memset_s(accountUid, ACCOUNT_UID_STR_LEN, 0, ACCOUNT_UID_STR_LEN);
    int32_t ret = GetOsAccountUid(accountUid, ACCOUNT_UID_STR_LEN, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GET_OS_ACCOUNT_UID_BY_USER_ID_TEST_001
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when accountId buffer is nullptr with idLen as ACCOUNT_UID_LEN_MAX-1
 *           size pointer and userId 0
 * @tc.type: FUN
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GET_OS_ACCOUNT_UID_BY_USER_ID_TEST_001, TestSize.Level1)
{
    int32_t userId = 0;
    uint32_t size = 0;
    int32_t ret = GetOsAccountUidByUserId(nullptr, ACCOUNT_UID_LEN_MAX - 1, &size, userId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GET_OS_ACCOUNT_UID_BY_USER_ID_TEST_002
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when size pointer is nullptr with valid accountId
 *           buffer idLen as ACCOUNT_UID_LEN_MAX-1 and userId 0
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GET_OS_ACCOUNT_UID_BY_USER_ID_TEST_002, TestSize.Level1)
{
    char accountId[ACCOUNT_UID_LEN_MAX];
    int32_t userId = 0;
    (void)memset_s(accountId, ACCOUNT_UID_LEN_MAX, 0, ACCOUNT_UID_LEN_MAX);
    int32_t ret = GetOsAccountUidByUserId(accountId, ACCOUNT_UID_LEN_MAX - 1, nullptr, userId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GET_OS_ACCOUNT_UID_BY_USER_ID_TEST_003
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when idLen is 0 with valid accountId buffer size pointer and userId 0
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GET_OS_ACCOUNT_UID_BY_USER_ID_TEST_003, TestSize.Level1)
{
    char accountId[ACCOUNT_UID_LEN_MAX];
    int32_t userId = 0;
    uint32_t size = 0;
    (void)memset_s(accountId, ACCOUNT_UID_LEN_MAX, 0, ACCOUNT_UID_LEN_MAX);
    int32_t ret = GetOsAccountUidByUserId(accountId, 0, &size, userId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GET_OS_ACCOUNT_UID_BY_USER_ID_TEST_004
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when userId is -1 with valid accountId buffer
 *           idLen as ACCOUNT_UID_LEN_MAX-1 and size pointer
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GET_OS_ACCOUNT_UID_BY_USER_ID_TEST_004, TestSize.Level1)
{
    char accountId[ACCOUNT_UID_LEN_MAX];
    int32_t userId = -1;
    uint32_t size = 0;
    (void)memset_s(accountId, ACCOUNT_UID_LEN_MAX, 0, ACCOUNT_UID_LEN_MAX);
    int32_t ret = GetOsAccountUidByUserId(accountId, ACCOUNT_UID_LEN_MAX - 1, &size, userId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GET_OS_ACCOUNT_UID_BY_USER_ID_TEST_005
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when userId is 0 with valid accountId buffer
 *           idLen as ACCOUNT_UID_LEN_MAX-1 and size pointer
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GET_OS_ACCOUNT_UID_BY_USER_ID_TEST_005, TestSize.Level1)
{
    char accountId[ACCOUNT_UID_LEN_MAX];
    int32_t userId = 0;
    uint32_t size = 0;
    (void)memset_s(accountId, ACCOUNT_UID_LEN_MAX, 0, ACCOUNT_UID_LEN_MAX);
    int32_t ret = GetOsAccountUidByUserId(accountId, ACCOUNT_UID_LEN_MAX - 1, &size, userId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: JUDGE_DEVICE_TYPE_AND_GET_OS_ACCOUNT_IDS_001
 * @tc.desc: Execute JudgeDeviceTypeAndGetOsAccountIds normally without fatal errors
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, JUDGE_DEVICE_TYPE_AND_GET_OS_ACCOUNT_IDS_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(JudgeDeviceTypeAndGetOsAccountIds());
}

/*
 * @tc.name: JUDGE_DEVICE_TYPE_AND_GET_OS_ACCOUNT_IDS_002
 * @tc.desc: Execute JudgeDeviceTypeAndGetOsAccountIds normally without
 *           fatal errors after setting device type to TYPE_CAR_ID
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, JUDGE_DEVICE_TYPE_AND_GET_OS_ACCOUNT_IDS_002, TestSize.Level1)
{
    LnnSetLocalNumInfo(NUM_KEY_DEV_TYPE_ID, TYPE_CAR_ID);
    EXPECT_NO_FATAL_FAILURE(JudgeDeviceTypeAndGetOsAccountIds());
}


/*
 * @tc.name: GetOsAccountIdByUserId_001
 * @tc.desc: Return SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED when
 *           Ohos account name is empty and in same account group
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetOsAccountIdByUserId_001, TestSize.Level0)
{
    int32_t userId = 123456;
    uint32_t len = 10;
    char *id = (char *)SoftBusCalloc(LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN * HEXIFY_UNIT_LEN);
    ASSERT_NE(id, nullptr);
    
    OHOS::AccountSA::OhosAccountInfo oh_acc_info;
    oh_acc_info.name_ = "";
    std::pair<bool, OHOS::AccountSA::OhosAccountInfo> oh_acc_info_pair = { true, oh_acc_info };
    OHOS::AccountSA::OhosAccountKitsMock mock;

    EXPECT_CALL(mock, IsSameAccountGroupDevice()).Times(1).WillOnce(testing::Return(true));
    EXPECT_EQ(GetOsAccountIdByUserId(userId, &id, &len), SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED);
    if (id != nullptr) {
        SoftBusFree(id);
    }
}

/*
 * @tc.name: GetOsAccountIdByUserId_002
 * @tc.desc: Return SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED when Ohos account name is
 *           default account name and in same account group
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetOsAccountIdByUserId_002, TestSize.Level0)
{
    int32_t userId = 123456;
    uint32_t len = 10;
    char *id = (char *)SoftBusCalloc(LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN * HEXIFY_UNIT_LEN);
    ASSERT_NE(id, nullptr);

    OHOS::AccountSA::OhosAccountInfo oh_acc_info;
    oh_acc_info.name_ = DEFAULT_ACCOUNT_NAME;
    std::pair<bool, OHOS::AccountSA::OhosAccountInfo> oh_acc_info_pair = { true, oh_acc_info };
    OHOS::AccountSA::OhosAccountKitsMock mock;

    EXPECT_CALL(mock, IsSameAccountGroupDevice()).Times(1).WillOnce(testing::Return(true));
    EXPECT_EQ(GetOsAccountIdByUserId(userId, &id, &len), SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED);

    if (id != nullptr) {
        SoftBusFree(id);
    }
}

/*
 * @tc.name: GetOsAccountUidByUserId_004
 * @tc.desc: Return SOFTBUS_OK and verify accountInfo matches expected UID when GetOsAccountDistributedInfo succeeds
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetOsAccountUidByUserId_004, TestSize.Level0)
{
    int32_t userId = 123456;
    uint32_t idLen = 10;
    uint32_t len = 0;
    char *accountInfo = (char *)SoftBusCalloc(ACCOUNT_UID_STR_LEN);
    ASSERT_NE(accountInfo, nullptr);
    OHOS::AccountSA::OhosAccountInfo oh_acc_info;
    oh_acc_info.uid_ = "1234567890";
    OHOS::AccountSA::OhosAccountKitsMock mock;
    EXPECT_CALL(mock, GetOsAccountDistributedInfo(userId, testing::_))
        .WillOnce(testing::DoAll(testing::SetArgReferee<1>(oh_acc_info), testing::Return(OHOS::ERR_OK)));
    int32_t ret = GetOsAccountUidByUserId(accountInfo, idLen, &len, userId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_STREQ(accountInfo, "1234567890");

    if (accountInfo != nullptr) {
        SoftBusFree(accountInfo);
    }
}

/*
 * @tc.name: GetOsAccountUidByUserId_005
 * @tc.desc: Return SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED when idLen is too small to hold the UID
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetOsAccountUidByUserId_005, TestSize.Level0)
{
    int32_t userId = 123456;
    uint32_t idLen = 5;
    uint32_t len = 0;
    char *accountInfo = (char *)SoftBusCalloc(ACCOUNT_UID_STR_LEN);
    ASSERT_NE(accountInfo, nullptr);

    OHOS::AccountSA::OhosAccountInfo oh_acc_info;
    oh_acc_info.uid_ = "1234567890";
    std::pair<bool, OHOS::AccountSA::OhosAccountInfo> oh_acc_info_pair = { true, oh_acc_info };
    OHOS::AccountSA::OhosAccountKitsMock mock;

    EXPECT_CALL(mock, GetOsAccountDistributedInfo(userId, testing::_))
        .WillOnce(testing::Return(OHOS::ERR_OK));
    EXPECT_EQ(GetOsAccountUidByUserId(accountInfo, idLen, &len, userId), SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED);

    if (accountInfo != nullptr) {
        SoftBusFree(accountInfo);
    }
}

/*
 * @tc.name: GetOsAccountUidByUserId_006
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when accountInfo buffer is nullptr idLen is 0 and Ohos account name is empty
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetOsAccountUidByUserId_006, TestSize.Level0)
{
    char *accountInfo = nullptr;
    uint32_t idLen = 0;
    uint32_t len = 0;
    uint32_t userId = 1001;

    OHOS::AccountSA::OhosAccountInfo oh_acc_info;
    oh_acc_info.name_ = "";
    std::pair<bool, OHOS::AccountSA::OhosAccountInfo> oh_acc_info_pair = { false, oh_acc_info };
    EXPECT_EQ(GetOsAccountUidByUserId(accountInfo, idLen, &len, userId),
        SOFTBUS_INVALID_PARAM);

    if (accountInfo != nullptr) {
        SoftBusFree(accountInfo);
    }
}

/*
 * @tc.name: GET_OS_ACCOUNT_UID_BY_USER_ID_001
 * @tc.desc: Return SOFTBUS_INVALID_PARAM when accountInfo buffer is nullptr idLen is 0
 *           and Ohos account name is default account name
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GET_OS_ACCOUNT_UID_BY_USER_ID_001, TestSize.Level0)
{
    char *accountInfo = nullptr;
    uint32_t idLen = 0;
    uint32_t len = 0;
    uint32_t userId = 1001;
    
    OHOS::AccountSA::OhosAccountInfo oh_acc_info;
    oh_acc_info.name_ = DEFAULT_ACCOUNT_NAME;
    std::pair<bool, OHOS::AccountSA::OhosAccountInfo> oh_acc_info_pair = { false, oh_acc_info };
    EXPECT_EQ(GetOsAccountUidByUserId(accountInfo, idLen, &len, userId),
        SOFTBUS_INVALID_PARAM);

    if (accountInfo != nullptr) {
        SoftBusFree(accountInfo);
    }
}

/*
 * @tc.name: GET_OS_ACCOUNT_UID_BY_USER_ID_002
 * @tc.desc: Return SOFTBUS_INVALID_PARAM for multiple invalid parameter combinations
 *           null buffer zero idLen null len pointer zero userId
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GET_OS_ACCOUNT_UID_BY_USER_ID_002, TestSize.Level0)
{
    char *accountInfo = static_cast<char*>(SoftBusCalloc(LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN));
    ASSERT_NE(accountInfo, nullptr);
    uint32_t idLen = LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN;
    uint32_t len = 0;
    uint32_t userId = 1001;
    
    OHOS::AccountSA::OhosAccountInfo oh_acc_info;
    oh_acc_info.uid_ = "123456789";
    OHOS::AccountSA::OhosAccountKitsMock mock;

    EXPECT_CALL(mock, IsSameAccountGroupDevice()).Times(0);

    EXPECT_EQ(GetOsAccountUidByUserId(nullptr, idLen, &len, userId),
        SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(GetOsAccountUidByUserId(accountInfo, 0, &len, userId),
        SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(GetOsAccountUidByUserId(accountInfo, idLen, nullptr, userId),
        SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(GetOsAccountUidByUserId(accountInfo, idLen, &len, 0),
        SOFTBUS_INVALID_PARAM);

    if (accountInfo != nullptr) {
        SoftBusFree(accountInfo);
    }
}
} // namespace OHOS::SoftBus