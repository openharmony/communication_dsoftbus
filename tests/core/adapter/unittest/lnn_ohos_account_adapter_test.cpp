/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"
#include <gmock/gmock-actions.h>

#include "lnn_ohos_account_adapter.h"
#include "lnn_ohos_account_adapter_mock.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

using namespace std;
using namespace testing::ext;

namespace OHOS::SoftBus {
#define DEFAULT_ACCOUNT_NAME "ohosAnonymousName"

constexpr char LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN = 10;

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

/**
 * @tc.name: GetOsAccountId_001
 * @tc.desc:  GetOsAccountId
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetOsAccountId_001, TestSize.Level1)
{
    uint32_t len = 0;
    char *accountInfo = (char *)malloc(LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN * HEXIFY_UNIT_LEN);
    EXPECT_EQ(GetOsAccountId(nullptr, LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN, &len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(GetOsAccountId(accountInfo, 0, &len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(GetOsAccountId(accountInfo, LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN, nullptr), SOFTBUS_INVALID_PARAM);
    free(accountInfo);
}

/**
 * @tc.name: GetOsAccountId_002
 * @tc.desc:  GetOsAccountId
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetOsAccountId_002, TestSize.Level1)
{
    uint32_t len = 0;
    char *accountInfo = (char *)malloc(LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN * HEXIFY_UNIT_LEN);
    AccountSA::OhosAccountKitsMock mock;
    EXPECT_CALL(mock, IsSameAccountGroupDevice()).Times(1).WillOnce(testing::Return(false));
    EXPECT_EQ(GetOsAccountId(accountInfo, LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN, &len), SOFTBUS_AUTH_INNER_ERR);
    free(accountInfo);
}

/**
 * @tc.name: GetOsAccountId_003
 * @tc.desc:  GetOsAccountId
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetOsAccountId_003, TestSize.Level1)
{
    char *accountInfo = (char *)malloc(LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN * HEXIFY_UNIT_LEN);
    uint32_t len = 0;
    OHOS::AccountSA::OhosAccountInfo oh_acc_info;
    std::pair<bool, OHOS::AccountSA::OhosAccountInfo> oh_acc_info_pair = { false, oh_acc_info };
    AccountSA::OhosAccountKitsMock mock;
    EXPECT_CALL(mock, IsSameAccountGroupDevice()).Times(1).WillOnce(testing::Return(true));
    EXPECT_CALL(mock, QueryOhosAccountInfo()).Times(1).WillOnce(testing::Return(oh_acc_info_pair));
    EXPECT_EQ(GetOsAccountId(accountInfo, LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN, &len),
        SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED);
    free(accountInfo);
}

/**
 * @tc.name: GetOsAccountId_004
 * @tc.desc:  GetOsAccountId
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetOsAccountId_004, TestSize.Level1)
{
    char *accountInfo = (char *)malloc(LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN * HEXIFY_UNIT_LEN);
    uint32_t len = 0;
    OHOS::AccountSA::OhosAccountInfo oh_acc_info;
    oh_acc_info.name_ = "";
    std::pair<bool, OHOS::AccountSA::OhosAccountInfo> oh_acc_info_pair = { true, oh_acc_info };
    OHOS::AccountSA::OhosAccountKitsMock mock;
    EXPECT_CALL(mock, IsSameAccountGroupDevice()).Times(1).WillOnce(testing::Return(true));
    EXPECT_CALL(mock, QueryOhosAccountInfo()).Times(1).WillOnce(testing::Return(oh_acc_info_pair));
    EXPECT_EQ(GetOsAccountId(accountInfo, LNN_OHOS_ACCOUNT_ADAPTER_TEST_ID_LEN, &len),
        SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED);

    free(accountInfo);
}

/**
 * @tc.name: GetCurrentAccount_001
 * @tc.desc:  GetCurrentAccount
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetCurrentAccount_001, TestSize.Level1)
{
    int64_t account = 10;
    EXPECT_EQ(GetCurrentAccount(nullptr), SOFTBUS_INVALID_PARAM);
    OHOS::AccountSA::OhosAccountKitsMock mock;
    EXPECT_CALL(mock, IsSameAccountGroupDevice()).Times(1).WillOnce(testing::Return(false));
    EXPECT_EQ(GetCurrentAccount(&account), SOFTBUS_AUTH_INNER_ERR);
}

/**
 * @tc.name: GetCurrentAccount_002
 * @tc.desc:  GetCurrentAccount
 * @tc.type: FUN
 * @tc.require: 1
 */
HWTEST_F(LnnOhosAccountAdapterTest, GetCurrentAccount_002, TestSize.Level1)
{
    int64_t account = 10;
    OHOS::AccountSA::OhosAccountInfo oh_acc_info;
    std::pair<bool, OHOS::AccountSA::OhosAccountInfo> oh_acc_info_pair = { false, oh_acc_info };
    OHOS::AccountSA::OhosAccountKitsMock mock;
    EXPECT_CALL(mock, IsSameAccountGroupDevice()).Times(1).WillOnce(testing::Return(true));
    EXPECT_CALL(mock, QueryOhosAccountInfo()).Times(1).WillOnce(testing::Return(oh_acc_info_pair));
    EXPECT_EQ(GetCurrentAccount(&account), SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED);
}

/**
 * @tc.name: GetCurrentAccount_003
 * @tc.desc: GetCurrentAccount
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
    EXPECT_CALL(mock, IsSameAccountGroupDevice()).Times(1).WillOnce(testing::Return(true));
    EXPECT_CALL(mock, QueryOhosAccountInfo()).Times(1).WillOnce(testing::Return(oh_acc_info_pair));
    EXPECT_EQ(GetCurrentAccount(&account), SOFTBUS_OK);
}

/**
 * @tc.name: GetCurrentAccount_004
 * @tc.desc: GetCurrentAccount
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
    EXPECT_CALL(mock, IsSameAccountGroupDevice()).Times(1).WillOnce(testing::Return(true));
    EXPECT_CALL(mock, QueryOhosAccountInfo()).Times(1).WillOnce(testing::Return(oh_acc_info_pair));
    EXPECT_EQ(GetCurrentAccount(&account), SOFTBUS_OK);
}

/**
 * @tc.name: GetCurrentAccount_005
 * @tc.desc: GetCurrentAccount
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
    EXPECT_CALL(mock, IsSameAccountGroupDevice()).Times(1).WillOnce(testing::Return(true));
    EXPECT_CALL(mock, QueryOhosAccountInfo()).Times(1).WillOnce(testing::Return(oh_acc_info_pair));
    EXPECT_EQ(GetCurrentAccount(&account), SOFTBUS_OK);
}

/**
 * @tc.name: GetCurrentAccount_006
 * @tc.desc:  GetCurrentAccount
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
    EXPECT_CALL(mock, IsSameAccountGroupDevice()).Times(1).WillOnce(testing::Return(true));
    EXPECT_CALL(mock, QueryOhosAccountInfo()).Times(1).WillOnce(testing::Return(oh_acc_info_pair));
    EXPECT_EQ(GetCurrentAccount(&account), SOFTBUS_OK);
}
} // namespace OHOS::SoftBus