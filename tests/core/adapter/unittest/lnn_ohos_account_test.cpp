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
#include <gtest/gtest.h>
#include <string>
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "lnn_ohos_account.h"
#include "lnn_ohos_account_mock.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

using namespace std;
using namespace testing;
using namespace testing::ext;
using ::testing::Return;

namespace OHOS {
class LNNOhosAccountTest : public testing::Test {
protected:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void LNNOhosAccountTest::SetUpTestCase(void)
{
}

void LNNOhosAccountTest::TearDownTestCase(void)
{
}

void LNNOhosAccountTest::SetUp()
{
}

void LNNOhosAccountTest::TearDown()
{
}

/**
 * @tc.name: LNN_GET_OHOS_ACCOUNT_INFO_001
 * @tc.desc: test accountHash == nullptr || len != SHA_256_HASH_LEN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountTest, LNN_GET_OHOS_ACCOUNT_INFO_001, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    ret = LnnGetOhosAccountInfo(nullptr, SHA_256_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    
    uint8_t accountHash[SHA_256_HASH_LEN-1] = {0};
    ret = LnnGetOhosAccountInfo(accountHash, SHA_256_HASH_LEN-1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: LNN_GET_OHOS_ACCOUNT_INFO_002
 * @tc.desc: test SoftBusGenerateStrHash return not ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountTest, LNN_GET_OHOS_ACCOUNT_INFO_002, TestSize.Level1)
{
    LnnOhosAccountInterfaceMock mocker;
    uint8_t accountHash[SHA_256_HASH_LEN] = {0};
    int32_t ret = SOFTBUS_OK;
    EXPECT_CALL(mocker, SoftBusGenerateStrHash).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnGetOhosAccountInfo(accountHash, SHA_256_HASH_LEN);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/**
 * @tc.name: LNN_GET_OHOS_ACCOUNT_INFO_003
 * @tc.desc: test LnnGetOhosAccountInfo return success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountTest, LNN_GET_OHOS_ACCOUNT_INFO_003, TestSize.Level1)
{
    LnnOhosAccountInterfaceMock mocker;
    uint8_t accountHash[SHA_256_HASH_LEN] = {0};
    int32_t ret = SOFTBUS_OK;
    EXPECT_CALL(mocker, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));

    EXPECT_CALL(mocker, GetOsAccountId).WillOnce(Return(SOFTBUS_OK));

    ret = LnnGetOhosAccountInfo(accountHash, SHA_256_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: LNN_INIT_OHOS_ACCOUNT
 * @tc.desc: InitOhosAccount generate default str hash fail.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountTest, LNN_INIT_OHOS_ACCOUNT, TestSize.Level1)
{
    LnnOhosAccountInterfaceMock mocker;
    int32_t ret = SOFTBUS_OK;
    EXPECT_CALL(mocker, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnInitOhosAccount();
    EXPECT_NE(ret, SOFTBUS_OK);
}

/**
 * @tc.name: LNN_UPDATE_OHOS_ACCOUNT_001
 * @tc.desc: OnAccountChanged get local account hash fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountTest, LNN_UPDATE_OHOS_ACCOUNT_001, TestSize.Level1)
{
    NiceMock <LnnOhosAccountInterfaceMock> mocker;
    ON_CALL(mocker, LnnGetLocalByteInfo).WillByDefault(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(mocker, SoftBusGenerateStrHash).Times(0);
    LnnUpdateOhosAccount(true);
    bool ret = LnnIsDefaultOhosAccount();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: LNN_UPDATE_OHOS_ACCOUNT_001
 * @tc.desc:  generate default str hash fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountTest, LNN_UPDATE_OHOS_ACCOUNT_002, TestSize.Level1)
{
    NiceMock <LnnOhosAccountInterfaceMock> mocker;
    ON_CALL(mocker, SoftBusGenerateStrHash).WillByDefault(Return(SOFTBUS_INVALID_PARAM));
    ON_CALL(mocker, LnnGetLocalByteInfo).WillByDefault(Return(SOFTBUS_OK));
    EXPECT_CALL(mocker, UpdateRecoveryDeviceInfoFromDb).Times(0);
    LnnUpdateOhosAccount(true);
    bool ret = LnnIsDefaultOhosAccount();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: LNN_UPDATE_OHOS_ACCOUNT_001
 * @tc.desc:  generate default str hash fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountTest, LNN_ON_OHOS_ACCOUNT_LOGOUT_001, TestSize.Level1)
{
    NiceMock <LnnOhosAccountInterfaceMock> mocker;
    ON_CALL(mocker, SoftBusGenerateStrHash).WillByDefault(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(mocker, UpdateRecoveryDeviceInfoFromDb).Times(0);
    LnnOnOhosAccountLogout();
    bool ret = LnnIsDefaultOhosAccount();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: LNN_IS_DEFAULT_OHOS_ACCOUNT_001
 * @tc.desc:  get local accountHash fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountTest, LNN_IS_DEFAULT_OHOS_ACCOUNT_001, TestSize.Level1)
{
    NiceMock <LnnOhosAccountInterfaceMock> mocker;
    ON_CALL(mocker, LnnGetLocalByteInfo).WillByDefault(Return(SOFTBUS_INVALID_PARAM));
    bool ret = LnnIsDefaultOhosAccount();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: LNN_IS_DEFAULT_OHOS_ACCOUNT_001
 * @tc.desc:  generate default str hash fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountTest, LNN_IS_DEFAULT_OHOS_ACCOUNT_002, TestSize.Level1)
{
    NiceMock <LnnOhosAccountInterfaceMock> mocker;
    ON_CALL(mocker, LnnGetLocalByteInfo).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(mocker, SoftBusGenerateStrHash).WillByDefault(Return(SOFTBUS_INVALID_PARAM));
    bool ret = LnnIsDefaultOhosAccount();
    EXPECT_FALSE(ret);
}
}
