/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <gtest/gtest.h>
#include <securec.h>
#include <string>

#include "lnn_ohos_account.h"
#include "lnn_ohos_account_mock.h"
#include "lnn_ohos_account_adapter_mock.h"
#include "softbus_common.h"
#include "softbus_error_code.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

using namespace std;
using namespace testing;
using namespace testing::ext;
using ::testing::Return;

namespace OHOS {
class LNNOhosAccountMockTest : public testing::Test {
public:
    static constexpr const char* defaultAccountUid = "ohosAnonymousUid";
    static constexpr const char* defaultUserId = "0";

protected:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void LNNOhosAccountMockTest::SetUpTestCase(void) { }

void LNNOhosAccountMockTest::TearDownTestCase(void) { }

void LNNOhosAccountMockTest::SetUp() { }

void LNNOhosAccountMockTest::TearDown() { }

/*
 * @tc.name: LNN_INIT_OHOS_ACCOUNT_001
 * @tc.desc: Return non-SOFTBUS_OK when SoftBusGenerateStrHash fails with
 *           SOFTBUS_INVALID_PARAM during LnnInitOhosAccount
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountMockTest, LNN_INIT_OHOS_ACCOUNT_001, TestSize.Level1)
{
    NiceMock<LnnOhosAccountInterfaceMock> mocker;

    EXPECT_CALL(mocker, SoftBusGenerateStrHash(_, _, _))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM));

    int32_t ret = LnnInitOhosAccount();
    EXPECT_NE(ret, SOFTBUS_OK);
}

 /*
 * @tc.name: LNN_INIT_OHOS_ACCOUNT_002
 * @tc.desc: Return SOFTBUS_OK when account info is available with successful
 *           GetCurrentAccount LnnGetOhosAccountInfo and GetOsAccountUid calls
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountMockTest, LNN_INIT_OHOS_ACCOUNT_002, TestSize.Level1) {
    NiceMock<LnnOhosAccountInterfaceMock> mocker;
    OHOS::AccountSA::OhosAccountKitsMock mock;
    int64_t* realAccountIdPtr = nullptr;
    
    EXPECT_CALL(mocker, GetCurrentAccount(_))
        .WillOnce(DoAll(
            SaveArg<0>(&realAccountIdPtr),
            Return(SOFTBUS_OK)));
    
    EXPECT_CALL(mocker, LnnGetOhosAccountInfo(_, _))
        .WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mocker, GetOsAccountUid(_, _, _))
        .WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, IsSameAccountGroupDevice()).Times(1)
        .WillOnce(testing::Return(true));
    
    EXPECT_EQ(LnnInitOhosAccount(), SOFTBUS_OK);
}


/*
 * @tc.name: LNN_INIT_OHOS_ACCOUNT_003
 * @tc.desc: Return SOFTBUS_OK when account info is unavailable (LnnGetOhosAccountInfo returns SOFTBUS_ERR)
 *           but other operations succeed
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountMockTest, LNN_INIT_OHOS_ACCOUNT_003, TestSize.Level1)
{
    NiceMock<LnnOhosAccountInterfaceMock> mocker;
    OHOS::AccountSA::OhosAccountKitsMock mock;
    EXPECT_CALL(mocker, LnnGetOhosAccountInfo(_, _))
        .WillOnce(Return(SOFTBUS_ERR));
    EXPECT_CALL(mocker, SoftBusGenerateStrHash(_, _, _))
        .WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mocker, GetCurrentAccount(_))
        .WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mocker, GetOsAccountUid(_, _, _))
        .WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mocker, LnnSetLocalStrInfo(_, _))
        .WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, IsSameAccountGroupDevice()).Times(1)
        .WillOnce(testing::Return(true));
    int32_t result = LnnInitOhosAccount();
    EXPECT_EQ(result, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_INIT_OHOS_ACCOUNT_004
 * @tc.desc: Return SOFTBUS_NETWORK_GENERATE_STR_HASH_ERR when SoftBusGenerateStrHash fails
 *           with SOFTBUS_ERR during LnnInitOhosAccount
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountMockTest, LNN_INIT_OHOS_ACCOUNT_004, TestSize.Level1) {
    NiceMock<LnnOhosAccountInterfaceMock> mocker;

    EXPECT_CALL(mocker, SoftBusGenerateStrHash(_, _, _))
        .WillOnce(Return(SOFTBUS_ERR));

    int32_t result = LnnInitOhosAccount();
    EXPECT_EQ(result, SOFTBUS_NETWORK_GENERATE_STR_HASH_ERR);
}

/*
 * @tc.name: LNN_UPDATE_OHOS_ACCOUNT_001
 * @tc.desc: Return true for LnnIsDefaultOhosAccount when LnnGetLocalByteInfo fails
 *           with SOFTBUS_INVALID_PARAM during LnnUpdateOhosAccount
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountMockTest, LNN_UPDATE_OHOS_ACCOUNT_001, TestSize.Level1)
{
    NiceMock<LnnOhosAccountInterfaceMock> mocker;
    ON_CALL(mocker, LnnGetLocalByteInfo)
        .WillByDefault(Return(SOFTBUS_INVALID_PARAM));
    LnnUpdateOhosAccount(UPDATE_HEARTBEAT);
    bool ret = LnnIsDefaultOhosAccount();
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: LNN_UPDATE_OHOS_ACCOUNT_001
 * @tc.desc: Update account successfully when LnnUpdateOhosAccount is called with UPDATE_ACCOUNT_ONLY reason
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountMockTest, LNN_UPDATE_OHOS_ACCOUNT_002, TestSize.Level1)
{
    NiceMock<LnnOhosAccountInterfaceMock> mocker;
    ON_CALL(mocker, SoftBusGenerateStrHash)
        .WillByDefault(Return(SOFTBUS_INVALID_PARAM));
    ON_CALL(mocker, LnnGetLocalByteInfo)
        .WillByDefault(Return(SOFTBUS_OK));
    LnnUpdateOhosAccount(UPDATE_HEARTBEAT);
    bool ret = LnnIsDefaultOhosAccount();
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: LNN_UPDATE_OHOS_ACCOUNT_003
 * @tc.desc: Use default account UID when GetOsAccountUid fails with SOFTBUS_ERR during LnnUpdateOhosAccount
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountMockTest, LNN_UPDATE_OHOS_ACCOUNT_003, TestSize.Level1) {
    NiceMock<LnnOhosAccountInterfaceMock> mocker;
    OHOS::AccountSA::OhosAccountKitsMock mock;
    EXPECT_CALL(mocker, LnnGetLocalByteInfo(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mocker, LnnGetLocalNumInfo(_, _))
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    LnnUpdateOhosAccount(UPDATE_ACCOUNT_ONLY);
}

/*
 * @tc.name: LNN_UPDATE_OHOS_ACCOUNT_004
 * @tc.desc: Use default account UID when GetOsAccountUid fails with SOFTBUS_ERR during LnnUpdateOhosAccount
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountMockTest, LNN_UPDATE_OHOS_ACCOUNT_004, TestSize.Level1) {
    NiceMock<LnnOhosAccountInterfaceMock> mocker;
    OHOS::AccountSA::OhosAccountKitsMock mock;
    
    EXPECT_CALL(mocker, GetOsAccountUid(_, _, _))
        .WillOnce(Return(SOFTBUS_ERR));
    
    const char* expectedUid = defaultAccountUid;
    EXPECT_CALL(mocker, LnnSetLocalStrInfo(
        STRING_KEY_ACCOUNT_UID,
        StrEq(expectedUid)))
        .WillOnce(Return(SOFTBUS_OK));
    
    char actualUid[ACCOUNT_UID_STR_LEN] = {0};
    ON_CALL(mocker, LnnGetLocalStrInfo(STRING_KEY_ACCOUNT_UID, _, _))
        .WillByDefault(DoAll(
            SetArrayArgument<1>(expectedUid, expectedUid + strlen(expectedUid) + 1),
            Return(SOFTBUS_OK)));
    
    EXPECT_CALL(mock, IsSameAccountGroupDevice()).Times(1).WillOnce(testing::Return(true));
    EXPECT_EQ(LnnInitOhosAccount(), SOFTBUS_OK);
    
    mocker.LnnGetLocalStrInfo(STRING_KEY_ACCOUNT_UID, actualUid, ACCOUNT_UID_STR_LEN);
    EXPECT_STREQ(actualUid, expectedUid);
}

/*
 * @tc.name: LNN_UPDATE_OHOS_ACCOUNT_006
 * @tc.desc: Not update account when account hash remains unchanged during
 *           LnnUpdateOhosAccount with UPDATE_ACCOUNT_ONLY reason
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountMockTest, LNN_UPDATE_OHOS_ACCOUNT_006, TestSize.Level1)
{
    NiceMock<LnnOhosAccountInterfaceMock> mocker;
    uint8_t mockHash[SHA_256_HASH_LEN];
    memset_s(mockHash, SHA_256_HASH_LEN, 0x11, SHA_256_HASH_LEN);
    uint8_t finalHash[SHA_256_HASH_LEN] = {0};

    EXPECT_CALL(mocker, LnnGetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, _, _))
        .WillRepeatedly(DoAll(
            SetArrayArgument<1>(mockHash, mockHash + SHA_256_HASH_LEN),
            Return(SOFTBUS_OK)
        ));
    LnnUpdateOhosAccount(UPDATE_ACCOUNT_ONLY);
    int ret = mocker.LnnGetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, finalHash, SHA_256_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(memcmp(finalHash, mockHash, SHA_256_HASH_LEN), 0);
}

/*
 * @tc.name: LNN_UPDATE_OHOS_ACCOUNT_001
 * @tc.desc: Return false for LnnIsDefaultOhosAccount when SoftBusGenerateStrHash
 *           fails with SOFTBUS_INVALID_PARAM during LnnOnOhosAccountLogout
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountMockTest, LNN_ON_OHOS_ACCOUNT_LOGOUT_001, TestSize.Level1)
{
    NiceMock<LnnOhosAccountInterfaceMock> mocker;
    ON_CALL(mocker, SoftBusGenerateStrHash)
        .WillByDefault(Return(SOFTBUS_INVALID_PARAM));
    LnnOnOhosAccountLogout();
    bool ret = LnnIsDefaultOhosAccount();
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: LNN_ON_OHOS_ACCOUNT_LOGOUT_002
 * @tc.desc: Generate hash and set account hash successfully when LnnOnOhosAccountLogout
 *           is called with successful dependent operations
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountMockTest, LNN_ON_OHOS_ACCOUNT_LOGOUT_002, TestSize.Level1) {
    NiceMock<LnnOhosAccountInterfaceMock> mocker;
    ON_CALL(mocker, LnnSetLocalNum64Info(_, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(mocker, SoftBusGenerateStrHash(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(mocker, LnnSetLocalByteInfo(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(mocker, GetOsAccountUid(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(mocker, LnnSetLocalStrInfo(_, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(mocker, DiscDeviceInfoChanged(_))
        .WillByDefault(Return());
    ON_CALL(mocker, LnnNotifyDeviceInfoChanged(_))
        .WillByDefault(Return());
    ON_CALL(mocker, LnnUpdateHeartbeatInfo(_))
        .WillByDefault(Return());
    LnnOnOhosAccountLogout();
}

/*
 * @tc.name: LNN_ON_OHOS_ACCOUNT_LOGOUT_003
 * @tc.desc: Log error and return when SoftBusGenerateStrHash fails with SOFTBUS_ERR during LnnOnOhosAccountLogout
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountMockTest, LNN_ON_OHOS_ACCOUNT_LOGOUT_003, TestSize.Level1) {
    NiceMock<LnnOhosAccountInterfaceMock> mocker;
    ON_CALL(mocker, LnnSetLocalNum64Info(_, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(mocker, SoftBusGenerateStrHash(_, _, _))
        .WillByDefault(Return(SOFTBUS_INVALID_PARAM));
    LnnOnOhosAccountLogout();
}

/*
 * @tc.name: LNN_ON_OHOS_ACCOUNT_LOGOUT_004
 * @tc.desc: Set default account UID when GetOsAccountUid fails with SOFTBUS_ERR during LnnOnOhosAccountLogout
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountMockTest, LNN_ON_OHOS_ACCOUNT_LOGOUT_004, TestSize.Level1) {
    NiceMock<LnnOhosAccountInterfaceMock> mocker;
    ON_CALL(mocker, LnnSetLocalNum64Info(_, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(mocker, SoftBusGenerateStrHash(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(mocker, LnnSetLocalByteInfo(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(mocker, GetOsAccountUid(_, _, _))
        .WillByDefault(Return(SOFTBUS_INVALID_PARAM));
    ON_CALL(mocker, LnnSetLocalStrInfo(_, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(mocker, DiscDeviceInfoChanged(_))
        .WillByDefault(Return());
    ON_CALL(mocker, LnnNotifyDeviceInfoChanged(_))
        .WillByDefault(Return());
    ON_CALL(mocker, LnnUpdateHeartbeatInfo(_))
        .WillByDefault(Return());
    LnnOnOhosAccountLogout();
}

/*
 * @tc.name: LNN_IS_DEFAULT_OHOS_ACCOUNT_001
 * @tc.desc: Return true for LnnIsDefaultOhosAccount when LnnGetLocalByteInfo fails with SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountMockTest, LNN_IS_DEFAULT_OHOS_ACCOUNT_001, TestSize.Level1)
{
    NiceMock<LnnOhosAccountInterfaceMock> mocker;
    ON_CALL(mocker, LnnGetLocalByteInfo)
        .WillByDefault(Return(SOFTBUS_INVALID_PARAM));
    bool ret = LnnIsDefaultOhosAccount();
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: LNN_IS_DEFAULT_OHOS_ACCOUNT_001
 * @tc.desc: Return false for LnnIsDefaultOhosAccount when SoftBusGenerateStrHash fails with SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountMockTest, LNN_IS_DEFAULT_OHOS_ACCOUNT_002, TestSize.Level1)
{
    NiceMock<LnnOhosAccountInterfaceMock> mocker;
    ON_CALL(mocker, LnnGetLocalByteInfo)
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(mocker, SoftBusGenerateStrHash)
        .WillByDefault(Return(SOFTBUS_INVALID_PARAM));
    bool ret = LnnIsDefaultOhosAccount();
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: LNN_JUDGE_DEVICE_TYPE_AND_GET_OHOS_ACCOUNT_INFO_001
 * @tc.desc: Return SOFTBUS_OK for LnnJudgeDeviceTypeAndGetOsAccountInfo
 *           on multiple calls with valid hash buffer and length
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountMockTest, LNN_JUDGE_DEVICE_TYPE_AND_GET_OHOS_ACCOUNT_INFO_001, TestSize.Level1)
{
    NiceMock<LnnOhosAccountInterfaceMock> mocker;
    uint8_t mockHash[SHA_256_HASH_LEN];
    int32_t ret = LnnJudgeDeviceTypeAndGetOsAccountInfo(mockHash, SHA_256_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnJudgeDeviceTypeAndGetOsAccountInfo(mockHash, SHA_256_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
 
/*
 * @tc.name: LNN_JUDGE_DEVICE_TYPE_AND_GET_OHOS_ACCOUNT_INFO_002
 * @tc.desc: Return SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED on first call and SOFTBUS_OK on
 *           second when LnnGetOhosAccountInfo first fails then succeeds
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNOhosAccountMockTest, LNN_JUDGE_DEVICE_TYPE_AND_GET_OHOS_ACCOUNT_INFO_002, TestSize.Level1)
{
    NiceMock<LnnOhosAccountInterfaceMock> mocker;
    uint8_t mockHash[SHA_256_HASH_LEN];
    EXPECT_CALL(mocker, LnnGetOhosAccountInfo(_, _))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM)).
        WillOnce(Return(SOFTBUS_OK));
    int32_t ret = LnnJudgeDeviceTypeAndGetOsAccountInfo(mockHash, SHA_256_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_ACCOUNT_INFO_FAILED);
    ret = LnnJudgeDeviceTypeAndGetOsAccountInfo(mockHash, SHA_256_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
} // namespace OHOS