/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "auth_device_profile_mock.h"
#include "auth_deviceprofile.cpp"
#include "lnn_app_bind_interface.h"
#include "softbus_error_code.h"
#include "trust_device_profile.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;
const int64_t TEST_ACCOUNT_ID = 123456789;
const int32_t TEST_SESSION_KEY_ID = 1;
const int32_t TEST_LOCAL_USER_ID = 100;
const char TEST_UDID[] = "1234567890";
const char TEST_UDID_HASH[] = "abcd";
const int32_t TEST_SOURCE_USER_ID = 1;
const int32_t TEST_SINK_USER_ID = 2;
const int64_t TEST_SOURCE_TOKEN_ID = 3;
const int64_t TEST_SINK_TOKEN_ID = 4;
const int32_t TEST_USER_ID_ONE = 1;
const int32_t TEST_USER_ID_TWO = 2;
const int32_t TEST_USER_ID_THREE = 3;
const uint32_t TEST_ERROR_USER_ID = -1;
const uint32_t CRED_ID_STR_LEN = 300;

typedef struct {
    bool isLocal;
    int32_t userId;
    char udid[UDID_BUF_LEN];
    char credId[CRED_ID_STR_LEN];
    char shareCredId[CRED_ID_STR_LEN];
    char accountUid[ACCOUNT_UID_STR_LEN];
} SoftBusAclInfo;

class AuthDeviceProfileTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    int32_t SetAclInfo(AuthACLInfo *aclInfo);
    int32_t SetSoftBusAclInfo(SoftBusAclInfo *info, int32_t userId);
};

void AuthDeviceProfileTest::SetUpTestCase() { }

void AuthDeviceProfileTest::TearDownTestCase() { }

void AuthDeviceProfileTest::SetUp() { }

void AuthDeviceProfileTest::TearDown() { }

int32_t AuthDeviceProfileTest::SetAclInfo(AuthACLInfo *aclInfo)
{
    if (aclInfo == nullptr) {
        AUTH_LOGE(AUTH_TEST, "aclInfo is null.");
        return SOFTBUS_INVALID_PARAM;
    }

    aclInfo->isServer = true;
    aclInfo->sourceUserId = TEST_SOURCE_USER_ID;
    aclInfo->sinkUserId = TEST_SINK_USER_ID;
    aclInfo->sourceTokenId = TEST_SOURCE_TOKEN_ID;
    aclInfo->sinkTokenId = TEST_SINK_TOKEN_ID;
    if (strcpy_s(aclInfo->sourceUdid, UDID_BUF_LEN, "ab") != EOK) {
        AUTH_LOGE(AUTH_TEST, "set sourceUdid fail.");
        return SOFTBUS_STRCPY_ERR;
    }
    if (strcpy_s(aclInfo->sinkUdid, UDID_BUF_LEN, "cd") != EOK) {
        AUTH_LOGE(AUTH_TEST, "set sinkUdid fail.");
        return SOFTBUS_STRCPY_ERR;
    }
    if (strcpy_s(aclInfo->sourceAccountId, ACCOUNT_ID_BUF_LEN, "ef") != EOK) {
        AUTH_LOGE(AUTH_TEST, "set sourceAccountId fail.");
        return SOFTBUS_STRCPY_ERR;
    }
    if (strcpy_s(aclInfo->sinkAccountId, ACCOUNT_ID_BUF_LEN, "gh") != EOK) {
        AUTH_LOGE(AUTH_TEST, "set sinkAccountId fail.");
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

int32_t AuthDeviceProfileTest::SetSoftBusAclInfo(SoftBusAclInfo *info, int32_t userId)
{
    if (info == nullptr) {
        AUTH_LOGE(AUTH_TEST, "info is null.");
        return SOFTBUS_INVALID_PARAM;
    }

    bool isLocal = true;
    std::string udid = "ab";
    std::string credId = "cd";
    std::string shareCredId = "ef";
    std::string accountUid = "gh";
    switch (userId) {
        case TEST_USER_ID_TWO:
            isLocal = false;
            udid = "12";
            credId = "34";
            shareCredId = "56";
            accountUid = "78";
            break;
        case TEST_USER_ID_THREE:
            udid = "ij";
            credId = "kl";
            shareCredId = "mn";
            accountUid = "op";
            break;
        default:
            break;
    }
    info->userId = userId;
    info->isLocal = isLocal;
    if (strcpy_s(info->udid, UDID_BUF_LEN, udid.c_str()) != EOK) {
        AUTH_LOGE(AUTH_TEST, "set udid fail.");
        return SOFTBUS_STRCPY_ERR;
    }
    if (strcpy_s(info->credId, CRED_ID_STR_LEN, credId.c_str()) != EOK) {
        AUTH_LOGE(AUTH_TEST, "set credId fail.");
        return SOFTBUS_STRCPY_ERR;
    }
    if (strcpy_s(info->shareCredId, CRED_ID_STR_LEN, shareCredId.c_str()) != EOK) {
        AUTH_LOGE(AUTH_TEST, "set shareCredId fail.");
        return SOFTBUS_STRCPY_ERR;
    }
    if (strcpy_s(info->accountUid, ACCOUNT_UID_STR_LEN, accountUid.c_str()) != EOK) {
        AUTH_LOGE(AUTH_TEST, "set accountUid fail.");
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

/*
 * @tc.name: IS_POTENTIAL_TRUSTED_DEVCIE_TEST_003
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, IS_POTENTIAL_DEVCIE_TEST_003, TestSize.Level1)
{
    const char *deviceIdHash = nullptr;
    bool ret = IsPotentialTrustedDeviceDp(deviceIdHash, true);
    EXPECT_FALSE(ret);
    deviceIdHash = "dev/ice%Id()Hash()";
    int64_t localAccountId = TEST_ACCOUNT_ID;
    int64_t peerAccountId = TEST_ACCOUNT_ID;
    ret = IsPotentialTrustedDeviceDp(deviceIdHash, true);
    EXPECT_FALSE(ret);
    DumpAccountId(localAccountId, peerAccountId);
}

/*
 * @tc.name: IS_POTENTIAL_TRUSTED_DEVCIE_TEST_004
 * @tc.desc:add ut for DelNotTrustDevice and UpdateDpSameAccount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, IS_POTENTIAL_DEVCIE_TEST_004, TestSize.Level1)
{
    const char *deviceIdHash = nullptr;
    deviceIdHash = "dev/ice%Id()Hash()";
    int32_t peerUserId = -1;
    int64_t accountId = 100;
    SessionKey sessionKey;
    (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
    DelNotTrustDevice(nullptr);
    UpdateDpAclParams aclParams = {
        .accountId = accountId,
        .deviceId = nullptr,
        .peerUserId = peerUserId
    };
    UpdateDpSameAccount(&aclParams, sessionKey, true, ACL_WRITE_DEFAULT);
    bool ret = IsPotentialTrustedDeviceDp(deviceIdHash, true);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: IS_NOT_TRUSTED_DEVCIE_TEST_001
 * @tc.desc: Insert not truste device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, IS_NOT_TRUSTED_DEVCIE_TEST_001, TestSize.Level1)
{
    const char udid[] = "testUdid";
    char hashStr[CUST_UDID_LEN + 1] = { 0 };
    int32_t ret = strcpy_s(hashStr, CUST_UDID_LEN, TEST_UDID_HASH);
    EXPECT_EQ(ret, EOK);
    InsertNotTrustDevice(hashStr);
    bool result = IsNotTrustDevice(hashStr);
    EXPECT_TRUE(result);
    AuthDeviceProfileInterfaceMock mock;
    EXPECT_CALL(mock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConvertBytesToHexString).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    DelNotTrustDevice(udid);
    EXPECT_CALL(mock, ConvertBytesToHexString).WillOnce(Return(SOFTBUS_OK));
    DelNotTrustDevice(udid);
}

/*
 * @tc.name: IS_NOT_TRUSTED_DEVCIE_TEST_002
 * @tc.desc: Do not insert not trust device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, IS_NOT_TRUSTED_DEVCIE_TEST_002, TestSize.Level1)
{
    std::string deviceIdHash = "testDeviceHash";
    std::string peerUdid = "peerUdid";
    int32_t peerUserId = 1;
    int32_t sessionKeyId = 1;
    AuthDeviceProfileInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(mock, SoftBusGetSysTimeMs).WillRepeatedly(Return(0));
    EXPECT_CALL(mock, GetActiveOsAccountIds).WillRepeatedly(Return(TEST_USER_ID_ONE));
    InsertDpSameAccountAcl(peerUdid, peerUserId, sessionKeyId);
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    InsertDpSameAccountAcl(peerUdid, peerUserId, sessionKeyId);
    bool result = IsNotTrustDevice(deviceIdHash);
    EXPECT_FALSE(result);
}

/*
 * @tc.name: GET_ACL_LOCAL_USERID_TEST_001
 * @tc.desc: 1.get accessee userId.2.get accesser userId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, GET_ACL_LOCAL_USERID_TEST_001, TestSize.Level1)
{
    OHOS::DistributedDeviceProfile::AccessControlProfile trustDevice;
    int32_t ret = GetAclLocalUserId(trustDevice);
    EXPECT_EQ(ret, -1);

    std::string deviceId = "abcdef";
    int32_t userId = 6;
    DistributedDeviceProfile::Accessee accessee;
    accessee.SetAccesseeDeviceId(deviceId);
    trustDevice.SetAccessee(accessee);
    DistributedDeviceProfile::Accesser accesser;
    accesser.SetAccesserUserId(userId);
    trustDevice.SetAccesser(accesser);
    trustDevice.SetTrustDeviceId(deviceId);
    ret = GetAclLocalUserId(trustDevice);
    EXPECT_EQ(ret, userId);
}

/*
 * @tc.name: GET_ACL_PEER_USERID_TEST_001
 * @tc.desc: 1.get accessee userId.2.get accesser userId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, GET_ACL_PEER_USERID_TEST_001, TestSize.Level1)
{
    OHOS::DistributedDeviceProfile::AccessControlProfile trustDevice;
    std::string deviceId = "1234567";
    trustDevice.SetTrustDeviceId(deviceId);
    int32_t ret = GetAclPeerUserId(trustDevice);
    EXPECT_EQ(ret, -1);

    deviceId = "abcdef";
    int32_t userId = 6;
    DistributedDeviceProfile::Accessee accessee;
    accessee.SetAccesseeDeviceId(deviceId);
    accessee.SetAccesseeUserId(userId);
    trustDevice.SetAccessee(accessee);
    trustDevice.SetTrustDeviceId(deviceId);
    ret = GetAclPeerUserId(trustDevice);
    EXPECT_EQ(ret, userId);
}

/*
 * @tc.name: GET_STRING_HASH_001
 * @tc.desc: test generate hash fail and success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, GET_STRING_HASH_001, TestSize.Level1)
{
    std::string str = "";
    char hashStrBuf[SHA_256_HEX_HASH_LEN] = { 0 };
    int32_t len = 32;
    AuthDeviceProfileInterfaceMock mock;
    EXPECT_CALL(mock, SoftBusGenerateStrHash).WillOnce(Return(SOFTBUS_ENCRYPT_ERR));
    int32_t ret = GetStringHash(str, hashStrBuf, len);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GENERATE_STR_HASH_ERR);
    EXPECT_CALL(mock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConvertBytesToHexString).WillOnce(Return(SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR));
    ret = GetStringHash(str, hashStrBuf, len);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR);
    EXPECT_CALL(mock, ConvertBytesToHexString).WillOnce(Return(SOFTBUS_OK));
    str = "abcdef123456";
    ret = GetStringHash(str, hashStrBuf, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: DP_HAS_ACCESS_CONTROL_PROFILE_TEST_001
 * @tc.desc: udid is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, DP_HAS_ACCESS_CONTROL_PROFILE_TEST_001, TestSize.Level1)
{
    bool result = DpHasAccessControlProfile(nullptr, false, 0);
    EXPECT_FALSE(result);
}

/*
 * @tc.name: DP_HAS_ACCESS_CONTROL_PROFILE_TEST_002
 * @tc.desc: aclProfiles is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, DP_HAS_ACCESS_CONTROL_PROFILE_TEST_002, TestSize.Level1)
{
    const char udid[] = "testUdid";
    bool result = DpHasAccessControlProfile(udid, false, 0);
    EXPECT_FALSE(result);
    result = DpHasAccessControlProfile(udid, true, 0);
    EXPECT_FALSE(result);
}

/*
 * @tc.name: IS_SAME_ACCOUNT_TEST_001
 * @tc.desc: LnnGetLocalNum64Info fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, IS_SAME_ACCOUNT_TEST_001, TestSize.Level1)
{
    AuthDeviceProfileInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetLocalNum64Info).WillOnce(Return(SOFTBUS_NETWORK_NOT_FOUND));
    bool result = IsSameAccount(TEST_ACCOUNT_ID);
    EXPECT_FALSE(result);
}

/*
 * @tc.name: IS_SAME_ACCOUNT_TEST_002
 * @tc.desc: accountId does not equal localAccountId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, IS_SAME_ACCOUNT_TEST_002, TestSize.Level1)
{
    int64_t accountId = TEST_ACCOUNT_ID;
    AuthDeviceProfileInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetLocalNum64Info).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetLocalNum64Info).WillOnce(DoAll(SetArgPointee<1>(TEST_ACCOUNT_ID + 1), Return(SOFTBUS_OK)));
    bool result = IsSameAccount(accountId);
    EXPECT_FALSE(result);
    OHOS::DistributedDeviceProfile::AccessControlProfile trustDevices;
    std::string peerUdid = TEST_UDID;
    int32_t localUserId = TEST_LOCAL_USER_ID;
    int32_t peerUserId = TEST_SOURCE_USER_ID;
    DumpDpAclInfo(peerUdid, localUserId, peerUserId, trustDevices);
    EXPECT_CALL(mock, LnnGetLocalNum64Info).WillOnce(DoAll(SetArgPointee<1>(TEST_ACCOUNT_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnIsDefaultOhosAccount).WillOnce(Return(false));
    result = IsSameAccount(accountId);
    EXPECT_TRUE(result);
}

/*
 * @tc.name: IS_SAME_ACCOUNT_TEST_003
 * @tc.desc: accountId is default ohos account
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, IS_SAME_ACCOUNT_TEST_003, TestSize.Level1)
{
    int64_t accountId = TEST_ACCOUNT_ID;
    AuthDeviceProfileInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetLocalNum64Info).WillRepeatedly(DoAll(SetArgPointee<1>(TEST_ACCOUNT_ID),
        Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnIsDefaultOhosAccount).WillOnce(Return(false));
    bool result = IsSameAccount(accountId);
    EXPECT_TRUE(result);
}

/*
 * @tc.name: GET_SESSION_KEY_PROFILE_TEST_001
 * @tc.desc: sessionKey is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, GET_SESSION_KEY_PROFILE_TEST_001, TestSize.Level1)
{
    uint32_t length = 0;
    bool result = GetSessionKeyProfile(TEST_SESSION_KEY_ID, nullptr, &length);
    EXPECT_FALSE(result);
}

/*
 * @tc.name: GET_SESSION_KEY_PROFILE_TEST_002
 * @tc.desc: length is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, GET_SESSION_KEY_PROFILE_TEST_002, TestSize.Level1)
{
    uint8_t sessionKey = 0;
    bool result = GetSessionKeyProfile(TEST_SESSION_KEY_ID, &sessionKey, nullptr);
    EXPECT_FALSE(result);
}

/*
 * @tc.name: GET_SESSION_KEY_PROFILE_TEST_003
 * @tc.desc: GetActiveOsAccountIds fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, GET_SESSION_KEY_PROFILE_TEST_003, TestSize.Level1)
{
    uint8_t sessionKey = 0;
    uint32_t length = 0;
    AuthDeviceProfileInterfaceMock mock;
    EXPECT_CALL(mock, GetActiveOsAccountIds).WillOnce(Return(TEST_ERROR_USER_ID));
    bool result = GetSessionKeyProfile(TEST_SESSION_KEY_ID, &sessionKey, &length);
    EXPECT_FALSE(result);
    EXPECT_CALL(mock, GetActiveOsAccountIds).WillRepeatedly(Return(TEST_USER_ID_ONE));
    result = GetSessionKeyProfile(TEST_SESSION_KEY_ID, &sessionKey, &length);
    EXPECT_FALSE(result);
}

/*
 * @tc.name: UPDATE_DP_SAME_ACCOUNT_ACL_TEST_001
 * @tc.desc: sessionKey is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, UPDATE_DP_SAME_ACCOUNT_ACL_TEST_001, TestSize.Level1)
{
    std::string peerUdid = TEST_UDID;
    int32_t peerUserId = TEST_LOCAL_USER_ID;
    int32_t sessionKeyId = TEST_SESSION_KEY_ID;
    int32_t ret = UpdateDpSameAccountAcl(peerUdid, 0, sessionKeyId);
    EXPECT_EQ(ret, GET_ALL_ACL_FAIL);
    ret = UpdateDpSameAccountAcl(peerUdid, peerUserId, peerUserId, sessionKeyId);
    EXPECT_EQ(ret, GET_ALL_ACL_FAIL);
}

/*
 * @tc.name: IS_TRUST_DEVICE_TEST_001
 * @tc.desc: device is not trusted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, IS_TRUST_DEVICE_TEST_001, TestSize.Level1)
{
    std::vector<OHOS::DistributedDeviceProfile::AccessControlProfile> trustDevices;
    const char *deviceIdHash = "deviceIdHash";
    const char *anonyDeviceIdHash = "anonyDeviceIdHash";
    bool isOnlyPointToPoint = true;
    AuthDeviceProfileInterfaceMock mock;
    EXPECT_CALL(mock, GetActiveOsAccountIds).WillRepeatedly(Return(TEST_USER_ID_ONE));
    EXPECT_CALL(mock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConvertBytesToHexString).WillRepeatedly(Return(SOFTBUS_OK));
    bool result = IsTrustDevice(trustDevices, deviceIdHash, anonyDeviceIdHash, isOnlyPointToPoint);
    EXPECT_FALSE(result);

    OHOS::DistributedDeviceProfile::AccessControlProfile aclProfile0;
    uint32_t bindType = (uint32_t)OHOS::DistributedDeviceProfile::BindType::SAME_ACCOUNT;
    aclProfile0.SetBindType(bindType);
    OHOS::DistributedDeviceProfile::AccessControlProfile aclProfile1;
    bindType = (uint32_t)OHOS::DistributedDeviceProfile::BindType::SHARE;
    aclProfile1.SetBindType(bindType);
    uint32_t deviceIdType = (uint32_t)OHOS::DistributedDeviceProfile::DeviceIdType::UUID;
    aclProfile1.SetDeviceIdType(deviceIdType);
    OHOS::DistributedDeviceProfile::AccessControlProfile aclProfile2;
    aclProfile2.SetBindType(bindType);
    deviceIdType = (uint32_t)OHOS::DistributedDeviceProfile::DeviceIdType::UDID;
    aclProfile2.SetDeviceIdType(deviceIdType);
    OHOS::DistributedDeviceProfile::AccessControlProfile aclProfile3;
    aclProfile3.SetBindType(bindType);
    aclProfile3.SetDeviceIdType(deviceIdType);
    std::string deviceId = "1234567";
    aclProfile3.SetTrustDeviceId(deviceId);
    int status = (uint32_t)OHOS::DistributedDeviceProfile::Status::INACTIVE;
    aclProfile3.SetStatus(status);
    OHOS::DistributedDeviceProfile::AccessControlProfile aclProfile4;
    aclProfile4.SetBindType(bindType);
    aclProfile4.SetDeviceIdType(deviceIdType);
    aclProfile4.SetTrustDeviceId(deviceId);
    status = (uint32_t)OHOS::DistributedDeviceProfile::Status::ACTIVE;
    aclProfile4.SetStatus(status);
    trustDevices.push_back(aclProfile0);
    trustDevices.push_back(aclProfile1);
    trustDevices.push_back(aclProfile2);
    trustDevices.push_back(aclProfile3);
    trustDevices.push_back(aclProfile4);
    result = IsTrustDevice(trustDevices, deviceIdHash, anonyDeviceIdHash, isOnlyPointToPoint);
    EXPECT_FALSE(result);
}

/*
 * @tc.name: IS_TRUST_DEVICE_TEST_002
 * @tc.desc: device is not trusted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, IS_TRUST_DEVICE_TEST_002, TestSize.Level1)
{
    std::vector<OHOS::DistributedDeviceProfile::AccessControlProfile> trustDevices;
    const char *deviceIdHash = "deviceIdHash";
    const char *anonyDeviceIdHash = "anonyDeviceIdHash";
    bool isOnlyPointToPoint = false;
    OHOS::DistributedDeviceProfile::AccessControlProfile aclProfile;
    uint32_t bindType = (uint32_t)OHOS::DistributedDeviceProfile::BindType::SHARE;
    aclProfile.SetBindType(bindType);
    uint32_t deviceIdType = (uint32_t)OHOS::DistributedDeviceProfile::DeviceIdType::UDID;
    aclProfile.SetDeviceIdType(deviceIdType);
    std::string deviceId = "1234567";
    aclProfile.SetTrustDeviceId(deviceId);
    int32_t status = (uint32_t)OHOS::DistributedDeviceProfile::Status::ACTIVE;
    aclProfile.SetStatus(status);
    int32_t userId = 100;
    DistributedDeviceProfile::Accessee accessee;
    accessee.SetAccesseeDeviceId(deviceId);
    aclProfile.SetAccessee(accessee);
    DistributedDeviceProfile::Accesser accesser;
    accesser.SetAccesserUserId(userId);
    aclProfile.SetAccesser(accesser);
    trustDevices.push_back(aclProfile);
    AuthDeviceProfileInterfaceMock mock;
    EXPECT_CALL(mock, GetActiveOsAccountIds).WillRepeatedly(Return(TEST_USER_ID_ONE));
    EXPECT_CALL(mock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConvertBytesToHexString).WillRepeatedly(Return(SOFTBUS_OK));
    bool result = IsTrustDevice(trustDevices, deviceIdHash, anonyDeviceIdHash, isOnlyPointToPoint);
    EXPECT_FALSE(result);
}

/*
 * @tc.name: IS_TRUST_DEVICE_TEST_003
 * @tc.desc: device is trusted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, IS_TRUST_DEVICE_TEST_003, TestSize.Level1)
{
    std::vector<OHOS::DistributedDeviceProfile::AccessControlProfile> trustDevices;
    const char *deviceIdHash = "8bb0cf6eb9b17d0f";
    const char *anonyDeviceIdHash = "anonyDeviceIdHash";
    bool isOnlyPointToPoint = false;
    OHOS::DistributedDeviceProfile::AccessControlProfile aclProfile;
    uint32_t bindType = (uint32_t)OHOS::DistributedDeviceProfile::BindType::SHARE;
    aclProfile.SetBindType(bindType);
    uint32_t deviceIdType = (uint32_t)OHOS::DistributedDeviceProfile::DeviceIdType::UDID;
    aclProfile.SetDeviceIdType(deviceIdType);
    std::string deviceId = "1234567";
    aclProfile.SetTrustDeviceId(deviceId);
    int32_t status = (uint32_t)OHOS::DistributedDeviceProfile::Status::ACTIVE;
    aclProfile.SetStatus(status);
    int32_t userId = 100;
    DistributedDeviceProfile::Accessee accessee;
    accessee.SetAccesseeDeviceId(deviceId);
    aclProfile.SetAccessee(accessee);
    DistributedDeviceProfile::Accesser accesser;
    accesser.SetAccesserUserId(userId);
    aclProfile.SetAccesser(accesser);
    trustDevices.push_back(aclProfile);
    AuthDeviceProfileInterfaceMock mock;
    EXPECT_CALL(mock, GetActiveOsAccountIds).WillRepeatedly(Return(TEST_USER_ID_ONE));
    EXPECT_CALL(mock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConvertBytesToHexString).WillRepeatedly(Return(SOFTBUS_OK));
    bool result = IsTrustDevice(trustDevices, deviceIdHash, anonyDeviceIdHash, isOnlyPointToPoint);
    EXPECT_FALSE(result);
}

/*
 * @tc.name: COMPARE_ACL_WITH_PEER_DEVICE_INFO_TEST_001
 * @tc.desc: LnnGetLocalStrInfo fail.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, COMPARE_ACL_WITH_PEER_DEVICE_INFO_TEST_001, TestSize.Level1)
{
    OHOS::DistributedDeviceProfile::AccessControlProfile aclProfile;
    const char *peerAccountHash = "8bb0cf6eb9b17d0f";
    const char *peerUdid = "1234567890";
    int32_t peerUserId = 1;
    AuthDeviceProfileInterfaceMock mock;
    EXPECT_CALL(mock, GetActiveOsAccountIds).WillRepeatedly(Return(TEST_LOCAL_USER_ID));
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_NETWORK_NOT_FOUND));
    bool result = CompareAclWithPeerDeviceInfo(aclProfile, peerAccountHash, peerUdid, peerUserId);
    EXPECT_FALSE(result);
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetLocalByteInfo).WillOnce(Return(SOFTBUS_NETWORK_NOT_FOUND));
    result = CompareAclWithPeerDeviceInfo(aclProfile, peerAccountHash, peerUdid, peerUserId);
    EXPECT_FALSE(result);
    EXPECT_CALL(mock, LnnGetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConvertBytesToHexString).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    result = CompareAclWithPeerDeviceInfo(aclProfile, peerAccountHash, peerUdid, peerUserId);
    EXPECT_FALSE(result);
}

/*
 * @tc.name: COMPARE_ACL_WITH_PEER_DEVICE_INFO_TEST_002
 * @tc.desc: accountId is default.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, COMPARE_ACL_WITH_PEER_DEVICE_INFO_TEST_002, TestSize.Level1)
{
    AuthDeviceProfileInterfaceMock mock;
    OHOS::DistributedDeviceProfile::AccessControlProfile aclProfile;
    const char *peerAccountHash = "8bb0cf6eb9b17d0f";
    const char *peerUdid = "1234567890";
    int32_t peerUserId = 1;
    std::string accountId = "ohosAnonymousUid";
    DistributedDeviceProfile::Accessee accessee;
    accessee.SetAccesseeAccountId(accountId);
    aclProfile.SetAccessee(accessee);
    DistributedDeviceProfile::Accesser accesser;
    accesser.SetAccesserAccountId(accountId);
    aclProfile.SetAccesser(accesser);
    EXPECT_CALL(mock, GetActiveOsAccountIds).WillRepeatedly(Return(TEST_LOCAL_USER_ID));
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConvertBytesToHexString).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    bool result = CompareAclWithPeerDeviceInfo(aclProfile, peerAccountHash, peerUdid, peerUserId);
    EXPECT_FALSE(result);
    std::string accountId1 = "8bb0cf6eb9b17d0f";
    accessee.SetAccesseeAccountId(accountId);
    aclProfile.SetAccessee(accessee);
    accesser.SetAccesserAccountId(accountId);
    aclProfile.SetAccesser(accesser);
    result = CompareAclWithPeerDeviceInfo(aclProfile, peerAccountHash, peerUdid, peerUserId);
    EXPECT_FALSE(result);
}

/*
 * @tc.name: IS_TRUSTED_DEVICE_FROM_ACCESS_TEST_003
 * @tc.desc: device is trust from access
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, IS_TRUSTED_DEVICE_FROM_ACCESS_TEST_003, TestSize.Level1)
{
    const char *accountHash = nullptr;
    const char *udid = nullptr;
    bool ret = IsTrustedDeviceFromAccess(accountHash, udid, 100);
    EXPECT_EQ(ret, false);
    accountHash = "dev/ice%Id()Hash()";
    udid = "dev/ice%Id()Hash()";
    ret = IsTrustedDeviceFromAccess(accountHash, udid, 100);
    EXPECT_EQ(ret, false);
    int32_t peerUserId = -1;
    int64_t accountId = 100;
    SessionKey sessionKey;
    (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
    DelNotTrustDevice(nullptr);
    UpdateDpAclParams aclParams = {
        .accountId = accountId,
        .deviceId = nullptr,
        .peerUserId = peerUserId
    };
    UpdateDpSameAccount(&aclParams, sessionKey, true, ACL_NOT_WRITE);
    UpdateDpSameAccount(&aclParams, sessionKey, true, ACL_WRITE_DEFAULT);
    ret = IsTrustedDeviceFromAccess(accountHash, udid, 100);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: PUT_DP_ACL_UK_BY_USER_ID_TEST_001
 * @tc.desc: sessionKey or sessionKeyId is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, PUT_DP_ACL_UK_BY_USER_ID_TEST_001, TestSize.Level1)
{
    int32_t userId = 1;
    uint32_t sessionKeyLen = 32;
    UpdateDpAclResult ret = PutDpAclUkByUserId(userId, nullptr, sessionKeyLen, nullptr);
    EXPECT_EQ(ret, GET_ALL_ACL_FAIL);

    uint8_t sessionKey = 2;
    ret = PutDpAclUkByUserId(userId, &sessionKey, sessionKeyLen, nullptr);
    EXPECT_EQ(ret, GET_ALL_ACL_FAIL);
}

/*
 * @tc.name: COMPARE_ASSET_ACL_SAME_ACCOUNT_TEST_001
 * @tc.desc: isSameSide is true.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, COMPARE_ASSET_ACL_SAME_ACCOUNT_TEST_001, TestSize.Level1)
{
    OHOS::DistributedDeviceProfile::AccessControlProfile aclProfile;
    uint32_t bindType = (uint32_t)OHOS::DistributedDeviceProfile::BindType::SHARE;
    aclProfile.SetBindType(bindType);
    AuthACLInfo aclInfo;
    int32_t result = SetAclInfo(&aclInfo);
    ASSERT_EQ(result, SOFTBUS_OK);
    bool isSameSide = true;
    bool ret = CompareAssetAclSameAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    bindType = (uint32_t)OHOS::DistributedDeviceProfile::BindType::SAME_ACCOUNT;
    aclProfile.SetBindType(bindType);
    ret = CompareAssetAclSameAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    DistributedDeviceProfile::Accesser accesser;
    accesser.SetAccesserDeviceId("ab");
    aclProfile.SetAccesser(accesser);
    ret = CompareAssetAclSameAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    DistributedDeviceProfile::Accessee accessee;
    accessee.SetAccesseeDeviceId("cd");
    aclProfile.SetAccessee(accessee);
    ret = CompareAssetAclSameAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    accesser.SetAccesserAccountId("ef");
    aclProfile.SetAccesser(accesser);
    ret = CompareAssetAclSameAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    accessee.SetAccesseeAccountId("gh");
    aclProfile.SetAccessee(accessee);
    ret = CompareAssetAclSameAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: COMPARE_ASSET_ACL_SAME_ACCOUNT_TEST_002
 * @tc.desc: isSameSide is true.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, COMPARE_ASSET_ACL_SAME_ACCOUNT_TEST_002, TestSize.Level1)
{
    OHOS::DistributedDeviceProfile::AccessControlProfile aclProfile;
    uint32_t bindType = (uint32_t)OHOS::DistributedDeviceProfile::BindType::SHARE;
    aclProfile.SetBindType(bindType);
    AuthACLInfo aclInfo;
    int32_t result = SetAclInfo(&aclInfo);
    ASSERT_EQ(result, SOFTBUS_OK);
    bool isSameSide = true;
    bindType = (uint32_t)OHOS::DistributedDeviceProfile::BindType::SAME_ACCOUNT;
    aclProfile.SetBindType(bindType);
    DistributedDeviceProfile::Accesser accesser;
    accesser.SetAccesserDeviceId("ab");
    accesser.SetAccesserAccountId("ef");
    accesser.SetAccesserUserId(1);
    aclProfile.SetAccesser(accesser);
    DistributedDeviceProfile::Accessee accessee;
    accessee.SetAccesseeDeviceId("cd");
    accessee.SetAccesseeAccountId("gh");
    aclProfile.SetAccessee(accessee);
    bool ret = CompareAssetAclSameAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    accessee.SetAccesseeUserId(2);
    aclProfile.SetAccessee(accessee);
    ret = CompareAssetAclSameAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_TRUE(ret);

    accessee.SetAccesseeAccountId("ohosAnonymousUid");
    aclProfile.SetAccessee(accessee);
    result = strcpy_s(aclInfo.sinkAccountId, ACCOUNT_ID_BUF_LEN, "ohosAnonymousUid");
    EXPECT_EQ(result, EOK);
    ret = CompareAssetAclSameAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    accesser.SetAccesserAccountId("ohosAnonymousUid");
    aclProfile.SetAccesser(accesser);
    result = strcpy_s(aclInfo.sourceAccountId, ACCOUNT_ID_BUF_LEN, "ohosAnonymousUid");
    EXPECT_EQ(result, EOK);
    ret = CompareAssetAclSameAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: COMPARE_ASSET_ACL_SAME_ACCOUNT_TEST_003
 * @tc.desc: isSameSide is false.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, COMPARE_ASSET_ACL_SAME_ACCOUNT_TEST_003, TestSize.Level1)
{
    OHOS::DistributedDeviceProfile::AccessControlProfile aclProfile;
    uint32_t bindType = (uint32_t)OHOS::DistributedDeviceProfile::BindType::SAME_ACCOUNT;
    aclProfile.SetBindType(bindType);
    AuthACLInfo aclInfo;
    int32_t result = SetAclInfo(&aclInfo);
    ASSERT_EQ(result, SOFTBUS_OK);
    bool isSameSide = false;
    bool ret = CompareAssetAclSameAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    DistributedDeviceProfile::Accesser accesser;
    accesser.SetAccesserDeviceId("cd");
    aclProfile.SetAccesser(accesser);
    ret = CompareAssetAclSameAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    DistributedDeviceProfile::Accessee accessee;
    accessee.SetAccesseeDeviceId("ab");
    aclProfile.SetAccessee(accessee);
    ret = CompareAssetAclSameAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    accesser.SetAccesserAccountId("gh");
    aclProfile.SetAccessee(accessee);
    ret = CompareAssetAclSameAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    accessee.SetAccesseeAccountId("ef");
    aclProfile.SetAccessee(accessee);
    ret = CompareAssetAclSameAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    accesser.SetAccesserUserId(2);
    aclProfile.SetAccesser(accesser);
    ret = CompareAssetAclSameAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: COMPARE_ASSET_ACL_SAME_ACCOUNT_TEST_004
 * @tc.desc: isSameSide is false.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, COMPARE_ASSET_ACL_SAME_ACCOUNT_TEST_004, TestSize.Level1)
{
    OHOS::DistributedDeviceProfile::AccessControlProfile aclProfile;
    uint32_t bindType = (uint32_t)OHOS::DistributedDeviceProfile::BindType::SAME_ACCOUNT;
    aclProfile.SetBindType(bindType);
    AuthACLInfo aclInfo;
    int32_t result = SetAclInfo(&aclInfo);
    ASSERT_EQ(result, SOFTBUS_OK);
    bool isSameSide = false;
    DistributedDeviceProfile::Accesser accesser;
    accesser.SetAccesserDeviceId("cd");
    accesser.SetAccesserAccountId("gh");
    accesser.SetAccesserUserId(2);
    aclProfile.SetAccesser(accesser);
    DistributedDeviceProfile::Accessee accessee;
    accessee.SetAccesseeDeviceId("ab");
    accessee.SetAccesseeAccountId("ef");
    accessee.SetAccesseeUserId(1);
    aclProfile.SetAccessee(accessee);
    bool ret = CompareAssetAclSameAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_TRUE(ret);

    accessee.SetAccesseeAccountId("ohosAnonymousUid");
    aclProfile.SetAccessee(accessee);
    result = strcpy_s(aclInfo.sourceAccountId, ACCOUNT_ID_BUF_LEN, "ohosAnonymousUid");
    EXPECT_EQ(result, EOK);
    ret = CompareAssetAclSameAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    accesser.SetAccesserAccountId("ohosAnonymousUid");
    aclProfile.SetAccesser(accesser);
    result = strcpy_s(aclInfo.sinkAccountId, ACCOUNT_ID_BUF_LEN, "ohosAnonymousUid");
    EXPECT_EQ(result, EOK);
    ret = CompareAssetAclSameAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: COMPARE_ASSET_ACL_DIFF_ACCOUNT_WITH_USER_LEVEL_TEST_001
 * @tc.desc: isSameSide is true.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, COMPARE_ASSET_ACL_DIFF_ACCOUNT_WITH_USER_LEVEL_TEST_001, TestSize.Level1)
{
    OHOS::DistributedDeviceProfile::AccessControlProfile aclProfile;
    uint32_t bindLevel = (uint32_t)OHOS::DistributedDeviceProfile::BindLevel::SERVICE;
    aclProfile.SetBindLevel(bindLevel);
    AuthACLInfo aclInfo;
    int32_t result = SetAclInfo(&aclInfo);
    ASSERT_EQ(result, SOFTBUS_OK);
    bool isSameSide = true;
    bool ret = CompareAssetAclDiffAccountWithUserLevel(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    bindLevel = (uint32_t)OHOS::DistributedDeviceProfile::BindLevel::USER;
    aclProfile.SetBindLevel(bindLevel);
    ret = CompareAssetAclDiffAccountWithUserLevel(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    DistributedDeviceProfile::Accesser accesser;
    accesser.SetAccesserDeviceId("ab");
    aclProfile.SetAccesser(accesser);
    ret = CompareAssetAclDiffAccountWithUserLevel(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    DistributedDeviceProfile::Accessee accessee;
    accessee.SetAccesseeDeviceId("cd");
    aclProfile.SetAccessee(accessee);
    ret = CompareAssetAclDiffAccountWithUserLevel(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    accesser.SetAccesserUserId(1);
    aclProfile.SetAccesser(accesser);
    ret = CompareAssetAclDiffAccountWithUserLevel(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    accessee.SetAccesseeUserId(2);
    aclProfile.SetAccessee(accessee);
    ret = CompareAssetAclDiffAccountWithUserLevel(aclProfile, &aclInfo, isSameSide);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: COMPARE_ASSET_ACL_DIFF_ACCOUNT_WITH_USER_LEVEL_TEST_002
 * @tc.desc: isSameSide is true.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, COMPARE_ASSET_ACL_DIFF_ACCOUNT_WITH_USER_LEVEL_TEST_002, TestSize.Level1)
{
    OHOS::DistributedDeviceProfile::AccessControlProfile aclProfile;
    uint32_t bindLevel = (uint32_t)OHOS::DistributedDeviceProfile::BindLevel::USER;
    aclProfile.SetBindLevel(bindLevel);
    AuthACLInfo aclInfo;
    int32_t result = SetAclInfo(&aclInfo);
    ASSERT_EQ(result, SOFTBUS_OK);
    bool isSameSide = false;
    bool ret = CompareAssetAclDiffAccountWithUserLevel(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    DistributedDeviceProfile::Accesser accesser;
    accesser.SetAccesserDeviceId("cd");
    aclProfile.SetAccesser(accesser);
    ret = CompareAssetAclDiffAccountWithUserLevel(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    DistributedDeviceProfile::Accessee accessee;
    accessee.SetAccesseeDeviceId("ab");
    aclProfile.SetAccessee(accessee);
    ret = CompareAssetAclDiffAccountWithUserLevel(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    accesser.SetAccesserUserId(2);
    aclProfile.SetAccesser(accesser);
    ret = CompareAssetAclDiffAccountWithUserLevel(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    accessee.SetAccesseeUserId(1);
    aclProfile.SetAccessee(accessee);
    ret = CompareAssetAclDiffAccountWithUserLevel(aclProfile, &aclInfo, isSameSide);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: COMPARE_ASSET_ACL_DIFF_ACCOUNT_001
 * @tc.desc: isSameSide is true.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, COMPARE_ASSET_ACL_DIFF_ACCOUNT_001, TestSize.Level1)
{
    OHOS::DistributedDeviceProfile::AccessControlProfile aclProfile;
    uint32_t bindType = (uint32_t)OHOS::DistributedDeviceProfile::BindType::SAME_ACCOUNT;
    aclProfile.SetBindType(bindType);
    AuthACLInfo aclInfo;
    int32_t result = SetAclInfo(&aclInfo);
    ASSERT_EQ(result, SOFTBUS_OK);
    bool isSameSide = true;
    bool ret = CompareAssetAclDiffAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    bindType = (uint32_t)OHOS::DistributedDeviceProfile::BindType::SHARE;
    aclProfile.SetBindType(bindType);
    ret = CompareAssetAclDiffAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    bindType = (uint32_t)OHOS::DistributedDeviceProfile::BindType::POINT_TO_POINT;
    aclProfile.SetBindType(bindType);
    uint32_t bindLevel = (uint32_t)OHOS::DistributedDeviceProfile::BindLevel::USER;
    aclProfile.SetBindLevel(bindLevel);
    ret = CompareAssetAclDiffAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    bindLevel = (uint32_t)OHOS::DistributedDeviceProfile::BindLevel::SERVICE;
    aclProfile.SetBindLevel(bindLevel);
    ret = CompareAssetAclDiffAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    DistributedDeviceProfile::Accesser accesser;
    accesser.SetAccesserDeviceId("ab");
    aclProfile.SetAccesser(accesser);
    ret = CompareAssetAclDiffAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    DistributedDeviceProfile::Accessee accessee;
    accessee.SetAccesseeDeviceId("cd");
    aclProfile.SetAccessee(accessee);
    ret = CompareAssetAclDiffAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    accesser.SetAccesserUserId(1);
    aclProfile.SetAccesser(accesser);
    ret = CompareAssetAclDiffAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: COMPARE_ASSET_ACL_DIFF_ACCOUNT_002
 * @tc.desc: isSameSide is true.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, COMPARE_ASSET_ACL_DIFF_ACCOUNT_002, TestSize.Level1)
{
    OHOS::DistributedDeviceProfile::AccessControlProfile aclProfile;
    uint32_t bindType = (uint32_t)OHOS::DistributedDeviceProfile::BindType::POINT_TO_POINT;
    aclProfile.SetBindType(bindType);
    uint32_t bindLevel = (uint32_t)OHOS::DistributedDeviceProfile::BindLevel::SERVICE;
    aclProfile.SetBindLevel(bindLevel);
    AuthACLInfo aclInfo;
    int32_t result = SetAclInfo(&aclInfo);
    ASSERT_EQ(result, SOFTBUS_OK);
    bool isSameSide = true;
    DistributedDeviceProfile::Accesser accesser;
    accesser.SetAccesserDeviceId("ab");
    accesser.SetAccesserUserId(1);
    aclProfile.SetAccesser(accesser);
    DistributedDeviceProfile::Accessee accessee;
    accessee.SetAccesseeDeviceId("cd");
    accessee.SetAccesseeUserId(2);
    aclProfile.SetAccessee(accessee);
    bool ret = CompareAssetAclDiffAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    accesser.SetAccesserTokenId(3);
    aclProfile.SetAccesser(accesser);
    ret = CompareAssetAclDiffAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    accessee.SetAccesseeTokenId(4);
    aclProfile.SetAccessee(accessee);
    ret = CompareAssetAclDiffAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: COMPARE_ASSET_ACL_DIFF_ACCOUNT_003
 * @tc.desc: isSameSide is true.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, COMPARE_ASSET_ACL_DIFF_ACCOUNT_003, TestSize.Level1)
{
    OHOS::DistributedDeviceProfile::AccessControlProfile aclProfile;
    uint32_t bindType = (uint32_t)OHOS::DistributedDeviceProfile::BindType::POINT_TO_POINT;
    aclProfile.SetBindType(bindType);
    uint32_t bindLevel = (uint32_t)OHOS::DistributedDeviceProfile::BindLevel::SERVICE;
    aclProfile.SetBindLevel(bindLevel);
    AuthACLInfo aclInfo;
    int32_t result = SetAclInfo(&aclInfo);
    ASSERT_EQ(result, SOFTBUS_OK);
    bool isSameSide = false;
    bool ret = CompareAssetAclDiffAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    DistributedDeviceProfile::Accesser accesser;
    accesser.SetAccesserDeviceId("cd");
    aclProfile.SetAccesser(accesser);
    ret = CompareAssetAclDiffAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    DistributedDeviceProfile::Accessee accessee;
    accessee.SetAccesseeDeviceId("ab");
    aclProfile.SetAccessee(accessee);
    ret = CompareAssetAclDiffAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    accesser.SetAccesserUserId(2);
    aclProfile.SetAccesser(accesser);
    ret = CompareAssetAclDiffAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    accessee.SetAccesseeUserId(1);
    aclProfile.SetAccessee(accessee);
    ret = CompareAssetAclDiffAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    accesser.SetAccesserTokenId(4);
    aclProfile.SetAccesser(accesser);
    ret = CompareAssetAclDiffAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_FALSE(ret);

    accessee.SetAccesseeTokenId(3);
    aclProfile.SetAccessee(accessee);
    ret = CompareAssetAclDiffAccount(aclProfile, &aclInfo, isSameSide);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: COMPARE_ASSET_ALL_ACL_TEST_001
 * @tc.desc: isSameAccount is true.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, COMPARE_ASSET_ALL_ACL_TEST_001, TestSize.Level1)
{
    OHOS::DistributedDeviceProfile::AccessControlProfile aclProfile;
    uint32_t bindType = (uint32_t)OHOS::DistributedDeviceProfile::BindType::SHARE;
    aclProfile.SetBindType(bindType);
    AuthACLInfo aclInfo;
    int32_t result = SetAclInfo(&aclInfo);
    ASSERT_EQ(result, SOFTBUS_OK);
    bool isSameSide = true;
    bool isSameAccount = true;
    bindType = (uint32_t)OHOS::DistributedDeviceProfile::BindType::SAME_ACCOUNT;
    aclProfile.SetBindType(bindType);
    DistributedDeviceProfile::Accesser accesser;
    accesser.SetAccesserDeviceId("ab");
    accesser.SetAccesserAccountId("ef");
    accesser.SetAccesserUserId(1);
    aclProfile.SetAccesser(accesser);
    DistributedDeviceProfile::Accessee accessee;
    accessee.SetAccesseeDeviceId("cd");
    accessee.SetAccesseeAccountId("gh");
    aclProfile.SetAccessee(accessee);
    bool ret = CompareAssetAllAcl(aclProfile, &aclInfo, isSameSide, isSameAccount);
    EXPECT_FALSE(ret);

    accessee.SetAccesseeUserId(2);
    aclProfile.SetAccessee(accessee);
    ret = CompareAssetAllAcl(aclProfile, &aclInfo, isSameSide, isSameAccount);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: COMPARE_ASSET_ALL_ACL_TEST_002
 * @tc.desc: isSameAccount is false.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, COMPARE_ASSET_ALL_ACL_TEST_002, TestSize.Level1)
{
    OHOS::DistributedDeviceProfile::AccessControlProfile aclProfile;
    AuthACLInfo aclInfo;
    int32_t result = SetAclInfo(&aclInfo);
    ASSERT_EQ(result, SOFTBUS_OK);
    bool isSameSide = true;
    bool isSameAccount = false;
    bool ret = CompareAssetAllAcl(aclProfile, &aclInfo, isSameSide, isSameAccount);
    EXPECT_FALSE(ret);

    uint32_t bindType = (uint32_t)OHOS::DistributedDeviceProfile::BindType::POINT_TO_POINT;
    aclProfile.SetBindType(bindType);
    uint32_t bindLevel = (uint32_t)OHOS::DistributedDeviceProfile::BindLevel::SERVICE;
    aclProfile.SetBindLevel(bindLevel);
    DistributedDeviceProfile::Accesser accesser;
    accesser.SetAccesserDeviceId("ab");
    accesser.SetAccesserUserId(1);
    accesser.SetAccesserTokenId(3);
    aclProfile.SetAccesser(accesser);
    DistributedDeviceProfile::Accessee accessee;
    accessee.SetAccesseeDeviceId("cd");
    accessee.SetAccesseeUserId(2);
    accessee.SetAccesseeTokenId(4);
    aclProfile.SetAccessee(accessee);
    ret = CompareAssetAllAcl(aclProfile, &aclInfo, isSameSide, isSameAccount);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: COMPARE_ASSET_ALL_ACL_TEST_003
 * @tc.desc: isSameAccount is false.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, COMPARE_ASSET_ALL_ACL_TEST_003, TestSize.Level1)
{
    OHOS::DistributedDeviceProfile::AccessControlProfile aclProfile;
    uint32_t bindLevel = (uint32_t)OHOS::DistributedDeviceProfile::BindLevel::USER;
    aclProfile.SetBindLevel(bindLevel);
    AuthACLInfo aclInfo;
    int32_t result = SetAclInfo(&aclInfo);
    ASSERT_EQ(result, SOFTBUS_OK);
    DistributedDeviceProfile::Accesser accesser;
    accesser.SetAccesserDeviceId("ab");
    accesser.SetAccesserUserId(1);
    aclProfile.SetAccesser(accesser);
    DistributedDeviceProfile::Accessee accessee;
    accessee.SetAccesseeDeviceId("cd");
    accessee.SetAccesseeUserId(2);
    aclProfile.SetAccessee(accessee);
    bool isSameSide = true;
    bool isSameAccount = false;
    bool ret = CompareAssetAllAcl(aclProfile, &aclInfo, isSameSide, isSameAccount);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: GET_LOCAL_UK_ID_FROM_ACCESS_TEST_001
 * @tc.desc: isServer is true or false.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, GET_LOCAL_UK_ID_FROM_ACCESS_TEST_001, TestSize.Level1)
{
    OHOS::DistributedDeviceProfile::AccessControlProfile aclProfile;
    AuthACLInfo aclInfo;
    int32_t result = SetAclInfo(&aclInfo);
    ASSERT_EQ(result, SOFTBUS_OK);
    DistributedDeviceProfile::Accesser accesser;
    accesser.SetAccesserDeviceId("ab");
    accesser.SetAccesserSessionKeyId(1);
    accesser.SetAccesserSKTimeStamp(135);
    aclProfile.SetAccesser(accesser);
    DistributedDeviceProfile::Accessee accessee;
    accessee.SetAccesseeDeviceId("cd");
    accessee.SetAccesseeSessionKeyId(2);
    accessee.SetAccesseeSKTimeStamp(246);
    aclProfile.SetAccessee(accessee);
    int32_t ukId = 0;
    uint64_t time = 0;
    GetLocalUkIdFromAccess(aclProfile, &aclInfo, &ukId, &time);
    EXPECT_EQ(ukId, 1);
    EXPECT_EQ(time, 135);

    accesser.SetAccesserDeviceId("abcd");
    aclProfile.SetAccesser(accesser);
    GetLocalUkIdFromAccess(aclProfile, &aclInfo, &ukId, &time);
    EXPECT_EQ(ukId, 1);
    EXPECT_EQ(time, 135);

    aclInfo.isServer = false;
    GetLocalUkIdFromAccess(aclProfile, &aclInfo, &ukId, &time);
    EXPECT_EQ(ukId, 2);
    EXPECT_EQ(time, 246);
}

/*
 * @tc.name: UPDATE_ACCESS_PROFILE_SESSION_KEY_ID_TEST_001
 * @tc.desc: Set ukid as default value.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, UPDATE_ACCESS_PROFILE_SESSION_KEY_ID_TEST_001, TestSize.Level1)
{
    OHOS::DistributedDeviceProfile::AccessControlProfile aclProfile;
    int32_t ukId = 10;
    UpdateAccessProfileSessionKeyId(aclProfile, &ukId);
    EXPECT_EQ(ukId, -1);
}

/*
 * @tc.name: GET_ACCESS_UK_ID_SAME_ACCOUNT_TEST_001
 * @tc.desc: acl or ukid or time is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, GET_ACCESS_UK_ID_SAME_ACCOUNT_TEST_001, TestSize.Level1)
{
    AuthACLInfo aclInfo;
    int32_t ukId = 0;
    uint64_t time = 0;
    int32_t ret = GetAccessUkIdSameAccount(nullptr, &ukId, &time);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = GetAccessUkIdSameAccount(&aclInfo, nullptr, &time);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = GetAccessUkIdSameAccount(&aclInfo, &ukId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GET_ACCESS_UK_ID_DIFF_ACCOUNT_WITH_USER_LEVEL_TEST_001
 * @tc.desc: acl or ukid or time is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, GET_ACCESS_UK_ID_DIFF_ACCOUNT_WITH_USER_LEVEL_TEST_001, TestSize.Level1)
{
    AuthACLInfo aclInfo;
    int32_t ukId = 0;
    uint64_t time = 0;
    int32_t ret = GetAccessUkIdDiffAccountWithUserLevel(nullptr, &ukId, &time);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = GetAccessUkIdDiffAccountWithUserLevel(&aclInfo, nullptr, &time);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = GetAccessUkIdDiffAccountWithUserLevel(&aclInfo, &ukId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GET_ACCESS_UK_ID_DIFF_ACCOUNT_TEST_001
 * @tc.desc: acl or ukid or time is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, GET_ACCESS_UK_ID_DIFF_ACCOUNT_TEST_001, TestSize.Level1)
{
    AuthACLInfo aclInfo;
    int32_t ukId = 0;
    uint64_t time = 0;
    int32_t ret = GetAccessUkIdDiffAccount(nullptr, &ukId, &time);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetAccessUkIdDiffAccount(&aclInfo, nullptr, &time);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetAccessUkIdDiffAccount(&aclInfo, &ukId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GET_ACCESS_UK_BY_UK_ID_TEST_001
 * @tc.desc: uk is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, GET_ACCESS_UK_BY_UK_ID_TEST_001, TestSize.Level1)
{
    int32_t sessionKeyId = 0;
    uint32_t ukLen = 10;
    int32_t ret = GetAccessUkByUkId(sessionKeyId, nullptr, ukLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: IS_SK_ID_INVALID_INNER_TEST_001
 * @tc.desc: AccountId is default.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, IS_SK_ID_INVALID_INNER_TEST_001, TestSize.Level1)
{
    int32_t sessionKeyId = 1;
    const char *accountHash = "1a2b3c4d5e6f";
    const char *udidShortHash = "a1b2c3d4e5f6";
    int32_t userId = 2;
    OHOS::DistributedDeviceProfile::AccessControlProfile aclProfile;
    AuthDeviceProfileInterfaceMock mock;
    EXPECT_CALL(mock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConvertBytesToHexString).WillRepeatedly(Return(SOFTBUS_OK));
    bool ret = IsSKIdInvalidInner(sessionKeyId, accountHash, udidShortHash, userId, aclProfile);
    EXPECT_TRUE(ret);

    DistributedDeviceProfile::Accesser accesser;
    accesser.SetAccesserDeviceId("ab");
    accesser.SetAccesserAccountId("ohosAnonymousUid");
    accesser.SetAccesserSessionKeyId(1);
    accesser.SetAccesserUserId(2);
    aclProfile.SetAccesser(accesser);
    DistributedDeviceProfile::Accessee accessee;
    accessee.SetAccesseeDeviceId("cd");
    accessee.SetAccesseeAccountId("ohosAnonymousUid");
    accessee.SetAccesseeSessionKeyId(3);
    accessee.SetAccesseeUserId(6);
    aclProfile.SetAccessee(accessee);
    ret = IsSKIdInvalidInner(sessionKeyId, accountHash, udidShortHash, userId, aclProfile);
    EXPECT_TRUE(ret);

    sessionKeyId = 3;
    ret = IsSKIdInvalidInner(sessionKeyId, accountHash, udidShortHash, userId, aclProfile);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: IS_SK_ID_INVALID_TEST_001
 * @tc.desc: accountHash or udidShortHash is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, IS_SK_ID_INVALID_TEST_001, TestSize.Level1)
{
    int32_t sessionKeyId = 1;
    const char *accountHash = "1a2b3c4d5e6f";
    int32_t userId = 2;
    bool ret = IsSKIdInvalid(sessionKeyId, nullptr, nullptr, userId);
    EXPECT_FALSE(ret);
    ret = IsSKIdInvalid(sessionKeyId, accountHash, nullptr, userId);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: IS_SK_ID_INVALID_TEST_002
 * @tc.desc: 1.accountHash length error.2.udidShortHash length error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, IS_SK_ID_INVALID_TEST_002, TestSize.Level1)
{
    int32_t sessionKeyId = 1;
    const char *accountHash = "1a2b3c4d5e6f";
    const char *udidShortHash = "a1b2c3d4e5f6";
    int32_t userId = 2;
    bool ret = IsSKIdInvalid(sessionKeyId, accountHash, udidShortHash, userId);
    EXPECT_FALSE(ret);

    const char *testUdidShortHash = "a1b2c3d4e5f6a1b2c3d4e5f6";
    ret = IsSKIdInvalid(sessionKeyId, accountHash, testUdidShortHash, userId);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: SELECT_ALL_ACL_TEST_001
 * @tc.desc: trustedInfoArray or num is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, SELECT_ALL_ACL_TEST_001, TestSize.Level1)
{
    int32_t ret = SelectAllAcl(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    uint32_t num = 1;
    ret = SelectAllAcl(nullptr, &num);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
} // namespace OHOS