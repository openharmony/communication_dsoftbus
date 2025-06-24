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

#include "auth_device_profile_listener.h"
#include "auth_deviceprofile.cpp"
#include "auth_device_profile_mock.h"
#include "auth_log.h"
#include "device_profile_listener.h"
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

class AuthDeviceProfileTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthDeviceProfileTest::SetUpTestCase() { }

void AuthDeviceProfileTest::TearDownTestCase() { }

void AuthDeviceProfileTest::SetUp() { }

void AuthDeviceProfileTest::TearDown() { }

static void OnDeviceBound(const char *udid, const char *groupInfo)
{
    (void)udid;
    (void)groupInfo;
    AUTH_LOGI(AUTH_TEST, "deviceBound success!");
}

static void OnDeviceNotTrusted(const char *udid, int32_t localUserId)
{
    (void)udid;
    (void)localUserId;
    AUTH_LOGI(AUTH_TEST, "device is not trusted!");
}

static DeviceProfileChangeListener g_deviceProfilePara = {
    .onDeviceProfileAdd = OnDeviceBound,
    .onDeviceProfileDeleted = OnDeviceNotTrusted,
};

/*
 * @tc.name: TRUST_DEVICE_PROFILE_ADD_TEST_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, TRUST_DEVICE_PROFILE_ADD_TEST_001, TestSize.Level1)
{
    RegisterToDp(&g_deviceProfilePara);
    std::unique_ptr<AuthToDeviceProfile::AuthDeviceProfileListener> myFunc_ =
        std::make_unique<AuthToDeviceProfile::AuthDeviceProfileListener>();
    AuthToDeviceProfile::TrustDeviceProfile profile;
    int32_t ret = myFunc_->OnTrustDeviceProfileAdd(profile);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TRUST_DEVICE_PROFILE_DELETE_TEST_002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, TRUST_DEVICE_PROFILE_DELETE_TEST_002, TestSize.Level1)
{
    RegisterToDp(&g_deviceProfilePara);
    std::unique_ptr<AuthToDeviceProfile::AuthDeviceProfileListener> myFunc_ =
        std::make_unique<AuthToDeviceProfile::AuthDeviceProfileListener>();
    AuthToDeviceProfile::TrustDeviceProfile profile;
    int32_t ret = myFunc_->OnTrustDeviceProfileDelete(profile);
    EXPECT_EQ(ret, SOFTBUS_OK);
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
    EXPECT_EQ(ret, false);
    deviceIdHash = "dev/ice%Id()Hash()";
    ret = IsPotentialTrustedDeviceDp(deviceIdHash, true);
    EXPECT_EQ(ret, false);
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
    uint8_t udidHash[SHA_256_HASH_LEN] = { 0 };
    char hashStr[CUST_UDID_LEN + 1] = { 0 };
    int32_t ret = SoftBusGenerateStrHash((const unsigned char *)udid, strlen(udid), udidHash);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ConvertBytesToHexString(hashStr, CUST_UDID_LEN + 1, udidHash, CUST_UDID_LEN / HEXIFY_UNIT_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    InsertNotTrustDevice(hashStr);
    bool result = IsNotTrustDevice(hashStr);
    EXPECT_TRUE(result);
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
    bool result = IsNotTrustDevice(deviceIdHash);
    EXPECT_FALSE(result);
    InsertDpSameAccountAcl(peerUdid, peerUserId, sessionKeyId);
}

/*
 * @tc.name: GET_ACL_LOCAL_USERID_TEST_001
 * @tc.desc: test GetAclLocalUserId
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
 * @tc.desc: test GetAclPeerUserId
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
 * @tc.desc: test GetStringHash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, GET_STRING_HASH_001, TestSize.Level1)
{
    std::string str = "";
    char hashStrBuf[SHA_256_HEX_HASH_LEN] = { 0 };
    int32_t len = 32;
    int32_t ret = GetStringHash(str, hashStrBuf, len);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GENERATE_STR_HASH_ERR);

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
    AuthDeviceProfileInterfaceMock mocker;
    EXPECT_CALL(mocker, LnnGetLocalNum64Info).WillRepeatedly(DoAll(SetArgPointee<1>(TEST_ACCOUNT_ID + 1),
        Return(SOFTBUS_OK)));
    bool result = IsSameAccount(accountId);
    EXPECT_FALSE(result);
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
    AuthDeviceProfileInterfaceMock mocker;
    EXPECT_CALL(mocker, LnnGetLocalNum64Info).WillRepeatedly(DoAll(SetArgPointee<1>(TEST_ACCOUNT_ID),
        Return(SOFTBUS_OK)));
    bool result = IsSameAccount(accountId);
    EXPECT_FALSE(result);
}

/*
 * @tc.name: GET_SESSION_KEY_PROFILE_TEST_001
 * @tc.desc: sessionKey is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, GET_SESSION_KEY_PROFILE_TEST_001, TestSize.Level1)
{
    uint8_t *sessionKey = nullptr;
    uint32_t length = 0;
    bool result = GetSessionKeyProfile(TEST_SESSION_KEY_ID, sessionKey, &length);
    EXPECT_TRUE(result);
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
    EXPECT_TRUE(result);
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
    bool result = GetSessionKeyProfile(TEST_SESSION_KEY_ID, &sessionKey, &length);
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
    int32_t ret = UpdateDpSameAccountAcl(peerUdid, peerUserId, sessionKeyId);
    EXPECT_EQ(ret, UPDATE_ACL_NOT_MATCH);
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
    bool result = IsTrustDevice(trustDevices, deviceIdHash, anonyDeviceIdHash, isOnlyPointToPoint);
    EXPECT_FALSE(result);

    const char *deviceIdHash1 = "8bb0cf6eb9b17d0f";
    result = IsTrustDevice(trustDevices, deviceIdHash1, anonyDeviceIdHash, isOnlyPointToPoint);
    EXPECT_TRUE(result);
}

/*
 * @tc.name: COMPARE_ACL_WITH_PEER_DEVICE_INFO_TEST_001
 * @tc.desc: test CompareAclWithPeerDeviceInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, COMPARE_ACL_WITH_PEER_DEVICE_INFO_TEST_001, TestSize.Level1)
{
    OHOS::DistributedDeviceProfile::AccessControlProfile aclProfile;
    const char *peerAccountHash = "8bb0cf6eb9b17d0f";
    const char *peerUdid = "1234567890";
    int32_t peerUserId = 1;
    bool result = CompareAclWithPeerDeviceInfo(aclProfile, peerAccountHash, peerUdid, peerUserId);
    EXPECT_FALSE(result);
}

/*
 * @tc.name: COMPARE_ACL_WITH_PEER_DEVICE_INFO_TEST_002
 * @tc.desc: test CompareAclWithPeerDeviceInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthDeviceProfileTest, COMPARE_ACL_WITH_PEER_DEVICE_INFO_TEST_002, TestSize.Level1)
{
    AuthDeviceProfileInterfaceMock mocker;
    EXPECT_CALL(mocker, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
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
    bool result = CompareAclWithPeerDeviceInfo(aclProfile, peerAccountHash, peerUdid, peerUserId);
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
    UpdateDpSameAccount(&aclParams, sessionKey, true, ACL_WRITE_DEFAULT);
    ret = IsTrustedDeviceFromAccess(accountHash, udid, 100);
    EXPECT_EQ(ret, false);
}
} // namespace OHOS