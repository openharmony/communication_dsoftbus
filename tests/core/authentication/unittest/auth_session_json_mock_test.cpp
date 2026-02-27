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

#include "auth_session_json.c"
#include "auth_session_json_deps_mock.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;
constexpr int64_t TEST_AUTH_ID = 1;
constexpr int32_t KEY_VALUE_LEN = 13;
constexpr int32_t TEST_AUTH_PORT = 1;
constexpr int32_t TEST_SESSION_PORT = 2;
constexpr int32_t TEST_PROXY_PORT = 3;
constexpr uint8_t KEY_VALUE[SESSION_KEY_LENGTH] = "123456keytest";

class AuthSessionJsonMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthSessionJsonMockTest::SetUpTestCase() { }

void AuthSessionJsonMockTest::TearDownTestCase() { }

void AuthSessionJsonMockTest::SetUp() { }

void AuthSessionJsonMockTest::TearDown() { }

/*
 * @tc.name: GET_ENHANCED_P2P_AUTH_KEY_TEST_001
 * @tc.desc: GetEnhancedP2pAuthKey test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, GET_ENHANCED_P2P_AUTH_KEY_TEST_001, TestSize.Level1)
{
    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    char udidHash[SHA_256_HEX_HASH_LEN] = { 0 };
    AuthSessionInfo info = { 0 };
    AuthDeviceKeyInfo deviceKey = { 0 };
    int32_t ret = GetEnhancedP2pAuthKey(udidHash, &info, &deviceKey);
    EXPECT_EQ(ret, SOFTBUS_AUTH_NOT_FOUND);
    ret = GetEnhancedP2pAuthKey(udidHash, &info, &deviceKey);
    EXPECT_EQ(ret, SOFTBUS_AUTH_NOT_FOUND);

    AuthHandle authHandle = { .authId = TEST_AUTH_ID };
    EXPECT_CALL(mocker, AuthGetLatestIdByUuid)
        .WillRepeatedly(DoAll(SetArgPointee<3>(authHandle), Return()));
    AuthManager auth = { 0 };
    EXPECT_CALL(mocker, GetAuthManagerByAuthId)
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Return(&auth));
    EXPECT_CALL(mocker, DelDupAuthManager)
        .WillRepeatedly(Return());
    SessionKey sessionKey = { .len = SESSION_KEY_LENGTH };
    EXPECT_EQ(memcpy_s(sessionKey.value, SESSION_KEY_LENGTH, KEY_VALUE, KEY_VALUE_LEN), EOK);
    EXPECT_CALL(mocker, GetLatestSessionKey)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(DoAll(SetArgPointee<3>(sessionKey), Return(SOFTBUS_OK)));

    ret = GetEnhancedP2pAuthKey(udidHash, &info, &deviceKey);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = GetEnhancedP2pAuthKey(udidHash, &info, &deviceKey);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = GetEnhancedP2pAuthKey(udidHash, &info, &deviceKey);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: PACK_NORMALIZED_KEY_VALUE_TEST_001
 * @tc.desc: PackNormalizedKeyValue test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, PACK_NORMALIZED_KEY_VALUE_TEST_001, TestSize.Level1)
{
    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    uint32_t dataLen = 1;
    uint8_t *data = reinterpret_cast<uint8_t *>(SoftBusMalloc(dataLen));
    if (data == nullptr) {
        return;
    }
    EXPECT_CALL(mocker, ConvertHexStringToBytes)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mocker, LnnDecryptAesGcm)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillOnce(DoAll(SetArgPointee<1>(nullptr), Return(SOFTBUS_OK)))
        .WillOnce(DoAll(SetArgPointee<1>(data), SetArgPointee<2>(0), Return(SOFTBUS_OK)));
    AuthSessionInfo info = { 0 };
    AuthDeviceKeyInfo deviceKey = { 0 };
    const char *fastAuth = "encryptedFastAuth";
    EXPECT_NO_FATAL_FAILURE(ParseFastAuthValue(&info, fastAuth, &deviceKey));
    EXPECT_NO_FATAL_FAILURE(ParseFastAuthValue(&info, fastAuth, &deviceKey));
    EXPECT_NO_FATAL_FAILURE(ParseFastAuthValue(&info, fastAuth, &deviceKey));
    EXPECT_NO_FATAL_FAILURE(ParseFastAuthValue(&info, fastAuth, &deviceKey));
    EXPECT_CALL(mocker, LnnEncryptAesGcm)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillOnce(DoAll(SetArgPointee<2>(nullptr), Return(SOFTBUS_OK)))
        .WillOnce(DoAll(SetArgPointee<2>(data), SetArgPointee<3>(0), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<2>(data), SetArgPointee<3>(dataLen), Return(SOFTBUS_OK)));
    EXPECT_CALL(mocker, ConvertBytesToUpperCaseHexString)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(mocker, JSON_AddStringToObject)
        .WillRepeatedly(Return(true));
    JsonObj obj;
    (void)memset_s(&obj, sizeof(JsonObj), 0, sizeof(JsonObj));
    SessionKey sessionKey;
    (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
    int32_t ret = PackNormalizedKeyValue(&obj, &sessionKey);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = PackNormalizedKeyValue(&obj, &sessionKey);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = PackNormalizedKeyValue(&obj, &sessionKey);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = PackNormalizedKeyValue(&obj, &sessionKey);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: PARSE_NORMALIZED_KEY_VALUE_TEST_001
 * @tc.desc: ParseNormalizedKeyValue test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, PARSE_NORMALIZED_KEY_VALUE_TEST_001, TestSize.Level1)
{
    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    uint32_t dataLen = strlen("true");
    uint8_t *data = reinterpret_cast<uint8_t *>(SoftBusMalloc(dataLen));
    if (data == nullptr) {
        return;
    }
    (void)memcpy_s(data, dataLen, "true", strlen("true"));
    EXPECT_CALL(mocker, ConvertHexStringToBytes)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mocker, LnnDecryptAesGcm)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillOnce(DoAll(SetArgPointee<1>(nullptr), Return(SOFTBUS_OK)))
        .WillOnce(DoAll(SetArgPointee<1>(data), SetArgPointee<2>(0), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<1>(data), SetArgPointee<2>(dataLen), Return(SOFTBUS_OK)));
    AuthSessionInfo info = { 0 };
    SessionKey sessionKey;
    (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
    const char *fastAuth = "encryptedFastAuth";
    int32_t ret = ParseNormalizedKeyValue(&info, fastAuth, &sessionKey);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = ParseNormalizedKeyValue(&info, fastAuth, &sessionKey);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = ParseNormalizedKeyValue(&info, fastAuth, &sessionKey);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = ParseNormalizedKeyValue(&info, fastAuth, &sessionKey);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = ParseNormalizedKeyValue(&info, fastAuth, &sessionKey);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: PARSE_NORMALIZE_DATA_TEST_001
 * @tc.desc: ParseNormalizeData test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, PARSE_NORMALIZE_DATA_TEST_001, TestSize.Level1)
{
    int64_t authSeq = 1;
    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    EXPECT_CALL(mocker, SoftBusGenerateStrHash)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mocker, ConvertBytesToUpperCaseHexString)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mocker, ConvertHexStringToBytes)
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(mocker, AuthUpdateCreateTime)
        .WillRepeatedly(Return());
    AuthSessionInfo info = { 0 };
    AuthDeviceKeyInfo deviceKey = { 0 };
    const char *key = "encnormalizedkeytest";
    int32_t ret = ParseNormalizeData(&info, const_cast<char *>(key), &deviceKey, authSeq);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = ParseNormalizeData(&info, const_cast<char *>(key), &deviceKey, authSeq);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = ParseNormalizeData(&info, const_cast<char *>(key), &deviceKey, authSeq);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = ParseNormalizeData(&info, const_cast<char *>(key), &deviceKey, authSeq);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = ParseNormalizeData(&info, const_cast<char *>(key), &deviceKey, authSeq);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = ParseNormalizeData(&info, const_cast<char *>(key), &deviceKey, authSeq);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: VERIFY_SESSION_INFO_ID_TYPE_TEST_001
 * @tc.desc: VerifySessionInfoIdType test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, VERIFY_SESSION_INFO_ID_TYPE_TEST_001, TestSize.Level1)
{
    AuthSessionInfo info = { .idType = EXCHANGE_NETWORKID, .connInfo.type = AUTH_LINK_TYPE_WIFI };
    char *networkId = nullptr;
    char *udid = nullptr;
    JsonObj obj;
    (void)memset_s(&obj, sizeof(JsonObj), 0, sizeof(JsonObj));
    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    EXPECT_CALL(mocker, LnnGetLocalStrInfoByIfnameIdx)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mocker, SoftBusGenerateStrHash)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mocker, ConvertBytesToUpperCaseHexString)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mocker, JSON_AddStringToObject)
        .WillRepeatedly(Return(false));
    EXPECT_NO_FATAL_FAILURE(PackWifiSinglePassInfo(&obj, &info));
    EXPECT_NO_FATAL_FAILURE(PackWifiSinglePassInfo(&obj, &info));
    EXPECT_NO_FATAL_FAILURE(PackWifiSinglePassInfo(&obj, &info));
    EXPECT_NO_FATAL_FAILURE(PackWifiSinglePassInfo(&obj, &info));
    EXPECT_NO_FATAL_FAILURE(PackWifiSinglePassInfo(&obj, &info));
    EXPECT_CALL(mocker, JSON_AddStringToObject)
        .WillOnce(Return(false))
        .WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    bool ret = VerifySessionInfoIdType(&info, &obj, networkId, udid);
    EXPECT_NE(ret, true);
    info.idType = EXCHANGE_UDID;
    ret = VerifySessionInfoIdType(&info, &obj, networkId, udid);
    EXPECT_NE(ret, true);
    ret = VerifySessionInfoIdType(&info, &obj, networkId, udid);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: PACK_DEVICE_JSON_INFO_TEST_001
 * @tc.desc: PackDeviceJsonInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, PACK_DEVICE_JSON_INFO_TEST_001, TestSize.Level1)
{
    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    EXPECT_CALL(mocker, IsSupportUDIDAbatement)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mocker, JSON_AddBoolToObject)
        .WillRepeatedly(Return(false));
    EXPECT_CALL(mocker, IsNeedUDIDAbatement)
        .WillRepeatedly(Return(false));
    EXPECT_CALL(mocker, JSON_AddStringToObject)
        .WillOnce(Return(false))
        .WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mocker, JSON_AddInt32ToObject)
        .WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    AuthSessionInfo info = { .connInfo.type = AUTH_LINK_TYPE_WIFI, .isConnectServer = false };
    JsonObj obj;
    (void)memset_s(&obj, sizeof(JsonObj), 0, sizeof(JsonObj));
    EXPECT_NO_FATAL_FAILURE(PackUDIDAbatementFlag(&obj, &info));
    int32_t ret = PackDeviceJsonInfo(&info, &obj);
    EXPECT_NE(ret, SOFTBUS_OK);
    info.isConnectServer = true;
    ret = PackDeviceJsonInfo(&info, &obj);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = PackDeviceJsonInfo(&info, &obj);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = PackDeviceJsonInfo(&info, &obj);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: PACK_NORMALIZED_DATA_TEST_001
 * @tc.desc: PackNormalizedData test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, PACK_NORMALIZED_DATA_TEST_001, TestSize.Level1)
{
    int64_t authSeq = 1;
    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    EXPECT_CALL(mocker, IsSupportFeatureByCapaBit)
        .WillRepeatedly(Return(false));
    EXPECT_CALL(mocker, GetSessionKeyProfile)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mocker, JSON_AddBoolToObject)
        .WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    AuthSessionInfo info = { .isServer = true, .connInfo.type = AUTH_LINK_TYPE_WIFI };
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    JsonObj obj;
    (void)memset_s(&obj, sizeof(JsonObj), 0, sizeof(JsonObj));
    int32_t ret = PackNormalizedData(&info, &obj, &nodeInfo, authSeq);
    EXPECT_NE(ret, SOFTBUS_OK);
    EXPECT_CALL(mocker, JSON_GetStringFromObject)
        .WillOnce(Return(false))
        .WillRepeatedly(Return(false));
    EXPECT_CALL(mocker, SoftBusGenerateStrHash)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(UnpackNormalizedKey(&obj, &info, NORMALIZED_KEY_ERROR, authSeq));
    EXPECT_NO_FATAL_FAILURE(UnpackNormalizedKey(&obj, &info, NORMALIZED_KEY_ERROR, authSeq));
    EXPECT_EQ(info.normalizedKey, nullptr);
    if (info.normalizedKey != nullptr) {
        SoftBusFree(info.normalizedKey);
    }
    EXPECT_NO_FATAL_FAILURE(UnpackNormalizedKey(&obj, &info, NORMALIZED_KEY_ERROR, authSeq));
    EXPECT_EQ(info.normalizedKey, nullptr);
    if (info.normalizedKey != nullptr) {
        SoftBusFree(info.normalizedKey);
    }
    EXPECT_NO_FATAL_FAILURE(UnpackNormalizedKey(&obj, &info, NORMALIZED_KEY_ERROR, authSeq));
    EXPECT_EQ(info.normalizedKey, nullptr);
    if (info.normalizedKey != nullptr) {
        SoftBusFree(info.normalizedKey);
    }
    ret = PackNormalizedData(&info, &obj, &nodeInfo, authSeq);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: PACK_DEVICE_ID_JSON_TEST_001
 * @tc.desc: PackDeviceIdJson test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, PACK_DEVICE_ID_JSON_TEST_001, TestSize.Level1)
{
    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    JsonObj obj;
    int64_t authSeq = 1;
    (void)memset_s(&obj, sizeof(JsonObj), 0, sizeof(JsonObj));
    EXPECT_CALL(mocker, JSON_CreateObject)
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Return(&obj));
    EXPECT_CALL(mocker, JSON_Delete)
        .WillRepeatedly(Return());
    EXPECT_CALL(mocker, LnnGetLocalStrInfo)
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(mocker, FindAuthPreLinkNodeById)
        .WillRepeatedly(Return(SOFTBUS_OK));
    AuthSessionInfo info = { 0 };
    char *ret = PackDeviceIdJson(&info, authSeq);
    EXPECT_EQ(ret, nullptr);
    ret = PackDeviceIdJson(&info, authSeq);
    EXPECT_EQ(ret, nullptr);
}

/*
 * @tc.name: UNPACK_WIFI_SINGLE_PASS_INFO_TEST_001
 * @tc.desc: UnpackWifiSinglePassInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, UNPACK_WIFI_SINGLE_PASS_INFO_TEST_001, TestSize.Level1)
{
    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    EXPECT_CALL(mocker, JSON_GetStringFromObject)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mocker, SoftBusSocketGetPeerName)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    JsonObj obj;
    (void)memset_s(&obj, sizeof(JsonObj), 0, sizeof(JsonObj));
    AuthSessionInfo info = { .connInfo.type = AUTH_LINK_TYPE_WIFI };
    bool ret = UnpackWifiSinglePassInfo(&obj, &info);
    EXPECT_EQ(ret, true);
    ret = UnpackWifiSinglePassInfo(&obj, &info);
    EXPECT_EQ(ret, true);
    ret = UnpackWifiSinglePassInfo(&obj, &info);
    EXPECT_EQ(ret, true);
    ret = UnpackWifiSinglePassInfo(&obj, &info);
    EXPECT_EQ(ret, true);
    ret = UnpackWifiSinglePassInfo(&obj, &info);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: VERIFY_EXCHANGE_ID_TYPE_AND_INFO_TEST_001
 * @tc.desc: VerifyExchangeIdTypeAndInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, VERIFY_EXCHANGE_ID_TYPE_AND_INFO_TEST_001, TestSize.Level1)
{
    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    EXPECT_CALL(mocker, GetPeerUdidByNetworkId)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mocker, GetIsExchangeUdidByNetworkId)
        .WillOnce(Return(SOFTBUS_OK))
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    const char *anonyUdid = "0123456789ABC";
    char testUdid[UDID_BUF_LEN] = "0123456789ABC";
    EXPECT_EQ(strcpy_s(info.udid, UDID_BUF_LEN, testUdid), EOK);
    int32_t ret = VerifyExchangeIdTypeAndInfo(&info, EXCHANGE_UDID, const_cast<char *>(anonyUdid));
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = VerifyExchangeIdTypeAndInfo(&info, EXCHANGE_NETWORKID, const_cast<char *>(anonyUdid));
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = VerifyExchangeIdTypeAndInfo(&info, EXCHANGE_NETWORKID, const_cast<char *>(anonyUdid));
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = VerifyExchangeIdTypeAndInfo(&info, EXCHANGE_NETWORKID, const_cast<char *>(anonyUdid));
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = VerifyExchangeIdTypeAndInfo(&info, EXCHANGE_NETWORKID, const_cast<char *>(anonyUdid));
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = VerifyExchangeIdTypeAndInfo(&info, EXCHANGE_NETWORKID, const_cast<char *>(anonyUdid));
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SET_EXCHANGE_ID_TYPE_AND_VALUE_TEST_001
 * @tc.desc: SetExchangeIdTypeAndValue test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, SET_EXCHANGE_ID_TYPE_AND_VALUE_TEST_001, TestSize.Level1)
{
    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    EXPECT_CALL(mocker, JSON_GetInt32FromOject)
        .WillRepeatedly(Return(false));
    JsonObj obj;
    (void)memset_s(&obj, sizeof(JsonObj), 0, sizeof(JsonObj));
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    int32_t ret = SetExchangeIdTypeAndValue(&obj, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_CALL(mocker, AuthMetaGetConnIdByInfo)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mocker, LnnDumpRemotePtk)
        .WillRepeatedly(Return());
    EXPECT_CALL(mocker, SoftBusBase64Encode)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mocker, JSON_AddStringToObject)
        .WillOnce(Return(false))
        .WillOnce(Return(true))
        .WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mocker, JSON_AddInt32ToObject)
        .WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mocker, ConvertBytesToHexString)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    const char *remoteUuid = "remoteUuidTest";
    EXPECT_NO_FATAL_FAILURE(PackWifiDirectInfo(&connInfo, &obj, &nodeInfo, remoteUuid, true));
    EXPECT_NO_FATAL_FAILURE(PackWifiDirectInfo(&connInfo, &obj, &nodeInfo, nullptr, false));
    EXPECT_NO_FATAL_FAILURE(PackWifiDirectInfo(&connInfo, &obj, &nodeInfo, remoteUuid, false));
    EXPECT_NO_FATAL_FAILURE(PackWifiDirectInfo(&connInfo, &obj, &nodeInfo, remoteUuid, false));
    EXPECT_NO_FATAL_FAILURE(PackWifiDirectInfo(&connInfo, &obj, &nodeInfo, remoteUuid, false));
    EXPECT_NO_FATAL_FAILURE(PackWifiDirectInfo(&connInfo, &obj, &nodeInfo, remoteUuid, false));
    EXPECT_NO_FATAL_FAILURE(PackWifiDirectInfo(&connInfo, &obj, &nodeInfo, remoteUuid, false));
    EXPECT_NO_FATAL_FAILURE(PackWifiDirectInfo(&connInfo, &obj, &nodeInfo, remoteUuid, false));
    EXPECT_NO_FATAL_FAILURE(PackWifiDirectInfo(&connInfo, &obj, &nodeInfo, remoteUuid, false));
    EXPECT_NO_FATAL_FAILURE(PackWifiDirectInfo(&connInfo, &obj, &nodeInfo, remoteUuid, false));
    ret = SetExchangeIdTypeAndValue(&obj, nullptr);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = SetExchangeIdTypeAndValue(nullptr, &info);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: PACK_CIPHER_RPA_INFO_TEST_001
 * @tc.desc: PackCipherRpaInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, PACK_CIPHER_RPA_INFO_TEST_001, TestSize.Level1)
{
    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_CALL(mocker, ConvertBytesToHexString)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = PackCipherRpaInfo(&json, &info);
    EXPECT_NE(ret, SOFTBUS_OK);
    EXPECT_CALL(mocker, ConvertBytesToHexString)
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = PackCipherRpaInfo(&json, &info);
    EXPECT_NE(ret, SOFTBUS_OK);
    EXPECT_CALL(mocker, ConvertBytesToHexString)
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = PackCipherRpaInfo(&json, &info);
    EXPECT_NE(ret, SOFTBUS_OK);
    EXPECT_CALL(mocker, ConvertBytesToHexString)
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = PackCipherRpaInfo(&json, &info);
    EXPECT_NE(ret, SOFTBUS_OK);
    EXPECT_CALL(mocker, ConvertBytesToHexString)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mocker, JSON_AddStringToObject)
        .WillRepeatedly(Return(true));
    ret = PackCipherRpaInfo(&json, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = PackCipherRpaInfo(&json, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: PACK_COMMON_EX_TEST_001
 * @tc.desc: PackCommonEx test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, PACK_COMMON_EX_TEST_001, TestSize.Level1)
{
    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    EXPECT_CALL(mocker, JSON_AddStringToObject)
        .WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mocker, JSON_AddInt32ToObject)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mocker, JSON_AddInt16ToObject)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mocker, JSON_AddBoolToObject)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mocker, JSON_AddInt64ToObject)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mocker, JSON_AddInt32ToObject)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mocker, JSON_AddInt32ToObject)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mocker, LnnGetSupportedProtocols)
        .WillRepeatedly(Return(0));
    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    int32_t ret = PackCommonEx(&json, &info);
    EXPECT_NE(ret, SOFTBUS_OK);
    EXPECT_CALL(mocker, JSON_GetStringFromObject)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mocker, ConvertHexStringToBytes)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM));
    UnpackCipherRpaInfo(&json, &info);
    EXPECT_CALL(mocker, ConvertHexStringToBytes)
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM));
    UnpackCipherRpaInfo(&json, &info);
    EXPECT_CALL(mocker, ConvertHexStringToBytes)
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM));
    UnpackCipherRpaInfo(&json, &info);
    EXPECT_CALL(mocker, ConvertHexStringToBytes)
        .WillRepeatedly(Return(SOFTBUS_OK));
    UnpackCipherRpaInfo(&json, &info);
    const char *btMac = "00:11:22:33:44:55";
    EXPECT_CALL(mocker, LnnGetBtMac)
        .WillRepeatedly(Return(btMac));
    EXPECT_CALL(mocker, StringToUpperCase)
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = PackCommonEx(&json, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: PACK_COMMON_TEST_001
 * @tc.desc: PackCommon test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, PACK_COMMON_TEST_001, TestSize.Level1)
{
    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_CALL(mocker, JSON_AddStringToObject)
        .WillOnce(Return(false));
    int32_t ret = PackCommon(&json, &info, SOFTBUS_NEW_V1, true);
    EXPECT_NE(ret, SOFTBUS_OK);
    EXPECT_CALL(mocker, JSON_AddStringToObject)
        .WillOnce(Return(true));
    EXPECT_CALL(mocker, JSON_AddInt32ToObject)
        .WillOnce(Return(false));
    ret = PackCommon(&json, &info, SOFTBUS_NEW_V1, true);
    EXPECT_NE(ret, SOFTBUS_OK);
    EXPECT_CALL(mocker, JSON_AddStringToObject)
        .WillOnce(Return(true))
        .WillOnce(Return(false));
    EXPECT_CALL(mocker, JSON_AddInt32ToObject)
        .WillOnce(Return(true));
    ret = PackCommon(&json, &info, SOFTBUS_NEW_V1, true);
    EXPECT_NE(ret, SOFTBUS_OK);
    EXPECT_CALL(mocker, JSON_AddStringToObject)
        .WillOnce(Return(false));
    ret = PackCommon(&json, &info, SOFTBUS_OLD_V2, true);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: PACK_BT_TEST_001
 * @tc.desc: PackBt test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, PACK_BT_TEST_001, TestSize.Level1)
{
    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_CALL(mocker, JSON_AddInt32ToObject)
        .WillOnce(Return(false));
    EXPECT_CALL(mocker, LnnGetNetworkIdByUuid)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    const char *remoteUuid = "remoteUuidTest";
    AddDiscoveryType(&json, nullptr);
    AddDiscoveryType(&json, remoteUuid);
    EXPECT_CALL(mocker, LnnGetRemoteNumInfo)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM));
    AddDiscoveryType(&json, remoteUuid);
    int32_t ret = PackBt(&json, &info, SOFTBUS_NEW_V1, true, remoteUuid);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: PACK_WIFI_TEST_001
 * @tc.desc: PackWiFi test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, PACK_WIFI_TEST_001, TestSize.Level1)
{
    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_CALL(mocker, JSON_AddInt32ToObject)
        .WillRepeatedly(Return(false));
    EXPECT_CALL(mocker, LnnGetAuthPort)
        .WillRepeatedly(Return(TEST_AUTH_PORT));
    EXPECT_CALL(mocker, LnnGetSessionPort)
        .WillRepeatedly(Return(TEST_SESSION_PORT));
    EXPECT_CALL(mocker, LnnGetProxyPort)
        .WillRepeatedly(Return(TEST_PROXY_PORT));
    int32_t ret = PackWiFi(&json, &info, SOFTBUS_NEW_V1, false, WLAN_IF);
    EXPECT_NE(ret, SOFTBUS_OK);
    EXPECT_CALL(mocker, JSON_AddInt32ToObject)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mocker, JSON_AddStringToObject)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mocker, SoftBusBase64Encode)
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = PackWiFi(&json, &info, SOFTBUS_NEW_V1, false, WLAN_IF);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: PACK_CERTIFICATEINFO_TEST_001
 * @tc.desc: PackCertificateInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, PACK_CERTIFICATEINFO_TEST_001, TestSize.Level1)
{
    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    info.isNeedPackCert = false;
    int32_t ret = PackCertificateInfo(&json, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = PackCertificateInfo(&json, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = PackCertificateInfo(&json, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    info.isNeedPackCert = true;
    ret = PackCertificateInfo(&json, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_CALL(mocker, JSON_AddBytesToObject)
        .WillRepeatedly(Return(false));
    EXPECT_CALL(mocker, FreeSoftbusChain)
        .WillRepeatedly(Return());
    ret = PackCertificateInfo(&json, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_CALL(mocker, JSON_AddBytesToObject)
        .WillRepeatedly(Return(true));
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: PACK_CERTIFICATEINFO_TEST_002
 * @tc.desc: credIdType is ACCOUNT_SHARED.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, PACK_CERTIFICATEINFO_TEST_002, TestSize.Level1)
{
    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    EXPECT_CALL(mocker, JSON_AddStringToObject)
        .WillRepeatedly(Return(true));
    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    char id[] = { 'a', 'b', 'c', 'd', 'e', 'f' };
    info.credId = id;
    int32_t ret = PackCertificateInfo(&json, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = PackCertificateInfo(&json, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: UNPACK_CERTIFICATEINFO_TEST_001
 * @tc.desc: UnpackCertificateInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, UNPACK_CERTIFICATEINFO_TEST_001, TestSize.Level1)
{
    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    int32_t ret = UnpackCertificateInfo(nullptr, &nodeInfo, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UnpackCertificateInfo(&json, &nodeInfo, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UnpackCertificateInfo(&json, &nodeInfo, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UnpackCertificateInfo(&json, &nodeInfo, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_CALL(mocker, JSON_GetBytesFromObject)
        .WillRepeatedly(Return(false));
    EXPECT_CALL(mocker, FreeSoftbusChain)
        .WillRepeatedly(Return());
    ret = UnpackCertificateInfo(&json, &nodeInfo, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_CALL(mocker, JSON_GetBytesFromObject)
        .WillRepeatedly(Return(true));
    ret = UnpackCertificateInfo(&json, &nodeInfo, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UnpackCertificateInfo(&json, &nodeInfo, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: PACK_USER_ID_CHECK_SUM_TEST_001
 * @tc.desc: PackUserIdCheckSum test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, PACK_USER_ID_CHECK_SUM_TEST_001, TestSize.Level1)
{
    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_CALL(mocker, ConvertBytesToHexString)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mocker, JSON_AddStringToObject)
        .WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    int32_t ret = PackUserIdCheckSum(&json, &nodeInfo);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = PackUserIdCheckSum(&json, &nodeInfo);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = PackUserIdCheckSum(&json, &nodeInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: PACK_DEVICE_INFO_MESSAGE_TEST_001
 * @tc.desc: PackDeviceInfoMessage test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, PACK_DEVICE_INFO_MESSAGE_TEST_001, TestSize.Level1)
{
    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_CALL(mocker, LnnGetLocalNodeInfoSafe)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    const char *brMacTempNull = "";
    const char *brMacTempInvalid = "00:00:00:00:00:00";
    const char *brMacTemp = "00:11:22:33:44:55";
    EXPECT_CALL(mocker, LnnGetBtMac)
        .WillOnce(Return(brMacTempNull))
        .WillOnce(Return(brMacTempInvalid))
        .WillRepeatedly(Return(brMacTemp));
    EXPECT_CALL(mocker, SoftBusGetBtState)
        .WillOnce(Return(BLE_DISABLE))
        .WillRepeatedly(Return(BLE_ENABLE));
    EXPECT_CALL(mocker, SoftBusGetBtMacAddr)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mocker, LnnGetLocalNodeInfo)
        .WillRepeatedly(Return(nullptr));
    const char *remoteUuid = "remoteUuidTest";
    char *ret = PackDeviceInfoMessage(&connInfo, SOFTBUS_NEW_V1, false, remoteUuid, &info);
    EXPECT_EQ(ret, nullptr);
    ret = PackDeviceInfoMessage(&connInfo, SOFTBUS_NEW_V1, false, remoteUuid, &info);
    EXPECT_EQ(ret, nullptr);
    ret = PackDeviceInfoMessage(&connInfo, SOFTBUS_NEW_V1, false, remoteUuid, &info);
    EXPECT_EQ(ret, nullptr);
    ret = PackDeviceInfoMessage(&connInfo, SOFTBUS_NEW_V1, false, remoteUuid, &info);
    EXPECT_EQ(ret, nullptr);
    ret = PackDeviceInfoMessage(&connInfo, SOFTBUS_NEW_V1, false, remoteUuid, &info);
    EXPECT_EQ(ret, nullptr);
    ret = PackDeviceInfoMessage(&connInfo, SOFTBUS_NEW_V1, false, remoteUuid, &info);
    EXPECT_EQ(ret, nullptr);
}

/*
 * @tc.name: PackSparkCheck_TEST_001
 * @tc.desc: pack spark check test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, PackSparkCheck_TEST_001, TestSize.Level1)
{
    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NiceMock<AuthSessionJsonDepsInterfaceMock> mockDeps;
    EXPECT_CALL(mockDeps, ConvertBytesToHexString)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mockDeps, JSON_AddStringToObject)
        .WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    EXPECT_NO_FATAL_FAILURE(PackSparkCheck(&json, &info));
    EXPECT_NO_FATAL_FAILURE(PackSparkCheck(&json, &info));
    EXPECT_NO_FATAL_FAILURE(PackSparkCheck(&json, &info));
}

/*
 * @tc.name: UnpackSparkCheck_TEST_001
 * @tc.desc: unpack spark check test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, UnpackSparkCheck_TEST_001, TestSize.Level1)
{
    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NiceMock<AuthSessionJsonDepsInterfaceMock> mockDeps;
    EXPECT_CALL(mockDeps, JSON_GetStringFromObject)
        .WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mockDeps, ConvertHexStringToBytes)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(UnpackSparkCheck(&json, &info));
    EXPECT_NO_FATAL_FAILURE(UnpackSparkCheck(&json, &info));
    EXPECT_NO_FATAL_FAILURE(UnpackSparkCheck(&json, &info));
}

/*
 * @tc.name: GENERATE_ACCOUNT_HASH_TEST_001
 * @tc.desc: GenerateAccountHash test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, GENERATE_ACCOUNT_HASH_TEST_001, TestSize.Level1)
{
    int64_t accountId = 100;
    char accountHashBuf[SHA_256_HEX_HASH_LEN] = { 0 };
    uint32_t bufLen = SHA_256_HEX_HASH_LEN;
    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    EXPECT_CALL(mocker, SoftBusGenerateStrHash)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mocker, ConvertBytesToHexString)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = GenerateAccountHash(accountId, accountHashBuf, bufLen);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GENERATE_STR_HASH_ERR);

    ret = GenerateAccountHash(accountId, accountHashBuf, bufLen);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR);

    ret = GenerateAccountHash(accountId, accountHashBuf, bufLen);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: PACK_DEVICE_KEY_ID_TEST_001
 * @tc.desc: PackDeviceKeyId test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, PACK_DEVICE_KEY_ID_TEST_001, TestSize.Level1)
{
    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    JsonObj obj;
    (void)memset_s(&obj, sizeof(JsonObj), 0, sizeof(JsonObj));
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    info.deviceKeyId.localDeviceKeyId = AUTH_INVALID_DEVICEKEY_ID;
    EXPECT_NO_FATAL_FAILURE(PackDeviceKeyId(&obj, &info));

    info.deviceKeyId.localDeviceKeyId = TEST_AUTH_ID;
    info.deviceKeyId.remoteDeviceKeyId = AUTH_INVALID_DEVICEKEY_ID;
    EXPECT_NO_FATAL_FAILURE(PackDeviceKeyId(&obj, &info));

    info.deviceKeyId.remoteDeviceKeyId = TEST_AUTH_ID;
    EXPECT_CALL(mocker, JSON_AddInt32ToObject)
        .WillOnce(Return(false));
    EXPECT_NO_FATAL_FAILURE(PackDeviceKeyId(&obj, &info));

    EXPECT_CALL(mocker, JSON_AddInt32ToObject)
        .WillOnce(Return(true))
        .WillOnce(Return(false));
    EXPECT_NO_FATAL_FAILURE(PackDeviceKeyId(&obj, &info));

    EXPECT_CALL(mocker, JSON_AddInt32ToObject)
        .WillRepeatedly(Return(true));
    EXPECT_NO_FATAL_FAILURE(PackDeviceKeyId(&obj, &info));
}

/*
 * @tc.name: TRY_GET_DM_SESSION_KEY_FOR_UNPACK_TEST_001
 * @tc.desc: TryGetDmSessionKeyForUnpack test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, TRY_GET_DM_SESSION_KEY_FOR_UNPACK_TEST_001, TestSize.Level1)
{
    AuthDeviceKeyInfo deviceKey;
    (void)memset_s(&deviceKey, sizeof(AuthDeviceKeyInfo), 0, sizeof(AuthDeviceKeyInfo));
    const char *tmpKey = "testKey";
    EXPECT_EQ(memcpy_s(deviceKey.deviceKey, SESSION_KEY_LENGTH, tmpKey, strlen(tmpKey)), EOK);
    deviceKey.keyLen = strlen(tmpKey);
    deviceKey.keyIndex = 12345;
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    const char *encNormalizedKey = "normalizedKey";
    int64_t authSeq = TEST_AUTH_ID;
    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    EXPECT_CALL(mocker, GetSessionKeyProfile)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int ret = TryGetDmSessionKeyForUnpack(&info, const_cast<char *>(encNormalizedKey), &deviceKey, authSeq);
    EXPECT_EQ(ret, SOFTBUS_AUTH_NORMALIZED_KEY_PROC_ERR);

    EXPECT_CALL(mocker, GetSessionKeyProfile)
        .WillRepeatedly(DoAll(SetArgPointee<1>(*deviceKey.deviceKey),
        SetArgPointee<2>(deviceKey.keyLen), Return(SOFTBUS_OK)));
    ret = TryGetDmSessionKeyForUnpack(&info, const_cast<char *>(encNormalizedKey), &deviceKey, authSeq);
    EXPECT_EQ(ret, SOFTBUS_AUTH_NORMALIZED_KEY_PROC_ERR);
}

/*
 * @tc.name: UNPACK_SK_ID_TEST_001
 * @tc.desc: UnpackSKId test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, UNPACK_SK_ID_TEST_001, TestSize.Level1)
{
    JsonObj obj;
    (void)memset_s(&obj, sizeof(JsonObj), 0, sizeof(JsonObj));
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    EXPECT_CALL(mocker, JSON_GetInt32FromOject)
        .WillOnce(Return(false));
    EXPECT_NO_FATAL_FAILURE(UnpackSKId(&obj, &info));

    int32_t localDeviceKeyId = AUTH_INVALID_DEVICEKEY_ID;
    EXPECT_CALL(mocker, JSON_GetInt32FromOject)
        .WillOnce(DoAll(SetArgPointee<2>(localDeviceKeyId), Return(true)))
        .WillOnce(Return(false));
    EXPECT_NO_FATAL_FAILURE(UnpackSKId(&obj, &info));

    localDeviceKeyId = TEST_AUTH_ID;
    EXPECT_CALL(mocker, JSON_GetInt32FromOject)
        .WillRepeatedly(DoAll(SetArgPointee<2>(localDeviceKeyId), Return(true)));
    EXPECT_NO_FATAL_FAILURE(UnpackSKId(&obj, &info));
}

/*
 * @tc.name: PACK_UDID_ABATEMENT_FLAG_TEST_001
 * @tc.desc: PackUDIDAbatementFlag test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, PACK_UDID_ABATEMENT_FLAG_TEST_001, TestSize.Level1)
{
    JsonObj obj;
    (void)memset_s(&obj, sizeof(JsonObj), 0, sizeof(JsonObj));
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    EXPECT_NO_FATAL_FAILURE(PackUDIDAbatementFlag(&obj, &info));

    EXPECT_CALL(mocker, IsSupportUDIDAbatement)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mocker, IsNeedUDIDAbatement)
        .WillRepeatedly(Return(false));
    EXPECT_NO_FATAL_FAILURE(PackUDIDAbatementFlag(&obj, &info));
}

/*
 * @tc.name: IS_NEED_NORMALIZED_PROCESS_TEST_001
 * @tc.desc: IsNeedNormalizedProcess test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, IS_NEED_NORMALIZED_PROCESS_TEST_001, TestSize.Level1)
{
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    info.isConnectServer = false;
    bool ret = IsNeedNormalizedProcess(&info);
    EXPECT_TRUE(ret);

    info.isConnectServer = true;
    info.deviceKeyId.hasDeviceKeyId = true;
    ret = IsNeedNormalizedProcess(&info);
    EXPECT_TRUE(ret);

    info.deviceKeyId.hasDeviceKeyId = false;
    info.authVersion = AUTH_VERSION_V1;
    ret = IsNeedNormalizedProcess(&info);
    EXPECT_TRUE(ret);

    info.authVersion = AUTH_VERSION_V2;
    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    EXPECT_CALL(mocker, IsTrustedDeviceFromAccess)
        .WillOnce(Return(true));
    ret = IsNeedNormalizedProcess(&info);
    EXPECT_TRUE(ret);

    EXPECT_CALL(mocker, IsTrustedDeviceFromAccess)
        .WillOnce(Return(false));
    ret = IsNeedNormalizedProcess(&info);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: UNPACK_META_PTK_TEST_001
 * @tc.desc: UnpackMetaPtk test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, UNPACK_META_PTK_TEST_001, TestSize.Level1)
{
    const char *remoteMetaPtk = "remoteMetaPtkTest";
    const char *decodePtk = "decodePtkTest";
    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    EXPECT_CALL(mocker, SoftBusBase64Decode)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_NO_FATAL_FAILURE(UnpackMetaPtk(const_cast<char *>(remoteMetaPtk), const_cast<char *>(decodePtk)));

    EXPECT_CALL(mocker, SoftBusBase64Decode)
        .WillOnce(DoAll(SetArgPointee<2>(PTK_DEFAULT_LEN + 1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mocker, LnnDumpRemotePtk)
        .WillRepeatedly(Return());
    EXPECT_NO_FATAL_FAILURE(UnpackMetaPtk(const_cast<char *>(remoteMetaPtk), const_cast<char *>(decodePtk)));

    EXPECT_CALL(mocker, SoftBusBase64Decode)
        .WillOnce(DoAll(SetArgPointee<2>(PTK_DEFAULT_LEN), Return(SOFTBUS_OK)));
    EXPECT_NO_FATAL_FAILURE(UnpackMetaPtk(const_cast<char *>(remoteMetaPtk), const_cast<char *>(decodePtk)));
}

/*
 * @tc.name: UNPACK_PTK_TEST_001
 * @tc.desc: UnpackPtk test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, UNPACK_PTK_TEST_001, TestSize.Level1)
{
    const char *remotePtk = "remotePtkTest";
    const char *decodePtk = "decodePtkTest";
    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    EXPECT_CALL(mocker, SoftBusBase64Decode)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_NO_FATAL_FAILURE(UnpackPtk(const_cast<char *>(remotePtk), const_cast<char *>(decodePtk)));

    EXPECT_CALL(mocker, SoftBusBase64Decode)
        .WillOnce(DoAll(SetArgPointee<2>(PTK_DEFAULT_LEN + 1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mocker, LnnDumpRemotePtk)
        .WillRepeatedly(Return());
    EXPECT_NO_FATAL_FAILURE(UnpackPtk(const_cast<char *>(remotePtk), const_cast<char *>(decodePtk)));

    EXPECT_CALL(mocker, SoftBusBase64Decode)
        .WillOnce(DoAll(SetArgPointee<2>(PTK_DEFAULT_LEN), Return(SOFTBUS_OK)));
    EXPECT_NO_FATAL_FAILURE(UnpackPtk(const_cast<char *>(remotePtk), const_cast<char *>(decodePtk)));
}

/*
 * @tc.name: PACK_CERTIFICATE_INFO_TEST_001
 * @tc.desc: PackCertificateInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, PACK_CERTIFICATE_INFO_TEST_001, TestSize.Level1)
{
    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    int32_t ret = PackCertificateInfo(&json, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    ret = PackCertificateInfo(&json, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(mocker, IsSupportUDIDAbatement)
        .WillRepeatedly(Return(true));
    info.isNeedPackCert = false;
    ret = PackCertificateInfo(&json, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);

    info.isNeedPackCert = true;
    EXPECT_CALL(mocker, JSON_AddBytesToObject)
        .WillRepeatedly(Return(false));
    EXPECT_CALL(mocker, FreeSoftbusChain)
        .WillRepeatedly(Return());
    ret = PackCertificateInfo(&json, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: UNPACK_CERTIFICATE_INFO_TEST_001
 * @tc.desc: UnpackCertificateInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, UNPACK_CERTIFICATE_INFO_TEST_001, TestSize.Level1)
{
    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    int32_t ret = UnpackCertificateInfo(&json, &nodeInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    ret = UnpackCertificateInfo(&json, &nodeInfo, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(mocker, IsSupportUDIDAbatement)
        .WillRepeatedly(Return(true));
    ret = UnpackCertificateInfo(&json, &nodeInfo, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(mocker, IsNeedUDIDAbatement)
        .WillRepeatedly(Return(true));
    ret = UnpackCertificateInfo(&json, &nodeInfo, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(mocker, InitSoftbusChain)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mocker, JSON_GetBytesFromObject)
        .WillRepeatedly(Return(false));
    EXPECT_CALL(mocker, FreeSoftbusChain)
        .WillRepeatedly(Return());
    ret = UnpackCertificateInfo(&json, &nodeInfo, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: UNPACK_CERTIFICATE_INFO_TEST_002
 * @tc.desc: UnpackCertificateInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, UNPACK_CERTIFICATE_INFO_TEST_002, TestSize.Level1)
{
    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    EXPECT_CALL(mocker, IsSupportUDIDAbatement)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mocker, IsNeedUDIDAbatement)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mocker, InitSoftbusChain)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mocker, JSON_GetBytesFromObject)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mocker, FreeSoftbusChain)
        .WillRepeatedly(Return());
    int32_t ret = UnpackCertificateInfo(&json, &nodeInfo, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: FillBroadcastCipherKey_TEST_001
 * @tc.desc: fill broadcast cipherkey test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, FillBroadcastCipherKey_TEST_001, TestSize.Level1)
{
    BroadcastCipherKey cipherKey;
    (void)memset_s(&cipherKey, sizeof(BroadcastCipherKey), 0, sizeof(BroadcastCipherKey));
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_EQ(SOFTBUS_OK, FillBroadcastCipherKey(&cipherKey, &info));
}

/*
 * @tc.name: GetLocalUdidShortHash_TEST_001
 * @tc.desc: test func GetLocalUdidShortHash
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonMockTest, GetLocalUdidShortHash_TEST_001, TestSize.Level1)
{
    NiceMock<AuthSessionJsonDepsInterfaceMock> mocker;
    EXPECT_CALL(mocker, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = 0;
    char localUdidHash[SHA_256_HEX_HASH_LEN] = { 0 };
    ret = GetLocalUdidShortHash(localUdidHash);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR);
}
} // namespace OHOS