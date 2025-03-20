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

#include <gtest/gtest.h>
#include <securec.h>

#include "auth_session_json.c"
#include "auth_session_json_mock.h"
#include "softbus_adapter_errcode.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;
constexpr int32_t PEER_IRK_LEN = 13;
constexpr int32_t PUBLIC_ADDRESS_LEN = 4;
constexpr int32_t CAPABILITY_LEN = 16;
constexpr int32_t DATA_TEST_LEN = 7;
constexpr int32_t TEST_DATA_LEN = 9;
constexpr int32_t TEST_FD = 123;
constexpr char DEVICE_KEY[SESSION_KEY_LENGTH] = "11111";
constexpr char UDID[UDID_BUF_LEN] = "123456789udidtest";
constexpr char UUID_TEST[UUID_BUF_LEN] = "123456789uuidtest";
constexpr char INVALID_UDID[UDID_BUF_LEN] = "\0";
constexpr char NETWORK_ID_TEST[NETWORK_ID_BUF_LEN] = "987654321";
constexpr char UNIFIED_NAME[DEVICE_NAME_BUF_LEN] = "unifiedName";
constexpr char INVALID_UNIFIED_NAME[DEVICE_NAME_BUF_LEN] = "\0";
constexpr char DEVICE_NAME_TEST[DEVICE_NAME_BUF_LEN] = "deviceName";
constexpr char IV_TEST[BROADCAST_IV_LEN] = "123456ivtest";
constexpr uint8_t PEER_IRK[LFINDER_IRK_LEN] = "123456irktest";
constexpr unsigned char PUBLIC_ADDRESS[LFINDER_MAC_ADDR_LEN] = "addr";
constexpr uint8_t STATIC_CAPABILITY[STATIC_CAP_LEN] = "staticCapability";
constexpr char REMOTE_PTK[PTK_DEFAULT_LEN] = "remotePtktest";
constexpr char KEY_TEST[SESSION_KEY_LENGTH] = "123456keytest";
constexpr char TEST_DATA[] = "testdata";

class AuthSessionJsonTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthSessionJsonTest::SetUpTestCase()
{
    int32_t ret = AuthCommonInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

void AuthSessionJsonTest::TearDownTestCase()
{
    AuthCommonDeinit();
}

void AuthSessionJsonTest::SetUp() { }

void AuthSessionJsonTest::TearDown() { }

/*
 @tc.name: PackFastAuthValue_TEST_001
 @tc.desc: PackFastAuthValue test
 @tc.type: FUNC
 @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, PackFastAuthValue_TEST_001, TestSize.Level1)
{
    JsonObj *json = JSON_CreateObject();
    EXPECT_NE(json, nullptr);
    char target[10] = { 0 };
    JSON_AddStringToObject(json, FAST_AUTH, "jsontest");
    OptString(json, DEVICE_ID, target, 10, "");
    OptString(json, FAST_AUTH, target, 10, "");
    int32_t val = 0;
    OptInt(json, P2P_ROLE, &val, 0);
    JSON_AddInt32ToObject(json, SOFTBUS_VERSION_TAG, 123);
    OptInt(json, SOFTBUS_VERSION_TAG, &val, 0);
    int64_t value = 0;
    OptInt64(json, NEW_CONN_CAP, &value, 1);
    JSON_AddInt64ToObject(json, NEW_CONN_CAP, -1);
    OptInt64(json, NEW_CONN_CAP, &value, 1);
    bool result;
    OptBool(json, BLE_P2P, &result, false);
    JSON_AddBoolToObject(json, BLE_P2P, true);
    OptBool(json, BLE_P2P, &result, false);
    JSON_Delete(json);
    JsonObj *obj = JSON_CreateObject();
    EXPECT_NE(obj, nullptr);
    AuthDeviceKeyInfo deviceCommKey;
    (void)memset_s(&deviceCommKey, sizeof(AuthDeviceKeyInfo), 0, sizeof(AuthDeviceKeyInfo));
    EXPECT_EQ(memcpy_s(deviceCommKey.deviceKey, SESSION_KEY_LENGTH, DEVICE_KEY, strlen(DEVICE_KEY)), EOK);
    deviceCommKey.keyLen = 5;
    deviceCommKey.keyIndex = 12345;
    AuthSessionJsonInterfaceMock mock;
    EXPECT_CALL(mock, LnnEncryptAesGcm).WillOnce(Return(SOFTBUS_ENCRYPT_ERR));
    int32_t ret = PackFastAuthValue(obj, &deviceCommKey);
    EXPECT_EQ(ret, SOFTBUS_ENCRYPT_ERR);
    EXPECT_CALL(mock, LnnEncryptAesGcm).WillOnce(Return(SOFTBUS_OK));
    ret = PackFastAuthValue(obj, &deviceCommKey);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    uint8_t *data = (uint8_t *)SoftBusCalloc(TEST_DATA_LEN);
    ASSERT_TRUE(data != nullptr);
    ret = memcpy_s(data, TEST_DATA_LEN, TEST_DATA, TEST_DATA_LEN);
    EXPECT_EQ(ret, EOK);
    EXPECT_CALL(mock, LnnEncryptAesGcm).WillOnce(DoAll(SetArgPointee<2>(data), Return(SOFTBUS_OK)));
    ret = PackFastAuthValue(obj, &deviceCommKey);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    JSON_Delete(obj);
}

/*
 @tc.name: GetUdidOrShortHash_TEST_001
 @tc.desc: GetUdidOrShortHash test
 @tc.type: FUNC
 @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, GetUdidOrShortHash_TEST_001, TestSize.Level1)
{
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    info.isServer = false;
    info.connInfo.type = AUTH_LINK_TYPE_ENHANCED_P2P;
    ASSERT_TRUE(memcpy_s(info.connInfo.info.ipInfo.udid, UDID_BUF_LEN, UDID, strlen(UDID)) == EOK);
    char udidHashHexStr[SHA_256_HEX_HASH_LEN] = { 0 };
    AuthSessionJsonInterfaceMock mock;
    EXPECT_CALL(mock, SoftBusGenerateStrHash).WillOnce(Return(SOFTBUS_ENCRYPT_ERR));
    bool ret = GetUdidOrShortHash(&info, udidHashHexStr, SHA_256_HEX_HASH_LEN);
    EXPECT_EQ(ret, false);
    EXPECT_CALL(mock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    ret = GetUdidOrShortHash(&info, udidHashHexStr, SHA_256_HEX_HASH_LEN);
    EXPECT_EQ(ret, true);
    info.connInfo.type = AUTH_LINK_TYPE_SESSION;
    ret = GetUdidOrShortHash(&info, udidHashHexStr, SHA_256_HEX_HASH_LEN);
    EXPECT_EQ(ret, true);
    info.isServer = true;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    ASSERT_TRUE(memcpy_s(info.udid, UDID_BUF_LEN, UDID, strlen(UDID)) == EOK);
    ret = GetUdidOrShortHash(&info, udidHashHexStr, SHA_256_HEX_HASH_LEN);
    EXPECT_EQ(ret, true);
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    ASSERT_TRUE(memcpy_s(info.udid, UDID_BUF_LEN, INVALID_UDID, strlen(INVALID_UDID)) == EOK);
    ret = GetUdidOrShortHash(&info, udidHashHexStr, SHA_256_HEX_HASH_LEN);
    EXPECT_EQ(ret, false);
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    ret = GetUdidOrShortHash(&info, udidHashHexStr, SHA_256_HEX_HASH_LEN);
    EXPECT_EQ(ret, false);
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    ret = GetUdidOrShortHash(&info, udidHashHexStr, SHA_256_HEX_HASH_LEN);
    EXPECT_EQ(ret, true);
}

/*
 @tc.name: GetEnhancedP2pAuthKey_TEST_001
 @tc.desc: GetEnhancedP2pAuthKey test
 @tc.type: FUNC
 @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, GetEnhancedP2pAuthKey_TEST_001, TestSize.Level1)
{
    AuthSessionInfo info;
    AuthDeviceKeyInfo deviceKey;
    AuthSessionJsonInterfaceMock mock;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    ASSERT_TRUE(memcpy_s(info.udid, UDID_BUF_LEN, UDID, strlen(UDID)) == EOK);
    EXPECT_CALL(mock, AuthFindDeviceKey).WillOnce(Return(SOFTBUS_AUTH_NOT_FOUND));
    info.isServer = true;
    info.isSupportFastAuth = true;
    info.isNeedFastAuth = false;
    PackFastAuth(nullptr, &info);
    int32_t ret =GetFastAuthKey("hashtest", &info, &deviceKey);
    EXPECT_EQ(ret, SOFTBUS_AUTH_NOT_FOUND);
    info.isNeedFastAuth = true;
    PackFastAuth(nullptr, &info);
    EXPECT_CALL(mock, AuthFindDeviceKey).WillOnce(Return(SOFTBUS_OK));
    ret = GetFastAuthKey("hashtest", &info, &deviceKey);
    EXPECT_EQ(ret, SOFTBUS_OK);
    info.connInfo.type = AUTH_LINK_TYPE_ENHANCED_P2P;
    info.isSupportFastAuth = false;
    EXPECT_CALL(mock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnEncryptAesGcm).WillRepeatedly(Return(SOFTBUS_OK));
    PackFastAuth(nullptr, &info);
    EXPECT_CALL(mock, AuthFindLatestNormalizeKey).WillRepeatedly(Return(SOFTBUS_OK));
    ret = GetFastAuthKey("hashtest", &info, &deviceKey);
    EXPECT_EQ(ret, SOFTBUS_OK);
    info.isServer = false;
    info.isNeedFastAuth = true;
    PackFastAuth(nullptr, &info);
    EXPECT_CALL(mock, AuthFindLatestNormalizeKey).WillRepeatedly(Return(SOFTBUS_AUTH_NOT_FOUND));
    EXPECT_CALL(mock, AuthFindDeviceKey).WillOnce(Return(SOFTBUS_OK));
    ret = GetFastAuthKey("hashtest", &info, &deviceKey);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_CALL(mock, AuthFindDeviceKey).WillRepeatedly(Return(SOFTBUS_AUTH_NOT_FOUND));
    ret = GetFastAuthKey("hashtest", &info, &deviceKey);
    EXPECT_EQ(ret, SOFTBUS_AUTH_NOT_FOUND);
}

/*
 @tc.name: VerifySessionInfoIdType_TEST_001
 @tc.desc: VerifySessionInfoIdType test
 @tc.type: FUNC
 @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, VerifySessionInfoIdType_TEST_001, TestSize.Level1)
{
    AuthSessionInfo info;
    const char *encryptedFastAuth = "encryptedFastAuth";
    AuthDeviceKeyInfo deviceKey;
    (void)memset_s(&deviceKey, sizeof(AuthDeviceKeyInfo), 0, sizeof(AuthDeviceKeyInfo));
    ASSERT_TRUE(memcpy_s(deviceKey.deviceKey, SESSION_KEY_LENGTH, DEVICE_KEY, strlen(DEVICE_KEY)) == EOK);
    deviceKey.keyLen = 5;
    deviceKey.keyIndex = 12345;
    AuthSessionJsonInterfaceMock mock;
    EXPECT_CALL(mock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, IsPotentialTrustedDevice).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, AuthFindLatestNormalizeKey).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, IsFeatureSupport).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AuthFindDeviceKey).WillRepeatedly(Return(SOFTBUS_OK));
    ParseFastAuthValue(&info, encryptedFastAuth, &deviceKey);
    JsonObj *obj = JSON_CreateObject();
    EXPECT_NE(obj, nullptr);
    JSON_AddStringToObject(obj, FAST_AUTH, encryptedFastAuth);
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    EXPECT_EQ(memcpy_s(info.udid, UDID_BUF_LEN, UDID, strlen(UDID)), EOK);
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    UnpackFastAuth(obj, &info);
    info.connInfo.type = AUTH_LINK_TYPE_ENHANCED_P2P;
    UnpackFastAuth(obj, &info);
    NodeInfo nodeInfo;
    nodeInfo.feature = 127;
    PackCompressInfo(obj, &nodeInfo);
    nodeInfo.feature = 0;
    PackCompressInfo(obj, &nodeInfo);
    PackWifiSinglePassInfo(obj, &info);
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    PackWifiSinglePassInfo(obj, &info);
    info.idType = EXCHANGE_NETWORKID;
    bool ret = VerifySessionInfoIdType(&info, obj, const_cast<char *>(NETWORK_ID_TEST), const_cast<char *>(UDID));
    EXPECT_EQ(ret, true);
    info.idType = EXCHANGE_UDID;
    ret = VerifySessionInfoIdType(&info, obj, const_cast<char *>(NETWORK_ID_TEST), const_cast<char *>(UDID));
    EXPECT_EQ(ret, true);
    JSON_Delete(obj);
}

/*
 @tc.name: PackDeviceIdJson_TEST_001
 @tc.desc: PackDeviceIdJson test
 @tc.type: FUNC
 @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, PackDeviceIdJson_TEST_001, TestSize.Level1)
{
    AuthSessionInfo info;
    NodeInfo nodeInfo;
    int64_t authSeq = 1;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    info.version = SOFTBUS_OLD_V1;
    info.idType = EXCHANGE_UDID;
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    info.isServer = true;
    char *deviceId = PackDeviceIdJson(nullptr, authSeq);
    EXPECT_EQ(deviceId, nullptr);
    AuthSessionJsonInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_NETWORK_NOT_FOUND));
    deviceId = PackDeviceIdJson(&info, authSeq);
    EXPECT_EQ(deviceId, nullptr);
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, FindAuthPreLinkNodeById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetLocalNodeInfo).WillRepeatedly(Return(&nodeInfo));
    EXPECT_CALL(mock, IsFeatureSupport).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, IsSupportFeatureByCapaBit).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, IsSupportUDIDAbatement).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, IsNeedUDIDAbatement).WillRepeatedly(Return(true));
    deviceId = PackDeviceIdJson(&info, authSeq);
    EXPECT_NE(deviceId, nullptr);
    JSON_Free(deviceId);
    info.isServer = false;
    deviceId = PackDeviceIdJson(&info, authSeq);
    EXPECT_NE(deviceId, nullptr);
    JSON_Free(deviceId);
    info.connInfo.type = AUTH_LINK_TYPE_BR;
    deviceId = PackDeviceIdJson(&info, authSeq);
    EXPECT_NE(deviceId, nullptr);
    JSON_Free(deviceId);
}

/*
 @tc.name: UnpackWifiSinglePassInfo_TEST_001
 @tc.desc: UnpackWifiSinglePassInfo test
 @tc.type: FUNC
 @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, UnpackWifiSinglePassInfo_TEST_001, TestSize.Level1)
{
    AuthSessionInfo info;
    info.connInfo.type = AUTH_LINK_TYPE_BR;
    info.connId = 12;
    JsonObj *obj = JSON_CreateObject();
    EXPECT_NE(obj, nullptr);
    JSON_AddStringToObject(obj, FAST_AUTH, "encryptedFastAuth");
    bool ret = UnpackWifiSinglePassInfo(obj, &info);
    EXPECT_EQ(ret, true);
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    AuthSessionJsonInterfaceMock mock;
    EXPECT_CALL(mock, GetFd).WillRepeatedly(Return(TEST_FD));
    ret = UnpackWifiSinglePassInfo(obj, &info);
    EXPECT_EQ(ret, true);
    SoftBusSockAddr addr;
    addr.saFamily = SOFTBUS_AF_INET;
    EXPECT_CALL(mock, SoftBusSocketGetPeerName).WillRepeatedly(DoAll(SetArgPointee<1>(addr), Return(SOFTBUS_OK)));
    ret = UnpackWifiSinglePassInfo(obj, &info);
    EXPECT_EQ(ret, true);
    EXPECT_CALL(mock, SoftBusGenerateStrHash).WillOnce(Return(SOFTBUS_OK));
    ret = UnpackWifiSinglePassInfo(obj, &info);
    EXPECT_EQ(ret, true);
    JSON_AddStringToObject(obj, DEV_IP_HASH_TAG, "12345678");
    ret = UnpackWifiSinglePassInfo(obj, &info);
    EXPECT_EQ(ret, false);
    JSON_Delete(obj);
}

/*
 @tc.name: SetExchangeIdTypeAndValue_TEST_001
 @tc.desc: SetExchangeIdTypeAndValue test
 @tc.type: FUNC
 @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, SetExchangeIdTypeAndValue_TEST_001, TestSize.Level1)
{
    JsonObj *obj1 = JSON_CreateObject();
    EXPECT_NE(obj1, nullptr);
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    info.idType = EXCHANGE_UDID;
    JSON_AddInt32ToObject(obj1, SOFTBUS_VERSION_TAG, 123);
    int32_t ret = SetExchangeIdTypeAndValue(nullptr, &info);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SetExchangeIdTypeAndValue(obj1, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SetExchangeIdTypeAndValue(obj1, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    JSON_AddInt32ToObject(obj1, EXCHANGE_ID_TYPE, EXCHANGE_UDID);
    ret = SetExchangeIdTypeAndValue(obj1, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    JSON_Delete(obj1);
    JsonObj *obj2 = JSON_CreateObject();
    EXPECT_NE(obj2, nullptr);
    JSON_AddInt32ToObject(obj2, EXCHANGE_ID_TYPE, EXCHANGE_NETWORKID);
    info.isServer = true;
    AuthSessionJsonInterfaceMock mock;
    EXPECT_CALL(mock, LnnRetrieveDeviceInfoByNetworkId).WillRepeatedly(Return(SOFTBUS_OK));
    ret = SetExchangeIdTypeAndValue(obj2, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    info.isServer = false;
    ret = SetExchangeIdTypeAndValue(obj2, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    info.idType = EXCHANGE_NETWORKID;
    ret = SetExchangeIdTypeAndValue(obj2, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    JSON_Delete(obj2);
    JsonObj *obj3 = JSON_CreateObject();
    EXPECT_NE(obj3, nullptr);
    JSON_AddInt32ToObject(obj3, EXCHANGE_ID_TYPE, EXCHANGE_FAIL);
    ret = SetExchangeIdTypeAndValue(obj3, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    JSON_Delete(obj3);
}

/*
 @tc.name: UnpackDeviceIdJson_TEST_001
 @tc.desc: UnpackDeviceIdJson test
 @tc.type: FUNC
 @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, UnpackDeviceIdJson_TEST_001, TestSize.Level1)
{
    int64_t authSeq = 1;
    JsonObj *obj = JSON_CreateObject();
    EXPECT_NE(obj, nullptr);
    AuthSessionInfo info;
    int32_t ret = UnpackDeviceIdJson(nullptr, 0, &info, authSeq);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    JSON_AddInt32ToObject(obj, EXCHANGE_ID_TYPE, EXCHANGE_FAIL);
    char *msg = JSON_PrintUnformatted(obj);
    ret = UnpackDeviceIdJson(msg, strlen(msg), &info, authSeq);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    if (msg != nullptr) {
        JSON_Free(msg);
    }
    JSON_Delete(obj);
    JsonObj *obj1 = JSON_CreateObject();
    EXPECT_NE(obj1, nullptr);
    JSON_AddStringToObject(obj1, CMD_TAG, CMD_GET_AUTH_INFO);
    JSON_AddStringToObject(obj1, DATA_TAG, "123456");
    JSON_AddStringToObject(obj1, DEVICE_ID_TAG, "654321");
    JSON_AddInt32ToObject(obj1, DATA_BUF_SIZE_TAG, PACKET_SIZE);
    JSON_AddInt32ToObject(obj1, SOFTBUS_VERSION_TAG, 123);
    JSON_AddInt32ToObject(obj1, EXCHANGE_ID_TYPE, EXCHANGE_UDID);
    JSON_AddStringToObject(obj1, SUPPORT_INFO_COMPRESS, TRUE_STRING_TAG);
    char *msg1 = JSON_PrintUnformatted(obj1);
    info.connInfo.type = AUTH_LINK_TYPE_BR;
    ret = UnpackDeviceIdJson(msg1, strlen(msg1), &info, authSeq);
    EXPECT_EQ(ret, SOFTBUS_CMP_FAIL);
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    info.isServer = false;
    ret = UnpackDeviceIdJson(msg1, strlen(msg1), &info, authSeq);
    EXPECT_EQ(ret, SOFTBUS_CMP_FAIL);
    info.isConnectServer = true;
    ret = UnpackDeviceIdJson(msg1, strlen(msg1), &info, authSeq);
    EXPECT_EQ(ret, SOFTBUS_OK);
    if (msg1 != nullptr) {
        JSON_Free(msg1);
    }
    JSON_Delete(obj1);
}

/*
 @tc.name: PackCommonDevInfo_TEST_001
 @tc.desc: PackCommonDevInfo test
 @tc.type: FUNC
 @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, PackCommonDevInfo_TEST_001, TestSize.Level1)
{
    JsonObj *json = JSON_CreateObject();
    EXPECT_NE(json, nullptr);
    NodeInfo info;
    AuthSessionJsonInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetDeviceName).WillRepeatedly(Return(nullptr));
    EXPECT_CALL(mock, LnnGetUnifiedDeviceName).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnConvertIdToDeviceType).WillRepeatedly(Return(nullptr));
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_EQ(memcpy_s(info.deviceInfo.unifiedName, DEVICE_NAME_BUF_LEN, INVALID_UNIFIED_NAME,
    strlen(INVALID_UNIFIED_NAME)), EOK);
    EXPECT_EQ(memcpy_s(info.uuid, UUID_BUF_LEN, INVALID_UDID, strlen(INVALID_UDID)), EOK);
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = PackCommonDevInfo(json, &info, true);
    EXPECT_EQ(ret, SOFTBUS_AUTH_PACK_DEVINFO_FAIL);
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    ret = PackCommonDevInfo(json, &info, true);
    EXPECT_EQ(ret, SOFTBUS_AUTH_PACK_DEVINFO_FAIL);
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_EQ(memcpy_s(info.deviceInfo.unifiedName, DEVICE_NAME_BUF_LEN, UNIFIED_NAME, strlen(UNIFIED_NAME)), EOK);
    EXPECT_EQ(memcpy_s(info.networkId, NETWORK_ID_BUF_LEN, NETWORK_ID_TEST, strlen(NETWORK_ID_TEST)), EOK);
    EXPECT_EQ(
    memcpy_s(info.deviceInfo.deviceName, DEVICE_NAME_BUF_LEN, DEVICE_NAME_TEST, strlen(DEVICE_NAME_TEST)), EOK);
    info.deviceInfo.deviceTypeId = 12;
    EXPECT_EQ(memcpy_s(info.uuid, UUID_BUF_LEN, UUID_TEST, strlen(UUID_TEST)), EOK);
    ret = PackCommonDevInfo(json, &info, false);
    EXPECT_EQ(ret, SOFTBUS_AUTH_PACK_DEVINFO_FAIL);
    JSON_Delete(json);
}

/*
 @tc.name: UnpackCipherRpaInfo_TEST_001
 @tc.desc: UnpackCipherRpaInfo test
 @tc.type: FUNC
 @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, UnpackCipherRpaInfo_TEST_001, TestSize.Level1)
{
    JsonObj *json = JSON_CreateObject();
    EXPECT_NE(json, nullptr);
    AuthSessionJsonInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetUnifiedDeviceName).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnConvertIdToDeviceType).WillRepeatedly(Return(nullptr));
    (void)JSON_AddStringToObject(json, BROADCAST_CIPHER_KEY, "cipherKeyTest");
    (void)JSON_AddStringToObject(json, BROADCAST_CIPHER_IV, "cipherIv");
    (void)JSON_AddStringToObject(json, IRK, "peerIrk");
    (void)JSON_AddStringToObject(json, PUB_MAC, "pubMac");
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_EQ(memcpy_s(info.cipherInfo.key, SESSION_KEY_LENGTH, KEY_TEST, strlen(KEY_TEST)), EOK);
    EXPECT_EQ(memcpy_s(info.cipherInfo.iv, BROADCAST_IV_LEN, IV_TEST, strlen(IV_TEST)), EOK);
    EXPECT_EQ(memcpy_s(info.rpaInfo.peerIrk, LFINDER_IRK_LEN, PEER_IRK, PEER_IRK_LEN), EOK);
    EXPECT_EQ(memcpy_s(info.rpaInfo.publicAddress, LFINDER_MAC_ADDR_LEN, PUBLIC_ADDRESS, PUBLIC_ADDRESS_LEN), EOK);
    UnpackCipherRpaInfo(json, &info);
    JSON_Delete(json);
    JsonObj *json1 = JSON_CreateObject();
    EXPECT_NE(json1, nullptr);
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    int32_t ret = PackCommon(json1, &info, SOFTBUS_OLD_V2, false);
    EXPECT_EQ(ret, SOFTBUS_AUTH_PACK_DEVINFO_FAIL);
    ret = PackCommon(json1, &info, SOFTBUS_NEW_V1, false);
    EXPECT_EQ(ret, SOFTBUS_AUTH_PACK_DEVINFO_FAIL);
    JSON_Delete(json1);
}

/*
 @tc.name: UnpackWifiDirectInfo_TEST_001
 @tc.desc: UnpackWifiDirectInfo test
 @tc.type: FUNC
 @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, UnpackWifiDirectInfo_TEST_001, TestSize.Level1)
{
    JsonObj *json = JSON_CreateObject();
    EXPECT_NE(json, nullptr);
    (void)JSON_AddStringToObject(json, IRK, "peerIrk");
    NodeInfo info;
    AuthSessionJsonInterfaceMock mock;
    EXPECT_CALL(mock, LnnConvertDeviceTypeToId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnHasDiscoveryType).WillRepeatedly(Return(false));
    EXPECT_CALL(mock, LnnGetAuthPort).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetSessionPort).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetProxyPort).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetUnifiedDeviceName).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnConvertIdToDeviceType).WillRepeatedly(Return(nullptr));
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_EQ(memcpy_s(info.staticCapability, STATIC_CAP_LEN, STATIC_CAPABILITY, CAPABILITY_LEN), EOK);
    UnpackWifiDirectInfo(json, &info, false);
    JSON_AddInt32ToObject(json, STATIC_CAP_LENGTH, 10);
    UnpackWifiDirectInfo(json, &info, false);
    JSON_AddStringToObject(json, STATIC_CAP, "staticCap");
    UnpackWifiDirectInfo(json, &info, false);
    JSON_AddStringToObject(json, PTK, "encodePtk");
    UnpackWifiDirectInfo(json, &info, false);
    EXPECT_EQ(memcpy_s(info.remotePtk, PTK_DEFAULT_LEN, REMOTE_PTK, strlen(REMOTE_PTK)), EOK);
    UnpackWifiDirectInfo(json, &info, false);
    UnpackCommon(json, &info, SOFTBUS_OLD_V1, true);
    JSON_AddStringToObject(json, DEVICE_TYPE, "TV");
    JSON_AddStringToObject(json, DEVICE_UUID, "123456");
    JSON_AddInt64ToObject(json, NEW_CONN_CAP, -1);
    UnpackCommon(json, &info, SOFTBUS_OLD_V1, true);
    UnpackCommon(json, &info, SOFTBUS_NEW_V1, false);
    JSON_AddStringToObject(json, NODE_ADDR, "127.0.0.0");
    UnpackCommon(json, &info, SOFTBUS_NEW_V1, false);
    char buf[10] = { 0 };
    int32_t ret = GetBtDiscTypeString(nullptr, buf, 10);
    EXPECT_EQ(ret, SOFTBUS_OK);
    info.discoveryType = 11;
    ret = GetBtDiscTypeString(&info, buf, 10);
    EXPECT_EQ(ret, SOFTBUS_OK);
    info.discoveryType = 15;
    ret = UnpackBt(json, &info, SOFTBUS_NEW_V1, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    JSON_AddInt64ToObject(json, TRANSPORT_PROTOCOL, 3);
    ret = UnpackBt(json, &info, SOFTBUS_NEW_V1, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = PackWiFi(json, &info, SOFTBUS_NEW_V1, false);
    EXPECT_EQ(ret, SOFTBUS_AUTH_PACK_DEVINFO_FAIL);
    JSON_Delete(json);
}

/*
 @tc.name: CheckBusVersion_TEST_001
 @tc.desc: CheckBusVersion test
 @tc.type: FUNC
 @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, CheckBusVersion_TEST_001, TestSize.Level1)
{
    JsonObj *json1 = JSON_CreateObject();
    EXPECT_NE(json1, nullptr);
    JSON_AddInt32ToObject(json1, BUS_MAX_VERSION, -1);
    JSON_AddInt32ToObject(json1, BUS_MIN_VERSION, -1);
    EXPECT_NE(CheckBusVersion(json1), SOFTBUS_OK);
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_NE(UnpackWiFi(json1, &info, SOFTBUS_OLD_V1, false), SOFTBUS_OK);
    JSON_Delete(json1);
    JsonObj *json = JSON_CreateObject();
    EXPECT_NE(json, nullptr);
    JSON_AddInt32ToObject(json, BUS_MAX_VERSION, 3);
    JSON_AddInt32ToObject(json, BUS_MIN_VERSION, 0);
    EXPECT_TRUE(CheckBusVersion(json) == 2);
    EXPECT_TRUE(UnpackWiFi(json, &info, SOFTBUS_OLD_V1, false) == SOFTBUS_OK);
    JSON_AddInt64ToObject(json, TRANSPORT_PROTOCOL, 63);
    JSON_AddStringToObject(json, BLE_OFFLINE_CODE, "123");
    EXPECT_TRUE(UnpackWiFi(json, &info, SOFTBUS_OLD_V1, false) == SOFTBUS_OK);
    JSON_Delete(json);
}

/*
 @tc.name: PackDeviceInfoBtV1_TEST_001
 @tc.desc: PackDeviceInfoBtV1 test
 @tc.type: FUNC
 @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, PackDeviceInfoBtV1_TEST_001, TestSize.Level1)
{
    NodeInfo info;
    AuthSessionJsonInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetBtMac).WillOnce(Return(nullptr));
    EXPECT_CALL(mock, LnnGetP2pMac).WillOnce(Return(nullptr));
    int32_t ret = PackDeviceInfoBtV1(nullptr, &info, false);
    EXPECT_EQ(ret, SOFTBUS_AUTH_PACK_DEVINFO_FAIL);
    JsonObj *json = JSON_CreateObject();
    EXPECT_NE(json, nullptr);
    EXPECT_CALL(mock, LnnGetBtMac).WillRepeatedly(Return("11:22:33:44:55"));
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    ret = PackDeviceInfoBtV1(json, &info, false);
    EXPECT_EQ(ret, SOFTBUS_AUTH_PACK_DEVINFO_FAIL);
    ret = UnpackDeviceInfoBtV1(json, &info);
    EXPECT_EQ(ret, SOFTBUS_AUTH_UNPACK_DEVINFO_FAIL);
    JSON_AddStringToObject(json, DEVICE_NAME, "testname");
    ret = UnpackDeviceInfoBtV1(json, &info);
    EXPECT_EQ(ret, SOFTBUS_AUTH_UNPACK_DEVINFO_FAIL);
    JSON_AddStringToObject(json, DEVICE_TYPE, "TV");
    ret = UnpackDeviceInfoBtV1(json, &info);
    EXPECT_EQ(ret, SOFTBUS_AUTH_UNPACK_DEVINFO_FAIL);
    JSON_AddStringToObject(json, DEVICE_UDID, "123456");
    JSON_AddStringToObject(json, UUID, "123456");
    JSON_AddStringToObject(json, BR_MAC_ADDR, "11:22:33:44:55");
    JSON_AddInt64ToObject(json, NEW_CONN_CAP, -1);
    ret = UnpackDeviceInfoBtV1(json, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    JSON_Delete(json);
}

/*
 @tc.name: UnpackDeviceInfoMessage_TEST_001
 @tc.desc: UnpackDeviceInfoMessage test
 @tc.type: FUNC
 @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, UnpackDeviceInfoMessage_TEST_001, TestSize.Level1)
{
    DevInfoData devInfo;
    NodeInfo nodeInfo;
    AuthSessionInfo info;
    AuthSessionJsonInterfaceMock mock;
    EXPECT_CALL(mock, IsSupportUDIDAbatement).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, IsNeedUDIDAbatement).WillRepeatedly(Return(false));
    EXPECT_CALL(mock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, IsFeatureSupport).WillRepeatedly(Return(false));
    (void)memset_s(&devInfo, sizeof(DevInfoData), 0, sizeof(DevInfoData));
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    JsonObj *obj = JSON_CreateObject();
    EXPECT_NE(obj, nullptr);
    JSON_AddInt32ToObject(obj, EXCHANGE_ID_TYPE, EXCHANGE_FAIL);
    char *msg = JSON_PrintUnformatted(obj);
    devInfo.msg = msg;
    devInfo.len = strlen(msg);
    devInfo.linkType = AUTH_LINK_TYPE_BLE;
    EXPECT_TRUE(UnpackDeviceInfoMessage(&devInfo, &nodeInfo, false, &info) == SOFTBUS_OK);
    devInfo.linkType = AUTH_LINK_TYPE_WIFI;
    nodeInfo.feature = 511;
    EXPECT_NE(UnpackDeviceInfoMessage(&devInfo, &nodeInfo, false, &info), SOFTBUS_OK);
    JSON_Delete(obj);
}

/*
 @tc.name: PACK_FAST_AUTH_VALUE_TEST_001
 @tc.desc: Pack fast auth value test
 @tc.type: FUNC
 @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, PACK_FAST_AUTH_VALUE_TEST_001, TestSize.Level1)
{
    AuthDeviceKeyInfo deviceCommKey = { 0 };
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(obj, nullptr);
    uint32_t keyLen = 0;
    deviceCommKey.keyLen = keyLen;
    AuthSessionJsonInterfaceMock mock;
    EXPECT_CALL(mock, LnnEncryptAesGcm).WillRepeatedly(Return(SOFTBUS_OK));
    uint64_t ret = PackFastAuthValue(obj, &deviceCommKey);
    EXPECT_NE(ret, SOFTBUS_OK);
    JSON_Delete(obj);
}
/*
 @tc.name: CHECK_BUS_VERSION_TEST_001
 @tc.desc: check bus version test
 @tc.type: FUNC
 @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, CHECK_BUS_VERSION_TEST_001, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    if (obj == NULL) {
        return;
    }

    NodeInfo *info = (NodeInfo *)SoftBusCalloc(sizeof(NodeInfo));
    if (info == NULL) {
        JSON_Delete(obj);
    return;
    }
    (void)memset_s(info, sizeof(NodeInfo), 0, sizeof(NodeInfo));

    SoftBusVersion version = SOFTBUS_NEW_V1;
    if (!JSON_AddInt32ToObject(obj, "CODE", (int32_t)1) || !JSON_AddInt32ToObject(obj, "BUS_MAX_VERSION", (int32_t)2) ||
        !JSON_AddInt32ToObject(obj, "BUS_MIN_VERSION", (int32_t)1) ||
        !JSON_AddInt32ToObject(obj, "AUTH_PORT", (int32_t)8710) ||
        !JSON_AddInt32ToObject(obj, "SESSION_PORT", (int32_t)26) ||
        !JSON_AddInt32ToObject(obj, "PROXY_PORT", (int32_t)80) || !JSON_AddStringToObject(obj, "DEV_IP", "127.0.0.1")) {
        JSON_Delete(obj);
        return;
    }
    JSON_AddStringToObject(obj, BLE_OFFLINE_CODE, "10244");

    info->connectInfo.authPort = 8710;
    info->connectInfo.sessionPort = 26;
    info->connectInfo.proxyPort = 80;
    info->supportedProtocols = LNN_PROTOCOL_BR;
    int32_t ret = UnpackWiFi(obj, info, version, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    JSON_AddInt32ToObject(obj, "BUS_MAX_VERSION", (int32_t)-1);
    ret = UnpackWiFi(obj, info, version, false);
    EXPECT_NE(ret, SOFTBUS_OK);

    (void)JSON_AddStringToObject(obj, "BROADCAST_CIPHER_KEY", "1222222222");
    (void)JSON_AddStringToObject(obj, "BROADCAST_CIPHER_IV", "1222222222");
    (void)JSON_AddStringToObject(obj, "IRK", "1222222222");
    (void)JSON_AddStringToObject(obj, "PUB_MAC", "1222222222");

    JSON_AddStringToObject(obj, "MASTER_UDID", "1122334554444");
    JSON_AddStringToObject(obj, "NODE_ADDR", "1122334554444");
    UnpackCommon(obj, info, version, false);
    version = SOFTBUS_OLD_V1;
    JSON_AddInt32ToObject(obj, "MASTER_WEIGHT", (int32_t)10);
    UnpackCommon(obj, info, version, true);
    UnpackCipherRpaInfo(obj, info);
    JSON_Delete(obj);
    SoftBusFree(info);
}

/*
 @tc.name: PACK_FAST_AUTH_VALUE_TEST_002
 @tc.desc: PackFastAuthValue test
 @tc.type: FUNC
 @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, PACK_FAST_AUTH_VALUE_TEST_002, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    EXPECT_NE(obj, nullptr);
    AuthDeviceKeyInfo deviceCommKey;
    AuthSessionJsonInterfaceMock mock;
    EXPECT_CALL(mock, LnnEncryptAesGcm).WillRepeatedly(Return(SOFTBUS_OK));
    (void)memset_s(&deviceCommKey, sizeof(AuthDeviceKeyInfo), 0, sizeof(AuthDeviceKeyInfo));
    int32_t ret = SoftBusGenerateRandomArray(deviceCommKey.deviceKey, SESSION_KEY_LENGTH);
    EXPECT_EQ(ret, SOFTBUS_OK);
    deviceCommKey.keyLen = SESSION_KEY_LENGTH;
    deviceCommKey.keyIndex = 12345;
    ret = PackFastAuthValue(obj, &deviceCommKey);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    JSON_Delete(obj);
}

/*
 @tc.name: GET_UDID_SHORT_HASH_TEST_001
 @tc.desc: GetUdidShortHash test
 @tc.type: FUNC
 @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, GET_UDID_SHORT_HASH_TEST_001, TestSize.Level1)
{
    AuthSessionInfo info = {
        .connInfo.type = AUTH_LINK_TYPE_BR,
        .isServer = true,
    };
    uint32_t bufLen = UDID_SHORT_HASH_HEX_STR;
    char udidHash[SHORT_UDID_HASH_HEX_LEN + 1];
    AuthSessionJsonInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetUdidByBrMac).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(false, GetUdidShortHash(nullptr, nullptr, bufLen));
    EXPECT_EQ(false, GetUdidShortHash(&info, nullptr, bufLen));
    EXPECT_EQ(false, GetUdidShortHash(&info, udidHash, bufLen));
    bufLen++;
    EXPECT_EQ(true, GetUdidShortHash(&info, udidHash, bufLen));
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    EXPECT_EQ(true, GetUdidShortHash(&info, udidHash, bufLen));
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    EXPECT_EQ(true, GetUdidShortHash(&info, udidHash, bufLen));
    info.connInfo.type = AUTH_LINK_TYPE_P2P;
    EXPECT_EQ(false, GetUdidShortHash(&info, udidHash, bufLen));
    info.isServer = false;
    EXPECT_EQ(true, GetUdidShortHash(&info, udidHash, bufLen));
    ASSERT_TRUE(memcpy_s(info.udid, UDID_BUF_LEN, UDID, strlen(UDID)) == EOK);
    EXPECT_EQ(true, GetUdidShortHash(&info, udidHash, bufLen));
}

/*
 @tc.name: PACK_NORMALIZED_KEY_VALUE_TEST_001
 @tc.desc: PackNormalizedKeyValue test
 @tc.type: FUNC
 @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, PACK_NORMALIZED_KEY_VALUE_TEST_001, TestSize.Level1)
{
    SessionKey sessionKey = {
        .len = SESSION_KEY_LENGTH,
    };
    AuthSessionJsonInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetUdidByBrMac).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AuthFindLatestNormalizeKey).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnEncryptAesGcm).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(SOFTBUS_OK, SoftBusGenerateRandomArray(sessionKey.value, SESSION_KEY_LENGTH));
    JsonObj *obj = JSON_CreateObject();
    EXPECT_NE(obj, nullptr);
    AuthSessionInfo info = {
        .isNeedFastAuth = false,
        .isServer = false,
        .normalizedType = NORMALIZED_KEY_ERROR,
        .localState = AUTH_STATE_WAIT,
        .connInfo.type = AUTH_LINK_TYPE_WIFI,
        .normalizedKey = nullptr,
    };
    PackNormalizedKey(obj, &info);
    info.isNeedFastAuth = true;
    PackNormalizedKey(obj, &info);
    info.isServer = true;
    PackNormalizedKey(obj, &info);
    info.normalizedType = NORMALIZED_NOT_SUPPORT;
    info.localState = AUTH_STATE_START;
    PackNormalizedKey(obj, &info);
    info.normalizedKey = &sessionKey;
    PackNormalizedKey(obj, &info);
    EXPECT_EQ(memcpy_s(info.connInfo.info.ipInfo.deviceIdHash, UUID_BUF_LEN, UUID_TEST, strlen(UUID_TEST)), EOK);
    PackNormalizedKey(obj, &info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, PackNormalizedKeyValue(obj, &sessionKey));
    JSON_Delete(obj);
}

/*
 @tc.name: PARSE_NORMALIZED_KEY_VALUE_TEST_001
 @tc.desc: ParseNormalizedKeyValue test
 @tc.type: FUNC
 @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, PARSE_NORMALIZED_KEY_VALUE_TEST_001, TestSize.Level1)
{
    int64_t authSeq = 1;
    const char *encNormalizedKey = "encnormalizedkeytest";
    SessionKey sessionKey = {
        .len = SESSION_KEY_LENGTH,
    };
    AuthSessionJsonInterfaceMock mock;
    EXPECT_CALL(mock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AuthFindLatestNormalizeKey).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AuthFindNormalizeKeyByServerSide).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(SOFTBUS_OK, SoftBusGenerateRandomArray(sessionKey.value, SESSION_KEY_LENGTH));
    AuthSessionInfo info;
    EXPECT_NE(SOFTBUS_OK, ParseNormalizedKeyValue(&info, encNormalizedKey, &sessionKey));
    ASSERT_TRUE(memcpy_s(info.uuid, UUID_BUF_LEN, UUID_TEST, strlen(UUID_TEST)) == EOK);
    AuthDeviceKeyInfo deviceKey;
    EXPECT_NE(SOFTBUS_OK, ParseNormalizeData(&info, const_cast<char *>(encNormalizedKey), &deviceKey, authSeq));
}

/*
 @tc.name: PACK_DEVICE_JSON_INFO_TEST_001
 @tc.desc: PackDeviceJsonInfo test
 @tc.type: FUNC
 @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, PACK_DEVICE_JSON_INFO_TEST_001, TestSize.Level1)
{
    int64_t authSeq = 1;
    JsonObj *obj = JSON_CreateObject();
    EXPECT_NE(obj, nullptr);
    SessionKey sessionKey;
    AuthSessionInfo info = {
        .connInfo.type = AUTH_LINK_TYPE_WIFI,
        .isConnectServer = false,
        .localState = AUTH_STATE_START,
        .isServer = false,
        .normalizedKey = &sessionKey,
    };
    AuthSessionJsonInterfaceMock mock;
    EXPECT_CALL(mock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AuthFindLatestNormalizeKey).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AuthFindNormalizeKeyByServerSide).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(SOFTBUS_OK, PackDeviceJsonInfo(&info, obj));
    const char *encNormalizedKey = "encnormalizedkeytest";
    EXPECT_EQ(true, JSON_AddStringToObject(obj, NORMALIZED_DATA, encNormalizedKey));
    UnpackNormalizedKey(obj, &info, NORMALIZED_NOT_SUPPORT, authSeq);
    UnpackNormalizedKey(obj, &info, NORMALIZED_SUPPORT, authSeq);
    info.isServer = true;
    info.normalizedKey = nullptr;
    EXPECT_EQ(memcpy_s(info.uuid, UUID_BUF_LEN, UUID_TEST, strlen(UUID_TEST)), EOK);
    UnpackNormalizedKey(obj, &info, NORMALIZED_SUPPORT, authSeq);
    info.isConnectServer = true;
    EXPECT_EQ(SOFTBUS_OK, PackDeviceJsonInfo(&info, obj));
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    EXPECT_EQ(SOFTBUS_OK, PackDeviceJsonInfo(&info, obj));
    JSON_Delete(obj);
}

/*
 @tc.name: PACK_DEVICE_INFO_MESSAGE_TEST_001
 @tc.desc: PackDeviceInfoMessage test
 @tc.type: FUNC
 @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, PACK_CERTIFICATE_INFO_TEST_001, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    EXPECT_NE(obj, nullptr);
    NodeInfo info;
    const char *staticCap = "staticCapTest";
    const char *encodePtk = "encodePtkTest";
    EXPECT_EQ(true, JSON_AddInt32ToObject(obj, STATIC_CAP_LENGTH, DATA_TEST_LEN));
    EXPECT_EQ(true, JSON_AddStringToObject(obj, STATIC_CAP, staticCap));
    EXPECT_EQ(true, JSON_AddStringToObject(obj, PTK, encodePtk));
    UnpackWifiDirectInfo(obj, &info, false);
    EXPECT_EQ(nullptr, PackDeviceInfoMessage(nullptr, SOFTBUS_NEW_V1, false, nullptr, nullptr));
    JSON_Delete(obj);
}

/*
 @tc.name: GenerateUdidShortHash_TEST_001
 @tc.desc: GenerateUdidShortHash test
 @tc.type: FUNC
 @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, GenerateUdidShortHash_TEST_001, TestSize.Level1)
{
    const char *udid = "123456";
    char udidHashHexStr[SHA_256_HEX_HASH_LEN] = { 0 };
    AuthSessionJsonInterfaceMock mock;
    EXPECT_CALL(mock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(GenerateUdidShortHash(udid, udidHashHexStr, SHA_256_HEX_HASH_LEN));
    EXPECT_TRUE(!GenerateUdidShortHash(udid, udidHashHexStr, 10));
}
}