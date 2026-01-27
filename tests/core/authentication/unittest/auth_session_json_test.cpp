/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "lnn_ohos_account_adapter.h"
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
 * @tc.name: PackFastAuthValue_TEST_001
 * @tc.desc: Quickly package authentication values test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, PackFastAuthValue_TEST_001, TestSize.Level1)
{
    JsonObj *json = JSON_CreateObject();
    EXPECT_NE(json, nullptr);
    char target[10] = { 0 };
    EXPECT_TRUE(JSON_AddStringToObject(json, FAST_AUTH, "jsontest"));
    EXPECT_NO_FATAL_FAILURE(OptString(json, DEVICE_ID, target, 10, ""));
    EXPECT_NO_FATAL_FAILURE(OptString(json, FAST_AUTH, target, 10, ""));
    int32_t val = 0;
    EXPECT_NO_FATAL_FAILURE(OptInt(json, P2P_ROLE, &val, 0));
    EXPECT_TRUE(JSON_AddInt32ToObject(json, SOFTBUS_VERSION_TAG, 123));
    EXPECT_NO_FATAL_FAILURE(OptInt(json, SOFTBUS_VERSION_TAG, &val, 0));
    int64_t value = 0;
    EXPECT_NO_FATAL_FAILURE(OptInt64(json, NEW_CONN_CAP, &value, 1));
    EXPECT_TRUE(JSON_AddInt64ToObject(json, NEW_CONN_CAP, -1));
    EXPECT_NO_FATAL_FAILURE(OptInt64(json, NEW_CONN_CAP, &value, 1));
    bool result;
    EXPECT_NO_FATAL_FAILURE(OptBool(json, BLE_P2P, &result, false));
    EXPECT_TRUE(JSON_AddBoolToObject(json, BLE_P2P, true));
    EXPECT_NO_FATAL_FAILURE(OptBool(json, BLE_P2P, &result, false));
    JSON_Delete(json);
    JsonObj *obj = JSON_CreateObject();
    EXPECT_NE(obj, nullptr);
    AuthDeviceKeyInfo deviceCommKey;
    (void)memset_s(&deviceCommKey, sizeof(AuthDeviceKeyInfo), 0, sizeof(AuthDeviceKeyInfo));
    EXPECT_EQ(memcpy_s(deviceCommKey.deviceKey, SESSION_KEY_LENGTH, DEVICE_KEY, strlen(DEVICE_KEY)), EOK);
    deviceCommKey.keyLen = 5;
    deviceCommKey.keyIndex = 12345;
    AuthSessionJsonInterfaceMock mock;
    EXPECT_CALL(mock, LnnEncryptAesGcm)
        .WillOnce(Return(SOFTBUS_ENCRYPT_ERR));
    int32_t ret = PackFastAuthValue(obj, &deviceCommKey);
    EXPECT_EQ(ret, SOFTBUS_ENCRYPT_ERR);
    EXPECT_CALL(mock, LnnEncryptAesGcm)
        .WillOnce(Return(SOFTBUS_OK));
    ret = PackFastAuthValue(obj, &deviceCommKey);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    uint8_t *data = (uint8_t *)SoftBusCalloc(TEST_DATA_LEN);
    ASSERT_TRUE(data != nullptr);
    ret = memcpy_s(data, TEST_DATA_LEN, TEST_DATA, TEST_DATA_LEN);
    EXPECT_EQ(ret, EOK);
    EXPECT_CALL(mock, LnnEncryptAesGcm)
        .WillOnce(DoAll(SetArgPointee<2>(data), Return(SOFTBUS_OK)));
    ret = PackFastAuthValue(obj, &deviceCommKey);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    EXPECT_NO_FATAL_FAILURE(JSON_Delete(obj));
}

/*
 * @tc.name: GetUdidOrShortHash_TEST_001
 * @tc.desc: Get udid or short hash interface test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
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
    EXPECT_CALL(mock, SoftBusGenerateStrHash)
        .WillOnce(Return(SOFTBUS_ENCRYPT_ERR));
    bool ret = GetUdidOrShortHash(&info, udidHashHexStr, SHA_256_HEX_HASH_LEN);
    EXPECT_EQ(ret, false);
    EXPECT_CALL(mock, SoftBusGenerateStrHash)
        .WillRepeatedly(Return(SOFTBUS_OK));
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
 * @tc.name: VerifySessionInfoIdType_TEST_001
 * @tc.desc: Verify session information id type interface test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
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
    EXPECT_CALL(mock, SoftBusGenerateStrHash)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, IsPotentialTrustedDevice)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mock, AuthFindLatestNormalizeKey)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, IsFeatureSupport)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetLocalStrInfo)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AuthFindDeviceKey)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(ParseFastAuthValue(&info, encryptedFastAuth, &deviceKey));
    JsonObj *obj = JSON_CreateObject();
    EXPECT_NE(obj, nullptr);
    EXPECT_TRUE(JSON_AddStringToObject(obj, FAST_AUTH, encryptedFastAuth));
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    EXPECT_EQ(memcpy_s(info.udid, UDID_BUF_LEN, UDID, strlen(UDID)), EOK);
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    EXPECT_NO_FATAL_FAILURE(UnpackFastAuth(obj, &info));
    info.connInfo.type = AUTH_LINK_TYPE_ENHANCED_P2P;
    EXPECT_NO_FATAL_FAILURE(UnpackFastAuth(obj, &info));
    NodeInfo nodeInfo;
    nodeInfo.feature = 127;
    EXPECT_NO_FATAL_FAILURE(PackCompressInfo(obj, &nodeInfo));
    nodeInfo.feature = 0;
    EXPECT_NO_FATAL_FAILURE(PackCompressInfo(obj, &nodeInfo));
    EXPECT_NO_FATAL_FAILURE(PackWifiSinglePassInfo(obj, &info));
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    EXPECT_NO_FATAL_FAILURE(PackWifiSinglePassInfo(obj, &info));
    info.idType = EXCHANGE_NETWORKID;
    bool ret = VerifySessionInfoIdType(&info, obj, const_cast<char *>(NETWORK_ID_TEST), const_cast<char *>(UDID));
    EXPECT_EQ(ret, true);
    info.idType = EXCHANGE_UDID;
    ret = VerifySessionInfoIdType(&info, obj, const_cast<char *>(NETWORK_ID_TEST), const_cast<char *>(UDID));
    EXPECT_EQ(ret, true);
    EXPECT_NO_FATAL_FAILURE(JSON_Delete(obj));
}

/*
 * @tc.name: PackDeviceIdJson_TEST_001
 * @tc.desc: Device id json pack interface test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
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
    EXPECT_CALL(mock, LnnGetLocalStrInfo)
        .WillRepeatedly(Return(SOFTBUS_NETWORK_NOT_FOUND));
    deviceId = PackDeviceIdJson(&info, authSeq);
    EXPECT_EQ(deviceId, nullptr);
    EXPECT_CALL(mock, LnnGetLocalStrInfo)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusGenerateStrHash)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetLocalStrInfo)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, FindAuthPreLinkNodeById)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetLocalNodeInfo)
        .WillRepeatedly(Return(&nodeInfo));
    EXPECT_CALL(mock, IsFeatureSupport)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mock, IsSupportFeatureByCapaBit)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mock, IsSupportUDIDAbatement)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mock, IsNeedUDIDAbatement)
        .WillRepeatedly(Return(true));
    deviceId = PackDeviceIdJson(&info, authSeq);
    EXPECT_NE(deviceId, nullptr);
    EXPECT_NO_FATAL_FAILURE(JSON_Free(deviceId));
    info.isServer = false;
    deviceId = PackDeviceIdJson(&info, authSeq);
    EXPECT_NE(deviceId, nullptr);
    EXPECT_NO_FATAL_FAILURE(JSON_Free(deviceId));
    info.connInfo.type = AUTH_LINK_TYPE_BR;
    deviceId = PackDeviceIdJson(&info, authSeq);
    EXPECT_NE(deviceId, nullptr);
    EXPECT_NO_FATAL_FAILURE(JSON_Free(deviceId));
}

/*
 * @tc.name: UnpackWifiSinglePassInfo_TEST_001
 * @tc.desc: Unpack of WiFi single channel information test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, UnpackWifiSinglePassInfo_TEST_001, TestSize.Level1)
{
    AuthSessionInfo info;
    info.connInfo.type = AUTH_LINK_TYPE_BR;
    info.connId = 12;
    JsonObj *obj = JSON_CreateObject();
    EXPECT_NE(obj, nullptr);
    EXPECT_TRUE(JSON_AddStringToObject(obj, FAST_AUTH, "encryptedFastAuth"));
    bool ret = UnpackWifiSinglePassInfo(obj, &info);
    EXPECT_EQ(ret, true);
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    AuthSessionJsonInterfaceMock mock;
    EXPECT_CALL(mock, GetFd)
        .WillRepeatedly(Return(TEST_FD));
    ret = UnpackWifiSinglePassInfo(obj, &info);
    EXPECT_EQ(ret, true);
    SoftBusSockAddr addr;
    addr.saFamily = SOFTBUS_AF_INET;
    EXPECT_CALL(mock, SoftBusSocketGetPeerName)
        .WillRepeatedly(DoAll(SetArgPointee<1>(addr), Return(SOFTBUS_OK)));
    ret = UnpackWifiSinglePassInfo(obj, &info);
    EXPECT_EQ(ret, true);
    EXPECT_CALL(mock, SoftBusGenerateStrHash)
        .WillOnce(Return(SOFTBUS_OK));
    ret = UnpackWifiSinglePassInfo(obj, &info);
    EXPECT_EQ(ret, true);
    EXPECT_TRUE(JSON_AddStringToObject(obj, DEV_IP_HASH_TAG, "12345678"));
    ret = UnpackWifiSinglePassInfo(obj, &info);
    EXPECT_EQ(ret, false);
    EXPECT_NO_FATAL_FAILURE(JSON_Delete(obj));
}

/*
 * @tc.name: SetExchangeIdTypeAndValue_TEST_001
 * @tc.desc: Set Exchange Id type and value test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, SetExchangeIdTypeAndValue_TEST_001, TestSize.Level1)
{
    JsonObj *obj1 = JSON_CreateObject();
    EXPECT_NE(obj1, nullptr);
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    info.idType = EXCHANGE_UDID;
    EXPECT_TRUE(JSON_AddInt32ToObject(obj1, SOFTBUS_VERSION_TAG, 123));
    int32_t ret = SetExchangeIdTypeAndValue(nullptr, &info);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SetExchangeIdTypeAndValue(obj1, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SetExchangeIdTypeAndValue(obj1, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(JSON_AddInt32ToObject(obj1, EXCHANGE_ID_TYPE, EXCHANGE_UDID));
    ret = SetExchangeIdTypeAndValue(obj1, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    JSON_Delete(obj1);
    JsonObj *obj2 = JSON_CreateObject();
    EXPECT_NE(obj2, nullptr);
    EXPECT_TRUE(JSON_AddInt32ToObject(obj2, EXCHANGE_ID_TYPE, EXCHANGE_NETWORKID));
    info.isServer = true;
    AuthSessionJsonInterfaceMock mock;
    EXPECT_CALL(mock, LnnRetrieveDeviceInfoByNetworkId)
        .WillRepeatedly(Return(SOFTBUS_OK));
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
    EXPECT_TRUE(JSON_AddInt32ToObject(obj3, EXCHANGE_ID_TYPE, EXCHANGE_FAIL));
    ret = SetExchangeIdTypeAndValue(obj3, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(JSON_Delete(obj3));
}

/*
 * @tc.name: UnpackDeviceIdJson_TEST_001
 * @tc.desc: Device IdJson unpack test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, UnpackDeviceIdJson_TEST_001, TestSize.Level1)
{
    int64_t authSeq = 1;
    JsonObj *obj = JSON_CreateObject();
    EXPECT_NE(obj, nullptr);
    AuthSessionInfo info;
    int32_t ret = UnpackDeviceIdJson(nullptr, 0, &info, authSeq);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(JSON_AddInt32ToObject(obj, EXCHANGE_ID_TYPE, EXCHANGE_FAIL));
    char *msg = JSON_PrintUnformatted(obj);
    ret = UnpackDeviceIdJson(msg, strlen(msg), &info, authSeq);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    if (msg != nullptr) {
        JSON_Free(msg);
    }
    JSON_Delete(obj);
    JsonObj *obj1 = JSON_CreateObject();
    EXPECT_NE(obj1, nullptr);
    EXPECT_TRUE(JSON_AddStringToObject(obj1, CMD_TAG, CMD_GET_AUTH_INFO));
    EXPECT_TRUE(JSON_AddStringToObject(obj1, DATA_TAG, "123456"));
    EXPECT_TRUE(JSON_AddStringToObject(obj1, DEVICE_ID_TAG, "654321"));
    EXPECT_TRUE(JSON_AddInt32ToObject(obj1, DATA_BUF_SIZE_TAG, PACKET_SIZE));
    EXPECT_TRUE(JSON_AddInt32ToObject(obj1, SOFTBUS_VERSION_TAG, 123));
    EXPECT_TRUE(JSON_AddInt32ToObject(obj1, EXCHANGE_ID_TYPE, EXCHANGE_UDID));
    EXPECT_TRUE(JSON_AddStringToObject(obj1, SUPPORT_INFO_COMPRESS, TRUE_STRING_TAG));
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
    EXPECT_NO_FATAL_FAILURE(JSON_Delete(obj1));
}

/*
 * @tc.name: PackCommonDevInfo_TEST_001
 * @tc.desc: Common Device information pack interface test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, PackCommonDevInfo_TEST_001, TestSize.Level1)
{
    JsonObj *json = JSON_CreateObject();
    EXPECT_NE(json, nullptr);
    NodeInfo info;
    AuthSessionJsonInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetDeviceName)
        .WillRepeatedly(Return(nullptr));
    EXPECT_CALL(mock, LnnGetUnifiedDeviceName)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnConvertIdToDeviceType)
        .WillRepeatedly(Return(nullptr));
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_EQ(
        memcpy_s(info.deviceInfo.unifiedName, DEVICE_NAME_BUF_LEN, INVALID_UNIFIED_NAME, strlen(INVALID_UNIFIED_NAME)),
        EOK);
    EXPECT_EQ(memcpy_s(info.uuid, UUID_BUF_LEN, INVALID_UDID, strlen(INVALID_UDID)), EOK);
    EXPECT_CALL(mock, LnnGetLocalStrInfo)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = PackCommonDevInfo(json, &info, true);
    EXPECT_EQ(ret, SOFTBUS_AUTH_PACK_DEVINFO_FAIL);
    EXPECT_CALL(mock, LnnGetLocalStrInfo)
        .WillRepeatedly(Return(SOFTBUS_OK));
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
    EXPECT_NO_FATAL_FAILURE(JSON_Delete(json));
}

/*
 * @tc.name: UnpackCipherRpaInfo_TEST_001
 * @tc.desc: Cipher Rpa information unpack test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, UnpackCipherRpaInfo_TEST_001, TestSize.Level1)
{
    JsonObj *json = JSON_CreateObject();
    EXPECT_NE(json, nullptr);
    AuthSessionJsonInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetLocalStrInfo)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetUnifiedDeviceName)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnConvertIdToDeviceType)
        .WillRepeatedly(Return(nullptr));
    EXPECT_TRUE(JSON_AddStringToObject(json, BROADCAST_CIPHER_KEY, "cipherKeyTest"));
    EXPECT_TRUE(JSON_AddStringToObject(json, BROADCAST_CIPHER_IV, "cipherIv"));
    EXPECT_TRUE(JSON_AddStringToObject(json, IRK, "peerIrk"));
    EXPECT_TRUE(JSON_AddStringToObject(json, PUB_MAC, "pubMac"));
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
    EXPECT_NO_FATAL_FAILURE(JSON_Delete(json1));
}

/*
 * @tc.name: UnpackWifiDirectInfo_TEST_001
 * @tc.desc: Wifi Direct information unpack interface test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, UnpackWifiDirectInfo_TEST_001, TestSize.Level1)
{
    JsonObj *json = JSON_CreateObject();
    EXPECT_NE(json, nullptr);
    EXPECT_TRUE(JSON_AddStringToObject(json, IRK, "peerIrk"));
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
    EXPECT_NO_FATAL_FAILURE(UnpackWifiDirectInfo(json, &info, false));
    EXPECT_TRUE(JSON_AddInt32ToObject(json, STATIC_CAP_LENGTH, 10));
    EXPECT_NO_FATAL_FAILURE(UnpackWifiDirectInfo(json, &info, false));
    EXPECT_TRUE(JSON_AddStringToObject(json, STATIC_CAP, "staticCap"));
    EXPECT_NO_FATAL_FAILURE(UnpackWifiDirectInfo(json, &info, false));
    EXPECT_TRUE(JSON_AddStringToObject(json, PTK, "encodePtk"));
    EXPECT_NO_FATAL_FAILURE(UnpackWifiDirectInfo(json, &info, false));
    EXPECT_EQ(memcpy_s(info.remotePtk, PTK_DEFAULT_LEN, REMOTE_PTK, strlen(REMOTE_PTK)), EOK);
    EXPECT_NO_FATAL_FAILURE(UnpackWifiDirectInfo(json, &info, false));
    EXPECT_NO_FATAL_FAILURE(UnpackCommon(json, &info, SOFTBUS_OLD_V1, true));
    EXPECT_TRUE(JSON_AddStringToObject(json, DEVICE_TYPE, "TV"));
    EXPECT_TRUE(JSON_AddStringToObject(json, DEVICE_UUID, "123456"));
    EXPECT_TRUE(JSON_AddInt64ToObject(json, NEW_CONN_CAP, -1));
    EXPECT_NO_FATAL_FAILURE(UnpackCommon(json, &info, SOFTBUS_OLD_V1, true));
    EXPECT_NO_FATAL_FAILURE(UnpackCommon(json, &info, SOFTBUS_NEW_V1, false));
    EXPECT_TRUE(JSON_AddStringToObject(json, NODE_ADDR, "127.0.0.0"));
    EXPECT_NO_FATAL_FAILURE(UnpackCommon(json, &info, SOFTBUS_NEW_V1, false));
    char buf[10] = { 0 };
    int32_t ret = GetBtDiscTypeString(nullptr, buf, 10);
    EXPECT_EQ(ret, SOFTBUS_OK);
    info.discoveryType = 11;
    ret = GetBtDiscTypeString(&info, buf, 10);
    EXPECT_EQ(ret, SOFTBUS_OK);
    info.discoveryType = 15;
    ret = UnpackBt(json, &info, SOFTBUS_NEW_V1, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(JSON_AddInt64ToObject(json, TRANSPORT_PROTOCOL, 3));
    ret = UnpackBt(json, &info, SOFTBUS_NEW_V1, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = PackWiFi(json, &info, SOFTBUS_NEW_V1, false, WLAN_IF);
    EXPECT_EQ(ret, SOFTBUS_AUTH_PACK_DEVINFO_FAIL);
    EXPECT_NO_FATAL_FAILURE(JSON_Delete(json));
}

/*
 * @tc.name: CheckBusVersion_TEST_001
 * @tc.desc: Check bus version information pack interface test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, CheckBusVersion_TEST_001, TestSize.Level1)
{
    JsonObj *json1 = JSON_CreateObject();
    EXPECT_NE(json1, nullptr);
    EXPECT_TRUE(JSON_AddInt32ToObject(json1, BUS_MAX_VERSION, -1));
    EXPECT_TRUE(JSON_AddInt32ToObject(json1, BUS_MIN_VERSION, -1));
    EXPECT_NE(CheckBusVersion(json1), SOFTBUS_OK);
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_NE(UnpackWiFi(json1, &info, SOFTBUS_OLD_V1, false, WLAN_IF), SOFTBUS_OK);
    JSON_Delete(json1);
    JsonObj *json = JSON_CreateObject();
    EXPECT_NE(json, nullptr);
    EXPECT_TRUE(JSON_AddInt32ToObject(json, BUS_MAX_VERSION, 3));
    EXPECT_TRUE(JSON_AddInt32ToObject(json, BUS_MIN_VERSION, 0));
    EXPECT_TRUE(CheckBusVersion(json) == 2);
    EXPECT_TRUE(UnpackWiFi(json, &info, SOFTBUS_OLD_V1, false, WLAN_IF) == SOFTBUS_OK);
    EXPECT_TRUE(JSON_AddInt64ToObject(json, TRANSPORT_PROTOCOL, 63));
    EXPECT_TRUE(JSON_AddStringToObject(json, BLE_OFFLINE_CODE, "123"));
    EXPECT_TRUE(UnpackWiFi(json, &info, SOFTBUS_OLD_V1, false, WLAN_IF) == SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(JSON_Delete(json));
}

/*
 * @tc.name: PackDeviceInfoBtV1_TEST_001
 * @tc.desc: Device BtV1 information pack interface test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, PackDeviceInfoBtV1_TEST_001, TestSize.Level1)
{
    NodeInfo info;
    AuthSessionJsonInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetBtMac)
        .WillOnce(Return(nullptr));
    EXPECT_CALL(mock, LnnGetP2pMac)
        .WillOnce(Return(nullptr));
    int32_t ret = PackDeviceInfoBtV1(nullptr, &info, false);
    EXPECT_EQ(ret, SOFTBUS_AUTH_PACK_DEVINFO_FAIL);
    JsonObj *json = JSON_CreateObject();
    EXPECT_NE(json, nullptr);
    EXPECT_CALL(mock, LnnGetBtMac)
        .WillRepeatedly(Return("11:22:33:44:55"));
    EXPECT_CALL(mock, LnnGetLocalStrInfo)
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = PackDeviceInfoBtV1(json, &info, false);
    EXPECT_EQ(ret, SOFTBUS_AUTH_PACK_DEVINFO_FAIL);
    ret = UnpackDeviceInfoBtV1(json, &info);
    EXPECT_EQ(ret, SOFTBUS_AUTH_UNPACK_DEVINFO_FAIL);
    EXPECT_TRUE(JSON_AddStringToObject(json, DEVICE_NAME, "testname"));
    ret = UnpackDeviceInfoBtV1(json, &info);
    EXPECT_EQ(ret, SOFTBUS_AUTH_UNPACK_DEVINFO_FAIL);
    EXPECT_TRUE(JSON_AddStringToObject(json, DEVICE_TYPE, "TV"));
    ret = UnpackDeviceInfoBtV1(json, &info);
    EXPECT_EQ(ret, SOFTBUS_AUTH_UNPACK_DEVINFO_FAIL);
    EXPECT_TRUE(JSON_AddStringToObject(json, DEVICE_UDID, "123456"));
    EXPECT_TRUE(JSON_AddStringToObject(json, UUID, "123456"));
    EXPECT_TRUE(JSON_AddStringToObject(json, BR_MAC_ADDR, "11:22:33:44:55"));
    EXPECT_TRUE(JSON_AddInt64ToObject(json, NEW_CONN_CAP, -1));
    ret = UnpackDeviceInfoBtV1(json, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(JSON_Delete(json));
}

/*
 * @tc.name: UnpackDeviceInfoMessage_TEST_001
 * @tc.desc: Device message information unpack interface test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, UnpackDeviceInfoMessage_TEST_001, TestSize.Level1)
{
    DevInfoData devInfo;
    NodeInfo nodeInfo;
    AuthSessionInfo info;
    AuthSessionJsonInterfaceMock mock;
    EXPECT_CALL(mock, IsSupportUDIDAbatement)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mock, IsNeedUDIDAbatement)
        .WillRepeatedly(Return(false));
    EXPECT_CALL(mock, LnnGetLocalNumInfo)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, IsFeatureSupport)
        .WillRepeatedly(Return(false));
    (void)memset_s(&devInfo, sizeof(DevInfoData), 0, sizeof(DevInfoData));
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    JsonObj *obj = JSON_CreateObject();
    EXPECT_NE(obj, nullptr);
    EXPECT_TRUE(JSON_AddInt32ToObject(obj, EXCHANGE_ID_TYPE, EXCHANGE_FAIL));
    char *msg = JSON_PrintUnformatted(obj);
    devInfo.msg = msg;
    devInfo.len = strlen(msg);
    devInfo.linkType = AUTH_LINK_TYPE_BLE;
    EXPECT_TRUE(UnpackDeviceInfoMessage(&devInfo, &nodeInfo, false, &info) == SOFTBUS_OK);
    devInfo.linkType = AUTH_LINK_TYPE_WIFI;
    nodeInfo.feature = 511;
    EXPECT_NE(UnpackDeviceInfoMessage(&devInfo, &nodeInfo, false, &info), SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(JSON_Delete(obj));
}

/*
 * @tc.name: PACK_FAST_AUTH_VALUE_TEST_001
 * @tc.desc: Pack fast auth value test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, PACK_FAST_AUTH_VALUE_TEST_001, TestSize.Level1)
{
    AuthDeviceKeyInfo deviceCommKey = { 0 };
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(obj, nullptr);
    uint32_t keyLen = 0;
    deviceCommKey.keyLen = keyLen;
    AuthSessionJsonInterfaceMock mock;
    EXPECT_CALL(mock, LnnEncryptAesGcm)
        .WillRepeatedly(Return(SOFTBUS_OK));
    uint64_t ret = PackFastAuthValue(obj, &deviceCommKey);
    EXPECT_NE(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(JSON_Delete(obj));
}
/*
 * @tc.name: CHECK_BUS_VERSION_TEST_001
 * @tc.desc: check bus version test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
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
    EXPECT_TRUE(JSON_AddStringToObject(obj, BLE_OFFLINE_CODE, "10244"));

    info->connectInfo.ifInfo[WLAN_IF].authPort = 8710;
    info->connectInfo.ifInfo[WLAN_IF].sessionPort = 26;
    info->connectInfo.ifInfo[WLAN_IF].proxyPort = 80;
    info->supportedProtocols = LNN_PROTOCOL_BR;
    int32_t ret = UnpackWiFi(obj, info, version, false, WLAN_IF);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(JSON_AddInt32ToObject(obj, "BUS_MAX_VERSION", (int32_t)-1));
    ret = UnpackWiFi(obj, info, version, false, WLAN_IF);
    EXPECT_NE(ret, SOFTBUS_OK);

    EXPECT_TRUE(JSON_AddStringToObject(obj, "BROADCAST_CIPHER_KEY", "1222222222"));
    EXPECT_TRUE(JSON_AddStringToObject(obj, "BROADCAST_CIPHER_IV", "1222222222"));
    EXPECT_TRUE(JSON_AddStringToObject(obj, "IRK", "1222222222"));
    EXPECT_TRUE(JSON_AddStringToObject(obj, "PUB_MAC", "1222222222"));

    EXPECT_TRUE(JSON_AddStringToObject(obj, "MASTER_UDID", "1122334554444"));
    EXPECT_TRUE(JSON_AddStringToObject(obj, "NODE_ADDR", "1122334554444"));
    EXPECT_NO_FATAL_FAILURE(UnpackCommon(obj, info, version, false));
    version = SOFTBUS_OLD_V1;
    EXPECT_TRUE(JSON_AddInt32ToObject(obj, "MASTER_WEIGHT", (int32_t)10));
    EXPECT_NO_FATAL_FAILURE(UnpackCommon(obj, info, version, true));
    EXPECT_NO_FATAL_FAILURE(UnpackCipherRpaInfo(obj, info));
    EXPECT_NO_FATAL_FAILURE(JSON_Delete(obj));
    EXPECT_NO_FATAL_FAILURE(SoftBusFree(info));
}

/*
 * @tc.name: PACK_FAST_AUTH_VALUE_TEST_002
 * @tc.desc: Fast auth value pack test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, PACK_FAST_AUTH_VALUE_TEST_002, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    EXPECT_NE(obj, nullptr);
    AuthDeviceKeyInfo deviceCommKey;
    AuthSessionJsonInterfaceMock mock;
    EXPECT_CALL(mock, LnnEncryptAesGcm)
        .WillRepeatedly(Return(SOFTBUS_OK));
    (void)memset_s(&deviceCommKey, sizeof(AuthDeviceKeyInfo), 0, sizeof(AuthDeviceKeyInfo));
    int32_t ret = SoftBusGenerateRandomArray(deviceCommKey.deviceKey, SESSION_KEY_LENGTH);
    EXPECT_EQ(ret, SOFTBUS_OK);
    deviceCommKey.keyLen = SESSION_KEY_LENGTH;
    deviceCommKey.keyIndex = 12345;
    ret = PackFastAuthValue(obj, &deviceCommKey);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    EXPECT_NO_FATAL_FAILURE(JSON_Delete(obj));
}

/*
 * @tc.name: PACK_NORMALIZED_KEY_VALUE_TEST_001
 * @tc.desc: NormalizedKey Value pack interface test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, PACK_NORMALIZED_KEY_VALUE_TEST_001, TestSize.Level1)
{
    int64_t authSeq = 1;
    SessionKey sessionKey = {
        .len = SESSION_KEY_LENGTH,
    };
    AuthSessionJsonInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetUdidByBrMac)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AuthFindLatestNormalizeKey)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnEncryptAesGcm)
        .WillRepeatedly(Return(SOFTBUS_OK));
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
    EXPECT_NO_FATAL_FAILURE(PackNormalizedKey(obj, &info, authSeq));
    info.isNeedFastAuth = true;
    EXPECT_NO_FATAL_FAILURE(PackNormalizedKey(obj, &info, authSeq));
    info.isServer = true;
    EXPECT_NO_FATAL_FAILURE(PackNormalizedKey(obj, &info, authSeq));
    info.normalizedType = NORMALIZED_NOT_SUPPORT;
    info.localState = AUTH_STATE_START;
    EXPECT_NO_FATAL_FAILURE(PackNormalizedKey(obj, &info, authSeq));
    info.normalizedKey = &sessionKey;
    EXPECT_NO_FATAL_FAILURE(PackNormalizedKey(obj, &info, authSeq));
    EXPECT_EQ(memcpy_s(info.connInfo.info.ipInfo.deviceIdHash, UUID_BUF_LEN, UUID_TEST, strlen(UUID_TEST)), EOK);
    EXPECT_NO_FATAL_FAILURE(PackNormalizedKey(obj, &info, authSeq));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, PackNormalizedKeyValue(obj, &sessionKey));
    EXPECT_NO_FATAL_FAILURE(JSON_Delete(obj));
}

/*
  * @tc.name: PARSE_NORMALIZED_KEY_VALUE_TEST_001
  * @tc.desc: Parse NormalizedKey Value test
  * @tc.type: FUNC
  * @tc.level: Level1
  * @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, PARSE_NORMALIZED_KEY_VALUE_TEST_001, TestSize.Level1)
{
    int64_t authSeq = 1;
    const char *encNormalizedKey = "encnormalizedkeytest";
    SessionKey sessionKey = {
        .len = SESSION_KEY_LENGTH,
    };
    AuthSessionJsonInterfaceMock mock;
    EXPECT_CALL(mock, SoftBusGenerateStrHash)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AuthFindLatestNormalizeKey)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AuthFindNormalizeKeyByServerSide)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(SOFTBUS_OK, SoftBusGenerateRandomArray(sessionKey.value, SESSION_KEY_LENGTH));
    AuthSessionInfo info;
    EXPECT_NE(SOFTBUS_OK, ParseNormalizedKeyValue(&info, encNormalizedKey, &sessionKey));
    ASSERT_TRUE(memcpy_s(info.uuid, UUID_BUF_LEN, UUID_TEST, strlen(UUID_TEST)) == EOK);
    AuthDeviceKeyInfo deviceKey;
    EXPECT_NE(SOFTBUS_OK, ParseNormalizeData(&info, const_cast<char *>(encNormalizedKey), &deviceKey, authSeq));
}

/*
 * @tc.name: PACK_DEVICE_JSON_INFO_TEST_001
 * @tc.desc: Device Json information pack test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
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
    EXPECT_CALL(mock, SoftBusGenerateStrHash)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AuthFindLatestNormalizeKey)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AuthFindNormalizeKeyByServerSide)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(SOFTBUS_OK, PackDeviceJsonInfo(&info, obj));
    const char *encNormalizedKey = "encnormalizedkeytest";
    EXPECT_EQ(true, JSON_AddStringToObject(obj, NORMALIZED_DATA, encNormalizedKey));
    EXPECT_NO_FATAL_FAILURE(UnpackNormalizedKey(obj, &info, NORMALIZED_NOT_SUPPORT, authSeq));
    EXPECT_NO_FATAL_FAILURE(UnpackNormalizedKey(obj, &info, NORMALIZED_SUPPORT, authSeq));
    info.isServer = true;
    info.normalizedKey = nullptr;
    EXPECT_EQ(memcpy_s(info.uuid, UUID_BUF_LEN, UUID_TEST, strlen(UUID_TEST)), EOK);
    EXPECT_NO_FATAL_FAILURE(UnpackNormalizedKey(obj, &info, NORMALIZED_SUPPORT, authSeq));
    info.isConnectServer = true;
    EXPECT_EQ(SOFTBUS_OK, PackDeviceJsonInfo(&info, obj));
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    EXPECT_EQ(SOFTBUS_OK, PackDeviceJsonInfo(&info, obj));
    EXPECT_NO_FATAL_FAILURE(JSON_Delete(obj));
}

/*
 * @tc.name: PACK_DEVICE_INFO_MESSAGE_TEST_001
 * @tc.desc: Device Message information pack test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
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
    EXPECT_NO_FATAL_FAILURE(UnpackWifiDirectInfo(obj, &info, false));
    EXPECT_EQ(nullptr, PackDeviceInfoMessage(nullptr, SOFTBUS_NEW_V1, false, nullptr, nullptr));
    EXPECT_NO_FATAL_FAILURE(JSON_Delete(obj));
}

/*
 * @tc.name: GenerateUdidShortHash_TEST_001
 * @tc.desc: Generate Udid Short Hash interface test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthSessionJsonTest, GenerateUdidShortHash_TEST_001, TestSize.Level1)
{
    const char *udid = "123456";
    char udidHashHexStr[SHA_256_HEX_HASH_LEN] = { 0 };
    AuthSessionJsonInterfaceMock mock;
    EXPECT_CALL(mock, SoftBusGenerateStrHash)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(GenerateUdidShortHash(udid, udidHashHexStr, SHA_256_HEX_HASH_LEN));
    EXPECT_TRUE(!GenerateUdidShortHash(udid, udidHashHexStr, 10));
}
} // namespace OHOS
