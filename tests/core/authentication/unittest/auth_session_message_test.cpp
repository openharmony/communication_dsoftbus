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

#include <cinttypes>
#include <gtest/gtest.h>
#include <securec.h>
#include <sys/time.h>

#include "auth_session_json.c"
#include "auth_session_message.c"
#include "auth_session_message.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_json.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;
constexpr int32_t PEER_IRK_LEN = 13;
constexpr int32_t PUBLIC_ADDRESS_LEN = 4;
constexpr int32_t DATA_TEST_LEN = 7;
constexpr int32_t CAPABILITY_LEN = 16;
constexpr char DEVICE_KEY[SESSION_KEY_LENGTH] = "11111";
constexpr char UDID[UDID_BUF_LEN] = "123456789udidtest";
constexpr char UUID_TEST[UUID_BUF_LEN] = "123456789uuidtest";
constexpr char INVALID_UDID[UDID_BUF_LEN] = "\0";
constexpr char NETWORK_ID_TEST[NETWORK_ID_BUF_LEN] = "987654321";
constexpr uint8_t DATA_TEST[UDID_BUF_LEN] = "1111111";
constexpr char UNIFIED_NAME[DEVICE_NAME_BUF_LEN] = "unifiedName";
constexpr char INVALID_UNIFIED_NAME[DEVICE_NAME_BUF_LEN] = "\0";
constexpr char DEVICE_NAME_TEST[DEVICE_NAME_BUF_LEN] = "deviceName";
constexpr char KEY_TEST[SESSION_KEY_LENGTH] = "123456keytest";
constexpr char IV_TEST[BROADCAST_IV_LEN] = "123456ivtest";
constexpr uint8_t PEER_IRK[LFINDER_IRK_LEN] = "123456irktest";
constexpr unsigned char PUBLIC_ADDRESS[LFINDER_MAC_ADDR_LEN] = "addr";
constexpr uint8_t STATIC_CAPABILITY[STATIC_CAP_LEN] = "staticCapability";
constexpr char REMOTE_PTK[PTK_DEFAULT_LEN] = "remotePtktest";
constexpr int32_t TEST_DATA_LEN = 10;

class AuthSessionMessageTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthSessionMessageTest::SetUpTestCase()
{
    int32_t ret = AuthCommonInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

void AuthSessionMessageTest::TearDownTestCase()
{
    AuthCommonDeinit();
}

void AuthSessionMessageTest::SetUp() { }

void AuthSessionMessageTest::TearDown() { }

/*
 * @tc.name: PackFastAuthValue_TEST_001
 * @tc.desc: PackFastAuthValue test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, PackFastAuthValue_TEST_001, TestSize.Level1)
{
    JsonObj *json = JSON_CreateObject();
    EXPECT_TRUE(json != nullptr);
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
    EXPECT_TRUE(obj != nullptr);
    AuthDeviceKeyInfo deviceCommKey;
    (void)memset_s(&deviceCommKey, sizeof(AuthDeviceKeyInfo), 0, sizeof(AuthDeviceKeyInfo));
    EXPECT_TRUE(memcpy_s(deviceCommKey.deviceKey, SESSION_KEY_LENGTH, DEVICE_KEY, strlen(DEVICE_KEY)) == EOK);
    deviceCommKey.keyLen = 5;
    deviceCommKey.keyIndex = 12345;
    EXPECT_NE(PackFastAuthValue(obj, &deviceCommKey), SOFTBUS_OK);
    JSON_Delete(obj);
}

/*
 * @tc.name: GenerateUdidShortHash_TEST_001
 * @tc.desc: GenerateUdidShortHash test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, GenerateUdidShortHash_TEST_001, TestSize.Level1)
{
    const char *udid = "123456";
    char udidHashHexStr[SHA_256_HEX_HASH_LEN] = { 0 };
    EXPECT_TRUE(GenerateUdidShortHash(udid, udidHashHexStr, SHA_256_HEX_HASH_LEN));
    EXPECT_TRUE(!GenerateUdidShortHash(udid, udidHashHexStr, 10));
}

/*
 * @tc.name: GetUdidOrShortHash_TEST_001
 * @tc.desc: GetUdidOrShortHash test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, GetUdidOrShortHash_TEST_001, TestSize.Level1)
{
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    info.isServer = false;
    info.connInfo.type = AUTH_LINK_TYPE_ENHANCED_P2P;
    ASSERT_TRUE(memcpy_s(info.connInfo.info.ipInfo.udid, UDID_BUF_LEN, UDID, strlen(UDID)) == EOK);
    char udidHashHexStr[SHA_256_HEX_HASH_LEN] = { 0 };
    EXPECT_TRUE(GetUdidOrShortHash(&info, udidHashHexStr, SHA_256_HEX_HASH_LEN));
    info.isServer = true;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    ASSERT_TRUE(memcpy_s(info.udid, UDID_BUF_LEN, UDID, strlen(UDID)) == EOK);
    EXPECT_TRUE(GetUdidOrShortHash(&info, udidHashHexStr, SHA_256_HEX_HASH_LEN));
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    ASSERT_TRUE(memcpy_s(info.udid, UDID_BUF_LEN, INVALID_UDID, strlen(INVALID_UDID)) == EOK);
    EXPECT_TRUE(!GetUdidOrShortHash(&info, udidHashHexStr, SHA_256_HEX_HASH_LEN));
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    ASSERT_TRUE(memcpy_s(info.udid, UDID_BUF_LEN, UDID, strlen(UDID)) == EOK);
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    EXPECT_TRUE(GetUdidOrShortHash(&info, udidHashHexStr, SHA_256_HEX_HASH_LEN));
}

/*
 * @tc.name: GetEnhancedP2pAuthKey_TEST_001
 * @tc.desc: GetEnhancedP2pAuthKey test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, GetEnhancedP2pAuthKey_TEST_001, TestSize.Level1)
{
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    ASSERT_TRUE(memcpy_s(info.udid, UDID_BUF_LEN, UDID, strlen(UDID)) == EOK);
    EXPECT_NE(GetEnhancedP2pAuthKey(nullptr, &info, nullptr), SOFTBUS_OK);
    info.connInfo.type = AUTH_LINK_TYPE_ENHANCED_P2P;
    EXPECT_NE(GetFastAuthKey("hashtest", &info, nullptr), SOFTBUS_OK);
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    EXPECT_NE(GetFastAuthKey("hashtest", &info, nullptr), SOFTBUS_OK);
    info.isServer = true;
    info.isSupportFastAuth = true;
    info.isNeedFastAuth = false;
    PackFastAuth(nullptr, &info);
    info.isNeedFastAuth = true;
    PackFastAuth(nullptr, &info);
    info.isSupportFastAuth = false;
    PackFastAuth(nullptr, &info);
    info.isServer = false;
    info.isNeedFastAuth = true;
    PackFastAuth(nullptr, &info);
}

/*
 * @tc.name: VerifySessionInfoIdType_TEST_001
 * @tc.desc: VerifySessionInfoIdType test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, VerifySessionInfoIdType_TEST_001, TestSize.Level1)
{
    AuthSessionInfo info;
    const char *encryptedFastAuth = "encryptedFastAuth";
    AuthDeviceKeyInfo deviceKey;
    (void)memset_s(&deviceKey, sizeof(AuthDeviceKeyInfo), 0, sizeof(AuthDeviceKeyInfo));
    ASSERT_TRUE(memcpy_s(deviceKey.deviceKey, SESSION_KEY_LENGTH, DEVICE_KEY, strlen(DEVICE_KEY)) == EOK);
    deviceKey.keyLen = 5;
    deviceKey.keyIndex = 12345;
    ParseFastAuthValue(&info, encryptedFastAuth, &deviceKey);
    JsonObj *obj = JSON_CreateObject();
    EXPECT_TRUE(obj != nullptr);
    JSON_AddStringToObject(obj, FAST_AUTH, encryptedFastAuth);
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    EXPECT_TRUE(memcpy_s(info.udid, UDID_BUF_LEN, UDID, strlen(UDID)) == EOK);
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
    EXPECT_TRUE(VerifySessionInfoIdType(&info, obj, const_cast<char *>(NETWORK_ID_TEST), const_cast<char *>(UDID)));
    info.idType = EXCHANGE_UDID;
    EXPECT_TRUE(VerifySessionInfoIdType(&info, obj, const_cast<char *>(NETWORK_ID_TEST), const_cast<char *>(UDID)));
    JSON_Delete(obj);
}

/*
 * @tc.name: PackDeviceIdJson_TEST_001
 * @tc.desc: PackDeviceIdJson test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, PackDeviceIdJson_TEST_001, TestSize.Level1)
{
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    info.version = SOFTBUS_OLD_V1;
    info.idType = EXCHANGE_UDID;
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    info.isServer = true;
    EXPECT_TRUE(PackDeviceIdJson(&info) == nullptr);
    info.isServer = false;
    EXPECT_TRUE(PackDeviceIdJson(&info) == nullptr);
    info.connInfo.type = AUTH_LINK_TYPE_BR;
    EXPECT_TRUE(PackDeviceIdJson(&info) == nullptr);
}

/*
 * @tc.name: UnpackWifiSinglePassInfo_TEST_001
 * @tc.desc: UnpackWifiSinglePassInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, UnpackWifiSinglePassInfo_TEST_001, TestSize.Level1)
{
    AuthSessionInfo info;
    info.connInfo.type = AUTH_LINK_TYPE_BR;
    info.connId = 12;
    JsonObj *obj = JSON_CreateObject();
    EXPECT_TRUE(obj != nullptr);
    JSON_AddStringToObject(obj, FAST_AUTH, "encryptedFastAuth");
    EXPECT_TRUE(UnpackWifiSinglePassInfo(obj, &info));
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    EXPECT_TRUE(UnpackWifiSinglePassInfo(obj, &info));
    JSON_AddStringToObject(obj, DEV_IP_HASH_TAG, "12345678");
    EXPECT_TRUE(UnpackWifiSinglePassInfo(obj, &info));
    JSON_Delete(obj);
}

/*
 * @tc.name: UnPackBtDeviceIdV1_TEST_001
 * @tc.desc: UnPackBtDeviceIdV1 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, UnPackBtDeviceIdV1_TEST_001, TestSize.Level1)
{
    bool sessionSupportFlag = false;
    SetCompressFlag("true", &sessionSupportFlag);
    SetCompressFlag("false", &sessionSupportFlag);
    AuthSessionInfo info;
    info.isServer = false;
    EXPECT_TRUE(UnPackBtDeviceIdV1(&info, DATA_TEST, DATA_TEST_LEN) == SOFTBUS_INVALID_PARAM);
    info.isServer = true;
    EXPECT_TRUE(UnPackBtDeviceIdV1(&info, DATA_TEST, DATA_TEST_LEN) == SOFTBUS_OK);
}

/*
 * @tc.name: SetExchangeIdTypeAndValue_TEST_001
 * @tc.desc: SetExchangeIdTypeAndValue test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, SetExchangeIdTypeAndValue_TEST_001, TestSize.Level1)
{
    JsonObj *obj1 = JSON_CreateObject();
    EXPECT_TRUE(obj1 != nullptr);
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    info.idType = EXCHANGE_UDID;
    JSON_AddInt32ToObject(obj1, SOFTBUS_VERSION_TAG, 123);
    EXPECT_TRUE(SetExchangeIdTypeAndValue(nullptr, &info) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(SetExchangeIdTypeAndValue(obj1, nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(SetExchangeIdTypeAndValue(obj1, &info) == SOFTBUS_OK);
    JSON_AddInt32ToObject(obj1, EXCHANGE_ID_TYPE, EXCHANGE_UDID);
    EXPECT_TRUE(SetExchangeIdTypeAndValue(obj1, &info) == SOFTBUS_OK);
    JSON_Delete(obj1);
    JsonObj *obj2 = JSON_CreateObject();
    EXPECT_TRUE(obj2 != nullptr);
    JSON_AddInt32ToObject(obj2, EXCHANGE_ID_TYPE, EXCHANGE_NETWORKID);
    info.isServer = true;
    EXPECT_TRUE(SetExchangeIdTypeAndValue(obj2, &info) == SOFTBUS_OK);
    info.isServer = false;
    EXPECT_TRUE(SetExchangeIdTypeAndValue(obj2, &info) == SOFTBUS_OK);
    info.idType = EXCHANGE_NETWORKID;
    EXPECT_TRUE(SetExchangeIdTypeAndValue(obj2, &info) == SOFTBUS_OK);
    JSON_Delete(obj2);
    JsonObj *obj3 = JSON_CreateObject();
    EXPECT_TRUE(obj3 != nullptr);
    JSON_AddInt32ToObject(obj3, EXCHANGE_ID_TYPE, EXCHANGE_FAIL);
    EXPECT_TRUE(SetExchangeIdTypeAndValue(obj3, &info) == SOFTBUS_OK);
    JSON_Delete(obj3);
}

/*
 * @tc.name: UnpackDeviceIdJson_TEST_001
 * @tc.desc: UnpackDeviceIdJson test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, UnpackDeviceIdJson_TEST_001, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    EXPECT_TRUE(obj != nullptr);
    AuthSessionInfo info;
    EXPECT_TRUE(UnpackDeviceIdJson(nullptr, 0, &info) == SOFTBUS_INVALID_PARAM);
    JSON_AddInt32ToObject(obj, EXCHANGE_ID_TYPE, EXCHANGE_FAIL);
    char *msg = JSON_PrintUnformatted(obj);
    EXPECT_TRUE(UnpackDeviceIdJson(msg, strlen(msg), &info) == SOFTBUS_NOT_FIND);
    if (msg != nullptr) {
        JSON_Free(msg);
    }
    JSON_Delete(obj);
    JsonObj *obj1 = JSON_CreateObject();
    EXPECT_TRUE(obj1 != nullptr);
    JSON_AddStringToObject(obj1, CMD_TAG, CMD_GET_AUTH_INFO);
    JSON_AddStringToObject(obj1, DATA_TAG, "123456");
    JSON_AddStringToObject(obj1, DEVICE_ID_TAG, "654321");
    JSON_AddInt32ToObject(obj1, DATA_BUF_SIZE_TAG, PACKET_SIZE);
    JSON_AddInt32ToObject(obj1, SOFTBUS_VERSION_TAG, 123);
    JSON_AddInt32ToObject(obj1, EXCHANGE_ID_TYPE, EXCHANGE_UDID);
    JSON_AddStringToObject(obj1, SUPPORT_INFO_COMPRESS, TRUE_STRING_TAG);
    char *msg1 = JSON_PrintUnformatted(obj1);
    info.connInfo.type = AUTH_LINK_TYPE_BR;
    EXPECT_TRUE(UnpackDeviceIdJson(msg1, strlen(msg1), &info) == SOFTBUS_CMP_FAIL);
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    info.isServer = false;
    EXPECT_TRUE(UnpackDeviceIdJson(msg1, strlen(msg1), &info) == SOFTBUS_CMP_FAIL);
    info.isConnectServer = true;
    EXPECT_TRUE(UnpackDeviceIdJson(msg1, strlen(msg1), &info) == SOFTBUS_OK);
    if (msg1 != nullptr) {
        JSON_Free(msg1);
    }
    JSON_Delete(obj1);
}

/*
 * @tc.name: PackCommonDevInfo_TEST_001
 * @tc.desc: PackCommonDevInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, PackCommonDevInfo_TEST_001, TestSize.Level1)
{
    JsonObj *json = JSON_CreateObject();
    EXPECT_TRUE(json != nullptr);
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_TRUE(memcpy_s(info.deviceInfo.unifiedName, DEVICE_NAME_BUF_LEN, INVALID_UNIFIED_NAME,
                    strlen(INVALID_UNIFIED_NAME)) == EOK);
    EXPECT_TRUE(memcpy_s(info.uuid, UUID_BUF_LEN, INVALID_UDID, strlen(INVALID_UDID)) == EOK);
    EXPECT_TRUE(PackCommonDevInfo(json, &info, true) == SOFTBUS_OK);
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_TRUE(memcpy_s(info.deviceInfo.unifiedName, DEVICE_NAME_BUF_LEN, UNIFIED_NAME, strlen(UNIFIED_NAME)) == EOK);
    EXPECT_TRUE(memcpy_s(info.networkId, NETWORK_ID_BUF_LEN, NETWORK_ID_TEST, strlen(NETWORK_ID_TEST)) == EOK);
    EXPECT_TRUE(
        memcpy_s(info.deviceInfo.deviceName, DEVICE_NAME_BUF_LEN, DEVICE_NAME_TEST, strlen(DEVICE_NAME_TEST)) == EOK);
    info.deviceInfo.deviceTypeId = 12;
    EXPECT_TRUE(memcpy_s(info.uuid, UUID_BUF_LEN, UUID_TEST, strlen(UUID_TEST)) == EOK);
    EXPECT_TRUE(PackCommonDevInfo(json, &info, false) == SOFTBUS_OK);
    JSON_Delete(json);
}

/*
 * @tc.name: UnpackCipherRpaInfo_TEST_001
 * @tc.desc: UnpackCipherRpaInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, UnpackCipherRpaInfo_TEST_001, TestSize.Level1)
{
    JsonObj *json = JSON_CreateObject();
    EXPECT_TRUE(json != nullptr);
    (void)JSON_AddStringToObject(json, BROADCAST_CIPHER_KEY, "cipherKeyTest");
    (void)JSON_AddStringToObject(json, BROADCAST_CIPHER_IV, "cipherIv");
    (void)JSON_AddStringToObject(json, IRK, "peerIrk");
    (void)JSON_AddStringToObject(json, PUB_MAC, "pubMac");
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_TRUE(memcpy_s(info.cipherInfo.key, SESSION_KEY_LENGTH, KEY_TEST, strlen(KEY_TEST)) == EOK);
    EXPECT_TRUE(memcpy_s(info.cipherInfo.iv, BROADCAST_IV_LEN, IV_TEST, strlen(IV_TEST)) == EOK);
    EXPECT_TRUE(memcpy_s(info.rpaInfo.peerIrk, LFINDER_IRK_LEN, PEER_IRK, PEER_IRK_LEN) == EOK);
    EXPECT_TRUE(memcpy_s(info.rpaInfo.publicAddress, LFINDER_MAC_ADDR_LEN, PUBLIC_ADDRESS, PUBLIC_ADDRESS_LEN) == EOK);
    UnpackCipherRpaInfo(json, &info);
    JSON_Delete(json);
    JsonObj *json1 = JSON_CreateObject();
    EXPECT_TRUE(json1 != nullptr);
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_TRUE(PackCommon(json1, &info, SOFTBUS_OLD_V2, false) == SOFTBUS_OK);
    EXPECT_TRUE(PackCommon(json1, &info, SOFTBUS_NEW_V1, false) == SOFTBUS_OK);
    JSON_Delete(json1);
}

/*
 * @tc.name: UnpackWifiDirectInfo_TEST_001
 * @tc.desc: UnpackWifiDirectInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, UnpackWifiDirectInfo_TEST_001, TestSize.Level1)
{
    JsonObj *json = JSON_CreateObject();
    EXPECT_TRUE(json != nullptr);
    (void)JSON_AddStringToObject(json, IRK, "peerIrk");
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_TRUE(memcpy_s(info.staticCapability, STATIC_CAP_LEN, STATIC_CAPABILITY, CAPABILITY_LEN) == EOK);
    UnpackWifiDirectInfo(json, &info, false);
    JSON_AddInt32ToObject(json, STATIC_CAP_LENGTH, 10);
    UnpackWifiDirectInfo(json, &info, false);
    JSON_AddStringToObject(json, STATIC_CAP, "staticCap");
    UnpackWifiDirectInfo(json, &info, false);
    JSON_AddStringToObject(json, PTK, "encodePtk");
    UnpackWifiDirectInfo(json, &info, false);
    EXPECT_TRUE(memcpy_s(info.remotePtk, PTK_DEFAULT_LEN, REMOTE_PTK, strlen(REMOTE_PTK)) == EOK);
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
    EXPECT_TRUE(GetBtDiscTypeString(nullptr, buf, 10) == SOFTBUS_OK);
    info.discoveryType = 11;
    EXPECT_TRUE(GetBtDiscTypeString(&info, buf, 10) == SOFTBUS_OK);
    info.discoveryType = 15;
    EXPECT_TRUE(UnpackBt(json, &info, SOFTBUS_NEW_V1, false) == SOFTBUS_OK);
    JSON_AddInt64ToObject(json, TRANSPORT_PROTOCOL, 3);
    EXPECT_TRUE(UnpackBt(json, &info, SOFTBUS_NEW_V1, false) == SOFTBUS_OK);
    EXPECT_TRUE(PackWiFi(json, &info, SOFTBUS_NEW_V1, false) == SOFTBUS_OK);
    JSON_Delete(json);
}

/*
 * @tc.name: CheckBusVersion_TEST_001
 * @tc.desc: CheckBusVersion test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, CheckBusVersion_TEST_001, TestSize.Level1)
{
    JsonObj *json1 = JSON_CreateObject();
    EXPECT_TRUE(json1 != nullptr);
    JSON_AddInt32ToObject(json1, BUS_MAX_VERSION, -1);
    JSON_AddInt32ToObject(json1, BUS_MIN_VERSION, -1);
    EXPECT_NE(CheckBusVersion(json1), SOFTBUS_OK);
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_NE(UnpackWiFi(json1, &info, SOFTBUS_OLD_V1, false), SOFTBUS_OK);
    JSON_Delete(json1);
    JsonObj *json = JSON_CreateObject();
    EXPECT_TRUE(json != nullptr);
    JSON_AddInt32ToObject(json, BUS_MAX_VERSION, 3);
    JSON_AddInt32ToObject(json, BUS_MIN_VERSION, 0);
    ;
    EXPECT_TRUE(CheckBusVersion(json) == 2);
    EXPECT_TRUE(UnpackWiFi(json, &info, SOFTBUS_OLD_V1, false) == SOFTBUS_OK);
    JSON_AddInt64ToObject(json, TRANSPORT_PROTOCOL, 63);
    JSON_AddStringToObject(json, BLE_OFFLINE_CODE, "123");
    EXPECT_TRUE(UnpackWiFi(json, &info, SOFTBUS_OLD_V1, false) == SOFTBUS_OK);
    JSON_Delete(json);
}

/*
 * @tc.name: PackDeviceInfoBtV1_TEST_001
 * @tc.desc: PackDeviceInfoBtV1 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, PackDeviceInfoBtV1_TEST_001, TestSize.Level1)
{
    NodeInfo info;
    EXPECT_TRUE(PackDeviceInfoBtV1(nullptr, &info, false) == SOFTBUS_AUTH_PACK_DEVINFO_FAIL);
    JsonObj *json = JSON_CreateObject();
    EXPECT_TRUE(json != nullptr);
    EXPECT_TRUE(PackDeviceInfoBtV1(json, &info, false) == SOFTBUS_OK);
    EXPECT_TRUE(UnpackDeviceInfoBtV1(json, &info) == SOFTBUS_OK);
    JSON_AddStringToObject(json, DEVICE_NAME, "testname");
    EXPECT_TRUE(UnpackDeviceInfoBtV1(json, &info) == SOFTBUS_OK);
    JSON_AddStringToObject(json, DEVICE_TYPE, "TV");
    EXPECT_TRUE(UnpackDeviceInfoBtV1(json, &info) == SOFTBUS_OK);
    JSON_AddStringToObject(json, DEVICE_UDID, "123456");
    JSON_AddStringToObject(json, UUID, "123456");
    JSON_AddStringToObject(json, BR_MAC_ADDR, "11:22:33:44:55");
    JSON_AddInt64ToObject(json, NEW_CONN_CAP, -1);
    EXPECT_TRUE(UnpackDeviceInfoBtV1(json, &info) == SOFTBUS_OK);
    JSON_Delete(json);
}

/*
 * @tc.name: UpdatePeerDeviceName_TEST_001
 * @tc.desc: UpdatePeerDeviceName test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, UpdatePeerDeviceName_TEST_001, TestSize.Level1)
{
    NodeInfo peerNodeInfo;
    (void)memset_s(&peerNodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    UpdatePeerDeviceName(&peerNodeInfo);
    ASSERT_TRUE(
        memcpy_s(peerNodeInfo.deviceInfo.unifiedName, DEVICE_NAME_BUF_LEN, UNIFIED_NAME, strlen(UNIFIED_NAME)) == EOK);
    ASSERT_TRUE(memcpy_s(peerNodeInfo.deviceInfo.unifiedDefaultName, DEVICE_NAME_BUF_LEN, DEVICE_NAME_TEST,
                    strlen(DEVICE_NAME_TEST)) == EOK);
    UpdatePeerDeviceName(&peerNodeInfo);
    ASSERT_TRUE(memcpy_s(peerNodeInfo.deviceInfo.unifiedDefaultName, DEVICE_NAME_BUF_LEN, UNIFIED_NAME,
                    strlen(UNIFIED_NAME)) == EOK);
    UpdatePeerDeviceName(&peerNodeInfo);
    AuthSessionInfo info;
    EXPECT_TRUE(PostDeviceIdData(123, &info, nullptr, 0) == SOFTBUS_AUTH_SEND_FAIL);
    info.isServer = false;
    EXPECT_NE(PostBtV1DevId(123, &info), SOFTBUS_OK);
    EXPECT_NE(PostWifiV1DevId(123, &info), SOFTBUS_OK);
    info.isServer = true;
    EXPECT_NE(PostBtV1DevId(123, &info), SOFTBUS_OK);
    EXPECT_NE(PostWifiV1DevId(123, &info), SOFTBUS_OK);
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    EXPECT_NE(PostDeviceIdV1(123, &info), SOFTBUS_OK);
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    EXPECT_NE(PostDeviceIdV1(123, &info), SOFTBUS_OK);
    EXPECT_NE(PostDeviceIdNew(123, &info), SOFTBUS_OK);
    EXPECT_TRUE(PostCloseAckMessage(123, &info) == SOFTBUS_AUTH_SEND_FAIL);
}

/*
 * @tc.name: ProcessDeviceIdMessage_TEST_001
 * @tc.desc: ProcessDeviceIdMessage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, ProcessDeviceIdMessage_TEST_001, TestSize.Level1)
{
    AuthSessionInfo info;
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    uint8_t data[] = "test";
    EXPECT_TRUE(ProcessDeviceIdMessage(&info, data, DEVICE_ID_STR_LEN) == SOFTBUS_INVALID_PARAM);
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    EXPECT_TRUE(ProcessDeviceIdMessage(&info, data, DEVICE_ID_STR_LEN + 1) == SOFTBUS_INVALID_PARAM);
    info.isServer = false;
    EXPECT_TRUE(ProcessDeviceIdMessage(&info, data, DEVICE_ID_STR_LEN) == SOFTBUS_INVALID_PARAM);
    info.isServer = true;
    EXPECT_TRUE(ProcessDeviceIdMessage(&info, data, DEVICE_ID_STR_LEN) == SOFTBUS_OK);
}

/*
 * @tc.name: UnpackDeviceInfoMessage_TEST_001
 * @tc.desc: UnpackDeviceInfoMessage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, UnpackDeviceInfoMessage_TEST_001, TestSize.Level1)
{
    DevInfoData devInfo;
    NodeInfo nodeInfo;
    AuthSessionInfo info;
    (void)memset_s(&devInfo, sizeof(DevInfoData), 0, sizeof(DevInfoData));
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    JsonObj *obj = JSON_CreateObject();
    EXPECT_TRUE(obj != nullptr);
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
 * @tc.name: IsDeviceMessagePacket_TEST_001
 * @tc.desc: IsDeviceMessagePacket test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, IsDeviceMessagePacket_TEST_001, TestSize.Level1)
{
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    DeviceMessageParse messageParse = { 0 };
    connInfo.type = AUTH_LINK_TYPE_BLE;
    EXPECT_TRUE(!IsDeviceMessagePacket(&connInfo, nullptr, nullptr, true, &messageParse));
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    EXPECT_TRUE(!IsDeviceMessagePacket(&connInfo, nullptr, nullptr, true, &messageParse));
}

/*
 * @tc.name: PACK_FAST_AUTH_VALUE_TEST_001
 * @tc.desc: Pack fast auth value test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, PACK_FAST_AUTH_VALUE_TEST_001, TestSize.Level1)
{
    AuthDeviceKeyInfo deviceCommKey = { 0 };
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(obj, nullptr);
    uint32_t keyLen = 0;
    deviceCommKey.keyLen = keyLen;
    uint64_t ret = PackFastAuthValue(obj, &deviceCommKey);
    EXPECT_NE(ret, SOFTBUS_OK);
    JSON_Delete(obj);
}

/*
 * @tc.name: CHECK_BUS_VERSION_TEST_001
 * @tc.desc: check bus version test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, CHECK_BUS_VERSION_TEST_001, TestSize.Level1)
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
    EXPECT_TRUE(ret == SOFTBUS_OK);
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
 * @tc.name: POST_BT_V1_DEVID_TEST_001
 * @tc.desc: post bt v1 devid test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, POST_BT_V1_DEVID_TEST_001, TestSize.Level1)
{
    int64_t authSeq = 0;
    AuthSessionInfo *info = (AuthSessionInfo *)SoftBusCalloc(sizeof(AuthSessionInfo));
    if (info == NULL) {
        return;
    }
    info->requestId = 1;
    info->connId = 1;
    info->isServer = false;
    info->version = SOFTBUS_NEW_V1;
    info->connInfo.type = AUTH_LINK_TYPE_WIFI;
    int32_t ret = PostDeviceIdV1(authSeq, info);
    EXPECT_NE(ret, SOFTBUS_OK);
    SoftBusFree(info);
}

/*
 * @tc.name: IS_EMPTY_SHORT_HASH_STR_TEST_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, IS_EMPTY_SHORT_HASH_STR_TEST_001, TestSize.Level1)
{
    char udidHash[SHA_256_HEX_HASH_LEN];
    const char *udidHash1 = "123456";
    const char *udidHash2 = "0000000000000000000000000000000000000000000000000000000000000000";
    (void)memset_s(udidHash, sizeof(udidHash), 0, sizeof(udidHash));
    EXPECT_TRUE(strcpy_s(udidHash, sizeof(udidHash), "") == EOK);
    bool ret = IsEmptyShortHashStr(udidHash);
    EXPECT_EQ(ret, true);

    (void)memset_s(udidHash, sizeof(udidHash), 0, sizeof(udidHash));
    EXPECT_TRUE(strcpy_s(udidHash, sizeof(udidHash), udidHash1) == EOK);
    ret = IsEmptyShortHashStr(udidHash);
    EXPECT_EQ(ret, false);

    (void)memset_s(udidHash, sizeof(udidHash), 0, sizeof(udidHash));
    EXPECT_TRUE(strcpy_s(udidHash, sizeof(udidHash), udidHash2) == EOK);
    ret = IsEmptyShortHashStr(udidHash);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: GET_LOCAL_UDISHASH_TEST_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, GET_LOCAL_UDISHASH_TEST_001, TestSize.Level1)
{
    int32_t ret = GetLocalUdidHash(nullptr, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: UPDATE_LOCAL_AUTH_STATE_TEST_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, UPDATE_LOCAL_AUTH_STATE_TEST_001, TestSize.Level1)
{
    uint64_t authSeq = 512;
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    info.isServer = true;
    int32_t ret = UpdateLocalAuthState(authSeq, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);

    info.isServer = false;
    info.peerState = AUTH_STATE_COMPATIBLE;
    ret = UpdateLocalAuthState(authSeq, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);

    info.peerState = AUTH_STATE_ACK;
    ret = UpdateLocalAuthState(authSeq, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: PACK_FAST_AUTH_VALUE_TEST_002
 * @tc.desc: PackFastAuthValue test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, PACK_FAST_AUTH_VALUE_TEST_002, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    EXPECT_TRUE(obj != nullptr);
    AuthDeviceKeyInfo deviceCommKey;
    (void)memset_s(&deviceCommKey, sizeof(AuthDeviceKeyInfo), 0, sizeof(AuthDeviceKeyInfo));
    EXPECT_EQ(SOFTBUS_OK, SoftBusGenerateRandomArray(deviceCommKey.deviceKey, SESSION_KEY_LENGTH));
    deviceCommKey.keyLen = SESSION_KEY_LENGTH;
    deviceCommKey.keyIndex = 12345;
    EXPECT_TRUE(PackFastAuthValue(obj, &deviceCommKey) == SOFTBUS_OK);
    JSON_Delete(obj);
}

/*
 * @tc.name: GET_UDID_SHORT_HASH_TEST_001
 * @tc.desc: GetUdidShortHash test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, GET_UDID_SHORT_HASH_TEST_001, TestSize.Level1)
{
    AuthSessionInfo info = {
        .connInfo.type = AUTH_LINK_TYPE_BR,
        .isServer = true,
    };
    uint32_t bufLen = UDID_SHORT_HASH_HEX_STR;
    char udidHash[SHORT_UDID_HASH_HEX_LEN + 1];
    EXPECT_EQ(false, GetUdidShortHash(nullptr, nullptr, bufLen));
    EXPECT_EQ(false, GetUdidShortHash(&info, nullptr, bufLen));
    EXPECT_EQ(false, GetUdidShortHash(&info, udidHash, bufLen));
    bufLen++;
    EXPECT_EQ(false, GetUdidShortHash(&info, udidHash, bufLen));
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    EXPECT_EQ(true, GetUdidShortHash(&info, udidHash, bufLen));
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    EXPECT_EQ(true, GetUdidShortHash(&info, udidHash, bufLen));
    info.connInfo.type = AUTH_LINK_TYPE_P2P;
    EXPECT_EQ(false, GetUdidShortHash(&info, udidHash, bufLen));
    info.isServer = false;
    EXPECT_EQ(false, GetUdidShortHash(&info, udidHash, bufLen));
    ASSERT_TRUE(memcpy_s(info.udid, UDID_BUF_LEN, UDID, strlen(UDID)) == EOK);
    EXPECT_EQ(true, GetUdidShortHash(&info, udidHash, bufLen));
}

/*
 * @tc.name: PACK_NORMALIZED_KEY_VALUE_TEST_001
 * @tc.desc: PackNormalizedKeyValue test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, PACK_NORMALIZED_KEY_VALUE_TEST_001, TestSize.Level1)
{
    SessionKey sessionKey = {
        .len = SESSION_KEY_LENGTH,
    };
    EXPECT_EQ(SOFTBUS_OK, SoftBusGenerateRandomArray(sessionKey.value, SESSION_KEY_LENGTH));
    JsonObj *obj = JSON_CreateObject();
    EXPECT_TRUE(obj != nullptr);
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
    EXPECT_TRUE(memcpy_s(info.connInfo.info.ipInfo.deviceIdHash, UUID_BUF_LEN, UUID_TEST, strlen(UUID_TEST)) == EOK);
    PackNormalizedKey(obj, &info);
    EXPECT_EQ(SOFTBUS_OK, PackNormalizedKeyValue(obj, &sessionKey));
    JSON_Delete(obj);
}

/*
 * @tc.name: PARSE_NORMALIZED_KEY_VALUE_TEST_001
 * @tc.desc: ParseNormalizedKeyValue test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, PARSE_NORMALIZED_KEY_VALUE_TEST_001, TestSize.Level1)
{
    const char *encNormalizedKey = "encnormalizedkeytest";
    SessionKey sessionKey = {
        .len = SESSION_KEY_LENGTH,
    };
    EXPECT_EQ(SOFTBUS_OK, SoftBusGenerateRandomArray(sessionKey.value, SESSION_KEY_LENGTH));
    AuthSessionInfo info;
    EXPECT_NE(SOFTBUS_OK, ParseNormalizedKeyValue(&info, encNormalizedKey, &sessionKey));
    ASSERT_TRUE(memcpy_s(info.uuid, UUID_BUF_LEN, UUID_TEST, strlen(UUID_TEST)) == EOK);
    AuthDeviceKeyInfo deviceKey;
    EXPECT_NE(SOFTBUS_OK, ParseNormalizeData(&info, const_cast<char *>(encNormalizedKey), &deviceKey));
}

/*
 * @tc.name: PACK_DEVICE_JSON_INFO_TEST_001
 * @tc.desc: PackDeviceJsonInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, PACK_DEVICE_JSON_INFO_TEST_001, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    EXPECT_TRUE(obj != nullptr);
    SessionKey sessionKey;
    AuthSessionInfo info = {
        .connInfo.type = AUTH_LINK_TYPE_WIFI,
        .isConnectServer = false,
        .localState = AUTH_STATE_START,
        .isServer = false,
        .normalizedKey = &sessionKey,
    };
    EXPECT_EQ(SOFTBUS_OK, PackDeviceJsonInfo(&info, obj));
    const char *encNormalizedKey = "encnormalizedkeytest";
    EXPECT_EQ(true, JSON_AddStringToObject(obj, NORMALIZED_DATA, encNormalizedKey));
    UnpackNormalizedKey(obj, &info, NORMALIZED_NOT_SUPPORT);
    UnpackNormalizedKey(obj, &info, NORMALIZED_SUPPORT);
    info.isServer = true;
    info.normalizedKey = nullptr;
    EXPECT_TRUE(memcpy_s(info.uuid, UUID_BUF_LEN, UUID_TEST, strlen(UUID_TEST)) == EOK);
    UnpackNormalizedKey(obj, &info, NORMALIZED_SUPPORT);
    info.isConnectServer = true;
    EXPECT_EQ(SOFTBUS_OK, PackDeviceJsonInfo(&info, obj));
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    EXPECT_EQ(SOFTBUS_OK, PackDeviceJsonInfo(&info, obj));
    JSON_Delete(obj);
}

/*
 * @tc.name: PACK_DEVICE_INFO_MESSAGE_TEST_001
 * @tc.desc: PackDeviceInfoMessage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, PACK_CERTIFICATE_INFO_TEST_001, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    EXPECT_TRUE(obj != nullptr);
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
 * @tc.name: GET_DUMP_SESSIONKEY_LIST_TEST_001
 * @tc.desc: GetDumpSessionKeyList test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionMessageTest, GET_DUMP_SESSIONKEY_LIST_TEST_001, TestSize.Level1)
{
    AuthSessionInfo info;
    uint64_t connId = 1;
    int64_t authSeq = 1;
    SessionKeyList sessionKeyList;
    info.connId = connId;
    info.isServer = false;
    info.isSupportFastAuth = true;
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    info.version = SOFTBUS_OLD_V1;
    SessionKey sessionKey;
    (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
    ASSERT_TRUE(memcpy_s(sessionKey.value, SESSION_KEY_LENGTH, KEY_TEST, PEER_IRK_LEN) == EOK);
    sessionKey.len = PEER_IRK_LEN;
    EXPECT_TRUE(AuthManagerSetSessionKey(authSeq, &info, &sessionKey, false, false) == SOFTBUS_OK);
    GetDumpSessionKeyList(authSeq, &info, &sessionKeyList);

    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    info.isSupportCompress = true;
    uint8_t compressData[TEST_DATA_LEN] = { 0 };
    uint32_t compressLen = TEST_DATA_LEN;
    char data[TEST_DATA_LEN] = { 0 };
    InDataInfo inDataInfo;
    (void)memset_s(&inDataInfo, sizeof(InDataInfo), 0, sizeof(InDataInfo));
    SetIndataInfo(&inDataInfo, nullptr, 0, data);
    SetIndataInfo(&inDataInfo, nullptr, compressLen, data);
    SetIndataInfo(&inDataInfo, compressData, 0, data);
}
} // namespace OHOS
