/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <cinttypes>
#include <gtest/gtest.h>
#include <securec.h>

#include "auth_device.c"
#include "auth_device_deps_mock.h"
#include "auth_log.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;

constexpr int64_t TEST_AUTH_ID = 1;
constexpr uint32_t TEST_REQUEST_ID = 100;
constexpr uint64_t TEST_CURRENT_TIME = 1000000;
constexpr char TEST_UDID[] = "1234567890abcdef1234567890abcdef12345678";
constexpr char TEST_UUID[] = "test_uuid_001";

static bool g_callbackCalled = false;

static void CallbackDeviceVerifyPass(AuthHandle authHandle, const NodeInfo *info)
{
    g_callbackCalled = true;
}

static void CallbackDeviceDisconnect(AuthHandle authHandle)
{
    g_callbackCalled = true;
}

static void CallbackGroupCreated(const char *groupId, int32_t groupType)
{
    g_callbackCalled = true;
}

static void CallbackGroupDeleted(const char *groupId, int32_t groupType)
{
    g_callbackCalled = true;
}

static void CallbackDeviceBound(const char *udid, const char *groupInfo)
{
    g_callbackCalled = true;
}

static void CallbackDeviceNotTrusted(const char *peerUdid)
{
    g_callbackCalled = true;
}

class AuthDeviceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthDeviceTest::SetUpTestCase() {}

void AuthDeviceTest::TearDownTestCase() {}

void AuthDeviceTest::SetUp()
{
    AUTH_LOGI(AUTH_TEST, "AuthDeviceTest start");
    g_callbackCalled = false;
    g_isInit = false;
    g_regDataChangeListener = false;
    (void)memset_s(&g_verifyListener, sizeof(g_verifyListener), 0, sizeof(g_verifyListener));
    (void)memset_s(&g_groupChangeListener, sizeof(g_groupChangeListener), 0, sizeof(g_groupChangeListener));
}

void AuthDeviceTest::TearDown()
{
    g_isInit = false;
    g_regDataChangeListener = false;
    (void)memset_s(&g_verifyListener, sizeof(g_verifyListener), 0, sizeof(g_verifyListener));
    (void)memset_s(&g_groupChangeListener, sizeof(g_groupChangeListener), 0, sizeof(g_groupChangeListener));
}

static AuthManager *CreateTestAuthManager(int64_t authId, bool isServer = false,
    AuthLinkType linkType = AUTH_LINK_TYPE_WIFI, SoftBusVersion version = SOFTBUS_NEW_V1)
{
    AuthManager *auth = static_cast<AuthManager *>(SoftBusCalloc(sizeof(AuthManager)));
    if (auth == nullptr) {
        return nullptr;
    }
    auth->authId = authId;
    auth->isServer = isServer;
    auth->version = version;
    auth->connId[linkType] = 1;
    auth->connInfo[linkType].type = linkType;
    if (strcpy_s(auth->uuid, UUID_BUF_LEN, TEST_UUID) != EOK) {
        SoftBusFree(auth);
        return nullptr;
    }
    return auth;
}

/*
 * @tc.name: IS_NEED_AUTH_LIMIT_TEST_001
 * @tc.desc: Test IsNeedAuthLimit with null param
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, IS_NEED_AUTH_LIMIT_TEST_001, TestSize.Level1)
{
    bool ret = IsNeedAuthLimit(NULL);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: IS_NEED_AUTH_LIMIT_TEST_002
 * @tc.desc: Test IsNeedAuthLimit when not init
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, IS_NEED_AUTH_LIMIT_TEST_002, TestSize.Level1)
{
    bool ret = IsNeedAuthLimit("testHash");
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: IS_NEED_AUTH_LIMIT_TEST_003
 * @tc.desc: Test IsNeedAuthLimit when key exists but time expired
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, IS_NEED_AUTH_LIMIT_TEST_003, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    EXPECT_CALL(mock, LnnMapInit).Times(1);
    AuthMapInit();
    const char *udidHash = "testHash";
    uint64_t storedTime = TEST_CURRENT_TIME - DELAY_AUTH_TIME - 1;
    EXPECT_CALL(mock, LnnMapGet).WillOnce(Return((void *)&storedTime));
    EXPECT_CALL(mock, GetCurrentTimeMsMock).WillOnce(Return(TEST_CURRENT_TIME));
    bool ret = IsNeedAuthLimit(udidHash);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: IS_NEED_AUTH_LIMIT_TEST_004
 * @tc.desc: Test IsNeedAuthLimit when key exists and within delay time
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, IS_NEED_AUTH_LIMIT_TEST_004, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    EXPECT_CALL(mock, LnnMapInit).Times(1);
    AuthMapInit();
    const char *udidHash = "testHash";
    uint64_t storedTime = TEST_CURRENT_TIME - 1000;
    EXPECT_CALL(mock, LnnMapGet).WillOnce(Return((void *)&storedTime));
    EXPECT_CALL(mock, GetCurrentTimeMsMock).WillOnce(Return(TEST_CURRENT_TIME));
    bool ret = IsNeedAuthLimit(udidHash);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: IS_NEED_AUTH_LIMIT_TEST_005
 * @tc.desc: Test IsNeedAuthLimit when LnnMapGet returns NULL
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, IS_NEED_AUTH_LIMIT_TEST_005, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    EXPECT_CALL(mock, LnnMapInit).Times(1);
    AuthMapInit();
    EXPECT_CALL(mock, LnnMapGet).WillOnce(Return(nullptr));
    bool ret = IsNeedAuthLimit("testHash");
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: AUTH_DELETE_LIMIT_MAP_TEST_001
 * @tc.desc: Test AuthDeleteLimitMap with null param
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DELETE_LIMIT_MAP_TEST_001, TestSize.Level1)
{
    AuthDeleteLimitMap(NULL);
}

/*
 * @tc.name: AUTH_DELETE_LIMIT_MAP_TEST_002
 * @tc.desc: Test AuthDeleteLimitMap when not init
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DELETE_LIMIT_MAP_TEST_002, TestSize.Level1)
{
    g_isInit = false;
    AuthDeleteLimitMap("testHash");
}

/*
 * @tc.name: AUTH_DELETE_LIMIT_MAP_TEST_003
 * @tc.desc: Test AuthDeleteLimitMap success
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DELETE_LIMIT_MAP_TEST_003, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    EXPECT_CALL(mock, LnnMapInit).Times(1);
    AuthMapInit();
    EXPECT_CALL(mock, LnnMapErase).WillOnce(Return(SOFTBUS_OK));
    AuthDeleteLimitMap("testHash");
}

/*
 * @tc.name: CLEAR_AUTH_LIMIT_MAP_TEST_001
 * @tc.desc: Test ClearAuthLimitMap when not init
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, CLEAR_AUTH_LIMIT_MAP_TEST_001, TestSize.Level1)
{
    g_isInit = false;
    ClearAuthLimitMap();
}

/*
 * @tc.name: CLEAR_AUTH_LIMIT_MAP_TEST_002
 * @tc.desc: Test ClearAuthLimitMap success
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, CLEAR_AUTH_LIMIT_MAP_TEST_002, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    EXPECT_CALL(mock, LnnMapInit).Times(1);
    AuthMapInit();
    EXPECT_CALL(mock, LnnMapDelete).Times(1);
    ClearAuthLimitMap();
}

/*
 * @tc.name: AUTH_ADD_NODE_TO_LIMIT_MAP_TEST_001
 * @tc.desc: Test AuthAddNodeToLimitMap with null udid
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_ADD_NODE_TO_LIMIT_MAP_TEST_001, TestSize.Level1)
{
    AuthAddNodeToLimitMap(NULL, SOFTBUS_AUTH_HICHAIN_LOCAL_IDENTITY_NOT_EXIST);
}

/*
 * @tc.name: AUTH_ADD_NODE_TO_LIMIT_MAP_TEST_002
 * @tc.desc: Test AuthAddNodeToLimitMap with non-matching reason
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_ADD_NODE_TO_LIMIT_MAP_TEST_002, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    AuthAddNodeToLimitMap(TEST_UDID, SOFTBUS_OK);
}

/*
 * @tc.name: AUTH_ADD_NODE_TO_LIMIT_MAP_TEST_003
 * @tc.desc: Test AuthAddNodeToLimitMap with hash generation failure
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_ADD_NODE_TO_LIMIT_MAP_TEST_003, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    EXPECT_CALL(mock, GetCurrentTimeMsMock).WillOnce(Return(TEST_CURRENT_TIME));
    EXPECT_CALL(mock, SoftBusGenerateStrHash).WillOnce(Return(SOFTBUS_ENCRYPT_ERR));
    AuthAddNodeToLimitMap(TEST_UDID, SOFTBUS_AUTH_HICHAIN_LOCAL_IDENTITY_NOT_EXIST);
}

/*
 * @tc.name: AUTH_ADD_NODE_TO_LIMIT_MAP_TEST_004
 * @tc.desc: Test AuthAddNodeToLimitMap with convert hex string failure
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_ADD_NODE_TO_LIMIT_MAP_TEST_004, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    EXPECT_CALL(mock, GetCurrentTimeMsMock).WillOnce(Return(TEST_CURRENT_TIME));
    EXPECT_CALL(mock, SoftBusGenerateStrHash).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConvertBytesToUpperCaseHexString).WillOnce(Return(SOFTBUS_ENCRYPT_ERR));
    AuthAddNodeToLimitMap(TEST_UDID, SOFTBUS_AUTH_HICHAIN_GROUP_NOT_EXIST);
}

/*
 * @tc.name: AUTH_ADD_NODE_TO_LIMIT_MAP_TEST_005
 * @tc.desc: Test AuthAddNodeToLimitMap success
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_ADD_NODE_TO_LIMIT_MAP_TEST_005, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    EXPECT_CALL(mock, LnnMapInit).Times(1);
    AuthMapInit();
    EXPECT_CALL(mock, GetCurrentTimeMsMock).WillOnce(Return(TEST_CURRENT_TIME));
    EXPECT_CALL(mock, SoftBusGenerateStrHash).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConvertBytesToUpperCaseHexString).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnMapSet).WillOnce(Return(SOFTBUS_OK));
    AuthAddNodeToLimitMap(TEST_UDID, SOFTBUS_AUTH_HICHAIN_NO_CANDIDATE_GROUP);
    EXPECT_TRUE(g_isInit);
}

/*
 * @tc.name: AUTH_ADD_NODE_TO_LIMIT_MAP_TEST_006
 * @tc.desc: Test AuthAddNodeToLimitMap with AuthMapInit failure
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_ADD_NODE_TO_LIMIT_MAP_TEST_006, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    g_isInit = false;
    EXPECT_CALL(mock, GetCurrentTimeMsMock).WillOnce(Return(TEST_CURRENT_TIME));
    EXPECT_CALL(mock, SoftBusGenerateStrHash).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConvertBytesToUpperCaseHexString).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnMapInit).Times(1);
    AuthAddNodeToLimitMap(TEST_UDID, SOFTBUS_AUTH_HICHAIN_LOCAL_IDENTITY_NOT_EXIST);
}

/*
 * @tc.name: AUTH_DEVICE_POST_TRANS_DATA_TEST_001
 * @tc.desc: Test AuthDevicePostTransData with null dataInfo
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_POST_TRANS_DATA_TEST_001, TestSize.Level1)
{
    AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    int32_t ret = AuthDevicePostTransData(handle, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_DEVICE_POST_TRANS_DATA_TEST_002
 * @tc.desc: Test AuthDevicePostTransData with invalid link type
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_POST_TRANS_DATA_TEST_002, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_MAX };
    AuthTransData dataInfo;
    (void)memset_s(&dataInfo, sizeof(dataInfo), 0, sizeof(dataInfo));
    dataInfo.module = MODULE_AUTH_CONNECTION;
    int32_t ret = AuthDevicePostTransData(handle, &dataInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_DEVICE_POST_TRANS_DATA_TEST_003
 * @tc.desc: Test AuthDevicePostTransData auth not found
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_POST_TRANS_DATA_TEST_003, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    AuthTransData dataInfo;
    (void)memset_s(&dataInfo, sizeof(dataInfo), 0, sizeof(dataInfo));
    dataInfo.module = MODULE_AUTH_CONNECTION;
    EXPECT_CALL(mock, GetAuthManagerByAuthId).WillOnce(Return(nullptr));
    int32_t ret = AuthDevicePostTransData(handle, &dataInfo);
    EXPECT_EQ(ret, SOFTBUS_AUTH_NOT_FOUND);
}

/*
 * @tc.name: AUTH_DEVICE_POST_TRANS_DATA_TEST_004
 * @tc.desc: Test AuthDevicePostTransData encrypt fail
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_POST_TRANS_DATA_TEST_004, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    AuthManager *auth = CreateTestAuthManager(TEST_AUTH_ID);
    ASSERT_NE(auth, nullptr);
    AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    AuthTransData dataInfo;
    (void)memset_s(&dataInfo, sizeof(dataInfo), 0, sizeof(dataInfo));
    dataInfo.module = MODULE_AUTH_CONNECTION;
    EXPECT_CALL(mock, GetAuthManagerByAuthId).WillOnce(Return(auth));
    EXPECT_CALL(mock, EncryptInner).WillOnce(Return(SOFTBUS_ENCRYPT_ERR));
    EXPECT_CALL(mock, DelDupAuthManager).Times(1);
    int32_t ret = AuthDevicePostTransData(handle, &dataInfo);
    EXPECT_EQ(ret, SOFTBUS_ENCRYPT_ERR);
    SoftBusFree(auth);
}

/*
 * @tc.name: AUTH_DEVICE_POST_TRANS_DATA_TEST_005
 * @tc.desc: Test AuthDevicePostTransData post data fail
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_POST_TRANS_DATA_TEST_005, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    AuthManager *auth = CreateTestAuthManager(TEST_AUTH_ID);
    ASSERT_NE(auth, nullptr);
    AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    AuthTransData dataInfo;
    (void)memset_s(&dataInfo, sizeof(dataInfo), 0, sizeof(dataInfo));
    dataInfo.module = MODULE_AUTH_CONNECTION;
    uint8_t *encData = static_cast<uint8_t *>(SoftBusMalloc(32));
    ASSERT_NE(encData, nullptr);
    EXPECT_CALL(mock, GetAuthManagerByAuthId).WillOnce(Return(auth));
    EXPECT_CALL(mock, EncryptInner).WillOnce(DoAll(SetArgPointee<3>(encData), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, PostAuthData).WillOnce(Return(SOFTBUS_AUTH_SEND_FAIL));
    EXPECT_CALL(mock, DelDupAuthManager).Times(1);
    int32_t ret = AuthDevicePostTransData(handle, &dataInfo);
    EXPECT_EQ(ret, SOFTBUS_AUTH_SEND_FAIL);
    SoftBusFree(auth);
}

/*
 * @tc.name: AUTH_DEVICE_POST_TRANS_DATA_TEST_006
 * @tc.desc: Test AuthDevicePostTransData success
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_POST_TRANS_DATA_TEST_006, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    AuthManager *auth = CreateTestAuthManager(TEST_AUTH_ID);
    ASSERT_NE(auth, nullptr);
    AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    AuthTransData dataInfo;
    (void)memset_s(&dataInfo, sizeof(dataInfo), 0, sizeof(dataInfo));
    dataInfo.module = MODULE_AUTH_CONNECTION;
    uint8_t *encData = static_cast<uint8_t *>(SoftBusMalloc(32));
    ASSERT_NE(encData, nullptr);
    EXPECT_CALL(mock, GetAuthManagerByAuthId).WillOnce(Return(auth));
    EXPECT_CALL(mock, EncryptInner).WillOnce(DoAll(SetArgPointee<3>(encData), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, PostAuthData).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, DelDupAuthManager).Times(1);
    int32_t ret = AuthDevicePostTransData(handle, &dataInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(auth);
}

/*
 * @tc.name: AUTH_DEVICE_ENCRYPT_TEST_001
 * @tc.desc: Test AuthDeviceEncrypt with invalid params
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_ENCRYPT_TEST_001, TestSize.Level1)
{
    AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    uint8_t inData[] = "test";
    uint8_t outData[128] = {0};
    uint32_t outLen = sizeof(outData);
    EXPECT_EQ(AuthDeviceEncrypt(NULL, inData, sizeof(inData), outData, &outLen), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(AuthDeviceEncrypt(&handle, NULL, sizeof(inData), outData, &outLen), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(AuthDeviceEncrypt(&handle, inData, 0, outData, &outLen), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(AuthDeviceEncrypt(&handle, inData, sizeof(inData), NULL, &outLen), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(AuthDeviceEncrypt(&handle, inData, sizeof(inData), outData, NULL), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_DEVICE_ENCRYPT_TEST_002
 * @tc.desc: Test AuthDeviceEncrypt auth not found
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_ENCRYPT_TEST_002, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    uint8_t inData[] = "test";
    uint8_t outData[128] = {0};
    uint32_t outLen = sizeof(outData);
    EXPECT_CALL(mock, GetAuthManagerByAuthId).WillOnce(Return(nullptr));
    int32_t ret = AuthDeviceEncrypt(&handle, inData, sizeof(inData), outData, &outLen);
    EXPECT_EQ(ret, SOFTBUS_AUTH_NOT_FOUND);
}

/*
 * @tc.name: AUTH_DEVICE_ENCRYPT_TEST_003
 * @tc.desc: Test AuthDeviceEncrypt encrypt fail
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_ENCRYPT_TEST_003, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    AuthManager *auth = CreateTestAuthManager(TEST_AUTH_ID);
    ASSERT_NE(auth, nullptr);
    AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    uint8_t inData[] = "test";
    uint8_t outData[128] = {0};
    uint32_t outLen = sizeof(outData);
    EXPECT_CALL(mock, GetAuthManagerByAuthId).WillOnce(Return(auth));
    EXPECT_CALL(mock, EncryptData).WillOnce(Return(SOFTBUS_ENCRYPT_ERR));
    EXPECT_CALL(mock, DelDupAuthManager).Times(1);
    int32_t ret = AuthDeviceEncrypt(&handle, inData, sizeof(inData), outData, &outLen);
    EXPECT_EQ(ret, SOFTBUS_ENCRYPT_ERR);
    SoftBusFree(auth);
}

/*
 * @tc.name: AUTH_DEVICE_ENCRYPT_TEST_004
 * @tc.desc: Test AuthDeviceEncrypt success
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_ENCRYPT_TEST_004, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    AuthManager *auth = CreateTestAuthManager(TEST_AUTH_ID);
    ASSERT_NE(auth, nullptr);
    AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    uint8_t inData[] = "test";
    uint8_t outData[128] = {0};
    uint32_t outLen = sizeof(outData);
    EXPECT_CALL(mock, GetAuthManagerByAuthId).WillOnce(Return(auth));
    EXPECT_CALL(mock, EncryptData).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, DelDupAuthManager).Times(1);
    int32_t ret = AuthDeviceEncrypt(&handle, inData, sizeof(inData), outData, &outLen);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(auth);
}

/*
 * @tc.name: AUTH_DEVICE_DECRYPT_TEST_001
 * @tc.desc: Test AuthDeviceDecrypt fail
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_DECRYPT_TEST_001, TestSize.Level1)
{
    AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    uint8_t inData[] = "test";
    uint8_t outData[128] = {0};
    uint32_t outLen = sizeof(outData);
    EXPECT_EQ(AuthDeviceDecrypt(NULL, inData, sizeof(inData), outData, &outLen), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(AuthDeviceDecrypt(&handle, NULL, sizeof(inData), outData, &outLen), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_DEVICE_DECRYPT_TEST_002
 * @tc.desc: Test AuthDeviceDecrypt auth not found
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_DECRYPT_TEST_002, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    uint8_t inData[] = "test";
    uint8_t outData[128] = {0};
    uint32_t outLen = sizeof(outData);
    EXPECT_CALL(mock, AuthGetDecryptSize).WillOnce(Return(sizeof(outData)));
    EXPECT_CALL(mock, GetAuthManagerByAuthId).WillOnce(Return(nullptr));
    int32_t ret = AuthDeviceDecrypt(&handle, inData, sizeof(inData), outData, &outLen);
    EXPECT_EQ(ret, SOFTBUS_AUTH_NOT_FOUND);
}

/*
 * @tc.name: AUTH_DEVICE_DECRYPT_TEST_003
 * @tc.desc: Test AuthDeviceDecrypt decrypt fail
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_DECRYPT_TEST_003, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    AuthManager *auth = CreateTestAuthManager(TEST_AUTH_ID);
    ASSERT_NE(auth, nullptr);
    AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    uint8_t inData[] = "test";
    uint8_t outData[128] = {0};
    uint32_t outLen = sizeof(outData);
    EXPECT_CALL(mock, AuthGetDecryptSize).WillOnce(Return(sizeof(outData)));
    EXPECT_CALL(mock, GetAuthManagerByAuthId).WillOnce(Return(auth));
    EXPECT_CALL(mock, DecryptData).WillOnce(Return(SOFTBUS_ENCRYPT_ERR));
    EXPECT_CALL(mock, DelDupAuthManager).Times(1);
    int32_t ret = AuthDeviceDecrypt(&handle, inData, sizeof(inData), outData, &outLen);
    EXPECT_EQ(ret, SOFTBUS_ENCRYPT_ERR);
    SoftBusFree(auth);
}

/*
 * @tc.name: AUTH_DEVICE_DECRYPT_TEST_004
 * @tc.desc: Test AuthDeviceDecrypt success
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_DECRYPT_TEST_004, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    AuthManager *auth = CreateTestAuthManager(TEST_AUTH_ID);
    ASSERT_NE(auth, nullptr);
    AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    uint8_t inData[] = "test";
    uint8_t outData[128] = {0};
    uint32_t outLen = sizeof(outData);
    EXPECT_CALL(mock, AuthGetDecryptSize).WillOnce(Return(sizeof(outData)));
    EXPECT_CALL(mock, GetAuthManagerByAuthId).WillOnce(Return(auth));
    EXPECT_CALL(mock, DecryptData).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, DelDupAuthManager).Times(1);
    int32_t ret = AuthDeviceDecrypt(&handle, inData, sizeof(inData), outData, &outLen);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(auth);
}

/*
 * @tc.name: AUTH_DEVICE_GET_CONN_INFO_TEST_001
 * @tc.desc: Test AuthDeviceGetConnInfo with null connInfo
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_GET_CONN_INFO_TEST_001, TestSize.Level1)
{
    AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    EXPECT_EQ(AuthDeviceGetConnInfo(handle, NULL), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_DEVICE_GET_CONN_INFO_TEST_002
 * @tc.desc: Test AuthDeviceGetConnInfo with invalid link type
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_GET_CONN_INFO_TEST_002, TestSize.Level1)
{
    AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_MAX };
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    EXPECT_EQ(AuthDeviceGetConnInfo(handle, &connInfo), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_DEVICE_GET_CONN_INFO_TEST_003
 * @tc.desc: Test AuthDeviceGetConnInfo auth not found
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_GET_CONN_INFO_TEST_003, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    EXPECT_CALL(mock, GetAuthManagerByAuthId).WillOnce(Return(nullptr));
    EXPECT_EQ(AuthDeviceGetConnInfo(handle, &connInfo), SOFTBUS_AUTH_NOT_FOUND);
}

/*
 * @tc.name: AUTH_DEVICE_GET_CONN_INFO_TEST_004
 * @tc.desc: Test AuthDeviceGetConnInfo success
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_GET_CONN_INFO_TEST_004, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    AuthManager *auth = CreateTestAuthManager(TEST_AUTH_ID);
    ASSERT_NE(auth, nullptr);
    AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    EXPECT_CALL(mock, GetAuthManagerByAuthId).WillOnce(Return(auth));
    EXPECT_CALL(mock, DelDupAuthManager).Times(1);
    int32_t ret = AuthDeviceGetConnInfo(handle, &connInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(connInfo.type, AUTH_LINK_TYPE_WIFI);
    SoftBusFree(auth);
}

/*
 * @tc.name: AUTH_DEVICE_GET_SERVER_SIDE_TEST_001
 * @tc.desc: Test AuthDeviceGetServerSide with null isServer
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_GET_SERVER_SIDE_TEST_001, TestSize.Level1)
{
    EXPECT_EQ(AuthDeviceGetServerSide(TEST_AUTH_ID, NULL), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_DEVICE_GET_SERVER_SIDE_TEST_002
 * @tc.desc: Test AuthDeviceGetServerSide auth not found
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_GET_SERVER_SIDE_TEST_002, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    bool isServer = false;
    EXPECT_CALL(mock, GetAuthManagerByAuthId).WillOnce(Return(nullptr));
    EXPECT_EQ(AuthDeviceGetServerSide(TEST_AUTH_ID, &isServer), SOFTBUS_AUTH_NOT_FOUND);
}

/*
 * @tc.name: AUTH_DEVICE_GET_SERVER_SIDE_TEST_003
 * @tc.desc: Test AuthDeviceGetServerSide success
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_GET_SERVER_SIDE_TEST_003, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    AuthManager *auth = CreateTestAuthManager(TEST_AUTH_ID, true);
    ASSERT_NE(auth, nullptr);
    bool isServer = false;
    EXPECT_CALL(mock, GetAuthManagerByAuthId).WillOnce(Return(auth));
    EXPECT_CALL(mock, DelDupAuthManager).Times(1);
    int32_t ret = AuthDeviceGetServerSide(TEST_AUTH_ID, &isServer);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(isServer);
    SoftBusFree(auth);
}

/*
 * @tc.name: AUTH_DEVICE_GET_DEVICE_UUID_TEST_001
 * @tc.desc: Test AuthDeviceGetDeviceUuid with null uuid
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_GET_DEVICE_UUID_TEST_001, TestSize.Level1)
{
    EXPECT_EQ(AuthDeviceGetDeviceUuid(TEST_AUTH_ID, NULL, UUID_BUF_LEN), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_DEVICE_GET_DEVICE_UUID_TEST_002
 * @tc.desc: Test AuthDeviceGetDeviceUuid auth not found
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_GET_DEVICE_UUID_TEST_002, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    char uuid[UUID_BUF_LEN] = {0};
    EXPECT_CALL(mock, GetAuthManagerByAuthId).WillOnce(Return(nullptr));
    EXPECT_EQ(AuthDeviceGetDeviceUuid(TEST_AUTH_ID, uuid, UUID_BUF_LEN), SOFTBUS_AUTH_NOT_FOUND);
}

/*
 * @tc.name: AUTH_DEVICE_GET_DEVICE_UUID_TEST_003
 * @tc.desc: Test AuthDeviceGetDeviceUuid success
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_GET_DEVICE_UUID_TEST_003, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    AuthManager *auth = CreateTestAuthManager(TEST_AUTH_ID);
    ASSERT_NE(auth, nullptr);
    char uuid[UUID_BUF_LEN] = {0};
    EXPECT_CALL(mock, GetAuthManagerByAuthId).WillOnce(Return(auth));
    EXPECT_CALL(mock, DelDupAuthManager).Times(1);
    int32_t ret = AuthDeviceGetDeviceUuid(TEST_AUTH_ID, uuid, UUID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_STREQ(uuid, TEST_UUID);
    SoftBusFree(auth);
}

/*
 * @tc.name: AUTH_DEVICE_GET_VERSION_TEST_001
 * @tc.desc: Test AuthDeviceGetVersion with null version
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_GET_VERSION_TEST_001, TestSize.Level1)
{
    EXPECT_EQ(AuthDeviceGetVersion(TEST_AUTH_ID, NULL), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_DEVICE_GET_VERSION_TEST_002
 * @tc.desc: Test AuthDeviceGetVersion auth not found
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_GET_VERSION_TEST_002, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    SoftBusVersion version;
    EXPECT_CALL(mock, GetAuthManagerByAuthId).WillOnce(Return(nullptr));
    EXPECT_EQ(AuthDeviceGetVersion(TEST_AUTH_ID, &version), SOFTBUS_AUTH_NOT_FOUND);
}

/*
 * @tc.name: AUTH_DEVICE_GET_VERSION_TEST_003
 * @tc.desc: Test AuthDeviceGetVersion success
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_GET_VERSION_TEST_003, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    AuthManager *auth = CreateTestAuthManager(TEST_AUTH_ID);
    ASSERT_NE(auth, nullptr);
    SoftBusVersion version;
    EXPECT_CALL(mock, GetAuthManagerByAuthId).WillOnce(Return(auth));
    EXPECT_CALL(mock, DelDupAuthManager).Times(1);
    int32_t ret = AuthDeviceGetVersion(TEST_AUTH_ID, &version);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(version, SOFTBUS_NEW_V1);
    SoftBusFree(auth);
}

/*
 * @tc.name: AUTH_DEVICE_NOT_TRUST_TEST_001
 * @tc.desc: Test AuthDeviceNotTrust with null param
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_NOT_TRUST_TEST_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(AuthDeviceNotTrust(NULL));
}

/*
 * @tc.name: AUTH_DEVICE_NOT_TRUST_TEST_002
 * @tc.desc: Test AuthDeviceNotTrust with empty string
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_NOT_TRUST_TEST_002, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(AuthDeviceNotTrust(""));
}

/*
 * @tc.name: AUTH_DEVICE_NOT_TRUST_TEST_003
 * @tc.desc: Test AuthDeviceNotTrust with get networkId fail
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_NOT_TRUST_TEST_003, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    EXPECT_CALL(mock, LnnGetNetworkIdByUdid).WillOnce(Return(SOFTBUS_NOT_FIND));
    EXPECT_NO_FATAL_FAILURE(AuthDeviceNotTrust(TEST_UDID));
}

/*
 * @tc.name: AUTH_DEVICE_NOT_TRUST_TEST_004
 * @tc.desc: Test AuthDeviceNotTrust success
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_NOT_TRUST_TEST_004, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    EXPECT_CALL(mock, LnnGetNetworkIdByUdid).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, RemoveNotPassedAuthManagerByUdid).Times(1);
    EXPECT_CALL(mock, AuthSessionHandleDeviceNotTrusted).Times(1);
    EXPECT_CALL(mock, LnnDeleteSpecificTrustedDevInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, JudgeDeviceTypeAndGetOsAccountIds).WillOnce(Return(100));
    EXPECT_CALL(mock, LnnHbOnTrustedRelationReduced).Times(1);
    EXPECT_CALL(mock, AuthRemoveDeviceKeyByUdidPacked).Times(1);
    EXPECT_CALL(mock, LnnRequestLeaveSpecific).WillOnce(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(AuthDeviceNotTrust(TEST_UDID));
}

/*
 * @tc.name: AUTH_NOTIFY_DEVICE_VERIFY_PASSED_TEST_001
 * @tc.desc: Test AuthNotifyDeviceVerifyPassed with null nodeInfo
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_NOTIFY_DEVICE_VERIFY_PASSED_TEST_001, TestSize.Level1)
{
    AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    EXPECT_NO_FATAL_FAILURE(AuthNotifyDeviceVerifyPassed(handle, NULL));
}

/*
 * @tc.name: AUTH_NOTIFY_DEVICE_VERIFY_PASSED_TEST_002
 * @tc.desc: Test AuthNotifyDeviceVerifyPassed auth not found
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_NOTIFY_DEVICE_VERIFY_PASSED_TEST_002, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(nodeInfo), 0, sizeof(nodeInfo));
    EXPECT_CALL(mock, GetAuthManagerByAuthId).WillOnce(Return(nullptr));
    EXPECT_NO_FATAL_FAILURE(AuthNotifyDeviceVerifyPassed(handle, &nodeInfo));
}

/*
 * @tc.name: AUTH_NOTIFY_DEVICE_VERIFY_PASSED_TEST_003
 * @tc.desc: Test AuthNotifyDeviceVerifyPassed with P2P link type
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_NOTIFY_DEVICE_VERIFY_PASSED_TEST_003, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    AuthManager *auth = CreateTestAuthManager(TEST_AUTH_ID, false, AUTH_LINK_TYPE_P2P);
    ASSERT_NE(auth, nullptr);
    AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_P2P };
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(nodeInfo), 0, sizeof(nodeInfo));
    EXPECT_CALL(mock, GetAuthManagerByAuthId).WillOnce(Return(auth));
    EXPECT_CALL(mock, DelDupAuthManager).Times(1);
    EXPECT_NO_FATAL_FAILURE(AuthNotifyDeviceVerifyPassed(handle, &nodeInfo));
    SoftBusFree(auth);
}

/*
 * @tc.name: AUTH_NOTIFY_DEVICE_VERIFY_PASSED_TEST_004
 * @tc.desc: Test AuthNotifyDeviceVerifyPassed with null verify callback
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_NOTIFY_DEVICE_VERIFY_PASSED_TEST_004, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    AuthManager *auth = CreateTestAuthManager(TEST_AUTH_ID, false, AUTH_LINK_TYPE_WIFI);
    ASSERT_NE(auth, nullptr);
    AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(nodeInfo), 0, sizeof(nodeInfo));
    EXPECT_CALL(mock, GetAuthManagerByAuthId).WillOnce(Return(auth));
    EXPECT_CALL(mock, DelDupAuthManager).Times(1);
    (void)memset_s(&g_verifyListener, sizeof(g_verifyListener), 0, sizeof(g_verifyListener));
    EXPECT_NO_FATAL_FAILURE(AuthNotifyDeviceVerifyPassed(handle, &nodeInfo));
    SoftBusFree(auth);
}

/*
 * @tc.name: AUTH_NOTIFY_DEVICE_VERIFY_PASSED_TEST_005
 * @tc.desc: Test AuthNotifyDeviceVerifyPassed with callback
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_NOTIFY_DEVICE_VERIFY_PASSED_TEST_005, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    AuthManager *auth = CreateTestAuthManager(TEST_AUTH_ID, false, AUTH_LINK_TYPE_WIFI);
    ASSERT_NE(auth, nullptr);
    AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(nodeInfo), 0, sizeof(nodeInfo));
    EXPECT_CALL(mock, GetAuthManagerByAuthId).WillOnce(Return(auth));
    EXPECT_CALL(mock, DelDupAuthManager).Times(1);
    g_callbackCalled = false;
    g_verifyListener.onDeviceVerifyPass = CallbackDeviceVerifyPass;
    EXPECT_NO_FATAL_FAILURE(AuthNotifyDeviceVerifyPassed(handle, &nodeInfo));
    EXPECT_TRUE(g_callbackCalled);
    g_verifyListener.onDeviceVerifyPass = nullptr;
    SoftBusFree(auth);
}

/*
 * @tc.name: AUTH_NOTIFY_DEVICE_DISCONNECT_TEST_001
 * @tc.desc: Test AuthNotifyDeviceDisconnect with null callback
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_NOTIFY_DEVICE_DISCONNECT_TEST_001, TestSize.Level1)
{
    (void)memset_s(&g_verifyListener, sizeof(g_verifyListener), 0, sizeof(g_verifyListener));
    AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    EXPECT_NO_FATAL_FAILURE(AuthNotifyDeviceDisconnect(handle));
}

/*
 * @tc.name: AUTH_NOTIFY_DEVICE_DISCONNECT_TEST_002
 * @tc.desc: Test AuthNotifyDeviceDisconnect with callback
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_NOTIFY_DEVICE_DISCONNECT_TEST_002, TestSize.Level1)
{
    g_callbackCalled = false;
    g_verifyListener.onDeviceDisconnect = CallbackDeviceDisconnect;
    AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    EXPECT_NO_FATAL_FAILURE(AuthNotifyDeviceDisconnect(handle));
    EXPECT_TRUE(g_callbackCalled);
    g_verifyListener.onDeviceDisconnect = nullptr;
}

/*
 * @tc.name: REG_AUTH_VERIFY_LISTENER_TEST_001
 * @tc.desc: Test RegAuthVerifyListener with null listener
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, REG_AUTH_VERIFY_LISTENER_TEST_001, TestSize.Level1)
{
    EXPECT_EQ(RegAuthVerifyListener(NULL), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: REG_AUTH_VERIFY_LISTENER_TEST_002
 * @tc.desc: Test RegAuthVerifyListener success
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, REG_AUTH_VERIFY_LISTENER_TEST_002, TestSize.Level1)
{
    AuthVerifyListener listener;
    (void)memset_s(&listener, sizeof(listener), 0, sizeof(listener));
    EXPECT_EQ(RegAuthVerifyListener(&listener), SOFTBUS_OK);
}

/*
 * @tc.name: UNREG_AUTH_VERIFY_LISTENER_TEST_001
 * @tc.desc: Test UnregAuthVerifyListener
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, UNREG_AUTH_VERIFY_LISTENER_TEST_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(UnregAuthVerifyListener());
}

/*
 * @tc.name: REG_GROUP_CHANGE_LISTENER_TEST_001
 * @tc.desc: Test RegGroupChangeListener with null listener
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, REG_GROUP_CHANGE_LISTENER_TEST_001, TestSize.Level1)
{
    EXPECT_EQ(RegGroupChangeListener(NULL), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: REG_GROUP_CHANGE_LISTENER_TEST_002
 * @tc.desc: Test RegGroupChangeListener success
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, REG_GROUP_CHANGE_LISTENER_TEST_002, TestSize.Level1)
{
    GroupChangeListener listener;
    (void)memset_s(&listener, sizeof(listener), 0, sizeof(listener));
    EXPECT_EQ(RegGroupChangeListener(&listener), SOFTBUS_OK);
}

/*
 * @tc.name: UNREG_GROUP_CHANGE_LISTENER_TEST_001
 * @tc.desc: Test UnregGroupChangeListener
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, UNREG_GROUP_CHANGE_LISTENER_TEST_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(UnregGroupChangeListener());
}

/*
 * @tc.name: ON_GROUP_CREATED_TEST_001
 * @tc.desc: Test OnGroupCreated with null callback
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, ON_GROUP_CREATED_TEST_001, TestSize.Level1)
{
    (void)memset_s(&g_groupChangeListener, sizeof(g_groupChangeListener), 0, sizeof(g_groupChangeListener));
    EXPECT_NO_FATAL_FAILURE(OnGroupCreated("groupId", 1));
}

/*
 * @tc.name: ON_GROUP_CREATED_TEST_002
 * @tc.desc: Test OnGroupCreated with callback
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, ON_GROUP_CREATED_TEST_002, TestSize.Level1)
{
    g_callbackCalled = false;
    g_groupChangeListener.onGroupCreated = CallbackGroupCreated;
    EXPECT_NO_FATAL_FAILURE(OnGroupCreated("groupId", 1));
    EXPECT_TRUE(g_callbackCalled);
    g_groupChangeListener.onGroupCreated = nullptr;
}

/*
 * @tc.name: ON_GROUP_DELETED_TEST_001
 * @tc.desc: Test OnGroupDeleted with null callback
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, ON_GROUP_DELETED_TEST_001, TestSize.Level1)
{
    (void)memset_s(&g_groupChangeListener, sizeof(g_groupChangeListener), 0, sizeof(g_groupChangeListener));
    EXPECT_NO_FATAL_FAILURE(OnGroupDeleted("groupId", 1));
}

/*
 * @tc.name: ON_GROUP_DELETED_TEST_002
 * @tc.desc: Test OnGroupDeleted with callback
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, ON_GROUP_DELETED_TEST_002, TestSize.Level1)
{
    g_callbackCalled = false;
    g_groupChangeListener.onGroupDeleted = CallbackGroupDeleted;
    EXPECT_NO_FATAL_FAILURE(OnGroupDeleted("groupId", 1));
    EXPECT_TRUE(g_callbackCalled);
    g_groupChangeListener.onGroupDeleted = nullptr;
}

/*
 * @tc.name: ON_DEVICE_BOUND_TEST_001
 * @tc.desc: Test OnDeviceBound with callback
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, ON_DEVICE_BOUND_TEST_001, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    g_callbackCalled = false;
    g_groupChangeListener.onDeviceBound = CallbackDeviceBound;
    EXPECT_CALL(mock, LnnInsertSpecificTrustedDevInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(OnDeviceBound(TEST_UDID, "groupInfo"));
    EXPECT_TRUE(g_callbackCalled);
    g_groupChangeListener.onDeviceBound = nullptr;
}

/*
 * @tc.name: ON_DEVICE_BOUND_TEST_002
 * @tc.desc: Test OnDeviceBound with null group callback
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, ON_DEVICE_BOUND_TEST_002, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    g_groupChangeListener.onDeviceBound = nullptr;
    EXPECT_CALL(mock, LnnInsertSpecificTrustedDevInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(OnDeviceBound(TEST_UDID, "groupInfo"));
}

/*
 * @tc.name: REG_TRUST_LISTENER_ON_HICHAIN_SA_START_TEST_001
 * @tc.desc: Test RegTrustListenerOnHichainSaStart fail
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, REG_TRUST_LISTENER_ON_HICHAIN_SA_START_TEST_001, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    EXPECT_CALL(mock, RegTrustDataChangeListener).WillOnce(Return(SOFTBUS_AUTH_REG_DATA_FAIL));
    int32_t ret = RegTrustListenerOnHichainSaStart();
    EXPECT_EQ(ret, SOFTBUS_AUTH_INIT_FAIL);
    EXPECT_FALSE(g_regDataChangeListener);
}

/*
 * @tc.name: REG_TRUST_LISTENER_ON_HICHAIN_SA_START_TEST_002
 * @tc.desc: Test RegTrustListenerOnHichainSaStart success
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, REG_TRUST_LISTENER_ON_HICHAIN_SA_START_TEST_002, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    EXPECT_CALL(mock, RegTrustDataChangeListener).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = RegTrustListenerOnHichainSaStart();
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(g_regDataChangeListener);
}

/*
 * @tc.name: RETRY_REG_TRUST_DATA_CHANGE_LISTENER_TEST_001
 * @tc.desc: Test RetryRegTrustDataChangeListener fail all retries
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, RETRY_REG_TRUST_DATA_CHANGE_LISTENER_TEST_001, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    EXPECT_CALL(mock, RegTrustDataChangeListener).Times(RETRY_REGDATA_TIMES)
        .WillRepeatedly(Return(SOFTBUS_AUTH_REG_DATA_FAIL));
    EXPECT_CALL(mock, SoftBusSleepMsMock).Times(RETRY_REGDATA_TIMES);
    int32_t ret = RetryRegTrustDataChangeListener();
    EXPECT_EQ(ret, SOFTBUS_AUTH_REG_DATA_FAIL);
}

/*
 * @tc.name: RETRY_REG_TRUST_DATA_CHANGE_LISTENER_TEST_002
 * @tc.desc: Test RetryRegTrustDataChangeListener success on second retry
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, RETRY_REG_TRUST_DATA_CHANGE_LISTENER_TEST_002, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    EXPECT_CALL(mock, RegTrustDataChangeListener)
        .WillOnce(Return(SOFTBUS_AUTH_REG_DATA_FAIL))
        .WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusSleepMsMock).Times(1);
    int32_t ret = RetryRegTrustDataChangeListener();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: AUTH_REGISTER_TO_DP_DELAY_TEST_001
 * @tc.desc: Test AuthRegisterToDpDelay RegisterToDp fail
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_REGISTER_TO_DP_DELAY_TEST_001, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    EXPECT_CALL(mock, RegisterToDp).WillOnce(Return(SOFTBUS_FUNC_NOT_REGISTER));
    int32_t ret = AuthRegisterToDpDelay();
    EXPECT_EQ(ret, SOFTBUS_FUNC_NOT_REGISTER);
}

/*
 * @tc.name: AUTH_REGISTER_TO_DP_DELAY_TEST_002
 * @tc.desc: Test AuthRegisterToDpDelay InitDbListDelay fail
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_REGISTER_TO_DP_DELAY_TEST_002, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    EXPECT_CALL(mock, RegisterToDp).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, InitDbListDelay).WillOnce(Return(SOFTBUS_NETWORK_DB_LOCK_INIT_FAILED));
    int32_t ret = AuthRegisterToDpDelay();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_DB_LOCK_INIT_FAILED);
}

/*
 * @tc.name: AUTH_REGISTER_TO_DP_DELAY_TEST_003
 * @tc.desc: Test AuthRegisterToDpDelay success
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_REGISTER_TO_DP_DELAY_TEST_003, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    EXPECT_CALL(mock, RegisterToDp).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, InitDbListDelay).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = AuthRegisterToDpDelay();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: AUTH_DEVICE_CLOSE_CONN_TEST_001
 * @tc.desc: Test AuthDeviceCloseConn with invalid type
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_CLOSE_CONN_TEST_001, TestSize.Level1)
{
    AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_MAX };
    EXPECT_NO_FATAL_FAILURE(AuthDeviceCloseConn(handle));
}

/*
 * @tc.name: AUTH_DEVICE_CLOSE_CONN_TEST_002
 * @tc.desc: Test AuthDeviceCloseConn auth not found
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_CLOSE_CONN_TEST_002, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    EXPECT_CALL(mock, GetAuthManagerByAuthId).WillOnce(Return(nullptr));
    EXPECT_NO_FATAL_FAILURE(AuthDeviceCloseConn(handle));
}

/*
 * @tc.name: AUTH_DEVICE_CLOSE_CONN_TEST_003
 * @tc.desc: Test AuthDeviceCloseConn WiFi type (do nothing)
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_CLOSE_CONN_TEST_003, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    AuthManager *auth = CreateTestAuthManager(TEST_AUTH_ID, false, AUTH_LINK_TYPE_WIFI);
    ASSERT_NE(auth, nullptr);
    AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    EXPECT_CALL(mock, GetAuthManagerByAuthId).WillOnce(Return(auth));
    EXPECT_CALL(mock, DelDupAuthManager).Times(1);
    EXPECT_CALL(mock, DisconnectAuthDevice).Times(0);
    EXPECT_NO_FATAL_FAILURE(AuthDeviceCloseConn(handle));
    SoftBusFree(auth);
}

/*
 * @tc.name: AUTH_DEVICE_CLOSE_CONN_TEST_004
 * @tc.desc: Test AuthDeviceCloseConn BR type (should disconnect)
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_CLOSE_CONN_TEST_004, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    AuthManager *auth = CreateTestAuthManager(TEST_AUTH_ID, false, AUTH_LINK_TYPE_BR);
    ASSERT_NE(auth, nullptr);
    AuthHandle handle = { .authId = TEST_AUTH_ID, .type = AUTH_LINK_TYPE_BR };
    EXPECT_CALL(mock, GetAuthManagerByAuthId).WillOnce(Return(auth));
    EXPECT_CALL(mock, DisconnectAuthDevice).Times(1);
    EXPECT_CALL(mock, DelDupAuthManager).Times(1);
    EXPECT_NO_FATAL_FAILURE(AuthDeviceCloseConn(handle));
    SoftBusFree(auth);
}

/*
 * @tc.name: AUTH_DEVICE_OPEN_CONN_TEST_001
 * @tc.desc: Test AuthDeviceOpenConn with null info
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_OPEN_CONN_TEST_001, TestSize.Level1)
{
    AuthConnCallback cb;
    (void)memset_s(&cb, sizeof(cb), 0, sizeof(cb));
    EXPECT_EQ(AuthDeviceOpenConn(NULL, TEST_REQUEST_ID, &cb), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_DEVICE_OPEN_CONN_TEST_002
 * @tc.desc: Test AuthDeviceOpenConn with invalid connInfo type
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_OPEN_CONN_TEST_002, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(connInfo), 0, sizeof(connInfo));
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    AuthConnCallback cb;
    (void)memset_s(&cb, sizeof(cb), 0, sizeof(cb));
    EXPECT_CALL(mock, CheckAuthConnCallback).WillOnce(Return(false));
    EXPECT_EQ(AuthDeviceOpenConn(&connInfo, TEST_REQUEST_ID, &cb), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_START_VERIFY_TEST_001
 * @tc.desc: Test AuthStartVerify with null params
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_START_VERIFY_TEST_001, TestSize.Level1)
{
    AuthVerifyCallback cb;
    (void)memset_s(&cb, sizeof(cb), 0, sizeof(cb));
    AuthVerifyParam param;
    (void)memset_s(&param, sizeof(param), 0, sizeof(param));
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(connInfo), 0, sizeof(connInfo));
    EXPECT_EQ(AuthStartVerify(NULL, &param, &cb), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(AuthStartVerify(&connInfo, NULL, &cb), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_START_CONN_VERIFY_TEST_001
 * @tc.desc: Test AuthStartConnVerify with null params
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_START_CONN_VERIFY_TEST_001, TestSize.Level1)
{
    AuthConnCallback cb;
    (void)memset_s(&cb, sizeof(cb), 0, sizeof(cb));
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(connInfo), 0, sizeof(connInfo));
    EXPECT_EQ(AuthStartConnVerify(NULL, TEST_REQUEST_ID, &cb, AUTH_MODULE_LNN, true), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_DIRECT_ONLINE_CREATE_AUTH_MANAGER_TEST_001
 * @tc.desc: Test AuthDirectOnlineCreateAuthManager with null info
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DIRECT_ONLINE_CREATE_AUTH_MANAGER_TEST_001, TestSize.Level1)
{
    EXPECT_EQ(AuthDirectOnlineCreateAuthManager(1, NULL), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_DIRECT_ONLINE_CREATE_AUTH_MANAGER_TEST_002
 * @tc.desc: Test AuthDirectOnlineCreateAuthManager with invalid connInfo type
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DIRECT_ONLINE_CREATE_AUTH_MANAGER_TEST_002, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.connInfo.type = AUTH_LINK_TYPE_MAX;
    EXPECT_CALL(mock, CheckAuthConnInfoTypeMock).WillOnce(Return(false));
    EXPECT_EQ(AuthDirectOnlineCreateAuthManager(1, &info), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_DIRECT_ONLINE_CREATE_AUTH_MANAGER_TEST_003
 * @tc.desc: Test AuthDirectOnlineCreateAuthManager non-BLE type fails
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DIRECT_ONLINE_CREATE_AUTH_MANAGER_TEST_003, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    EXPECT_CALL(mock, CheckAuthConnInfoTypeMock).WillOnce(Return(true));
    EXPECT_CALL(mock, RequireAuthLockMock).WillOnce(Return(true));
    EXPECT_CALL(mock, ReleaseAuthLockMock).Times(1);
    int32_t ret = AuthDirectOnlineCreateAuthManager(1, &info);
    EXPECT_EQ(ret, SOFTBUS_AUTH_UNEXPECTED_CONN_TYPE);
}

/*
 * @tc.name: AUTH_DIRECT_ONLINE_CREATE_AUTH_MANAGER_TEST_004
 * @tc.desc: Test AuthDirectOnlineCreateAuthManager require lock fail
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DIRECT_ONLINE_CREATE_AUTH_MANAGER_TEST_004, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    EXPECT_CALL(mock, CheckAuthConnInfoTypeMock).WillOnce(Return(true));
    EXPECT_CALL(mock, RequireAuthLockMock).WillOnce(Return(false));
    int32_t ret = AuthDirectOnlineCreateAuthManager(1, &info);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/*
 * @tc.name: AUTH_DIRECT_ONLINE_CREATE_AUTH_MANAGER_TEST_005
 * @tc.desc: Test AuthDirectOnlineCreateAuthManager get device auth manager null
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DIRECT_ONLINE_CREATE_AUTH_MANAGER_TEST_005, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    EXPECT_CALL(mock, CheckAuthConnInfoTypeMock).WillOnce(Return(true));
    EXPECT_CALL(mock, RequireAuthLockMock).WillOnce(Return(true));
    EXPECT_CALL(mock, GetDeviceAuthManager).WillOnce(Return(nullptr));
    EXPECT_CALL(mock, ReleaseAuthLockMock).Times(1);
    int32_t ret = AuthDirectOnlineCreateAuthManager(1, &info);
    EXPECT_EQ(ret, SOFTBUS_AUTH_NOT_FOUND);
}

/*
 * @tc.name: AUTH_DIRECT_ONLINE_CREATE_AUTH_MANAGER_TEST_006
 * @tc.desc: Test AuthDirectOnlineCreateAuthManager success
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DIRECT_ONLINE_CREATE_AUTH_MANAGER_TEST_006, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    AuthManager *auth = CreateTestAuthManager(TEST_AUTH_ID, false, AUTH_LINK_TYPE_BLE);
    ASSERT_NE(auth, nullptr);
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    EXPECT_CALL(mock, CheckAuthConnInfoTypeMock).WillOnce(Return(true));
    EXPECT_CALL(mock, RequireAuthLockMock).WillOnce(Return(true));
    EXPECT_CALL(mock, GetDeviceAuthManager).WillOnce(Return(auth));
    EXPECT_CALL(mock, ReleaseAuthLockMock).Times(1);
    int32_t ret = AuthDirectOnlineCreateAuthManager(1, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(auth);
}

/*
 * @tc.name: AUTH_DEVICE_GET_CONN_INFO_TEST_005
 * @tc.desc: Test AuthDeviceGetConnInfo with type below WIFI
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_DEVICE_GET_CONN_INFO_TEST_005, TestSize.Level1)
{
    AuthHandle handle = { .authId = TEST_AUTH_ID, .type = 0 };
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    EXPECT_EQ(AuthDeviceGetConnInfo(handle, &connInfo), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ON_DEVICE_NOT_TRUSTED_TEST_001
 * @tc.desc: Test OnDeviceNotTrusted with has profile and callback null
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, ON_DEVICE_NOT_TRUSTED_TEST_001, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    int32_t localUserId = 100;
    EXPECT_CALL(mock, RemoveNotPassedAuthManagerByUdid).Times(1);
    EXPECT_CALL(mock, AuthSessionHandleDeviceNotTrusted).Times(1);
    EXPECT_CALL(mock, DpHasAccessControlProfile(_, false, localUserId)).WillOnce(Return(false));
    EXPECT_CALL(mock, LnnDeleteLinkFinderInfo).Times(1);
    EXPECT_CALL(mock, DpHasAccessControlProfile(_, true, localUserId)).WillOnce(Return(true));
    EXPECT_CALL(mock, LnnDeleteSpecificTrustedDevInfo).Times(0);
    (void)memset_s(&g_verifyListener, sizeof(g_verifyListener), 0, sizeof(g_verifyListener));
    EXPECT_NO_FATAL_FAILURE(OnDeviceNotTrusted(TEST_UDID, localUserId, HICHAIN_DEVICE));
}

/*
 * @tc.name: ON_DEVICE_NOT_TRUSTED_TEST_002
 * @tc.desc: Test OnDeviceNotTrusted with no profile and callback set
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, ON_DEVICE_NOT_TRUSTED_TEST_002, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    int32_t localUserId = 100;
    g_callbackCalled = false;
    g_verifyListener.onDeviceNotTrusted = CallbackDeviceNotTrusted;
    EXPECT_CALL(mock, RemoveNotPassedAuthManagerByUdid).Times(1);
    EXPECT_CALL(mock, AuthSessionHandleDeviceNotTrusted).Times(1);
    EXPECT_CALL(mock, DpHasAccessControlProfile(_, false, localUserId)).WillOnce(Return(false));
    EXPECT_CALL(mock, LnnDeleteLinkFinderInfo).Times(1);
    EXPECT_CALL(mock, DpHasAccessControlProfile(_, true, localUserId)).WillOnce(Return(false));
    EXPECT_CALL(mock, LnnDeleteSpecificTrustedDevInfo).Times(1);
    EXPECT_CALL(mock, LnnHbOnTrustedRelationReduced).Times(1);
    EXPECT_CALL(mock, AuthRemoveDeviceKeyByUdidPacked).Times(1);
    EXPECT_NO_FATAL_FAILURE(OnDeviceNotTrusted(TEST_UDID, localUserId, HICHAIN_DEVICE));
    EXPECT_TRUE(g_callbackCalled);
    g_verifyListener.onDeviceNotTrusted = nullptr;
}

/*
 * @tc.name: AUTH_MAP_INIT_TEST_001
 * @tc.desc: Test AuthMapInit success
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, AUTH_MAP_INIT_TEST_001, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    EXPECT_CALL(mock, LnnMapInit).Times(1);
    bool ret = AuthMapInit();
    EXPECT_TRUE(ret);
    EXPECT_TRUE(g_isInit);
}

/*
 * @tc.name: VERIFY_DEVICE_TEST_001
 * @tc.desc: Test VerifyDevice with RegTrustDataChangeListener failure
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(AuthDeviceTest, VERIFY_DEVICE_TEST_001, TestSize.Level1)
{
    NiceMock<AuthDeviceDepsInterfaceMock> mock;
    g_regDataChangeListener = false;
    EXPECT_CALL(mock, GenSeqMock).WillOnce(Return(1));
    EXPECT_CALL(mock, RegTrustDataChangeListener).Times(RETRY_REGDATA_TIMES)
        .WillRepeatedly(Return(SOFTBUS_AUTH_REG_DATA_FAIL));
    EXPECT_CALL(mock, SoftBusSleepMsMock).Times(RETRY_REGDATA_TIMES);
    EXPECT_CALL(mock, SoftbusHitraceStart(_, _)).Times(1);
    EXPECT_CALL(mock, SoftbusHitraceStop).Times(1);
    AuthRequest request;
    (void)memset_s(&request, sizeof(request), 0, sizeof(request));
    request.requestId = TEST_REQUEST_ID;
    int32_t ret = VerifyDevice(&request);
    EXPECT_EQ(ret, SOFTBUS_AUTH_INIT_FAIL);
}
} // namespace OHOS
