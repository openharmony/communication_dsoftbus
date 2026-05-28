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


constexpr uint64_t TEST_CURRENT_TIME = 1000000;
constexpr char TEST_UDID[] = "1234567890abcdef1234567890abcdef12345678";
constexpr char TEST_UUID[] = "test_uuid_001";


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
} // namespace OHOS
