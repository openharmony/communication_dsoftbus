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

#include <cinttypes>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <securec.h>
#include <sys/time.h>

#include "auth_connection.c"
#include "auth_connection.h"
#include "auth_device.c"
#include "auth_interface.c"
#include "auth_interface.h"
#include "auth_interface_mock.h"
#include "auth_log.h"
#include "auth_manager.h"
#include "auth_session_fsm.c"
#include "auth_session_fsm.h"
#include "auth_session_key.c"
#include "auth_session_key.h"
#include "lnn_lane_interface.h"
#include "softbus_adapter_json.h"
#include "softbus_error_code.h"
#include "softbus_socket.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;
constexpr char NODE_BR_MAC[] = "12345TTU";
constexpr char NODE_BLE_MAC[] = "23456TTU";
constexpr char NODE_IP[] = "10.146.181.134";
constexpr uint32_t TEST_DATA_LEN = 30;
constexpr uint32_t AUTH_DEFAULT_VALUE = 0;
constexpr int32_t INDEX = 1;
constexpr int64_t TEST_ACCOUNT_ID = 12345;
constexpr int64_t TEST_INVALID_ACCOUNT_ID = 12345;
class AuthOtherMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthOtherMockTest::SetUpTestCase() { }

void AuthOtherMockTest::TearDownTestCase() { }

void AuthOtherMockTest::SetUp() { }

void AuthOtherMockTest::TearDown() { }

/*
 * @tc.name: AUTH_INIT_TEST_001
 * @tc.desc: Verify that AuthInit successfully initializes the authentication module when all
 *           sub-modules initialize correctly.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, AUTH_INIT_TEST_001, TestSize.Level1)
{
    AuthOtherInterfaceMock authMock;
    EXPECT_CALL(authMock, AuthDeviceInit).WillOnce(Return(SOFTBUS_INVALID_PARAM)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authMock, RegHichainSaStatusListener).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authMock, CustomizedSecurityProtocolInit).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authMock, AuthMetaInit).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = AuthInit();
    EXPECT_EQ(ret, SOFTBUS_AUTH_INIT_FAIL);
    ret = AuthInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(AuthDeinit());
}

/*
 * @tc.name: AUTH_INIT_TEST_002
 * @tc.desc: Verify that AuthInit returns an error when sub-module initialization fails,
 *           specifically when RegHichainSaStatusListener or CustomizedSecurityProtocolInit
 *           encounters issues.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, AUTH_INIT_TEST_002, TestSize.Level1)
{
    AuthOtherInterfaceMock authMock;
    EXPECT_CALL(authMock, AuthDeviceInit).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authMock, RegHichainSaStatusListener)
        .WillOnce(Return(SOFTBUS_AUTH_GET_SA_MANAGER_FAIL))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authMock, CustomizedSecurityProtocolInit).WillRepeatedly(Return(SOFTBUS_CREATE_LIST_ERR));
    int32_t ret = AuthInit();
    EXPECT_EQ(ret, SOFTBUS_AUTH_HICHAIN_SA_PROC_ERR);
    ret = AuthInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(AuthDeinit());
}

/*
 * @tc.name: AUTH_CHECK_META_EXIST_TEST_001
 * @tc.desc: Verify that AuthCheckMetaExist successfully checks for the existence of metadata for
 *           a given connection information.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, AUTH_CHECK_META_EXIST_TEST_001, TestSize.Level1)
{
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    ASSERT_EQ(strcpy_s(connInfo.info.brInfo.brMac, BT_MAC_LEN, NODE_BR_MAC), EOK);
    ASSERT_EQ(strcpy_s(connInfo.info.bleInfo.bleMac, BT_MAC_LEN, NODE_BLE_MAC), EOK);
    ASSERT_EQ(strcpy_s(connInfo.info.ipInfo.ip, IP_STR_MAX_LEN, NODE_IP), EOK);
    bool isExist = false;
    int32_t ret = AuthCheckMetaExist(&connInfo, &isExist);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: AUTH_CHECK_META_EXIST_TEST_002
 * @tc.desc: Verify that AuthCheckMetaExist returns an invalid parameter error when provided with
 *           null connection information or a null existence flag pointer.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, AUTH_CHECK_META_EXIST_TEST_002, TestSize.Level1)
{
    bool isExist = false;
    int32_t ret = AuthCheckMetaExist(nullptr, &isExist);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    ret = AuthCheckMetaExist(&connInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_HAS_TRUSTED_RELATION_TEST_001
 * @tc.desc: Verify that AuthHasTrustedRelation returns TRUSTED_RELATION_NO when
 *           LnnGetTrustedDevInfoFromDb successfully retrieves trusted device information.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, AUTH_HAS_TRUSTED_RELATION_TEST_001, TestSize.Level1)
{
    AuthOtherInterfaceMock authMock;
    EXPECT_CALL(authMock, LnnGetTrustedDevInfoFromDb).WillRepeatedly(Return(SOFTBUS_OK));
    TrustedReturnType ret = AuthHasTrustedRelation();
    EXPECT_EQ(ret, TRUSTED_RELATION_NO);
}

/*
 * @tc.name: AUTH_HAS_TRUSTED_RELATION_TEST_002
 * @tc.desc: Verify that AuthHasTrustedRelation returns TRUSTED_RELATION_IGNORE when
 *           LnnGetTrustedDevInfoFromDb fails to retrieve trusted device information.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, AUTH_HAS_TRUSTED_RELATION_TEST_002, TestSize.Level1)
{
    AuthOtherInterfaceMock authMock;
    EXPECT_CALL(authMock, LnnGetTrustedDevInfoFromDb).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    TrustedReturnType ret = AuthHasTrustedRelation();
    EXPECT_EQ(ret, TRUSTED_RELATION_IGNORE);
}

/*
 * @tc.name: AUTH_HAS_SAME_ACCOUNT_GROUP_TEST_001
 * @tc.desc: Verify that AuthHasSameAccountGroup correctly determines if there is a same account
 *           group, based on the result of IsSameAccountGroupDevice.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, AUTH_HAS_SAME_ACCOUNT_GROUP_TEST_001, TestSize.Level1)
{
    AuthOtherInterfaceMock authMock;
    EXPECT_CALL(authMock, IsSameAccountGroupDevice).WillOnce(Return(true)).WillRepeatedly(Return(false));
    bool ret = AuthHasSameAccountGroup();
    EXPECT_TRUE(ret);
    ret = AuthHasSameAccountGroup();
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: IS_SAME_ACCOUNT_DEVICE_TEST_001
 * @tc.desc: Verify that IsSameAccountDevice returns false when LnnGetLocalByteInfo fails to
 *           retrieve local device information.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, IS_SAME_ACCOUNT_DEVICE_TEST_001, TestSize.Level1)
{
    AuthOtherInterfaceMock authMock;
    EXPECT_CALL(authMock, LnnGetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_OK));

    DeviceInfo device = {
        .devId = "testId",
        .accountHash = "accounthashtest",
    };
    EXPECT_FALSE(IsSameAccountDevice(&device));
}

/*
 * @tc.name: IS_SAME_ACCOUNT_DEVICE_TEST_002
 * @tc.desc: Verify that IsSameAccountDevice returns false when LnnGetLocalByteInfo returns an
 *           invalid parameter, indicating a failure to retrieve local device information.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, IS_SAME_ACCOUNT_DEVICE_TEST_002, TestSize.Level1)
{
    AuthOtherInterfaceMock authMock;
    EXPECT_CALL(authMock, LnnGetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    DeviceInfo device = {
        .devId = "testId",
        .accountHash = "accounthashtest",
    };
    EXPECT_FALSE(IsSameAccountDevice(&device));
}

/*
 * @tc.name: AUTH_IS_POTENTIAL_TRUSTED_TEST_001
 * @tc.desc: Verify that AuthIsPotentialTrusted correctly identifies a device as potentially
 *           trusted when local byte info is available, default OHOS account is enabled, and
 *           IsPotentialTrustedDevice returns true.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, AUTH_IS_POTENTIAL_TRUSTED_TEST_001, TestSize.Level1)
{
    AuthOtherInterfaceMock authMock;
    EXPECT_CALL(authMock, LnnGetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authMock, LnnIsDefaultOhosAccount).WillRepeatedly(Return(true));
    EXPECT_CALL(authMock, IsPotentialTrustedDevice).WillRepeatedly(Return(true));
    DeviceInfo device = {
        .devId = "testId",
        .accountHash = "accounthashtest",
    };
    EXPECT_TRUE(AuthIsPotentialTrusted(&device, true));
}

/*
 * @tc.name: AUTH_IS_POTENTIAL_TRUSTED_TEST_002
 * @tc.desc: Verify that AuthIsPotentialTrusted returns false when LnnGetLocalByteInfo fails to
 *           retrieve local device information.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, AUTH_IS_POTENTIAL_TRUSTED_TEST_002, TestSize.Level1)
{
    AuthOtherInterfaceMock authMock;
    EXPECT_CALL(authMock, LnnGetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_NETWORK_NOT_FOUND));
    DeviceInfo device = {
        .devId = "testId",
        .accountHash = "accounthashtest",
    };
    EXPECT_FALSE(AuthIsPotentialTrusted(&device, true));
}

/*
 * @tc.name: AUTH_GET_GROUP_TEST_001
 * @tc.desc: Verify that AuthGetGroupType returns AUTH_DEFAULT_VALUE when provided with null UDID
 *           or UUID parameters.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, AUTH_GET_GROUP_TEST_001, TestSize.Level1)
{
    const char *udid = "testudid";
    const char *uuid = "testuuid";
    uint32_t type = AuthGetGroupType(nullptr, uuid);
    EXPECT_EQ(type, AUTH_DEFAULT_VALUE);
    type = AuthGetGroupType(udid, nullptr);
    EXPECT_EQ(type, AUTH_DEFAULT_VALUE);
}

/*
 * @tc.name: AUTH_GET_META_TYPE_TEST_001
 * @tc.desc: Verify that AuthGetMetaType correctly determines if an authentication ID corresponds
 *           to a meta-authentication type.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, AUTH_GET_META_TYPE_TEST_001, TestSize.Level1)
{
    int64_t authId = 0;
    const char *udid = "000";
    const char *uuid = "000";
    const char *ip = "192.168.12.1";
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    ASSERT_EQ(strcpy_s(info.udid, UDID_BUF_LEN, udid), EOK);
    ASSERT_EQ(strcpy_s(info.uuid, UUID_BUF_LEN, uuid), EOK);
    ASSERT_EQ(strcpy_s(info.connInfo.info.ipInfo.ip, IP_LEN, ip), EOK);
    info.connId = 0;
    info.isServer = false;
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    AuthManager *auth = NewAuthManager(authId, &info);
    ASSERT_NE(auth, nullptr);

    AuthOtherInterfaceMock authMock;
    EXPECT_CALL(authMock, GetAuthManagerByAuthId).WillRepeatedly(Return(nullptr));

    bool isMetaAuth = false;
    int32_t ret = AuthGetMetaType(authId, &isMetaAuth);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(isMetaAuth);

    DelAuthManager(auth, info.connInfo.type);
}

/*
 * @tc.name: AUTH_RESTORE_AUTH_MANAGER_TEST_001
 * @tc.desc: Verify that AuthRestoreAuthManager fails to restore the authentication manager when
 *           AuthFindLatestNormalizeKey returns an error.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, AUTH_RESTORE_AUTH_MANAGER_TEST_001, TestSize.Level1)
{
    AuthOtherInterfaceMock authMock;
    EXPECT_CALL(authMock, AuthFindLatestNormalizeKey).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authMock, IsCloudSyncEnabled).WillRepeatedly(Return(true));
    EXPECT_CALL(authMock, IsFeatureSupport).WillRepeatedly(Return(true));
    EXPECT_CALL(authMock, LnnGetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_OK));

    AuthConnInfo connInfo = {
        .type = AUTH_LINK_TYPE_BLE,
    };
    const char *udidHash = "uuidHash";
    uint32_t requestId = 1;
    int64_t authId = 0;
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    int32_t ret = AuthRestoreAuthManager(udidHash, &connInfo, requestId, &nodeInfo, &authId);
    EXPECT_EQ(ret, SOFTBUS_AUTH_MANAGER_RESTORE_FAIL);
    ret = AuthRestoreAuthManager(udidHash, &connInfo, requestId, &nodeInfo, &authId);
    EXPECT_EQ(ret, SOFTBUS_AUTH_MANAGER_RESTORE_FAIL);
}

/*
 * @tc.name: AUTH_RESTORE_AUTH_MANAGER_TEST_002
 * @tc.desc: Verify that AuthRestoreAuthManager fails to restore the authentication manager when
 *           LnnGetLocalByteInfo returns an error.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, AUTH_RESTORE_AUTH_MANAGER_TEST_002, TestSize.Level1)
{
    AuthOtherInterfaceMock authMock;
    EXPECT_CALL(authMock, AuthFindLatestNormalizeKey).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authMock, IsCloudSyncEnabled).WillRepeatedly(Return(true));
    EXPECT_CALL(authMock, IsFeatureSupport).WillRepeatedly(Return(true));
    EXPECT_CALL(authMock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authMock, LnnGetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_NETWORK_NOT_FOUND));

    AuthConnInfo connInfo = {
        .type = AUTH_LINK_TYPE_BLE,
    };
    const char *udidHash = "uuidHash";
    uint32_t requestId = 1;
    int64_t authId = 0;
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    int32_t ret = AuthRestoreAuthManager(udidHash, &connInfo, requestId, &nodeInfo, &authId);
    EXPECT_EQ(ret, SOFTBUS_AUTH_MANAGER_RESTORE_FAIL);
}

/*
 * @tc.name: AUTH_RESTORE_AUTH_MANAGER_TEST_003
 * @tc.desc: Verify that AuthRestoreAuthManager fails to restore the authentication manager when
 *           both AuthFindLatestNormalizeKey and AuthFindDeviceKey return errors.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, AUTH_RESTORE_AUTH_MANAGER_TEST_003, TestSize.Level1)
{
    AuthOtherInterfaceMock authMock;
    EXPECT_CALL(authMock, AuthFindLatestNormalizeKey).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(authMock, AuthFindDeviceKey).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(authMock, IsCloudSyncEnabled).WillRepeatedly(Return(true));
    EXPECT_CALL(authMock, IsFeatureSupport).WillRepeatedly(Return(true));
    EXPECT_CALL(authMock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authMock, LnnGetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_OK));

    AuthConnInfo connInfo = {
        .type = AUTH_LINK_TYPE_BLE,
    };
    const char *udidHash = "uuidHash";
    uint32_t requestId = 1;
    int64_t authId = 0;
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    int32_t ret = AuthRestoreAuthManager(udidHash, &connInfo, requestId, &nodeInfo, &authId);
    EXPECT_EQ(ret, SOFTBUS_AUTH_MANAGER_RESTORE_FAIL);
}

/*
 * @tc.name: AUTH_DIRECT_ONLINE_PROCESS_SESSION_KEY_TEST_001
 * @tc.desc: Verify that AuthDirectOnlineProcessSessionKey returns an error when provided with an
 *           unsupported authentication link type.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, AUTH_DIRECT_ONLINE_PROCESS_SESSION_KEY_TEST_001, TestSize.Level1)
{
    AuthDeviceKeyInfo keyInfo = {
        .keyLen = strlen("testKey"),
        .isOldKey = true,
    };
    ASSERT_EQ(memcpy_s(keyInfo.deviceKey, SESSION_KEY_LENGTH, "testKey", strlen("testKey")), EOK);
    AuthSessionInfo info = {
        .connInfo.type = AUTH_LINK_TYPE_MAX,
    };
    int64_t authId = 0;
    int32_t ret = AuthDirectOnlineProcessSessionKey(&info, &keyInfo, &authId);
    EXPECT_EQ(ret, SOFTBUS_AUTH_SESSION_KEY_PROC_ERR);
}

/*
 * @tc.name: FILL_AUTH_SESSION_INFO_TEST_001
 * @tc.desc: Verify that FillAuthSessionInfo returns an error when LnnGetLocalByteInfo fails to
 *           retrieve local node information.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, FILL_AUTH_SESSION_INFO_TEST_001, TestSize.Level1)
{
    AuthOtherInterfaceMock authMock;
    EXPECT_CALL(authMock, LnnGetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    AuthSessionInfo info = {
        .connInfo.info.bleInfo.deviceIdHash = "123456789udidhashtest",
    };
    NodeInfo nodeInfo = {
        .authCapacity = 127,
        .uuid = "123456789uuidhashtest",
        .deviceInfo.deviceUdid = "123456789udidtest",
    };
    AuthDeviceKeyInfo keyInfo;
    (void)memset_s(&keyInfo, sizeof(AuthDeviceKeyInfo), 0, sizeof(AuthDeviceKeyInfo));
    int32_t ret = FillAuthSessionInfo(&info, &nodeInfo, &keyInfo, true);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
}

/*
 * @tc.name: AUTH_GET_AUTH_HANDLE_BY_INDEX_TEST_001
 * @tc.desc: Verify that AuthGetAuthHandleByIndex returns SOFTBUS_AUTH_NOT_SUPPORT_NORMALIZE or
 *           SOFTBUS_LOCK_ERR under specific conditions related to LnnGetRemoteNodeInfoByKey.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, AUTH_GET_AUTH_HANDLE_BY_INDEX_TEST_001, TestSize.Level1)
{
    AuthOtherInterfaceMock authMock;
    EXPECT_CALL(authMock, LnnGetRemoteNodeInfoByKey)
        .WillOnce(Return(SOFTBUS_OK))
        .WillRepeatedly(AuthOtherInterfaceMock::ActionOfLnnGetRemoteNodeInfoByKey);

    AuthConnInfo connInfo = {
        .info.ipInfo.ip = "192.168.12.1",
        .type = AUTH_LINK_TYPE_WIFI,
    };
    AuthHandle authHandle;
    (void)memset_s(&authHandle, sizeof(AuthHandle), 0, sizeof(AuthHandle));

    int32_t ret = AuthGetAuthHandleByIndex(&connInfo, true, INDEX, &authHandle);
    EXPECT_EQ(ret, SOFTBUS_AUTH_NOT_SUPPORT_NORMALIZE);
    ret = AuthGetAuthHandleByIndex(&connInfo, true, INDEX, &authHandle);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/*
 * @tc.name: AUTH_GET_AUTH_HANDLE_BY_INDEX_TEST_002
 * @tc.desc: Verify that AuthGetAuthHandleByIndex returns SOFTBUS_INVALID_PARAM or
 *           SOFTBUS_AUTH_NOT_SUPPORT_NORMALIZE under specific conditions related to
 *           LnnGetRemoteNodeInfoByKey and LnnGetNetworkIdByUdidHash.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, AUTH_GET_AUTH_HANDLE_BY_INDEX_TEST_002, TestSize.Level1)
{
    AuthOtherInterfaceMock authMock;
    EXPECT_CALL(authMock, LnnGetNetworkIdByUdidHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authMock, LnnGetRemoteNodeInfoByKey)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));

    AuthConnInfo connInfo = {
        .info.ipInfo.ip = "192.168.12.1",
        .type = AUTH_LINK_TYPE_BLE,
    };
    AuthHandle authHandle;
    (void)memset_s(&authHandle, sizeof(AuthHandle), 0, sizeof(AuthHandle));

    char UDID_TEST[UDID_BUF_LEN] = "123456789udidtest";
    connInfo.type = AUTH_LINK_TYPE_BLE;
    ASSERT_EQ(memcpy_s(connInfo.info.bleInfo.deviceIdHash, UDID_HASH_LEN, UDID_TEST, strlen(UDID_TEST)), EOK);

    int32_t ret = AuthGetAuthHandleByIndex(&connInfo, true, INDEX, &authHandle);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = AuthGetAuthHandleByIndex(&connInfo, true, INDEX, &authHandle);
    EXPECT_EQ(ret, SOFTBUS_AUTH_NOT_SUPPORT_NORMALIZE);
}

/*
 * @tc.name: AUTH_GET_P2P_CONN_INFO_TEST_001
 * @tc.desc: Verify that AuthGetHmlConnInfo and AuthGetP2pConnInfo return SOFTBUS_LOCK_ERR when
 *           attempting to retrieve connection information without proper locking.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, AUTH_GET_P2P_CONN_INFO_TEST_001, TestSize.Level1)
{
    AuthHandle authHandle = {
        .authId = INDEX,
        .type = AUTH_LINK_TYPE_MAX,
    };
    EXPECT_NO_FATAL_FAILURE(AuthRemoveAuthManagerByAuthHandle(authHandle));
    authHandle.type = AUTH_LINK_TYPE_WIFI;
    EXPECT_NO_FATAL_FAILURE(AuthRemoveAuthManagerByAuthHandle(authHandle));

    AuthConnInfo connInfo = {
        .info.ipInfo.ip = "192.168.12.1",
        .type = AUTH_LINK_TYPE_BLE,
    };

    AuthOtherInterfaceMock authMock;
    EXPECT_CALL(authMock, ConvertBytesToHexString)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(PrintAuthConnInfo(nullptr));
    EXPECT_NO_FATAL_FAILURE(PrintAuthConnInfo(&connInfo));

    bool isMetaAuth = false;
    const char *uuid = "000";
    int32_t ret = AuthGetHmlConnInfo(uuid, &connInfo, isMetaAuth);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
    ret = AuthGetP2pConnInfo(uuid, &connInfo, isMetaAuth);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/*
 * @tc.name: AUTH_CHECK_SESSION_KEY_VALID_BY_CONN_INFO_TEST_001
 * @tc.desc: Verify that AuthCheckSessionKeyValidByConnInfo correctly validates session keys based
 *           on connection information, handling invalid parameters and network node retrieval
 *           failures.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, AUTH_CHECK_SESSION_KEY_VALID_BY_CONN_INFO_TEST_001, TestSize.Level1)
{
    AuthOtherInterfaceMock authMock;
    EXPECT_CALL(authMock, LnnGetRemoteNodeInfoById)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(AuthOtherInterfaceMock::ActionOfLnnGetRemoteNodeInfoById);

    const char *networkId = "123456456";
    AuthConnInfo connInfo = {
        .info.ipInfo.ip = "192.168.12.1",
        .type = AUTH_LINK_TYPE_BLE,
    };
    int32_t ret = AuthCheckSessionKeyValidByConnInfo(nullptr, &connInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AuthCheckSessionKeyValidByConnInfo(networkId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AuthCheckSessionKeyValidByConnInfo(networkId, &connInfo);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
    ret = AuthCheckSessionKeyValidByConnInfo(networkId, &connInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: GET_IS_EXCHANGE_UDID_BY_NETWORKID_TEST_001
 * @tc.desc: Verify that GetIsExchangeUdidByNetworkId correctly retrieves the exchange UDID status
 *           for a given network ID, handling invalid parameters and cases where the status is not
 *           found.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, GET_IS_EXCHANGE_UDID_BY_NETWORKID_TEST_001, TestSize.Level1)
{
    AuthOtherInterfaceMock authMock;
    bool isExchangeUdid = false;
    const char *networkId = "networkId";
    int32_t ret = GetIsExchangeUdidByNetworkId(nullptr, &isExchangeUdid);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetIsExchangeUdidByNetworkId(networkId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetIsExchangeUdidByNetworkId(networkId, &isExchangeUdid);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: GET_PEER_UDID_BY_NETWORK_ID_TEST_001
 * @tc.desc: Verify that GetPeerUdidByNetworkId returns an invalid parameter error when provided
 *           with an invalid buffer length for the UDID.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, GET_PEER_UDID_BY_NETWORK_ID_TEST_001, TestSize.Level1)
{
    const char *networkId = "networkId";
    char udid[UDID_BUF_LEN] = { 0 };
    int32_t ret = GetPeerUdidByNetworkId(networkId, udid, TEST_DATA_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: CONVERT_TO_AUTH_LINK_TYPE_TEST_001
 * @tc.desc: Verify that ConvertToAuthLinkType correctly converts various DiscoveryType values to
 *           their corresponding AuthLinkType values.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, CONVERT_TO_AUTH_LINK_TYPE_TEST_001, TestSize.Level1)
{
    DiscoveryType type = DISCOVERY_TYPE_UNKNOWN;
    AuthLinkType ret = ConvertToAuthLinkType(type);
    EXPECT_EQ(ret, AUTH_LINK_TYPE_MAX);

    type = DISCOVERY_TYPE_WIFI;
    ret = ConvertToAuthLinkType(type);
    EXPECT_EQ(ret, AUTH_LINK_TYPE_WIFI);

    type = DISCOVERY_TYPE_BLE;
    ret = ConvertToAuthLinkType(type);
    EXPECT_EQ(ret, AUTH_LINK_TYPE_BLE);

    type = DISCOVERY_TYPE_BR;
    ret = ConvertToAuthLinkType(type);
    EXPECT_EQ(ret, AUTH_LINK_TYPE_BR);

    type = DISCOVERY_TYPE_P2P;
    ret = ConvertToAuthLinkType(type);
    EXPECT_EQ(ret, AUTH_LINK_TYPE_P2P);
}

/*
 * @tc.name: CONVERT_TO_DISCOVERY_TYPE_TEST_001
 * @tc.desc: Verify that ConvertToDiscoveryType correctly converts various AuthLinkType values to
 *           their corresponding DiscoveryType values.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, CONVERT_TO_DISCOVERY_TYPE_TEST_001, TestSize.Level1)
{
    AuthLinkType type = AUTH_LINK_TYPE_WIFI;
    DiscoveryType ret = ConvertToDiscoveryType(type);
    EXPECT_EQ(ret, DISCOVERY_TYPE_WIFI);

    type = AUTH_LINK_TYPE_BLE;
    ret = ConvertToDiscoveryType(type);
    EXPECT_EQ(ret, DISCOVERY_TYPE_BLE);

    type = AUTH_LINK_TYPE_BR;
    ret = ConvertToDiscoveryType(type);
    EXPECT_EQ(ret, DISCOVERY_TYPE_BR);

    type = AUTH_LINK_TYPE_P2P;
    ret = ConvertToDiscoveryType(type);
    EXPECT_EQ(ret, DISCOVERY_TYPE_P2P);

    type = AUTH_LINK_TYPE_MAX;
    ret = ConvertToDiscoveryType(type);
    EXPECT_EQ(ret, DISCOVERY_TYPE_UNKNOWN);
}

/*
 * @tc.name: GET_AUTH_CAPACITY_TEST_001
 * @tc.desc: Verify that GetAuthCapacity returns AUTH_DEFAULT_VALUE when SoftbusGetConfig fails to
 *           retrieve the authentication capacity.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, GET_AUTH_CAPACITY_TEST_001, TestSize.Level1)
{
    AuthOtherInterfaceMock authMock;
    EXPECT_CALL(authMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    uint32_t ret = GetAuthCapacity();
    EXPECT_EQ(ret, AUTH_DEFAULT_VALUE);
}

/*
 * @tc.name: GET_CONFIG_SUPPORT_AS_SERVER_TEST_001
 * @tc.desc: Verify that GetConfigSupportAsServer returns false when SoftbusGetConfig fails to
 *           retrieve the server support configuration.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, GET_CONFIG_SUPPORT_AS_SERVER_TEST_001, TestSize.Level1)
{
    AuthOtherInterfaceMock authMock;
    EXPECT_CALL(authMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    bool ret = GetConfigSupportAsServer();
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: CONVERT_TO_AUTH_CONN_INFO_TEST_001
 * @tc.desc: Verify that ConvertToAuthConnInfo correctly converts ConnectionInfo to AuthConnInfo,
 *           handling various connection types and protocols, including invalid and unsupported
 *           types.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, CONVERT_TO_AUTH_CONN_INFO_TEST_001, TestSize.Level1)
{
    ConnectionInfo info = {
        .type = CONNECT_TCP,
        .socketInfo.protocol = LNN_PROTOCOL_BR,
    };
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));

    int32_t ret = ConvertToAuthConnInfo(&info, &connInfo);
    EXPECT_EQ(ret, SOFTBUS_AUTH_INVALID_PROTOCOL);

    info.socketInfo.protocol = LNN_PROTOCOL_IP;
    ret = ConvertToAuthConnInfo(&info, &connInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    info.type = CONNECT_BR;
    ret = ConvertToAuthConnInfo(&info, &connInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    info.type = CONNECT_BLE;
    ret = ConvertToAuthConnInfo(&info, &connInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    info.type = CONNECT_TYPE_MAX;
    ret = ConvertToAuthConnInfo(&info, &connInfo);
    EXPECT_EQ(ret, SOFTBUS_AUTH_UNEXPECTED_CONN_TYPE);
}

/*
 * @tc.name: CONVERT_TO_CONNECT_OPTION_TEST_001
 * @tc.desc: Verify that ConvertToConnectOption correctly converts AuthConnInfo to ConnectOption,
 *           handling various authentication link types, including unsupported types.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, CONVERT_TO_CONNECT_OPTION_TEST_001, TestSize.Level1)
{
    AuthConnInfo connInfo = {
        .type = AUTH_LINK_TYPE_BR,
    };
    ConnectOption option;
    (void)memset_s(&option, sizeof(ConnectOption), 0, sizeof(ConnectOption));

    int32_t ret = ConvertToConnectOption(&connInfo, &option);
    EXPECT_EQ(ret, SOFTBUS_OK);

    connInfo.type = AUTH_LINK_TYPE_BLE;
    ret = ConvertToConnectOption(&connInfo, &option);
    EXPECT_EQ(ret, SOFTBUS_OK);

    connInfo.type = AUTH_LINK_TYPE_P2P;
    ret = ConvertToConnectOption(&connInfo, &option);
    EXPECT_EQ(ret, SOFTBUS_OK);

    connInfo.type = AUTH_LINK_TYPE_P2P;
    ret = ConvertToConnectOption(&connInfo, &option);
    EXPECT_EQ(ret, SOFTBUS_OK);

    connInfo.type = AUTH_LINK_TYPE_MAX;
    ret = ConvertToConnectOption(&connInfo, &option);
    EXPECT_EQ(ret, SOFTBUS_AUTH_UNEXPECTED_CONN_TYPE);
}

/*
 * @tc.name: COMPARE_SESSION_CONN_INFO_TEST_001
 * @tc.desc: Verify that CompareConnInfo correctly compares two AuthConnInfo structures,
 *           specifically for session connection information, considering connection ID and UDID.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, COMPARE_SESSION_CONN_INFO_TEST_001, TestSize.Level1)
{
    AuthConnInfo connInfo1 = {
        .type = AUTH_LINK_TYPE_SESSION,
        .info.sessionInfo.connId = AUTH_DEFAULT_VALUE,
        .info.sessionInfo.udid = "udid",
    };
    AuthConnInfo connInfo2 = {
        .type = AUTH_LINK_TYPE_SESSION,
        .info.sessionInfo.connId = AUTH_DEFAULT_VALUE,
        .info.sessionInfo.udid = "udid",
    };
    bool cmpShortHash = false;

    bool ret = CompareConnInfo(&connInfo1, &connInfo2, cmpShortHash);
    EXPECT_TRUE(ret);
    connInfo2.info.sessionInfo.connId = INDEX;
    ret = CompareConnInfo(&connInfo1, &connInfo2, cmpShortHash);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: AUTH_GET_USB_CONN_INFO_TEST_001
 * @tc.desc: Verify that AuthGetUsbConnInfo returns SOFTBUS_LOCK_ERR or AUTH_INVALID_ID under
 *           specific conditions related to retrieving USB connection information.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, AUTH_GET_USB_CONN_INFO_TEST_001, TestSize.Level1)
{
    AuthHandle authHandle = {
        .authId = INDEX,
        .type = AUTH_LINK_TYPE_MAX,
    };
    EXPECT_NO_FATAL_FAILURE(AuthRemoveAuthManagerByAuthHandle(authHandle));
    authHandle.type = AUTH_LINK_TYPE_USB;
    EXPECT_NO_FATAL_FAILURE(AuthRemoveAuthManagerByAuthHandle(authHandle));

    AuthConnInfo connInfo = {
        .info.ipInfo.ip = "::1%lo",
        .type = AUTH_LINK_TYPE_USB,
    };

    bool isMetaAuth = false;
    const char *uuid = "000";
    int32_t ret = AuthGetUsbConnInfo(uuid, &connInfo, isMetaAuth);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);

    isMetaAuth = true;
    ret = AuthGetUsbConnInfo(uuid, &connInfo, isMetaAuth);
    EXPECT_EQ(ret, AUTH_INVALID_ID);
}

/*
 * @tc.name: IS_SAME_ACCOUNT_ID_TEST_001
 * @tc.desc: Verify that IsSameAccountId returns false when LnnGetLocalNum64Info fails to
 *           retrieve the local account ID.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, IS_SAME_ACCOUNT_ID_TEST_001, TestSize.Level1)
{
    AuthOtherInterfaceMock authMock;
    EXPECT_CALL(authMock, LnnGetLocalNum64Info).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_FALSE(IsSameAccountId(TEST_ACCOUNT_ID));
}

/*
 * @tc.name: IS_SAME_ACCOUNT_ID_TEST_002
 * @tc.desc: Verify that IsSameAccountId returns true when the provided account ID matches the
 *           local account ID and the local account is not a default OHOS account.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, IS_SAME_ACCOUNT_ID_TEST_002, TestSize.Level1)
{
    int64_t localId = TEST_INVALID_ACCOUNT_ID;
    AuthOtherInterfaceMock authMock;
    EXPECT_CALL(authMock, LnnGetLocalNum64Info(_, _)).WillOnce(DoAll(SetArgPointee<1>(localId), Return(SOFTBUS_OK)));
    EXPECT_CALL(authMock, LnnIsDefaultOhosAccount()).WillOnce(Return(false));
    EXPECT_TRUE(IsSameAccountId(TEST_ACCOUNT_ID));
}

/*
 * @tc.name: IS_SAME_ACCOUNT_ID_TEST_003
 * @tc.desc: Verify that IsSameAccountId returns false when the local account is a default OHOS
 *           account, even if the provided account ID matches the local account ID.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, IS_SAME_ACCOUNT_ID_TEST_003, TestSize.Level1)
{
    AuthOtherInterfaceMock authMock;
    int64_t localId = TEST_ACCOUNT_ID;
    EXPECT_CALL(authMock, LnnGetLocalNum64Info(_, _)).WillOnce(DoAll(SetArgPointee<1>(localId), Return(SOFTBUS_OK)));
    EXPECT_CALL(authMock, LnnIsDefaultOhosAccount()).WillOnce(Return(true));
    EXPECT_FALSE(IsSameAccountId(localId));
}

/*
 * @tc.name: IS_SAME_ACCOUNT_ID_TEST_004
 * @tc.desc: Verify that IsSameAccountId returns true when the provided account ID matches the
 *           local account ID and the local account is not a default OHOS account.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthOtherMockTest, IS_SAME_ACCOUNT_ID_TEST_004, TestSize.Level1)
{
    AuthOtherInterfaceMock authMock;
    int64_t localId = TEST_ACCOUNT_ID;
    EXPECT_CALL(authMock, LnnGetLocalNum64Info(_, _)).WillOnce(DoAll(SetArgPointee<1>(localId), Return(SOFTBUS_OK)));
    EXPECT_CALL(authMock, LnnIsDefaultOhosAccount()).WillOnce(Return(false));
    EXPECT_TRUE(IsSameAccountId(localId));
}
} // namespace OHOS
