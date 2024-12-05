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

#include "auth_device.c"
#include "auth_lane.c"
#include "auth_manager.c"
#include "auth_manager.h"
#include "auth_request.h"
#include "auth_session_key.c"

namespace OHOS {
using namespace testing::ext;
const uint64_t CONN_ID = 10 | ((uint64_t)AUTH_LINK_TYPE_WIFI << INT32_BIT_NUM);
constexpr int64_t AUTH_SEQ = 1;
constexpr int64_t AUTH_SEQ_1 = 2;
constexpr int64_t AUTH_SEQ_2 = 3;
constexpr int64_t AUTH_SEQ_3 = 4;
constexpr int64_t AUTH_SEQ_4 = 5;
constexpr int64_t AUTH_SEQ_5 = 6;
constexpr uint64_t CONN_ID_1 = 11;
constexpr uint64_t CONN_ID_2 = 12;
constexpr uint64_t CONN_ID_3 = 13;
constexpr int32_t PORT = 1;
constexpr int32_t PORT_1 = 2;
constexpr int32_t KEY_INDEX = 1;
constexpr int32_t GROUP_TYPE = 100;
constexpr int32_t DEVICE_ID_HASH_LEN = 9;
constexpr int32_t KEY_VALUE_LEN = 13;
constexpr uint32_t REQUEST_ID = 1000;
constexpr uint32_t REQUEST_ID_1 = 1001;
constexpr int32_t LENTH = 20;
constexpr int32_t TMP_DATA_LEN = 10;
constexpr char UDID_TEST[UDID_BUF_LEN] = "123456789udidtest";
constexpr char INVALID_UDID_TEST[UDID_BUF_LEN] = "nullptr";
constexpr char UUID_TEST[UUID_BUF_LEN] = "123456789uuidtest";
constexpr char IP_TEST[IP_LEN] = "192.168.51.170";
constexpr char INVALID_IP_TEST[IP_LEN] = "127.0.0.0";
constexpr char BR_MAC[BT_MAC_LEN] = "00:15:5d:de:d4:23";
constexpr char BLE_MAC[BT_MAC_LEN] = "00:15:5d:de:d4:23";
constexpr uint8_t DEVICE_ID_HASH[UDID_HASH_LEN] = "123456789";
constexpr char PEER_UID[MAX_ACCOUNT_HASH_LEN] = "123456789uditest";
constexpr uint8_t KEY_VALUE[SESSION_KEY_LENGTH] = "123456keytest";
constexpr uint8_t TMP_IN_DATA[TMP_DATA_LEN] = "tmpInData";
static const int32_t TEST_DATA_LEN = 600;
constexpr int32_t DEFAULT_USERID = 100;

class AuthManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthManagerTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "AuthManagerTest start";
    ListInit(&g_authClientList);
    ListInit(&g_authServerList);
    AuthCommonInit();
}

void AuthManagerTest::TearDownTestCase()
{
    DestroyAuthManagerList();
    AuthCommonDeinit();
    GTEST_LOG_(INFO) << "AuthManagerTest end";
}

void AuthManagerTest::SetUp() { }

void AuthManagerTest::TearDown() { }

static void SetAuthSessionInfo(AuthSessionInfo *info, uint64_t connId, bool isServer, AuthLinkType type)
{
    (void)memset_s(info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    info->connId = connId;
    info->isServer = isServer;
    info->connInfo.type = type;
    info->version = SOFTBUS_NEW_V2;
    ASSERT_TRUE(memcpy_s(info->udid, UDID_BUF_LEN, UDID_TEST, strlen(UDID_TEST)) == EOK);
    ASSERT_TRUE(memcpy_s(info->uuid, UUID_BUF_LEN, UUID_TEST, strlen(UUID_TEST)) == EOK);
    switch (type) {
        case AUTH_LINK_TYPE_WIFI:
            ASSERT_TRUE(memcpy_s(info->connInfo.info.ipInfo.ip, IP_LEN, IP_TEST, strlen(IP_TEST)) == EOK);
            break;
        case AUTH_LINK_TYPE_BLE:
            ASSERT_TRUE(memcpy_s(info->connInfo.info.bleInfo.bleMac, BT_MAC_LEN, BLE_MAC, strlen(BLE_MAC)) == EOK);
            ASSERT_TRUE(memcpy_s(info->connInfo.info.bleInfo.deviceIdHash, UDID_HASH_LEN,
                DEVICE_ID_HASH, DEVICE_ID_HASH_LEN) == EOK);
            break;
        case AUTH_LINK_TYPE_BR:
            ASSERT_TRUE(memcpy_s(info->connInfo.info.brInfo.brMac, BT_MAC_LEN, BR_MAC, strlen(BR_MAC)) == EOK);
            break;
        default:
            break;
    }
}

/*
 * @tc.name: NEW_AND_FIND_AUTH_MANAGER_TEST_001
 * @tc.desc: NewAndFindAuthManager test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthManagerTest, NEW_AND_FIND_AUTH_MANAGER_TEST_001, TestSize.Level1)
{
    AuthSessionInfo info;
    SetAuthSessionInfo(&info, CONN_ID, false, AUTH_LINK_TYPE_WIFI);
    AuthManager *auth = NewAuthManager(AUTH_SEQ, &info);
    EXPECT_TRUE(auth != nullptr);
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    ASSERT_TRUE(memcpy_s(connInfo.info.ipInfo.ip, IP_LEN, IP_TEST, strlen(IP_TEST)) == EOK);
    EXPECT_TRUE(FindAuthManagerByConnInfo(&connInfo, false) != nullptr);
    AuthNotifyAuthPassed(AUTH_SEQ, &info);
    ASSERT_TRUE(memcpy_s(connInfo.info.ipInfo.ip, IP_LEN, INVALID_IP_TEST, strlen(INVALID_IP_TEST)) == EOK);
    EXPECT_TRUE(FindAuthManagerByConnInfo(&connInfo, false) == nullptr);
    AuthNotifyAuthPassed(AUTH_SEQ, &info);
    RemoveAuthManagerByConnInfo(&connInfo, false);
    PrintAuthConnInfo(&connInfo);
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_BR;
    ASSERT_TRUE(memcpy_s(connInfo.info.brInfo.brMac, BT_MAC_LEN, BR_MAC, strlen(BR_MAC)) == EOK);
    PrintAuthConnInfo(&connInfo);
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_BLE;
    ASSERT_TRUE(memcpy_s(connInfo.info.bleInfo.deviceIdHash, UDID_HASH_LEN, DEVICE_ID_HASH, DEVICE_ID_HASH_LEN) == EOK);
    ASSERT_TRUE(memcpy_s(connInfo.info.bleInfo.bleMac, BT_MAC_LEN, BLE_MAC, strlen(BLE_MAC)) == EOK);
    PrintAuthConnInfo(&connInfo);
    connInfo.type = AUTH_LINK_TYPE_P2P;
    PrintAuthConnInfo(&connInfo);
    PrintAuthConnInfo(nullptr);
    EXPECT_EQ(FindAuthManagerByUuid(UUID_TEST, AUTH_LINK_TYPE_WIFI, false), nullptr);
    EXPECT_EQ(FindAuthManagerByUdid(UDID_TEST, AUTH_LINK_TYPE_WIFI, false), nullptr);
    SessionKey sessionKey = { { 0 }, TEST_DATA_LEN };
    EXPECT_EQ(AddSessionKey(&auth->sessionKeyList, AUTH_SEQ, &sessionKey, AUTH_LINK_TYPE_WIFI, false), SOFTBUS_OK);
    EXPECT_EQ(SetSessionKeyAvailable(&auth->sessionKeyList, AUTH_SEQ), SOFTBUS_OK);
    AuthManagerSetAuthPassed(AUTH_SEQ, &info);
    EXPECT_NE(FindAuthManagerByUuid(UUID_TEST, AUTH_LINK_TYPE_WIFI, false), nullptr);
    EXPECT_NE(FindAuthManagerByUdid(UDID_TEST, AUTH_LINK_TYPE_WIFI, false), nullptr);
}

static int32_t MyUpdateFuncReturnError(AuthManager *auth1, const AuthManager *auth2, AuthLinkType type)
{
    GTEST_LOG_(INFO) << "MyUpdateFuncReturnError Called";
    return SOFTBUS_INVALID_PARAM;
}

static int32_t MyUpdateFuncReturnOk(AuthManager *auth1, const AuthManager *auth2, AuthLinkType type)
{
    GTEST_LOG_(INFO) << "MyUpdateFuncReturnOk Called";
    return SOFTBUS_OK;
}

/*
 * @tc.name: FIND_AUTH_MANAGER_TEST_001
 * @tc.desc: FindAuthManager test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthManagerTest, FIND_AUTH_MANAGER_TEST_001, TestSize.Level1)
{
    AuthHandle authHandle;
    EXPECT_TRUE(FindAuthManagerByAuthId(AUTH_SEQ) != nullptr);
    authHandle.authId = AUTH_SEQ;
    HandleUpdateSessionKeyEvent(&authHandle);
    EXPECT_TRUE(FindAuthManagerByAuthId(AUTH_SEQ_2) == nullptr);
    authHandle.authId = AUTH_SEQ_2;
    HandleUpdateSessionKeyEvent(&authHandle);
    EXPECT_TRUE(FindAuthManagerByConnId(CONN_ID, false) != nullptr);
    AuthManager *auth = FindAuthManagerByConnId(CONN_ID, true);
    EXPECT_TRUE(auth == nullptr);
    EXPECT_TRUE(UpdateAuthManagerByAuthId(AUTH_SEQ_2,
        MyUpdateFuncReturnError, auth, AUTH_LINK_TYPE_WIFI) == SOFTBUS_AUTH_NOT_FOUND);
    EXPECT_NE(UpdateAuthManagerByAuthId(AUTH_SEQ, MyUpdateFuncReturnError, auth,
        AUTH_LINK_TYPE_WIFI), SOFTBUS_OK);
    EXPECT_TRUE(UpdateAuthManagerByAuthId(AUTH_SEQ, MyUpdateFuncReturnOk, auth, AUTH_LINK_TYPE_WIFI) == SOFTBUS_OK);
    AuthConnInfo connInfo;
    uint32_t type = 0;
    EXPECT_EQ(GetAuthConnInfoByUuid(UUID_TEST, (AuthLinkType)type, &connInfo), SOFTBUS_INVALID_PARAM);
    type = 9;
    EXPECT_EQ(GetAuthConnInfoByUuid(UUID_TEST, (AuthLinkType)type, &connInfo), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(GetAuthConnInfoByUuid(UUID_TEST, AUTH_LINK_TYPE_WIFI, &connInfo), SOFTBUS_OK);
    AuthHandle authHandle2 = {
        .authId = AUTH_SEQ,
        .type = AUTH_LINK_TYPE_WIFI,
    };
    AuthHandleLeaveLNN(authHandle2);
}

/*
 * @tc.name: GET_AUTH_MANAGER_BY_CONN_INFO_TEST_001
 * @tc.desc: GetAuthManagerByConnInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthManagerTest, GET_AUTH_MANAGER_BY_CONN_INFO_TEST_001, TestSize.Level1)
{
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    ASSERT_TRUE(memcpy_s(connInfo.info.ipInfo.ip, IP_LEN, INVALID_IP_TEST, strlen(INVALID_IP_TEST)) == EOK);
    EXPECT_TRUE(GetAuthManagerByConnInfo(&connInfo, false) == nullptr);
    EXPECT_TRUE(GetLatestIdByConnInfo(&connInfo) == AUTH_INVALID_ID);
    AuthSessionInfo info;
    SetAuthSessionInfo(&info, CONN_ID, false, AUTH_LINK_TYPE_WIFI);
    EXPECT_TRUE(NewAuthManager(AUTH_SEQ, &info) != nullptr);
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    ASSERT_TRUE(memcpy_s(connInfo.info.ipInfo.ip, IP_LEN, IP_TEST, strlen(IP_TEST)) == EOK);
    AuthManager *auth = GetAuthManagerByConnInfo(&connInfo, false);
    EXPECT_TRUE(auth != nullptr);
    EXPECT_TRUE(GetLatestIdByConnInfo(&connInfo) == AUTH_INVALID_ID);
    EXPECT_TRUE(GetAuthIdByConnInfo(&connInfo, false) == AUTH_SEQ);
    DelDupAuthManager(auth);
    EXPECT_TRUE(GetAuthIdByConnId(CONN_ID, true) == AUTH_INVALID_ID);
    EXPECT_TRUE(GetAuthIdByConnId(CONN_ID, false) == AUTH_SEQ);
    EXPECT_TRUE(GetLatestIdByConnInfo(nullptr) == AUTH_INVALID_ID);
}

/*
 * @tc.name: AUTH_DIRECT_ONLINE_CREATE_AUTHMANAGER_TEST_001
 * @tc.desc: AuthDirectOnlineCreateAuthManager test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthManagerTest, AUTH_DIRECT_ONLINE_CREATE_AUTHMANAGER_TEST_001, TestSize.Level1)
{
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_BLE;
    ASSERT_TRUE(memcpy_s(connInfo.info.bleInfo.bleMac, BT_MAC_LEN, BLE_MAC, strlen(BLE_MAC)) == EOK);
    ASSERT_TRUE(memcpy_s(connInfo.info.bleInfo.deviceIdHash, UDID_HASH_LEN, DEVICE_ID_HASH, DEVICE_ID_HASH_LEN) == EOK);
    EXPECT_TRUE(GetActiveAuthIdByConnInfo(&connInfo, false) == AUTH_INVALID_ID);

    AuthSessionInfo info;
    info.isSupportFastAuth = true;
    info.version = SOFTBUS_OLD_V2;
    SetAuthSessionInfo(&info, CONN_ID_2, false, AUTH_LINK_TYPE_BLE);
    bool isNewCreated;
    EXPECT_TRUE(GetDeviceAuthManager(AUTH_SEQ_4, &info, &isNewCreated, AUTH_SEQ_4) != nullptr);
    EXPECT_TRUE(AuthDirectOnlineCreateAuthManager(AUTH_SEQ_4, &info) == SOFTBUS_OK);
    AuthManager *auth = GetDeviceAuthManager(AUTH_SEQ_4, &info, &isNewCreated, AUTH_SEQ_4);
    auth->hasAuthPassed[AUTH_LINK_TYPE_BLE] = true;
    EXPECT_TRUE(GetActiveAuthIdByConnInfo(&connInfo, false) == AUTH_SEQ_4);
    AuthHandle authHandle = { .authId = AUTH_SEQ_4, .type = AUTH_LINK_TYPE_BLE };
    RemoveAuthManagerByAuthId(authHandle);
}

/*
 * @tc.name: AUTH_DIRECT_ONLINE_CREATE_AUTHMANAGER_TEST_002
 * @tc.desc: AuthDirectOnlineCreateAuthManager test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthManagerTest, AUTH_DIRECT_ONLINE_CREATE_AUTHMANAGER_TEST_002, TestSize.Level1)
{
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_BLE;
    ASSERT_TRUE(memcpy_s(connInfo.info.bleInfo.bleMac, BT_MAC_LEN, BLE_MAC, strlen(BLE_MAC)) == EOK);
    ASSERT_TRUE(memcpy_s(connInfo.info.bleInfo.deviceIdHash, UDID_HASH_LEN, DEVICE_ID_HASH, DEVICE_ID_HASH_LEN) == EOK);
    AuthSessionInfo info;
    info.isSupportFastAuth = true;
    info.version = SOFTBUS_OLD_V2;
    SetAuthSessionInfo(&info, CONN_ID_3, false, AUTH_LINK_TYPE_BLE);
    bool isNewCreated;
    EXPECT_TRUE(GetDeviceAuthManager(AUTH_SEQ_5, &info, &isNewCreated, AUTH_SEQ_5) != nullptr);
    EXPECT_TRUE(AuthDirectOnlineCreateAuthManager(AUTH_SEQ_5, &info) == SOFTBUS_OK);
    AuthManager *auth = GetDeviceAuthManager(AUTH_SEQ_5, &info, &isNewCreated, AUTH_SEQ_5);
    auth->hasAuthPassed[AUTH_LINK_TYPE_BLE] = true;
    EXPECT_TRUE(GetActiveAuthIdByConnInfo(&connInfo, false) == AUTH_SEQ_5);
    auth->hasAuthPassed[AUTH_LINK_TYPE_BLE] = false;
    auth->lastActiveTime = MAX_AUTH_VALID_PERIOD - GetCurrentTimeMs() - 1000;
    EXPECT_TRUE(GetActiveAuthIdByConnInfo(&connInfo, false) == AUTH_INVALID_ID);
    SessionKey sessionKey = { { 0 }, TEST_DATA_LEN };
    EXPECT_EQ(AddSessionKey(&auth->sessionKeyList, AUTH_SEQ_5, &sessionKey, AUTH_LINK_TYPE_BLE, false), SOFTBUS_OK);
    EXPECT_EQ(SetSessionKeyAvailable(&auth->sessionKeyList, AUTH_SEQ_5), SOFTBUS_OK);
    EXPECT_TRUE(GetActiveAuthIdByConnInfo(&connInfo, false) == AUTH_INVALID_ID);
    auth->hasAuthPassed[AUTH_LINK_TYPE_BLE] = true;
    auth->lastActiveTime = MAX_AUTH_VALID_PERIOD - GetCurrentTimeMs() + 1000;
    EXPECT_TRUE(GetActiveAuthIdByConnInfo(&connInfo, false) == AUTH_SEQ_5);
    AuthHandle authHandle = { .authId = AUTH_SEQ_5, .type = AUTH_LINK_TYPE_BLE };
    RemoveAuthManagerByAuthId(authHandle);
}

/*
 * @tc.name: GET_ACTIVE_AUTH_ID_BY_CONN_INFO_TEST_001
 * @tc.desc: GetActiveAuthIdByConnInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthManagerTest, GET_ACTIVE_AUTH_ID_BY_CONN_INFO_TEST_001, TestSize.Level1)
{
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    ASSERT_TRUE(memcpy_s(connInfo.info.ipInfo.ip, IP_LEN, IP_TEST, strlen(IP_TEST)) == EOK);
    EXPECT_TRUE(GetActiveAuthIdByConnInfo(&connInfo, false) == AUTH_INVALID_ID);
    AuthSessionInfo info;
    SetAuthSessionInfo(&info, CONN_ID_1, false, AUTH_LINK_TYPE_WIFI);
    bool isNewCreated;
    EXPECT_TRUE(GetDeviceAuthManager(AUTH_SEQ_1, &info, &isNewCreated, AUTH_SEQ_1) != nullptr);
    info.isSupportFastAuth = true;
    info.version = SOFTBUS_OLD_V2;
    SessionKey sessionKey;
    (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
    ASSERT_TRUE(memcpy_s(sessionKey.value, SESSION_KEY_LENGTH, KEY_VALUE, KEY_VALUE_LEN) == EOK);
    sessionKey.len = KEY_VALUE_LEN;
    EXPECT_TRUE(AuthManagerSetSessionKey(AUTH_SEQ_1, &info, &sessionKey, false, false) == SOFTBUS_OK);
    SetAuthSessionInfo(&info, CONN_ID_1, true, AUTH_LINK_TYPE_WIFI);
    AuthManager *auth = GetDeviceAuthManager(AUTH_SEQ_1, &info, &isNewCreated, AUTH_SEQ_1);
    auth->hasAuthPassed[AUTH_LINK_TYPE_WIFI] = true;
    auth->lastActiveTime = MAX_AUTH_VALID_PERIOD - GetCurrentTimeMs() + 1000;
    EXPECT_TRUE(GetDeviceAuthManager(AUTH_SEQ_1, &info, &isNewCreated, AUTH_SEQ_1) != nullptr);
    EXPECT_TRUE(GetActiveAuthIdByConnInfo(&connInfo, false) == AUTH_SEQ_1);
    SetAuthSessionInfo(&info, CONN_ID_1, false, AUTH_LINK_TYPE_WIFI);
    info.isSupportFastAuth = false;
    info.version = SOFTBUS_OLD_V2;
    EXPECT_TRUE(AuthManagerSetSessionKey(AUTH_SEQ_1, &info, &sessionKey, true, false) == SOFTBUS_OK);
    AuthHandle authHandle = { .authId = AUTH_SEQ_1, .type = AUTH_LINK_TYPE_WIFI };
    RemoveAuthManagerByAuthId(authHandle);
}

/*
 * @tc.name: AUTH_MANAGER_GET_SESSION_KEY_TEST_001
 * @tc.desc: AuthManagerGetSessionKey test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthManagerTest, AUTH_MANAGER_GET_SESSION_KEY_TEST_001, TestSize.Level1)
{
    AuthSessionInfo info;
    SetAuthSessionInfo(&info, CONN_ID_1, false, AUTH_LINK_TYPE_BLE);
    info.isSupportFastAuth = true;
    info.version = SOFTBUS_OLD_V2;
    SessionKey sessionKey;
    (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
    ASSERT_TRUE(memcpy_s(sessionKey.value, SESSION_KEY_LENGTH, KEY_VALUE, KEY_VALUE_LEN) == EOK);
    sessionKey.len = KEY_VALUE_LEN;
    EXPECT_TRUE(AuthManagerSetSessionKey(AUTH_SEQ_1, &info, &sessionKey, false, false) == SOFTBUS_OK);
    SessionKey tmpKey;
    EXPECT_TRUE(AuthManagerGetSessionKey(AUTH_SEQ_1, &info, &tmpKey) == SOFTBUS_AUTH_GET_SESSION_KEY_FAIL);
    SetAuthSessionInfo(&info, CONN_ID_1, false, AUTH_LINK_TYPE_WIFI);
    info.isSupportFastAuth = false;
    info.version = SOFTBUS_OLD_V2;
    EXPECT_TRUE(AuthManagerSetSessionKey(AUTH_SEQ_1, &info, &sessionKey, true, false) == SOFTBUS_OK);
    EXPECT_TRUE(AuthManagerGetSessionKey(AUTH_SEQ_1, &info, &tmpKey) == SOFTBUS_OK);
    AuthHandle authHandle1 = { .authId = AUTH_SEQ_3, .type = AUTH_LINK_TYPE_BLE };
    AuthHandle authHandle2 = { .authId = AUTH_SEQ_1, .type = AUTH_LINK_TYPE_WIFI };
    RemoveAuthManagerByAuthId(authHandle1);
    RemoveAuthManagerByAuthId(authHandle2);
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    ASSERT_TRUE(memcpy_s(connInfo.info.ipInfo.ip, IP_LEN, IP_TEST, strlen(IP_TEST)) == EOK);
    RemoveAuthManagerByConnInfo(&connInfo, false);
}

/*
 * @tc.name: RETRY_REG_TRUST_DATA_CHANGE_LISTENER_TEST_001
 * @tc.desc: RetryRegTrustDataChangeListener test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthManagerTest, RETRY_REG_TRUST_DATA_CHANGE_LISTENER_TEST_001, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = AUTH_SEQ };
    NodeInfo nodeInfo;
    AuthNotifyDeviceVerifyPassed(authHandle, &nodeInfo);
    authHandle.authId = AUTH_SEQ_2;
    AuthNotifyDeviceVerifyPassed(authHandle, &nodeInfo);
    AuthNotifyDeviceDisconnect(authHandle);
    OnDeviceNotTrusted(UDID_TEST, DEFAULT_USERID);
    OnGroupCreated("myId", GROUP_TYPE);
    OnGroupDeleted("myId", GROUP_TYPE);
    OnDeviceBound(UDID_TEST, "groupInfo");
    EXPECT_NE(RetryRegTrustDataChangeListener(), SOFTBUS_OK);
    RemoveNotPassedAuthManagerByUdid(nullptr);
    RemoveNotPassedAuthManagerByUdid(PEER_UID);
    RemoveNotPassedAuthManagerByUdid(UDID_TEST);
    DestroyAuthManagerList();
}

static void MyConnOpenedFunc(uint32_t requestId, AuthHandle authHandle)
{
    GTEST_LOG_(INFO) << "MyConnOpenedFunc Called";
}

static void MyConnOpenFailed(uint32_t requestId, int32_t reason)
{
    GTEST_LOG_(INFO) << "MyConnOpenFailed Called";
}

/*
 * @tc.name: START_VERIFY_DEVICE_TEST_001
 * @tc.desc: StartVerifyDevice test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthManagerTest, START_VERIFY_DEVICE_TEST_001, TestSize.Level1)
{
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    ASSERT_TRUE(memcpy_s(connInfo.info.ipInfo.ip, IP_LEN, IP_TEST, strlen(IP_TEST)) == EOK);
    connInfo.info.ipInfo.port = PORT;
    AuthVerifyCallback verifyCb;
    AuthConnCallback connCb;
    connCb.onConnOpened = MyConnOpenedFunc;
    connCb.onConnOpenFailed = MyConnOpenFailed;
    g_regDataChangeListener = false;
    EXPECT_TRUE(StartVerifyDevice(REQUEST_ID, &connInfo, &verifyCb, AUTH_MODULE_LNN, true) == SOFTBUS_AUTH_INIT_FAIL);
    g_regDataChangeListener = true;
    EXPECT_TRUE(StartVerifyDevice(REQUEST_ID, &connInfo, &verifyCb, AUTH_MODULE_LNN, true) == SOFTBUS_AUTH_CONN_FAIL);
    EXPECT_TRUE(StartVerifyDevice(REQUEST_ID, &connInfo, nullptr, AUTH_MODULE_LNN, true) == SOFTBUS_INVALID_PARAM);
    AuthSessionInfo info;
    SetAuthSessionInfo(&info, CONN_ID, false, AUTH_LINK_TYPE_WIFI);
    EXPECT_TRUE(NewAuthManager(AUTH_SEQ, &info) != nullptr);
    AuthHandle authHandle = { .authId = AUTH_SEQ_1, .type = AUTH_LINK_TYPE_WIFI };
    AuthHandle authHandle2 = { .authId = AUTH_SEQ, .type = AUTH_LINK_TYPE_WIFI };
    EXPECT_TRUE(AuthStartReconnectDevice(authHandle, &connInfo, REQUEST_ID, &connCb) == SOFTBUS_AUTH_NOT_FOUND);
    EXPECT_TRUE(AuthStartReconnectDevice(authHandle2, &connInfo, REQUEST_ID, &connCb) == SOFTBUS_AUTH_CONN_FAIL);
    NodeInfo nodeInfo;
    ReportAuthRequestPassed(REQUEST_ID_1, authHandle, &nodeInfo);
    ReportAuthRequestFailed(REQUEST_ID, SOFTBUS_AUTH_CONN_FAIL);
}

/*
 * @tc.name: COMPLEMENT_CONNECTION_INFO_IF_NEED_TEST_001
 * @tc.desc: ComplementConnectionInfoIfNeed test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthManagerTest, COMPLEMENT_CONNECTION_INFO_IF_NEED_TEST_001, TestSize.Level1)
{
    AuthSessionInfo info;
    SetAuthSessionInfo(&info, CONN_ID, false, AUTH_LINK_TYPE_WIFI);
    AuthManagerSetAuthPassed(AUTH_SEQ_1, &info);
    AuthManagerSetAuthPassed(AUTH_SEQ, &info);
    info.connInfo.info.ipInfo.port = PORT;
    ASSERT_TRUE(memcpy_s(info.nodeInfo.p2pInfo.p2pMac, MAC_LEN, IP_TEST, strlen(IP_TEST)) == EOK);
    SetAuthSessionInfo(&info, CONN_ID, true, AUTH_LINK_TYPE_WIFI);
    EXPECT_TRUE(NewAuthManager(AUTH_SEQ, &info) != nullptr);
    AuthManagerSetAuthPassed(AUTH_SEQ, &info);
    SetAuthSessionInfo(&info, CONN_ID_1, false, AUTH_LINK_TYPE_BLE);
    AuthManagerSetAuthFailed(AUTH_SEQ_1, &info, SOFTBUS_AUTH_TIMEOUT);
    info.connInfo.info.bleInfo.protocol = BLE_GATT;
    info.nodeInfo.feature = 511;
    AuthManagerSetAuthFinished(AUTH_SEQ_1, &info);
    info.connInfo.info.bleInfo.protocol = BLE_COC;
    AuthManagerSetAuthFinished(AUTH_SEQ_1, &info);
    SetAuthSessionInfo(&info, CONN_ID, true, AUTH_LINK_TYPE_WIFI);
    info.connInfo.info.ipInfo.port = PORT_1;
    AuthManagerSetAuthFailed(AUTH_SEQ, &info, SOFTBUS_AUTH_TIMEOUT);
    SetAuthSessionInfo(&info, CONN_ID, true, AUTH_LINK_TYPE_BR);
    AuthManagerSetAuthFinished(AUTH_SEQ_1, &info);
}

/*
 * @tc.name: HANDLE_RECONNECT_RESULT_TEST_001
 * @tc.desc: HandleReconnectResult test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthManagerTest, HANDLE_RECONNECT_RESULT_TEST_001, TestSize.Level1)
{
    ClearAuthRequest();
    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    HandleReconnectResult(&request, CONN_ID_1, SOFTBUS_INVALID_PARAM, 0);
    request.authId = REQUEST_ID;
    request.type = REQUEST_TYPE_RECONNECT;
    HandleReconnectResult(&request, CONN_ID_1, SOFTBUS_OK, 0);
    EXPECT_TRUE(AddAuthRequest(&request) == SOFTBUS_OK);
    DfxRecordLnnConnectEnd(REQUEST_ID_1, CONN_ID_1, nullptr, SOFTBUS_OK);
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    DfxRecordLnnConnectEnd(REQUEST_ID_1, CONN_ID_1, &connInfo, SOFTBUS_OK);
    OnConnectResult(REQUEST_ID_1, CONN_ID_1, SOFTBUS_OK, &connInfo);
    OnConnectResult(REQUEST_ID, CONN_ID_1, SOFTBUS_OK, &connInfo);
    connInfo.type = AUTH_LINK_TYPE_BLE;
    OnConnectResult(REQUEST_ID, CONN_ID_1, SOFTBUS_OK, &connInfo);
    request.authId = REQUEST_ID_1;
    request.type = REQUEST_TYPE_VERIFY;
    EXPECT_TRUE(AddAuthRequest(&request) == SOFTBUS_OK);
    OnConnectResult(REQUEST_ID_1, CONN_ID_1, SOFTBUS_INVALID_PARAM, &connInfo);
    OnConnectResult(REQUEST_ID_1, CONN_ID_1, SOFTBUS_INVALID_PARAM, nullptr);
    OnConnectResult(REQUEST_ID_1, CONN_ID_1, SOFTBUS_OK, &connInfo);
}

/*
 * @tc.name: TRY_GET_BR_CONN_INFO_TEST_001
 * @tc.desc: TryGetBrConnInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthManagerTest, TRY_GET_BR_CONN_INFO_TEST_001, TestSize.Level1)
{
    AuthConnInfo connInfo;
    AuthDataHead head;
    uint8_t data[] = "testdata";
    DeviceMessageParse messageParse = { CODE_VERIFY_DEVICE, DEFAULT_FREQ_CYCLE };
    HandleAuthData(&connInfo, &head, data);
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    ASSERT_TRUE(memcpy_s(connInfo.info.ipInfo.ip, IP_LEN, INVALID_IP_TEST, strlen(INVALID_IP_TEST)) == EOK);
    FlushDeviceProcess(&connInfo, true, &messageParse);
    HandleConnectionData(CONN_ID_1, &connInfo, false, &head, nullptr);
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    ASSERT_TRUE(memcpy_s(connInfo.info.ipInfo.ip, IP_LEN, IP_TEST, strlen(IP_TEST)) == EOK);
    FlushDeviceProcess(&connInfo, true, &messageParse);
    HandleConnectionData(CONN_ID_1, &connInfo, false, &head, nullptr);
    connInfo.type = AUTH_LINK_TYPE_BLE;
    HandleDeviceInfoData(CONN_ID_1, &connInfo, true, &head, nullptr);
    (void)memset_s(&head, sizeof(AuthDataHead), 0, sizeof(AuthDataHead));
    HandleCloseAckData(CONN_ID_1, &connInfo, true, &head, nullptr);
    head.seq = AUTH_SEQ_1;
    HandleCloseAckData(CONN_ID_1, &connInfo, true, &head, nullptr);
    OnDataReceived(CONN_ID_1, &connInfo, true, nullptr, data);
    OnDataReceived(CONN_ID_1, nullptr, true, &head, data);
    OnDataReceived(CONN_ID_1, &connInfo, true, &head, nullptr);
    head.seq = AUTH_SEQ;
    head.flag = AUTH_SEQ_1;
    head.len = DEVICE_ID_HASH_LEN;
    head.module = AUTH_SEQ_2;
    head.dataType = DATA_TYPE_DEVICE_ID;
    OnDataReceived(CONN_ID_1, &connInfo, true, &head, data);
    head.dataType = DATA_TYPE_AUTH;
    OnDataReceived(CONN_ID_1, &connInfo, true, &head, data);
    head.dataType = DATA_TYPE_DEVICE_INFO;
    OnDataReceived(CONN_ID_1, &connInfo, true, &head, data);
    head.dataType = DATA_TYPE_CLOSE_ACK;
    OnDataReceived(CONN_ID_1, &connInfo, true, &head, data);
    head.dataType = DATA_TYPE_CONNECTION;
    OnDataReceived(CONN_ID_1, &connInfo, true, &head, data);
    head.dataType = DATA_TYPE_META_NEGOTIATION;
    OnDataReceived(CONN_ID_1, &connInfo, true, &head, data);
    head.dataType = DATA_TYPE_DECRYPT_FAIL;
    OnDataReceived(CONN_ID_1, &connInfo, true, &head, data);
    head.dataType = DATA_TYPE_CANCEL_AUTH;
    OnDataReceived(CONN_ID_1, &connInfo, true, &head, data);
    EXPECT_TRUE(TryGetBrConnInfo(UUID_TEST, &connInfo) == SOFTBUS_AUTH_GET_BR_CONN_INFO_FAIL);
}

/*
 * @tc.name: AUTH_DEVICE_GET_P2P_CONN_INFO_TEST_001
 * @tc.desc: AuthDeviceGetP2pConnInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthManagerTest, AUTH_DEVICE_GET_P2P_CONN_INFO_TEST_001, TestSize.Level1)
{
    uint64_t connId = CONN_ID;
    HandleDisconnectedEvent(reinterpret_cast<void *>(&connId));
    AuthHandle authHandle = { .authId = AUTH_SEQ_1, .type = AUTH_LINK_TYPE_WIFI };
    AuthHandleLeaveLNN(authHandle);
    authHandle.authId = AUTH_SEQ;
    AuthHandleLeaveLNN(authHandle);
    AuthConnInfo connInfo;
    EXPECT_TRUE(AuthDeviceGetP2pConnInfo(nullptr, &connInfo) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(AuthDeviceGetP2pConnInfo(UUID_TEST, nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(AuthDeviceGetP2pConnInfo(UUID_TEST, &connInfo) == SOFTBUS_AUTH_NOT_FOUND);
    EXPECT_TRUE(AuthDeviceGetHmlConnInfo(nullptr, &connInfo) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(AuthDeviceGetHmlConnInfo(UUID_TEST, nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(AuthDeviceGetHmlConnInfo(UUID_TEST, &connInfo) == SOFTBUS_AUTH_NOT_FOUND);
    AuthSessionInfo info;
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    (void)strcpy_s(info.uuid, sizeof(info.uuid), UUID_TEST);
    SetAuthSessionInfo(&info, CONN_ID, false, AUTH_LINK_TYPE_WIFI);
    AuthManager *auth = NewAuthManager(authHandle.authId, &info);
    EXPECT_TRUE(auth != nullptr);
    EXPECT_EQ(AuthDeviceGetPreferConnInfo(UUID_TEST, &connInfo), SOFTBUS_AUTH_GET_BR_CONN_INFO_FAIL);
    EXPECT_EQ(AuthDeviceCheckConnInfo(UUID_TEST, AUTH_LINK_TYPE_WIFI, false), false);
    EXPECT_EQ(AuthDeviceCheckConnInfo(UUID_TEST, AUTH_LINK_TYPE_P2P, false), false);
    SessionKey sessionKey = { { 0 }, TEST_DATA_LEN };
    EXPECT_EQ(AddSessionKey(&auth->sessionKeyList, AUTH_SEQ, &sessionKey, AUTH_LINK_TYPE_WIFI, false), SOFTBUS_OK);
    EXPECT_EQ(SetSessionKeyAvailable(&auth->sessionKeyList, AUTH_SEQ), SOFTBUS_OK);
    AuthManagerSetAuthPassed(authHandle.authId, &info);
    EXPECT_EQ(AuthDeviceGetPreferConnInfo(UUID_TEST, &connInfo), SOFTBUS_OK);
    EXPECT_EQ(AuthDeviceCheckConnInfo(UUID_TEST, AUTH_LINK_TYPE_WIFI, false), true);
}

/*
 * @tc.name: AUTH_DEVICE_OPEN_CONN_TEST_001
 * @tc.desc: AuthDeviceOpenConn test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthManagerTest, AUTH_DEVICE_OPEN_CONN_TEST_001, TestSize.Level1)
{
    EXPECT_TRUE(AuthDeviceOpenConn(nullptr, REQUEST_ID, nullptr) == SOFTBUS_INVALID_PARAM);
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    ASSERT_TRUE(memcpy_s(connInfo.info.ipInfo.ip, IP_LEN, IP_TEST, strlen(IP_TEST)) == EOK);
    AuthConnCallback callback;
    callback.onConnOpened = MyConnOpenedFunc;
    callback.onConnOpenFailed = MyConnOpenFailed;
    EXPECT_TRUE(AuthDeviceOpenConn(&connInfo, REQUEST_ID, &callback) == SOFTBUS_AUTH_NOT_FOUND);
    connInfo.type = AUTH_LINK_TYPE_BLE;
    EXPECT_TRUE(AuthDeviceOpenConn(&connInfo, REQUEST_ID, &callback) == SOFTBUS_AUTH_CONN_FAIL);
    connInfo.type = AUTH_LINK_TYPE_ENHANCED_P2P;
    EXPECT_TRUE(AuthDeviceOpenConn(&connInfo, REQUEST_ID, &callback) == SOFTBUS_AUTH_CONN_FAIL);
    connInfo.type = AUTH_LINK_TYPE_MAX;
    EXPECT_TRUE(AuthDeviceOpenConn(&connInfo, REQUEST_ID, &callback) == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_GET_LATEST_AUTH_SEQ_LIST_TEST_001
 * @tc.desc: AuthGetLatestAuthSeqList test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthManagerTest, AUTH_GET_LATEST_AUTH_SEQ_LIST_TEST_001, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = AUTH_SEQ_3, .type = AUTH_LINK_TYPE_BLE };
    authHandle.authId = AUTH_SEQ;
    AuthDeviceCloseConn(authHandle);
    AuthDeviceCloseConn(authHandle);
    int64_t authSeq[DISCOVERY_TYPE_COUNT] = { 0 };
    EXPECT_TRUE(AuthGetLatestAuthSeqList(nullptr, authSeq, DISCOVERY_TYPE_COUNT) == SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(AuthGetLatestAuthSeqList("", authSeq, DISCOVERY_TYPE_COUNT), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(AuthGetLatestAuthSeqList(UDID_TEST, authSeq, DISCOVERY_TYPE_COUNT), SOFTBUS_OK);
    EXPECT_EQ(AuthGetLatestAuthSeqList(INVALID_UDID_TEST, authSeq, DISCOVERY_TYPE_COUNT), SOFTBUS_AUTH_NOT_FOUND);
}

/*
 * @tc.name: AUTH_DEVICE_ENCRYPT_TEST_001
 * @tc.desc: AuthDeviceEncrypt test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthManagerTest, AUTH_DEVICE_ENCRYPT_TEST_001, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = AUTH_SEQ_3, .type = AUTH_LINK_TYPE_WIFI };
    uint8_t outData[LENTH] = { 0 };
    uint32_t outLen = LENTH;
    EXPECT_TRUE(AuthDeviceEncrypt(&authHandle, TMP_IN_DATA, TMP_DATA_LEN, outData, &outLen) == SOFTBUS_INVALID_PARAM);
    authHandle.authId = AUTH_SEQ;
    EXPECT_TRUE(AuthDeviceEncrypt(&authHandle, TMP_IN_DATA, TMP_DATA_LEN, outData, &outLen) == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_DEVICE_GET_CONN_INFO_TEST_001
 * @tc.desc: AuthDeviceGetConnInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthManagerTest, AUTH_DEVICE_GET_CONN_INFO_TEST_001, TestSize.Level1)
{
    AuthConnInfo connInfo;
    AuthHandle authHandle = { .authId = AUTH_SEQ, .type = AUTH_LINK_TYPE_WIFI };
    EXPECT_TRUE(AuthDeviceGetConnInfo(authHandle, &connInfo) == SOFTBUS_OK);
    EXPECT_TRUE(AuthDeviceGetConnInfo(authHandle, nullptr) == SOFTBUS_INVALID_PARAM);
    authHandle.authId = AUTH_SEQ_3;
    EXPECT_TRUE(AuthDeviceGetConnInfo(authHandle, &connInfo) == SOFTBUS_AUTH_NOT_FOUND);
}

/*
 * @tc.name: AUTH_DEVICE_GET_SERVER_SIDE_TEST_001
 * @tc.desc: AuthDeviceGetServerSide test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthManagerTest, AUTH_DEVICE_GET_SERVER_SIDE_TEST_001, TestSize.Level1)
{
    AuthConnInfo connInfo;
    AuthDataHead head;
    (void)memset_s(&head, sizeof(AuthDataHead), 0, sizeof(AuthDataHead));
    head.flag = CLIENT_SIDE_FLAG;
    HandleDeviceIdData(CONN_ID, &connInfo, false, &head, nullptr);
    head.flag = SERVER_SIDE_FLAG;
    HandleDeviceIdData(CONN_ID, &connInfo, false, &head, nullptr);
    bool isServer;
    EXPECT_TRUE(AuthDeviceGetServerSide(AUTH_SEQ, &isServer) == SOFTBUS_OK);
    EXPECT_TRUE(AuthDeviceGetServerSide(AUTH_SEQ, nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(AuthDeviceGetServerSide(AUTH_SEQ_3, &isServer) == SOFTBUS_AUTH_NOT_FOUND);
}

/*
 * @tc.name: AUTH_SET_TCP_KEEPALIVE_BY_CONNINFO_TEST_001
 * @tc.desc: AuthSetTcpKeepaliveByConnInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthManagerTest, AUTH_SET_TCP_KEEPALIVE_BY_CONNINFO_TEST_001, TestSize.Level1)
{
    int32_t ret;
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(connInfo), 0, sizeof(connInfo));

    ret = AuthSetTcpKeepaliveByConnInfo(nullptr, HIGH_FREQ_CYCLE);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    ret = AuthSetTcpKeepaliveByConnInfo(&connInfo, HIGH_FREQ_CYCLE);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: AUTH_GET_LATEST_AUTH_SEQ_LIST_BY_TYPE_TEST_001
 * @tc.desc: AuthGetLatestAuthSeqListByType test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthManagerTest, AUTH_GET_LATEST_AUTH_SEQ_LIST_BY_TYPE_TEST_001, TestSize.Level1)
{
    AuthSessionInfo info;
    SetAuthSessionInfo(&info, CONN_ID, false, AUTH_LINK_TYPE_BLE);
    AuthManager *auth = NewAuthManager(AUTH_SEQ, &info);
    EXPECT_TRUE(auth != nullptr);
    SessionKey sessionKey = { { 0 }, TEST_DATA_LEN };
    AddSessionKey(&auth->sessionKeyList, AUTH_SEQ, &sessionKey, AUTH_LINK_TYPE_BLE, false);
    SetSessionKeyAvailable(&auth->sessionKeyList, AUTH_SEQ);
    AuthManagerSetAuthPassed(AUTH_SEQ, &info);
    auth->lastAuthSeq[AUTH_LINK_TYPE_BLE] = AUTH_SEQ;
    int64_t authSeq[DISCOVERY_TYPE_COUNT] = { 0 };
    uint64_t authVerifyTime[2] = { 0 };
    int32_t ret = AuthGetLatestAuthSeqListByType(nullptr, authSeq, authVerifyTime, DISCOVERY_TYPE_BLE);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    int32_t ret1 = AuthGetLatestAuthSeqListByType("", authSeq, authVerifyTime, DISCOVERY_TYPE_BLE);
    EXPECT_TRUE(ret1 == SOFTBUS_INVALID_PARAM);
    int32_t ret2 = AuthGetLatestAuthSeqListByType(UDID_TEST, authSeq, authVerifyTime, DISCOVERY_TYPE_BLE);
    EXPECT_TRUE(ret2 == SOFTBUS_OK);
}

/*
 * @tc.name: PROCESS_SESSION_KEY_TEST_001
 * @tc.desc: ProcessSessionKey test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthManagerTest, PROCESS_SESSION_KEY_TEST_001, TestSize.Level1)
{
    AuthSessionInfo info;
    SetAuthSessionInfo(&info, CONN_ID, false, AUTH_LINK_TYPE_BLE);
    info.normalizedType = NORMALIZED_SUPPORT;
    AuthManager *auth = NewAuthManager(AUTH_SEQ, &info);
    EXPECT_TRUE(auth != nullptr);
    SessionKey sessionKey = { { 0 }, TEST_DATA_LEN };
    AuthManager *auth1 = GetExistAuthManager(AUTH_SEQ, &info);
    EXPECT_TRUE(auth1 != nullptr);
    info.connInfo.type = AUTH_LINK_TYPE_MAX;
    int32_t keyIndex = KEY_INDEX;
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    auth->hasAuthPassed[AUTH_LINK_TYPE_BLE] = true;
    int32_t ret = ProcessEmptySessionKey(&info, keyIndex, false, &sessionKey);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = AuthProcessEmptySessionKey(&info, keyIndex);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    info.module = AUTH_MODULE_TRANS;
    ret = AuthProcessEmptySessionKey(&info, keyIndex);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    AuthManager *auth2 = FindAuthManagerByUdid(info.udid, info.connInfo.type, info.isServer);
    EXPECT_TRUE(auth2 != nullptr);
    keyIndex = 0;
    ret = ProcessEmptySessionKey(&info, keyIndex, false, &sessionKey);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: GENERATE_UDID_HASH_TEST_001
 * @tc.desc: GenerateUdidHash test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthManagerTest, GENERATE_UDID_HASH_TEST_001, TestSize.Level1)
{
    NodeInfo info;
    AuthHandle authHandle = {
        .authId = AUTH_SEQ,
        .type = AUTH_LINK_TYPE_WIFI,
    };
    ReportAuthRequestPassed(REQUEST_ID_1, authHandle, &info);
    ReportAuthRequestPassed(REQUEST_ID_1 + 1, authHandle, &info);
    AuthSessionInfo sessionInfo;
    PostCancelAuthMessage(AUTH_SEQ, &sessionInfo);
    AuthNotifyAuthPassed(AUTH_SEQ, &sessionInfo);
    AuthConnInfo connInfo;
    AuthDataHead head;
    HandleDecryptFailData(CONN_ID_1, &connInfo, true, &head, nullptr);
    HandleCancelAuthData(CONN_ID_1, &connInfo, true, &head, nullptr);
    connInfo.type = AUTH_LINK_TYPE_BLE;
    bool fromServer = true;
    CorrectFromServer(CONN_ID_1, &connInfo, &fromServer);
    uint8_t hash[SHA_256_HASH_LEN];
    int32_t ret = GenerateUdidHash(UDID_TEST, hash);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    CorrectFromServer(CONN_ID_1, &connInfo, &fromServer);
}

/*
 * @tc.name: GET_ALL_HML_OR_P2P_AUTH_HANDLE_NUM_TEST_001
 * @tc.desc: GetAllHmlOrP2pAuthHandleNum test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthManagerTest, GET_ALL_HML_OR_P2P_AUTH_HANDLE_NUM_TEST_001, TestSize.Level1)
{
    AuthHandle authHandle1 = {
        .authId = AUTH_SEQ,
        .type = AUTH_LINK_TYPE_WIFI,
    };
    AuthDeviceGetLatestIdByUuid(UDID_TEST, AUTH_LINK_TYPE_BLE, &authHandle1);
    AuthDeviceGetLatestIdByUuid(UDID_TEST, AUTH_LINK_TYPE_BR, &authHandle1);
    uint32_t ret = GetAllHmlOrP2pAuthHandleNum();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = GetHmlOrP2pAuthHandle(nullptr, nullptr);
    EXPECT_TRUE(ret == 3868524547);
    AuthHandle *authHandle = &authHandle1;
    ret = GetHmlOrP2pAuthHandle(&authHandle, nullptr);
    EXPECT_TRUE(ret == 3868524547);
    int32_t num = 0;
    ret = GetHmlOrP2pAuthHandle(&authHandle, &num);
    EXPECT_TRUE(ret == 3868983317);
}

/*
 * @tc.name: AUTH_DEVICE_GET_AUTH_HANDLE_BY_INDEX_TEST_001
 * @tc.desc: AuthDeviceGetAuthHandleByIndex test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthManagerTest, AUTH_DEVICE_GET_AUTH_HANDLE_BY_INDEX_TEST_001, TestSize.Level1)
{
    AuthHandle authHandle;
    int32_t ret = AuthDeviceGetAuthHandleByIndex(UDID_TEST, false, KEY_INDEX, &authHandle);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = AuthDeviceGetAuthHandleByIndex(UDID_TEST, false, KEY_INDEX, &authHandle);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = AuthDeviceGetAuthHandleByIndex(UDID_TEST, false, KEY_INDEX, &authHandle);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = AuthDeviceGetAuthHandleByIndex(nullptr, false, KEY_INDEX, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthDeviceGetAuthHandleByIndex(UDID_TEST, true, KEY_INDEX, &authHandle);
    EXPECT_TRUE(ret == SOFTBUS_AUTH_NOT_FOUND);
}

/*
 * @tc.name: AUTH_MAP_INIT_TEST_001
 * @tc.desc: AuthMapInit test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthManagerTest, AUTH_MAP_INIT_TEST_001, TestSize.Level1)
{
    uint64_t currentTime = 123456;
    InsertToAuthLimitMap(UDID_TEST, currentTime);
    AuthDeleteLimitMap(nullptr);
    ClearAuthLimitMap();
    int32_t res = GetNodeFromAuthLimitMap(UDID_TEST, &currentTime);
    EXPECT_TRUE(res == SOFTBUS_OK);
    bool ret = AuthMapInit();
    EXPECT_TRUE(ret == true);
    InsertToAuthLimitMap(UDID_TEST, currentTime);
    currentTime = 0;
    InsertToAuthLimitMap(UUID_TEST, currentTime);
    res = GetNodeFromAuthLimitMap(UDID_TEST, &currentTime);
    EXPECT_TRUE(res == SOFTBUS_OK);
    res = GetNodeFromAuthLimitMap(INVALID_UDID_TEST, &currentTime);
    EXPECT_TRUE(res == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: IS_NEED_AUTH_LIMIT_TEST_001
 * @tc.desc: IsNeedAuthLimit test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthManagerTest, IS_NEED_AUTH_LIMIT_TEST_001, TestSize.Level1)
{
    bool ret = IsNeedAuthLimit(nullptr);
    EXPECT_TRUE(ret == false);
    ret = IsNeedAuthLimit(INVALID_UDID_TEST);
    EXPECT_TRUE(ret == false);
    ret = IsNeedAuthLimit(UUID_TEST);
    EXPECT_TRUE(ret == false);
    ret = IsNeedAuthLimit(UDID_TEST);
    EXPECT_TRUE(ret == false);
    AuthDeleteLimitMap(nullptr);
    AuthDeleteLimitMap(INVALID_UDID_TEST);
    AuthDeleteLimitMap(UUID_TEST);
    AuthDeleteLimitMap(UDID_TEST);
    ClearAuthLimitMap();
}

/*
 * @tc.name: AUTH_DEVICE_ENCRYPT_TEST_002
 * @tc.desc: AuthDeviceEncrypt test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthManagerTest, AUTH_DEVICE_ENCRYPT_TEST_002, TestSize.Level1)
{
    AuthAddNodeToLimitMap(UDID_TEST, SOFTBUS_AUTH_HICHAIN_GROUP_NOT_EXIST);
    AuthAddNodeToLimitMap(UDID_TEST, SOFTBUS_AUTH_HICHAIN_LOCAL_IDENTITY_NOT_EXIST);
    AuthAddNodeToLimitMap(UDID_TEST, SOFTBUS_AUTH_HICHAIN_NO_CANDIDATE_GROUP);
    AuthAddNodeToLimitMap(UDID_TEST, SOFTBUS_INVALID_PARAM);
    AuthDeviceNotTrust(nullptr);
    const char *peerUdid = "";
    AuthDeviceNotTrust(peerUdid);
    AuthDeviceNotTrust(UDID_TEST);
    AuthSessionInfo info;
    SetAuthSessionInfo(&info, CONN_ID, false, AUTH_LINK_TYPE_WIFI);
    AuthManager *auth = NewAuthManager(AUTH_SEQ, &info);
    EXPECT_TRUE(auth != nullptr);
    AuthHandle authHandle = {
        .authId = AUTH_SEQ_5,
        .type = AUTH_LINK_TYPE_WIFI,
    };
    uint8_t outData[LENTH] = { 0 };
    uint32_t outLen = LENTH + TMP_DATA_LEN + 32;
    EXPECT_TRUE(AuthDeviceEncrypt(&authHandle, TMP_IN_DATA, TMP_DATA_LEN, outData, &outLen) == SOFTBUS_AUTH_NOT_FOUND);
    authHandle.authId = AUTH_SEQ;
    EXPECT_TRUE(AuthDeviceEncrypt(&authHandle, TMP_IN_DATA, TMP_DATA_LEN, outData, &outLen) == SOFTBUS_ENCRYPT_ERR);
}

/*
 * @tc.name: REMOVE_AUTHSESSION_KEY_BY_INDEX_TEST_001
 * @tc.desc: RemoveAuthSessionKeyByIndex test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthManagerTest, REMOVE_AUTHSESSION_KEY_BY_INDEX_TEST_001, TestSize.Level1)
{
    int64_t authSeq = 1;
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    SetAuthSessionInfo(&info, CONN_ID, false, AUTH_LINK_TYPE_WIFI);
    AuthManager *auth = NewAuthManager(authSeq, &info);
    EXPECT_TRUE(auth != nullptr);
    SessionKey sessionKey = { { 0 }, TEST_DATA_LEN };
    EXPECT_EQ(AddSessionKey(&auth->sessionKeyList, authSeq, &sessionKey, AUTH_LINK_TYPE_WIFI, false), SOFTBUS_OK);
    RemoveAuthSessionKeyByIndex(0, 0, AUTH_LINK_TYPE_WIFI);
}

static void OnConnOpened(uint32_t requestId, AuthHandle authHandle)
{
    (void)requestId;
    (void)authHandle;
}

static void OnConnOpenFailed(uint32_t requestId, int32_t reason)
{
    (void)requestId;
    (void)reason;
}

/*
 * @tc.name: REPORT_AUTH_REQUEST_PASSED_TEST_001
 * @tc.desc: ReportAuthRequestPassed test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthManagerTest, REPORT_AUTH_REQUEST_PASSED_TEST_001, TestSize.Level1)
{
    AuthRequest request;
    AuthHandle authHandle = {
        .authId = AUTH_SEQ,
        .type = AUTH_LINK_TYPE_BLE,
    };
    NodeInfo nodeInfo;

    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    request.requestId = 1;
    request.connInfo.type = AUTH_LINK_TYPE_BLE;
    request.connCb.onConnOpened = OnConnOpened;
    request.connCb.onConnOpenFailed = OnConnOpenFailed;
    int32_t ret = AddAuthRequest(&request);
    EXPECT_TRUE(ret != 0);
    ReportAuthRequestPassed(request.requestId, authHandle, &nodeInfo);
    DelAuthRequest(request.requestId);
}
} // namespace OHOS
