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

#include "auth_manager.h"
#include "auth_manager.c"
#include "auth_request.h"

namespace OHOS {
using namespace testing::ext;
const uint64_t CONN_ID = 10 | ((uint64_t)AUTH_LINK_TYPE_WIFI << INT32_BIT_NUM);
constexpr int64_t AUTH_SEQ = 1;
constexpr int64_t AUTH_SEQ_1 = 2;
constexpr int64_t AUTH_SEQ_2 = 3;
constexpr int64_t AUTH_SEQ_3 = 4;
constexpr uint64_t CONN_ID_1 = 11;
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

void AuthManagerTest::SetUp()
{
}

void AuthManagerTest::TearDown()
{
}

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
            ASSERT_TRUE(memcpy_s(info->connInfo.info.bleInfo.deviceIdHash,
                UDID_HASH_LEN, DEVICE_ID_HASH, DEVICE_ID_HASH_LEN) == EOK);
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
    ASSERT_TRUE(memcpy_s(connInfo.info.ipInfo.ip, IP_LEN, INVALID_IP_TEST, strlen(INVALID_IP_TEST)) == EOK);
    EXPECT_TRUE(FindAuthManagerByConnInfo(&connInfo, false) == nullptr);
    RemoveAuthManagerByConnInfo(&connInfo, false);
    PrintAuthConnInfo(&connInfo);
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_BR;
    ASSERT_TRUE(memcpy_s(connInfo.info.brInfo.brMac, BT_MAC_LEN, BR_MAC, strlen(BR_MAC)) == EOK);
    PrintAuthConnInfo(&connInfo);
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_BLE;
    ASSERT_TRUE(memcpy_s(connInfo.info.bleInfo.deviceIdHash, UDID_HASH_LEN,
        DEVICE_ID_HASH, DEVICE_ID_HASH_LEN) == EOK);
    ASSERT_TRUE(memcpy_s(connInfo.info.bleInfo.bleMac, BT_MAC_LEN,
        BLE_MAC, strlen(BLE_MAC)) == EOK);
    PrintAuthConnInfo(&connInfo);
    connInfo.type = AUTH_LINK_TYPE_P2P;
    PrintAuthConnInfo(&connInfo);
    PrintAuthConnInfo(nullptr);
    EXPECT_EQ(FindAuthManagerByUuid(UUID_TEST, AUTH_LINK_TYPE_WIFI, false), nullptr);
    EXPECT_EQ(FindAuthManagerByUdid(UDID_TEST, AUTH_LINK_TYPE_WIFI, false), nullptr);
    SessionKey sessionKey = { { 0 }, TEST_DATA_LEN };
    EXPECT_EQ(AddSessionKey(&auth->sessionKeyList, AUTH_SEQ, &sessionKey, AUTH_LINK_TYPE_WIFI), SOFTBUS_OK);
    EXPECT_EQ(SetSessionKeyAvailable(&auth->sessionKeyList, AUTH_SEQ), SOFTBUS_OK);
    AuthManagerSetAuthPassed(AUTH_SEQ, &info);
    EXPECT_NE(FindAuthManagerByUuid(UUID_TEST, AUTH_LINK_TYPE_WIFI, false), nullptr);
    EXPECT_NE(FindAuthManagerByUdid(UDID_TEST, AUTH_LINK_TYPE_WIFI, false), nullptr);
}

static int32_t MyUpdateFuncReturnError(AuthManager *auth1, const AuthManager *auth2, AuthLinkType type)
{
    GTEST_LOG_(INFO) << "MyUpdateFuncReturnError Called";
    return SOFTBUS_ERR;
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
    EXPECT_TRUE(FindAuthManagerByAuthId(AUTH_SEQ) != nullptr);
    EXPECT_TRUE(FindAuthManagerByAuthId(AUTH_SEQ_2) == nullptr);
    EXPECT_TRUE(FindAuthManagerByConnId(CONN_ID, false) != nullptr);
    AuthManager *auth = FindAuthManagerByConnId(CONN_ID, true);
    EXPECT_TRUE(auth == nullptr);
    EXPECT_TRUE(UpdateAuthManagerByAuthId(AUTH_SEQ_2,
        MyUpdateFuncReturnError, auth, AUTH_LINK_TYPE_WIFI) == SOFTBUS_AUTH_NOT_FOUND);
    EXPECT_TRUE(UpdateAuthManagerByAuthId(AUTH_SEQ, MyUpdateFuncReturnError, auth,
        AUTH_LINK_TYPE_WIFI) == SOFTBUS_ERR);
    EXPECT_TRUE(UpdateAuthManagerByAuthId(AUTH_SEQ, MyUpdateFuncReturnOk, auth, AUTH_LINK_TYPE_WIFI) == SOFTBUS_OK);
    AuthConnInfo connInfo;
    EXPECT_EQ(GetAuthConnInfoByUuid(UUID_TEST, AUTH_LINK_TYPE_WIFI, &connInfo), SOFTBUS_OK);
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
    EXPECT_TRUE(AuthManagerIsExist(AUTH_SEQ_1, &info, &isNewCreated) != nullptr);
    info.isSupportFastAuth = true;
    info.version = SOFTBUS_OLD_V2;
    SessionKey sessionKey;
    (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
    ASSERT_TRUE(memcpy_s(sessionKey.value, SESSION_KEY_LENGTH, KEY_VALUE, KEY_VALUE_LEN) == EOK);
    sessionKey.len = KEY_VALUE_LEN;
    EXPECT_TRUE(AuthManagerSetSessionKey(AUTH_SEQ_1, &info, &sessionKey, false) == SOFTBUS_OK);
    SetAuthSessionInfo(&info, CONN_ID_1, true, AUTH_LINK_TYPE_WIFI);
    EXPECT_TRUE(AuthManagerIsExist(AUTH_SEQ_1, &info, &isNewCreated) != nullptr);
    EXPECT_TRUE(GetActiveAuthIdByConnInfo(&connInfo, false) == AUTH_SEQ_1);
    SetAuthSessionInfo(&info, CONN_ID_1, false, AUTH_LINK_TYPE_WIFI);
    info.isSupportFastAuth = false;
    info.version = SOFTBUS_OLD_V2;
    EXPECT_TRUE(AuthManagerSetSessionKey(AUTH_SEQ_1, &info, &sessionKey, true) == SOFTBUS_OK);
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
    EXPECT_TRUE(AuthManagerSetSessionKey(AUTH_SEQ_1, &info, &sessionKey, false) == SOFTBUS_OK);
    SessionKey tmpKey;
    EXPECT_TRUE(AuthManagerGetSessionKey(AUTH_SEQ_1, &info, &tmpKey) == SOFTBUS_AUTH_GET_SESSION_KEY_FAIL);
    SetAuthSessionInfo(&info, CONN_ID_1, false, AUTH_LINK_TYPE_WIFI);
    info.isSupportFastAuth = false;
    info.version = SOFTBUS_OLD_V2;
    EXPECT_TRUE(AuthManagerSetSessionKey(AUTH_SEQ_1, &info, &sessionKey, true) == SOFTBUS_OK);
    EXPECT_TRUE(AuthManagerGetSessionKey(AUTH_SEQ_1, &info, &tmpKey) == SOFTBUS_OK);
    RemoveAuthSessionKeyByIndex(AUTH_SEQ_3, KEY_INDEX, AUTH_LINK_TYPE_BLE);
    RemoveAuthSessionKeyByIndex(AUTH_SEQ_1, KEY_INDEX, AUTH_LINK_TYPE_BLE);
    AuthHandle authHandle1 = {.authId = AUTH_SEQ_3, .type = AUTH_LINK_TYPE_BLE};
    AuthHandle authHandle2 = {.authId = AUTH_SEQ_1, .type = AUTH_LINK_TYPE_WIFI};
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
    NotifyDeviceVerifyPassed(authHandle, &nodeInfo);
    authHandle.authId = AUTH_SEQ_2;
    NotifyDeviceVerifyPassed(authHandle, &nodeInfo);
    NotifyDeviceDisconnect(authHandle);
    OnDeviceNotTrusted(UDID_TEST);
    OnGroupCreated("myId", GROUP_TYPE);
    OnGroupDeleted("myId", GROUP_TYPE);
    OnDeviceBound(UDID_TEST, "groupInfo");
    EXPECT_TRUE(RetryRegTrustDataChangeListener() == SOFTBUS_ERR);
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
    EXPECT_TRUE(StartVerifyDevice(REQUEST_ID, &connInfo, &verifyCb, &connCb, true) == SOFTBUS_AUTH_INIT_FAIL);
    g_regDataChangeListener = true;
    EXPECT_TRUE(StartVerifyDevice(REQUEST_ID, &connInfo, &verifyCb, &connCb, true) == SOFTBUS_AUTH_CONN_FAIL);
    EXPECT_TRUE(StartVerifyDevice(REQUEST_ID, &connInfo, nullptr, nullptr, true) == SOFTBUS_AUTH_CONN_FAIL);
    AuthSessionInfo info;
    SetAuthSessionInfo(&info, CONN_ID, false, AUTH_LINK_TYPE_WIFI);
    EXPECT_TRUE(NewAuthManager(AUTH_SEQ, &info) != nullptr);
    AuthHandle authHandle = { .authId = AUTH_SEQ_1, .type = AUTH_LINK_TYPE_WIFI };
    AuthHandle authHandle2 = { .authId = AUTH_SEQ, .type = AUTH_LINK_TYPE_WIFI };
    EXPECT_TRUE(StartReconnectDevice(authHandle, &connInfo, REQUEST_ID, &connCb) == SOFTBUS_AUTH_NOT_FOUND);
    EXPECT_TRUE(StartReconnectDevice(authHandle2, &connInfo, REQUEST_ID, &connCb) == SOFTBUS_AUTH_CONN_FAIL);
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
    HandleReconnectResult(&request, CONN_ID_1, SOFTBUS_ERR, 0);
    request.authId = REQUEST_ID;
    request.type = REQUEST_TYPE_RECONNECT;
    HandleReconnectResult(&request, CONN_ID_1, SOFTBUS_OK, 0);
    EXPECT_TRUE(AddAuthRequest(&request) == SOFTBUS_OK);
    HandleBleConnectResult(REQUEST_ID_1, AUTH_SEQ, CONN_ID, SOFTBUS_OK, 0);
    HandleBleConnectResult(REQUEST_ID, AUTH_SEQ, CONN_ID, SOFTBUS_OK, 0);
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
    OnConnectResult(REQUEST_ID_1, CONN_ID_1, SOFTBUS_ERR, &connInfo);
    OnConnectResult(REQUEST_ID_1, CONN_ID_1, SOFTBUS_ERR, nullptr);
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
    DeviceMessageParse messageParse = { CODE_VERIFY_DEVICE, DEFT_FREQ_CYCLE };
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
    EXPECT_EQ(AddSessionKey(&auth->sessionKeyList, AUTH_SEQ, &sessionKey, AUTH_LINK_TYPE_WIFI), SOFTBUS_OK);
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
    AuthHandle authHandle = { .authId = AUTH_SEQ_3, .type = AUTH_LINK_TYPE_BLE  };
    authHandle.authId = AUTH_SEQ;
    AuthDeviceCloseConn(authHandle);
    AuthDeviceCloseConn(authHandle);
    int64_t authSeq[DISCOVERY_TYPE_COUNT] = { 0 };
    EXPECT_TRUE(AuthGetLatestAuthSeqList(nullptr, authSeq,
        DISCOVERY_TYPE_COUNT) == SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(AuthGetLatestAuthSeqList("", authSeq, DISCOVERY_TYPE_COUNT), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(AuthGetLatestAuthSeqList(UDID_TEST, authSeq, DISCOVERY_TYPE_COUNT), SOFTBUS_OK);
    EXPECT_EQ(AuthGetLatestAuthSeqList(INVALID_UDID_TEST, authSeq,
        DISCOVERY_TYPE_COUNT), SOFTBUS_AUTH_NOT_FOUND);
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
    uint8_t outData[LENTH] = {0};
    uint32_t outLen = LENTH;
    EXPECT_TRUE(AuthDeviceEncrypt(&authHandle, TMP_IN_DATA,
        TMP_DATA_LEN, outData, &outLen) == SOFTBUS_INVALID_PARAM);
    authHandle.authId = AUTH_SEQ;
    EXPECT_TRUE(AuthDeviceEncrypt(&authHandle, TMP_IN_DATA,
        TMP_DATA_LEN, outData, &outLen) == SOFTBUS_INVALID_PARAM);
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
 * @tc.name: AUTH_VERIFY_AFTER_NOTIFY_NORMALIZE_TEST_001
 * @tc.desc: AuthVerifyAfterNotifyNormalize test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthManagerTest, AUTH_VERIFY_AFTER_NOTIFY_NORMALIZE_TEST_001, TestSize.Level1)
{
    NormalizeRequest request;

    (void)memset_s(&request, sizeof(NormalizeRequest), 0, sizeof(NormalizeRequest));
    EXPECT_TRUE(AuthVerifyAfterNotifyNormalize(nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(AuthVerifyAfterNotifyNormalize(&request) != SOFTBUS_OK);
    EXPECT_TRUE(LooperInit() == SOFTBUS_OK);
    EXPECT_TRUE(AuthVerifyAfterNotifyNormalize(&request) == SOFTBUS_OK);
    LooperDeinit();
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
    AddSessionKey(&auth->sessionKeyList, AUTH_SEQ, &sessionKey, AUTH_LINK_TYPE_BLE);
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
} // namespace OHOS
