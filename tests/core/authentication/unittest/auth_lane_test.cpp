/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <securec.h>
#include <thread>

#include "auth_device.c"
#include "auth_interface.c"
#include "auth_interface.h"
#include "auth_lane.c"
#include "auth_lane_mock.h"
#include "auth_log.h"
#include "auth_manager.c"
#include "auth_manager.h"
#include "lnn_lane_common.h"
#include "lnn_trans_lane.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {

const uint64_t CONN_ID = 10 | ((uint64_t)AUTH_LINK_TYPE_WIFI << INT32_BIT_NUM);
constexpr char NETWORK_ID[] = "testnetworkid123";
constexpr char UUID_TEST[UUID_BUF_LEN] = "testId123";
constexpr char UDID_TEST[UDID_BUF_LEN] = "testId123";
constexpr char IP_TEST[IP_LEN] = "192.168.51.170";
constexpr char BR_MAC[BT_MAC_LEN] = "00:15:5d:de:d4:23";
constexpr char BLE_MAC[BT_MAC_LEN] = "00:15:5d:de:d4:23";
constexpr uint8_t DEVICE_ID_HASH[UDID_HASH_LEN] = "123456789";
constexpr int64_t AUTH_SEQ = 1;
constexpr int32_t DEVICE_ID_HASH_LEN = 9;
constexpr int32_t PORT = 1;

static void OnConnOpenedTest(uint32_t requestId, AuthHandle authHandle)
{
    (void)requestId;
    (void)authHandle;
    AUTH_LOGI(
        AUTH_TEST, "OnConnOpenedTest: requestId=%{public}d, authId=%{public}" PRId64 "", requestId, authHandle.authId);
}

static void OnConnOpenFailedTest(uint32_t requestId, int32_t reason)
{
    (void)requestId;
    (void)reason;
    AUTH_LOGI(AUTH_TEST, "OnConnOpenFailedTest: requestId=%{public}d, reason=%{public}d.", requestId, reason);
}

static AuthConnCallback authConnCb = {
    .onConnOpened = OnConnOpenedTest,
    .onConnOpenFailed = OnConnOpenFailedTest,
};

class AuthLaneTest : public testing::Test {
public:
    AuthLaneTest() { }
    ~AuthLaneTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void AuthLaneTest::SetUpTestCase()
{
    int32_t ret = LooperInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnInitDistributedLedger();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnInitLocalLedger();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnInitLnnLooper();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = InitLane();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    GTEST_LOG_(INFO) << "AuthLaneTest start";
}

void AuthLaneTest::TearDownTestCase()
{
    DeinitLane();
    LnnDeinitLocalLedger();
    LnnDeinitDistributedLedger();
    LooperDeinit();
    GTEST_LOG_(INFO) << "AuthLaneTest end";
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
            ASSERT_TRUE(memcpy_s(info->connInfo.info.bleInfo.deviceIdHash, UDID_HASH_LEN,
                DEVICE_ID_HASH, DEVICE_ID_HASH_LEN) == EOK);
            break;
        case AUTH_LINK_TYPE_BR:
            ASSERT_TRUE(memcpy_s(info->connInfo.info.brInfo.brMac, BT_MAC_LEN, BR_MAC, strlen(BR_MAC)) == EOK);
            break;
        case AUTH_LINK_TYPE_P2P:
        case AUTH_LINK_TYPE_ENHANCED_P2P:
            ASSERT_TRUE(memcpy_s(info->connInfo.info.ipInfo.ip, IP_LEN, IP_TEST, strlen(IP_TEST)) == EOK);
            info->connInfo.info.ipInfo.port = PORT;
            break;
        default:
            break;
    }
}

/*
 * @tc.name: ADD_AUTH_REQUEST_NODE_TEST_001
 * @tc.desc: add auth request node test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthLaneTest, ADD_AUTH_REQUEST_NODE_TEST_001, TestSize.Level1)
{
    uint32_t laneReqId = 1;
    uint32_t authRequestId = 1;

    InitAuthReqInfo();
    ListInit(&g_authClientList);
    ListInit(&g_authServerList);
    AuthCommonInit();
    AuthLaneInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetRemoteStrInfo)
        .WillRepeatedly(DoAll(SetArrayArgument<2>(UUID_TEST, UUID_TEST + UUID_BUF_LEN), Return(SOFTBUS_OK)));
    int32_t ret = AddAuthReqNode(nullptr, laneReqId, authRequestId, &authConnCb);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    ret = AddAuthReqNode(NETWORK_ID, INVALID_LANE_REQ_ID, authRequestId, &authConnCb);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    ret = AddAuthReqNode(NETWORK_ID, laneReqId, authRequestId, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    ret = AddAuthReqNode(NETWORK_ID, laneReqId, authRequestId, &authConnCb);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    LaneConnInfo info;
    (void)memset_s(&info, sizeof(LaneConnInfo), 0, sizeof(LaneConnInfo));
    AuthOnLaneAllocSuccess(laneReqId, &info);

    AuthHandle authHandle;
    (void)memset_s(&info, sizeof(LaneConnInfo), 0, sizeof(LaneConnInfo));
    authHandle.authId = 1;
    authHandle.type = AUTH_LINK_TYPE_WIFI;
    OnAuthConnOpenedSucc(authRequestId, authHandle);

    ret = DelAuthReqInfoByAuthHandle(&authHandle);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    DestroyAuthManagerList();
    AuthCommonDeinit();
    DeInitAuthReqInfo();
}

/*
 * @tc.name: AUTH_GET_REQUEST_OPTION_TEST_001
 * @tc.desc: auth get request option test test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthLaneTest, AUTH_GET_REQUEST_OPTION_TEST_001, TestSize.Level1)
{
    AuthLaneInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetRemoteStrInfo)
        .WillRepeatedly(DoAll(SetArrayArgument<2>(UUID_TEST, UUID_TEST + UUID_BUF_LEN), Return(SOFTBUS_OK)));
    LaneAllocInfo allocInfo;
    (void)memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo));

    int32_t ret = AuthGetLaneAllocInfo(nullptr, &allocInfo);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    ret = AuthGetLaneAllocInfo(NETWORK_ID, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    ret = AuthGetLaneAllocInfo(NETWORK_ID, &allocInfo);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: GET_AUTH_LINK_TYPE_LIST_TEST_001
 * @tc.desc: get auth link type list test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthLaneTest, GET_AUTH_LINK_TYPE_LIST_TEST_001, TestSize.Level1)
{
    AuthLinkTypeList linkTypeList;
    (void)memset_s(&linkTypeList, sizeof(AuthLinkTypeList), 0, sizeof(AuthLinkTypeList));

    AuthLaneInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));

    int32_t ret = GetAuthLinkTypeList(nullptr, &linkTypeList);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    ret = GetAuthLinkTypeList(NETWORK_ID, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    ret = GetAuthLinkTypeList(NETWORK_ID, &linkTypeList);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: AUTH_ALLOC_LANE_001
 * @tc.desc: auth alloc lane test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthLaneTest, AUTH_ALLOC_LANE_001, TestSize.Level1)
{
    InitAuthReqInfo();
    ListInit(&g_authClientList);
    ListInit(&g_authServerList);
    AuthCommonInit();
    uint32_t authRequestId = 0;

    int32_t ret = AuthAllocLane(NETWORK_ID, authRequestId, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    ret = AuthAllocLane(nullptr, authRequestId, &authConnCb);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    AuthLaneInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetRemoteStrInfo)
        .WillRepeatedly(DoAll(SetArrayArgument<2>(UUID_TEST, UUID_TEST + UUID_BUF_LEN), Return(SOFTBUS_OK)));
    ret = AuthAllocLane(NETWORK_ID, authRequestId, &authConnCb);
    EXPECT_NE(ret, SOFTBUS_OK);
    DestroyAuthManagerList();
    AuthCommonDeinit();
    DeInitAuthReqInfo();
}

/*
 * @tc.name: AUTH_ALLOC_LANE_WLAN_001
 * @tc.desc: auth alloc lane wlan test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthLaneTest, AUTH_ALLOC_LANE_WLAN_001, TestSize.Level1)
{
    InitAuthReqInfo();
    ListInit(&g_authClientList);
    ListInit(&g_authServerList);
    AuthCommonInit();
    AuthLaneInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetRemoteStrInfo)
        .WillRepeatedly(DoAll(SetArrayArgument<2>(UUID_TEST, UUID_TEST + UUID_BUF_LEN), Return(SOFTBUS_OK)));

    AuthSessionInfo info;
    SetAuthSessionInfo(&info, CONN_ID, false, AUTH_LINK_TYPE_WIFI);
    EXPECT_TRUE(NewAuthManager(AUTH_SEQ, &info) != nullptr);
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    ASSERT_TRUE(memcpy_s(connInfo.info.ipInfo.ip, IP_LEN, IP_TEST, strlen(IP_TEST)) == EOK);
    AuthManager *auth = FindAuthManagerByConnInfo(&connInfo, false);
    EXPECT_TRUE(auth != nullptr);
    auth->hasAuthPassed[AUTH_LINK_TYPE_WIFI] = true;
    auth->authId = 1;
    auth->lastVerifyTime = 1;

    uint32_t authRequestId = AuthGenRequestId();
    int32_t ret = AuthAllocConn(NETWORK_ID, authRequestId, &authConnCb);
    EXPECT_NE(ret, SOFTBUS_OK);

    uint32_t laneReqId = GetLaneManager()->lnnGetLaneHandle(LANE_TYPE_CTRL);
    LaneConnInfo laneConnInfo;
    (void)memset_s(&laneConnInfo, sizeof(LaneConnInfo), 0, sizeof(LaneConnInfo));
    laneConnInfo.laneId = 1;
    laneConnInfo.type = LANE_WLAN_5G;
    AuthOnLaneAllocSuccess(laneReqId, &laneConnInfo);

    DupAuthManager(auth);
    DestroyAuthManagerList();
    AuthCommonDeinit();
    DeInitAuthReqInfo();
}

/*
 * @tc.name: AUTH_ALLOC_LANE_WLAN_002
 * @tc.desc: AuthDeviceOpenConn return SOFTBUS_AUTH_NOT_FOUND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthLaneTest, AUTH_ALLOC_LANE_WLAN_002, TestSize.Level1)
{
    InitAuthReqInfo();
    ListInit(&g_authClientList);
    ListInit(&g_authServerList);
    AuthCommonInit();
    AuthLaneInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetRemoteStrInfo)
        .WillRepeatedly(DoAll(SetArrayArgument<2>(UUID_TEST, UUID_TEST + UUID_BUF_LEN), Return(SOFTBUS_OK)));

    AuthSessionInfo info;
    SetAuthSessionInfo(&info, CONN_ID, false, AUTH_LINK_TYPE_WIFI);
    EXPECT_TRUE(NewAuthManager(AUTH_SEQ, &info) != nullptr);
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    ASSERT_TRUE(memcpy_s(connInfo.info.ipInfo.ip, IP_LEN, IP_TEST, strlen(IP_TEST)) == EOK);
    AuthManager *auth = FindAuthManagerByConnInfo(&connInfo, false);
    EXPECT_TRUE(auth != nullptr);
    auth->hasAuthPassed[AUTH_LINK_TYPE_WIFI] = true;

    uint32_t authRequestId = AuthGenRequestId();
    int32_t ret = AuthAllocConn(NETWORK_ID, authRequestId, &authConnCb);
    EXPECT_NE(ret, SOFTBUS_OK);

    uint32_t laneReqId = GetLaneManager()->lnnGetLaneHandle(LANE_TYPE_CTRL);
    LaneConnInfo laneConnInfo;
    (void)memset_s(&laneConnInfo, sizeof(LaneConnInfo), 0, sizeof(LaneConnInfo));
    laneConnInfo.laneId = 1;
    laneConnInfo.type = LANE_WLAN_5G;
    AuthOnLaneAllocSuccess(laneReqId, &laneConnInfo);

    DupAuthManager(auth);
    DestroyAuthManagerList();
    AuthCommonDeinit();
    DeInitAuthReqInfo();
}

/*
 * @tc.name: AUTH_ALLOC_LANE_WLAN_003
 * @tc.desc: AuthOnLaneAllocFail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthLaneTest, AUTH_ALLOC_LANE_WLAN_003, TestSize.Level1)
{
    InitAuthReqInfo();
    ListInit(&g_authClientList);
    ListInit(&g_authServerList);
    AuthCommonInit();
    AuthLaneInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetRemoteStrInfo)
        .WillRepeatedly(DoAll(SetArrayArgument<2>(UUID_TEST, UUID_TEST + UUID_BUF_LEN), Return(SOFTBUS_OK)));

    AuthSessionInfo info;
    SetAuthSessionInfo(&info, CONN_ID, false, AUTH_LINK_TYPE_WIFI);
    EXPECT_TRUE(NewAuthManager(AUTH_SEQ, &info) != nullptr);
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    ASSERT_TRUE(memcpy_s(connInfo.info.ipInfo.ip, IP_LEN, IP_TEST, strlen(IP_TEST)) == EOK);
    AuthManager *auth = FindAuthManagerByConnInfo(&connInfo, false);
    EXPECT_TRUE(auth != nullptr);
    auth->hasAuthPassed[AUTH_LINK_TYPE_WIFI] = true;

    uint32_t authRequestId = AuthGenRequestId();
    int32_t ret = AuthAllocConn(NETWORK_ID, authRequestId, &authConnCb);
    EXPECT_NE(ret, SOFTBUS_OK);

    uint32_t laneReqId = GetLaneManager()->lnnGetLaneHandle(LANE_TYPE_CTRL);
    AuthOnLaneAllocFail(laneReqId, SOFTBUS_INVALID_PARAM);

    DupAuthManager(auth);
    DestroyAuthManagerList();
    AuthCommonDeinit();
    DeInitAuthReqInfo();
}

/*
 * @tc.name: AUTH_ALLOC_LANE_BLE_001
 * @tc.desc: auth alloc lane ble test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthLaneTest, AUTH_ALLOC_LANE_BLE_001, TestSize.Level1)
{
    InitAuthReqInfo();
    ListInit(&g_authClientList);
    ListInit(&g_authServerList);
    AuthCommonInit();
    AuthLaneInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetRemoteStrInfo)
        .WillRepeatedly(DoAll(SetArrayArgument<2>(UUID_TEST, UUID_TEST + UUID_BUF_LEN), Return(SOFTBUS_OK)));

    AuthSessionInfo info;
    SetAuthSessionInfo(&info, CONN_ID, false, AUTH_LINK_TYPE_BLE);
    EXPECT_TRUE(NewAuthManager(AUTH_SEQ, &info) != nullptr);
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_BLE;
    ASSERT_TRUE(memcpy_s(connInfo.info.bleInfo.bleMac, BT_MAC_LEN, BLE_MAC, strlen(BLE_MAC)) == EOK);
    AuthManager *auth = FindAuthManagerByConnInfo(&connInfo, false);
    EXPECT_TRUE(auth != nullptr);
    auth->hasAuthPassed[AUTH_LINK_TYPE_BLE] = true;
    auth->authId = 1;
    auth->lastVerifyTime = 1;

    uint32_t authRequestId = AuthGenRequestId();
    int32_t ret = AuthAllocConn(NETWORK_ID, authRequestId, &authConnCb);
    EXPECT_NE(ret, SOFTBUS_OK);

    uint32_t laneReqId = GetLaneManager()->lnnGetLaneHandle(LANE_TYPE_CTRL);
    LaneConnInfo laneConnInfo;
    (void)memset_s(&laneConnInfo, sizeof(LaneConnInfo), 0, sizeof(LaneConnInfo));
    laneConnInfo.laneId = 1;
    laneConnInfo.type = LANE_BLE;
    AuthOnLaneAllocSuccess(laneReqId, &laneConnInfo);

    DupAuthManager(auth);
    DestroyAuthManagerList();
    AuthCommonDeinit();
    DeInitAuthReqInfo();
}

/*
 * @tc.name: AUTH_ALLOC_LANE_BR_001
 * @tc.desc: auth alloc lane br test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthLaneTest, AUTH_ALLOC_LANE_BR_001, TestSize.Level1)
{
    InitAuthReqInfo();
    ListInit(&g_authClientList);
    ListInit(&g_authServerList);
    AuthCommonInit();
    AuthLaneInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetRemoteStrInfo)
        .WillRepeatedly(DoAll(SetArrayArgument<2>(UUID_TEST, UUID_TEST + UUID_BUF_LEN), Return(SOFTBUS_OK)));

    AuthSessionInfo info;
    SetAuthSessionInfo(&info, CONN_ID, false, AUTH_LINK_TYPE_BR);
    EXPECT_TRUE(NewAuthManager(AUTH_SEQ, &info) != nullptr);
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_BR;
    ASSERT_TRUE(memcpy_s(connInfo.info.brInfo.brMac, BT_MAC_LEN, BR_MAC, strlen(BR_MAC)) == EOK);
    AuthManager *auth = FindAuthManagerByConnInfo(&connInfo, false);
    EXPECT_TRUE(auth != nullptr);
    auth->hasAuthPassed[AUTH_LINK_TYPE_BR] = true;
    auth->authId = 1;
    auth->lastVerifyTime = 1;

    uint32_t authRequestId = AuthGenRequestId();
    int32_t ret = AuthAllocConn(NETWORK_ID, authRequestId, &authConnCb);
    EXPECT_NE(ret, SOFTBUS_OK);

    uint32_t laneReqId = GetLaneManager()->lnnGetLaneHandle(LANE_TYPE_CTRL);
    LaneConnInfo laneConnInfo;
    (void)memset_s(&laneConnInfo, sizeof(LaneConnInfo), 0, sizeof(LaneConnInfo));
    laneConnInfo.laneId = 1;
    laneConnInfo.type = LANE_BR;
    AuthOnLaneAllocSuccess(laneReqId, &laneConnInfo);

    DupAuthManager(auth);
    DestroyAuthManagerList();
    AuthCommonDeinit();
    DeInitAuthReqInfo();
}

/*
 * @tc.name: AUTH_ALLOC_LANE_P2P_001
 * @tc.desc: IsReuseP2p return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthLaneTest, AUTH_ALLOC_LANE_P2P_001, TestSize.Level1)
{
    InitAuthReqInfo();
    ListInit(&g_authClientList);
    ListInit(&g_authServerList);
    AuthCommonInit();
    AuthLaneInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetRemoteStrInfo)
        .WillRepeatedly(DoAll(SetArrayArgument<2>(UUID_TEST, UUID_TEST + UUID_BUF_LEN), Return(SOFTBUS_OK)));

    AuthSessionInfo info;
    SetAuthSessionInfo(&info, CONN_ID, false, AUTH_LINK_TYPE_P2P);
    EXPECT_TRUE(NewAuthManager(AUTH_SEQ, &info) != nullptr);
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_P2P;
    ASSERT_TRUE(memcpy_s(connInfo.info.ipInfo.ip, IP_LEN, IP_TEST, strlen(IP_TEST)) == EOK);
    connInfo.info.ipInfo.port = PORT;
    AuthManager *auth = FindAuthManagerByConnInfo(&connInfo, false);
    EXPECT_TRUE(auth != nullptr);
    auth->hasAuthPassed[AUTH_LINK_TYPE_P2P] = true;
    auth->authId = 1;
    auth->lastVerifyTime = 1;

    uint32_t authRequestId = AuthGenRequestId();
    int32_t ret = AuthAllocConn(NETWORK_ID, authRequestId, &authConnCb);
    EXPECT_NE(ret, SOFTBUS_OK);

    uint32_t laneReqId = GetLaneManager()->lnnGetLaneHandle(LANE_TYPE_CTRL);
    AuthOnLaneAllocFail(laneReqId, SOFTBUS_INVALID_PARAM);

    DupAuthManager(auth);
    DestroyAuthManagerList();
    AuthCommonDeinit();
    DeInitAuthReqInfo();
}

/*
 * @tc.name: AUTH_ALLOC_LANE_ENHANCED_P2P_001
 * @tc.desc: IsReuseP2p return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthLaneTest, AUTH_ALLOC_LANE_ENHANCED_P2P_001, TestSize.Level1)
{
    InitAuthReqInfo();
    ListInit(&g_authClientList);
    ListInit(&g_authServerList);
    AuthCommonInit();
    AuthLaneInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetRemoteStrInfo)
        .WillRepeatedly(DoAll(SetArrayArgument<2>(UUID_TEST, UUID_TEST + UUID_BUF_LEN), Return(SOFTBUS_OK)));

    AuthSessionInfo info;
    SetAuthSessionInfo(&info, CONN_ID, false, AUTH_LINK_TYPE_ENHANCED_P2P);
    EXPECT_TRUE(NewAuthManager(AUTH_SEQ, &info) != nullptr);
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_ENHANCED_P2P;
    ASSERT_TRUE(memcpy_s(connInfo.info.ipInfo.ip, IP_LEN, IP_TEST, strlen(IP_TEST)) == EOK);
    connInfo.info.ipInfo.port = PORT;
    AuthManager *auth = FindAuthManagerByConnInfo(&connInfo, false);
    EXPECT_TRUE(auth != nullptr);
    auth->hasAuthPassed[AUTH_LINK_TYPE_ENHANCED_P2P] = true;
    auth->authId = 1;
    auth->lastVerifyTime = 1;

    uint32_t authRequestId = AuthGenRequestId();
    int32_t ret = AuthAllocConn(NETWORK_ID, authRequestId, &authConnCb);
    EXPECT_NE(ret, SOFTBUS_OK);

    uint32_t laneReqId = GetLaneManager()->lnnGetLaneHandle(LANE_TYPE_CTRL);
    AuthOnLaneAllocFail(laneReqId, SOFTBUS_INVALID_PARAM);

    DelAuthManager(auth, connInfo.type);
    DestroyAuthManagerList();
    AuthCommonDeinit();
    DeInitAuthReqInfo();
}
} // namespace OHOS