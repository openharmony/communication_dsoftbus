/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"
#include <securec.h>

#include "trans_lane_pending_ctl.c"
#include "trans_lane_pending_test_mock.h"
#include "trans_auth_lane_pending_ctl.c"

using namespace testing;
using namespace testing::ext;

#define TEST_CHANNEL_ID 2048
#define TEST_SESSION_ID 8
#define TEST_NEW_SESSION_ID 16
#define TEST_NEW_CHANNEL_ID 1024
#define TEST_LEN 128
#define TEST_LANE_ID 268438006
#define TEST_NEW_LANE_ID 268438007
#define TEST_TOKEN_ID 123456

namespace OHOS {

const char *TEST_IP = "192.168.1.111";
const char *TEST_SESSION_NAME = "ohos.distributedschedule.dms.test";
const char *TEST_NEW_SESSION_NAME = "test.ohos.distributedschedule.dms.test";
const char *TEST_FAST_TRANS_DATA = "testFastTransData";
const char *TEST_DEVICE_ID = "ABCDEF00ABCDEF00ABCDEF00";
const char *TEST_PKG_NAME = "ohos.distributedschedule.dms.test";
const char *PEER_UDID = "123412341234abcdef";
const char *TEST_DSL2_RE_SESSION_NAME = "com.test.security.devicesec";

class TransLanePendingTest : public testing::Test {
public:
    TransLanePendingTest(void)
    {}
    ~TransLanePendingTest(void)
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransLanePendingTest::SetUpTestCase(void) { }

void TransLanePendingTest::TearDownTestCase(void)
{
    TransReqLanePendingDeinit();
    TransAsyncReqLanePendingDeinit();
    TransSocketLaneMgrDeinit();
    TransFreeLanePendingDeinit();
}

static SoftBusList *TestCreateSessionList(void)
{
    SoftBusList *list = reinterpret_cast<SoftBusList *>(SoftBusCalloc(sizeof(SoftBusList)));
    if (list == nullptr) {
        return nullptr;
    }
    SoftBusMutexAttr mutexAttr;
    mutexAttr.type = SOFTBUS_MUTEX_RECURSIVE;
    int32_t ret = SoftBusMutexInit(&list->lock, &mutexAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ListInit(&list->list);
    return list;
}

static SessionParam *TestCreateSessionParam(void)
{
    SessionAttribute *attr = reinterpret_cast<SessionAttribute *>(SoftBusCalloc(sizeof(SessionAttribute)));
    if (attr == nullptr) {
        return nullptr;
    }
    attr->fastTransData = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_FAST_TRANS_DATA));
    attr->fastTransDataSize = TEST_LEN;
    attr->dataType = TYPE_BYTES;
    SessionParam *param = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    if (param == nullptr) {
        SoftBusFree(attr);
        return nullptr;
    }
    param->attr = attr;
    param->sessionName = TEST_SESSION_NAME;
    param->sessionId = TEST_SESSION_ID;
    param->isQosLane = false;
    param->isAsync = false;
    param->peerDeviceId = TEST_DEVICE_ID;
    return param;
}

static SessionParam *TestCreateNewSessionParam(void)
{
    SessionAttribute *attr = reinterpret_cast<SessionAttribute *>(SoftBusCalloc(sizeof(SessionAttribute)));
    if (attr == nullptr) {
        return nullptr;
    }
    attr->fastTransData = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_FAST_TRANS_DATA));
    attr->fastTransDataSize = TEST_LEN;
    attr->dataType = TYPE_BYTES;
    SessionParam *param = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    if (param == nullptr) {
        SoftBusFree(attr);
        return nullptr;
    }
    param->attr = attr;
    param->sessionName = TEST_NEW_SESSION_NAME;
    param->sessionId = TEST_NEW_SESSION_ID;
    param->isQosLane = true;
    param->isAsync = true;
    param->peerDeviceId = TEST_DEVICE_ID;
    return param;
}

static TransReqLaneItem *TestCreateSessionTransReqLaneItem(void)
{
    TransReqLaneItem *reqLane = reinterpret_cast<TransReqLaneItem *>(SoftBusCalloc(sizeof(TransReqLaneItem)));
    if (reqLane == nullptr) {
        return nullptr;
    }
    reqLane->bSucc = true;
    reqLane->isFinished = true;
    reqLane->isNetWorkingChannel = true;
    reqLane->laneHandle = TEST_NEW_LANE_ID;
    reqLane->errCode = 0;
    reqLane->param = *(TestCreateSessionParam());
    return reqLane;
}

static SessionParam *TestCreateSessionParamWithPara(const char *sessionName)
{
    SessionAttribute *attr = reinterpret_cast<SessionAttribute *>(SoftBusCalloc(sizeof(SessionAttribute)));
    if (attr == nullptr) {
        return nullptr;
    }
    attr->fastTransData = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_FAST_TRANS_DATA));
    attr->fastTransDataSize = TEST_LEN;
    attr->dataType = TYPE_BUTT;
    SessionParam *param = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    if (param == nullptr) {
        SoftBusFree(attr);
        return nullptr;
    }
    param->attr = attr;
    param->sessionName = sessionName;
    param->sessionId = TEST_SESSION_ID;
    param->isQosLane = false;
    param->isAsync = false;
    param->peerDeviceId = TEST_DEVICE_ID;
    return param;
}

static uint32_t TestApplyLaneReqId(LaneType type)
{
    (void)type;
    return TEST_LANE_ID;
}

static int32_t TestLnnAllocLane(uint32_t laneHandle, const LaneAllocInfo *allocInfo, const LaneAllocListener *listener)
{
    (void)laneHandle;
    (void)allocInfo;
    (void)listener;
    return SOFTBUS_OK;
}

static int32_t TestLnnAllocLaneFail(uint32_t laneHandle, const LaneAllocInfo *allocInfo,
    const LaneAllocListener *listener)
{
    (void)laneHandle;
    (void)allocInfo;
    (void)listener;
    return SOFTBUS_INVALID_PARAM;
}

static int32_t TestLnnFreeLane(uint32_t laneHandle)
{
    (void)laneHandle;
    return SOFTBUS_OK;
}

static int32_t TestLnnFreeLaneFail(uint32_t laneHandle)
{
    (void)laneHandle;
    return SOFTBUS_INVALID_PARAM;
}

static int32_t TestLnnCancelLaneFail(uint32_t laneHandle)
{
    (void)laneHandle;
    return SOFTBUS_INVALID_PARAM;
}

static int32_t TestLnnCancelLane(uint32_t laneHandle)
{
    (void)laneHandle;
    return SOFTBUS_OK;
}

static LnnLaneManager g_laneManager = {
    .lnnGetLaneHandle = TestApplyLaneReqId,
    .lnnAllocLane = TestLnnAllocLane,
    .lnnFreeLane = TestLnnFreeLane,
    .lnnCancelLane = TestLnnCancelLane,
};

static LnnLaneManager g_laneManagerApplyFail = {
    .lnnGetLaneHandle = nullptr,
    .lnnAllocLane = TestLnnAllocLaneFail,
    .lnnFreeLane = TestLnnFreeLaneFail,
    .lnnCancelLane = TestLnnCancelLaneFail,
};

/*
 * @tc.name: TransReqLanePendingInitTest001
 * @tc.desc: trans req lane pending init returns malloc err when CreateSoftBusList fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransReqLanePendingInitTest001, TestSize.Level1)
{
    SoftBusList *list = TestCreateSessionList();
    EXPECT_NE(list, nullptr);
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, CreateSoftBusList).WillRepeatedly(Return(nullptr));
    int32_t ret = TransReqLanePendingInit();
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);
}

/*
 * @tc.name: TransReqLanePendingInitTest002
 * @tc.desc: trans req lane pending init returns ok when CreateSoftBusList succeeds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransReqLanePendingInitTest002, TestSize.Level1)
{
    SoftBusList *list = TestCreateSessionList();
    EXPECT_NE(list, nullptr);
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, CreateSoftBusList).WillRepeatedly(Return(list));
    int32_t ret = TransReqLanePendingInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransAsyncReqLanePendingInitTest001
 * @tc.desc: trans async req lane pending init returns malloc err when CreateSoftBusList fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAsyncReqLanePendingInitTest001, TestSize.Level1)
{
    SoftBusList *list = TestCreateSessionList();
    EXPECT_NE(list, nullptr);
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, CreateSoftBusList).WillRepeatedly(Return(nullptr));
    int32_t ret = TransAsyncReqLanePendingInit();
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);
}

/*
 * @tc.name: TransAsyncReqLanePendingInitTest002
 * @tc.desc: trans async req lane pending init returns ok when CreateSoftBusList succeeds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAsyncReqLanePendingInitTest002, TestSize.Level1)
{
    SoftBusList *list = TestCreateSessionList();
    EXPECT_NE(list, nullptr);
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, CreateSoftBusList).WillRepeatedly(Return(list));
    int32_t ret = TransAsyncReqLanePendingInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransSocketLaneMgrInitTest001
 * @tc.desc: trans socket lane mgr init returns malloc err when CreateSoftBusList fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransSocketLaneMgrInitTest001, TestSize.Level1)
{
    SoftBusList *list = TestCreateSessionList();
    EXPECT_NE(list, nullptr);
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, CreateSoftBusList).WillRepeatedly(Return(nullptr));
    int32_t ret = TransSocketLaneMgrInit();
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);
}

/*
 * @tc.name: TransSocketLaneMgrInitTest002
 * @tc.desc: trans socket lane mgr init returns ok when CreateSoftBusList succeeds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransSocketLaneMgrInitTest002, TestSize.Level1)
{
    SoftBusList *list = TestCreateSessionList();
    EXPECT_NE(list, nullptr);
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, CreateSoftBusList).WillRepeatedly(Return(list));
    int32_t ret = TransSocketLaneMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransFreeLanePendingInitTest001
 * @tc.desc: trans free lane pending init returns malloc err when CreateSoftBusList fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransFreeLanePendingInitTest001, TestSize.Level1)
{
    SoftBusList *list = TestCreateSessionList();
    EXPECT_NE(list, nullptr);
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, CreateSoftBusList).WillRepeatedly(Return(nullptr));
    int32_t ret = TransFreeLanePendingInit();
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);
}

/*
 * @tc.name: TransFreeLanePendingInitTest002
 * @tc.desc: trans free lane pending init returns ok on fresh init when CreateSoftBusList succeeds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransFreeLanePendingInitTest002, TestSize.Level1)
{
    SoftBusList *list = TestCreateSessionList();
    EXPECT_NE(list, nullptr);
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, CreateSoftBusList).WillRepeatedly(Return(list));
    int32_t ret = TransFreeLanePendingInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransFreeLanePendingInitTest003
 * @tc.desc: trans free lane pending init returns ok when already initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransFreeLanePendingInitTest003, TestSize.Level1)
{
    SoftBusList *list = TestCreateSessionList();
    EXPECT_NE(list, nullptr);
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, CreateSoftBusList).WillRepeatedly(Return(list));
    int32_t ret = TransFreeLanePendingInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransFreeLanePendingInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ClearSessionParamMemoryTest001
 * @tc.desc: clear session param memory frees all allocated fields and sets them to nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, ClearSessionParamMemoryTest001, TestSize.Level1)
{
    SessionParam *param = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(param != nullptr);
    char *sessionName = reinterpret_cast<char *>(SoftBusCalloc(sizeof(char)));
    EXPECT_TRUE(sessionName != nullptr);
    char *peerSessionName = reinterpret_cast<char *>(SoftBusCalloc(sizeof(char)));
    EXPECT_TRUE(peerSessionName != nullptr);
    char *peerDeviceId = reinterpret_cast<char *>(SoftBusCalloc(sizeof(char)));
    EXPECT_TRUE(peerDeviceId != nullptr);
    char *groupId = reinterpret_cast<char *>(SoftBusCalloc(sizeof(char)));
    EXPECT_TRUE(groupId != nullptr);
    SessionAttribute *attr = reinterpret_cast<SessionAttribute *>(SoftBusCalloc(sizeof(SessionAttribute)));
    EXPECT_TRUE(attr != nullptr);
    param->sessionName = sessionName;
    param->peerSessionName = peerSessionName;
    param->peerDeviceId = peerDeviceId;
    param->groupId = groupId;
    param->attr = attr;
    ClearSessionParamMemory(param);
    EXPECT_TRUE(param->sessionName == nullptr);
    EXPECT_TRUE(param->peerSessionName == nullptr);
    EXPECT_TRUE(param->peerDeviceId == nullptr);
    EXPECT_TRUE(param->groupId == nullptr);
    EXPECT_TRUE(param->attr == nullptr);
    SoftBusFree(param);
}

/*
 * @tc.name: TransGetConnectOptByConnInfoTest001
 * @tc.desc: trans get connect opt by conn info returns invalid param when info or connOpt is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransGetConnectOptByConnInfoTest001, TestSize.Level1)
{
    LaneConnInfo info;
    info.type = LANE_BLE_REUSE;
    ConnectOption connOpt;
    int32_t ret = TransGetConnectOptByConnInfo(nullptr, &connOpt);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransGetConnectOptByConnInfo(&info, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransGetConnectOptByConnInfoTest002
 * @tc.desc: trans get connect opt by conn info returns ok for p2p and p2p reuse lane type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransGetConnectOptByConnInfoTest002, TestSize.Level1)
{
    LaneConnInfo info = {};
    ConnectOption connOpt;
    (void)strcpy_s(info.connInfo.p2p.peerIp, IP_LEN, TEST_IP);
    info.type = LANE_P2P;
    int32_t ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.type = LANE_P2P_REUSE;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransGetConnectOptByConnInfoTest003
 * @tc.desc: trans get connect opt by conn info returns ok for wlan lane types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransGetConnectOptByConnInfoTest003, TestSize.Level1)
{
    LaneConnInfo info = {};
    ConnectOption connOpt;
    info.type = LANE_WLAN_2P4G;
    int32_t ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.type = LANE_WLAN_5G;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.type = LANE_ETH;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransGetConnectOptByConnInfoTest004
 * @tc.desc: trans get connect opt by conn info returns ok for bt lane types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransGetConnectOptByConnInfoTest004, TestSize.Level1)
{
    LaneConnInfo info = {};
    ConnectOption connOpt;
    info.type = LANE_BR;
    int32_t ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.type = LANE_BLE;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.type = LANE_COC;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransGetConnectOptByConnInfoTest005
 * @tc.desc: trans get connect opt by conn info returns ok for ble direct and coc direct lane type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransGetConnectOptByConnInfoTest005, TestSize.Level1)
{
    LaneConnInfo info = {};
    ConnectOption connOpt;
    info.type = LANE_BLE_DIRECT;
    int32_t ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.type = LANE_COC_DIRECT;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransGetConnectOptByConnInfoTest006
 * @tc.desc: trans get connect opt by conn info returns ok for hml lane type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransGetConnectOptByConnInfoTest006, TestSize.Level1)
{
    LaneConnInfo info = {};
    info.type = LANE_HML;
    ConnectOption connOpt;
    (void)memset_s(&connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    int32_t ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransGetConnectOptByConnInfoTest007
 * @tc.desc: trans get connect opt by conn info returns failed for unsupported lane type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransGetConnectOptByConnInfoTest007, TestSize.Level1)
{
    LaneConnInfo info = {};
    info.type = LANE_BLE_REUSE;
    ConnectOption connOpt;
    (void)memset_s(&connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    int32_t ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_TRANS_GET_CONN_OPT_FAILED, ret);
}

/*
 * @tc.name: TransGetLaneInfoTest001
 * @tc.desc: trans get lane info returns invalid param when any param is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransGetLaneInfoTest001, TestSize.Level1)
{
    SessionParam param;
    LaneConnInfo connInfo;
    uint32_t laneHandle;
    int32_t ret = TransGetLaneInfo(nullptr, &connInfo, &laneHandle);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransGetLaneInfo(&param, nullptr, &laneHandle);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransGetLaneInfo(&param, &connInfo, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransGetLaneInfoTest002
 * @tc.desc: trans get lane info returns stop bind by cancel when session state is cancelling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransGetLaneInfoTest002, TestSize.Level1)
{
    SessionParam *newParam = TestCreateNewSessionParam();
    ASSERT_TRUE(newParam != nullptr);
    LaneConnInfo connInfo;
    uint32_t laneHandle = TEST_LANE_ID;
    int32_t channelType = CHANNEL_TYPE_PROXY;
    CoreSessionState state = CORE_SESSION_STATE_CANCELLING;
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = TransAddSocketChannelInfo(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID,
        TEST_NEW_CHANNEL_ID, channelType, state);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransGetLaneInfo(newParam, &connInfo, &laneHandle);
    EXPECT_EQ(SOFTBUS_TRANS_STOP_BIND_BY_CANCEL, ret);
    ret = TransDeleteSocketChannelInfoBySession(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(const_cast<SessionAttribute *>(newParam->attr));
    newParam->attr = nullptr;
    SoftBusFree(newParam);
    newParam = nullptr;
}

/*
 * @tc.name: TransGetLaneInfoTest003
 * @tc.desc: trans get lane info returns invalid session type when lane trans type is butt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransGetLaneInfoTest003, TestSize.Level1)
{
    SessionParam *param = TestCreateSessionParam();
    ASSERT_TRUE(param != nullptr);
    LaneConnInfo connInfo;
    uint32_t laneHandle = TEST_LANE_ID;
    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;
    CoreSessionState state = CORE_SESSION_STATE_CHANNEL_OPENED;
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_WIFI_DIRECT_INIT_FAILED));
    EXPECT_CALL(mock, TransGetLaneTransTypeBySession).WillOnce(Return(LANE_T_BUTT));
    int32_t ret = TransAddSocketChannelInfo(TEST_SESSION_NAME, TEST_SESSION_ID,
        TEST_CHANNEL_ID, channelType, state);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransGetLaneInfo(param, &connInfo, &laneHandle);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_SESSION_TYPE, ret);
    ret = TransDeleteSocketChannelInfoBySession(TEST_SESSION_NAME, TEST_SESSION_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(const_cast<SessionAttribute *>(param->attr));
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
}

/*
 * @tc.name: TransGetLaneInfoTest004
 * @tc.desc: trans get lane info returns error when TransGetUidAndPid fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransGetLaneInfoTest004, TestSize.Level1)
{
    SessionParam *param = TestCreateSessionParam();
    ASSERT_TRUE(param != nullptr);
    LaneConnInfo connInfo;
    uint32_t laneHandle = TEST_LANE_ID;
    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;
    CoreSessionState state = CORE_SESSION_STATE_CHANNEL_OPENED;
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, TransGetLaneTransTypeBySession).WillRepeatedly(Return(LANE_T_MSG));
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_WIFI_DIRECT_INIT_FAILED));
    int32_t ret = TransAddSocketChannelInfo(TEST_SESSION_NAME, TEST_SESSION_ID,
        TEST_CHANNEL_ID, channelType, state);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransGetLaneInfo(param, &connInfo, &laneHandle);
    EXPECT_EQ(SOFTBUS_WIFI_DIRECT_INIT_FAILED, ret);
    ret = TransDeleteSocketChannelInfoBySession(TEST_SESSION_NAME, TEST_SESSION_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(const_cast<SessionAttribute *>(param->attr));
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
}

/*
 * @tc.name: TransGetLaneInfoTest005
 * @tc.desc: trans get lane info returns malloc err when cond wait succeeds but calloc fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransGetLaneInfoTest005, TestSize.Level1)
{
    SessionParam *param = TestCreateSessionParam();
    ASSERT_TRUE(param != nullptr);
    LaneConnInfo connInfo;
    uint32_t laneHandle = TEST_LANE_ID;
    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;
    CoreSessionState state = CORE_SESSION_STATE_CHANNEL_OPENED;
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, GetLaneManager).WillRepeatedly(Return(&g_laneManager));
    EXPECT_CALL(mock, LnnRequestLane).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusCondWait).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransAddSocketChannelInfo(TEST_SESSION_NAME, TEST_SESSION_ID,
        TEST_CHANNEL_ID, channelType, state);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransGetLaneInfo(param, &connInfo, &laneHandle);
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);
    ret = TransDeleteSocketChannelInfoBySession(TEST_SESSION_NAME, TEST_SESSION_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(const_cast<SessionAttribute *>(param->attr));
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
}

/*
 * @tc.name: TransAsyncGetLaneInfoByQosTest001
 * @tc.desc: trans async get lane info by qos returns invalid param when any required param is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAsyncGetLaneInfoByQosTest001, TestSize.Level1)
{
    SessionParam param;
    LaneAllocInfo allocInfo;
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    uint32_t laneHandle;
    int32_t ret = TransAsyncGetLaneInfoByQos(nullptr, &allocInfo, &laneHandle, &appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransAsyncGetLaneInfoByQos(&param, nullptr, &laneHandle, &appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransAsyncGetLaneInfoByQos(&param, &allocInfo, nullptr, &appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransAsyncGetLaneInfoByQosTest002
 * @tc.desc: trans async get lane info by qos returns err when GetLaneManager is null or fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAsyncGetLaneInfoByQosTest002, TestSize.Level1)
{
    SessionParam *newParam = TestCreateNewSessionParam();
    ASSERT_TRUE(newParam != nullptr);
    LaneAllocInfo allocInfo;
    uint32_t laneHandle;
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, GetLaneManager).WillOnce(Return(nullptr));
    int32_t ret = TransAsyncGetLaneInfoByQos(newParam, &allocInfo, &laneHandle, &appInfo);
    EXPECT_EQ(SOFTBUS_TRANS_GET_LANE_INFO_ERR, ret);
    EXPECT_CALL(mock, GetLaneManager).WillRepeatedly(Return(&g_laneManagerApplyFail));
    ret = TransAsyncGetLaneInfoByQos(newParam, &allocInfo, &laneHandle, &appInfo);
    EXPECT_EQ(SOFTBUS_TRANS_GET_LANE_INFO_ERR, ret);
    SoftBusFree(const_cast<SessionAttribute *>(newParam->attr));
    newParam->attr = nullptr;
    SoftBusFree(newParam);
    newParam = nullptr;
}

/*
 * @tc.name: TransAsyncGetLaneInfoByQosTest003
 * @tc.desc: trans async get lane info by qos returns no init when async req lane pending list is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAsyncGetLaneInfoByQosTest003, TestSize.Level1)
{
    SessionParam *newParam = TestCreateNewSessionParam();
    ASSERT_TRUE(newParam != nullptr);
    LaneAllocInfo allocInfo;
    uint32_t laneHandle;
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    SoftBusList *tmpList = g_asyncReqLanePendingList;
    g_asyncReqLanePendingList = nullptr;
    EXPECT_CALL(mock, GetLaneManager).WillRepeatedly(Return(&g_laneManager));
    int32_t ret = TransAsyncGetLaneInfoByQos(newParam, &allocInfo, &laneHandle, &appInfo);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    g_asyncReqLanePendingList = tmpList;
    SoftBusFree(const_cast<SessionAttribute *>(newParam->attr));
    newParam->attr = nullptr;
    SoftBusFree(newParam);
    newParam = nullptr;
}

/*
 * @tc.name: TransAsyncGetLaneInfoByQosTest004
 * @tc.desc: trans async get lane info by qos returns stop bind by cancel when session is cancelling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAsyncGetLaneInfoByQosTest004, TestSize.Level1)
{
    SessionParam *newParam = TestCreateNewSessionParam();
    ASSERT_TRUE(newParam != nullptr);
    LaneAllocInfo allocInfo;
    uint32_t laneHandle;
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;
    CoreSessionState state = CORE_SESSION_STATE_CANCELLING;
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = TransAddSocketChannelInfo(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID,
        TEST_NEW_CHANNEL_ID, channelType, state);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransAsyncGetLaneInfoByQos(newParam, &allocInfo, &laneHandle, &appInfo);
    EXPECT_EQ(SOFTBUS_TRANS_GET_LANE_INFO_ERR, ret);
    ret = TransDeleteSocketChannelInfoBySession(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(const_cast<SessionAttribute *>(newParam->attr));
    newParam->attr = nullptr;
    SoftBusFree(newParam);
    newParam = nullptr;
}

/*
 * @tc.name: TransAsyncGetLaneInfoByQosTest005
 * @tc.desc: trans async get lane info by qos returns ok when session state is init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAsyncGetLaneInfoByQosTest005, TestSize.Level1)
{
    SessionParam *newParam = TestCreateNewSessionParam();
    ASSERT_TRUE(newParam != nullptr);
    LaneAllocInfo allocInfo;
    uint32_t laneHandle;
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;
    CoreSessionState state = CORE_SESSION_STATE_INIT;
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = TransAddSocketChannelInfo(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID,
        TEST_NEW_CHANNEL_ID, channelType, state);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransAsyncGetLaneInfoByQos(newParam, &allocInfo, &laneHandle, &appInfo);
    EXPECT_EQ(SOFTBUS_TRANS_GET_LANE_INFO_ERR, ret);
    ret = TransDeleteSocketChannelInfoBySession(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(const_cast<SessionAttribute *>(newParam->attr));
    newParam->attr = nullptr;
    SoftBusFree(newParam);
    newParam = nullptr;
}

/*
 * @tc.name: TransAsyncGetReserveLaneInfoByQosTest001
 * @tc.desc: trans async get reserve lane info by qos returns invalid param when required param is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAsyncGetReserveLaneInfoByQosTest001, TestSize.Level1)
{
    SessionParam param;
    (void)memset_s(&param, sizeof(SessionParam), 0, sizeof(SessionParam));
    LaneAllocInfo allocInfo;
    (void)memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo));
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    uint32_t laneHandle;
    uint64_t laneId = 1;
    int32_t ret = TransAsyncGetReserveLaneInfoByQos(nullptr, &allocInfo, &laneHandle, laneId, &appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransAsyncGetReserveLaneInfoByQos(&param, nullptr, &laneHandle, laneId, &appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransAsyncGetReserveLaneInfoByQos(&param, &allocInfo, &laneHandle, 0, &appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransAsyncGetReserveLaneInfoByQos(&param, &allocInfo, nullptr, laneId, &appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransAsyncGetReserveLaneInfoByQosTest002
 * @tc.desc: trans async get reserve lane info by qos returns err when GetLaneManager is null or fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAsyncGetReserveLaneInfoByQosTest002, TestSize.Level1)
{
    SessionParam *newParam = TestCreateNewSessionParam();
    ASSERT_TRUE(newParam != nullptr);
    LaneAllocInfo allocInfo;
    (void)memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo));
    uint32_t laneHandle;
    uint64_t laneId = 1;
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, GetLaneManager).WillOnce(Return(nullptr));
    int32_t ret = TransAsyncGetReserveLaneInfoByQos(newParam, &allocInfo, &laneHandle, laneId, &appInfo);
    EXPECT_EQ(SOFTBUS_TRANS_GET_LANE_INFO_ERR, ret);
    EXPECT_CALL(mock, GetLaneManager).WillRepeatedly(Return(&g_laneManagerApplyFail));
    ret = TransAsyncGetReserveLaneInfoByQos(newParam, &allocInfo, &laneHandle, laneId, &appInfo);
    EXPECT_EQ(SOFTBUS_TRANS_GET_LANE_INFO_ERR, ret);
    SoftBusFree(const_cast<SessionAttribute *>(newParam->attr));
    newParam->attr = nullptr;
    SoftBusFree(newParam);
    newParam = nullptr;
}

/*
 * @tc.name: TransAsyncGetReserveLaneInfoByQosTest003
 * @tc.desc: trans async get reserve lane info by qos returns no init when async req list is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAsyncGetReserveLaneInfoByQosTest003, TestSize.Level1)
{
    SessionParam *newParam = TestCreateNewSessionParam();
    ASSERT_TRUE(newParam != nullptr);
    LaneAllocInfo allocInfo;
    (void)memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo));
    uint32_t laneHandle;
    uint64_t laneId = 1;
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    SoftBusList *tmpList = g_asyncReqLanePendingList;
    g_asyncReqLanePendingList = nullptr;
    EXPECT_CALL(mock, GetLaneManager).WillRepeatedly(Return(&g_laneManager));
    int32_t ret = TransAsyncGetReserveLaneInfoByQos(newParam, &allocInfo, &laneHandle, laneId, &appInfo);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    g_asyncReqLanePendingList = tmpList;
    SoftBusFree(const_cast<SessionAttribute *>(newParam->attr));
    newParam->attr = nullptr;
    SoftBusFree(newParam);
    newParam = nullptr;
}

/*
 * @tc.name: TransDelStateReserveTest001
 * @tc.desc: trans del state reserve returns invalid param when param or laneConnInfo is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransDelStateReserveTest001, TestSize.Level1)
{
    SessionParam *param = TestCreateNewSessionParam();
    int32_t ret = TransDelStateReserve(nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransDelStateReserve(param, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    SoftBusFree(param);
    param = nullptr;
}

/*
 * @tc.name: BuildTransEventExtraTest001
 * @tc.desc: build trans event extra sets socketName, peerNetworkId, laneId and result from param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, BuildTransEventExtraTest001, TestSize.Level1)
{
    SessionParam *param = TestCreateSessionParam();
    ASSERT_TRUE(param != nullptr);
    TransEventExtra extra;
    extra.linkType = LANE_BLE;
    BuildTransEventExtra(&extra, param, 0, LANE_T_BYTE, 0);
    EXPECT_EQ(extra.socketName, param->sessionName);
    EXPECT_EQ(extra.peerNetworkId, param->peerDeviceId);
    EXPECT_EQ(extra.laneId, 0);
    EXPECT_EQ(extra.result, EVENT_STAGE_RESULT_OK);
    SoftBusFree(const_cast<SessionAttribute *>(param->attr));
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
}

/*
 * @tc.name: BuildTransEventExtraTest002
 * @tc.desc: build trans event extra sets result to failed when ret is not ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, BuildTransEventExtraTest002, TestSize.Level1)
{
    SessionParam *param = TestCreateSessionParam();
    ASSERT_TRUE(param != nullptr);
    TransEventExtra extra;
    extra.linkType = LANE_BLE;
    BuildTransEventExtra(&extra, param, TEST_LANE_ID, LANE_T_BYTE, SOFTBUS_TRANS_GET_LANE_INFO_ERR);
    EXPECT_EQ(extra.result, EVENT_STAGE_RESULT_FAILED);
    EXPECT_EQ(extra.errcode, SOFTBUS_TRANS_GET_LANE_INFO_ERR);
    SoftBusFree(const_cast<SessionAttribute *>(param->attr));
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
}

/*
 * @tc.name: CallbackOpenChannelFailedTest001
 * @tc.desc: callback open channel failed calls ClientIpcOnChannelOpenFailed with session info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, CallbackOpenChannelFailedTest001, TestSize.Level1)
{
    SessionParam *param = TestCreateSessionParam();
    ASSERT_TRUE(param != nullptr);
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    (void)strcpy_s(appInfo.myData.pkgName, sizeof(appInfo.myData.pkgName), TEST_PKG_NAME);
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, ClientIpcOnChannelOpenFailed).WillOnce(Return(SOFTBUS_OK));
    CallbackOpenChannelFailed(param, &appInfo, SOFTBUS_TRANS_GET_LANE_INFO_ERR);
    SoftBusFree(const_cast<SessionAttribute *>(param->attr));
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
}

/*
 * @tc.name: CopyAsyncReqItemSessionParamIdsTest001
 * @tc.desc: copy async req item session param ids returns ok with valid params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, CopyAsyncReqItemSessionParamIdsTest001, TestSize.Level1)
{
    SessionParam *param = TestCreateSessionParam();
    ASSERT_TRUE(param != nullptr);
    SessionParam target;
    int32_t ret = CopyAsyncReqItemSessionParamIds(param, &target);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(const_cast<SessionAttribute *>(param->attr));
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
}

/*
 * @tc.name: CopyAsyncReqItemSessionParamIdsTest002
 * @tc.desc: copy async req item session param ids returns invalid param when source or target is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, CopyAsyncReqItemSessionParamIdsTest002, TestSize.Level1)
{
    SessionParam *param = TestCreateSessionParam();
    ASSERT_TRUE(param != nullptr);
    SessionParam target;
    int32_t ret = CopyAsyncReqItemSessionParamIds(nullptr, &target);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = CopyAsyncReqItemSessionParamIds(param, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    SoftBusFree(const_cast<SessionAttribute *>(param->attr));
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
}

/*
 * @tc.name: TransGetLaneReqItemParamByLaneHandleTest001
 * @tc.desc: trans get lane req item param by lane handle returns invalid param when reqLane is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransGetLaneReqItemParamByLaneHandleTest001, TestSize.Level1)
{
    int32_t ret = TransGetLaneReqItemParamByLaneHandle(0, nullptr, nullptr, nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransGetLaneReqItemParamByLaneHandleTest002
 * @tc.desc: trans get lane req item param returns no init when async req lane pending list is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransGetLaneReqItemParamByLaneHandleTest002, TestSize.Level1)
{
    TransReqLaneItem *reqLane = TestCreateSessionTransReqLaneItem();
    ASSERT_TRUE(reqLane != nullptr);
    SoftBusList *tmpList = g_asyncReqLanePendingList;
    g_asyncReqLanePendingList = nullptr;
    int32_t ret = TransGetLaneReqItemParamByLaneHandle(0, reqLane, nullptr, nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    g_asyncReqLanePendingList = tmpList;
    SoftBusFree(reqLane);
}

/*
 * @tc.name: TransGetLaneReqItemParamByLaneHandleTest003
 * @tc.desc: trans get lane req item param returns node not found when lane handle not in list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransGetLaneReqItemParamByLaneHandleTest003, TestSize.Level1)
{
    SessionParam *newParam = TestCreateNewSessionParam();
    ASSERT_TRUE(newParam != nullptr);
    TransReqLaneItem *reqLane = TestCreateSessionTransReqLaneItem();
    ASSERT_TRUE(reqLane != nullptr);
    uint64_t callingTokenId;
    uint64_t firstTokenId;
    int64_t timeStart;
    int32_t ret = TransGetLaneReqItemParamByLaneHandle(0, reqLane, &callingTokenId, &firstTokenId, &timeStart);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
    SoftBusFree(reqLane);
    SoftBusFree(newParam);
}

/*
 * @tc.name: TransGetLaneReqItemParamByLaneHandleTest004
 * @tc.desc: trans get lane req item param returns ok when lane handle exists in pending list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransGetLaneReqItemParamByLaneHandleTest004, TestSize.Level1)
{
    SessionParam *newParam = TestCreateNewSessionParam();
    ASSERT_TRUE(newParam != nullptr);
    TransReqLaneItem *reqLane = TestCreateSessionTransReqLaneItem();
    ASSERT_TRUE(reqLane != nullptr);
    uint64_t callingTokenId;
    uint64_t firstTokenId;
    int64_t timeStart;
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    int32_t ret = TransAddAsyncLaneReqFromPendingList(TEST_NEW_LANE_ID, newParam, &appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransGetLaneReqItemParamByLaneHandle(TEST_NEW_LANE_ID, reqLane, &callingTokenId, &firstTokenId, &timeStart);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(reqLane);
    SoftBusFree(newParam);
    ret = TransDelLaneReqFromPendingList(TEST_NEW_LANE_ID, true);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransAsyncOpenChannelProcTest001
 * @tc.desc: trans async open channel proc goes to err exit when TransOpenChannelProc fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAsyncOpenChannelProcTest001, TestSize.Level1)
{
    SessionParam *param = TestCreateSessionParam();
    ASSERT_TRUE(param != nullptr);
    AppInfo appInfo;
    TransEventExtra extra;
    extra.peerUdid = PEER_UDID;
    LaneConnInfo connInnerInfo;
    connInnerInfo.type = LANE_WLAN_2P4G;
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, TransOpenChannelProc).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    TransAsyncOpenChannelProc(TEST_LANE_ID, param, &appInfo, &extra, &connInnerInfo);
    SoftBusFree(const_cast<SessionAttribute *>(param->attr));
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
}

/*
 * @tc.name: TransAsyncOpenChannelProcTest002
 * @tc.desc: trans async open channel proc goes to err exit when ClientIpcSetChannelInfo fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAsyncOpenChannelProcTest002, TestSize.Level1)
{
    SessionParam *param = TestCreateSessionParam();
    ASSERT_TRUE(param != nullptr);
    AppInfo appInfo;
    TransEventExtra extra;
    extra.peerUdid = PEER_UDID;
    LaneConnInfo connInnerInfo;
    connInnerInfo.type = LANE_WLAN_2P4G;
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, TransOpenChannelProc).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ClientIpcSetChannelInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    TransAsyncOpenChannelProc(TEST_LANE_ID, param, &appInfo, &extra, &connInnerInfo);
    SoftBusFree(const_cast<SessionAttribute *>(param->attr));
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
}

/*
 * @tc.name: TransAsyncOpenChannelProcTest003
 * @tc.desc: trans async open channel proc goes to err exit when TransLaneMgrAddLane fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAsyncOpenChannelProcTest003, TestSize.Level1)
{
    SessionParam *param = TestCreateSessionParam();
    ASSERT_TRUE(param != nullptr);
    AppInfo appInfo;
    TransEventExtra extra;
    extra.peerUdid = PEER_UDID;
    LaneConnInfo connInnerInfo;
    connInnerInfo.type = LANE_WLAN_2P4G;
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, TransOpenChannelProc).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ClientIpcSetChannelInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransLaneMgrAddLane).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    TransAsyncOpenChannelProc(TEST_LANE_ID, param, &appInfo, &extra, &connInnerInfo);
    SoftBusFree(const_cast<SessionAttribute *>(param->attr));
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
}

/*
 * @tc.name: TransAsyncOpenChannelProcTest004
 * @tc.desc: trans async open channel proc succeeds when all steps return ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAsyncOpenChannelProcTest004, TestSize.Level1)
{
    SessionParam *param = TestCreateSessionParam();
    ASSERT_TRUE(param != nullptr);
    AppInfo appInfo;
    TransEventExtra extra;
    extra.peerUdid = PEER_UDID;
    LaneConnInfo connInnerInfo;
    connInnerInfo.type = LANE_WLAN_2P4G;
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, TransOpenChannelProc).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ClientIpcSetChannelInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransLaneMgrAddLane).WillRepeatedly(Return(SOFTBUS_OK));
    TransAsyncOpenChannelProc(TEST_LANE_ID, param, &appInfo, &extra, &connInnerInfo);
    SoftBusFree(const_cast<SessionAttribute *>(param->attr));
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
}

/*
 * @tc.name: TransAsyncSetFirstTokenInfoTest001
 * @tc.desc: trans async set first token info sets firstTokenId from callingTokenId when not set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAsyncSetFirstTokenInfoTest001, TestSize.Level1)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo.callingTokenId = TEST_TOKEN_ID;
    TransEventExtra extra;
    uint64_t firstTokenId = TOKENID_NOT_SET;
    TransAsyncSetFirstTokenInfo(firstTokenId, &appInfo, &extra);
    EXPECT_EQ(extra.firstTokenId, appInfo.callingTokenId);
}

/*
 * @tc.name: CheckSocketChannelStateTest001
 * @tc.desc: check socket channel state returns ok when session state is init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, CheckSocketChannelStateTest001, TestSize.Level1)
{
    TransEventExtra extra;
    extra.linkType = LANE_BR;
    CoreSessionState state = CORE_SESSION_STATE_INIT;
    int32_t channelType = CHANNEL_TYPE_PROXY;
    uint32_t laneHandle = TEST_NEW_LANE_ID;
    SessionParam *newParam = TestCreateNewSessionParam();
    ASSERT_TRUE(newParam != nullptr);
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = TransAddSocketChannelInfo(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID,
        TEST_NEW_CHANNEL_ID, channelType, state);
    EXPECT_EQ(SOFTBUS_OK, ret);
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    ret = TransAddAsyncLaneReqFromPendingList(TEST_NEW_LANE_ID, newParam, &appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = CheckSocketChannelState(laneHandle, newParam, &extra, LANE_T_BYTE);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(newParam);
    newParam = nullptr;
}

/*
 * @tc.name: CheckSocketChannelStateTest002
 * @tc.desc: check socket channel state returns stop bind by cancel when session state is cancelling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, CheckSocketChannelStateTest002, TestSize.Level1)
{
    TransEventExtra extra;
    extra.linkType = LANE_BR;
    int32_t channelType = CHANNEL_TYPE_PROXY;
    uint32_t laneHandle = TEST_NEW_LANE_ID;
    SessionParam *newParam = TestCreateNewSessionParam();
    ASSERT_TRUE(newParam != nullptr);
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = TransAddSocketChannelInfo(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID,
        TEST_NEW_CHANNEL_ID, channelType, CORE_SESSION_STATE_INIT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    ret = TransAddAsyncLaneReqFromPendingList(TEST_NEW_LANE_ID, newParam, &appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransSetSocketChannelStateBySession(newParam->sessionName, newParam->sessionId,
        CORE_SESSION_STATE_CANCELLING);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = CheckSocketChannelState(laneHandle, newParam, &extra, LANE_T_BYTE);
    EXPECT_EQ(SOFTBUS_TRANS_STOP_BIND_BY_CANCEL, ret);
    SoftBusFree(newParam);
    newParam = nullptr;
}

/*
 * @tc.name: TransOnAsyncLaneSuccessTest001
 * @tc.desc: trans on async lane success handles lane handle not found without crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransOnAsyncLaneSuccessTest001, TestSize.Level1)
{
    uint32_t laneHandle = 0;
    LaneConnInfo connInfo;
    connInfo.type = LANE_BR;
    EXPECT_NO_FATAL_FAILURE(TransOnAsyncLaneSuccess(laneHandle, &connInfo));
}

/*
 * @tc.name: TransOnAsyncLaneSuccessTest002
 * @tc.desc: trans on async lane success calls async open channel proc when lane req item found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransOnAsyncLaneSuccessTest002, TestSize.Level1)
{
    uint32_t laneHandle = TEST_NEW_LANE_ID;
    LaneConnInfo connInfo;
    connInfo.type = LANE_BR;
    CoreSessionState state = CORE_SESSION_STATE_INIT;
    int32_t channelType = CHANNEL_TYPE_PROXY;
    SessionParam *newParam = TestCreateNewSessionParam();
    ASSERT_TRUE(newParam != nullptr);
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransGetPkgNameBySessionName).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = TransAddSocketChannelInfo(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID,
        TEST_NEW_CHANNEL_ID, channelType, state);
    EXPECT_EQ(SOFTBUS_OK, ret);
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    ret = TransAddAsyncLaneReqFromPendingList(laneHandle, newParam, &appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransOnAsyncLaneSuccess(laneHandle, &connInfo);
    TransDeleteSocketChannelInfoBySession(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID);
    SoftBusFree(newParam);
    newParam = nullptr;
}

/*
 * @tc.name: TransOnAsyncLaneFailTest001
 * @tc.desc: trans on async lane fail handles lane handle not found without crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransOnAsyncLaneFailTest001, TestSize.Level1)
{
    uint32_t laneHandle = 0;
    int32_t reason = SOFTBUS_CONN_BR_INVALID_ADDRESS_ERR;
    EXPECT_NO_FATAL_FAILURE(TransOnAsyncLaneFail(laneHandle, reason));
}

/*
 * @tc.name: TransOnAsyncLaneFailTest002
 * @tc.desc: trans on async lane fail calls callback open channel failed when lane req item found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransOnAsyncLaneFailTest002, TestSize.Level1)
{
    uint32_t laneHandle = TEST_LANE_ID;
    int32_t reason = SOFTBUS_CONN_BR_INVALID_ADDRESS_ERR;
    CoreSessionState state = CORE_SESSION_STATE_INIT;
    int32_t channelType = CHANNEL_TYPE_PROXY;
    SessionParam *newParam = TestCreateNewSessionParam();
    ASSERT_TRUE(newParam != nullptr);
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    int32_t ret = TransAddAsyncLaneReqFromPendingList(TEST_NEW_LANE_ID, newParam, &appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransAddSocketChannelInfo(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID,
        TEST_NEW_CHANNEL_ID, channelType, state);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransOnAsyncLaneFail(laneHandle, reason);
    SoftBusFree(newParam);
    newParam = nullptr;
}

/*
 * @tc.name: TransOnAsyncLaneReserveFailTest001
 * @tc.desc: trans on async lane reserve fail handles lane handle not found without crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransOnAsyncLaneReserveFailTest001, TestSize.Level1)
{
    uint32_t laneHandle = 0;
    int32_t reason = SOFTBUS_CONN_BR_INVALID_ADDRESS_ERR;
    EXPECT_NO_FATAL_FAILURE(TransOnAsyncLaneReserveFail(laneHandle, reason));
}

/*
 * @tc.name: TransOnAsyncLaneReserveFailTest002
 * @tc.desc: trans on async lane reserve fail clears session param when lane req item found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransOnAsyncLaneReserveFailTest002, TestSize.Level1)
{
    uint32_t laneHandle = TEST_LANE_ID;
    int32_t reason = SOFTBUS_CONN_BR_INVALID_ADDRESS_ERR;
    CoreSessionState state = CORE_SESSION_STATE_INIT;
    int32_t channelType = CHANNEL_TYPE_PROXY;
    SessionParam *newParam = TestCreateNewSessionParam();
    ASSERT_TRUE(newParam != nullptr);
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    int32_t ret = TransAddAsyncLaneReqFromPendingList(TEST_NEW_LANE_ID, newParam, &appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransAddSocketChannelInfo(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID,
        TEST_NEW_CHANNEL_ID, channelType, state);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransOnAsyncLaneReserveFail(laneHandle, reason);
    SoftBusFree(const_cast<SessionAttribute *>(newParam->attr));
    newParam->attr = nullptr;
    SoftBusFree(newParam);
    newParam = nullptr;
}

/*
 * @tc.name: TransAuthWithParaAddLaneReqToListTest001
 * @tc.desc: trans auth with para add lane req to list returns no init when list is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAuthWithParaAddLaneReqToListTest001, TestSize.Level1)
{
    g_authWithParaAsyncReqLaneList = nullptr;
    uint32_t laneReqId = TEST_LANE_ID;
    bool accountInfo = true;
    int32_t channelId = TEST_CHANNEL_ID;
    int32_t ret = TransAuthWithParaAddLaneReqToList(laneReqId, nullptr, accountInfo, channelId);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
 * @tc.name: TransAuthWithParaAddLaneReqToListTest002
 * @tc.desc: trans auth with para add lane req to list returns invalid param when sessionName is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAuthWithParaAddLaneReqToListTest002, TestSize.Level1)
{
    g_authWithParaAsyncReqLaneList = TestCreateSessionList();
    ASSERT_TRUE(g_authWithParaAsyncReqLaneList != nullptr);
    uint32_t laneReqId = TEST_LANE_ID;
    bool accountInfo = true;
    int32_t channelId = TEST_CHANNEL_ID;
    int32_t ret = TransAuthWithParaAddLaneReqToList(laneReqId, nullptr, accountInfo, channelId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    DestroySoftBusList(g_authWithParaAsyncReqLaneList);
    g_authWithParaAsyncReqLaneList = nullptr;
}

/*
 * @tc.name: TransAuthWithParaAddLaneReqToListTest003
 * @tc.desc: trans auth with para add lane req to list returns ok with valid params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAuthWithParaAddLaneReqToListTest003, TestSize.Level1)
{
    g_authWithParaAsyncReqLaneList = TestCreateSessionList();
    ASSERT_TRUE(g_authWithParaAsyncReqLaneList != nullptr);
    uint32_t laneReqId = TEST_LANE_ID;
    const char *sessionName = TEST_SESSION_NAME;
    bool accountInfo = true;
    int32_t channelId = TEST_CHANNEL_ID;
    int32_t ret = TransAuthWithParaAddLaneReqToList(laneReqId, sessionName, accountInfo, channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    DestroySoftBusList(g_authWithParaAsyncReqLaneList);
    g_authWithParaAsyncReqLaneList = nullptr;
}

/*
 * @tc.name: TransAuthWithParaDelLaneReqByIdTest001
 * @tc.desc: trans auth with para del lane req by id returns no init when list is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAuthWithParaDelLaneReqByIdTest001, TestSize.Level1)
{
    uint32_t laneReqId = TEST_LANE_ID;
    int32_t ret = TransAuthWithParaDelLaneReqById(laneReqId);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
 * @tc.name: TransAuthWithParaDelLaneReqByIdTest002
 * @tc.desc: trans auth with para del lane req by id returns not ok when lane req not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAuthWithParaDelLaneReqByIdTest002, TestSize.Level1)
{
    g_authWithParaAsyncReqLaneList = TestCreateSessionList();
    ASSERT_TRUE(g_authWithParaAsyncReqLaneList != nullptr);
    uint32_t laneReqId = TEST_LANE_ID;
    int32_t ret = TransAuthWithParaDelLaneReqById(laneReqId);
    EXPECT_NE(SOFTBUS_OK, ret);
    DestroySoftBusList(g_authWithParaAsyncReqLaneList);
    g_authWithParaAsyncReqLaneList = nullptr;
}

/*
 * @tc.name: TransAuthWithParaDelLaneReqByIdTest003
 * @tc.desc: trans auth with para del lane req by id returns ok when lane req exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAuthWithParaDelLaneReqByIdTest003, TestSize.Level1)
{
    g_authWithParaAsyncReqLaneList = TestCreateSessionList();
    ASSERT_TRUE(g_authWithParaAsyncReqLaneList != nullptr);
    uint32_t laneReqId = TEST_LANE_ID;
    const char *sessionName = TEST_SESSION_NAME;
    bool accountInfo = false;
    int32_t channelId = TEST_CHANNEL_ID;
    int32_t ret = TransAuthWithParaAddLaneReqToList(laneReqId, sessionName, accountInfo, channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransAuthWithParaDelLaneReqById(laneReqId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    DestroySoftBusList(g_authWithParaAsyncReqLaneList);
    g_authWithParaAsyncReqLaneList = nullptr;
}

/*
 * @tc.name: TransUpdateAuthWithParaLaneConnInfoTest001
 * @tc.desc: trans update auth with para lane conn info returns invalid param when param is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransUpdateAuthWithParaLaneConnInfoTest001, TestSize.Level1)
{
    uint32_t laneReqId = TEST_LANE_ID;
    LaneConnInfo connInfo;
    int32_t ret = TransUpdateAuthWithParaLaneConnInfo(laneReqId, true, &connInfo, SOFTBUS_OK);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransUpdateAuthWithParaLaneConnInfoTest002
 * @tc.desc: trans update auth with para lane conn info returns node not found when req not in list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransUpdateAuthWithParaLaneConnInfoTest002, TestSize.Level1)
{
    g_authWithParaAsyncReqLaneList = TestCreateSessionList();
    ASSERT_TRUE(g_authWithParaAsyncReqLaneList != nullptr);
    uint32_t laneReqId = TEST_LANE_ID;
    LaneConnInfo connInfo;
    int32_t ret = TransUpdateAuthWithParaLaneConnInfo(laneReqId, true, &connInfo, SOFTBUS_OK);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
    DestroySoftBusList(g_authWithParaAsyncReqLaneList);
    g_authWithParaAsyncReqLaneList = nullptr;
}

/*
 * @tc.name: TransUpdateAuthWithParaLaneConnInfoTest003
 * @tc.desc: trans update auth with para lane conn info returns ok when req exists in list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransUpdateAuthWithParaLaneConnInfoTest003, TestSize.Level1)
{
    g_authWithParaAsyncReqLaneList = TestCreateSessionList();
    ASSERT_TRUE(g_authWithParaAsyncReqLaneList != nullptr);
    uint32_t laneReqId = TEST_LANE_ID;
    const char *sessionName = TEST_SESSION_NAME;
    bool accountInfo = false;
    int32_t channelId = TEST_CHANNEL_ID;
    LaneConnInfo connInfo;
    int32_t ret = TransAuthWithParaAddLaneReqToList(laneReqId, sessionName, accountInfo, channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransUpdateAuthWithParaLaneConnInfo(laneReqId, true, &connInfo, SOFTBUS_OK);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransAuthWithParaDelLaneReqById(laneReqId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    DestroySoftBusList(g_authWithParaAsyncReqLaneList);
    g_authWithParaAsyncReqLaneList = nullptr;
}

/*
 * @tc.name: TransAuthWithParaGetLaneReqByLaneReqIdTest001
 * @tc.desc: trans auth with para get lane req returns invalid param when paraNode is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAuthWithParaGetLaneReqByLaneReqIdTest001, TestSize.Level1)
{
    uint32_t laneReqId = TEST_LANE_ID;
    int32_t ret = TransAuthWithParaGetLaneReqByLaneReqId(laneReqId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransAuthWithParaGetLaneReqByLaneReqIdTest002
 * @tc.desc: trans auth with para get lane req returns no init when list is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAuthWithParaGetLaneReqByLaneReqIdTest002, TestSize.Level1)
{
    uint32_t laneReqId = TEST_LANE_ID;
    TransAuthWithParaNode paraNode;
    int32_t ret = TransAuthWithParaGetLaneReqByLaneReqId(laneReqId, &paraNode);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
 * @tc.name: TransAuthWithParaGetLaneReqByLaneReqIdTest003
 * @tc.desc: trans auth with para get lane req returns not ok when req not found in list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAuthWithParaGetLaneReqByLaneReqIdTest003, TestSize.Level1)
{
    g_authWithParaAsyncReqLaneList = TestCreateSessionList();
    ASSERT_TRUE(g_authWithParaAsyncReqLaneList != nullptr);
    uint32_t laneReqId = TEST_LANE_ID;
    TransAuthWithParaNode paraNode;
    int32_t ret = TransAuthWithParaGetLaneReqByLaneReqId(laneReqId, &paraNode);
    EXPECT_NE(SOFTBUS_OK, ret);
    DestroySoftBusList(g_authWithParaAsyncReqLaneList);
    g_authWithParaAsyncReqLaneList = nullptr;
}

/*
 * @tc.name: TransAuthWithParaGetLaneReqByLaneReqIdTest004
 * @tc.desc: trans auth with para get lane req returns ok when req exists in list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAuthWithParaGetLaneReqByLaneReqIdTest004, TestSize.Level1)
{
    g_authWithParaAsyncReqLaneList = TestCreateSessionList();
    ASSERT_TRUE(g_authWithParaAsyncReqLaneList != nullptr);
    uint32_t laneReqId = TEST_LANE_ID;
    const char *sessionName = TEST_SESSION_NAME;
    bool accountInfo = false;
    int32_t channelId = TEST_CHANNEL_ID;
    TransAuthWithParaNode paraNode;
    int32_t ret = TransAuthWithParaAddLaneReqToList(laneReqId, sessionName, accountInfo, channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransAuthWithParaGetLaneReqByLaneReqId(laneReqId, &paraNode);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransAuthWithParaDelLaneReqById(laneReqId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    DestroySoftBusList(g_authWithParaAsyncReqLaneList);
    g_authWithParaAsyncReqLaneList = nullptr;
}

/*
 * @tc.name: TransWaitingFreeCallbackTest001
 * @tc.desc: trans waiting free callback returns not find when lane handle not in list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransWaitingFreeCallbackTest001, TestSize.Level1)
{
    uint32_t laneReqId = TEST_LANE_ID;
    int32_t ret = TransWaitingFreeCallback(laneReqId);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}

/*
 * @tc.name: TransWaitingFreeCallbackTest002
 * @tc.desc: trans waiting free callback returns error when cond wait fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransWaitingFreeCallbackTest002, TestSize.Level1)
{
    uint32_t laneReqId = TEST_LANE_ID;
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, SoftBusCondWait).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransAddFreeLaneToPending(laneReqId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransWaitingFreeCallback(laneReqId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransDelLaneFreeFromPending(laneReqId, false);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransWaitingFreeCallbackTest003
 * @tc.desc: trans waiting free callback returns ok when cond wait succeeds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransWaitingFreeCallbackTest003, TestSize.Level1)
{
    uint32_t laneReqId = TEST_LANE_ID;
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, SoftBusCondWait).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransAddFreeLaneToPending(laneReqId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransWaitingFreeCallback(laneReqId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransDelLaneFreeFromPending(laneReqId, false);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransWaitingFreeLaneTest001
 * @tc.desc: trans waiting free lane returns no init when free lane pending list is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransWaitingFreeLaneTest001, TestSize.Level1)
{
    uint32_t laneReqId = TEST_LANE_ID;
    SoftBusList *tmpList = g_freeLanePendingList;
    g_freeLanePendingList = nullptr;
    int32_t ret = TransWaitingFreeLane(laneReqId);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    g_freeLanePendingList = tmpList;
}

/*
 * @tc.name: TransWaitingFreeLaneTest002
 * @tc.desc: trans waiting free lane returns err when GetLaneManager is null or fails to free
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransWaitingFreeLaneTest002, TestSize.Level1)
{
    uint32_t laneReqId = TEST_LANE_ID;
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, GetLaneManager).WillOnce(Return(nullptr));
    int32_t ret = TransWaitingFreeLane(laneReqId);
    EXPECT_EQ(SOFTBUS_TRANS_GET_LANE_INFO_ERR, ret);
    ret = TransDelLaneFreeFromPending(laneReqId, false);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(mock, GetLaneManager).WillRepeatedly(Return(&g_laneManagerApplyFail));
    ret = TransWaitingFreeLane(laneReqId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransWaitingFreeLaneTest003
 * @tc.desc: trans waiting free lane returns lane is existed when lane already in pending list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransWaitingFreeLaneTest003, TestSize.Level1)
{
    uint32_t laneReqId = TEST_LANE_ID;
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, GetLaneManager).WillRepeatedly(Return(&g_laneManager));
    EXPECT_CALL(mock, SoftBusCondWait).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = TransAddFreeLaneToPending(laneReqId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransWaitingFreeLane(laneReqId);
    EXPECT_EQ(SOFTBUS_TRANS_LANE_IS_EXISTED, ret);
    ret = TransDelLaneFreeFromPending(laneReqId, false);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransFreeLaneByLaneHandleTest001
 * @tc.desc: trans free lane by lane handle returns err when GetLaneManager is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransFreeLaneByLaneHandleTest001, TestSize.Level1)
{
    uint32_t laneReqId = TEST_LANE_ID;
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, GetLaneManager).WillOnce(Return(nullptr));
    int32_t ret = TransFreeLaneByLaneHandle(laneReqId, true);
    EXPECT_EQ(SOFTBUS_TRANS_GET_LANE_INFO_ERR, ret);
}

/*
 * @tc.name: TransFreeLaneByLaneHandleTest002
 * @tc.desc: trans free lane by lane handle returns ok when async free succeeds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransFreeLaneByLaneHandleTest002, TestSize.Level1)
{
    uint32_t laneReqId = TEST_LANE_ID;
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, GetLaneManager).WillRepeatedly(Return(&g_laneManager));
    int32_t ret = TransFreeLaneByLaneHandle(laneReqId, true);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransFreeLaneByLaneHandleTest003
 * @tc.desc: trans free lane by lane handle returns lane is existed when lane already pending
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransFreeLaneByLaneHandleTest003, TestSize.Level1)
{
    uint32_t laneReqId = TEST_LANE_ID;
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, GetLaneManager).WillRepeatedly(Return(&g_laneManager));
    int32_t ret = TransAddFreeLaneToPending(laneReqId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransFreeLaneByLaneHandle(laneReqId, false);
    EXPECT_EQ(SOFTBUS_TRANS_LANE_IS_EXISTED, ret);
    ret = TransDelLaneFreeFromPending(laneReqId, false);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransUpdateFreeLaneStatusTest001
 * @tc.desc: trans update free lane status returns no init when free lane pending list is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransUpdateFreeLaneStatusTest001, TestSize.Level1)
{
    uint32_t laneHandle = TEST_LANE_ID;
    SoftBusList *tmpList = g_freeLanePendingList;
    g_freeLanePendingList = nullptr;
    int32_t ret = TransUpdateFreeLaneStatus(laneHandle, false, false, SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    g_freeLanePendingList = tmpList;
}

/*
 * @tc.name: TransUpdateFreeLaneStatusTest002
 * @tc.desc: trans update free lane status returns node not found when lane handle not in list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransUpdateFreeLaneStatusTest002, TestSize.Level1)
{
    uint32_t laneHandle = TEST_LANE_ID;
    int32_t ret = TransUpdateFreeLaneStatus(laneHandle, false, false, SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
}

/*
 * @tc.name: TransUpdateFreeLaneStatusTest003
 * @tc.desc: trans update free lane status returns ok when lane handle exists in list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransUpdateFreeLaneStatusTest003, TestSize.Level1)
{
    uint32_t laneHandle = TEST_LANE_ID;
    int32_t ret = TransAddFreeLaneToPending(laneHandle);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransUpdateFreeLaneStatus(laneHandle, false, false, SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransDelLaneFreeFromPending(laneHandle, false);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransOnLaneFreeSuccessTest001
 * @tc.desc: trans on lane free success handles lane handle not in list without crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransOnLaneFreeSuccessTest001, TestSize.Level1)
{
    uint32_t laneHandle = TEST_LANE_ID;
    EXPECT_NO_FATAL_FAILURE(TransOnLaneFreeSuccess(laneHandle));
}

/*
 * @tc.name: TransOnLaneFreeSuccessTest002
 * @tc.desc: trans on lane free success updates free lane status when lane handle in list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransOnLaneFreeSuccessTest002, TestSize.Level1)
{
    uint32_t laneHandle = TEST_LANE_ID;
    int32_t ret = TransAddFreeLaneToPending(laneHandle);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransOnLaneFreeSuccess(laneHandle);
    ret = TransDelLaneFreeFromPending(laneHandle, false);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: IsShareSessionTest001
 * @tc.desc: is share session returns false for normal session and true for ishare session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, IsShareSessionTest001, TestSize.Level1)
{
    const char *sessionName = TEST_SESSION_NAME;
    bool ret = IsShareSession(sessionName);
    EXPECT_EQ(ret, false);
    ret = IsShareSession(SESSION_NAME_ISHARE);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: IsDslSessionTest001
 * @tc.desc: is dsl session returns false for null and normal session, true for dsl session names
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, IsDslSessionTest001, TestSize.Level1)
{
    bool ret = IsDslSession(nullptr);
    EXPECT_EQ(ret, false);
    ret = IsDslSession(SESSION_NAME_DSL);
    EXPECT_EQ(ret, true);
    ret = IsDslSession(TEST_DSL2_RE_SESSION_NAME);
    EXPECT_EQ(ret, true);
    const char *sessionName = TEST_SESSION_NAME;
    ret = IsDslSession(sessionName);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: PeerDeviceIsLegacyOsTest001
 * @tc.desc: peer device is legacy os returns false when LnnGetDLAuthCapacity fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, PeerDeviceIsLegacyOsTest001, TestSize.Level1)
{
    const char *peerNetworkId = TEST_DEVICE_ID;
    const char *sessionName = TEST_SESSION_NAME;
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, LnnGetDLAuthCapacity).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    bool ret = PeerDeviceIsLegacyOs(peerNetworkId, sessionName);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: PeerDeviceIsLegacyOsTest002
 * @tc.desc: peer device is legacy os returns false when auth capacity is not zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, PeerDeviceIsLegacyOsTest002, TestSize.Level1)
{
    const char *peerNetworkId = TEST_DEVICE_ID;
    const char *sessionName = TEST_SESSION_NAME;
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, LnnGetDLAuthCapacity).WillRepeatedly(Return(SOFTBUS_OK));
    bool ret = PeerDeviceIsLegacyOs(peerNetworkId, sessionName);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: PeerDeviceIsLegacyOsTest003
 * @tc.desc: peer device is legacy os returns true when auth capacity is zero and session is dbd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, PeerDeviceIsLegacyOsTest003, TestSize.Level1)
{
    const char *peerNetworkId = TEST_DEVICE_ID;
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, LnnGetDLAuthCapacity).WillRepeatedly(Return(SOFTBUS_OK));
    bool ret = PeerDeviceIsLegacyOs(peerNetworkId, SESSION_NAME_DBD);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: GetAllocInfoBySessionParamTest001
 * @tc.desc: get alloc info by session param returns invalid session type when lane trans type is butt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, GetAllocInfoBySessionParamTest001, TestSize.Level1)
{
    LanePreferredLinkList preferred;
    ModuleLaneAdapter(&preferred);
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, TransGetLaneTransTypeBySession).WillOnce(Return(LANE_T_BUTT));
    SessionParam *param = TestCreateSessionParamWithPara(TEST_SESSION_NAME);
    ASSERT_TRUE(param != nullptr);
    LaneAllocInfo allocInfo;
    int32_t ret = GetAllocInfoBySessionParam(param, &allocInfo);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_SESSION_TYPE, ret);
    SoftBusFree(const_cast<SessionAttribute *>(param->attr));
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
}

/*
 * @tc.name: GetAllocInfoBySessionParamTest002
 * @tc.desc: get alloc info by session param returns invalid param when TransGetUidAndPid fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, GetAllocInfoBySessionParamTest002, TestSize.Level1)
{
    LanePreferredLinkList preferred;
    ModuleLaneAdapter(&preferred);
    SessionParam *param = TestCreateSessionParamWithPara(TEST_SESSION_NAME);
    ASSERT_TRUE(param != nullptr);
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, TransGetLaneTransTypeBySession).WillRepeatedly(Return(LANE_T_MSG));
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransGetUidAndPid).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    LaneAllocInfo allocInfo;
    int32_t ret = GetAllocInfoBySessionParam(param, &allocInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    SoftBusFree(const_cast<SessionAttribute *>(param->attr));
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
}

/*
 * @tc.name: GetAllocInfoBySessionParamTest003
 * @tc.desc: get alloc info by session param returns ok with valid params and uid pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, GetAllocInfoBySessionParamTest003, TestSize.Level1)
{
    LanePreferredLinkList preferred;
    ModuleLaneAdapter(&preferred);
    SessionParam *param = TestCreateSessionParamWithPara(TEST_SESSION_NAME);
    ASSERT_TRUE(param != nullptr);
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, TransGetLaneTransTypeBySession).WillRepeatedly(Return(LANE_T_MSG));
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    LaneAllocInfo allocInfo;
    int32_t ret = GetAllocInfoBySessionParam(param, &allocInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(const_cast<SessionAttribute *>(param->attr));
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
}

/*
 * @tc.name: GetRequestOptionBySessionParamTest001
 * @tc.desc: get request option by session param returns invalid session type when trans type is butt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, GetRequestOptionBySessionParamTest001, TestSize.Level1)
{
    LaneRequestOption requestOption;
    SessionParam *param = TestCreateSessionParamWithPara(TEST_SESSION_NAME);
    ASSERT_TRUE(param != nullptr);
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, TransGetLaneTransTypeBySession).WillOnce(Return(LANE_T_BUTT));
    int32_t ret = GetRequestOptionBySessionParam(param, &requestOption);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_SESSION_TYPE, ret);
    SoftBusFree(const_cast<SessionAttribute *>(param->attr));
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
}

/*
 * @tc.name: GetRequestOptionBySessionParamTest002
 * @tc.desc: get request option by session param returns invalid param when TransGetUidAndPid fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, GetRequestOptionBySessionParamTest002, TestSize.Level1)
{
    LaneRequestOption requestOption;
    SessionParam *param = TestCreateSessionParamWithPara(TEST_NEW_SESSION_NAME);
    ASSERT_TRUE(param != nullptr);
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, TransGetLaneTransTypeBySession).WillRepeatedly(Return(LANE_T_MSG));
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransGetUidAndPid).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = GetRequestOptionBySessionParam(param, &requestOption);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    SoftBusFree(const_cast<SessionAttribute *>(param->attr));
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
}

/*
 * @tc.name: GetRequestOptionBySessionParamTest003
 * @tc.desc: get request option by session param returns ok for dsl session name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, GetRequestOptionBySessionParamTest003, TestSize.Level1)
{
    LaneRequestOption requestOption;
    SessionParam *param = TestCreateSessionParamWithPara(SESSION_NAME_DSL);
    ASSERT_TRUE(param != nullptr);
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = GetRequestOptionBySessionParam(param, &requestOption);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(const_cast<SessionAttribute *>(param->attr));
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
}

/*
 * @tc.name: CancelLaneOnWaitLaneStateTest001
 * @tc.desc: cancel lane on wait lane state handles lane handle zero without crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, CancelLaneOnWaitLaneStateTest001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(CancelLaneOnWaitLaneState(0, false));
}

/*
 * @tc.name: CancelLaneOnWaitLaneStateTest002
 * @tc.desc: cancel lane on wait lane state handles fail lane manager without crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, CancelLaneOnWaitLaneStateTest002, TestSize.Level1)
{
    uint32_t laneHandle = TEST_LANE_ID;
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, GetLaneManager).WillRepeatedly(Return(&g_laneManagerApplyFail));
    EXPECT_NO_FATAL_FAILURE(CancelLaneOnWaitLaneState(laneHandle, true));
}

/*
 * @tc.name: CancelLaneOnWaitLaneStateTest003
 * @tc.desc: cancel lane on wait lane state cancels lane with valid lane manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, CancelLaneOnWaitLaneStateTest003, TestSize.Level1)
{
    uint32_t laneHandle = TEST_LANE_ID;
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, GetLaneManager).WillRepeatedly(Return(&g_laneManager));
    EXPECT_NO_FATAL_FAILURE(CancelLaneOnWaitLaneState(laneHandle, true));
}

/*
 * @tc.name: TransAsyncGetLaneInfoTest001
 * @tc.desc: trans async get lane info returns invalid param when any required param is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAsyncGetLaneInfoTest001, TestSize.Level1)
{
    SessionParam param;
    uint32_t laneHandle;
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    int32_t ret = TransAsyncGetLaneInfo(nullptr, nullptr, &appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransAsyncGetLaneInfo(&param, nullptr, &appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransAsyncGetLaneInfo(nullptr, &laneHandle, &appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransAsyncGetLaneInfoTest002
 * @tc.desc: trans async get lane info returns invalid session type when trans type is butt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAsyncGetLaneInfoTest002, TestSize.Level1)
{
    uint32_t laneHandle;
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, TransGetLaneTransTypeBySession).WillOnce(Return(LANE_T_BUTT));
    SessionParam *param = TestCreateSessionParamWithPara(TEST_SESSION_NAME);
    ASSERT_TRUE(param != nullptr);
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    int32_t ret = TransAsyncGetLaneInfo(param, &laneHandle, &appInfo);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_SESSION_TYPE, ret);
    SoftBusFree(const_cast<SessionAttribute *>(param->attr));
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
}

/*
 * @tc.name: TransAsyncGetLaneInfoTest003
 * @tc.desc: trans async get lane info returns get lane info err when lane request fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAsyncGetLaneInfoTest003, TestSize.Level1)
{
    uint32_t laneHandle;
    SessionParam *param = TestCreateSessionParamWithPara(TEST_SESSION_NAME);
    ASSERT_TRUE(param != nullptr);
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, TransGetLaneTransTypeBySession).WillRepeatedly(Return(LANE_T_MSG));
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = TransAsyncGetLaneInfo(param, &laneHandle, &appInfo);
    EXPECT_EQ(SOFTBUS_TRANS_GET_LANE_INFO_ERR, ret);
    SoftBusFree(const_cast<SessionAttribute *>(param->attr));
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
}

/*
 * @tc.name: TransAsyncGetLaneInfoTest004
 * @tc.desc: trans async get lane info returns ok when all steps succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAsyncGetLaneInfoTest004, TestSize.Level1)
{
    uint32_t laneHandle;
    SessionParam *param = TestCreateSessionParamWithPara(TEST_SESSION_NAME);
    ASSERT_TRUE(param != nullptr);
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;
    CoreSessionState state = CORE_SESSION_STATE_INIT;
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, GetLaneManager).WillRepeatedly(Return(&g_laneManager));
    EXPECT_CALL(mock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = TransAddSocketChannelInfo(TEST_SESSION_NAME, TEST_SESSION_ID,
        TEST_CHANNEL_ID, channelType, state);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransAsyncGetLaneInfo(param, &laneHandle, &appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransDeleteSocketChannelInfoBySession(TEST_SESSION_NAME, TEST_SESSION_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(const_cast<SessionAttribute *>(param->attr));
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
}

/*
 * @tc.name: TransAsyncGetLaneReserveInfoTest001
 * @tc.desc: trans async get lane reserve info returns invalid param when required param is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAsyncGetLaneReserveInfoTest001, TestSize.Level1)
{
    SessionParam param;
    uint32_t laneHandle;
    uint64_t laneId = 1;
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    int32_t ret = TransAsyncGetLaneReserveInfo(nullptr, nullptr, laneId, &appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransAsyncGetLaneReserveInfo(&param, nullptr, laneId, &appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransAsyncGetLaneReserveInfo(nullptr, &laneHandle, laneId, &appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransAsyncGetLaneReserveInfoTest002
 * @tc.desc: trans async get lane reserve info returns invalid session type when trans type is butt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAsyncGetLaneReserveInfoTest002, TestSize.Level1)
{
    uint32_t laneHandle;
    uint64_t laneId = 1;
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, TransGetLaneTransTypeBySession).WillOnce(Return(LANE_T_BUTT));
    SessionParam *param = TestCreateSessionParamWithPara(TEST_SESSION_NAME);
    ASSERT_TRUE(param != nullptr);
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    int32_t ret = TransAsyncGetLaneReserveInfo(param, &laneHandle, laneId, &appInfo);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_SESSION_TYPE, ret);
    SoftBusFree(const_cast<SessionAttribute *>(param->attr));
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
}

/*
 * @tc.name: TransAsyncGetLaneReserveInfoTest003
 * @tc.desc: trans async get lane reserve info returns get lane info err when lane request fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAsyncGetLaneReserveInfoTest003, TestSize.Level1)
{
    uint32_t laneHandle;
    uint64_t laneId = 1;
    SessionParam *param = TestCreateSessionParamWithPara(TEST_SESSION_NAME);
    ASSERT_TRUE(param != nullptr);
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, TransGetLaneTransTypeBySession).WillRepeatedly(Return(LANE_T_MSG));
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = TransAsyncGetLaneReserveInfo(param, &laneHandle, laneId, &appInfo);
    EXPECT_EQ(SOFTBUS_TRANS_GET_LANE_INFO_ERR, ret);
    SoftBusFree(const_cast<SessionAttribute *>(param->attr));
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
}

/*
 * @tc.name: TransAsyncGetLaneReserveInfoTest004
 * @tc.desc: trans async get lane reserve info returns err when lane handle not found in list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAsyncGetLaneReserveInfoTest004, TestSize.Level1)
{
    uint32_t laneHandle;
    uint64_t laneId = 1;
    SessionParam *param = TestCreateSessionParamWithPara(TEST_SESSION_NAME);
    ASSERT_TRUE(param != nullptr);
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;
    CoreSessionState state = CORE_SESSION_STATE_INIT;
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, GetLaneManager).WillRepeatedly(Return(&g_laneManager));
    EXPECT_CALL(mock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = TransAddSocketChannelInfo(TEST_SESSION_NAME, TEST_SESSION_ID,
        TEST_CHANNEL_ID, channelType, state);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransAsyncGetLaneReserveInfo(param, &laneHandle, laneId, &appInfo);
    EXPECT_EQ(SOFTBUS_TRANS_GET_LANE_INFO_ERR, ret);
    ret = TransDeleteSocketChannelInfoBySession(TEST_SESSION_NAME, TEST_SESSION_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(const_cast<SessionAttribute *>(param->attr));
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
}

/*
 * @tc.name: TransNotifyLaneQosEventTest001
 * @tc.desc: trans notify lane qos event returns invalid param for out of range owner or event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransNotifyLaneQosEventTest001, TestSize.Level1)
{
    int32_t ret = TransNotifyLaneQosEvent(0,
        static_cast<LaneOwner>(LANE_OWNER_BUTT + 1), static_cast<LaneQosEvent>(LANE_QOS_BW_BUTT + 1));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransNotifyLaneQosEvent(0,
        static_cast<LaneOwner>(LANE_OWNER_SELF - 1), static_cast<LaneQosEvent>(LANE_QOS_BW_BUTT + 1));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransNotifyLaneQosEvent(TEST_LANE_ID, LANE_OWNER_SELF,
        static_cast<LaneQosEvent>(LANE_QOS_BW_BUTT + 1));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransNotifyLaneQosEvent(TEST_LANE_ID, LANE_OWNER_SELF,
        static_cast<LaneQosEvent>(LANE_QOS_BW_HIGH - 1));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransNotifyLaneQosEventTest002
 * @tc.desc: trans notify lane qos event returns ok for valid owner and qos event combinations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransNotifyLaneQosEventTest002, TestSize.Level1)
{
    int32_t ret = TransNotifyLaneQosEvent(TEST_LANE_ID, LANE_OWNER_SELF, LANE_QOS_BW_MID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransNotifyLaneQosEvent(TEST_LANE_ID, LANE_OWNER_OTHER, LANE_QOS_BW_MID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransNotifyLaneQosEvent(TEST_LANE_ID, LANE_OWNER_SELF, LANE_QOS_BW_HIGH);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: DestroyNetworkingReqItemParamTest001
 * @tc.desc: destroy networking req item param handles null lane item without crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, DestroyNetworkingReqItemParamTest001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(DestroyNetworkingReqItemParam(nullptr));
}

/*
 * @tc.name: DestroyNetworkingReqItemParamTest002
 * @tc.desc: destroy networking req item param frees sessionName when peerDeviceId is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, DestroyNetworkingReqItemParamTest002, TestSize.Level1)
{
    TransReqLaneItem laneItem;
    laneItem.param.peerDeviceId = nullptr;
    laneItem.param.sessionName = reinterpret_cast<const char *>(SoftBusCalloc(TEST_LEN));
    (void)strcpy_s(const_cast<char *>(laneItem.param.sessionName), TEST_LEN, TEST_SESSION_NAME);
    EXPECT_NO_FATAL_FAILURE(DestroyNetworkingReqItemParam(&laneItem));
    EXPECT_TRUE(laneItem.param.sessionName == nullptr);
}

/*
 * @tc.name: DestroyNetworkingReqItemParamTest003
 * @tc.desc: destroy networking req item param frees peerDeviceId when sessionName is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, DestroyNetworkingReqItemParamTest003, TestSize.Level1)
{
    TransReqLaneItem laneItem;
    laneItem.param.sessionName = nullptr;
    laneItem.param.peerDeviceId = reinterpret_cast<const char *>(SoftBusCalloc(TEST_LEN));
    (void)strcpy_s(const_cast<char *>(laneItem.param.peerDeviceId), TEST_LEN, TEST_DEVICE_ID);
    EXPECT_NO_FATAL_FAILURE(DestroyNetworkingReqItemParam(&laneItem));
    EXPECT_TRUE(laneItem.param.peerDeviceId == nullptr);
}

/*
 * @tc.name: TransGetChannelIdByLaneHandleTest001
 * @tc.desc: trans get channel id by lane handle returns invalid param when list is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransGetChannelIdByLaneHandleTest001, TestSize.Level1)
{
    if (g_reqLanePendingList != nullptr) {
        g_reqLanePendingList = nullptr;
    }
    int32_t channelId = 0;
    bool isNetWorkingChannel;
    char sessionName;
    char peerNetworkId;
    int32_t ret = TransGetChannelIdByLaneHandle(1, &channelId, &isNetWorkingChannel, &sessionName, &peerNetworkId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransAddInfoByLaneHandleTest001
 * @tc.desc: trans add info by lane handle returns invalid param when req lane pending list is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAddInfoByLaneHandleTest001, TestSize.Level1)
{
    if (g_reqLanePendingList != nullptr) {
        g_reqLanePendingList = nullptr;
    }
    NetWorkingChannelInfo info = {};
    int32_t ret = TransAddInfoByLaneHandle(&info, TEST_DEVICE_ID, 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransAddInfoByLaneHandleTest002
 * @tc.desc: trans add info by lane handle returns ok when adding non networking channel info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAddInfoByLaneHandleTest002, TestSize.Level1)
{
    SoftBusList *list = TestCreateSessionList();
    EXPECT_NE(list, nullptr);
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, CreateSoftBusList).WillRepeatedly(Return(list));
    int32_t ret = TransReqLanePendingInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ASSERT_TRUE(g_reqLanePendingList != nullptr);
    TransReqLaneItem *item = reinterpret_cast<TransReqLaneItem *>(SoftBusCalloc(sizeof(TransReqLaneItem)));
    ASSERT_TRUE(item != nullptr);
    item->laneHandle = 1235;
    (void)SoftBusMutexLock(&(g_reqLanePendingList->lock));
    ListAdd(&(g_reqLanePendingList->list), &(item->node));
    (void)SoftBusMutexUnlock(&(g_reqLanePendingList->lock));
    NetWorkingChannelInfo info = {
        .channelId = TEST_CHANNEL_ID,
        .isNetWorkingChannel = false
    };
    ret = TransAddInfoByLaneHandle(&info, TEST_DEVICE_ID, 1235);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransAddInfoByLaneHandleTest003
 * @tc.desc: trans add info by lane handle returns ok when adding networking channel info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAddInfoByLaneHandleTest003, TestSize.Level1)
{
    SoftBusList *list = TestCreateSessionList();
    EXPECT_NE(list, nullptr);
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, CreateSoftBusList).WillRepeatedly(Return(list));
    int32_t ret = TransReqLanePendingInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ASSERT_TRUE(g_reqLanePendingList != nullptr);
    TransReqLaneItem *item = reinterpret_cast<TransReqLaneItem *>(SoftBusCalloc(sizeof(TransReqLaneItem)));
    ASSERT_TRUE(item != nullptr);
    item->laneHandle = 1235;
    (void)SoftBusMutexLock(&(g_reqLanePendingList->lock));
    ListAdd(&(g_reqLanePendingList->list), &(item->node));
    (void)SoftBusMutexUnlock(&(g_reqLanePendingList->lock));
    NetWorkingChannelInfo info;
    info.isNetWorkingChannel = true;
    info.channelId = TEST_CHANNEL_ID;
    (void)strcpy_s(info.sessionName, SESSION_NAME_SIZE_MAX, TEST_SESSION_NAME);
    ret = TransAddInfoByLaneHandle(&info, TEST_DEVICE_ID, 1235);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransAddInfoByLaneHandleTest004
 * @tc.desc: trans add info by lane handle returns node not found when lane handle not in list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAddInfoByLaneHandleTest004, TestSize.Level1)
{
    NetWorkingChannelInfo info;
    info.isNetWorkingChannel = true;
    info.channelId = TEST_CHANNEL_ID;
    (void)strcpy_s(info.sessionName, SESSION_NAME_SIZE_MAX, TEST_SESSION_NAME);
    int32_t ret = TransAddInfoByLaneHandle(&info, TEST_DEVICE_ID, 1234);
    EXPECT_EQ(ret, SOFTBUS_TRANS_NODE_NOT_FOUND);
}

/*
 * @tc.name: TransProxyGetAppInfoTest001
 * @tc.desc: trans proxy get app info returns network not found when LnnGetLocalStrInfo fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransProxyGetAppInfoTest001, TestSize.Level1)
{
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, LnnGetOsTypeByNetworkId)
        .WillOnce(DoAll(SetArgPointee<1>(OH_OS_TYPE), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_NETWORK_NOT_FOUND));
    AppInfo appInfo;
    int32_t ret = TransProxyGetAppInfo(TEST_SESSION_NAME, TEST_DEVICE_ID, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NOT_FOUND);
}

/*
 * @tc.name: TransProxyGetAppInfoTest002
 * @tc.desc: trans proxy get app info returns remote uuid err when LnnGetRemoteStrInfo fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransProxyGetAppInfoTest002, TestSize.Level1)
{
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, LnnGetOsTypeByNetworkId)
        .WillOnce(DoAll(SetArgPointee<1>(OH_OS_TYPE), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND));
    AppInfo appInfo;
    int32_t ret = TransProxyGetAppInfo(TEST_SESSION_NAME, TEST_DEVICE_ID, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_GET_REMOTE_UUID_ERR);
}

/*
 * @tc.name: TransProxyGetAppInfoTest003
 * @tc.desc: trans proxy get app info returns ok when all remote info queries succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransProxyGetAppInfoTest003, TestSize.Level1)
{
    NiceMock<TransLanePendingTestInterfaceMock> mock;
    EXPECT_CALL(mock, LnnGetOsTypeByNetworkId)
        .WillOnce(DoAll(SetArgPointee<1>(OH_OS_TYPE), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    NodeInfo nodeInfo;
    (void)strcpy_s(nodeInfo.deviceInfo.deviceVersion, DEVICE_VERSION_SIZE_MAX, TEST_DEVICE_ID);
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById)
        .WillRepeatedly(DoAll(SetArgPointee<2>(nodeInfo), Return(SOFTBUS_OK)));
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    int32_t ret = TransProxyGetAppInfo(TEST_SESSION_NAME, TEST_DEVICE_ID, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: UpdateChannelCancelEncryptionTest001
 * @tc.desc: test update channel cancel encryption with cancelEncryptionBit = 0 disables bit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, UpdateChannelCancelEncryptionTest001, TestSize.Level1)
{
    SessionParam param;
    (void)memset_s(&param, sizeof(SessionParam), 0, sizeof(SessionParam));
    param.cancelEncryptionBit = 0;
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo.udpChannelCapability = 0;
    LaneLinkType type = LANE_USB;
    EXPECT_NO_FATAL_FAILURE(UpdateChannelCancelEncryption(&param, type, &appInfo));
    EXPECT_EQ(0, appInfo.udpChannelCapability);
}

/*
 * @tc.name: UpdateChannelCancelEncryptionTest002
 * @tc.desc: test update channel cancel encryption with cancelEncryptionBit > 0 and dataType != TYPE_FILE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, UpdateChannelCancelEncryptionTest002, TestSize.Level1)
{
    SessionAttribute attr;
    (void)memset_s(&attr, sizeof(SessionAttribute), 0, sizeof(SessionAttribute));
    attr.dataType = TYPE_BYTES;
    SessionParam param;
    (void)memset_s(&param, sizeof(SessionParam), 0, sizeof(SessionParam));
    param.cancelEncryptionBit = 1 << LINK_TYPE_WIRED;
    param.attr = &attr;
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo.udpChannelCapability = 0;
    LaneLinkType type = LANE_USB;
    EXPECT_NO_FATAL_FAILURE(UpdateChannelCancelEncryption(&param, type, &appInfo));
    EXPECT_EQ(0, appInfo.udpChannelCapability);
}

/*
 * @tc.name: UpdateChannelCancelEncryptionTest003
 * @tc.desc: test update channel cancel encryption with cancelEncryptionBit > 0, dataType = TYPE_FILE, type = LANE_USB
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, UpdateChannelCancelEncryptionTest003, TestSize.Level1)
{
    SessionAttribute attr;
    (void)memset_s(&attr, sizeof(SessionAttribute), 0, sizeof(SessionAttribute));
    attr.dataType = TYPE_FILE;
    SessionParam param;
    (void)memset_s(&param, sizeof(SessionParam), 0, sizeof(SessionParam));
    param.cancelEncryptionBit = 1 << LINK_TYPE_WIRED;
    param.attr = &attr;
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo.udpChannelCapability = 0;
    LaneLinkType type = LANE_USB;
    EXPECT_NO_FATAL_FAILURE(UpdateChannelCancelEncryption(&param, type, &appInfo));
    EXPECT_NE(0, appInfo.udpChannelCapability & (1 << UDP_CHANNEL_CANCEL_ENCRYPTION));
}

/*
 * @tc.name: UpdateChannelCancelEncryptionTest004
 * @tc.desc: test update channel cancel encryption with cancelEncryptionBit > 0, dataType = TYPE_FILE, type != LANE_USB
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, UpdateChannelCancelEncryptionTest004, TestSize.Level1)
{
    SessionAttribute attr;
    (void)memset_s(&attr, sizeof(SessionAttribute), 0, sizeof(SessionAttribute));
    attr.dataType = TYPE_FILE;
    SessionParam param;
    (void)memset_s(&param, sizeof(SessionParam), 0, sizeof(SessionParam));
    param.cancelEncryptionBit = 1 << LINK_TYPE_WIRED;
    param.attr = &attr;
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo.udpChannelCapability = 0;
    LaneLinkType type = LANE_BR;
    EXPECT_NO_FATAL_FAILURE(UpdateChannelCancelEncryption(&param, type, &appInfo));
    EXPECT_EQ(0, appInfo.udpChannelCapability & (1 << UDP_CHANNEL_CANCEL_ENCRYPTION));
}

/*
 * @tc.name: UpdateChannelCancelEncryptionTest005
 * @tc.desc: test update channel cancel encryption with existing capability bits preserved
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, UpdateChannelCancelEncryptionTest005, TestSize.Level1)
{
    SessionAttribute attr;
    (void)memset_s(&attr, sizeof(SessionAttribute), 0, sizeof(SessionAttribute));
    attr.dataType = TYPE_FILE;
    SessionParam param;
    (void)memset_s(&param, sizeof(SessionParam), 0, sizeof(SessionParam));
    param.cancelEncryptionBit = 1 << LINK_TYPE_WIRED;
    param.attr = &attr;
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo.udpChannelCapability = (1 << UDP_CHANNEL_MULTIPATH_OFFSET) | (1 << CHANNEL_ISMULTINEG_OFFSET);
    LaneLinkType type = LANE_USB;
    EXPECT_NO_FATAL_FAILURE(UpdateChannelCancelEncryption(&param, type, &appInfo));
    EXPECT_NE(0, appInfo.udpChannelCapability & (1 << UDP_CHANNEL_MULTIPATH_OFFSET));
    EXPECT_NE(0, appInfo.udpChannelCapability & (1 << CHANNEL_ISMULTINEG_OFFSET));
    EXPECT_NE(0, appInfo.udpChannelCapability & (1 << UDP_CHANNEL_CANCEL_ENCRYPTION));
}

/*
 * @tc.name: UpdateChannelCancelEncryptionTest006
 * @tc.desc: test update channel cancel encryption disables bit when cancelEncryptionBit = 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, UpdateChannelCancelEncryptionTest006, TestSize.Level1)
{
    SessionAttribute attr;
    (void)memset_s(&attr, sizeof(SessionAttribute), 0, sizeof(SessionAttribute));
    attr.dataType = TYPE_FILE;
    SessionParam param;
    (void)memset_s(&param, sizeof(SessionParam), 0, sizeof(SessionParam));
    param.cancelEncryptionBit = 0;
    param.attr = &attr;
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo.udpChannelCapability = (1 << UDP_CHANNEL_CANCEL_ENCRYPTION) | (1 << UDP_CHANNEL_MULTIPATH_OFFSET);
    LaneLinkType type = LANE_USB;
    EXPECT_NO_FATAL_FAILURE(UpdateChannelCancelEncryption(&param, type, &appInfo));
    EXPECT_EQ(0, appInfo.udpChannelCapability & (1 << UDP_CHANNEL_CANCEL_ENCRYPTION));
    EXPECT_NE(0, appInfo.udpChannelCapability & (1 << UDP_CHANNEL_MULTIPATH_OFFSET));
}

/*
 * @tc.name: UpdateChannelCancelEncryptionTest007
 * @tc.desc: test update channel cancel encryption with wrong link type bit does not enable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, UpdateChannelCancelEncryptionTest007, TestSize.Level1)
{
    SessionAttribute attr;
    (void)memset_s(&attr, sizeof(SessionAttribute), 0, sizeof(SessionAttribute));
    attr.dataType = TYPE_FILE;
    SessionParam param;
    (void)memset_s(&param, sizeof(SessionParam), 0, sizeof(SessionParam));
    param.cancelEncryptionBit = 1 << LINK_TYPE_WIFI;
    param.attr = &attr;
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo.udpChannelCapability = 0;
    LaneLinkType type = LANE_USB;
    EXPECT_NO_FATAL_FAILURE(UpdateChannelCancelEncryption(&param, type, &appInfo));
    EXPECT_EQ(0, appInfo.udpChannelCapability & (1 << UDP_CHANNEL_CANCEL_ENCRYPTION));
}

/*
 * @tc.name: UpdateChannelCancelEncryptionTest008
 * @tc.desc: test update channel cancel encryption with hml link type bit enables cancel encryption
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, UpdateChannelCancelEncryptionTest008, TestSize.Level1)
{
    SessionAttribute attr;
    (void)memset_s(&attr, sizeof(SessionAttribute), 0, sizeof(SessionAttribute));
    attr.dataType = TYPE_FILE;
    SessionParam param;
    (void)memset_s(&param, sizeof(SessionParam), 0, sizeof(SessionParam));
    param.cancelEncryptionBit = 1u << LINK_TYPE_WIFI;
    param.attr = &attr;
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo.udpChannelCapability = 0;
    LaneLinkType type = LANE_HML;
    EXPECT_NO_FATAL_FAILURE(UpdateChannelCancelEncryption(&param, type, &appInfo));
    EXPECT_NE(0, appInfo.udpChannelCapability & (1u << UDP_CHANNEL_CANCEL_ENCRYPTION));
}

/*
 * @tc.name: UpdateChannelCancelEncryptionTest009
 * @tc.desc: test update channel cancel encryption with wrong link type bit for hml does not enable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, UpdateChannelCancelEncryptionTest009, TestSize.Level1)
{
    SessionAttribute attr;
    (void)memset_s(&attr, sizeof(SessionAttribute), 0, sizeof(SessionAttribute));
    attr.dataType = TYPE_FILE;
    SessionParam param;
    (void)memset_s(&param, sizeof(SessionParam), 0, sizeof(SessionParam));
    param.cancelEncryptionBit = 1u << LINK_TYPE_WIRED;
    param.attr = &attr;
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo.udpChannelCapability = (1u << UDP_CHANNEL_MULTIPATH_OFFSET) | (1u << CHANNEL_ISMULTINEG_OFFSET);
    LaneLinkType type = LANE_HML;
    EXPECT_NO_FATAL_FAILURE(UpdateChannelCancelEncryption(&param, type, &appInfo));
    EXPECT_NE(0, appInfo.udpChannelCapability & (1u << UDP_CHANNEL_MULTIPATH_OFFSET));
    EXPECT_NE(0, appInfo.udpChannelCapability & (1u << CHANNEL_ISMULTINEG_OFFSET));
    EXPECT_EQ(0, appInfo.udpChannelCapability & (1u << UDP_CHANNEL_CANCEL_ENCRYPTION));
}
} // namespace OHOS
