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
    TransLanePendingTest()
    {}
    ~TransLanePendingTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransLanePendingTest::SetUpTestCase(void){ }

void TransLanePendingTest::TearDownTestCase(void)
{
    TransReqLanePendingDeinit();
    TransAsyncReqLanePendingDeinit();
    TransSocketLaneMgrDeinit();
    TransFreeLanePendingDeinit();
}

static SoftBusList *TestCreateSessionList()
{
    SoftBusList *list = static_cast<SoftBusList*>(SoftBusCalloc(sizeof(SoftBusList)));
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

static SessionParam *TestCreateSessionParam()
{
    SessionAttribute *attr = static_cast<SessionAttribute*>(SoftBusCalloc(sizeof(SessionAttribute)));
    if (attr == nullptr) {
        return nullptr;
    }
    attr->fastTransData = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_FAST_TRANS_DATA));
    attr->fastTransDataSize = TEST_LEN;
    attr->dataType = TYPE_BYTES;
    SessionParam *param = static_cast<SessionParam*>(SoftBusCalloc(sizeof(SessionParam)));
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

static SessionParam *TestCreateNewSessionParam()
{
    SessionAttribute *attr = static_cast<SessionAttribute*>(SoftBusCalloc(sizeof(SessionAttribute)));
    if (attr == nullptr) {
        return nullptr;
    }
    attr->fastTransData = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_FAST_TRANS_DATA));
    attr->fastTransDataSize = TEST_LEN;
    attr->dataType = TYPE_BYTES;
    SessionParam *param = static_cast<SessionParam*>(SoftBusCalloc(sizeof(SessionParam)));
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

static SessionParam *TestCreateSessionParamWithPara(const char *sessionName)
{
    SessionAttribute *attr = reinterpret_cast<SessionAttribute *>(SoftBusCalloc(sizeof(SessionAttribute)));
    if (attr == nullptr) {
        return nullptr;
    }
    attr->fastTransData = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_FAST_TRANS_DATA));
    attr->fastTransDataSize = TEST_LEN;
    attr->dataType = TYPE_BUTT;
    SessionParam *param = (SessionParam *)SoftBusCalloc(sizeof(SessionParam));
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
    return SOFTBUS_OK;
}

static int32_t TestLnnAllocLaneFail(uint32_t laneHandle, const LaneAllocInfo *allocInfo,
    const LaneAllocListener *listener)
{
    return SOFTBUS_INVALID_PARAM;
}

static int32_t TestLnnFreeLane(uint32_t laneHandle)
{
    return SOFTBUS_OK;
}

static int32_t TestLnnFreeLaneFail(uint32_t laneHandle)
{
    return SOFTBUS_INVALID_PARAM;
}

static int32_t TestLnnCancelLaneFail(uint32_t laneHandle)
{
    return SOFTBUS_INVALID_PARAM;
}

static int32_t TestLnnCancelLane(uint32_t laneHandle)
{
    return SOFTBUS_OK;
}

static LnnLaneManager g_LaneManager = {
    .lnnGetLaneHandle = TestApplyLaneReqId,
    .lnnAllocLane = TestLnnAllocLane,
    .lnnFreeLane = TestLnnFreeLane,
    .lnnCancelLane = TestLnnCancelLane,
};

static LnnLaneManager g_LaneManagerApplyFail = {
    .lnnGetLaneHandle = nullptr,
    .lnnAllocLane = TestLnnAllocLaneFail,
    .lnnFreeLane = TestLnnFreeLaneFail,
    .lnnCancelLane = TestLnnCancelLaneFail,
};

/**
 * @tc.name: TransReqLanePendingInit001
 * @tc.desc: test TransReqLanePendingInit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransReqLanePendingInit001, TestSize.Level1)
{
    // will free in TearDownTestCase
    SoftBusList *list = TestCreateSessionList();
    EXPECT_NE(list, nullptr);
    NiceMock<TransLanePendingTestInterfaceMock> TransLanePendingMock;
    EXPECT_CALL(TransLanePendingMock, CreateSoftBusList).WillRepeatedly(Return(nullptr));
    int32_t ret = TransReqLanePendingInit();
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);
    EXPECT_CALL(TransLanePendingMock, CreateSoftBusList).WillRepeatedly(Return(list));
    ret = TransReqLanePendingInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransAsyncReqLanePendingInit001
 * @tc.desc: test TransAsyncReqLanePendingInit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAsyncReqLanePendingInit001, TestSize.Level1)
{
    // will free in TearDownTestCase
    SoftBusList *list = TestCreateSessionList();
    EXPECT_NE(list, nullptr);
    NiceMock<TransLanePendingTestInterfaceMock> TransLanePendingMock;
    EXPECT_CALL(TransLanePendingMock, CreateSoftBusList).WillRepeatedly(Return(nullptr));
    int32_t ret = TransAsyncReqLanePendingInit();
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);
    EXPECT_CALL(TransLanePendingMock, CreateSoftBusList).WillRepeatedly(Return(list));
    ret = TransAsyncReqLanePendingInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransAsyncReqLanePendingInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransSocketLaneMgrInit001
 * @tc.desc: test TransSocketLaneMgrInit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransSocketLaneMgrInit001, TestSize.Level1)
{
    // will free in TearDownTestCase
    SoftBusList *list = TestCreateSessionList();
    EXPECT_NE(list, nullptr);
    NiceMock<TransLanePendingTestInterfaceMock> TransLanePendingMock;
    EXPECT_CALL(TransLanePendingMock, CreateSoftBusList).WillRepeatedly(Return(nullptr));
    int32_t ret = TransSocketLaneMgrInit();
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);
    EXPECT_CALL(TransLanePendingMock, CreateSoftBusList).WillRepeatedly(Return(list));
    ret = TransSocketLaneMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransSocketLaneMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransFreeLanePendingInit001
 * @tc.desc: test TransFreeLanePendingInit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransFreeLanePendingInit001, TestSize.Level1)
{
    // will free in TearDownTestCase
    SoftBusList *list = TestCreateSessionList();
    EXPECT_NE(list, nullptr);
    NiceMock<TransLanePendingTestInterfaceMock> TransLanePendingMock;
    EXPECT_CALL(TransLanePendingMock, CreateSoftBusList).WillRepeatedly(Return(nullptr));
    int32_t ret = TransFreeLanePendingInit();
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);
    EXPECT_CALL(TransLanePendingMock, CreateSoftBusList).WillRepeatedly(Return(list));
    ret = TransFreeLanePendingInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransFreeLanePendingInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: DestroyAsyncReqItemParam001
 * @tc.desc: test DestroyAsyncReqItemParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, DestroyAsyncReqItemParam001, TestSize.Level1)
{
    SessionParam *param = static_cast<SessionParam*>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(param != nullptr);
    char *sessionName = static_cast<char*>(SoftBusCalloc(sizeof(char)));
    EXPECT_TRUE(sessionName != nullptr);
    char *peerSessionName = static_cast<char*>(SoftBusCalloc(sizeof(char)));
    EXPECT_TRUE(peerSessionName != nullptr);
    char *peerDeviceId = static_cast<char*>(SoftBusCalloc(sizeof(char)));
    EXPECT_TRUE(peerDeviceId != nullptr);
    char *groupId = static_cast<char*>(SoftBusCalloc(sizeof(char)));
    EXPECT_TRUE(groupId != nullptr);
    SessionAttribute *attr = static_cast<SessionAttribute*>(SoftBusCalloc(sizeof(SessionAttribute)));
    EXPECT_TRUE(attr != nullptr);
    param->sessionName = sessionName;
    param->peerSessionName = peerSessionName;
    param->peerDeviceId = peerDeviceId;
    param->groupId = groupId;
    param->attr = attr;

    DestroyAsyncReqItemParam(param);

    EXPECT_TRUE(param->sessionName == nullptr);
    EXPECT_TRUE(param->peerSessionName == nullptr);
    EXPECT_TRUE(param->peerDeviceId == nullptr);
    EXPECT_TRUE(param->groupId == nullptr);
    EXPECT_TRUE(param->attr == nullptr);
    SoftBusFree(param);
}

/**
 * @tc.name: TransGetConnectOptByConnInfo001
 * @tc.desc: test TransGetConnectOptByConnInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransGetConnectOptByConnInfo001, TestSize.Level1)
{
    LaneConnInfo info = {
        .type = LANE_P2P,
    };
    ConnectOption connOpt;
    (void)strcpy_s(info.connInfo.p2p.peerIp, IP_LEN, TEST_IP);
    int32_t ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.type = LANE_WLAN_2P4G;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.type = LANE_WLAN_5G;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.type = LANE_ETH;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.type = LANE_BR;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.type = LANE_BLE;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.type = LANE_COC;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.type = LANE_P2P_REUSE;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.type = LANE_BLE_DIRECT;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.type = LANE_COC_DIRECT;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.type = LANE_HML;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.type = LANE_BLE_REUSE;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_TRANS_GET_CONN_OPT_FAILED, ret);
    ret = TransGetConnectOptByConnInfo(nullptr, &connOpt);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransGetConnectOptByConnInfo(&info, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: TransGetLaneInfo001
 * @tc.desc: Should return SOFTBUS_INVALID_PARAM when given invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransGetLaneInfo001, TestSize.Level1)
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

/**
 * @tc.name: TransGetLaneInfo002
 * @tc.desc: Should return SOFTBUS_TRANS_STOP_BIND_BY_CANCEL when state is CORE_SESSION_STATE_CANCELLING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransGetLaneInfo002, TestSize.Level1)
{
    SessionParam *param = TestCreateSessionParam();
    ASSERT_TRUE(param != nullptr);
    SessionParam *newParam = TestCreateNewSessionParam();
    ASSERT_TRUE(newParam != nullptr);
    LaneConnInfo connInfo;
    uint32_t laneHandle = TEST_LANE_ID;

    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;
    CoreSessionState state = CORE_SESSION_STATE_CHANNEL_OPENED;
    NiceMock<TransLanePendingTestInterfaceMock> TransLanePendingMock;
    EXPECT_CALL(TransLanePendingMock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_WIFI_DIRECT_INIT_FAILED));
    int32_t ret = TransAddSocketChannelInfo(TEST_SESSION_NAME, TEST_SESSION_ID,
        TEST_CHANNEL_ID, channelType, state);
    EXPECT_EQ(SOFTBUS_OK, ret);
    channelType = CHANNEL_TYPE_PROXY;
    state = CORE_SESSION_STATE_CANCELLING;
    ret = TransAddSocketChannelInfo(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID,
        TEST_NEW_CHANNEL_ID, channelType, state);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransGetLaneInfo(newParam, &connInfo, &laneHandle);
    EXPECT_EQ(SOFTBUS_TRANS_STOP_BIND_BY_CANCEL, ret);
    EXPECT_CALL(TransLanePendingMock, TransGetLaneTransTypeBySession).WillOnce(Return(LANE_T_BUTT));
    ret = TransGetLaneInfo(param, &connInfo, &laneHandle);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_SESSION_TYPE, ret);

    EXPECT_CALL(TransLanePendingMock, TransGetLaneTransTypeBySession).WillRepeatedly(Return(LANE_T_MSG));
    EXPECT_CALL(TransLanePendingMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransLanePendingMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    ret = TransGetLaneInfo(param, &connInfo, &laneHandle);
    EXPECT_EQ(SOFTBUS_WIFI_DIRECT_INIT_FAILED, ret);

    EXPECT_CALL(TransLanePendingMock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransLanePendingMock, GetLaneManager).WillRepeatedly(Return(&g_LaneManager));
    EXPECT_CALL(TransLanePendingMock, LnnRequestLane).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransLanePendingMock, SoftBusCondWait).WillOnce(Return(SOFTBUS_OK));
    ret = TransGetLaneInfo(param, &connInfo, &laneHandle);
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);

    ret = TransDeleteSocketChannelInfoBySession(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransDeleteSocketChannelInfoBySession(TEST_SESSION_NAME, TEST_SESSION_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree((void *)(param->attr));
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
    SoftBusFree((void *)(newParam->attr));
    newParam->attr = nullptr;
    SoftBusFree(newParam);
    newParam = nullptr;
}

/**
 * @tc.name: TransAsyncGetLaneInfoByOption001
 * @tc.desc: Should return SOFTBUS_INVALID_PARAM when given invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAsyncGetLaneInfoByOption001, TestSize.Level1)
{
    SessionParam param;
    LaneRequestOption requestOption;
    uint32_t laneHandle;
    int32_t ret = TransAsyncGetLaneInfoByOption(nullptr, &requestOption, &laneHandle, 0, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransAsyncGetLaneInfoByOption(&param, nullptr, &laneHandle, 0, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransAsyncGetLaneInfoByOption(&param, &requestOption, nullptr, 0, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: TransAsyncGetLaneInfoByOption002
 * @tc.desc: Should return SOFTBUS_TRANS_GET_LANE_INFO_ERR when GetLaneManager is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
 HWTEST_F(TransLanePendingTest, TransAsyncGetLaneInfoByOption002, TestSize.Level1)
{
    SessionParam *newParam = TestCreateNewSessionParam();
    ASSERT_TRUE(newParam != nullptr);
    LaneRequestOption requestOption;
    uint32_t laneHandle;
    NiceMock<TransLanePendingTestInterfaceMock> TransLanePendingMock;
    EXPECT_CALL(TransLanePendingMock, GetLaneManager).WillOnce(Return(nullptr));
    int32_t ret = TransAsyncGetLaneInfoByOption(newParam, &requestOption, &laneHandle, 0, 0);
    EXPECT_EQ(SOFTBUS_TRANS_GET_LANE_INFO_ERR, ret);

    SoftBusList *tmpList = g_asyncReqLanePendingList;
    g_asyncReqLanePendingList = nullptr;
    EXPECT_CALL(TransLanePendingMock, GetLaneManager).WillRepeatedly(Return(&g_LaneManager));
    ret = TransAsyncGetLaneInfoByOption(newParam, &requestOption, &laneHandle, 0, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    g_asyncReqLanePendingList = tmpList;

    EXPECT_CALL(TransLanePendingMock, LnnRequestLane).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = TransAsyncGetLaneInfoByOption(newParam, &requestOption, &laneHandle, 0, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    EXPECT_CALL(TransLanePendingMock, LnnRequestLane).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;
    CoreSessionState state = CORE_SESSION_STATE_CANCELLING;
    EXPECT_CALL(TransLanePendingMock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    ret =
        TransAddSocketChannelInfo(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID, TEST_NEW_CHANNEL_ID, channelType, state);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransAsyncGetLaneInfoByOption(newParam, &requestOption, &laneHandle, 0, 0);
    EXPECT_EQ(SOFTBUS_TRANS_STOP_BIND_BY_CANCEL, ret);
    ret = TransDeleteSocketChannelInfoBySession(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);

    state = CORE_SESSION_STATE_INIT;
    ret =
        TransAddSocketChannelInfo(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID, TEST_NEW_CHANNEL_ID, channelType, state);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransAsyncGetLaneInfoByOption(newParam, &requestOption, &laneHandle, 0, 0);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransDeleteSocketChannelInfoBySession(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SoftBusFree((void *)(newParam->attr));
    newParam->attr = nullptr;
    SoftBusFree(newParam);
    newParam = nullptr;
}

/**
 * @tc.name: TransAsyncGetLaneInfoByQos001
 * @tc.desc: Should return SOFTBUS_INVALID_PARAM when given invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAsyncGetLaneInfoByQos001, TestSize.Level1)
{
    SessionParam param;
    LaneAllocInfo allocInfo;
    uint32_t laneHandle;
    int32_t ret = TransAsyncGetLaneInfoByQos(nullptr, &allocInfo, &laneHandle, 0, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransAsyncGetLaneInfoByQos(&param, nullptr, &laneHandle, 0, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransAsyncGetLaneInfoByQos(&param, &allocInfo, nullptr, 0, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: TransAsyncGetLaneInfoByQos002
 * @tc.desc: Should return SOFTBUS_TRANS_GET_LANE_INFO_ERR when GetLaneManager is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
 HWTEST_F(TransLanePendingTest, TransAsyncGetLaneInfoByQos002, TestSize.Level1)
{
    SessionParam *newParam = TestCreateNewSessionParam();
    ASSERT_TRUE(newParam != nullptr);
    LaneAllocInfo allocInfo;
    uint32_t laneHandle;
    NiceMock<TransLanePendingTestInterfaceMock> TransLanePendingMock;
    EXPECT_CALL(TransLanePendingMock, GetLaneManager).WillOnce(Return(nullptr));
    int32_t ret = TransAsyncGetLaneInfoByQos(newParam, &allocInfo, &laneHandle, 0, 0);
    EXPECT_EQ(SOFTBUS_TRANS_GET_LANE_INFO_ERR, ret);

    EXPECT_CALL(TransLanePendingMock, GetLaneManager).WillRepeatedly(Return(&g_LaneManagerApplyFail));
    ret = TransAsyncGetLaneInfoByQos(newParam, &allocInfo, &laneHandle, 0, 0);
    EXPECT_EQ(SOFTBUS_TRANS_GET_LANE_INFO_ERR, ret);

    SoftBusList *tmpList = g_asyncReqLanePendingList;
    g_asyncReqLanePendingList = nullptr;
    EXPECT_CALL(TransLanePendingMock, GetLaneManager).WillRepeatedly(Return(&g_LaneManager));
    ret = TransAsyncGetLaneInfoByQos(newParam, &allocInfo, &laneHandle, 0, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    g_asyncReqLanePendingList = tmpList;

    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;
    CoreSessionState state = CORE_SESSION_STATE_CANCELLING;
    EXPECT_CALL(TransLanePendingMock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    ret =
        TransAddSocketChannelInfo(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID, TEST_NEW_CHANNEL_ID, channelType, state);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransAsyncGetLaneInfoByQos(newParam, &allocInfo, &laneHandle, 0, 0);
    EXPECT_EQ(SOFTBUS_TRANS_STOP_BIND_BY_CANCEL, ret);
    ret = TransDeleteSocketChannelInfoBySession(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);

    state = CORE_SESSION_STATE_INIT;
    ret =
        TransAddSocketChannelInfo(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID, TEST_NEW_CHANNEL_ID, channelType, state);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransAsyncGetLaneInfoByQos(newParam, &allocInfo, &laneHandle, 0, 0);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransDeleteSocketChannelInfoBySession(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SoftBusFree((void *)(newParam->attr));
    newParam->attr = nullptr;
    SoftBusFree(newParam);
    newParam = nullptr;
}

/**
 * @tc.name: BuildTransEventExtra001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, BuildTransEventExtra001, TestSize.Level1)
{
    SessionParam *param = TestCreateSessionParam();
    ASSERT_TRUE(param != nullptr);
    TransEventExtra extra;
    extra.linkType = LANE_BLE;
    BuildTransEventExtra(&extra, param, 0, LANE_T_BYTE, 0);
    SoftBusFree((void *)(param->attr));
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
}

/**
 * @tc.name: CallbackOpenChannelFailed001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, CallbackOpenChannelFailed001, TestSize.Level1)
{
    SessionParam *param = TestCreateSessionParam();
    ASSERT_TRUE(param != nullptr);
    AppInfo appInfo;
    CallbackOpenChannelFailed(param, &appInfo, 0);
    SoftBusFree((void *)(param->attr));
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
}

/**
 * @tc.name: CopyAsyncReqItemSessionParamIds001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, CopyAsyncReqItemSessionParamIds001, TestSize.Level1)
{
    SessionParam *param = TestCreateSessionParam();
    ASSERT_TRUE(param != nullptr);
    SessionParam target;

    int32_t ret = CopyAsyncReqItemSessionParamIds(param, &target);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SoftBusFree((void *)(param->attr));
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
}

/**
 * @tc.name: TransGetLaneReqItemParamByLaneHandle001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransGetLaneReqItemParamByLaneHandle001, TestSize.Level1)
{
    SessionParam *newParam = TestCreateNewSessionParam();
    ASSERT_TRUE(newParam != nullptr);
    uint64_t callingTokenId;
    uint64_t firstTokenId;
    int64_t timeStart;
    int32_t ret = TransGetLaneReqItemParamByLaneHandle(0, nullptr, nullptr, nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftBusList *tmpList = g_asyncReqLanePendingList;
    g_asyncReqLanePendingList = nullptr;
    ret = TransGetLaneReqItemParamByLaneHandle(0, newParam, nullptr, nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    g_asyncReqLanePendingList = tmpList;

    ret = TransGetLaneReqItemParamByLaneHandle(0, newParam, &callingTokenId, &firstTokenId, &timeStart);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);

    ret = TransAddAsyncLaneReqFromPendingList(TEST_NEW_LANE_ID, newParam, 0, 0);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransGetLaneReqItemParamByLaneHandle(TEST_NEW_LANE_ID, newParam, &callingTokenId, &firstTokenId, &timeStart);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SoftBusFree(newParam);
    newParam = nullptr;
    ret = TransDelLaneReqFromPendingList(TEST_NEW_LANE_ID, true);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: RecordFailOpenSessionKpi001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, RecordFailOpenSessionKpi001, TestSize.Level1)
{
    SessionParam *param = TestCreateSessionParam();
    ASSERT_TRUE(param != nullptr);
    SessionParam target;

    int32_t ret = CopyAsyncReqItemSessionParamIds(param, &target);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SoftBusFree((void *)(param->attr));
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
}

/**
 * @tc.name: TransAsyncOpenChannelProc001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAsyncOpenChannelProc001, TestSize.Level1)
{
    SessionParam *param = TestCreateSessionParam();
    ASSERT_TRUE(param != nullptr);
    AppInfo appInfo;
    TransEventExtra extra;
    extra.peerUdid = PEER_UDID;
    LaneConnInfo connInnerInfo;

    connInnerInfo.type = LANE_WLAN_2P4G;
    NiceMock<TransLanePendingTestInterfaceMock> TransLanePendingMock;
    EXPECT_CALL(TransLanePendingMock, TransOpenChannelProc).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    TransAsyncOpenChannelProc(TEST_LANE_ID, param, &appInfo, &extra, &connInnerInfo);

    EXPECT_CALL(TransLanePendingMock, TransOpenChannelProc).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransLanePendingMock, ClientIpcSetChannelInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    TransAsyncOpenChannelProc(TEST_LANE_ID, param, &appInfo, &extra, &connInnerInfo);

    EXPECT_CALL(TransLanePendingMock, ClientIpcSetChannelInfo).WillRepeatedly(Return(SOFTBUS_OK));
    TransAsyncOpenChannelProc(TEST_LANE_ID, param, &appInfo, &extra, &connInnerInfo);

    EXPECT_CALL(TransLanePendingMock, TransLaneMgrAddLane).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    TransAsyncOpenChannelProc(TEST_LANE_ID, param, &appInfo, &extra, &connInnerInfo);

    EXPECT_CALL(TransLanePendingMock, TransLaneMgrAddLane).WillRepeatedly(Return(SOFTBUS_OK));
    TransAsyncOpenChannelProc(TEST_LANE_ID, param, &appInfo, &extra, &connInnerInfo);

    SoftBusFree((void *)(param->attr));
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;

    uint64_t firstTokenId;
    firstTokenId = TOKENID_NOT_SET;
    appInfo.callingTokenId = TEST_TOKEN_ID;
    TransAsyncSetFirstTokenInfo(firstTokenId, &appInfo, &extra);
}

/**
 * @tc.name: CheckSocketChannelState001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, CheckSocketChannelState001, TestSize.Level1)
{
    TransEventExtra extra;
    extra.linkType = LANE_BR;
    CoreSessionState state = CORE_SESSION_STATE_INIT;
    int32_t channelType = CHANNEL_TYPE_PROXY;
    uint32_t laneHandle = TEST_NEW_LANE_ID;
    SessionParam *newParam = TestCreateNewSessionParam();
    ASSERT_TRUE(newParam != nullptr);

    NiceMock<TransLanePendingTestInterfaceMock> TransLanePendingMock;
    EXPECT_CALL(TransLanePendingMock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret =
        TransAddSocketChannelInfo(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID, TEST_NEW_CHANNEL_ID, channelType, state);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = CheckSocketChannelState(laneHandle, newParam, &extra, LANE_T_BYTE);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransSetSocketChannelStateBySession(newParam->sessionName, newParam->sessionId,
        CORE_SESSION_STATE_CANCELLING);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransAddAsyncLaneReqFromPendingList(TEST_NEW_LANE_ID, newParam, 0, 0);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = CheckSocketChannelState(laneHandle, newParam, &extra, LANE_T_BYTE);
    EXPECT_EQ(SOFTBUS_TRANS_STOP_BIND_BY_CANCEL, ret);
    SoftBusFree(newParam);
    newParam = nullptr;
}

/**
 * @tc.name: TransOnAsyncLaneSuccess001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransOnAsyncLaneSuccess001, TestSize.Level1)
{
    uint32_t laneHandle = 0;
    LaneConnInfo connInfo;
    connInfo.type = LANE_BR;
    CoreSessionState state = CORE_SESSION_STATE_INIT;
    int32_t channelType = CHANNEL_TYPE_PROXY;
    SessionParam *newParam = TestCreateNewSessionParam();
    ASSERT_TRUE(newParam != nullptr);

    TransOnAsyncLaneSuccess(laneHandle, &connInfo);

    laneHandle = TEST_NEW_LANE_ID;
    NiceMock<TransLanePendingTestInterfaceMock> TransLanePendingMock;
    EXPECT_CALL(TransLanePendingMock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret =
        TransAddSocketChannelInfo(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID, TEST_NEW_CHANNEL_ID, channelType, state);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransAddAsyncLaneReqFromPendingList(laneHandle, newParam, 0, 0);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(TransLanePendingMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_TRANS_BAD_KEY));
    TransOnAsyncLaneSuccess(laneHandle, &connInfo);

    EXPECT_CALL(TransLanePendingMock, TransGetPkgNameBySessionName).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransLanePendingMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    ret =
        TransAddSocketChannelInfo(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID, TEST_NEW_CHANNEL_ID, channelType, state);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransAddAsyncLaneReqFromPendingList(laneHandle, newParam, 0, 0);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(TransLanePendingMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    TransOnAsyncLaneSuccess(laneHandle, &connInfo);

    TransDeleteSocketChannelInfoBySession(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID);

    SoftBusFree(newParam);
    newParam = nullptr;
}

/**
 * @tc.name: TransOnAsyncLaneFail001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransOnAsyncLaneFail001, TestSize.Level1)
{
    uint32_t laneHandle = 0;
    int32_t reason = SOFTBUS_CONN_BR_INVALID_ADDRESS_ERR;
    CoreSessionState state = CORE_SESSION_STATE_INIT;
    int32_t channelType = CHANNEL_TYPE_PROXY;

    TransOnAsyncLaneFail(laneHandle, reason);

    laneHandle = TEST_LANE_ID;
    SessionParam *newParam = TestCreateNewSessionParam();
    ASSERT_TRUE(newParam != nullptr);
    int32_t ret = TransAddAsyncLaneReqFromPendingList(TEST_NEW_LANE_ID, newParam, 0, 0);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<TransLanePendingTestInterfaceMock> TransLanePendingMock;
    EXPECT_CALL(TransLanePendingMock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    ret =
        TransAddSocketChannelInfo(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID, TEST_NEW_CHANNEL_ID, channelType, state);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(TransLanePendingMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_TRANS_BAD_KEY));
    TransOnAsyncLaneFail(laneHandle, reason);

    ret = TransAddAsyncLaneReqFromPendingList(TEST_NEW_LANE_ID, newParam, 0, 0);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret =
        TransAddSocketChannelInfo(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID, TEST_NEW_CHANNEL_ID, channelType, state);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(TransLanePendingMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    TransOnAsyncLaneFail(laneHandle, reason);

    SoftBusFree(newParam);
    newParam = nullptr;
}

/**
 * @tc.name: TransAuthWithParaAddLaneReqToList001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAuthWithParaAddLaneReqToList001, TestSize.Level1)
{
    g_authWithParaAsyncReqLaneList = nullptr;
    uint32_t laneReqId = TEST_LANE_ID;
    const char *sessionName = TEST_SESSION_NAME;
    bool accountInfo = true;
    int32_t channelId = TEST_CHANNEL_ID;
    int32_t ret = TransAuthWithParaAddLaneReqToList(laneReqId, nullptr, accountInfo, channelId);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    g_authWithParaAsyncReqLaneList = TestCreateSessionList();
    ASSERT_TRUE(g_authWithParaAsyncReqLaneList != nullptr);
    ret = TransAuthWithParaAddLaneReqToList(laneReqId, nullptr, accountInfo, channelId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransAuthWithParaAddLaneReqToList(laneReqId, sessionName, accountInfo, channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);

    DestroySoftBusList(g_authWithParaAsyncReqLaneList);
    g_authWithParaAsyncReqLaneList = nullptr;
}

/**
 * @tc.name: TransAuthWithParaAddLaneReqToList002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAuthWithParaAddLaneReqToList002, TestSize.Level1)
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

/**
 * @tc.name: TransAuthWithParaDelLaneReqById001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAuthWithParaDelLaneReqById001, TestSize.Level1)
{
    uint32_t laneReqId = TEST_LANE_ID;

    int32_t ret = TransAuthWithParaDelLaneReqById(laneReqId);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    g_authWithParaAsyncReqLaneList = TestCreateSessionList();
    ASSERT_TRUE(g_authWithParaAsyncReqLaneList != nullptr);
    ret = TransAuthWithParaDelLaneReqById(laneReqId);
    EXPECT_NE(SOFTBUS_OK, ret);

    const char *sessionName = TEST_SESSION_NAME;
    bool accountInfo = false;
    int32_t channelId = TEST_CHANNEL_ID;
    ret = TransAuthWithParaAddLaneReqToList(laneReqId, sessionName, accountInfo, channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransAuthWithParaDelLaneReqById(laneReqId);
    EXPECT_EQ(SOFTBUS_OK, ret);

    DestroySoftBusList(g_authWithParaAsyncReqLaneList);
    g_authWithParaAsyncReqLaneList = nullptr;
}

/**
 * @tc.name: TransUpdateAuthWithParaLaneConnInfo001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransUpdateAuthWithParaLaneConnInfo001, TestSize.Level1)
{
    uint32_t laneReqId = TEST_LANE_ID;
    LaneConnInfo connInfo;

    int32_t ret = TransUpdateAuthWithParaLaneConnInfo(laneReqId, true, &connInfo, SOFTBUS_OK);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    g_authWithParaAsyncReqLaneList = TestCreateSessionList();
    ASSERT_TRUE(g_authWithParaAsyncReqLaneList != nullptr);
    ret = TransUpdateAuthWithParaLaneConnInfo(laneReqId, true, &connInfo, SOFTBUS_OK);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);

    const char *sessionName = TEST_SESSION_NAME;
    bool accountInfo = false;
    int32_t channelId = TEST_CHANNEL_ID;
    ret = TransAuthWithParaAddLaneReqToList(laneReqId, sessionName, accountInfo, channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransUpdateAuthWithParaLaneConnInfo(laneReqId, true, &connInfo, SOFTBUS_OK);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransAuthWithParaDelLaneReqById(laneReqId);
    EXPECT_EQ(SOFTBUS_OK, ret);

    DestroySoftBusList(g_authWithParaAsyncReqLaneList);
    g_authWithParaAsyncReqLaneList = nullptr;
}

/**
 * @tc.name: TransAuthWithParaGetLaneReqByLaneReqId001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAuthWithParaGetLaneReqByLaneReqId001, TestSize.Level1)
{
    uint32_t laneReqId = TEST_LANE_ID;
    TransAuthWithParaNode paraNode;

    int32_t ret = TransAuthWithParaGetLaneReqByLaneReqId(laneReqId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransAuthWithParaGetLaneReqByLaneReqId(laneReqId, &paraNode);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    g_authWithParaAsyncReqLaneList = TestCreateSessionList();
    ASSERT_TRUE(g_authWithParaAsyncReqLaneList != nullptr);
    ret = TransAuthWithParaGetLaneReqByLaneReqId(laneReqId, &paraNode);
    EXPECT_NE(SOFTBUS_OK, ret);

    const char *sessionName = TEST_SESSION_NAME;
    bool accountInfo = false;
    int32_t channelId = TEST_CHANNEL_ID;
    ret = TransAuthWithParaAddLaneReqToList(laneReqId, sessionName, accountInfo, channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransAuthWithParaGetLaneReqByLaneReqId(laneReqId, &paraNode);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransAuthWithParaDelLaneReqById(laneReqId);
    EXPECT_EQ(SOFTBUS_OK, ret);

    DestroySoftBusList(g_authWithParaAsyncReqLaneList);
    g_authWithParaAsyncReqLaneList = nullptr;
}

/**
 * @tc.name: TransWaitingFreeCallback001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransWaitingFreeCallback001, TestSize.Level1)
{
    uint32_t laneReqId = TEST_LANE_ID;
    int32_t ret = TransWaitingFreeCallback(laneReqId);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    NiceMock<TransLanePendingTestInterfaceMock> TransLanePendingMock;
    EXPECT_CALL(TransLanePendingMock, SoftBusCondWait).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TransAddFreeLaneToPending(laneReqId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransWaitingFreeCallback(laneReqId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    EXPECT_CALL(TransLanePendingMock, SoftBusCondWait).WillOnce(Return(SOFTBUS_OK));
    ret = TransWaitingFreeCallback(laneReqId);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransDelLaneFreeFromPending(laneReqId, false);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransWaitingFreeLane001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransWaitingFreeLane001, TestSize.Level1)
{
    uint32_t laneReqId = TEST_LANE_ID;
    SoftBusList *tmpList = g_freeLanePendingList;
    g_freeLanePendingList = nullptr;
    int32_t ret = TransWaitingFreeLane(laneReqId);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    g_freeLanePendingList = tmpList;

    NiceMock<TransLanePendingTestInterfaceMock> TransLanePendingMock;
    EXPECT_CALL(TransLanePendingMock, GetLaneManager).WillOnce(Return(nullptr));
    ret = TransWaitingFreeLane(laneReqId);
    EXPECT_EQ(SOFTBUS_TRANS_GET_LANE_INFO_ERR, ret);
    ret = TransDelLaneFreeFromPending(laneReqId, false);
    EXPECT_EQ(SOFTBUS_OK, ret);

    EXPECT_CALL(TransLanePendingMock, GetLaneManager).WillRepeatedly(Return(&g_LaneManagerApplyFail));
    ret = TransWaitingFreeLane(laneReqId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    EXPECT_CALL(TransLanePendingMock, GetLaneManager).WillRepeatedly(Return(&g_LaneManager));
    EXPECT_CALL(TransLanePendingMock, SoftBusCondWait).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransAddFreeLaneToPending(laneReqId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransWaitingFreeLane(laneReqId);
    EXPECT_EQ(SOFTBUS_TRANS_LANE_IS_EXISTED, ret);

    ret = TransDelLaneFreeFromPending(laneReqId, false);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransFreeLaneByLaneHandle001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransFreeLaneByLaneHandle001, TestSize.Level1)
{
    uint32_t laneReqId = TEST_LANE_ID;
    NiceMock<TransLanePendingTestInterfaceMock> TransLanePendingMock;
    EXPECT_CALL(TransLanePendingMock, GetLaneManager).WillOnce(Return(nullptr));
    int32_t ret = TransFreeLaneByLaneHandle(laneReqId, true);
    EXPECT_EQ(SOFTBUS_TRANS_GET_LANE_INFO_ERR, ret);
    
    EXPECT_CALL(TransLanePendingMock, GetLaneManager).WillRepeatedly(Return(&g_LaneManager));
    ret = TransFreeLaneByLaneHandle(laneReqId, true);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransAddFreeLaneToPending(laneReqId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransFreeLaneByLaneHandle(laneReqId, false);
    EXPECT_EQ(SOFTBUS_TRANS_LANE_IS_EXISTED, ret);

    ret = TransDelLaneFreeFromPending(laneReqId, false);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransUpdateFreeLaneStatus001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransUpdateFreeLaneStatus001, TestSize.Level1)
{
    uint32_t laneHandle = TEST_LANE_ID;
    SoftBusList *tmpList = g_freeLanePendingList;
    g_freeLanePendingList = nullptr;
    int32_t ret = TransUpdateFreeLaneStatus(laneHandle, false, false, SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    g_freeLanePendingList = tmpList;

    ret = TransUpdateFreeLaneStatus(laneHandle, false, false, SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);

    ret = TransAddFreeLaneToPending(laneHandle);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransUpdateFreeLaneStatus(laneHandle, false, false, SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransDelLaneFreeFromPending(laneHandle, false);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransOnLaneFreeSuccess001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransOnLaneFreeSuccess001, TestSize.Level1)
{
    uint32_t laneHandle = TEST_LANE_ID;
    TransOnLaneFreeSuccess(laneHandle);

    int32_t ret = TransAddFreeLaneToPending(laneHandle);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransOnLaneFreeSuccess(laneHandle);
    ret = TransDelLaneFreeFromPending(laneHandle, false);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: IsShareSession001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, IsShareSession001, TestSize.Level1)
{
    const char *sessionName = TEST_SESSION_NAME;
    bool ret = IsShareSession(sessionName);
    EXPECT_EQ(ret, false);

    ret = IsShareSession(SESSION_NAME_ISHARE);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: IsDslSession001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, IsDslSession001, TestSize.Level1)
{
    bool ret = IsDslSession(nullptr);
    EXPECT_EQ(ret, false);

    ret = IsDslSession(SESSION_NAME_DSL);
    EXPECT_EQ(ret, true);

    ret = IsDslSession(TEST_DSL2_RE_SESSION_NAME);
    EXPECT_EQ(ret, true);

    ret = IsDslSession(TEST_DSL2_RE_SESSION_NAME);
    EXPECT_EQ(ret, true);

    const char *sessionName = TEST_SESSION_NAME;
    ret = IsDslSession(sessionName);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: PeerDeviceIsLegacyOs001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, PeerDeviceIsLegacyOs001, TestSize.Level1)
{
    const char *peerNetworkId = TEST_DEVICE_ID;
    const char *sessionName = TEST_SESSION_NAME;
    NiceMock<TransLanePendingTestInterfaceMock> TransLanePendingMock;

    EXPECT_CALL(TransLanePendingMock, LnnGetDLAuthCapacity).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    bool ret = PeerDeviceIsLegacyOs(peerNetworkId, sessionName);
    EXPECT_EQ(ret, false);

    EXPECT_CALL(TransLanePendingMock, LnnGetDLAuthCapacity).WillRepeatedly(Return(SOFTBUS_OK));
    ret = PeerDeviceIsLegacyOs(peerNetworkId, sessionName);
    EXPECT_EQ(ret, false);

    ret = PeerDeviceIsLegacyOs(peerNetworkId, SESSION_NAME_DBD);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: GetAllocInfoBySessionParam001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, GetAllocInfoBySessionParam001, TestSize.Level1)
{
    LanePreferredLinkList preferred;
    ModuleLaneAdapter(&preferred);
    NiceMock<TransLanePendingTestInterfaceMock> TransLanePendingMock;
    EXPECT_CALL(TransLanePendingMock, TransGetLaneTransTypeBySession).WillOnce(Return(LANE_T_BUTT));
    SessionParam *param = TestCreateSessionParamWithPara(SESSION_NAME_PHONEPAD);
    ASSERT_TRUE(param != nullptr);
    LaneAllocInfo allocInfo;
    int32_t ret = GetAllocInfoBySessionParam(param, &allocInfo);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_SESSION_TYPE, ret);

    EXPECT_CALL(TransLanePendingMock, TransGetLaneTransTypeBySession).WillRepeatedly(Return(LANE_T_MSG));
    EXPECT_CALL(TransLanePendingMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransLanePendingMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    EXPECT_CALL(TransLanePendingMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransLanePendingMock, TransGetUidAndPid).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = GetAllocInfoBySessionParam(param, &allocInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    EXPECT_CALL(TransLanePendingMock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    ret = GetAllocInfoBySessionParam(param, &allocInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SoftBusFree((void *)param->attr);
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
}

/**
 * @tc.name: GetRequestOptionBySessionParam001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, GetRequestOptionBySessionParam001, TestSize.Level1)
{
    LaneRequestOption requestOption;
    SessionParam *param = TestCreateSessionParamWithPara(SESSION_NAME_PHONEPAD);
    ASSERT_TRUE(param != nullptr);
    NiceMock<TransLanePendingTestInterfaceMock> TransLanePendingMock;
    EXPECT_CALL(TransLanePendingMock, TransGetLaneTransTypeBySession).WillOnce(Return(LANE_T_BUTT));
    int32_t ret = GetRequestOptionBySessionParam(param, &requestOption);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_SESSION_TYPE, ret);
    SoftBusFree((void *)param->attr);
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;

    param = TestCreateSessionParamWithPara(SESSION_NAME_DISTRIBUTE_COMMUNICATION);
    ASSERT_TRUE(param != nullptr);
    EXPECT_CALL(TransLanePendingMock, TransGetLaneTransTypeBySession).WillRepeatedly(Return(LANE_T_MSG));
    EXPECT_CALL(TransLanePendingMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransLanePendingMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    EXPECT_CALL(TransLanePendingMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransLanePendingMock, TransGetUidAndPid).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = GetRequestOptionBySessionParam(param, &requestOption);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    SoftBusFree((void *)param->attr);
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;

    param = TestCreateSessionParamWithPara(SESSION_NAME_DSL);
    ASSERT_TRUE(param != nullptr);
    EXPECT_CALL(TransLanePendingMock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    ret = GetRequestOptionBySessionParam(param, &requestOption);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SoftBusFree((void *)param->attr);
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
}

/**
 * @tc.name: CancelLaneOnWaitLaneState001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, CancelLaneOnWaitLaneState001, TestSize.Level1)
{
    CancelLaneOnWaitLaneState(0, false);

    uint32_t laneHandle = TEST_LANE_ID;
    NiceMock<TransLanePendingTestInterfaceMock> TransLanePendingMock;
    EXPECT_CALL(TransLanePendingMock, GetLaneManager).WillRepeatedly(Return(&g_LaneManagerApplyFail));
    CancelLaneOnWaitLaneState(laneHandle, true);

    EXPECT_CALL(TransLanePendingMock, GetLaneManager).WillRepeatedly(Return(&g_LaneManager));
    CancelLaneOnWaitLaneState(laneHandle, true);
}

/**
 * @tc.name: TransAsyncGetLaneInfo001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAsyncGetLaneInfo001, TestSize.Level1)
{
    SessionParam param;
    uint32_t laneHandle;
    int32_t ret = TransAsyncGetLaneInfo(nullptr, nullptr, 0, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransAsyncGetLaneInfo(&param, nullptr, 0, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransAsyncGetLaneInfo(nullptr, &laneHandle, 0, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: TransAsyncGetLaneInfo002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAsyncGetLaneInfo002, TestSize.Level1)
{
    uint32_t laneHandle;
    NiceMock<TransLanePendingTestInterfaceMock> TransLanePendingMock;
    EXPECT_CALL(TransLanePendingMock, TransGetLaneTransTypeBySession).WillOnce(Return(LANE_T_BUTT));
    SessionParam *param = TestCreateSessionParamWithPara(SESSION_NAME_PHONEPAD);
    ASSERT_TRUE(param != nullptr);
    int32_t ret = TransAsyncGetLaneInfo(param, &laneHandle, 0, 0);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_SESSION_TYPE, ret);
    
    EXPECT_CALL(TransLanePendingMock, TransGetLaneTransTypeBySession).WillRepeatedly(Return(LANE_T_MSG));
    EXPECT_CALL(TransLanePendingMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransLanePendingMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    EXPECT_CALL(TransLanePendingMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransLanePendingMock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransAsyncGetLaneInfo(param, &laneHandle, 0, 0);
    EXPECT_EQ(SOFTBUS_TRANS_GET_LANE_INFO_ERR, ret);

    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;
    CoreSessionState state = CORE_SESSION_STATE_INIT;
    EXPECT_CALL(TransLanePendingMock, GetLaneManager).WillRepeatedly(Return(&g_LaneManager));
    EXPECT_CALL(TransLanePendingMock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    ret =
        TransAddSocketChannelInfo(TEST_SESSION_NAME, TEST_SESSION_ID, TEST_CHANNEL_ID, channelType, state);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransAsyncGetLaneInfo(param, &laneHandle, 0, 0);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransDeleteSocketChannelInfoBySession(TEST_SESSION_NAME, TEST_SESSION_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree((void *)(param->attr));
    param->attr = nullptr;
    SoftBusFree(param);
    param = nullptr;
}

/**
 * @tc.name: TransCancelLaneItemCondByLaneHandle001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransCancelLaneItemCondByLaneHandle001, TestSize.Level1)
{
    uint32_t laneHandle = TEST_LANE_ID;
    SoftBusList *tmpList = g_reqLanePendingList;
    g_reqLanePendingList = nullptr;
    int32_t ret =TransCancelLaneItemCondByLaneHandle(laneHandle, true, false, SOFTBUS_OK);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    g_reqLanePendingList = tmpList;

    ret =TransCancelLaneItemCondByLaneHandle(laneHandle, true, false, SOFTBUS_OK);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    ret = TransAddLaneReqFromPendingList(laneHandle);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret =TransCancelLaneItemCondByLaneHandle(laneHandle, true, false, SOFTBUS_OK);
    EXPECT_EQ(SOFTBUS_OK, ret);

    TransReqLanePendingDeinit();
}


/**
 * @tc.name: TransNotifyLaneQosEventTest001
 * @tc.desc: TransNotifyLaneQosEvent test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransNotifyLaneQosEventTest001, TestSize.Level1)
{
    int32_t ret = TransNotifyLaneQosEvent(0, (LaneOwner)(LANE_OWNER_BUTT + 1), (LaneQosEvent)(LANE_QOS_BW_BUTT + 1));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransNotifyLaneQosEvent(0, (LaneOwner)(LANE_OWNER_SELF - 1), (LaneQosEvent)(LANE_QOS_BW_BUTT + 1));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransNotifyLaneQosEvent(TEST_LANE_ID, LANE_OWNER_SELF, (LaneQosEvent)(LANE_QOS_BW_BUTT + 1));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransNotifyLaneQosEvent(TEST_LANE_ID, LANE_OWNER_SELF, (LaneQosEvent)(LANE_QOS_BW_HIGH - 1));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransNotifyLaneQosEvent(TEST_LANE_ID, LANE_OWNER_SELF, LANE_QOS_BW_MID);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransNotifyLaneQosEvent(TEST_LANE_ID, LANE_OWNER_OTHER, LANE_QOS_BW_MID);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransNotifyLaneQosEvent(TEST_LANE_ID, LANE_OWNER_SELF, LANE_QOS_BW_HIGH);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

} // namespace OHOS
