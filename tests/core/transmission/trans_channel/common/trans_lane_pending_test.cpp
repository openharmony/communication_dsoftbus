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

#include <securec.h>
#include "cJSON.h"

#include "gtest/gtest.h"
#include "session.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"
#include "trans_channel_common.h"
#include "trans_lane_pending_ctl.c"
#include "trans_lane_pending_ctl.h"
#include "trans_lane_pending_test_mock.h"

using namespace testing;
using namespace testing::ext;

#define TEST_CHANNEL_ID 2048
#define TEST_SESSION_ID 8
#define TEST_NEW_SESSION_ID 16
#define TEST_NEW_CHANNEL_ID 1024
#define TEST_LEN 128
#define TEST_LANE_ID 268438006
#define TEST_TOKEN_ID 123456

namespace OHOS {

const char *TEST_IP = "192.168.1.111";
const char *TEST_SESSION_NAME = "ohos.distributedschedule.dms.test";
const char *TEST_NEW_SESSION_NAME = "test.ohos.distributedschedule.dms.test";
const char *TEST_FAST_TRANS_DATA = "testFastTransData";
const char *TEST_DEVICE_ID = "ABCDEF00ABCDEF00ABCDEF00";
const char *TEST_PKG_NAME = "ohos.distributedschedule.dms.test";
const char *PEER_UDID = "123412341234abcdef";

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
    int ret = SoftBusMutexInit(&list->lock, &mutexAttr);
    EXPECT_EQ(ret, SOFTBUS_OK);
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

static uint32_t TestApplyLaneReqId(LaneType type)
{
    (void)type;
    return TEST_LANE_ID;
}

static int32_t TestLnnAllocLane(uint32_t laneHandle, const LaneAllocInfo *allocInfo, const LaneAllocListener *listener)
{
    return SOFTBUS_OK;
}

static LnnLaneManager g_LaneManager = {
    .lnnGetLaneHandle = TestApplyLaneReqId,
    .lnnAllocLane = TestLnnAllocLane,
};

static LnnLaneManager g_LaneManagerApplyFail = {
    .lnnGetLaneHandle = NULL,
    .lnnAllocLane = TestLnnAllocLane,
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
    EXPECT_EQ(ret, SOFTBUS_MALLOC_ERR);
    EXPECT_CALL(TransLanePendingMock, CreateSoftBusList).WillRepeatedly(Return(list));
    ret = TransReqLanePendingInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
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
    EXPECT_EQ(ret, SOFTBUS_MALLOC_ERR);
    EXPECT_CALL(TransLanePendingMock, CreateSoftBusList).WillRepeatedly(Return(list));
    ret = TransAsyncReqLanePendingInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransAsyncReqLanePendingInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
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
    EXPECT_EQ(ret, SOFTBUS_MALLOC_ERR);
    EXPECT_CALL(TransLanePendingMock, CreateSoftBusList).WillRepeatedly(Return(list));
    ret = TransSocketLaneMgrInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransSocketLaneMgrInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
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
    EXPECT_EQ(ret, SOFTBUS_MALLOC_ERR);
    EXPECT_CALL(TransLanePendingMock, CreateSoftBusList).WillRepeatedly(Return(list));
    ret = TransFreeLanePendingInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransFreeLanePendingInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
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
    EXPECT_EQ(ret, SOFTBUS_OK);
    info.type = LANE_WLAN_2P4G;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(ret, SOFTBUS_OK);
    info.type = LANE_WLAN_5G;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(ret, SOFTBUS_OK);
    info.type = LANE_ETH;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(ret, SOFTBUS_OK);
    info.type = LANE_BR;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(ret, SOFTBUS_OK);
    info.type = LANE_BLE;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(ret, SOFTBUS_OK);
    info.type = LANE_COC;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(ret, SOFTBUS_OK);
    info.type = LANE_P2P_REUSE;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(ret, SOFTBUS_OK);
    info.type = LANE_BLE_DIRECT;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(ret, SOFTBUS_OK);
    info.type = LANE_COC_DIRECT;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(ret, SOFTBUS_OK);
    info.type = LANE_HML;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(ret, SOFTBUS_OK);
    info.type = LANE_BLE_REUSE;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(ret, SOFTBUS_TRANS_GET_CONN_OPT_FAILED);
    ret = TransGetConnectOptByConnInfo(nullptr, &connOpt);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransGetConnectOptByConnInfo(&info, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
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
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransGetLaneInfo(&param, nullptr, &laneHandle);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransGetLaneInfo(&param, &connInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
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
    EXPECT_EQ(ret, SOFTBUS_OK);
    channelType = CHANNEL_TYPE_PROXY;
    state = CORE_SESSION_STATE_CANCELLING;
    ret = TransAddSocketChannelInfo(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID,
        TEST_NEW_CHANNEL_ID, channelType, state);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransGetLaneInfo(newParam, &connInfo, &laneHandle);
    EXPECT_EQ(ret, SOFTBUS_TRANS_STOP_BIND_BY_CANCEL);
    EXPECT_CALL(TransLanePendingMock, TransGetLaneTransTypeBySession).WillOnce(Return(LANE_T_BUTT));
    ret = TransGetLaneInfo(param, &connInfo, &laneHandle);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_TYPE);

    EXPECT_CALL(TransLanePendingMock, TransGetLaneTransTypeBySession).WillRepeatedly(Return(LANE_T_MSG));
    EXPECT_CALL(TransLanePendingMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransLanePendingMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    ret = TransGetLaneInfo(param, &connInfo, &laneHandle);
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_INIT_FAILED);

    EXPECT_CALL(TransLanePendingMock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransLanePendingMock, GetLaneManager).WillRepeatedly(Return(&g_LaneManager));
    EXPECT_CALL(TransLanePendingMock, LnnRequestLane).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransLanePendingMock, SoftBusCondWait).WillOnce(Return(SOFTBUS_OK));
    ret = TransGetLaneInfo(param, &connInfo, &laneHandle);
    EXPECT_EQ(ret, SOFTBUS_MALLOC_ERR);

    ret = TransDeleteSocketChannelInfoBySession(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransDeleteSocketChannelInfoBySession(TEST_SESSION_NAME, TEST_SESSION_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree((void *)(param->attr));
    param->attr = NULL;
    SoftBusFree(param);
    param = NULL;
    SoftBusFree((void *)(newParam->attr));
    newParam->attr = NULL;
    SoftBusFree(newParam);
    newParam = NULL;
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
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransAsyncGetLaneInfoByOption(&param, nullptr, &laneHandle, 0, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransAsyncGetLaneInfoByOption(&param, &requestOption, nullptr, 0, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: TransAsyncGetLaneInfoByOption002
 * @tc.desc: Should return SOFTBUS_TRANS_GET_LANE_INFO_ERR when GetLaneManager is NULL
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
    EXPECT_CALL(TransLanePendingMock, GetLaneManager).WillOnce(Return(NULL));
    int32_t ret = TransAsyncGetLaneInfoByOption(newParam, &requestOption, &laneHandle, 0, 0);
    EXPECT_EQ(ret, SOFTBUS_TRANS_GET_LANE_INFO_ERR);

    SoftBusList *tmpList = g_asyncReqLanePendingList;
    g_asyncReqLanePendingList = NULL;
    EXPECT_CALL(TransLanePendingMock, GetLaneManager).WillRepeatedly(Return(&g_LaneManager));
    ret = TransAsyncGetLaneInfoByOption(newParam, &requestOption, &laneHandle, 0, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    g_asyncReqLanePendingList = tmpList;

    EXPECT_CALL(TransLanePendingMock, LnnRequestLane).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = TransAsyncGetLaneInfoByOption(newParam, &requestOption, &laneHandle, 0, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    EXPECT_CALL(TransLanePendingMock, LnnRequestLane).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;
    CoreSessionState state = CORE_SESSION_STATE_CANCELLING;
    EXPECT_CALL(TransLanePendingMock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    ret =
        TransAddSocketChannelInfo(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID, TEST_NEW_CHANNEL_ID, channelType, state);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransAsyncGetLaneInfoByOption(newParam, &requestOption, &laneHandle, 0, 0);
    EXPECT_EQ(ret, SOFTBUS_TRANS_STOP_BIND_BY_CANCEL);
    ret = TransDeleteSocketChannelInfoBySession(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);

    state = CORE_SESSION_STATE_INIT;
    ret =
        TransAddSocketChannelInfo(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID, TEST_NEW_CHANNEL_ID, channelType, state);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransAsyncGetLaneInfoByOption(newParam, &requestOption, &laneHandle, 0, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransDeleteSocketChannelInfoBySession(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree((void *)(newParam->attr));
    newParam->attr = NULL;
    SoftBusFree(newParam);
    newParam = NULL;
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
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransAsyncGetLaneInfoByQos(&param, nullptr, &laneHandle, 0, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransAsyncGetLaneInfoByQos(&param, &allocInfo, nullptr, 0, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: TransAsyncGetLaneInfoByQos002
 * @tc.desc: Should return SOFTBUS_TRANS_GET_LANE_INFO_ERR when GetLaneManager is NULL
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
    EXPECT_CALL(TransLanePendingMock, GetLaneManager).WillOnce(Return(NULL));
    int32_t ret = TransAsyncGetLaneInfoByQos(newParam, &allocInfo, &laneHandle, 0, 0);
    EXPECT_EQ(ret, SOFTBUS_TRANS_GET_LANE_INFO_ERR);

    EXPECT_CALL(TransLanePendingMock, GetLaneManager).WillRepeatedly(Return(&g_LaneManagerApplyFail));
    ret = TransAsyncGetLaneInfoByQos(newParam, &allocInfo, &laneHandle, 0, 0);
    EXPECT_EQ(ret, SOFTBUS_TRANS_GET_LANE_INFO_ERR);

    SoftBusList *tmpList = g_asyncReqLanePendingList;
    g_asyncReqLanePendingList = NULL;
    EXPECT_CALL(TransLanePendingMock, GetLaneManager).WillRepeatedly(Return(&g_LaneManager));
    ret = TransAsyncGetLaneInfoByQos(newParam, &allocInfo, &laneHandle, 0, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    g_asyncReqLanePendingList = tmpList;

    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;
    CoreSessionState state = CORE_SESSION_STATE_CANCELLING;
    EXPECT_CALL(TransLanePendingMock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    ret =
        TransAddSocketChannelInfo(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID, TEST_NEW_CHANNEL_ID, channelType, state);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransAsyncGetLaneInfoByQos(newParam, &allocInfo, &laneHandle, 0, 0);
    EXPECT_EQ(ret, SOFTBUS_TRANS_STOP_BIND_BY_CANCEL);
    ret = TransDeleteSocketChannelInfoBySession(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);

    state = CORE_SESSION_STATE_INIT;
    ret =
        TransAddSocketChannelInfo(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID, TEST_NEW_CHANNEL_ID, channelType, state);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransAsyncGetLaneInfoByQos(newParam, &allocInfo, &laneHandle, 0, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransDeleteSocketChannelInfoBySession(TEST_NEW_SESSION_NAME, TEST_NEW_SESSION_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree((void *)(newParam->attr));
    newParam->attr = NULL;
    SoftBusFree(newParam);
    newParam = NULL;
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
    param->attr = NULL;
    SoftBusFree(param);
    param = NULL;
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
    param->attr = NULL;
    SoftBusFree(param);
    param = NULL;
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
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree((void *)(param->attr));
    param->attr = NULL;
    SoftBusFree(param);
    param = NULL;
}

/**
 * @tc.name: TransGetLaneReqItemParamByLaneHandle001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransGetLaneReqItemParamByLaneHandle001, TestSize.Level1)
{
    uint32_t callingTokenId;
    uint32_t firstTokenId;
    int64_t timeStart;
    SessionParam *param = TestCreateSessionParam();
    ASSERT_TRUE(param != nullptr);
    int32_t ret = TransGetLaneReqItemParamByLaneHandle(0, NULL, NULL, NULL, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    SoftBusList *tmpList = g_asyncReqLanePendingList;
    g_asyncReqLanePendingList = NULL;
    ret = TransGetLaneReqItemParamByLaneHandle(0, param, NULL, NULL, NULL);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    g_asyncReqLanePendingList = tmpList;

    ret = TransGetLaneReqItemParamByLaneHandle(0, param, &callingTokenId, &firstTokenId, &timeStart);
    EXPECT_EQ(ret, SOFTBUS_TRANS_NODE_NOT_FOUND);

    ret = TransAddAsyncLaneReqFromPendingList(TEST_LANE_ID, param, 0, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransGetLaneReqItemParamByLaneHandle(TEST_LANE_ID, param, &callingTokenId, &firstTokenId, &timeStart);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree((void *)(param->attr));
    param->attr = NULL;
    SoftBusFree(param);
    param = NULL;
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
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree((void *)(param->attr));
    param->attr = NULL;
    SoftBusFree(param);
    param = NULL;
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
    EXPECT_CALL(TransLanePendingMock, TransOpenChannelProc).WillOnce(Return(SOFTBUS_ERR));
    TransAsyncOpenChannelProc(TEST_LANE_ID, param, &appInfo, &extra, &connInnerInfo);

    EXPECT_CALL(TransLanePendingMock, TransOpenChannelProc).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransLanePendingMock, ClientIpcSetChannelInfo).WillOnce(Return(SOFTBUS_ERR));
    TransAsyncOpenChannelProc(TEST_LANE_ID, param, &appInfo, &extra, &connInnerInfo);

    EXPECT_CALL(TransLanePendingMock, ClientIpcSetChannelInfo).WillRepeatedly(Return(SOFTBUS_OK));
    TransAsyncOpenChannelProc(TEST_LANE_ID, param, &appInfo, &extra, &connInnerInfo);

    EXPECT_CALL(TransLanePendingMock, TransLaneMgrAddLane).WillOnce(Return(SOFTBUS_ERR));
    TransAsyncOpenChannelProc(TEST_LANE_ID, param, &appInfo, &extra, &connInnerInfo);

    EXPECT_CALL(TransLanePendingMock, TransLaneMgrAddLane).WillRepeatedly(Return(SOFTBUS_OK));
    TransAsyncOpenChannelProc(TEST_LANE_ID, param, &appInfo, &extra, &connInnerInfo);

    SoftBusFree((void *)(param->attr));
    param->attr = NULL;
    SoftBusFree(param);
    param = NULL;
}

/**
 * @tc.name: TransAsyncSetFirstTokenInfo001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLanePendingTest, TransAsyncSetFirstTokenInfo001, TestSize.Level1)
{
    uint32_t firstTokenId;
    AppInfo appInfo;
    TransEventExtra event;
    firstTokenId = TOKENID_NOT_SET;
    appInfo.callingTokenId = TEST_TOKEN_ID;
    TransAsyncSetFirstTokenInfo(firstTokenId, &appInfo, &event);
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
    uint32_t laneHandle = TEST_LANE_ID;
    SessionParam *param = TestCreateSessionParam();
    ASSERT_TRUE(param != nullptr);

    NiceMock<TransLanePendingTestInterfaceMock> TransLanePendingMock;
    EXPECT_CALL(TransLanePendingMock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret =
        TransAddSocketChannelInfo(TEST_SESSION_NAME, TEST_SESSION_ID, TEST_CHANNEL_ID, channelType, state);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = CheckSocketChannelState(laneHandle, param, &extra, LANE_T_BYTE);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransSetSocketChannelStateBySession(param->sessionName, param->sessionId, CORE_SESSION_STATE_CANCELLING);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = CheckSocketChannelState(laneHandle, param, &extra, LANE_T_BYTE);
    EXPECT_EQ(ret, SOFTBUS_TRANS_STOP_BIND_BY_CANCEL);

    SoftBusFree((void *)(param->attr));
    param->attr = NULL;
    SoftBusFree(param);
    param = NULL;
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

    TransOnAsyncLaneSuccess(laneHandle, &connInfo);

    laneHandle = TEST_LANE_ID;
    NiceMock<TransLanePendingTestInterfaceMock> TransLanePendingMock;
    EXPECT_CALL(TransLanePendingMock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret =
        TransAddSocketChannelInfo(TEST_SESSION_NAME, TEST_SESSION_ID, TEST_CHANNEL_ID, channelType, state);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(TransLanePendingMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_TRANS_BAD_KEY));
    TransOnAsyncLaneSuccess(laneHandle, &connInfo);

    EXPECT_CALL(TransLanePendingMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_OK));
    TransOnAsyncLaneSuccess(laneHandle, &connInfo);
}
} // namespace OHOS
