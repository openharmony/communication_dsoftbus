/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "bus_center_manager.h"
#include "lnn_lane.h"
#include "softbus_adapter_mem.h"
#include "softbus_feature_config.h"
#include "trans_channel_common.c"
#include "trans_channel_limit.h"
#include "trans_lane_pending_ctl.c"
#include "trans_session_service.h"

using namespace testing::ext;

namespace OHOS {

#define MAX_COUNT (4)
static int32_t g_count = 0;
const char *g_pkgName = "dms";
const char *g_sessionName = "ohos.distributedschedule.dms.test";
const char *g_invalidName = "ohos.invalid.dms.test";
const char *g_networkId = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";
const char *g_deviceId = "ABCDEF00ABCDEF00ABCDEF00";
const char *g_groupId = "TEST_GROUP_ID";

static SessionAttribute g_sessionAttr[] = {
    {.dataType = TYPE_MESSAGE},
    {.dataType = TYPE_BYTES},
    {.dataType = TYPE_FILE},
    {.dataType = TYPE_STREAM},
    {.dataType = LANE_T_BUTT},
};

class TransLaneTest : public testing::Test {
public:
    TransLaneTest()
    {}
    ~TransLaneTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransLaneTest::SetUpTestCase(void)
{
    SoftbusConfigInit();
    ConnServerInit();
    AuthInit();
    BusCenterServerInit();
    TransServerInit();
    int32_t ret = TransReqLanePendingInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransFreeLanePendingInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransSessionMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

void TransLaneTest::TearDownTestCase(void)
{
    ConnServerDeinit();
    AuthDeinit();
    BusCenterServerDeinit();
    TransServerDeinit();
    TransReqLanePendingDeinit();
    TransFreeLanePendingDeinit();
}

SessionParam* GenerateCommParamTest()
{
    SessionParam *sessionParam = (SessionParam *)SoftBusCalloc(sizeof(SessionParam));
    if (sessionParam == NULL) {
        return nullptr;
    }
    sessionParam->sessionName = g_sessionName;
    sessionParam->peerSessionName = g_sessionName;
    sessionParam->peerDeviceId = g_deviceId;
    sessionParam->groupId = g_groupId;
    sessionParam->attr = &g_sessionAttr[g_count];
    if (g_count > MAX_COUNT) {
        g_count = 0;
    }
    g_count++;
    return sessionParam;
}

SessionParam* GenerateParamTest(SessionAttribute *sessionAttr)
{
    SessionParam *sessionParam = (SessionParam *)SoftBusCalloc(sizeof(SessionParam));
    if (sessionParam == NULL) {
        return nullptr;
    }
    sessionParam->sessionName = g_sessionName;
    sessionParam->peerSessionName = g_sessionName;
    sessionParam->peerDeviceId = g_deviceId;
    sessionParam->groupId = g_groupId;
    sessionParam->attr = sessionAttr;
    return sessionParam;
}

/**
 * @tc.name: TransLaneTest001
 * @tc.desc: trans lane pending init and deinit.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransLaneTest001, TestSize.Level1)
{
    (void)TransReqLanePendingInit();
    int32_t ret = TransReqLanePendingInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransReqLanePendingDeinit();
    TransReqLanePendingDeinit();
}

/**
 * @tc.name: TransLaneTest002
 * @tc.desc: add trans lane pending and delete trans lane pending.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransLaneTest002, TestSize.Level1)
{
    (void)TransReqLanePendingInit();
    uint32_t laneHandle = 1;
    uint32_t invalidId = 111;
    int32_t ret = TransAddLaneReqFromPendingList(laneHandle);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransDelLaneReqFromPendingList(invalidId, false);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);

    ret = TransDelLaneReqFromPendingList(laneHandle, false);
    EXPECT_EQ(SOFTBUS_OK, ret);

    TransReqLanePendingDeinit();
    ret = TransAddLaneReqFromPendingList(laneHandle);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransDelLaneReqFromPendingList(laneHandle, false);
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);
    TransReqLanePendingDeinit();
}

/**
 * @tc.name: TransLaneTest003
 * @tc.desc: trans get lane Reqitem by laneReqId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransLaneTest003, TestSize.Level1)
{
    uint32_t laneHandle = 1;
    uint32_t invalidId = 111;
    bool bSucc = false;
    int32_t errCode = SOFTBUS_OK;
    LaneConnInfo *connInfo = (LaneConnInfo *)SoftBusCalloc(sizeof(LaneConnInfo));
    ASSERT_TRUE(connInfo != nullptr);
    int32_t ret = TransGetLaneReqItemByLaneHandle(invalidId, &bSucc, connInfo, &errCode);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    (void)TransReqLanePendingInit();
    (void)memset_s(connInfo, sizeof(LaneConnInfo), 0, sizeof(LaneConnInfo));
    ret = TransAddLaneReqFromPendingList(laneHandle);
    ASSERT_TRUE(ret == SOFTBUS_OK);

    ret = TransGetLaneReqItemByLaneHandle(invalidId, &bSucc, connInfo, &errCode);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);

    ret = TransGetLaneReqItemByLaneHandle(laneHandle, &bSucc, connInfo, &errCode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransGetLaneReqItemByLaneHandle(laneHandle, &bSucc, NULL, &errCode);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);

    ret = TransDelLaneReqFromPendingList(laneHandle, false);
    EXPECT_EQ(SOFTBUS_OK, ret);

    TransReqLanePendingDeinit();
    ret = TransAddLaneReqFromPendingList(laneHandle);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    TransReqLanePendingDeinit();

    ret = TransGetLaneReqItemByLaneHandle(laneHandle, &bSucc, connInfo, &errCode);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    SoftBusFree(connInfo);
}

/**
 * @tc.name: TransLaneTest004
 * @tc.desc: trans update lane connInfo by laneReqId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransLaneTest004, TestSize.Level1)
{
    (void)TransReqLanePendingInit();
    uint32_t laneHandle = 1;
    uint32_t invalidId = 111;
    bool bSucc = false;
    int32_t errCode = SOFTBUS_OK;
    LaneConnInfo *connInfo = (LaneConnInfo *)SoftBusCalloc(sizeof(LaneConnInfo));
    ASSERT_TRUE(connInfo != nullptr);
    (void)memset_s(connInfo, sizeof(LaneConnInfo), 0, sizeof(LaneConnInfo));
    int32_t ret = TransAddLaneReqFromPendingList(laneHandle);
    ASSERT_TRUE(ret == SOFTBUS_OK);

    ret = TransUpdateLaneConnInfoByLaneHandle(invalidId, bSucc, connInfo, false, errCode);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);

    ret = TransUpdateLaneConnInfoByLaneHandle(laneHandle, bSucc, connInfo, false, errCode);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    connInfo->connInfo.p2p.protocol = 1;
    ret = TransUpdateLaneConnInfoByLaneHandle(laneHandle, bSucc, connInfo, false, errCode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransDelLaneReqFromPendingList(laneHandle, false);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransReqLanePendingDeinit();

    ret = TransUpdateLaneConnInfoByLaneHandle(laneHandle, bSucc, connInfo, false, errCode);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    TransReqLanePendingDeinit();
    SoftBusFree(connInfo);
}

/**
 * @tc.name: TransLaneTest005
 * @tc.desc: trans lane request success by laneReqId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransLaneTest005, TestSize.Level1)
{
    (void)TransReqLanePendingInit();
    uint32_t laneHandle = 1;
    uint32_t invalidId = 111;
    LaneConnInfo *connInfo = (LaneConnInfo *)SoftBusCalloc(sizeof(LaneConnInfo));
    ASSERT_TRUE(connInfo != nullptr);
    (void)memset_s(connInfo, sizeof(LaneConnInfo), 0, sizeof(LaneConnInfo));
    int32_t ret = TransAddLaneReqFromPendingList(laneHandle);
    ASSERT_TRUE(ret == SOFTBUS_OK);

    TransOnLaneRequestSuccess(invalidId, connInfo);
    connInfo->connInfo.p2p.protocol = 1;
    TransOnLaneRequestSuccess(laneHandle, connInfo);

    ret = TransDelLaneReqFromPendingList(laneHandle, false);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransReqLanePendingDeinit();
    SoftBusFree(connInfo);
}

/**
 * @tc.name: TransLaneTest006
 * @tc.desc: trans lane request fail by laneReqId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransLaneTest006, TestSize.Level1)
{
    (void)TransReqLanePendingInit();
    uint32_t laneHandle = 1;
    uint32_t invalidId = 111;
    LaneRequestFailReason reason = LANE_LINK_FAILED;
    LaneConnInfo *connInfo = (LaneConnInfo *)SoftBusCalloc(sizeof(LaneConnInfo));
    ASSERT_TRUE(connInfo != nullptr);
    (void)memset_s(connInfo, sizeof(LaneConnInfo), 0, sizeof(LaneConnInfo));
    int32_t ret = TransAddLaneReqFromPendingList(laneHandle);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    TransOnLaneRequestFail(invalidId, reason);
    connInfo->connInfo.p2p.protocol = 1;
    TransOnLaneRequestFail(laneHandle, reason);

    ret = TransDelLaneReqFromPendingList(laneHandle, false);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransReqLanePendingDeinit();
    SoftBusFree(connInfo);
}

/**
 * @tc.name: TransLaneTest007
 * @tc.desc: trans lane state change and get stream lane type.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransLaneTest007, TestSize.Level1)
{
    int32_t ret = GetStreamLaneType(RAW_STREAM);
    EXPECT_EQ(ret, LANE_T_RAW_STREAM);

    ret = GetStreamLaneType(COMMON_VIDEO_STREAM);
    EXPECT_EQ(ret, LANE_T_COMMON_VIDEO);

    ret = GetStreamLaneType(COMMON_AUDIO_STREAM);
    EXPECT_EQ(ret, LANE_T_COMMON_VOICE);

    ret = GetStreamLaneType(LANE_T_BUTT);
    EXPECT_EQ(ret, LANE_T_BUTT);
}

/**
 * @tc.name: TransLaneTest008
 * @tc.desc: trans get lane by session.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransLaneTest008, TestSize.Level1)
{
    int32_t ret = TransGetLaneTransTypeBySession(NULL);
    EXPECT_EQ(ret, LANE_T_BUTT);

    SessionParam* sessionParam = GenerateCommParamTest();
    ASSERT_TRUE(sessionParam != nullptr);
    ret = TransGetLaneTransTypeBySession(sessionParam);
    EXPECT_EQ(ret, LANE_T_MSG);
    SoftBusFree(sessionParam);

    sessionParam = GenerateCommParamTest();
    ASSERT_TRUE(sessionParam != nullptr);
    ret = TransGetLaneTransTypeBySession(sessionParam);
    EXPECT_EQ(ret, LANE_T_BYTE);
    SoftBusFree(sessionParam);

    sessionParam = GenerateCommParamTest();
    ASSERT_TRUE(sessionParam != nullptr);
    ret = TransGetLaneTransTypeBySession(sessionParam);
    EXPECT_EQ(ret, LANE_T_FILE);
    SoftBusFree(sessionParam);

    sessionParam = GenerateCommParamTest();
    ASSERT_TRUE(sessionParam != nullptr);
    ret = TransGetLaneTransTypeBySession(sessionParam);
    EXPECT_EQ(ret, LANE_T_RAW_STREAM);
    SoftBusFree(sessionParam);

    sessionParam = GenerateCommParamTest();
    ASSERT_TRUE(sessionParam != nullptr);
    ret = TransGetLaneTransTypeBySession(sessionParam);
    EXPECT_EQ(ret, LANE_T_BUTT);
    SoftBusFree(sessionParam);
}


/**
 * @tc.name: TransLaneTest009
 * @tc.desc: trans get lane linkType by session linkType.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransLaneTest009, TestSize.Level1)
{
    LinkType type = (LinkType)LINK_TYPE_WIFI_WLAN_5G;
    LaneLinkType ret = TransGetLaneLinkTypeBySessionLinkType(type);
    EXPECT_EQ(ret, LANE_WLAN_5G);

    type = (LinkType)LINK_TYPE_WIFI_WLAN_2G;
    ret = TransGetLaneLinkTypeBySessionLinkType(type);
    EXPECT_EQ(ret, LANE_WLAN_2P4G);

    type = (LinkType)LINK_TYPE_WIFI_P2P;
    ret = TransGetLaneLinkTypeBySessionLinkType(type);
    EXPECT_EQ(ret, LANE_P2P);

    type = (LinkType)LINK_TYPE_BR;
    ret = TransGetLaneLinkTypeBySessionLinkType(type);
    EXPECT_EQ(ret, LANE_BR);
}

/**
 * @tc.name: TransLaneTest010
 * @tc.desc: transform session perferred to lane perferred.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransLaneTest010, TestSize.Level1)
{
    int32_t ret = TransReqLanePendingInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionAttribute sessionAttr = {
        .dataType = LANE_T_BUTT,
        .linkTypeNum = 4,
    };
    SessionParam *sessionParam = GenerateParamTest(&sessionAttr);
    ASSERT_TRUE(sessionParam != nullptr);
    LanePreferredLinkList *preferred = (LanePreferredLinkList *)SoftBusCalloc(sizeof(LanePreferredLinkList));
    ASSERT_TRUE(preferred != nullptr);
    (void)memset_s(preferred, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    TransformSessionPreferredToLanePreferred(sessionParam, preferred, NULL);
    SoftBusFree(sessionParam);
    SoftBusFree(preferred);
}

/**
 * @tc.name: TransLaneTest011
 * @tc.desc: trans softbus condwait.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransLaneTest011, TestSize.Level1)
{
    SoftBusCond *cond = 0;
    SoftBusMutex *mutex = 0;
    uint32_t timeMillis = 0;
    int32_t ret = TransSoftBusCondWait(NULL, NULL, timeMillis);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    timeMillis = 1;
    ret = TransSoftBusCondWait(cond, mutex, timeMillis);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: TransLaneTest012
 * @tc.desc: trans req lane pending init.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransLaneTest012, TestSize.Level1)
{
    uint32_t laneHandle = 1;
    uint32_t invalidId = 111;
    int32_t ret = TransWaitingRequestCallback(laneHandle);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    (void)TransReqLanePendingInit();
    bool bSucc = true;

    ret = TransWaitingRequestCallback(laneHandle);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    ret = TransAddLaneReqFromPendingList(laneHandle);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransWaitingRequestCallback(invalidId);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    LaneConnInfo connInfo;
    connInfo.type = LANE_WLAN_5G;
    ret = TransUpdateLaneConnInfoByLaneHandle(laneHandle, bSucc, &connInfo, false, SOFTBUS_OK);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransWaitingRequestCallback(laneHandle);
    EXPECT_EQ(SOFTBUS_OK, ret);

    (void)TransDelLaneReqFromPendingList(laneHandle, false);
    TransReqLanePendingDeinit();

    ret = TransWaitingRequestCallback(laneHandle);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/**
 * @tc.name: TransLaneTest013
 * @tc.desc: trans add laneReq to pending and waitting.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransLaneTest013, TestSize.Level1)
{
    (void)LnnInitDistributedLedger();
    TransOption trans = {
        .transType = LANE_T_MSG,
        .expectedBw = 1,
        .pid = 1,
        .expectedLink = {
            .linkTypeNum = 2,
            .linkType = {
                LANE_WLAN_2P4G,
                LANE_P2P
            },
        },
    };
    uint32_t laneHandle = 1;
    LaneRequestOption requestOption = {
        .type = LANE_TYPE_TRANS,
    };
    (void)memcpy_s(&trans.networkId, NETWORK_ID_BUF_LEN, "networkId", strlen("networkId") + 1);
    NetWorkingChannelInfo info = {
        .channelId = INVALID_CHANNEL_ID,
        .isNetWorkingChannel = false,
    };
    (void)memcpy_s(info.sessionName, SESSION_NAME_SIZE_MAX, g_sessionName, SESSION_NAME_SIZE_MAX);

    int32_t ret = TransAddLaneReqToPendingAndWaiting(&info, laneHandle, &requestOption);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    (void)TransReqLanePendingInit();

    (void)memcpy_s(&requestOption.requestInfo, sizeof(TransOption), &trans, sizeof(TransOption));
    ret = TransAddLaneReqToPendingAndWaiting(&info, laneHandle, &requestOption);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransAddLaneReqToPendingAndWaiting(&info, laneHandle, &requestOption);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransAddLaneReqToPendingAndWaiting(&info, laneHandle, &requestOption);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    (void)TransDelLaneReqFromPendingList(laneHandle, false);
    LnnDeinitDistributedLedger();
    TransReqLanePendingDeinit();
}

/**
 * @tc.name: TransLaneTest014
 * @tc.desc: trans get lane info by option.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransLaneTest014, TestSize.Level1)
{
    (void)TransReqLanePendingInit();
    uint32_t laneHandle = 1;
    uint32_t errCode = SOFTBUS_OK;
    LaneRequestOption requestOption = {
        .type = LANE_TYPE_TRANS,
    };
    LaneConnInfo connInfo;
    NetWorkingChannelInfo info = {
        .channelId = INVALID_CHANNEL_ID,
        .isNetWorkingChannel = false,
    };
    (void)memcpy_s(info.sessionName, SESSION_NAME_SIZE_MAX, g_sessionName, SESSION_NAME_SIZE_MAX);
    int32_t ret = TransGetLaneInfoByOption(NULL, &connInfo, &laneHandle, &info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransGetLaneInfoByOption(&requestOption, &connInfo, &laneHandle, &info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    (void)InitLane();
    ret = TransGetLaneInfoByOption(&requestOption, &connInfo, &laneHandle, &info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransUpdateLaneConnInfoByLaneHandle(laneHandle, true, &connInfo, false, errCode);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);

    ret = TransGetLaneInfoByOption(&requestOption, &connInfo, &laneHandle, &info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    (void)LnnFreeLane(laneHandle);
    DeinitLane();
    TransReqLanePendingDeinit();
}

/**
 * @tc.name: TransLaneTest015
 * @tc.desc: trans add session server item.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransLaneTest015, TestSize.Level1)
{
    (void)TransReqLanePendingInit();
    uint32_t laneHandle = 1;
    LaneConnInfo connInfo = {
        .type = LANE_P2P,
        .connInfo.p2p.protocol = 1,
        .connInfo.p2p.localIp = {"local Ip"},
        .connInfo.p2p.peerIp = {"peer Ip"},
    };
    SessionServer *node = (SessionServer *)SoftBusCalloc(sizeof(SessionServer));
    ASSERT_TRUE(node != nullptr);
    (void)memcpy_s((void *)node->sessionName, SESSION_NAME_SIZE_MAX,
        "normal sessionName", strlen("normal sessionName") + 1);
    int32_t ret = TransSessionServerAddItem(node);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SessionAttribute sessionNormalAttr = {
        .dataType = TYPE_MESSAGE,
        .linkTypeNum = 4,
    };
    SessionParam *sessionParam = GenerateParamTest(&sessionNormalAttr);
    SoftBusFree(sessionParam);
    ret = TransGetLaneInfo(NULL, &connInfo, &laneHandle);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    TransSessionServerDelItem(g_sessionName);
    SoftBusFree(node);
    (void)LnnFreeLane(laneHandle);
    DeinitLane();
    TransReqLanePendingDeinit();
}

/**
 * @tc.name: TransLaneTest016
 * @tc.desc: trans set wlan connect info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransLaneTest016, TestSize.Level1)
{
    WlanConnInfo connInfo;
    ConnectOption connOpt;
    int32_t ret = SetWlanConnInfo(&connInfo, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransLaneTest017
 * @tc.desc: trans set br connect info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransLaneTest017, TestSize.Level1)
{
    BrConnInfo brInfo;
    ConnectOption connOpt;
    int32_t ret = SetBrConnInfo(&brInfo, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransLaneTest018
 * @tc.desc: trans set ble connect info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransLaneTest018, TestSize.Level1)
{
    BleConnInfo bleInfo;
    ConnectOption connOpt;
    int32_t ret = SetBleConnInfo(&bleInfo, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransLaneTest019
 * @tc.desc: trans get connect opt by connect info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransLaneTest019, TestSize.Level1)
{
    LaneConnInfo info = {
        .type = LANE_P2P,
    };
    ConnectOption connOpt;
    int32_t ret = TransGetConnectOptByConnInfo(NULL, &connOpt);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    info.type = LANE_P2P;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);

    info.type = LANE_WLAN_2P4G;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);

    info.type = LANE_BR;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);

    info.type = LANE_P2P_REUSE;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);

    info.type = LANE_BLE_DIRECT;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);

    info.type = LANE_BLE;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);

    info.type = LANE_HML;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);

    info.type = LANE_LINK_TYPE_BUTT;
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_TRANS_GET_CONN_OPT_FAILED, ret);
}

/**
 * @tc.name: TransLaneTest020
 * @tc.desc: trans get auth type by network id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransLaneTest020, TestSize.Level1)
{
    const char* peerNetWorkId = "peer networkId";
    bool ret = TransGetAuthTypeByNetWorkId(peerNetWorkId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    (void)LnnInitDistributedLedger();
    ret = TransGetAuthTypeByNetWorkId(peerNetWorkId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    LnnDeinitDistributedLedger();
}

/**
 * @tc.name: TransLaneTest021
 * @tc.desc: trans check session name invalid on auth channel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransLaneTest021, TestSize.Level1)
{
    const char *emptyName  = nullptr;
    const char *invalidName  = "invalid name";
    const char *sessionName  = "ohos.distributedhardware.devicemanager.resident";
    bool ret = CheckSessionNameValidOnAuthChannel(emptyName);
    EXPECT_FALSE(ret);
    ret = CheckSessionNameValidOnAuthChannel(invalidName);
    EXPECT_FALSE(ret);
    ret = CheckSessionNameValidOnAuthChannel(sessionName);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: TransLaneTest022
 * @tc.desc: transform session perferred to lane perferred use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransLaneTest022, TestSize.Level1)
{
    int32_t ret = TransReqLanePendingInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionAttribute sessionAttr = {
        .dataType = LANE_T_BUTT,
        .linkTypeNum = -1,
    };
    SessionParam *sessionParam = GenerateParamTest(&sessionAttr);
    ASSERT_TRUE(sessionParam != nullptr);
    LanePreferredLinkList *preferred = (LanePreferredLinkList*)SoftBusCalloc(sizeof(LanePreferredLinkList));
    ASSERT_TRUE(preferred != nullptr);
    (void)memset_s(preferred, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    TransformSessionPreferredToLanePreferred(sessionParam, preferred, NULL);
    SoftBusFree(sessionParam);
    SoftBusFree(preferred);
    SessionAttribute sessionAttr1 = {
        .dataType = LANE_T_BUTT,
        .linkTypeNum = 5,
    };
    SessionParam *sessionParam1 = GenerateParamTest(&sessionAttr1);
    ASSERT_TRUE(sessionParam1 != nullptr);
    LanePreferredLinkList *preferred1 = (LanePreferredLinkList*)SoftBusCalloc(sizeof(LanePreferredLinkList));
    ASSERT_TRUE(preferred1 != nullptr);
    (void)memset_s(preferred1, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    TransformSessionPreferredToLanePreferred(sessionParam1, preferred1, NULL);
    SoftBusFree(sessionParam1);
    SoftBusFree(preferred1);
    SessionAttribute sessionAttr2 = {
        .dataType = LANE_T_BUTT,
        .linkTypeNum = 7,
    };
    SessionParam *sessionParam2 = GenerateParamTest(&sessionAttr2);
    ASSERT_TRUE(sessionParam2 != nullptr);
    LanePreferredLinkList *preferred2 = (LanePreferredLinkList*)SoftBusCalloc(sizeof(LanePreferredLinkList));
    ASSERT_TRUE(preferred2 != nullptr);
    (void)memset_s(preferred2, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    TransformSessionPreferredToLanePreferred(sessionParam2, preferred2, NULL);
    SoftBusFree(sessionParam2);
    SoftBusFree(preferred2);
}

/**
 * @tc.name: TransLaneTest023
 * @tc.desc: PeerDeviceIsLegacyOs func test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransLaneTest023, TestSize.Level1)
{
    bool ret = PeerDeviceIsLegacyOs(g_networkId, g_sessionName);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TransLaneTest024
 * @tc.desc: PeerDeviceIsLegacyOs func test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransLaneTest024, TestSize.Level1)
{
    P2pConnInfo *p2pInfo = (P2pConnInfo *)SoftBusMalloc(sizeof(P2pConnInfo));
    ASSERT_TRUE(p2pInfo != nullptr);
    ConnectOption *connOpt = (ConnectOption *)SoftBusMalloc(sizeof(ConnectOption));
    ASSERT_TRUE(connOpt != nullptr);

    int32_t ret = SetHmlConnectInfo(p2pInfo, connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SoftBusFree(p2pInfo);
    SoftBusFree(connOpt);
}
} // namespace OHOS