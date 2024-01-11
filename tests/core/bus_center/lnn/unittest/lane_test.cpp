/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <securec.h>

#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_lane.h"
#include "lnn_lane_link.h"
#include "lnn_lane_reliability.h"
#include "lnn_lane_select.h"
#include "lnn_local_net_ledger.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "softbus_errcode.h"
#include "softbus_utils.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;
constexpr char NODE_NETWORK_ID[] = "111122223333abcdef";
constexpr char NODE_UDID[] = "123456ABCDEF";
constexpr char NODE_BT_MAC[] = "b1:ab:cd:ef:aa:d7";
constexpr uint32_t REMOTE_SESSION_PORT = 6060;
constexpr uint32_t REMOTE_AUTH_PORT = 7070;
constexpr uint32_t REMOTE_PROXY_PORT = 8080;
constexpr char REMOTE_WLAN_IP[] = "10.146.181.134";
constexpr char LOCAL_NETWORK_ID[] = "444455556666abcdef";
constexpr uint32_t FILE_DEFAULT_LINK_NUM = 4;
constexpr uint32_t LANE_PREFERRED_LINK_NUM = 2;
constexpr uint32_t DEFAULT_QOSINFO_MIN_BW = 10;
constexpr uint32_t DEFAULT_QOSINFO_MAX_LATENCY = 10000;
constexpr uint32_t DEFAULT_QOSINFO_MIN_LATENCY = 2500;
constexpr uint32_t LOW_BW = 500 * 1024;
constexpr uint32_t HIGH_BW = 160 * 1024 * 1024;

static NodeInfo g_nodeInfo;
constexpr int32_t DEFAULT_PID = 0;

static void ConstructRemoteNode(void);
static void ConstructLocalInfo(void);

class LaneTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LaneTest::SetUpTestCase()
{
    int32_t ret = LooperInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnInitDistributedLedger();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnInitLocalLedger();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = InitLane();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ConstructRemoteNode();
    ConstructLocalInfo();
    GTEST_LOG_(INFO) << "LaneTest start";
}

void LaneTest::TearDownTestCase()
{
    DeinitLane();
    LnnDeinitLocalLedger();
    LnnDeinitDistributedLedger();
    LooperDeinit();
    (void)memset_s(&g_nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    GTEST_LOG_(INFO) << "LaneTest end";
}

void LaneTest::SetUp()
{
}

void LaneTest::TearDown()
{
}

static void ConstructRemoteNode(void)
{
    (void)memset_s(&g_nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    uint32_t cap = 0;
    LnnSetNetCapability(&cap, BIT_BR);
    LnnSetNetCapability(&cap, BIT_WIFI_P2P);
    LnnSetNetCapability(&cap, BIT_WIFI_24G);
    LnnSetNetCapability(&cap, BIT_WIFI_5G);
    g_nodeInfo.netCapacity = cap;
    int ret = strncpy_s(g_nodeInfo.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID, strlen(NODE_NETWORK_ID));
    EXPECT_TRUE(ret == EOK);
    ret = LnnSetDeviceUdid(&g_nodeInfo, NODE_UDID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetDiscoveryType(&g_nodeInfo, DISCOVERY_TYPE_WIFI);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetProxyPort(&g_nodeInfo, REMOTE_PROXY_PORT);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetSessionPort(&g_nodeInfo, REMOTE_SESSION_PORT);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnSetWiFiIp(&g_nodeInfo, REMOTE_WLAN_IP);
    ret = LnnSetAuthPort(&g_nodeInfo, REMOTE_AUTH_PORT);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnSetBtMac(&g_nodeInfo, NODE_BT_MAC);
    (void)LnnAddOnlineNode(&g_nodeInfo);
}

static void ConstructLocalInfo(void)
{
    int32_t ret = LnnSetLocalStrInfo(STRING_KEY_NETWORKID, LOCAL_NETWORK_ID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalNumInfo(NUM_KEY_NET_CAP, (1 << BIT_BR) |
        (1 << BIT_WIFI_24G) | (1 << BIT_WIFI_5G) | (1 << BIT_WIFI_P2P));
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

static void NotifyWlanLinkSuccess(uint32_t reqId, const LaneLinkInfo *linkInfo)
{
    EXPECT_TRUE((linkInfo->type == LANE_WLAN_2P4G) || (linkInfo->type == LANE_WLAN_5G));
    EXPECT_EQ(linkInfo->linkInfo.wlan.connInfo.port, REMOTE_SESSION_PORT);
    EXPECT_STREQ(REMOTE_WLAN_IP, linkInfo->linkInfo.wlan.connInfo.addr);
    printf("WLAN: linkSuccess, reqId:0x%x\n", reqId);
}

static void NotifyWlanLinkFail(uint32_t reqId, int32_t reason)
{
    printf("WLAN: reqId:0x%x, fail reason:%d\n", reqId, reason);
}

static void NotifyWlanLinkException(uint32_t reqId, int32_t reason)
{
    printf("WLAN: reqId:0x%x, exception reason:%d\n", reqId, reason);
}

static void NotifyBrLinkSuccess(uint32_t reqId, const LaneLinkInfo *linkInfo)
{
    EXPECT_TRUE(linkInfo->type == LANE_BR);
    EXPECT_STREQ(linkInfo->linkInfo.br.brMac, NODE_BT_MAC);
    printf("BR: linkSuccess, reqId:0x%x\n", reqId);
}

static void NotifyBrLinkFail(uint32_t reqId, int32_t reason)
{
    printf("BR: reqId:0x%x, reason:%d\n", reqId, reason);
}

static void NotifyBrLinkException(uint32_t reqId, int32_t reason)
{
    printf("BR: reqId:0x%x, reason:%d\n", reqId, reason);
}

static const char *GetLinkType(LaneLinkType type)
{
    switch (type) {
        case LANE_BR:
            return "BR";
        case LANE_WLAN_2P4G:
            return "Wlan_2.4G";
        case LANE_WLAN_5G:
            return "Wlan_5G";
        case LANE_P2P:
            return "P2P";
        default:
            return "Unknown-Link";
    }
}

static void OnLaneRequestSuccess(uint32_t laneId, const LaneConnInfo *info)
{
    printf("LaneRequestSucc: laneId:0x%x, linkType:%s\n", laneId, GetLinkType(info->type));
    const LnnLaneManager *laneManager = GetLaneManager();
    int32_t ret = laneManager->lnnFreeLane(laneId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

static void OnLaneRequestFail(uint32_t laneId, int32_t errCode)
{
    printf("LaneRequestFail: laneId:0x%x, reason:%d\n", laneId, errCode);
    const LnnLaneManager *laneManager = GetLaneManager();
    int32_t ret = laneManager->lnnFreeLane(laneId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

static void OnLaneStateChange(uint32_t laneId, LaneState state)
{
    printf("LaneStateChange: laneId:0x%x, state:%d\n", laneId, state);
    const LnnLaneManager *laneManager = GetLaneManager();
    int32_t ret = laneManager->lnnFreeLane(laneId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LANE_ID_APPLY_Test_001
* @tc.desc: apply laneId test
* @tc.type: FUNC
* @tc.require: I5FBFG
*/
HWTEST_F(LaneTest, LANE_ID_APPLY_Test_001, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneId = laneManager->applyLaneId(laneType);
    EXPECT_TRUE(laneId != INVALID_LANE_ID);
    int32_t ret = laneManager->lnnFreeLane(laneId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LANE_ID_APPLY_Test_002
* @tc.desc: apply laneId test
* @tc.type: FUNC
* @tc.require: I5FBFG
*/
HWTEST_F(LaneTest, LANE_ID_APPLY_Test_002, TestSize.Level1)
{
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneId;
    uint32_t *laneIdList = (uint32_t *)SoftBusCalloc(sizeof(uint32_t) * MAX_LANE_ID_NUM);
    if (laneIdList == nullptr) {
        return;
    }
    const LnnLaneManager *laneManager = GetLaneManager();
    uint32_t i;
    for (i = 0; i < MAX_LANE_ID_NUM; i++) {
        laneId = laneManager->applyLaneId(laneType);
        EXPECT_TRUE(laneId != INVALID_LANE_ID);
        laneIdList[i] = laneId;
    }
    laneId = laneManager->applyLaneId(laneType);
    EXPECT_TRUE(laneId == INVALID_LANE_ID);
    for (i = 0; i < MAX_LANE_ID_NUM; i++) {
        EXPECT_EQ(laneManager->lnnFreeLane(laneIdList[i]), SOFTBUS_OK);
    }
    SoftBusFree(laneIdList);
}

/*
* @tc.name: LANE_SELECT_Test_001
* @tc.desc: lane select fileTransLane by LNN
* @tc.type: FUNC
* @tc.require: I5FBFG
*/
HWTEST_F(LaneTest, LANE_SELECT_Test_001, TestSize.Level1)
{
    LanePreferredLinkList recommendList;
    (void)memset_s(&recommendList, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    uint32_t listNum = 0;
    LaneSelectParam selectParam;
    (void)memset_s(&selectParam, sizeof(LaneSelectParam), 0, sizeof(LaneSelectParam));
    selectParam.transType = LANE_T_FILE;
    selectParam.expectedBw = 0;
    int32_t ret = SelectLane(NODE_NETWORK_ID, &selectParam, &recommendList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(listNum, FILE_DEFAULT_LINK_NUM);
}

/*
* @tc.name: EXPECT_LANE_SELECT_BY_QOS_Test_001
* @tc.desc: lane select fileTransLane by qos
* @tc.type: FUNC
* @tc.require: I5FBFG
*/
HWTEST_F(LaneTest, EXPECT_LANE_SELECT_BY_QOS_Test_001, TestSize.Level1)
{
    LanePreferredLinkList recommendList;
    (void)memset_s(&recommendList, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    LaneSelectParam selectParam;
    (void)memset_s(&selectParam, sizeof(LaneSelectParam), 0, sizeof(LaneSelectParam));
    selectParam.transType = LANE_T_FILE;
    selectParam.qosRequire.minBW = DEFAULT_QOSINFO_MIN_BW;
    selectParam.qosRequire.maxLaneLatency = DEFAULT_QOSINFO_MAX_LATENCY;
    selectParam.qosRequire.minLaneLatency = DEFAULT_QOSINFO_MIN_LATENCY;
    int32_t ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_SELECT_Test_002
* @tc.desc: lane select by preferredLinkList
* @tc.type: FUNC
* @tc.require: I5FBFG
*/
HWTEST_F(LaneTest, LANE_SELECT_Test_002, TestSize.Level1)
{
    LanePreferredLinkList recommendList;
    (void)memset_s(&recommendList, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    uint32_t listNum = 0;
    LaneSelectParam selectParam;
    (void)memset_s(&selectParam, sizeof(LaneSelectParam), 0, sizeof(LaneSelectParam));
    selectParam.transType = LANE_T_BYTE;
    selectParam.expectedBw = 0;
    selectParam.list.linkTypeNum = LANE_PREFERRED_LINK_NUM;
    selectParam.list.linkType[0] = LANE_WLAN_5G;
    selectParam.list.linkType[1] = LANE_BR;
    int32_t ret = SelectLane(NODE_NETWORK_ID, &selectParam, &recommendList, &listNum);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    EXPECT_TRUE(listNum == LANE_PREFERRED_LINK_NUM);
}

/*
* @tc.name: EXPECT_LANE_SELECT_BY_QOS_Test_002
* @tc.desc: lane select BYTE TransLane by qos
* @tc.type: FUNC
* @tc.require: I5FBFG
*/
HWTEST_F(LaneTest, EXPECT_LANE_SELECT_BY_QOS_Test_002, TestSize.Level1)
{
    LanePreferredLinkList recommendList;
    (void)memset_s(&recommendList, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    LaneSelectParam selectParam;
    (void)memset_s(&selectParam, sizeof(LaneSelectParam), 0, sizeof(LaneSelectParam));
    selectParam.transType = LANE_T_BYTE;
    int32_t ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &recommendList);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LANE_LINK_Test_001
* @tc.desc: LaneLink of wlan5G
* @tc.type: FUNC
* @tc.require: I5FBFG
*/
HWTEST_F(LaneTest, LANE_LINK_Test_001, TestSize.Level1)
{
    ConnServerInit();
    InitLaneReliability();
    LinkRequest reqInfo;
    (void)memset_s(&reqInfo, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    int32_t ret = memcpy_s(reqInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID, strlen(NODE_NETWORK_ID));
    EXPECT_TRUE(ret == EOK);
    reqInfo.linkType = LANE_WLAN_2P4G;
    reqInfo.transType = LANE_T_BYTE;
    reqInfo.pid = DEFAULT_PID;
    LaneLinkCb linkCb = {
        .OnLaneLinkSuccess = NotifyWlanLinkSuccess,
        .OnLaneLinkFail = NotifyWlanLinkFail,
        .OnLaneLinkException = NotifyWlanLinkException,
    };
    uint32_t requestId = 0x5A5A;
    ret = BuildLink(&reqInfo, requestId, &linkCb);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ConnServerDeinit();
}

/*
* @tc.name: LANE_LINK_Test_002
* @tc.desc: LaneLink of BR
* @tc.type: FUNC
* @tc.require: I5FBFG
*/
HWTEST_F(LaneTest, LANE_LINK_Test_002, TestSize.Level1)
{
    LinkRequest reqInfo;
    (void)memset_s(&reqInfo, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    int32_t ret = memcpy_s(reqInfo.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID, strlen(NODE_NETWORK_ID));
    EXPECT_TRUE(ret == EOK);
    reqInfo.linkType = LANE_BR;
    reqInfo.transType = LANE_T_BYTE;
    reqInfo.pid = DEFAULT_PID;
    LaneLinkCb linkCb = {
        .OnLaneLinkSuccess = NotifyBrLinkSuccess,
        .OnLaneLinkFail = NotifyBrLinkFail,
        .OnLaneLinkException = NotifyBrLinkException,
    };
    uint32_t requestId = 0x5A5A;
    ret = BuildLink(&reqInfo, requestId, &linkCb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: TRANS_LANE_ALLOC_Test_001
* @tc.desc: TransLaneRequest test
* @tc.type: FUNC
* @tc.require: I5FBFG
*/
HWTEST_F(LaneTest, TRANS_LANE_ALLOC_Test_001, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    uint32_t laneId = laneManager->applyLaneId(LANE_TYPE_TRANS);
    EXPECT_TRUE(laneId != INVALID_LANE_ID);
    LaneRequestOption request;
    (void)memset_s(&request, sizeof(LaneRequestOption), 0, sizeof(LaneRequestOption));
    request.type = LANE_TYPE_TRANS;
    TransOption *trans = &request.requestInfo.trans;
    int32_t ret = memcpy_s(trans->networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID, sizeof(NODE_NETWORK_ID));
    EXPECT_TRUE(ret == EOK);
    trans->transType = LANE_T_RAW_STREAM;
    trans->pid = DEFAULT_PID;
    trans->qosRequire.minBW = DEFAULT_QOSINFO_MIN_BW + HIGH_BW;
    trans->qosRequire.maxLaneLatency = DEFAULT_QOSINFO_MAX_LATENCY;
    trans->qosRequire.minLaneLatency = DEFAULT_QOSINFO_MIN_LATENCY;
    ILaneListener listener = {
        .OnLaneRequestSuccess = OnLaneRequestSuccess,
        .OnLaneRequestFail = OnLaneRequestFail,
        .OnLaneStateChange = OnLaneStateChange,
    };
    ret = laneManager->lnnRequestLane(laneId, &request, &listener);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    trans->qosRequire.minBW = DEFAULT_QOSINFO_MIN_BW + LOW_BW;
    ret = laneManager->lnnRequestLane(laneId, &request, &listener);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    SoftBusSleepMs(5);
}
} // namespace OHOS
