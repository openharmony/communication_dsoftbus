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
#include "lnn_parameter_utils.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "softbus_error_code.h"
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
constexpr uint32_t LANE_PREFERRED_LINK_NUM = 2;
constexpr uint32_t DEFAULT_QOSINFO_MIN_BW = 10;
constexpr uint32_t DEFAULT_QOSINFO_MAX_LATENCY = 10000;
constexpr uint32_t DEFAULT_QOSINFO_MIN_LATENCY = 2500;
constexpr uint32_t LOW_BW = 500 * 1024;
constexpr uint32_t HIGH_BW = 160 * 1024 * 1024;
constexpr uint32_t LANE_REQ_ID_TYPE_SHIFT = 28;
constexpr uint64_t LANE_ID = 123456;

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
    int32_t ret = LnnInitDistributedLedger();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnInitLocalLedger();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnInitLnnLooper();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LooperInit();
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
    LooperDeinit();
    LnnDeinitLnnLooper();
    LnnDeinitLocalLedger();
    LnnDeinitDistributedLedger();
    (void)memset_s(&g_nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    GTEST_LOG_(INFO) << "LaneTest end";
}

void LaneTest::SetUp() { }

void LaneTest::TearDown() { }

static void ConstructRemoteNode(void)
{
    (void)memset_s(&g_nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    uint32_t cap = 0;
    LnnSetNetCapability(&cap, BIT_BR);
    LnnSetNetCapability(&cap, BIT_WIFI_P2P);
    LnnSetNetCapability(&cap, BIT_WIFI_24G);
    LnnSetNetCapability(&cap, BIT_WIFI_5G);
    g_nodeInfo.netCapacity = cap;
    int32_t ret = strncpy_s(g_nodeInfo.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID, strlen(NODE_NETWORK_ID));
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
    ret = LnnSetLocalNumInfo(
        NUM_KEY_NET_CAP, (1 << BIT_BR) | (1 << BIT_WIFI_24G) | (1 << BIT_WIFI_5G) | (1 << BIT_WIFI_P2P));
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

static void NotifyWlanLinkSuccess(uint32_t reqId, LaneLinkType linkType, const LaneLinkInfo *linkInfo)
{
    EXPECT_TRUE((linkInfo->type == LANE_WLAN_2P4G) || (linkInfo->type == LANE_WLAN_5G));
    EXPECT_EQ(linkInfo->linkInfo.wlan.connInfo.port, REMOTE_SESSION_PORT);
    EXPECT_STREQ(REMOTE_WLAN_IP, linkInfo->linkInfo.wlan.connInfo.addr);
    printf("WLAN: linkSuccess, reqId:0x%x\n", reqId);
}

static void NotifyWlanLinkFail(uint32_t reqId, int32_t reason, LaneLinkType linkType)
{
    printf("WLAN: reqId:0x%x, fail reason:%d, linkType:%d\n", reqId, reason, linkType);
}

static void NotifyBrLinkSuccess(uint32_t reqId, LaneLinkType linkType, const LaneLinkInfo *linkInfo)
{
    EXPECT_TRUE(linkInfo->type == LANE_BR);
    EXPECT_STREQ(linkInfo->linkInfo.br.brMac, NODE_BT_MAC);
    printf("BR: linkSuccess, reqId:0x%x\n", reqId);
}

static void NotifyBrLinkFail(uint32_t reqId, int32_t reason, LaneLinkType linkType)
{
    printf("BR: reqId:0x%x, fail reason:%d, linkType:%d\n", reqId, reason, linkType);
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

static void OnLaneAllocSuccess(uint32_t laneHandle, const LaneConnInfo *info)
{
    printf("LaneAllocSucc: laneReqId:0x%x, linkType:%s\n", laneHandle, GetLinkType(info->type));
    const LnnLaneManager *laneManager = GetLaneManager();
    int32_t ret = laneManager->lnnFreeLane(laneHandle);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

static void OnLaneAllocFail(uint32_t laneHandle, int32_t errCode)
{
    printf("LaneAllocFail: laneReqId:0x%x, reason:%d\n", laneHandle, errCode);
    const LnnLaneManager *laneManager = GetLaneManager();
    int32_t ret = laneManager->lnnFreeLane(laneHandle);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

static void OnLaneFreeSuccess(uint32_t laneHandle)
{
    GTEST_LOG_(INFO) << "free lane success, laneReqId=" << laneHandle;
}

static void OnLaneFreeFail(uint32_t laneHandle, int32_t errCode)
{
    GTEST_LOG_(INFO) << "free lane failed, laneReqId=" << laneHandle << ", errCode=" << errCode;
}

/*
 * @tc.name: LANE_REQ_ID_APPLY_Test_001
 * @tc.desc: apply laneReqId test
 * @tc.type: FUNC
 * @tc.require: I5FBFG
 */
HWTEST_F(LaneTest, LANE_REQ_ID_APPLY_Test_001, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);
    EXPECT_EQ(laneType, laneReqId >> LANE_REQ_ID_TYPE_SHIFT);
    FreeLaneReqId(laneReqId);
}

/*
 * @tc.name: LANE_REQ_ID_APPLY_Test_002
 * @tc.desc: apply laneReqId test
 * @tc.type: FUNC
 * @tc.require: I5FBFG
 */
HWTEST_F(LaneTest, LANE_REQ_ID_APPLY_Test_002, TestSize.Level1)
{
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId;
    uint32_t *laneReqIdList = (uint32_t *)SoftBusCalloc(sizeof(uint32_t) * MAX_LANE_REQ_ID_NUM);
    if (laneReqIdList == nullptr) {
        return;
    }
    const LnnLaneManager *laneManager = GetLaneManager();
    uint32_t i;
    for (i = 0; i < MAX_LANE_REQ_ID_NUM; i++) {
        laneReqId = laneManager->lnnGetLaneHandle(laneType);
        EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);
        laneReqIdList[i] = laneReqId;
    }
    laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId == INVALID_LANE_REQ_ID);
    for (i = 0; i < MAX_LANE_REQ_ID_NUM; i++) {
        FreeLaneReqId(laneReqIdList[i]);
    }
    SoftBusFree(laneReqIdList);
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
    EXPECT_EQ(listNum, 4);
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
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(listNum, 2);
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
    EXPECT_EQ(ret, SOFTBUS_OK);
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
        .onLaneLinkSuccess = NotifyWlanLinkSuccess,
        .onLaneLinkFail = NotifyWlanLinkFail,
    };
    uint32_t requestId = 0x5A5A;
    ret = BuildLink(&reqInfo, requestId, &linkCb);
    EXPECT_EQ(ret, SOFTBUS_TCPCONNECTION_SOCKET_ERR);
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
    EXPECT_EQ(ret, EOK);
    reqInfo.linkType = LANE_BR;
    reqInfo.transType = LANE_T_BYTE;
    reqInfo.pid = DEFAULT_PID;
    LaneLinkCb linkCb = {
        .onLaneLinkSuccess = NotifyBrLinkSuccess,
        .onLaneLinkFail = NotifyBrLinkFail,
    };
    uint32_t requestId = 0x5A5A;
    ret = BuildLink(&reqInfo, requestId, &linkCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
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
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(LANE_TYPE_TRANS);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);
    LaneAllocInfo allocInfo;
    (void)memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo));
    allocInfo.type = LANE_TYPE_TRANS;
    allocInfo.transType = LANE_T_RAW_STREAM;
    int32_t ret = memcpy_s(allocInfo.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID, sizeof(NODE_NETWORK_ID));
    EXPECT_TRUE(ret == EOK);
    allocInfo.pid = DEFAULT_PID;
    allocInfo.qosRequire.minBW = DEFAULT_QOSINFO_MIN_BW + HIGH_BW;
    allocInfo.qosRequire.maxLaneLatency = DEFAULT_QOSINFO_MAX_LATENCY;
    allocInfo.qosRequire.minLaneLatency = DEFAULT_QOSINFO_MIN_LATENCY;
    LaneAllocListener listener = {
        .onLaneAllocSuccess = OnLaneAllocSuccess,
        .onLaneAllocFail = OnLaneAllocFail,
        .onLaneFreeSuccess = OnLaneFreeSuccess,
        .onLaneFreeFail = OnLaneFreeFail,
    };
    ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &listener);
    EXPECT_EQ(ret, SOFTBUS_OK);

    laneReqId = laneManager->lnnGetLaneHandle(LANE_TYPE_TRANS);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);
    allocInfo.qosRequire.minBW = DEFAULT_QOSINFO_MIN_BW + LOW_BW;
    ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(5);
}

/*
 * @tc.name: ADD_LANE_RESOURCE_TO_POOL_Test_001
 * @tc.desc: AddLaneResourceToPool test
 * @tc.type: FUNC
 * @tc.require: I5FBFG
 */
HWTEST_F(LaneTest, ADD_LANE_RESOURCE_TO_POOL_Test_001, TestSize.Level1)
{
    LaneLinkInfo linkInfo = {
        .type = LANE_HML,
    };
    EXPECT_EQ(strncpy_s(linkInfo.peerUdid, UDID_BUF_LEN, NODE_UDID, UDID_BUF_LEN), EOK);
    EXPECT_EQ(strncpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, REMOTE_WLAN_IP, IP_LEN), EOK);
    EXPECT_EQ(AddLaneResourceToPool(&linkInfo, LANE_ID, true), SOFTBUS_OK);
    linkInfo.type = LANE_BR;
    EXPECT_EQ(strncpy_s(linkInfo.linkInfo.br.brMac, BT_MAC_LEN, NODE_BT_MAC, BT_MAC_LEN), EOK);
    EXPECT_EQ(AddLaneResourceToPool(&linkInfo, LANE_ID, true), SOFTBUS_OK);
    linkInfo.type = LANE_BLE;
    EXPECT_EQ(strncpy_s(linkInfo.linkInfo.ble.bleMac, BT_MAC_LEN, NODE_BT_MAC, BT_MAC_LEN), EOK);
    EXPECT_EQ(AddLaneResourceToPool(&linkInfo, LANE_ID, true), SOFTBUS_OK);
    linkInfo.type = LANE_BLE_DIRECT;
    EXPECT_EQ(
        strncpy_s(linkInfo.linkInfo.bleDirect.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID, NETWORK_ID_BUF_LEN),
        EOK);
    EXPECT_EQ(AddLaneResourceToPool(&linkInfo, LANE_ID, true), SOFTBUS_OK);
    linkInfo.type = LANE_WLAN_5G;
    EXPECT_EQ(AddLaneResourceToPool(&linkInfo, LANE_ID, true), SOFTBUS_OK);
    EXPECT_EQ(AddLaneResourceToPool(nullptr, LANE_ID, true), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(AddLaneResourceToPool(&linkInfo, INVALID_LANE_ID, true), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: CHECK_LANE_RESOURCE_NUM_BY_LINK_TYPE_Test_001
 * @tc.desc: CheckLaneResourceNumByLinkType test
 * @tc.type: FUNC
 * @tc.require: I5FBFG
 */
HWTEST_F(LaneTest, CHECK_LANE_RESOURCE_NUM_BY_LINK_TYPE_Test_001, TestSize.Level1)
{
    const char *peerUdid = "123456ABCDEF";
    EXPECT_EQ(InitLaneLink(), SOFTBUS_OK);
    int32_t laneNum = 0;
    EXPECT_EQ(CheckLaneResourceNumByLinkType(peerUdid, LANE_HML, &laneNum), SOFTBUS_NOT_FIND);
    EXPECT_EQ(CheckLaneResourceNumByLinkType(nullptr, LANE_HML, &laneNum), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(CheckLaneResourceNumByLinkType(peerUdid, LANE_LINK_TYPE_BUTT, &laneNum), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(CheckLaneResourceNumByLinkType(peerUdid, LANE_HML_RAW, &laneNum), SOFTBUS_NOT_FIND);
}

/*
 * @tc.name: UPDATE_LANE_RESOURCE_LANE_ID_Test_001
 * @tc.desc: UpdateLaneResourceLaneId test
 * @tc.type: FUNC
 * @tc.require: I5FBFG
 */
HWTEST_F(LaneTest, UPDATE_LANE_RESOURCE_LANE_ID_Test_001, TestSize.Level1)
{
    uint64_t oldLaneId = LANE_ID;
    uint64_t newLaneId = LANE_ID + 1;
    const char *peerUdid = "123456ABCDEF";
    const char *peerUdid1 = "123456ABCDEFGHIGK";
    EXPECT_EQ(UpdateLaneResourceLaneId(oldLaneId, newLaneId, peerUdid), SOFTBUS_NOT_FIND);
    EXPECT_EQ(UpdateLaneResourceLaneId(oldLaneId, newLaneId, peerUdid1), SOFTBUS_NOT_FIND);
    EXPECT_EQ(UpdateLaneResourceLaneId(INVALID_LANE_ID, newLaneId, peerUdid1), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateLaneResourceLaneId(oldLaneId, INVALID_LANE_ID, peerUdid1), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateLaneResourceLaneId(oldLaneId, INVALID_LANE_ID, nullptr), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: DESTROY_LINK_Test_001
 * @tc.desc: DestroyLink test
 * @tc.type: FUNC
 * @tc.require: I5FBFG
 */
HWTEST_F(LaneTest, DESTROY_LINK_Test_001, TestSize.Level1)
{
    const char *networkId = "111122223333abcdef";
    uint32_t laneReqId = LANE_REQ_ID_TYPE_SHIFT;
    EXPECT_EQ(DestroyLink(networkId, laneReqId, LANE_P2P), SOFTBUS_LANE_RESOURCE_NOT_FOUND);
    EXPECT_EQ(DestroyLink(nullptr, laneReqId, LANE_P2P), SOFTBUS_INVALID_PARAM);
}
} // namespace OHOS
