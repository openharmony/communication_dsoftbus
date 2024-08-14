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

#include "softbus_adapter_mem.h"
#include "trans_channel_common.c"
#include "trans_lane_manager.c"

using namespace testing::ext;
namespace OHOS {
#define TEST_SESSION_NAME "com.softbus.transmission.test"
#define TEST_CONN_IP "192.168.8.1"
#define TEST_AUTH_PORT 6000
#define TEST_AUTH_DATA "test auth message data"
#define TEST_PKG_NAME "com.test.trans.demo.pkgname"

static SessionAttribute g_sessionAttr[] = {
    {.dataType = TYPE_MESSAGE},
    {.dataType = TYPE_BYTES},
    {.dataType = TYPE_FILE},
    {.dataType = TYPE_STREAM},
    {.dataType = LANE_T_BUTT},
};
class TransLaneManagerTest : public testing::Test {
public:
    TransLaneManagerTest()
    {}
    ~TransLaneManagerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransLaneManagerTest::SetUpTestCase(void)
{}

void TransLaneManagerTest::TearDownTestCase(void)
{}

/**
 * @tc.name: GetTransSessionInfoByLane001
 * @tc.desc: GetTransSessionInfoByLane, use the wrong parameter.
 * @tc.desc: ConvertLaneLinkTypeToDumper, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneManagerTest, GetTransSessionInfoByLane001, TestSize.Level1)
{
    TransLaneInfo *laneItem = (TransLaneInfo *)SoftBusCalloc(sizeof(TransLaneInfo));
    ASSERT_TRUE(laneItem != nullptr);

    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);

    TransDumpLaneLinkType transDumpLaneLinkType;

    GetTransSessionInfoByLane(laneItem, appInfo);

    transDumpLaneLinkType = ConvertLaneLinkTypeToDumper(LANE_BR);
    EXPECT_EQ(DUMPER_LANE_BR, transDumpLaneLinkType);

    transDumpLaneLinkType = ConvertLaneLinkTypeToDumper(LANE_BLE);
    EXPECT_EQ(DUMPER_LANE_BLE, transDumpLaneLinkType);

    transDumpLaneLinkType = ConvertLaneLinkTypeToDumper(LANE_P2P);
    EXPECT_EQ(DUMPER_LANE_P2P, transDumpLaneLinkType);

    transDumpLaneLinkType = ConvertLaneLinkTypeToDumper(LANE_WLAN_2P4G);
    EXPECT_EQ(DUMPER_LANE_WLAN, transDumpLaneLinkType);

    transDumpLaneLinkType = ConvertLaneLinkTypeToDumper(LANE_WLAN_5G);
    EXPECT_EQ(DUMPER_LANE_WLAN, transDumpLaneLinkType);

    transDumpLaneLinkType = ConvertLaneLinkTypeToDumper(LANE_ETH);
    EXPECT_EQ(DUMPER_LANE_ETH, transDumpLaneLinkType);

    transDumpLaneLinkType = ConvertLaneLinkTypeToDumper(LANE_LINK_TYPE_BUTT);
    EXPECT_EQ(DUMPER_LANE_LINK_TYPE_BUTT, transDumpLaneLinkType);
}

/**
 * @tc.name: TransChannelInit001
 * @tc.desc: TransChannelInit001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneManagerTest, TransChannelInit001, TestSize.Level1)
{
    int32_t ret = TransLaneMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransLaneMgrDeinit();
}

/**
 * @tc.name: TransLaneChannelForEachShowInfo001
 * @tc.desc: TransLaneChannelForEachShowInfo, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneManagerTest, TransLaneChannelForEachShowInfo001, TestSize.Level1)
{
    int fd = 1;
    TransLaneMgrDeinit();
    TransLaneChannelForEachShowInfo(fd);

    int32_t ret = TransLaneMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransLaneChannelForEachShowInfo(fd);
}

/**
 * @tc.name: TransLaneMgrAddLane001
 * @tc.desc: TransLaneMgrAddLane001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneManagerTest, TransLaneMgrAddLane001, TestSize.Level1)
{
    uint32_t laneHandle = 1;
    bool isQosLane = false;
    TransInfo transInfo = {
        .channelId = 2112,
        .channelType = 2112
    };
    AppInfoData *myData = (AppInfoData *)SoftBusCalloc(sizeof(AppInfoData));
    ASSERT_TRUE(myData != nullptr);
    LaneConnInfo *connInfo = (LaneConnInfo *)SoftBusCalloc(sizeof(LaneConnInfo));
    ASSERT_TRUE(connInfo != nullptr);

    TransLaneMgrDeinit();
    int32_t ret = TransLaneMgrAddLane(&transInfo, connInfo, laneHandle, isQosLane, myData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransLaneMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransLaneMgrAddLane(&transInfo, connInfo, laneHandle, isQosLane, myData);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransLaneMgrDeinit();

    ret = TransLaneMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransLaneMgrAddLane(&transInfo, NULL, laneHandle, isQosLane, myData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    transInfo.channelId = 1;
    transInfo.channelType = 2;
    ret = TransLaneMgrAddLane(&transInfo, connInfo, laneHandle, isQosLane, myData);
    EXPECT_EQ(SOFTBUS_OK, ret);
    if (myData != NULL) {
        SoftBusFree(myData);
    }
    if (connInfo != NULL) {
        SoftBusFree(connInfo);
    }
}

/**
 * @tc.name: TransLaneMgrDelLane001
 * @tc.desc: TransLaneMgrDelLane001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneManagerTest, TransLaneMgrDelLane001, TestSize.Level1)
{
    int32_t channelId = 12;
    int32_t channelType = 22;
    TRANS_LOGI(TRANS_TEST, "TransLaneMgrDelLane001 start");
    TransLaneMgrDeinit();
    int32_t ret = TransLaneMgrDelLane(channelId, channelType, true);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    ret = TransLaneMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransLaneMgrDeinit();
    channelId = -1;
    channelType = 9999999;
    ret = TransLaneMgrDelLane(channelId, channelType, true);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    TRANS_LOGI(TRANS_TEST, "TransLaneMgrDelLane001 end");
}

/**
 * @tc.name: TransLaneMgrDeathCallback001
 * @tc.desc: TransLaneMgrDeathCallback001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneManagerTest, TransLaneMgrDeathCallback001, TestSize.Level1)
{
    int32_t pid = 2112;
    const char *pkgName = TEST_PKG_NAME;

    TransLaneMgrDeinit();
    TransLaneMgrDeathCallback(pkgName, pid);

    int32_t ret = TransLaneMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    pid = -1;
    TransLaneMgrDeathCallback(pkgName, pid);
    TransLaneMgrDeinit();
}

/**
 * @tc.name: TransGetLaneReqIdByChannelId001
 * @tc.desc: TransGetLaneReqIdByChannelId001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneManagerTest, TransGetLaneReqIdByChannelId001, TestSize.Level1)
{
    int32_t channelId = 2112;
    uint32_t laneHandle = 22;

    int32_t ret = TransGetLaneHandleByChannelId(channelId, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransLaneMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    channelId = -1;
    ret = TransGetLaneHandleByChannelId(channelId, &laneHandle);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
}

/**
 * @tc.name: TransGetChannelInfoByLaneReqId001
 * @tc.desc: TransGetChannelInfoByLaneReqId001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneManagerTest, TransGetChannelInfoByLaneReqId001, TestSize.Level1)
{
    int32_t channelId = 2112;
    int32_t channelType = 2112;
    uint32_t laneHandle = 0;

    int32_t ret = TransLaneMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransLaneMgrDeinit();

    ret = TransGetChannelInfoByLaneHandle(laneHandle, NULL, &channelType);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransGetChannelInfoByLaneHandle(laneHandle, &channelId, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransLaneMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransGetChannelInfoByLaneHandle(laneHandle, &channelId, &channelType);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
}

/**
 * @tc.name: TransSocketChannelInfoTest001
 * @tc.desc: TransSocketChannelInfoTest001.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneManagerTest, TransSocketChannelInfoTest001, TestSize.Level1)
{
    int32_t ret = TransSocketLaneMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    char sessionName[SESSION_NAME_SIZE_MAX] = "testSessionName";
    int32_t sessionId = 1;
    ret = TransAddSocketChannelInfo(
        sessionName, sessionId, INVALID_CHANNEL_ID, CHANNEL_TYPE_BUTT, CORE_SESSION_STATE_INIT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CoreSessionState state;
    ret = TransGetSocketChannelStateBySession(sessionName, sessionId, &state);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(state, CORE_SESSION_STATE_INIT);
    int32_t channelId = 1;
    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;
    ret = TransUpdateSocketChannelInfoBySession(sessionName, sessionId, channelId, channelType);
    EXPECT_EQ(SOFTBUS_OK, ret);
    uint32_t lanHandele = 1;
    ret = TransUpdateSocketChannelLaneInfoBySession(sessionName, sessionId, lanHandele, false, true);
    EXPECT_EQ(SOFTBUS_OK, ret);
    lanHandele = INVALID_CHANNEL_ID;
    ret = TransGetSocketChannelLaneInfoBySession(sessionName, sessionId, &lanHandele, NULL, NULL);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(lanHandele, 1);
    ret = TransGetSocketChannelStateByChannel(channelId, channelType, &state);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(state, CORE_SESSION_STATE_INIT);
    ret = TransSetSocketChannelStateByChannel(channelId, channelType, CORE_SESSION_STATE_CHANNEL_OPENED);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransGetSocketChannelStateBySession(sessionName, sessionId, &state);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(state, CORE_SESSION_STATE_CHANNEL_OPENED);
    ret = TransSetSocketChannelStateBySession(sessionName, sessionId, CORE_SESSION_STATE_CANCELLING);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransGetSocketChannelStateByChannel(channelId, channelType, &state);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(state, CORE_SESSION_STATE_CANCELLING);
    int32_t pid = -1;
    ret = TransGetPidFromSocketChannelInfoBySession(sessionName, sessionId, &pid);
    EXPECT_EQ(pid, 0);
    ret = TransDeleteSocketChannelInfoByChannel(channelId, channelType);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransDeleteSocketChannelInfoBySession(sessionName, sessionId);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = TransDeleteSocketChannelInfoByPid(pid);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    TransSocketLaneMgrDeinit();
    ret = TransAddSocketChannelInfo(
        sessionName, sessionId, INVALID_CHANNEL_ID, CHANNEL_TYPE_BUTT, CORE_SESSION_STATE_INIT);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/**
 * @tc.name: CopyAppInfoFromSessionParam001
 * @tc.desc: CopyAppInfoFromSessionParam, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneManagerTest, CopyAppInfoFromSessionParam001, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);

    SessionParam *sessionParam = (SessionParam *)SoftBusCalloc(sizeof(SessionParam));
    EXPECT_TRUE(sessionParam != NULL);
    (void)memcpy_s(appInfo->peerData.deviceId, DEVICE_ID_SIZE_MAX, "test", DEVICE_ID_SIZE_MAX);

    int32_t ret = CopyAppInfoFromSessionParam(appInfo, sessionParam);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftBusFree(appInfo);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransGetChannelType001
 * @tc.desc: TransGetChannelType, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneManagerTest, TransGetChannelType001, TestSize.Level1)
{
    SessionParam *param = (SessionParam *)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(param != nullptr);

    int tmp = 0;
    param->attr = &g_sessionAttr[tmp];

    LaneConnInfo *connInfo = (LaneConnInfo *)SoftBusCalloc(sizeof(LaneConnInfo));
    ASSERT_TRUE(connInfo != nullptr);

    TransInfo *transInfo = (TransInfo *)SoftBusCalloc(sizeof(TransInfo));
    ASSERT_TRUE(transInfo != nullptr);

    transInfo->channelType = TransGetChannelType(NULL, connInfo->type);
    EXPECT_EQ(CHANNEL_TYPE_BUTT, transInfo->channelType);

    connInfo->type = LANE_BR;
    transInfo->channelType = TransGetChannelType(param, connInfo->type);
    EXPECT_EQ(CHANNEL_TYPE_PROXY, transInfo->channelType);

    connInfo->type = LANE_P2P;
    tmp = 2;
    param->attr = &g_sessionAttr[tmp];
    transInfo->channelType = TransGetChannelType(param, connInfo->type);
    EXPECT_EQ(CHANNEL_TYPE_UDP, transInfo->channelType);

    tmp = 0;
    param->attr = &g_sessionAttr[tmp];
    connInfo->type = LANE_BR;
    transInfo->channelType = TransGetChannelType(param, connInfo->type);
    EXPECT_EQ(CHANNEL_TYPE_PROXY, transInfo->channelType);
    connInfo->type = LANE_P2P;

    tmp = 1;
    param->attr = &g_sessionAttr[tmp];
    transInfo->channelType = TransGetChannelType(param, connInfo->type);
    EXPECT_EQ(CHANNEL_TYPE_TCP_DIRECT, transInfo->channelType);

    SoftBusFree(param);
    SoftBusFree(connInfo);
    SoftBusFree(transInfo);
}

/**
 * @tc.name: FindConfigType001
 * @tc.desc: FindConfigType001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneManagerTest, FindConfigType001, TestSize.Level1)
{
    int32_t channelType = 0;
    int32_t businessType = 0;

    int32_t ret = FindConfigType(channelType, businessType);
    EXPECT_EQ(SOFTBUS_CONFIG_TYPE_MAX, ret);

    channelType = CHANNEL_TYPE_AUTH;
    businessType = BUSINESS_TYPE_BYTE;
    ret = FindConfigType(channelType, businessType);
    EXPECT_EQ(SOFTBUS_INT_AUTH_MAX_BYTES_LENGTH, ret);
}
} // OHOS
