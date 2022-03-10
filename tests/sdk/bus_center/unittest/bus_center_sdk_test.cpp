/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "softbus_bus_center.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_utils.h"

namespace OHOS {
using namespace testing::ext;

constexpr char TEST_PKG_NAME[] = "com.softbus.test";
constexpr char TEST_PKG_ERROR_NAME[] = "com.softbus.error.test";
constexpr int32_t DEFAULT_NODE_STATE_CB_NUM = 9;
constexpr uint8_t DEFAULT_LOCAL_DEVICE_TYPE_ID = 0;
constexpr int32_t ERRO_CAPDATA_LEN = 514;
static int32_t g_subscribeId = 0;
static int32_t g_publishId = 0;

class BusCenterSdkTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BusCenterSdkTest::SetUpTestCase()
{
}

void BusCenterSdkTest::TearDownTestCase()
{
}

void BusCenterSdkTest::SetUp()
{
}

void BusCenterSdkTest::TearDown()
{
}

static int32_t GetSubscribeId(void)
{
    g_subscribeId++;
    return g_subscribeId;
}

static int32_t GetPublishId(void)
{
    g_publishId++;
    return g_publishId;
}

static SubscribeInfo g_sInfo = {
    .subscribeId = 1,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata3",
    .dataLen = sizeof("capdata3")
};

static PublishInfo g_pInfo = {
    .publishId = 1,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata4",
    .dataLen = sizeof("capdata4")
};

static PublishInfo g_pInfo1 = {
    .publishId = 1,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .capability = "dvKit",
    .capabilityData = NULL,
    .dataLen = 0
};

static SubscribeInfo g_sInfo1 = {
    .subscribeId = 1,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capability = "hicall",
    .capabilityData = NULL,
    .dataLen = 0,
};

static void OnNodeOnline(NodeBasicInfo *info)
{
    (void)info;
}

static INodeStateCb g_nodeStateCb = {
    .events = EVENT_NODE_STATE_ONLINE,
    .onNodeOnline = OnNodeOnline,
};

static void OnJoinLNNDone(ConnectionAddr *addr, const char *networkId, int32_t retCode)
{
    (void)addr;
    (void)networkId;
    (void)retCode;
}

static void OnLeaveLNNDone(const char *networkId, int32_t retCode)
{
    (void)networkId;
    (void)retCode;
}

static void OnTimeSyncResult(const TimeSyncResultInfo *info, int32_t retCode)
{
    (void)info;
    (void)retCode;
}

static ITimeSyncCb g_timeSyncCb = {
    .onTimeSyncResult = OnTimeSyncResult,
};

static void TestDeviceFound(const DeviceInfo *device)
{
    printf("[client]TestDeviceFound\n");
}

static void TestDiscoverResult(int32_t refreshId, RefreshResult reason)
{
    printf("[client]TestDiscoverResult:%d\n", reason);
}

static void TestPublishResult(int publishId, PublishResult reason)
{
    printf("[client]TestPublishResult:%d\n", reason);
}

static IRefreshCallback g_refreshCb = {
    .OnDeviceFound = TestDeviceFound,
    .OnDiscoverResult = TestDiscoverResult
};

static IPublishCb g_publishCb = {
    .OnPublishResult = TestPublishResult
};

/*
* @tc.name: BUS_CENTER_SDK_Join_Lnn_Test_001
* @tc.desc: bus center JoinLNN interface exception test
* @tc.type: FUNC
* @tc.require: AR000FK6J4
*/
HWTEST_F(BusCenterSdkTest, BUS_CENTER_SDK_Join_Lnn_Test_001, TestSize.Level0)
{
    ConnectionAddr addr;

    EXPECT_TRUE(JoinLNN(NULL, &addr, OnJoinLNNDone) != SOFTBUS_OK);
    EXPECT_TRUE(JoinLNN(TEST_PKG_NAME, NULL, OnJoinLNNDone) != SOFTBUS_OK);
    EXPECT_TRUE(JoinLNN(TEST_PKG_NAME, &addr, NULL) != SOFTBUS_OK);
}

/*
* @tc.name: BUS_CENTER_SDK_Leave_Lnn_Test_001
* @tc.desc: bus center LeaveLNN interface exception test
* @tc.type: FUNC
* @tc.require: AR000FK6J4
*/
HWTEST_F(BusCenterSdkTest, BUS_CENTER_SDK_Leave_Lnn_Test_001, TestSize.Level0)
{
    char errNetIdLenMore[] = "012345678998765432100123456789987654321001234567899876543210abcde";
    char networkId[] = "0123456789987654321001234567899876543210012345678998765432100123";

    EXPECT_TRUE(LeaveLNN(NULL, networkId, OnLeaveLNNDone) != SOFTBUS_OK);
    EXPECT_TRUE(LeaveLNN(TEST_PKG_NAME, NULL, OnLeaveLNNDone) != SOFTBUS_OK);
    EXPECT_TRUE(LeaveLNN(TEST_PKG_NAME, networkId, NULL) != SOFTBUS_OK);
    EXPECT_TRUE(LeaveLNN(TEST_PKG_NAME, errNetIdLenMore, OnLeaveLNNDone) != SOFTBUS_OK);
}

/*
* @tc.name: BUS_CENTER_SDK_STATE_CB_Test_001
* @tc.desc: bus center node state callback reg and unreg interface test
* @tc.type: FUNC
* @tc.require: AR000FK6J4
*/
HWTEST_F(BusCenterSdkTest, BUS_CENTER_SDK_STATE_CB_Test_001, TestSize.Level0)
{
    EXPECT_TRUE(RegNodeDeviceStateCb(TEST_PKG_NAME, &g_nodeStateCb) == SOFTBUS_OK);
    EXPECT_TRUE(UnregNodeDeviceStateCb(&g_nodeStateCb) == SOFTBUS_OK);
}

/*
* @tc.name: BUS_CENTER_SDK_STATE_CB_Test_002
* @tc.desc: bus center node state callback reg and unreg upper limit interface test
* @tc.type: FUNC
* @tc.require: AR000FK6J4
*/
HWTEST_F(BusCenterSdkTest, BUS_CENTER_SDK_STATE_CB_Test_002, TestSize.Level0)
{
    int i;

    for (i = 0; i <= DEFAULT_NODE_STATE_CB_NUM; ++i) {
        EXPECT_TRUE(RegNodeDeviceStateCb(TEST_PKG_NAME, &g_nodeStateCb) == SOFTBUS_OK);
    }
    for (i = 0; i < DEFAULT_NODE_STATE_CB_NUM; ++i) {
        EXPECT_TRUE(UnregNodeDeviceStateCb(&g_nodeStateCb) == SOFTBUS_OK);
    }
}

/*
* @tc.name: BUS_CENTER_SDK_GET_ALL_NODE_INFO_Test_001
* @tc.desc: get all node info interface test
* @tc.type: FUNC
* @tc.require: AR000FK6J4
*/
HWTEST_F(BusCenterSdkTest, BUS_CENTER_SDK_GET_ALL_NODE_INFO_Test_001, TestSize.Level0)
{
    NodeBasicInfo *info = NULL;
    int infoNum;

    EXPECT_TRUE(GetAllNodeDeviceInfo(TEST_PKG_NAME, &info, &infoNum) == SOFTBUS_OK);
    EXPECT_TRUE(info == NULL);
    EXPECT_TRUE(infoNum == 0);
    if (info != NULL) {
        FreeNodeInfo(info);
    }
}

/*
* @tc.name: BUS_CENTER_SDK_GET_LOCAL_NODE_INFO_Test_001
* @tc.desc: get local info interface test
* @tc.type: FUNC
* @tc.require: AR000FK6J4
*/
HWTEST_F(BusCenterSdkTest, BUS_CENTER_SDK_GET_LOCAL_NODE_INFO_Test_001, TestSize.Level0)
{
    NodeBasicInfo info;

    EXPECT_TRUE(GetLocalNodeDeviceInfo(TEST_PKG_NAME, &info) == SOFTBUS_OK);
    EXPECT_TRUE(strlen(info.networkId) == (NETWORK_ID_BUF_LEN - 1));
    EXPECT_TRUE(info.deviceTypeId == DEFAULT_LOCAL_DEVICE_TYPE_ID);
}

/*
* @tc.name: BUS_CENTER_SDK_GET_NODE_KEY_INFO_Test_001
* @tc.desc: get node key info interface test
* @tc.type: FUNC
* @tc.require: AR000FK6J4
*/
HWTEST_F(BusCenterSdkTest, BUS_CENTER_SDK_GET_NODE_KEY_INFO_Test_001, TestSize.Level0)
{
    NodeBasicInfo info;
    char uuid[UUID_BUF_LEN] = {0};
    char udid[UDID_BUF_LEN] = {0};

    (void)memset_s(&info, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    EXPECT_TRUE(GetLocalNodeDeviceInfo(TEST_PKG_NAME, &info) == SOFTBUS_OK);
    EXPECT_TRUE(GetNodeKeyInfo(TEST_PKG_NAME, info.networkId, NODE_KEY_UDID,
        (uint8_t *)udid, UDID_BUF_LEN) == SOFTBUS_OK);
    EXPECT_TRUE(GetNodeKeyInfo(TEST_PKG_NAME, info.networkId, NODE_KEY_UUID,
        (uint8_t *)uuid, UUID_BUF_LEN) == SOFTBUS_OK);
    EXPECT_TRUE(strlen(uuid) == (UUID_BUF_LEN - 1));
}

/*
* @tc.name: BUS_CENTER_SDK_START_TIME_SYNC_Test_001
* @tc.desc: start time sync interface test
* @tc.type: FUNC
* @tc.require: AR000FN60G
*/
HWTEST_F(BusCenterSdkTest, BUS_CENTER_SDK_START_TIME_SYNC_Test_001, TestSize.Level0)
{
    char networkId[] = "0123456789987654321001234567899876543210012345678998765432100123";

    EXPECT_TRUE(StartTimeSync(NULL, networkId, LOW_ACCURACY, SHORT_PERIOD, &g_timeSyncCb) != SOFTBUS_OK);
    EXPECT_TRUE(StartTimeSync(TEST_PKG_NAME, NULL, LOW_ACCURACY, SHORT_PERIOD, &g_timeSyncCb) != SOFTBUS_OK);
    EXPECT_TRUE(StartTimeSync(TEST_PKG_NAME, networkId, LOW_ACCURACY, SHORT_PERIOD, &g_timeSyncCb) != SOFTBUS_OK);
    EXPECT_TRUE(StartTimeSync(TEST_PKG_NAME, networkId, LOW_ACCURACY, SHORT_PERIOD, NULL) != SOFTBUS_OK);
}

/*
* @tc.name: BUS_CENTER_SDK_START_TIME_SYNC_Test_002
* @tc.desc: start time sync interface test
* @tc.type: FUNC
* @tc.require: AR000FN60G
*/
HWTEST_F(BusCenterSdkTest, BUS_CENTER_SDK_START_TIME_SYNC_Test_002, TestSize.Level0)
{
    char networkId[] = "0123456789987654321001234567899876543210012345678998765432100123";

    EXPECT_TRUE(StopTimeSync(NULL, networkId) != SOFTBUS_OK);
    EXPECT_TRUE(StopTimeSync(TEST_PKG_NAME, NULL) != SOFTBUS_OK);
    EXPECT_TRUE(StopTimeSync(TEST_PKG_NAME, networkId) != SOFTBUS_OK);
}

/**
 * @tc.name: PublishLNNTest001
 * @tc.desc: Verify wrong parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterSdkTest, PublishLNNTest001, TestSize.Level0)
{
    int32_t ret = PublishLNN(NULL, &g_pInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);

    ret = PublishLNN(TEST_PKG_NAME, NULL, &g_publishCb);
    EXPECT_TRUE(ret != 0);

    ret = PublishLNN(TEST_PKG_NAME, &g_pInfo, NULL);
    EXPECT_TRUE(ret != 0);

    g_pInfo.medium = (ExchanageMedium)(COAP + 1);
    ret = PublishLNN(TEST_PKG_NAME, &g_pInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    g_pInfo.medium = COAP;

    g_pInfo.mode = (DiscoverMode)(DISCOVER_MODE_ACTIVE + 1);
    ret = PublishLNN(TEST_PKG_NAME, &g_pInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    g_pInfo.mode = DISCOVER_MODE_ACTIVE;

    g_pInfo.freq = (ExchangeFreq)(SUPER_HIGH + 1);
    ret = PublishLNN(TEST_PKG_NAME, &g_pInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    g_pInfo.freq = LOW;

    g_pInfo.capabilityData = NULL;
    ret = PublishLNN(TEST_PKG_NAME, &g_pInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    g_pInfo.capabilityData = (unsigned char *)"capdata1";

    g_pInfo.dataLen = ERRO_CAPDATA_LEN;
    ret = PublishLNN(TEST_PKG_NAME, &g_pInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    g_pInfo.dataLen = sizeof("capdata1");

    ret = PublishLNN(TEST_PKG_ERROR_NAME, &g_pInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: PublishLNNTest002
 * @tc.desc: Verify normal case
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterSdkTest, PublishLNNTest002, TestSize.Level0)
{
    int32_t ret;
    int tmpId1 = GetPublishId();
    int tmpId2 = GetPublishId();

    g_pInfo.publishId = tmpId1;
    ret = PublishLNN(TEST_PKG_NAME, &g_pInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    g_pInfo1.publishId = tmpId2;
    ret = PublishLNN(TEST_PKG_NAME, &g_pInfo1, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(TEST_PKG_NAME, tmpId1);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(TEST_PKG_NAME, tmpId2);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: RefreshLNNTest001
 * @tc.desc: Verify wrong parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterSdkTest, RefreshLNNTest001, TestSize.Level0)
{
    int ret;

    ret = RefreshLNN(NULL, &g_sInfo, &g_refreshCb);
    EXPECT_TRUE(ret != 0);

    ret = RefreshLNN(TEST_PKG_ERROR_NAME, &g_sInfo, &g_refreshCb);
    EXPECT_TRUE(ret != 0);

    ret = RefreshLNN(TEST_PKG_NAME, NULL, &g_refreshCb);
    EXPECT_TRUE(ret != 0);

    ret = RefreshLNN(TEST_PKG_NAME, &g_sInfo, NULL);
    EXPECT_TRUE(ret != 0);

    g_sInfo.medium = (ExchanageMedium)(COAP + 1);
    ret = RefreshLNN(TEST_PKG_NAME, &g_sInfo, &g_refreshCb);
    EXPECT_TRUE(ret != 0);
    g_sInfo.medium = COAP;

    g_sInfo.mode = (DiscoverMode)(DISCOVER_MODE_ACTIVE + 1);
    ret = RefreshLNN(TEST_PKG_NAME, &g_sInfo, &g_refreshCb);
    EXPECT_TRUE(ret != 0);
    g_sInfo.mode = DISCOVER_MODE_ACTIVE;

    g_sInfo.freq = (ExchangeFreq)(SUPER_HIGH + 1);
    ret = RefreshLNN(TEST_PKG_NAME, &g_sInfo, &g_refreshCb);
    EXPECT_TRUE(ret != 0);
    g_sInfo.freq = LOW;

    g_sInfo.capabilityData = NULL;
    ret = RefreshLNN(TEST_PKG_NAME, &g_sInfo, &g_refreshCb);
    EXPECT_TRUE(ret != 0);
    g_sInfo.capabilityData = (unsigned char *)"capdata1";

    g_sInfo.dataLen = ERRO_CAPDATA_LEN;
    ret = RefreshLNN(TEST_PKG_NAME, &g_sInfo, &g_refreshCb);
    EXPECT_TRUE(ret != 0);
    g_sInfo.dataLen = sizeof("capdata1");
}

/**
 * @tc.name: RefreshLNNTest002
 * @tc.desc: Verify normal case
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterSdkTest, RefreshLNNTest002, TestSize.Level0)
{
    int32_t ret;
    int tmpId1 = GetSubscribeId();
    int tmpId2 = GetSubscribeId();

    g_sInfo.subscribeId = tmpId1;
    ret = RefreshLNN(TEST_PKG_NAME, &g_sInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    g_sInfo1.subscribeId = tmpId2;
    ret = RefreshLNN(TEST_PKG_NAME, &g_sInfo1, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(TEST_PKG_NAME, tmpId1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(TEST_PKG_NAME, tmpId2);
    EXPECT_TRUE(ret == 0);
}
} // namespace OHOS
