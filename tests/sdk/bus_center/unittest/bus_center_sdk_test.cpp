/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include "bus_center_server_proxy.h"
#include "bus_center_server_proxy_standard.h"
#include "client_bus_center_manager.h"
#include "softbus_access_token_test.h"
#include "softbus_bus_center.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_server_frame.h"
#include "softbus_utils.h"

#define CAPABILITY_1 "capdata1"
#define CAPABILITY_3 "capdata3"
#define CAPABILITY_4 "capdata4"

namespace OHOS {
using namespace testing::ext;

constexpr char TEST_PKG_NAME[] = "com.softbus.test";
constexpr char TEST_PKG_NAME_1[] = "com.softbus.test1";
constexpr int32_t DEFAULT_NODE_STATE_CB_NUM = 9;
constexpr uint8_t DEFAULT_LOCAL_DEVICE_TYPE_ID_1 = 0;
constexpr uint8_t DEFAULT_LOCAL_DEVICE_TYPE_ID_2 = 14;
constexpr uint8_t DEFAULT_LOCAL_DEVICE_TYPE_ID_3 = 17;
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
    SetAccessTokenPermission("busCenterTest");
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
    .capabilityData = (unsigned char *)CAPABILITY_3,
    .dataLen = strlen(CAPABILITY_3)
};

static PublishInfo g_pInfo = {
    .publishId = 1,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)CAPABILITY_4,
    .dataLen = strlen(CAPABILITY_4)
};

static PublishInfo g_pInfo1 = {
    .publishId = 1,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .capability = "dvKit",
    .capabilityData = nullptr,
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
    .capabilityData = nullptr,
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

static void TestPublishResult(int32_t publishId, PublishResult reason)
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

static void OnDataLevelChanged(const char *networkId, const DataLevel dataLevel)
{
    (void)networkId;
    (void)dataLevel;
}

static IDataLevelCb g_dataLevelCb = {
    .onDataLevelChanged = OnDataLevelChanged
};
/*
 * @tc.name: BUS_CENTER_SDK_Join_Lnn_Test_001
 * @tc.desc: bus center JoinLNN interface exception test
 * @tc.type: FUNC
 * @tc.require: I5I7B9
 */
HWTEST_F(BusCenterSdkTest, BUS_CENTER_SDK_Join_Lnn_Test_001, TestSize.Level0)
{
    ConnectionAddr addr;

    EXPECT_TRUE(JoinLNN(nullptr, &addr, OnJoinLNNDone) != SOFTBUS_OK);
    EXPECT_TRUE(JoinLNN(TEST_PKG_NAME, nullptr, OnJoinLNNDone) != SOFTBUS_OK);
    EXPECT_TRUE(JoinLNN(TEST_PKG_NAME, &addr, nullptr) != SOFTBUS_OK);
}

/*
 * @tc.name: BUS_CENTER_SDK_Leave_Lnn_Test_001
 * @tc.desc: bus center LeaveLNN interface exception test
 * @tc.type: FUNC
 * @tc.require: I5I7B9
 */
HWTEST_F(BusCenterSdkTest, BUS_CENTER_SDK_Leave_Lnn_Test_001, TestSize.Level0)
{
    char errNetIdLenMore[] = "012345678998765432100123456789987654321001234567899876543210abcde";
    char networkId[] = "0123456789987654321001234567899876543210012345678998765432100123";

    EXPECT_TRUE(LeaveLNN(nullptr, networkId, OnLeaveLNNDone) != SOFTBUS_OK);
    EXPECT_TRUE(LeaveLNN(TEST_PKG_NAME, nullptr, OnLeaveLNNDone) != SOFTBUS_OK);
    EXPECT_TRUE(LeaveLNN(TEST_PKG_NAME, networkId, nullptr) != SOFTBUS_OK);
    EXPECT_TRUE(LeaveLNN(TEST_PKG_NAME, errNetIdLenMore, OnLeaveLNNDone) != SOFTBUS_OK);
}

/*
 * @tc.name: BUS_CENTER_SDK_STATE_CB_Test_001
 * @tc.desc: bus center node state callback reg and unreg interface test
 * @tc.type: FUNC
 * @tc.require: I5I7B9
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
 * @tc.require: I5I7B9
 */
HWTEST_F(BusCenterSdkTest, BUS_CENTER_SDK_STATE_CB_Test_002, TestSize.Level0)
{
    int32_t i;

    for (i = 0; i <= DEFAULT_NODE_STATE_CB_NUM; ++i) {
        EXPECT_TRUE(RegNodeDeviceStateCb(TEST_PKG_NAME, &g_nodeStateCb) == SOFTBUS_OK);
    }
    for (i = 0; i < DEFAULT_NODE_STATE_CB_NUM; ++i) {
        EXPECT_TRUE(UnregNodeDeviceStateCb(&g_nodeStateCb) == SOFTBUS_OK);
    }
}

/*
 * @tc.name: BUS_CENTER_SDK_STATE_CB_Test_003
 * @tc.desc: bus center node state callback reg param check
 * @tc.type: FUNC
 * @tc.require: I5I7B9
 */
HWTEST_F(BusCenterSdkTest, BUS_CENTER_SDK_STATE_CB_Test_003, TestSize.Level0)
{
    EXPECT_EQ(RegNodeDeviceStateCb(nullptr, &g_nodeStateCb), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(RegNodeDeviceStateCb(TEST_PKG_NAME, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UnregNodeDeviceStateCb(nullptr), SOFTBUS_INVALID_PARAM);

    INodeStateCb nodeStateCb = {};
    nodeStateCb.events = 0;
    EXPECT_EQ(RegNodeDeviceStateCb(TEST_PKG_NAME, nullptr), SOFTBUS_INVALID_PARAM);
    nodeStateCb.events = EVENT_NODE_STATE_ONLINE;
    EXPECT_EQ(RegNodeDeviceStateCb(TEST_PKG_NAME, nullptr), SOFTBUS_INVALID_PARAM);
    nodeStateCb.events = EVENT_NODE_STATE_ONLINE;
    nodeStateCb.onNodeOnline = OnNodeOnline;
    EXPECT_EQ(RegNodeDeviceStateCb(TEST_PKG_NAME, &nodeStateCb), SOFTBUS_OK);

    nodeStateCb.events = EVENT_NODE_STATE_OFFLINE;
    EXPECT_EQ(RegNodeDeviceStateCb(TEST_PKG_NAME, nullptr), SOFTBUS_INVALID_PARAM);
    nodeStateCb.events = EVENT_NODE_STATE_INFO_CHANGED;
    EXPECT_EQ(RegNodeDeviceStateCb(TEST_PKG_NAME, nullptr), SOFTBUS_INVALID_PARAM);
    nodeStateCb.events = EVENT_NODE_STATUS_CHANGED;
    EXPECT_EQ(RegNodeDeviceStateCb(TEST_PKG_NAME, nullptr), SOFTBUS_INVALID_PARAM);
    nodeStateCb.events = EVENT_NODE_HICHAIN_PROOF_EXCEPTION;
    EXPECT_EQ(RegNodeDeviceStateCb(TEST_PKG_NAME, nullptr), SOFTBUS_INVALID_PARAM);
    nodeStateCb.events = EVENT_NODE_STATE_ONLINE & EVENT_NODE_HICHAIN_PROOF_EXCEPTION;
    EXPECT_EQ(RegNodeDeviceStateCb(TEST_PKG_NAME, nullptr), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: BUS_CENTER_SDK_GET_ALL_NODE_INFO_Test_001
 * @tc.desc: get all node info interface test
 * @tc.type: FUNC
 * @tc.require: I5I7B9
 */
HWTEST_F(BusCenterSdkTest, BUS_CENTER_SDK_GET_ALL_NODE_INFO_Test_001, TestSize.Level0)
{
    NodeBasicInfo *info = nullptr;
    int32_t infoNum;

    EXPECT_EQ(GetAllNodeDeviceInfo(nullptr, &info, &infoNum), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(GetAllNodeDeviceInfo(TEST_PKG_NAME, nullptr, &infoNum), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(GetAllNodeDeviceInfo(TEST_PKG_NAME, &info, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(GetAllNodeDeviceInfo(TEST_PKG_NAME, &info, &infoNum), SOFTBUS_OK);
    if (infoNum == 0) {
        EXPECT_TRUE(info == nullptr);
    } else {
        EXPECT_TRUE(info != nullptr);
    }
    if (info != nullptr) {
        FreeNodeInfo(info);
    }
}

/*
 * @tc.name: BUS_CENTER_SDK_GET_LOCAL_NODE_INFO_Test_001
 * @tc.desc: get local info interface test
 * @tc.type: FUNC
 * @tc.require: I5I7B9
 */
HWTEST_F(BusCenterSdkTest, BUS_CENTER_SDK_GET_LOCAL_NODE_INFO_Test_001, TestSize.Level0)
{
    NodeBasicInfo info;

    EXPECT_EQ(GetLocalNodeDeviceInfo(nullptr, &info), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(GetLocalNodeDeviceInfo(TEST_PKG_NAME, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(GetLocalNodeDeviceInfo(TEST_PKG_NAME, &info), SOFTBUS_OK);
    EXPECT_EQ(strlen(info.networkId), (NETWORK_ID_BUF_LEN - 1));
    EXPECT_TRUE(info.deviceTypeId == DEFAULT_LOCAL_DEVICE_TYPE_ID_1 ||
        info.deviceTypeId == DEFAULT_LOCAL_DEVICE_TYPE_ID_2 ||
        info.deviceTypeId == DEFAULT_LOCAL_DEVICE_TYPE_ID_3);
}

/*
 * @tc.name: BUS_CENTER_SDK_GET_NODE_KEY_INFO_Test_001
 * @tc.desc: get node key info interface test
 * @tc.type: FUNC
 * @tc.require: I5I7B9
 */
HWTEST_F(BusCenterSdkTest, BUS_CENTER_SDK_GET_NODE_KEY_INFO_Test_001, TestSize.Level0)
{
    NodeBasicInfo info;
    NodeBasicInfo *remoteNodeInfo = nullptr;
    int32_t infoNum = 0;
    char uuid[UUID_BUF_LEN] = {0};
    char udid[UDID_BUF_LEN] = {0};
    char brMac[BT_MAC_LEN] = {0};
    char ipAddr[IP_STR_MAX_LEN] = {0};
    char deviceName[DEVICE_NAME_BUF_LEN] = {0};
    int32_t netCapacity = 0;
    int32_t netType = 0;

    (void)memset_s(&info, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    EXPECT_TRUE(GetLocalNodeDeviceInfo(TEST_PKG_NAME, &info) == SOFTBUS_OK);
    EXPECT_TRUE(GetNodeKeyInfo(nullptr, info.networkId, NODE_KEY_UDID,
        (uint8_t *)udid, UDID_BUF_LEN) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(GetNodeKeyInfo(TEST_PKG_NAME, info.networkId, NODE_KEY_UDID,
        (uint8_t *)udid, 0) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(GetNodeKeyInfo(TEST_PKG_NAME, info.networkId, NODE_KEY_UDID,
        (uint8_t *)udid, UDID_BUF_LEN) == SOFTBUS_OK);
    EXPECT_TRUE(GetNodeKeyInfo(TEST_PKG_NAME, info.networkId, NODE_KEY_UUID,
        (uint8_t *)uuid, UUID_BUF_LEN) == SOFTBUS_OK);
    EXPECT_TRUE(strlen(uuid) == (UUID_BUF_LEN - 1));

    EXPECT_TRUE(GetNodeKeyInfo(TEST_PKG_NAME, info.networkId, NODE_KEY_BR_MAC,
        (uint8_t *)brMac, BT_MAC_LEN) == SOFTBUS_OK);
    EXPECT_TRUE(GetNodeKeyInfo(TEST_PKG_NAME, info.networkId, NODE_KEY_IP_ADDRESS,
        (uint8_t *)ipAddr, IP_STR_MAX_LEN) == SOFTBUS_OK);
    EXPECT_TRUE(GetNodeKeyInfo(TEST_PKG_NAME, info.networkId, NODE_KEY_DEV_NAME,
        (uint8_t *)deviceName, DEVICE_NAME_BUF_LEN) == SOFTBUS_OK);
    EXPECT_TRUE(GetNodeKeyInfo(TEST_PKG_NAME, info.networkId, NODE_KEY_NETWORK_CAPABILITY,
        (uint8_t *)&netCapacity, LNN_COMMON_LEN) == SOFTBUS_OK);
    EXPECT_TRUE(GetNodeKeyInfo(TEST_PKG_NAME, info.networkId, NODE_KEY_NETWORK_TYPE,
        (uint8_t *)&netType, LNN_COMMON_LEN) == SOFTBUS_OK);

    EXPECT_TRUE(GetAllNodeDeviceInfo(TEST_PKG_NAME, &remoteNodeInfo, &infoNum) == SOFTBUS_OK);
    for (int32_t i = 0; i < infoNum; i++) {
        EXPECT_TRUE(GetNodeKeyInfo(TEST_PKG_NAME, (remoteNodeInfo + i)->networkId, NODE_KEY_BR_MAC,
            (uint8_t *)brMac, BT_MAC_LEN) == SOFTBUS_OK);
        EXPECT_TRUE(GetNodeKeyInfo(TEST_PKG_NAME, (remoteNodeInfo + i)->networkId, NODE_KEY_IP_ADDRESS,
            (uint8_t *)ipAddr, IP_STR_MAX_LEN) == SOFTBUS_OK);
        EXPECT_TRUE(GetNodeKeyInfo(TEST_PKG_NAME, (remoteNodeInfo + i)->networkId, NODE_KEY_DEV_NAME,
            (uint8_t *)deviceName, DEVICE_NAME_BUF_LEN) == SOFTBUS_OK);
        EXPECT_TRUE(GetNodeKeyInfo(TEST_PKG_NAME, (remoteNodeInfo + i)->networkId, NODE_KEY_NETWORK_CAPABILITY,
            (uint8_t *)&netCapacity, LNN_COMMON_LEN) == SOFTBUS_OK);
        EXPECT_TRUE(GetNodeKeyInfo(TEST_PKG_NAME, (remoteNodeInfo + i)->networkId, NODE_KEY_NETWORK_TYPE,
            (uint8_t *)&netType, LNN_COMMON_LEN) == SOFTBUS_OK);
    }
    FreeNodeInfo(remoteNodeInfo);
}

/*
 * @tc.name: BUS_CENTER_SDK_GET_NODE_KEY_INFO_Test_002
 * @tc.desc: get node key info(screen status) interface test
 * @tc.type: FUNC
 * @tc.require: I5I7B9
 */
HWTEST_F(BusCenterSdkTest, BUS_CENTER_SDK_GET_NODE_KEY_INFO_Test_002, TestSize.Level0)
{
    NodeBasicInfo info;
    NodeBasicInfo *remoteNodeInfo = nullptr;
    int32_t infoNum = 0;
    bool isScreenOn = false;
    (void)memset_s(&info, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    EXPECT_TRUE(GetLocalNodeDeviceInfo(TEST_PKG_NAME, &info) == SOFTBUS_OK);
    EXPECT_TRUE(GetAllNodeDeviceInfo(TEST_PKG_NAME, &remoteNodeInfo, &infoNum) == SOFTBUS_OK);
    for (int32_t i = 0; i < infoNum; i++) {
        EXPECT_TRUE(GetNodeKeyInfo(TEST_PKG_NAME, (remoteNodeInfo + i)->networkId, NODE_KEY_DEVICE_SCREEN_STATUS,
            (uint8_t *)&isScreenOn, DATA_DEVICE_SCREEN_STATUS_LEN) == SOFTBUS_OK);
    }
    FreeNodeInfo(remoteNodeInfo);
}

/*
 * @tc.name: BUS_CENTER_SDK_START_TIME_SYNC_Test_001
 * @tc.desc: start time sync interface test
 * @tc.type: FUNC
 * @tc.require: I5I7B9
 */
HWTEST_F(BusCenterSdkTest, BUS_CENTER_SDK_START_TIME_SYNC_Test_001, TestSize.Level0)
{
    char networkId[] = "0123456789987654321001234567899876543210012345678998765432100123";

    EXPECT_TRUE(StartTimeSync(nullptr, networkId, LOW_ACCURACY, SHORT_PERIOD, &g_timeSyncCb) != SOFTBUS_OK);
    EXPECT_TRUE(StartTimeSync(TEST_PKG_NAME, nullptr, LOW_ACCURACY, SHORT_PERIOD, &g_timeSyncCb) != SOFTBUS_OK);
    EXPECT_TRUE(StartTimeSync(TEST_PKG_NAME, networkId, LOW_ACCURACY, SHORT_PERIOD, &g_timeSyncCb) != SOFTBUS_OK);
    EXPECT_TRUE(StartTimeSync(TEST_PKG_NAME, networkId, LOW_ACCURACY, SHORT_PERIOD, nullptr) != SOFTBUS_OK);
}

/*
 * @tc.name: BUS_CENTER_SDK_START_TIME_SYNC_Test_002
 * @tc.desc: start time sync interface test
 * @tc.type: FUNC
 * @tc.require: I5I7B9
 */
HWTEST_F(BusCenterSdkTest, BUS_CENTER_SDK_START_TIME_SYNC_Test_002, TestSize.Level0)
{
    char networkId[] = "0123456789987654321001234567899876543210012345678998765432100123";

    EXPECT_TRUE(StopTimeSync(nullptr, networkId) != SOFTBUS_OK);
    EXPECT_TRUE(StopTimeSync(TEST_PKG_NAME, nullptr) != SOFTBUS_OK);
    EXPECT_TRUE(StopTimeSync(TEST_PKG_NAME, networkId) != SOFTBUS_OK);
}

/**
 * @tc.name: PublishLNNTest001
 * @tc.desc: Verify wrong parameter
 * @tc.type: FUNC
 * @tc.require: I5I7B9
 */
HWTEST_F(BusCenterSdkTest, PublishLNNTest001, TestSize.Level0)
{
    int32_t ret = PublishLNN(nullptr, &g_pInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);

    ret = PublishLNN(TEST_PKG_NAME, nullptr, &g_publishCb);
    EXPECT_TRUE(ret != 0);

    ret = PublishLNN(TEST_PKG_NAME, &g_pInfo, nullptr);
    EXPECT_TRUE(ret != 0);

    g_pInfo.medium = (ExchangeMedium)(COAP + 1);
    ret = PublishLNN(TEST_PKG_NAME, &g_pInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    g_pInfo.medium = COAP;

    g_pInfo.mode = (DiscoverMode)(DISCOVER_MODE_ACTIVE + 1);
    ret = PublishLNN(TEST_PKG_NAME, &g_pInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    g_pInfo.mode = DISCOVER_MODE_ACTIVE;

    g_pInfo.freq = (ExchangeFreq)(FREQ_BUTT);
    ret = PublishLNN(TEST_PKG_NAME, &g_pInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    g_pInfo.freq = LOW;

    g_pInfo.capabilityData = nullptr;
    ret = PublishLNN(TEST_PKG_NAME, &g_pInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    g_pInfo.capabilityData = (unsigned char *)CAPABILITY_1;

    g_pInfo.dataLen = ERRO_CAPDATA_LEN;
    ret = PublishLNN(TEST_PKG_NAME, &g_pInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    g_pInfo.dataLen = strlen(CAPABILITY_1);
}

/**
 * @tc.name: PublishLNNTest002
 * @tc.desc: Verify normal case
 * @tc.type: FUNC
 * @tc.require: I5I7B9 I5PTUS
 */
HWTEST_F(BusCenterSdkTest, PublishLNNTest002, TestSize.Level0)
{
    int32_t ret;
    int32_t tmpId1 = GetPublishId();
    int32_t tmpId2 = GetPublishId();
    int32_t tmpId3 = GetPublishId();
    NodeBasicInfo info;
    char localIp[IP_LEN] = {0};
    char loopBackIpAddr[] = "127.0.0.1";
    char invalidIpAddr[] = "0.0.0.0";
    (void)memset_s(&info, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    EXPECT_TRUE(GetLocalNodeDeviceInfo(TEST_PKG_NAME, &info) == SOFTBUS_OK);
    EXPECT_TRUE(GetNodeKeyInfo(TEST_PKG_NAME, info.networkId, NODE_KEY_IP_ADDRESS,
        (uint8_t *)localIp, IP_LEN) == SOFTBUS_OK);
    if (strcmp(localIp, loopBackIpAddr) != 0 && strcmp(localIp, invalidIpAddr) != 0 && strcmp(localIp, "") != 0) {
        g_pInfo.publishId = tmpId1;
        ret = PublishLNN(TEST_PKG_NAME, &g_pInfo, &g_publishCb);
        EXPECT_TRUE(ret == SOFTBUS_OK);
        g_pInfo1.publishId = tmpId2;
        ret = PublishLNN(TEST_PKG_NAME, &g_pInfo1, &g_publishCb);
        EXPECT_TRUE(ret == SOFTBUS_OK);
        g_pInfo1.publishId = tmpId3;
        ret = PublishLNN(TEST_PKG_NAME_1, &g_pInfo1, &g_publishCb);
        EXPECT_TRUE(ret == SOFTBUS_OK);
        ret = StopPublishLNN(TEST_PKG_NAME, tmpId1);
        EXPECT_TRUE(ret == SOFTBUS_OK);
        ret = StopPublishLNN(TEST_PKG_NAME, tmpId2);
        EXPECT_TRUE(ret == SOFTBUS_OK);
        ret = StopPublishLNN(TEST_PKG_NAME_1, tmpId3);
        EXPECT_TRUE(ret == SOFTBUS_OK);
    }
}

/**
 * @tc.name: RefreshLNNTest001
 * @tc.desc: Verify wrong parameter
 * @tc.type: FUNC
 * @tc.require: I5I7B9
 */
HWTEST_F(BusCenterSdkTest, RefreshLNNTest001, TestSize.Level0)
{
    int32_t ret;

    ret = RefreshLNN(nullptr, &g_sInfo, &g_refreshCb);
    EXPECT_TRUE(ret != 0);

    ret = RefreshLNN(TEST_PKG_NAME, nullptr, &g_refreshCb);
    EXPECT_TRUE(ret != 0);

    ret = RefreshLNN(TEST_PKG_NAME, &g_sInfo, nullptr);
    EXPECT_TRUE(ret != 0);

    g_sInfo.medium = (ExchangeMedium)(COAP + 1);
    ret = RefreshLNN(TEST_PKG_NAME, &g_sInfo, &g_refreshCb);
    EXPECT_TRUE(ret != 0);
    g_sInfo.medium = COAP;

    g_sInfo.mode = (DiscoverMode)(DISCOVER_MODE_ACTIVE + 1);
    ret = RefreshLNN(TEST_PKG_NAME, &g_sInfo, &g_refreshCb);
    EXPECT_TRUE(ret != 0);
    g_sInfo.mode = DISCOVER_MODE_ACTIVE;

    g_sInfo.freq = (ExchangeFreq)(FREQ_BUTT);
    ret = RefreshLNN(TEST_PKG_NAME, &g_sInfo, &g_refreshCb);
    EXPECT_TRUE(ret != 0);
    g_sInfo.freq = LOW;

    g_sInfo.capabilityData = nullptr;
    ret = RefreshLNN(TEST_PKG_NAME, &g_sInfo, &g_refreshCb);
    EXPECT_TRUE(ret != 0);
    g_sInfo.capabilityData = (unsigned char *)CAPABILITY_1;

    g_sInfo.dataLen = ERRO_CAPDATA_LEN;
    ret = RefreshLNN(TEST_PKG_NAME, &g_sInfo, &g_refreshCb);
    EXPECT_TRUE(ret != 0);
    g_sInfo.dataLen = strlen(CAPABILITY_1);
}

/**
 * @tc.name: RefreshLNNTest002
 * @tc.desc: Verify normal case
 * @tc.type: FUNC
 * @tc.require: I5I7B9 I5PTUS
 */
HWTEST_F(BusCenterSdkTest, RefreshLNNTest002, TestSize.Level0)
{
    int32_t ret;
    int32_t tmpId1 = GetSubscribeId();
    int32_t tmpId2 = GetSubscribeId();
    int32_t tmpId3 = GetSubscribeId();
    NodeBasicInfo info;
    char localIp[IP_LEN] = {0};
    char loopBackIpAddr[] = "127.0.0.1";
    char invalidIpAddr[] = "0.0.0.0";
    (void)memset_s(&info, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    EXPECT_TRUE(GetLocalNodeDeviceInfo(TEST_PKG_NAME, &info) == SOFTBUS_OK);
    EXPECT_TRUE(GetNodeKeyInfo(TEST_PKG_NAME, info.networkId, NODE_KEY_IP_ADDRESS,
        (uint8_t *)localIp, IP_LEN) == SOFTBUS_OK);
    if (strcmp(localIp, loopBackIpAddr) != 0 &&
        strcmp(localIp, invalidIpAddr) != 0 &&
        strcmp(localIp, "") != 0) {
        g_sInfo.subscribeId = tmpId1;
        ret = RefreshLNN(TEST_PKG_NAME, &g_sInfo, &g_refreshCb);
        EXPECT_TRUE(ret == SOFTBUS_OK);
        g_sInfo1.subscribeId = tmpId2;
        ret = RefreshLNN(TEST_PKG_NAME, &g_sInfo1, &g_refreshCb);
        EXPECT_TRUE(ret == SOFTBUS_OK);
        g_sInfo1.subscribeId = tmpId3;
        ret = RefreshLNN(TEST_PKG_NAME_1, &g_sInfo1, &g_refreshCb);
        EXPECT_TRUE(ret == SOFTBUS_OK);
        ret = StopRefreshLNN(TEST_PKG_NAME, tmpId1);
        EXPECT_TRUE(ret == SOFTBUS_OK);
        ret = StopRefreshLNN(TEST_PKG_NAME, tmpId2);
        EXPECT_TRUE(ret == SOFTBUS_OK);
        ret = StopRefreshLNN(TEST_PKG_NAME_1, tmpId3);
        EXPECT_TRUE(ret == SOFTBUS_OK);
    }
}

/**
 * @tc.name: SET_NODE_DATA_CHANGE_FLAG_INNER_Test001
 * @tc.desc: Set Node Data Change Flag Inner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterSdkTest, SET_NODE_DATA_CHANGE_FLAG_INNER_Test001, TestSize.Level0)
{
    char pkgName[] = "test";
    char *networkId = nullptr;
    uint16_t dataChangeFlag = 0;
    int32_t ret = SetNodeDataChangeFlagInner(pkgName, networkId, dataChangeFlag);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SERVER_IPC_SET_NODE_DATA_CHANGE_FLAG_Test001
 * @tc.desc: ServerIpcSetNodeDataChangeFlag Result
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterSdkTest, SERVER_IPC_SET_NODE_DATA_CHANGE_FLAG_Test001, TestSize.Level1)
{
    char pkgName[] = "test";
    char *networkId1 = nullptr;
    uint16_t dataChangeFlag = false;
    BusCenterServerProxyInit();
    int32_t ret = ServerIpcSetNodeDataChangeFlag(pkgName, networkId1, dataChangeFlag);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SERVER_IPC_SET_NODE_DATA_CHANGE_Test001
 * @tc.desc: Meta Node On Leave Result
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterSdkTest, SERVER_IPC_SET_NODE_DATA_CHANGE_Test002, TestSize.Level1)
{
    BusCenterServerProxyInit();
    char pkgName[] = "pkgname";
    char networkId[] = "12313";
    uint16_t dataChangeFlag = 11;
    int32_t ret = ServerIpcSetNodeDataChangeFlag(pkgName, networkId, dataChangeFlag);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: BUS_CENTER_SDK_PARAM_CHECK_Test001
 * @tc.desc: test sdk parm check
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterSdkTest, BUS_CENTER_SDK_PARAM_CHECK_Test001, TestSize.Level1)
{
    EXPECT_EQ(RegDataLevelChangeCb(nullptr, &g_dataLevelCb), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(RegDataLevelChangeCb(TEST_PKG_NAME, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(RegDataLevelChangeCb(TEST_PKG_NAME, &g_dataLevelCb), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UnregDataLevelChangeCb(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UnregDataLevelChangeCb(TEST_PKG_NAME), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SetDataLevel(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SetDataLevel(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(StopPublishLNN(nullptr, 0), SOFTBUS_INVALID_PARAM);
    char msg[] = "abc";
    EXPECT_EQ(SyncTrustedRelationShip(nullptr, msg, strlen(msg)), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SyncTrustedRelationShip(TEST_PKG_NAME, nullptr, strlen(msg)), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SyncTrustedRelationShip(TEST_PKG_NAME, msg, strlen(msg)), SOFTBUS_IPC_ERR);
}
} // namespace OHOS
