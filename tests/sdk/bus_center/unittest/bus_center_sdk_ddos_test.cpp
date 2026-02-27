/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>
#include "bus_center_server_proxy.h"
#include "bus_center_server_proxy_standard.h"
#include "client_bus_center_manager.h"
#include "lnn_log.h"
#include "softbus_access_token_test.h"
#include "softbus_bus_center.h"
#include "softbus_def.h"
#include "softbus_ddos.h"
#include "softbus_error_code.h"
#include "softbus_server_frame.h"
#include "softbus_utils.h"
#include <securec.h>

#define CAPABILITY_1 "capdata1"
#define CAPABILITY_3 "capdata3"
#define CAPABILITY_4 "capdata4"
#define USE_TIMES 100
#define GET_DEVICE_INFO_TIMES 300
#define DATA_CHANGE_FLAG 11
#define LEAVELNN_TIMES 20

namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr char TEST_PKG_NAME[] = "com.softbus.test";
static int32_t g_subscribeId = 0;
static int32_t g_publishId = 0;

class BusCenterSdkDdosTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BusCenterSdkDdosTest::SetUpTestCase()
{
    SetAccessTokenPermission("busCenterTest");
    uint64_t tokenId = SetTokenIdByProcessName("device_manager");
    printf("SetTokenIdByProcessName tokenId:%ju\n", tokenId);
    if (BusCenterClientInit() != SOFTBUS_OK) {
        GTEST_LOG_(INFO) << "bus center client init failed";
    }
    if (InitDdos()) {
        GTEST_LOG_(INFO) << "ddos init failed";
    }
}

void BusCenterSdkDdosTest::TearDownTestCase() { }

void BusCenterSdkDdosTest::SetUp() { }

void BusCenterSdkDdosTest::TearDown() { }

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

static SubscribeInfo g_sInfo = { .subscribeId = 1,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)CAPABILITY_3,
    .dataLen = strlen(CAPABILITY_3) };

static PublishInfo g_pInfo = { .publishId = 1,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)CAPABILITY_4,
    .dataLen = strlen(CAPABILITY_4) };

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

static IRefreshCallback g_refreshCb = { .OnDeviceFound = TestDeviceFound, .OnDiscoverResult = TestDiscoverResult };

static IPublishCb g_publishCb = { .OnPublishResult = TestPublishResult };
/*
* @tc.name: DDOS_GET_NODE_KEY_INFO_Test_001
* @tc.desc: get node key info interface test
* @tc.type: FUNC
* @tc.require: I5I7B9
*/
HWTEST_F(BusCenterSdkDdosTest, DDOS_GET_NODE_KEY_INFO_Test_001, TestSize.Level0)
{
    NodeBasicInfo info;
    char udid[UDID_BUF_LEN] = {0};
    EXPECT_TRUE(GetLocalNodeDeviceInfo(TEST_PKG_NAME, &info) == SOFTBUS_OK);
    for (int i = 0; i < GET_DEVICE_INFO_TIMES; i++) {
        GetNodeKeyInfo(TEST_PKG_NAME, info.networkId, NODE_KEY_UDID,
        (uint8_t *)udid, UDID_BUF_LEN);
    }
    EXPECT_TRUE(GetNodeKeyInfo(TEST_PKG_NAME, info.networkId, NODE_KEY_UDID,
        (uint8_t *)udid, UDID_BUF_LEN) == SOFTBUS_DDOS_ID_AND_USER_SAME_COUNT_LIMIT);
}

/*
* @tc.name: DDOS_SET_NODE_KEY_INFO_Test_001
* @tc.desc: set node key info interface test
* @tc.type: FUNC
* @tc.require: I5I7B9
*/
HWTEST_F(BusCenterSdkDdosTest, DDOS_SET_NODE_KEY_INFO_Test_001, TestSize.Level0)
{
    NodeBasicInfo info = {0};
    char cap[SERVICE_FIND_CAP_LEN] = "123456789";
    EXPECT_TRUE(GetLocalNodeDeviceInfo(TEST_PKG_NAME, &info) == SOFTBUS_OK);
    for (int i = 0; i < GET_DEVICE_INFO_TIMES; i++) {
        SetNodeKeyInfo(TEST_PKG_NAME, info.networkId, NODE_KEY_SERVICE_FIND_CAP_EX,
        (uint8_t *)cap, SERVICE_FIND_CAP_LEN);
    }
    EXPECT_TRUE(SetNodeKeyInfo(TEST_PKG_NAME, info.networkId, NODE_KEY_SERVICE_FIND_CAP_EX,
        (uint8_t *)cap, SERVICE_FIND_CAP_LEN) == SOFTBUS_DDOS_ID_AND_USER_SAME_COUNT_LIMIT);
}

/*
* @tc.name: DDOS_SET_NODE_DATA_CHANGE_Test001
* @tc.desc: set node data change flag test
* @tc.type: FUNC
* @tc.require: I5I7B9
*/
HWTEST_F(BusCenterSdkDdosTest, DDOS_SET_NODE_DATA_CHANGE_Test001, TestSize.Level0)
{
    char networkId[] = "12313";
    uint16_t dataChangeFlag = DATA_CHANGE_FLAG;
    for (int i = 0; i < USE_TIMES; i++) {
        SetNodeDataChangeFlag(TEST_PKG_NAME, networkId, dataChangeFlag);
    }
    int32_t ret = SetNodeDataChangeFlag(TEST_PKG_NAME, networkId, dataChangeFlag);
    EXPECT_EQ(ret, SOFTBUS_DDOS_ID_AND_USER_SAME_COUNT_LIMIT);
}

/*
 * @tc.name: DDOS_START_TIME_SYNC_Test_001
 * @tc.desc: start time sync interface test
 * @tc.type: FUNC
 * @tc.require: I5I7B9
 */
HWTEST_F(BusCenterSdkDdosTest, DDOS_START_TIME_SYNC_Test_001, TestSize.Level0)
{
    char networkId[] = "0123456789987654321001234567899876543210012345678998765432100123";
    for (int i = 0; i < USE_TIMES; i++) {
        StartTimeSync(TEST_PKG_NAME, networkId, LOW_ACCURACY, SHORT_PERIOD, &g_timeSyncCb);
    }
    int32_t ret = StartTimeSync(TEST_PKG_NAME, networkId, LOW_ACCURACY, SHORT_PERIOD, &g_timeSyncCb);
    EXPECT_EQ(ret, SOFTBUS_DDOS_ID_AND_USER_SAME_COUNT_LIMIT);
}

/*
 * @tc.name: DDOS_PublishLNNTest001
 * @tc.desc: Verify normal case
 * @tc.type: FUNC
 * @tc.require: I5I7B9 I5PTUS
 */
HWTEST_F(BusCenterSdkDdosTest, DDOS_PublishLNNTest001, TestSize.Level0)
{
    int32_t tmpId1 = GetPublishId();
    g_pInfo.publishId = tmpId1;
    for (int i = 0; i < USE_TIMES; i++) {
        PublishLNN(TEST_PKG_NAME, &g_pInfo, &g_publishCb);
        StopPublishLNN(TEST_PKG_NAME, tmpId1);
    }
    int32_t ret = PublishLNN(TEST_PKG_NAME, &g_pInfo, &g_publishCb);
    EXPECT_TRUE(ret == SOFTBUS_DDOS_ID_AND_USER_SAME_COUNT_LIMIT);
    ret = StopPublishLNN(TEST_PKG_NAME, tmpId1);
    EXPECT_TRUE(ret == SOFTBUS_DDOS_ID_AND_USER_SAME_COUNT_LIMIT);
}

/*
 * @tc.name: DDOS_RefreshLNNTest001
 * @tc.desc: Verify normal case
 * @tc.type: FUNC
 * @tc.require: I5I7B9 I5PTUS
 */
HWTEST_F(BusCenterSdkDdosTest, DDOS_RefreshLNNTest001, TestSize.Level0)
{
    int32_t ret;
    int32_t tmpId1 = GetSubscribeId();
    g_sInfo.subscribeId = tmpId1;
    for (int i = 0; i < USE_TIMES; i++) {
        RefreshLNN(TEST_PKG_NAME, &g_sInfo, &g_refreshCb);
        StopRefreshLNN(TEST_PKG_NAME, tmpId1);
    }
    ret = RefreshLNN(TEST_PKG_NAME, &g_sInfo, &g_refreshCb);
    EXPECT_TRUE(ret == SOFTBUS_DDOS_ID_AND_USER_SAME_COUNT_LIMIT);
    ret = StopRefreshLNN(TEST_PKG_NAME, tmpId1);
    EXPECT_TRUE(ret == SOFTBUS_DDOS_ID_AND_USER_SAME_COUNT_LIMIT);
}

/*
 * @tc.name: DDOS_Leave_Lnn_Test_001
 * @tc.desc: bus center LeaveLNN interface exception test
 * @tc.type: FUNC
 * @tc.require: I5I7B9
 */
HWTEST_F(BusCenterSdkDdosTest, DDOS_Leave_Lnn_Test_001, TestSize.Level0)
{
    char networkId[] = "012345678998765432100123456789987654321001234567899876543210abcde";
    for (int i = 0; i < USE_TIMES; i++) {
        LeaveLNN(TEST_PKG_NAME, networkId, OnLeaveLNNDone);
    }
    EXPECT_TRUE(LeaveLNN(TEST_PKG_NAME, networkId, OnLeaveLNNDone) == SOFTBUS_DDOS_USER_SAME_ID_COUNT_LIMIT);
}

/*
 * @tc.name: DDOS_Leave_Lnn_Test_002
 * @tc.desc: bus center LeaveLNN interface exception test
 * @tc.type: FUNC
 * @tc.require: I5I7B9
 */
HWTEST_F(BusCenterSdkDdosTest, DDOS_Leave_Lnn_Test_002, TestSize.Level0)
{
    char networkId[] = "012345678998765432100123456789987654321001234567899876543210abcde";
    constexpr char testPkgName[] = "com.softbus.test00";
    constexpr char testPkgName1[] = "com.softbus.test01";
    constexpr char testPkgName2[] = "com.softbus.test02";
    constexpr char testPkgName3[] = "com.softbus.test03";
    constexpr char testPkgName4[] = "com.softbus.test04";
    constexpr char testPkgName5[] = "com.softbus.test05";
    constexpr char testPkgName6[] = "com.softbus.test06";
    constexpr char testPkgName7[] = "com.softbus.test07";
    for (int i = 0; i < USE_TIMES; i++) {
        LeaveLNN(testPkgName, networkId, OnLeaveLNNDone);
        LeaveLNN(testPkgName1, networkId, OnLeaveLNNDone);
        LeaveLNN(testPkgName2, networkId, OnLeaveLNNDone);
        LeaveLNN(testPkgName3, networkId, OnLeaveLNNDone);
        LeaveLNN(testPkgName4, networkId, OnLeaveLNNDone);
        LeaveLNN(testPkgName5, networkId, OnLeaveLNNDone);
        LeaveLNN(testPkgName6, networkId, OnLeaveLNNDone);
    }
    for (int i = 0; i < LEAVELNN_TIMES; i++) {
        LeaveLNN(testPkgName7, networkId, OnLeaveLNNDone);
    }
    EXPECT_TRUE(LeaveLNN(testPkgName7, networkId, OnLeaveLNNDone) == SOFTBUS_DDOS_ID_SAME_COUNT_LIMIT);
}

/*
 * @tc.name: DDOS_GET_LOCAL_NODE_INFO_Test_001
 * @tc.desc: get local info interface test
 * @tc.type: FUNC
 * @tc.require: I5I7B9
 */
HWTEST_F(BusCenterSdkDdosTest, DDOS_GET_LOCAL_NODE_INFO_Test_001, TestSize.Level0)
{
    NodeBasicInfo info;
    char networkId[] = "12313";
    uint16_t dataChangeFlag = DATA_CHANGE_FLAG;
    constexpr char testPkgName[] = "com.softbus.test00";
    constexpr char testPkgName1[] = "com.softbus.test01";
    constexpr char testPkgName2[] = "com.softbus.test02";
    constexpr char testPkgName3[] = "com.softbus.test03";
    for (int i = 0; i < USE_TIMES; i++) {
        SetNodeDataChangeFlag(testPkgName, networkId, dataChangeFlag);
        SetNodeDataChangeFlag(testPkgName1, networkId, dataChangeFlag);
        SetNodeDataChangeFlag(testPkgName2, networkId, dataChangeFlag);
        SetNodeDataChangeFlag(testPkgName3, networkId, dataChangeFlag);
    }
    for (int i = 0; i < USE_TIMES; i++) {
        GetLocalNodeDeviceInfo(testPkgName, &info);
    }
    EXPECT_TRUE(GetLocalNodeDeviceInfo(testPkgName, &info) != SOFTBUS_OK);
    sleep(10);
}
} // namespace OHOS
