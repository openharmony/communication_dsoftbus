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
constexpr int32_t DEFAULT_NODE_STATE_CB_NUM = 9;
constexpr uint8_t DEFAULT_LOCAL_DEVICE_TYPE_ID = 0;

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

    EXPECT_TRUE(LeaveLNN(NULL, OnLeaveLNNDone) != SOFTBUS_OK);
    EXPECT_TRUE(LeaveLNN(networkId, NULL) != SOFTBUS_OK);
    EXPECT_TRUE(LeaveLNN(errNetIdLenMore, OnLeaveLNNDone) != SOFTBUS_OK);
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
        if (i < DEFAULT_NODE_STATE_CB_NUM) {
            EXPECT_TRUE(RegNodeDeviceStateCb(TEST_PKG_NAME, &g_nodeStateCb) == SOFTBUS_OK);
        } else {
            EXPECT_TRUE(RegNodeDeviceStateCb(TEST_PKG_NAME, &g_nodeStateCb) != SOFTBUS_OK);
        }
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
} // namespace OHOS
