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

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>

#include "auth_interface.h"
#include "bus_center_manager.h"
#include "lnn_decision_db.c"
#include "lnn_decision_db.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_event_monitor.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_network_manager.h"
#include "lnn_node_info.h"

#include "softbus_adapter_mem.h"
#include "softbus_conn_interface.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

namespace OHOS {
using namespace testing::ext;
constexpr uint32_t TEST_DATA_LEN = 10;
constexpr uint8_t DEFAULT_SIZE = 5;
constexpr char NODE1_UDID[] = "123456ABCDEF";
constexpr char NODE2_UDID[] = "123456ABCDEG";

class NetLedgerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void NetLedgerTest::SetUpTestCase() { }

void NetLedgerTest::TearDownTestCase() { }

void NetLedgerTest::SetUp()
{
    int32_t ret = LnnInitLocalLedger();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnInitDistributedLedger();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LNN_LOGI(LNN_TEST, "NetLedgerTest start");
}

void NetLedgerTest::TearDown()
{
    LnnDeinitLocalLedger();
    LnnDeinitDistributedLedger();
}

/*
 * @tc.name: AUTH_TYPE_VALUE_SET_CLEAR_Test_001
 * @tc.desc: auth type value set and clear test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NetLedgerTest, AUTH_TYPE_VALUE_SET_CLEAR_Test_001, TestSize.Level1)
{
    int32_t ret;
    uint32_t authType = 0;
    uint32_t *authTypeValue = nullptr;

    ret = LnnSetAuthTypeValue(authTypeValue, ONLINE_HICHAIN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnClearAuthTypeValue(authTypeValue, ONLINE_HICHAIN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    authTypeValue = &authType;
    ret = LnnSetAuthTypeValue(authTypeValue, AUTH_TYPE_BUTT);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnClearAuthTypeValue(authTypeValue, AUTH_TYPE_BUTT);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LnnSetAuthTypeValue(authTypeValue, ONLINE_METANODE);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnClearAuthTypeValue(authTypeValue, ONLINE_HICHAIN);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: BUILD_TRUSTED_DEV_INFO_RECORD_Test_001
 * @tc.desc: build trusted dev info record test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NetLedgerTest, BUILD_TRUSTED_DEV_INFO_RECORD_Test_001, TestSize.Level1)
{
    int32_t ret;
    const char *udid = "testdata";
    TrustedDevInfoRecord record;

    (void)memset_s(&record, sizeof(TrustedDevInfoRecord), 0, sizeof(TrustedDevInfoRecord));
    ret = BuildTrustedDevInfoRecord(udid, &record);
    EXPECT_EQ(ret, SOFTBUS_OK);

    udid = nullptr;
    ret = BuildTrustedDevInfoRecord(udid, &record);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_GET_TRUSTED_DEV_INFO_FROM_DB_Test_001
 * @tc.desc: lnn get trusted dev info from db test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NetLedgerTest, LNN_GET_TRUSTED_DEV_INFO_FROM_DB_Test_001, TestSize.Level1)
{
    uint32_t num = 0;
    int32_t ret;

    char *udidArray = new char[TEST_DATA_LEN];
    ASSERT_NE(udidArray, nullptr);
    ret = LnnGetTrustedDevInfoFromDb(&udidArray, &num);
    EXPECT_EQ(ret, SOFTBUS_OK);
    delete[] udidArray;
}

/*
 * @tc.name: DL_GET_Test_001
 * @tc.desc: Dl Get Auth test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NetLedgerTest, DL_GET_Test_001, TestSize.Level1)
{
    char networkId[DEFAULT_SIZE] = "1234";
    int32_t info = 1234;
    EXPECT_TRUE(LnnGetRemoteNumInfo(nullptr, NUM_KEY_SESSION_PORT, &info) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetRemoteNumInfo(networkId, STRING_KEY_END, &info) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetRemoteNumInfo(networkId, NUM_KEY_END, &info) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetRemoteNumInfo(networkId, NUM_KEY_END, nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetRemoteNumInfo(networkId, NUM_KEY_AUTH_PORT, &info) != SOFTBUS_OK);
}

/*
 * @tc.name: LNN_ADD_META_INFO_Test_001
 * @tc.desc: Lnn Add Meta Info test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NetLedgerTest, LNN_ADD_META_INFO_Test_001, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_TRUE(LnnAddMetaInfo(&info) == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_DELETE_META_INFO_Test_001
 * @tc.desc: Lnn Delete Meta Info test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NetLedgerTest, LNN_DELETE_META_INFO_Test_001, TestSize.Level1)
{
    char udid[DEFAULT_SIZE] = "1234";
    AuthLinkType type = AUTH_LINK_TYPE_WIFI;
    EXPECT_TRUE(LnnDeleteMetaInfo(udid, type) != SOFTBUS_OK);
}

/*
 * @tc.name: GET_ALL_ONLINE_AND_META_NODE_INFO_Test_001
 * @tc.desc: Get All Online And Meta Node Info test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NetLedgerTest, GET_ALL_ONLINE_AND_META_NODE_INFO_Test_001, TestSize.Level1)
{
    NodeBasicInfo base;
    NodeBasicInfo *info = nullptr;
    int32_t infoNum = 0;
    EXPECT_TRUE(LnnGetAllOnlineAndMetaNodeInfo(nullptr, &infoNum) == SOFTBUS_INVALID_PARAM);
    info = &base;
    (void)memset_s(info, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    EXPECT_TRUE(LnnGetAllOnlineAndMetaNodeInfo(&info, nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetAllOnlineAndMetaNodeInfo(&info, &infoNum) == SOFTBUS_OK);
    SoftBusFree(info);
    info = nullptr;
    infoNum = DEFAULT_SIZE;
    EXPECT_TRUE(LnnGetAllOnlineAndMetaNodeInfo(&info, &infoNum) == SOFTBUS_OK);
    SoftBusFree(info);
}

/*
 * @tc.name: LNN_META_INFO_ADD_DEL_Test_001
 * @tc.desc: lnn add and del meta info test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NetLedgerTest, LNN_META_INFO_ADD_DEL_Test_001, TestSize.Level1)
{
    int32_t ret;
    NodeInfo info;

    ret = LnnDeleteMetaInfo(NODE2_UDID, AUTH_LINK_TYPE_WIFI);
    EXPECT_NE(ret, SOFTBUS_OK);
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    LnnSetDeviceUdid(&info, NODE1_UDID);
    info.metaInfo.metaDiscType = AUTH_LINK_TYPE_WIFI;
    ret = LnnAddMetaInfo(&info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnDeleteMetaInfo(NODE1_UDID, AUTH_LINK_TYPE_WIFI);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnDeleteMetaInfo(NODE1_UDID, AUTH_LINK_TYPE_WIFI);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnDeleteMetaInfo(NODE1_UDID, AUTH_LINK_TYPE_WIFI);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_REMOTE_NUM16_INFO_Test_001
 * @tc.desc: lnn get remote num16 info test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NetLedgerTest, LNN_GET_REMOTE_NUM16_INFO_Test_001, TestSize.Level1)
{
    int32_t ret;
    int16_t info1 = 0;
    int16_t *info2 = nullptr;
    constexpr char *networkId = nullptr;

    ret = LnnGetRemoteNum16Info(NODE1_UDID, NUM_KEY_META_NODE, &info1);
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteNum16Info(networkId, NUM_KEY_META_NODE, &info1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteNum16Info(networkId, NUM_KEY_META_NODE, info2);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteNum16Info(NODE1_UDID, STRING_KEY_BEGIN, &info1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteNum16Info(NODE1_UDID, BYTE_KEY_END, &info1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
} // namespace OHOS
