/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
 * @tc.desc: Verify LnnSetAuthTypeValue and LnnClearAuthTypeValue with nullptr
 *           or invalid parameters return SOFTBUS_INVALID_PARAM; with valid
 *           parameters return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.level: Level1
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
 * @tc.name: LNN_GET_TRUSTED_DEV_INFO_FROM_DB_Test_001
 * @tc.desc: Verify LnnGetTrustedDevInfoFromDb retrieves trusted device info
 *           from database successfully and returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.level: Level1
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
 * @tc.desc: Verify LnnGetRemoteNumInfo and LnnGetRemoteNumInfoByIfnameIdx
 *           with invalid parameters return SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetLedgerTest, DL_GET_Test_001, TestSize.Level1)
{
    char networkId[DEFAULT_SIZE] = "1234";
    int32_t info = 1234;
    EXPECT_TRUE(LnnGetRemoteNumInfoByIfnameIdx(nullptr, NUM_KEY_SESSION_PORT, &info, WLAN_IF) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetRemoteNumInfo(networkId, STRING_KEY_END, &info) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetRemoteNumInfo(networkId, NUM_KEY_END, &info) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetRemoteNumInfo(networkId, NUM_KEY_END, nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetRemoteNumInfoByIfnameIdx(networkId, NUM_KEY_AUTH_PORT, &info, WLAN_IF) != SOFTBUS_OK);
}

/*
 * @tc.name: LNN_ADD_META_INFO_Test_001
 * @tc.desc: Verify LnnAddMetaInfo adds meta info to nodeInfo successfully
 *           and returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.level: Level1
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
 * @tc.desc: Verify LnnDeleteMetaInfo with non-existent udid returns error
 *           and not SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.level: Level1
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
 * @tc.desc: Verify LnnGetAllOnlineAndMetaNodeInfo with nullptr parameters
 *           returns SOFTBUS_INVALID_PARAM; with valid parameters returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.level: Level1
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
 * @tc.desc: Verify LnnAddMetaInfo adds meta info successfully and LnnDeleteMetaInfo
 *           deletes meta info successfully; repeated delete returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.level: Level1
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
 * @tc.desc: Verify LnnGetRemoteNum16Info with invalid parameters returns
 *           SOFTBUS_INVALID_PARAM; with valid UDID but non-existent key returns error
 * @tc.type: FUNC
 * @tc.level: Level1
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

/*
 * @tc.name: LNN_GET_ONLINE_AND_OFFLINE_WITHIN_TIME_UDIDS_Test_001
 * @tc.desc: Verify LnnGetOnlineAndOfflineWithinTimeUdids with nullptr parameters
 *           returns SOFTBUS_INVALID_PARAM; with valid parameters returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetLedgerTest, LNN_GET_ONLINE_AND_OFFLINE_WITHIN_TIME_UDIDS_Test_001, TestSize.Level1)
{
    char *udids = nullptr;
    int32_t udidNum = 0;
    EXPECT_EQ(LnnGetOnlineAndOfflineWithinTimeUdids(nullptr, &udidNum, 0), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnGetOnlineAndOfflineWithinTimeUdids(&udids, nullptr, 0), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnGetOnlineAndOfflineWithinTimeUdids(&udids, &udidNum, 0), SOFTBUS_OK);
    SoftBusFree(udids);
    udids = nullptr;
    udidNum = DEFAULT_SIZE;
    EXPECT_EQ(LnnGetOnlineAndOfflineWithinTimeUdids(&udids, &udidNum, 0), SOFTBUS_OK);
    SoftBusFree(udids);
}

/*
 * @tc.name: IS_NEED_UPDATE_HUK_KEY_Test_001
 * @tc.desc: Verify IsNeedUpdateHukKey checks if HUK key needs to be updated
 *           and returns true with diffTime output parameter
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetLedgerTest, IS_NEED_UPDATE_HUK_KEY_Test_001, TestSize.Level1)
{
    uint64_t diffTime = 0;
    bool ret = IsNeedUpdateHukKey(&diffTime);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: START_CHECK_HUK_KEY_TIME_PROC_Test_001
 * @tc.desc: Verify StartCheckHukKeyTimeProc executes without fatal failure
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetLedgerTest, START_CHECK_HUK_KEY_TIME_PROC_Test_001, TestSize.Level1)
{
    int32_t para = 0;
    EXPECT_NO_FATAL_FAILURE(StartCheckHukKeyTimeProc(static_cast<void *>(&para)));
}

/*
 * @tc.name: LNN_FIND_DEVICE_UDIDT_RUSTED_INFO_FROMDB_Test_001
 * @tc.desc: Verify LnnFindDeviceUdidTrustedInfoFromDb with nullptr udid returns
 *           SOFTBUS_INVALID_PARAM; with valid but non-existent udid returns SOFTBUS_NOT_FIND
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetLedgerTest, LNN_FIND_DEVICE_UDIDT_RUSTED_INFO_FROMDB_Test_001, TestSize.Level1)
{
    int32_t ret;
    constexpr char *strUdid = nullptr;
    ret = LnnFindDeviceUdidTrustedInfoFromDb(strUdid);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnFindDeviceUdidTrustedInfoFromDb(NODE1_UDID);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_001
 * @tc.desc: Verify DeviceDbRecoveryInit initializes successfully and returns true
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetLedgerTest, LNN_INIT_DECISION_DB_DELAY_Test_001, TestSize.Level1)
{
    bool retVal = DeviceDbRecoveryInit();
    EXPECT_TRUE(retVal);
}

/*
 * @tc.name: LNN_IS_POTENTIAL_HOME_GROUP_Test_001
 * @tc.desc: Verify LnnIsPotentialHomeGroup with non-home-group UDID returns false
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetLedgerTest, LNN_IS_POTENTIAL_HOME_GROUP_Test_001, TestSize.Level1)
{
    bool ret;
    ret = LnnIsPotentialHomeGroup(NODE1_UDID);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: IS_DEVICE_TRUSTED_Test_001
 * @tc.desc: Verify IsDeviceTrusted with empty udid or non-existent udid returns false
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetLedgerTest, IS_DEVICE_TRUSTED_Test_001, TestSize.Level1)
{
    bool ret;
    int32_t userId = 12345;
    const char udid[] = "";
    ret = IsDeviceTrusted(udid, userId);
    EXPECT_FALSE(ret);
    ret = IsDeviceTrusted(NODE1_UDID, userId);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: TRY_RECOVERY_TRUST_DEVINFOTABLE_Test_001
 * @tc.desc: Verify InitTrustedDevInfoTable fails and TryRecoveryTrustedDevInfoTable
 *           attempts to recover and returns true
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetLedgerTest, TRY_RECOVERY_TRUST_DEVINFOTABLE_Test_001, TestSize.Level1)
{
    bool ret;
    int32_t retVal = InitTrustedDevInfoTable();
    EXPECT_EQ(retVal, SOFTBUS_NETWORK_INIT_TRUST_DEV_INFO_FAILED);
    RecoveryTrustedDevInfoProcess();
    ret = TryRecoveryTrustedDevInfoTable();
    ClearRecoveryDeviceList();
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: GET_ALL_DEV_NUM_Test_001
 * @tc.desc: Verify GetAllDevNums retrieves total device numbers successfully
 *           and returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetLedgerTest, GET_ALL_DEV_NUM_Test_001, TestSize.Level1)
{
    uint32_t num = 0;
    int32_t ret;
    int32_t userId = 123;
    ret = GetAllDevNums(&num, userId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_DELETE_SPECIFIC_TRUSTED_DEV_INFO_Test_001
 * @tc.desc: Verify LnnDeleteSpecificTrustedDevInfo deletes specific trusted
 *           device info successfully and returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetLedgerTest, LNN_DELETE_SPECIFIC_TRUSTED_DEV_INFO_Test_001, TestSize.Level1)
{
    const char *udid = "672392378745";
    int32_t localUserId = 123;
    int32_t ret;
    ret = LnnDeleteSpecificTrustedDevInfo(udid, localUserId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_INSERT_SPECIFIC_TRUSTED_DEV_INFO_Test_001
 * @tc.desc: Verify LnnInsertSpecificTrustedDevInfo inserts specific trusted
 *           device info successfully and returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetLedgerTest, LNN_INSERT_SPECIFIC_TRUSTED_DEV_INFO_Test_001, TestSize.Level1)
{
    int32_t ret;
    const char *udid = "672392378745";
    ret = LnnInsertSpecificTrustedDevInfo(udid);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: UPDATE_RECOVERY_DEVICE_INFO_FROM_DB_Test_001
 * @tc.desc: Verify InitDbListDelay and UpdateRecoveryDeviceInfoFromDb fail
 *           when device info cannot be retrieved and return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetLedgerTest, UPDATE_RECOVERY_DEVICE_INFO_FROM_DB_Test_001, TestSize.Level1)
{
    int32_t retVal = InitDbListDelay();
    EXPECT_EQ(retVal, SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR);
    retVal = UpdateRecoveryDeviceInfoFromDb();
    EXPECT_EQ(retVal, SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR);
}
} // namespace OHOS
