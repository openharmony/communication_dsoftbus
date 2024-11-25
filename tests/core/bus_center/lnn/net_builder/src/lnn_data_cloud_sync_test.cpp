/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "lnn_data_cloud_sync.h"
#include "lnn_device_info_recovery.h"
#include "lnn_log.h"
#include "lnn_node_info.h"
#include "lnn_parameter_utils.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr char VALUE[] = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000#1";
constexpr char RIGHT_KEY[] = "123456789#1111111111111111111111111111111111111111111111111111111111111111#DEVICE_NAME";

class LNNDataCloudSyncTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNDataCloudSyncTest::SetUpTestCase() { }

void LNNDataCloudSyncTest::TearDownTestCase() { }

void LNNDataCloudSyncTest::SetUp()
{
    LNN_LOGI(LNN_TEST, "LNNDataCloudSyncTest start");
}

void LNNDataCloudSyncTest::TearDown() { }

/*
 * @tc.name: LnnLedgerAllDataSyncToDB_Test_001
 * @tc.desc: LnnLedgerAllDataSyncToDB
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDataCloudSyncTest, LnnAsyncCallLedgerAllDataSyncToDB_Test_001, TestSize.Level1)
{
    NodeInfo *info = nullptr;
    int32_t ret = LnnAsyncCallLedgerAllDataSyncToDB(info);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    info = (NodeInfo *)SoftBusCalloc(sizeof(NodeInfo));
    ASSERT_NE(info, nullptr);
    info->accountId = 0;
    ret = LnnLedgerAllDataSyncToDB(info);
    if (ret != SOFTBUS_NOT_IMPLEMENT) {
        EXPECT_EQ(ret, SOFTBUS_KV_CLOUD_DISABLED);
    } else {
        EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    }
    info->accountId = 18390933952;
    ret = LnnAsyncCallLedgerAllDataSyncToDB(info);
    EXPECT_NE(ret, SOFTBUS_OK);
    SoftBusFree(info);
}

/*
 * @tc.name: LnnLedgerDataChangeSyncToDB_Test_002
 * @tc.desc: LnnLedgerDataChangeSyncToDB
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDataCloudSyncTest, LnnLedgerDataChangeSyncToDB_Test_002, TestSize.Level1)
{
    char *key = nullptr;
    int32_t ret = LnnLedgerDataChangeSyncToDB(key, VALUE, strlen(VALUE));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    LnnDeleteSyncToDB();
}

/*
 * @tc.name: LnnDBDataChangeSyncToCache_Test_003
 * @tc.desc: LnnDBDataChangeSyncToCache
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDataCloudSyncTest, LnnDBDataChangeSyncToCache_Test_003, TestSize.Level1)
{
    char *key = nullptr;
    char *value = nullptr;
    ChangeType type = DB_UPDATE;
    int32_t ret = LnnDBDataChangeSyncToCache(key, value, type);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnDBDataChangeSyncToCache(RIGHT_KEY, value, type);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnDBDataChangeSyncToCache(RIGHT_KEY, VALUE, type);
    NodeInfo localCaheInfo;
    if (LnnGetLocalCacheNodeInfo(&localCaheInfo) == SOFTBUS_NOT_IMPLEMENT) {
        EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    } else {
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
    type = DB_DELETE;
    ret = LnnDBDataChangeSyncToCache(RIGHT_KEY, VALUE, type);
    EXPECT_EQ(ret, SOFTBUS_OK);
    type = DB_CHANGE_TYPE_MAX;
    ret = LnnDBDataChangeSyncToCache(RIGHT_KEY, VALUE, type);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnDBDataAddChangeSyncToCache_Test_004
 * @tc.desc: LnnDBDataAddChangeSyncToCache
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDataCloudSyncTest, LnnDBDataAddChangeSyncToCache_Test_004, TestSize.Level1)
{
    const char **key = nullptr;
    const char **value = nullptr;
    int32_t keySize = 0;
    int32_t ret = LnnDBDataAddChangeSyncToCache(key, value, keySize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
} // namespace OHOS
