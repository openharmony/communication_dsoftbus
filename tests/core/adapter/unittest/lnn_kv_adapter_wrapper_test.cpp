/*
* Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "lnn_kv_adapter_wrapper.h"
#include "softbus_errcode.h"
#include "softbus_adapter_mem.h"
#include <cstdint>
#include <string>
#include <cstring>

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace {
constexpr int32_t MAX_STRING_LEN = 4096;
constexpr int32_t MIN_STRING_LEN = 1;
constexpr int32_t APP_ID_LEN = 8;
constexpr int32_t STORE_ID_LEN = 19;
const std::string APP_ID = "dsoftbus";
const std::string STORE_ID = "dsoftbus_kv_db_test";
}
static int32_t g_dbId = 1;
class KVAdapterWrapperTest : public testing::Test {
protected:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
void KVAdapterWrapperTest::SetUpTestCase(void)
{
    int32_t dbID;
    LnnCreateKvAdapter(&dbID, APP_ID.c_str(), APP_ID_LEN, STORE_ID.c_str(), STORE_ID_LEN);
    g_dbId = dbID;
}

void KVAdapterWrapperTest::TearDownTestCase(void)
{
    LnnDestroyKvAdapter(g_dbId);
}

void KVAdapterWrapperTest::SetUp()
{
}

void KVAdapterWrapperTest::TearDown()
{
}

/**
 * @tc.name: LnnPutDBData
 * @tc.desc: LnnPutDBData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnPutDBData001, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    string keyStr = "aaa";
    string valueStr = "aaa";
    EXPECT_EQ(LnnPutDBData(dbId, keyStr.c_str(), 3, valueStr.c_str(), 3), SOFTBUS_OK);
    dbId++;
    EXPECT_EQ(LnnPutDBData(dbId, keyStr.c_str(), MAX_STRING_LEN, valueStr.c_str(), MAX_STRING_LEN),
        SOFTBUS_INVALID_PARAM);
    dbId = 0;
    EXPECT_EQ(LnnPutDBData(dbId, keyStr.c_str(), MAX_STRING_LEN, valueStr.c_str(), MAX_STRING_LEN),
        SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnPutDBData(dbId, keyStr.c_str(), MAX_STRING_LEN, valueStr.c_str(), MAX_STRING_LEN + 1),
        SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnPutDBData(dbId, keyStr.c_str(), MAX_STRING_LEN, valueStr.c_str(), MIN_STRING_LEN - 1),
        SOFTBUS_INVALID_PARAM);
    char *valuePtr = nullptr;
    EXPECT_EQ(LnnPutDBData(dbId, keyStr.c_str(), MAX_STRING_LEN, valuePtr, MIN_STRING_LEN - 1),
        SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnPutDBData(dbId, keyStr.c_str(), MAX_STRING_LEN + 1, valuePtr, MIN_STRING_LEN - 1),
        SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnPutDBData(dbId, keyStr.c_str(), MIN_STRING_LEN - 1, valuePtr, MIN_STRING_LEN - 1),
        SOFTBUS_INVALID_PARAM);
    char *keyPtr = nullptr;
    EXPECT_EQ(LnnPutDBData(dbId, keyPtr, MIN_STRING_LEN - 1, valuePtr, MIN_STRING_LEN - 1), SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: LnnDeleteDBData
 * @tc.desc: LnnDeleteDBData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnDelete001, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    string keyStr = "aaa";
    string valueStr = "ccc";
    EXPECT_EQ(LnnPutDBData(dbId, keyStr.c_str(), 3, valueStr.c_str(), 3), SOFTBUS_OK);
    EXPECT_EQ(LnnDeleteDBData(dbId, keyStr.c_str(), 3), SOFTBUS_OK);
    dbId++;
    EXPECT_EQ(LnnDeleteDBData(dbId, keyStr.c_str(), MAX_STRING_LEN), SOFTBUS_INVALID_PARAM);
    dbId = 0;
    EXPECT_EQ(LnnDeleteDBData(dbId, keyStr.c_str(), MAX_STRING_LEN), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnDeleteDBData(dbId, keyStr.c_str(), MAX_STRING_LEN + 1), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnDeleteDBData(dbId, keyStr.c_str(), MIN_STRING_LEN - 1), SOFTBUS_INVALID_PARAM);
    char *keyPtr = nullptr;
    EXPECT_EQ(LnnDeleteDBData(dbId, keyPtr, MIN_STRING_LEN - 1), SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: LnnDeleteDBDataByPrefix
 * @tc.desc: LnnDeleteDBDataByPrefix
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnDeleteByPrefix001, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    string keyStr = "aa11";
    string valueStr = "111";
    EXPECT_EQ(LnnPutDBData(dbId, keyStr.c_str(), 4, valueStr.c_str(), 3), SOFTBUS_OK);
    string keyStr2 = "aa22";
    string valueStr2 = "222";
    EXPECT_EQ(LnnPutDBData(dbId, keyStr2.c_str(), 4, valueStr2.c_str(), 3), SOFTBUS_OK);
    string keyPrefix = "aa";
    EXPECT_EQ(LnnDeleteDBDataByPrefix(dbId, keyPrefix.c_str(), 2), SOFTBUS_OK);
    dbId++;
    EXPECT_EQ(LnnDeleteDBDataByPrefix(dbId, keyStr.c_str(), MAX_STRING_LEN), SOFTBUS_INVALID_PARAM);
    dbId = 0;
    EXPECT_EQ(LnnDeleteDBDataByPrefix(dbId, keyStr.c_str(), MAX_STRING_LEN), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnDeleteDBDataByPrefix(dbId, keyStr.c_str(), MAX_STRING_LEN + 1), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnDeleteDBDataByPrefix(dbId, keyStr.c_str(), MIN_STRING_LEN - 1), SOFTBUS_INVALID_PARAM);
    char *keyPtr = nullptr;
    EXPECT_EQ(LnnDeleteDBDataByPrefix(dbId, keyPtr, MIN_STRING_LEN - 1), SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: LnnGetDBData
 * @tc.desc: LnnGetDBData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnGet001, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    string keyStr = "aaa";
    string valueStr = "aaa";
    char *value = nullptr;
    EXPECT_EQ(LnnPutDBData(dbId, keyStr.c_str(), 3, valueStr.c_str(), 3), SOFTBUS_OK);
    EXPECT_EQ(LnnGetDBData(dbId, keyStr.c_str(), 3, &value), SOFTBUS_OK);
    SoftBusFree(value);
    value = nullptr;
    dbId++;
    EXPECT_EQ(LnnGetDBData(dbId, keyStr.c_str(), MAX_STRING_LEN, &value), SOFTBUS_INVALID_PARAM);
    dbId = 0;
    EXPECT_EQ(LnnGetDBData(dbId, keyStr.c_str(), MAX_STRING_LEN, &value), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnGetDBData(dbId, keyStr.c_str(), MAX_STRING_LEN + 1, &value), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnGetDBData(dbId, keyStr.c_str(), MIN_STRING_LEN - 1, &value), SOFTBUS_INVALID_PARAM);
    char *keyPtr = nullptr;
    EXPECT_EQ(LnnGetDBData(dbId, keyPtr, MIN_STRING_LEN - 1, &value), SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: LnnPutDBDataBatch
 * @tc.desc: LnnPutDBDataBatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnPutBatch001, TestSize.Level1)
{
    int32_t dbId = g_dbId;
    CloudSyncInfo info {
        .networkId = "networkId",
        .deviceName = "deviceName",
        .unifiedName = "unifiedName",
        .unifiedDefaultName = "unifiedDefaultName",
        .nickName = "nickName",
        .deviceTypeId = 1,
        .deviceUdid = "deviceUdid",
        .uuid = "uuid",
        .softBusVersion = "softBusVersion",
        .isBleP2p = true,
        .supportedProtocols = 1,
        .pkgVersion = "pkgVersion",
        .wifiVersion = 1,
        .bleVersion = 1,
        .macAddr = "macAddr",
        .accountId = 1,
        .feature = 1,
        .connSubFeature = 1,
        .authCapacity = 1,
        .osType = 1,
        .osVersion = "osVersion",
        .stateVersion = 1,
        .p2pMac = "p2pMac",
        .peerIrk = {1},
        .publicAddress = {1},
        .remotePtk = "remotePtk",
        .tableMain = "tableMain",
        .lifeTotal = 1,
        .curBeginTime = 1,
        .currentIndex = 1,
        .cipherKey = {1},
        .cipherIv = {1},
        .distributedSwitch = true
    };
    EXPECT_EQ(LnnPutDBDataBatch(dbId, &info), SOFTBUS_OK);
    char *value = nullptr;
    string SEPARATOR = "#";
    string networkIdKey = to_string(info.accountId) + SEPARATOR + info.deviceUdid + SEPARATOR + "NETWORK_ID";
    string expectNetworkIdValue = info.networkId + SEPARATOR + to_string(info.stateVersion);
    LnnGetDBData(dbId, networkIdKey.c_str(), networkIdKey.length(), &value);
    EXPECT_EQ(strcmp(value, expectNetworkIdValue.c_str()), 0);
    SoftBusFree(value);
}

/**
 * @tc.name: LnnDestroyKvAdapter
 * @tc.desc: LnnDestroyKvAdapter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterWrapperTest, LnnDestroy001, TestSize.Level1)
{
    int32_t dbId;
    int32_t createRet = LnnCreateKvAdapter(&dbId, APP_ID.c_str(), APP_ID_LEN, STORE_ID.c_str(), STORE_ID_LEN);
    EXPECT_EQ(createRet, SOFTBUS_OK);
    EXPECT_EQ(LnnDestroyKvAdapter(dbId), SOFTBUS_OK);
}

} // namespace OHOS
