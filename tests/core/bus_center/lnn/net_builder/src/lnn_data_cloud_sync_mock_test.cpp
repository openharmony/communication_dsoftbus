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

#include <gtest/gtest.h>
#include <securec.h>
#include <cstddef>
#include <cstdlib>
#include <cstring>

#include "lnn_data_cloud_sync_deps_mock.h"
#include "lnn_kv_adapter_wrapper_mock.h"
#include "lnn_net_ledger_mock.h"
#include "lnn_data_cloud_sync.h"
#include "lnn_data_cloud_sync.c"

constexpr char MACTEST[BT_MAC_LEN] = "00:11:22:33:44";
constexpr char PEERUUID[UUID_BUF_LEN] = "021315ASD";
constexpr char NETWORKID[NETWORK_ID_BUF_LEN] = "123456ABD";
constexpr char PEERUDID[UDID_BUF_LEN] = "021315ASD";
constexpr char SOFTBUSVERSION[DEVICE_VERSION_SIZE_MAX] = "softBusVersion";
constexpr char TMPMSG[] = "{\"type\":1}";
constexpr int32_t TMP_LEN = 10;
constexpr int32_t STATE_VERSION = 2;
constexpr uint64_t TIMES_STAP0 = 0;
constexpr uint64_t TIMES_STAP1 = 1;
constexpr uint64_t TIMES_STAP2 = 2;

namespace OHOS {
using namespace testing;
using namespace testing::ext;
class LNNDataCloudSyncMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNDataCloudSyncMockTest::SetUpTestCase() {}

void LNNDataCloudSyncMockTest::TearDownTestCase() {}

void LNNDataCloudSyncMockTest::SetUp() {}

void LNNDataCloudSyncMockTest::TearDown() {}

/*
 * @tc.name: DBCipherInfoSyncToCache_Test_001
 * @tc.desc: DBCipherInfoSyncToCache
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDataCloudSyncMockTest, DBCipherInfoSyncToCache_Test_001, TestSize.Level1)
{
    NiceMock<LnnDataCloudSyncInterfaceMock> DataCloudSyncMock;
    EXPECT_CALL(DataCloudSyncMock, LnnSetRemoteBroadcastCipherInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(DataCloudSyncMock, ConvertHexStringToBytes).WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    char fieldName[FIELDNAME_MAX_LEN] = { 0 };
    NodeInfo cacheInfo;
    (void)memset_s(&cacheInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_BROADCAST_CIPHER_KEY));
    const char *value = "valueTest";
    size_t valueLength = strlen(value);
    const char *udid = "udidTest";
    EXPECT_EQ(DBCipherInfoSyncToCache(&cacheInfo, fieldName, value, valueLength, udid),
        SOFTBUS_KV_CONVERT_BYTES_FAILED);
    EXPECT_EQ(DBCipherInfoSyncToCache(&cacheInfo, fieldName, value, valueLength, udid), SOFTBUS_OK);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_BROADCAST_CIPHER_IV));
    EXPECT_CALL(DataCloudSyncMock, ConvertHexStringToBytes).WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(DBCipherInfoSyncToCache(&cacheInfo, fieldName, value, valueLength, udid),
        SOFTBUS_KV_CONVERT_BYTES_FAILED);
    EXPECT_EQ(DBCipherInfoSyncToCache(&cacheInfo, fieldName, value, valueLength, udid), SOFTBUS_OK);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_JSON_BROADCAST_KEY_TABLE));
    EXPECT_EQ(DBCipherInfoSyncToCache(&cacheInfo, fieldName, value, valueLength, udid), SOFTBUS_OK);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_DISTRIBUTED_SWITCH));
    EXPECT_EQ(DBCipherInfoSyncToCache(&cacheInfo, fieldName, value, valueLength, udid), SOFTBUS_OK);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, value));
    EXPECT_EQ(DBCipherInfoSyncToCache(&cacheInfo, fieldName, value, valueLength, udid), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNNDataCloudSyncMockTest_Test_001
 * @tc.desc: DBDeviceNameInfoSyncToCache
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDataCloudSyncMockTest, LNNDataCloudSyncMockTest_Test_001, TestSize.Level1)
{
    NodeInfo cacheInfo;
    (void)memset_s(&cacheInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    char fieldName[FIELDNAME_MAX_LEN] = { 0 };
    const char *value = "valueTest";
    size_t valueLength = strlen(value);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_DEVICE_NAME));
    EXPECT_EQ(DBDeviceNameInfoSyncToCache(&cacheInfo, fieldName, value, valueLength), SOFTBUS_OK);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_UNIFIED_DEVICE_NAME));
    EXPECT_EQ(DBDeviceNameInfoSyncToCache(&cacheInfo, fieldName, value, valueLength), SOFTBUS_OK);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_UNIFIED_DEFAULT_DEVICE_NAME));
    EXPECT_EQ(DBDeviceNameInfoSyncToCache(&cacheInfo, fieldName, value, valueLength), SOFTBUS_OK);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_SETTINGS_NICK_NAME));
    EXPECT_EQ(DBDeviceNameInfoSyncToCache(&cacheInfo, fieldName, value, valueLength), SOFTBUS_OK);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, value));
    EXPECT_EQ(DBDeviceNameInfoSyncToCache(&cacheInfo, fieldName, value, valueLength), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: DBConnectMacInfoSyncToCache_Test_001
 * @tc.desc: DBConnectMacInfoSyncToCache
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDataCloudSyncMockTest, DBConnectMacInfoSyncToCache_Test_001, TestSize.Level1)
{
    NiceMock<LnnDataCloudSyncInterfaceMock> DataCloudSyncMock;
    EXPECT_CALL(DataCloudSyncMock, ConvertHexStringToBytes).WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    char fieldName[FIELDNAME_MAX_LEN] = { 0 };
    NodeInfo cacheInfo;
    (void)memset_s(&cacheInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    const char *value = "valueTest";
    size_t valueLength = strlen(value);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_BT_MAC));
    EXPECT_EQ(DBConnectMacInfoSyncToCache(&cacheInfo, fieldName, value, valueLength), SOFTBUS_OK);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_P2P_MAC_ADDR));
    EXPECT_EQ(DBConnectMacInfoSyncToCache(&cacheInfo, fieldName, value, valueLength), SOFTBUS_OK);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_DEVICE_IRK));
    EXPECT_EQ(DBConnectMacInfoSyncToCache(&cacheInfo, fieldName, value, valueLength),
        SOFTBUS_KV_CONVERT_BYTES_FAILED);
    EXPECT_EQ(DBConnectMacInfoSyncToCache(&cacheInfo, fieldName, value, valueLength), SOFTBUS_OK);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_DEVICE_PUB_MAC));
    EXPECT_CALL(DataCloudSyncMock, ConvertHexStringToBytes).WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(DBConnectMacInfoSyncToCache(&cacheInfo, fieldName, value, valueLength),
        SOFTBUS_KV_CONVERT_BYTES_FAILED);
    EXPECT_EQ(DBConnectMacInfoSyncToCache(&cacheInfo, fieldName, value, valueLength), SOFTBUS_OK);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, value));
    EXPECT_EQ(DBDeviceNameInfoSyncToCache(&cacheInfo, fieldName, value, valueLength), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: JudgeFieldNameIsDeviceBasicInfo_Test_001
 * @tc.desc: JudgeFieldNameIsDeviceBasicInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDataCloudSyncMockTest, JudgeFieldNameIsDeviceBasicInfo_Test_001, TestSize.Level1)
{
    char fieldName[FIELDNAME_MAX_LEN] = { 0 };
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_DEVICE_NAME));
    EXPECT_EQ(JudgeFieldNameIsDeviceBasicInfo(nullptr), false);
    EXPECT_EQ(JudgeFieldNameIsDeviceBasicInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_UNIFIED_DEVICE_NAME));
    EXPECT_EQ(JudgeFieldNameIsDeviceBasicInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_UNIFIED_DEFAULT_DEVICE_NAME));
    EXPECT_EQ(JudgeFieldNameIsDeviceBasicInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_SETTINGS_NICK_NAME));
    EXPECT_EQ(JudgeFieldNameIsDeviceBasicInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_DEVICE_UDID));
    EXPECT_EQ(JudgeFieldNameIsDeviceBasicInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_DEVICE_TYPE));
    EXPECT_EQ(JudgeFieldNameIsDeviceBasicInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_OS_TYPE));
    EXPECT_EQ(JudgeFieldNameIsDeviceBasicInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_OS_VERSION));
    EXPECT_EQ(JudgeFieldNameIsDeviceBasicInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_DEVICE_UUID));
    EXPECT_EQ(JudgeFieldNameIsDeviceBasicInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_DEVICE_PUB_MAC));
    EXPECT_EQ(JudgeFieldNameIsDeviceBasicInfo(fieldName), false);
}

/*
 * @tc.name: JudgeFieldNameIsNumInfo_Test_001
 * @tc.desc: JudgeFieldNameIsNumInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDataCloudSyncMockTest, JudgeFieldNameIsNumInfo_Test_001, TestSize.Level1)
{
    char fieldName[FIELDNAME_MAX_LEN] = { 0 };
    EXPECT_EQ(JudgeFieldNameIsNumInfo(nullptr), false);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_STATE_VERSION));
    EXPECT_EQ(JudgeFieldNameIsNumInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_TRANSPORT_PROTOCOL));
    EXPECT_EQ(JudgeFieldNameIsNumInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_WIFI_VERSION));
    EXPECT_EQ(JudgeFieldNameIsNumInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_BLE_VERSION));
    EXPECT_EQ(JudgeFieldNameIsNumInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_ACCOUNT_ID));
    EXPECT_EQ(JudgeFieldNameIsNumInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_FEATURE));
    EXPECT_EQ(JudgeFieldNameIsNumInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_CONN_SUB_FEATURE));
    EXPECT_EQ(JudgeFieldNameIsNumInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_AUTH_CAP));
    EXPECT_EQ(JudgeFieldNameIsNumInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_DEVICE_PUB_MAC));
    EXPECT_EQ(JudgeFieldNameIsNumInfo(fieldName), false);
}

/*
 * @tc.name: JudgeFieldNameIsConnectInfo_Test_001
 * @tc.desc: JudgeFieldNameIsConnectInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDataCloudSyncMockTest, JudgeFieldNameIsConnectInfo_Test_001, TestSize.Level1)
{
    char fieldName[FIELDNAME_MAX_LEN] = { 0 };
    EXPECT_EQ(JudgeFieldNameIsConnectInfo(nullptr), false);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_NETWORK_ID));
    EXPECT_EQ(JudgeFieldNameIsConnectInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_PKG_VERSION));
    EXPECT_EQ(JudgeFieldNameIsConnectInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_BT_MAC));
    EXPECT_EQ(JudgeFieldNameIsConnectInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_P2P_MAC_ADDR));
    EXPECT_EQ(JudgeFieldNameIsConnectInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_DEVICE_IRK));
    EXPECT_EQ(JudgeFieldNameIsConnectInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_DEVICE_PUB_MAC));
    EXPECT_EQ(JudgeFieldNameIsConnectInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_PTK));
    EXPECT_EQ(JudgeFieldNameIsConnectInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_SW_VERSION));
    EXPECT_EQ(JudgeFieldNameIsConnectInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_DEVICE_PUB_MAC));
    EXPECT_EQ(JudgeFieldNameIsConnectInfo(fieldName), true);
}

/*
 * @tc.name: JudgeFieldNameIsCipherInfo_Test_001
 * @tc.desc: JudgeFieldNameIsCipherInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDataCloudSyncMockTest, JudgeFieldNameIsCipherInfo_Test_001, TestSize.Level1)
{
    char fieldName[FIELDNAME_MAX_LEN] = { 0 };
    EXPECT_EQ(JudgeFieldNameIsCipherInfo(nullptr), false);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_BROADCAST_CIPHER_KEY));
    EXPECT_EQ(JudgeFieldNameIsCipherInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_BROADCAST_CIPHER_IV));
    EXPECT_EQ(JudgeFieldNameIsCipherInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_JSON_BROADCAST_KEY_TABLE));
    EXPECT_EQ(JudgeFieldNameIsCipherInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_JSON_KEY_TOTAL_LIFE));
    EXPECT_EQ(JudgeFieldNameIsCipherInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_JSON_KEY_TIMESTAMP_BEGIN));
    EXPECT_EQ(JudgeFieldNameIsCipherInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_JSON_KEY_CURRENT_INDEX));
    EXPECT_EQ(JudgeFieldNameIsCipherInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_DISTRIBUTED_SWITCH));
    EXPECT_EQ(JudgeFieldNameIsCipherInfo(fieldName), true);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_DEVICE_PUB_MAC));
    EXPECT_EQ(JudgeFieldNameIsCipherInfo(fieldName), false);
}

/*
 * @tc.name: DBDataChangeBatchSyncToCacheInternal_Test_001
 * @tc.desc: DBDataChangeBatchSyncToCacheInternal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDataCloudSyncMockTest, DBDataChangeBatchSyncToCacheInternal_Test_001, TestSize.Level1)
{
    char fieldName[FIELDNAME_MAX_LEN] = { 0 };
    NodeInfo cacheInfo;
    (void)memset_s(&cacheInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    const char *value = "valueTest";
    size_t valueLength = strlen(value);
    const char *udid = "udidTest";
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_DEVICE_UDID));
    EXPECT_EQ(DBDataChangeBatchSyncToCacheInternal(&cacheInfo, fieldName, value, valueLength, udid), SOFTBUS_OK);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_STATE_VERSION));
    EXPECT_EQ(DBDataChangeBatchSyncToCacheInternal(&cacheInfo, fieldName, value, valueLength, udid), SOFTBUS_OK);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_PKG_VERSION));
    EXPECT_EQ(DBDataChangeBatchSyncToCacheInternal(&cacheInfo, fieldName, value, valueLength, udid), SOFTBUS_OK);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_DISTRIBUTED_SWITCH));
    EXPECT_EQ(DBDataChangeBatchSyncToCacheInternal(&cacheInfo, fieldName, value, valueLength, udid), SOFTBUS_OK);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_BLE_P2P));
    EXPECT_EQ(DBDataChangeBatchSyncToCacheInternal(&cacheInfo, fieldName, value, valueLength, udid), SOFTBUS_OK);
    const char *value1 = "true";
    char deviceUdid[UDID_BUF_LEN] = { 0 };
    UpdateInfoToLedger(&cacheInfo, deviceUdid, fieldName, const_cast<char *>(value1));
    EXPECT_EQ(DBDataChangeBatchSyncToCacheInternal(&cacheInfo, fieldName, value1, valueLength, udid), SOFTBUS_OK);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, value));
    EXPECT_EQ(DBDataChangeBatchSyncToCacheInternal(&cacheInfo, fieldName, value, valueLength, udid),
        SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DBDataChangeBatchSyncToCacheInternal(nullptr, fieldName, value, valueLength, udid),
        SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DBDataChangeBatchSyncToCacheInternal(&cacheInfo, nullptr, value, valueLength, udid),
        SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DBDataChangeBatchSyncToCacheInternal(&cacheInfo, fieldName, nullptr, valueLength, udid),
        SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DBDataChangeBatchSyncToCacheInternal(&cacheInfo, fieldName, value, valueLength, nullptr),
        SOFTBUS_INVALID_PARAM);
    const char *udid1 = "123456789123456789123456789123456789123456789123456789123456789123456789";
    EXPECT_EQ(DBDataChangeBatchSyncToCacheInternal(&cacheInfo, fieldName, value, valueLength, udid1),
        SOFTBUS_INVALID_PARAM);
    const char *key = "key";
    char splitKeyValue[SPLIT_KEY_NUM][SPLIT_MAX_LEN];
    EXPECT_EQ(SplitKeyOrValue(nullptr, splitKeyValue, 0), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SplitKeyOrValue(key, nullptr, 0), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetInfoFromSplitKey_Test_001
 * @tc.desc: GetInfoFromSplitKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDataCloudSyncMockTest, GetInfoFromSplitKey_Test_001, TestSize.Level1)
{
    char splitKey[][SPLIT_MAX_LEN] = {
        "123456",
        "234567",
        "345678",
    };
    int64_t accountId;
    char deviceUdid[UDID_BUF_LEN] = { 0 };
    char fieldName[FIELDNAME_MAX_LEN] = { 0 };
    EXPECT_EQ(GetInfoFromSplitKey(splitKey, &accountId, deviceUdid, fieldName), SOFTBUS_OK);
    EXPECT_EQ(GetInfoFromSplitKey(nullptr, &accountId, deviceUdid, fieldName), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(GetInfoFromSplitKey(splitKey, nullptr, deviceUdid, fieldName), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(GetInfoFromSplitKey(splitKey, &accountId, nullptr, fieldName), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(GetInfoFromSplitKey(splitKey, &accountId, deviceUdid, nullptr), SOFTBUS_INVALID_PARAM);
    char splitValue[SPLIT_VALUE_NUM][SPLIT_MAX_LEN];
    const char *key = "key";
    const char *value = "value";
    CloudSyncValue parseValue;
    EXPECT_EQ(SplitString(nullptr, splitValue, key, value, &parseValue), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SplitString(splitKey, nullptr, key, value, &parseValue), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SplitString(splitKey, splitValue, nullptr, value, &parseValue), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SplitString(splitKey, splitValue, key, nullptr, &parseValue), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SplitString(splitKey, splitValue, key, value, nullptr), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: HandleDBAddChangeInternal_Test_001
 * @tc.desc: HandleDBAddChangeInternal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDataCloudSyncMockTest, HandleDBAddChangeInternal_Test_001, TestSize.Level1)
{
    NodeInfo localCaheInfo = { .stateVersion = 12, };
    EXPECT_EQ(EOK, strcpy_s(localCaheInfo.deviceInfo.deviceUdid, UDID_BUF_LEN, PEERUDID));
    NiceMock<LnnDataCloudSyncInterfaceMock> DataCloudSyncMock;
    EXPECT_CALL(DataCloudSyncMock, LnnGetLocalCacheNodeInfo).WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(DoAll(SetArgPointee<0>(localCaheInfo), Return(SOFTBUS_OK)));
    const char *key = "key1#key2#key3";
    const char *value = "value1#value2#value3";
    NodeInfo cacheInfo;
    (void)memset_s(&cacheInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_EQ(HandleDBAddChangeInternal(key, value, &cacheInfo), SOFTBUS_ERR);
    EXPECT_EQ(HandleDBAddChangeInternal(key, value, &cacheInfo), SOFTBUS_ERR);
}

/*
 * @tc.name: SetDBNameDataToDLedger_Test_001
 * @tc.desc: SetDBNameDataToDLedger
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDataCloudSyncMockTest, SetDBNameDataToDLedger_Test_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> NetLedgerMock;
    EXPECT_CALL(NetLedgerMock, LnnSetDLDeviceInfoName).WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetLedgerMock, LnnSetDLUnifiedDeviceName).WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetLedgerMock, LnnSetDLUnifiedDefaultDeviceName).WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetLedgerMock, LnnSetDLDeviceNickNameByUdid).WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    NodeInfo cacheInfo;
    (void)memset_s(&cacheInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    char deviceUdid[UDID_BUF_LEN] = { 0 };
    char fieldName[FIELDNAME_MAX_LEN] = { 0 };
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_DEVICE_NAME));
    EXPECT_EQ(SetDBNameDataToDLedger(&cacheInfo, deviceUdid, fieldName), SOFTBUS_OK);
    EXPECT_EQ(SetDBNameDataToDLedger(&cacheInfo, deviceUdid, fieldName), SOFTBUS_ERR);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_UNIFIED_DEVICE_NAME));
    EXPECT_EQ(SetDBNameDataToDLedger(&cacheInfo, deviceUdid, fieldName), SOFTBUS_ERR);
    EXPECT_EQ(SetDBNameDataToDLedger(&cacheInfo, deviceUdid, fieldName), SOFTBUS_OK);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_UNIFIED_DEFAULT_DEVICE_NAME));
    EXPECT_EQ(SetDBNameDataToDLedger(&cacheInfo, deviceUdid, fieldName), SOFTBUS_ERR);
    EXPECT_EQ(SetDBNameDataToDLedger(&cacheInfo, deviceUdid, fieldName), SOFTBUS_OK);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_SETTINGS_NICK_NAME));
    EXPECT_EQ(SetDBNameDataToDLedger(&cacheInfo, deviceUdid, fieldName), SOFTBUS_ERR);
    EXPECT_EQ(SetDBNameDataToDLedger(&cacheInfo, deviceUdid, fieldName), SOFTBUS_OK);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_DISTRIBUTED_SWITCH));
    EXPECT_EQ(SetDBNameDataToDLedger(&cacheInfo, deviceUdid, fieldName), SOFTBUS_OK);
}

/*
 * @tc.name: SetDBDataToDistributedLedger_Test_001
 * @tc.desc: SetDBDataToDistributedLedger
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDataCloudSyncMockTest, SetDBDataToDistributedLedger_Test_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> NetLedgerMock;
    EXPECT_CALL(NetLedgerMock, LnnSetDLDeviceBroadcastCipherKey).WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetLedgerMock, LnnSetDLDeviceBroadcastCipherIv).WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(NetLedgerMock, LnnSetDLDeviceStateVersion).WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<LnnDataCloudSyncInterfaceMock> DataCloudSyncMock;
    EXPECT_CALL(DataCloudSyncMock, LnnUpdateNetworkId).WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    NodeInfo cacheInfo;
    (void)memset_s(&cacheInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    char deviceUdid[UDID_BUF_LEN] = { 0 };
    char fieldName[FIELDNAME_MAX_LEN] = { 0 };
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_BROADCAST_CIPHER_KEY));
    EXPECT_EQ(SetDBDataToDistributedLedger(&cacheInfo, deviceUdid, 0, fieldName), SOFTBUS_ERR);
    EXPECT_EQ(SetDBDataToDistributedLedger(&cacheInfo, deviceUdid, 0, fieldName), SOFTBUS_OK);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_BROADCAST_CIPHER_IV));
    EXPECT_EQ(SetDBDataToDistributedLedger(&cacheInfo, deviceUdid, 0, fieldName), SOFTBUS_ERR);
    EXPECT_EQ(SetDBDataToDistributedLedger(&cacheInfo, deviceUdid, 0, fieldName), SOFTBUS_OK);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_NETWORK_ID));
    EXPECT_EQ(SetDBDataToDistributedLedger(&cacheInfo, deviceUdid, 0, fieldName), SOFTBUS_ERR);
    EXPECT_EQ(SetDBDataToDistributedLedger(&cacheInfo, deviceUdid, 0, fieldName), SOFTBUS_OK);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_STATE_VERSION));
    EXPECT_EQ(SetDBDataToDistributedLedger(&cacheInfo, deviceUdid, 0, fieldName), SOFTBUS_ERR);
    EXPECT_EQ(SetDBDataToDistributedLedger(&cacheInfo, deviceUdid, 0, fieldName), SOFTBUS_OK);
    EXPECT_EQ(EOK, strcpy_s(fieldName, FIELDNAME_MAX_LEN, DEVICE_INFO_DISTRIBUTED_SWITCH));
    const char *value = "value";
    UpdateInfoToLedger(&cacheInfo, deviceUdid, fieldName, const_cast<char *>(value));
    EXPECT_EQ(SetDBDataToDistributedLedger(&cacheInfo, deviceUdid, 0, fieldName), SOFTBUS_OK);
    EXPECT_EQ(SetDBDataToDistributedLedger(nullptr, deviceUdid, 0, fieldName), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SetDBDataToDistributedLedger(&cacheInfo, nullptr, 0, fieldName), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SetDBDataToDistributedLedger(&cacheInfo, deviceUdid, UDID_BUF_LEN, fieldName),
        SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SetDBDataToDistributedLedger(&cacheInfo, deviceUdid, 0, nullptr), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: IsIgnoreUpdate_Test_001
 * @tc.desc: IsIgnoreUpdate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDataCloudSyncMockTest, IsIgnoreUpdate_Test_001, TestSize.Level1)
{
    NodeInfo cacheInfo;
    (void)memset_s(&cacheInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    char deviceUdid[UDID_BUF_LEN] = { 0 };
    char fieldName[FIELDNAME_MAX_LEN] = { 0 };
    const char *value = "value";
    const char *deviceUdid1 = "123456789123456789123456789123456789123456789123456789123456789123456789";
    UpdateInfoToLedger(nullptr, deviceUdid, fieldName, const_cast<char *>(value));
    UpdateInfoToLedger(&cacheInfo, nullptr, fieldName, const_cast<char *>(value));
    UpdateInfoToLedger(&cacheInfo, deviceUdid, nullptr, const_cast<char *>(value));
    UpdateInfoToLedger(&cacheInfo, deviceUdid, fieldName, nullptr);
    UpdateInfoToLedger(&cacheInfo, const_cast<char *>(deviceUdid1), fieldName, const_cast<char *>(value));
    EXPECT_EQ(IsIgnoreUpdate(STATE_VERSION, TIMES_STAP0, STATE_VERSION, TIMES_STAP0), false);
    EXPECT_EQ(IsIgnoreUpdate(STATE_VERSION, TIMES_STAP2, STATE_VERSION, TIMES_STAP1), true);
}

/*
 * @tc.name: HandleDBUpdateInternal_Test_001
 * @tc.desc: HandleDBUpdateInternal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDataCloudSyncMockTest, HandleDBUpdateInternal_Test_001, TestSize.Level1)
{
    NiceMock<LnnDataCloudSyncInterfaceMock> DataCloudSyncMock;
    EXPECT_CALL(DataCloudSyncMock, LnnGenerateHexStringHash).WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(DataCloudSyncMock, LnnRetrieveDeviceInfo).WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(DataCloudSyncMock, LnnSaveRemoteDeviceInfo).WillRepeatedly(Return(SOFTBUS_OK));
    char deviceUdid[UDID_BUF_LEN] = { 0 };
    char fieldName[FIELDNAME_MAX_LEN] = { 0 };
    CloudSyncValue parseValue;
    char trueValue[SPLIT_MAX_LEN] = { 0 };
    int32_t localStateVersion = 0;
    EXPECT_EQ(HandleDBUpdateInternal(deviceUdid, fieldName, trueValue, &parseValue, localStateVersion), SOFTBUS_ERR);
    EXPECT_EQ(HandleDBUpdateInternal(deviceUdid, fieldName, trueValue, &parseValue, localStateVersion), SOFTBUS_OK);
    EXPECT_EQ(HandleDBUpdateInternal(deviceUdid, fieldName, trueValue, &parseValue, localStateVersion), SOFTBUS_OK);
    EXPECT_EQ(HandleDBUpdateInternal(nullptr, fieldName, trueValue, &parseValue, localStateVersion),
        SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(HandleDBUpdateInternal(deviceUdid, nullptr, trueValue, &parseValue, localStateVersion),
        SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(HandleDBUpdateInternal(deviceUdid, fieldName, nullptr, &parseValue, localStateVersion),
        SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnDBDataAddChangeSyncToCache_Test_001
 * @tc.desc: LnnDBDataAddChangeSyncToCache
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDataCloudSyncMockTest, LnnDBDataAddChangeSyncToCache_Test_001, TestSize.Level1)
{
    const char **key = reinterpret_cast<const char **>(SoftBusCalloc(TMP_LEN * TMP_LEN));
    const char **value = reinterpret_cast<const char **>(SoftBusCalloc(TMP_LEN * TMP_LEN));
    int32_t keySize = 0;
    EXPECT_EQ(LnnDBDataAddChangeSyncToCache(nullptr, value, keySize), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnDBDataAddChangeSyncToCache(key, nullptr, keySize), SOFTBUS_INVALID_PARAM);
    SoftBusFree(key);
    SoftBusFree(value);
}

/*
 * @tc.name: LnnDBDataChangeSyncToCacheInner_Test_001
 * @tc.desc: LnnDBDataChangeSyncToCacheInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDataCloudSyncMockTest, LnnDBDataChangeSyncToCacheInner_Test_001, TestSize.Level1)
{
    NodeInfo cacheInfo = { .accountId = 12345, };
    EXPECT_EQ(EOK, strcpy_s(cacheInfo.p2pInfo.p2pMac, MAC_LEN, MACTEST));
    EXPECT_EQ(EOK, strcpy_s(cacheInfo.connectInfo.macAddr, MAC_LEN, MACTEST));
    EXPECT_EQ(EOK, strcpy_s(cacheInfo.deviceInfo.deviceUdid, UDID_BUF_LEN, PEERUDID));
    EXPECT_EQ(EOK, strcpy_s(cacheInfo.uuid, UUID_BUF_LEN, PEERUUID));
    EXPECT_EQ(EOK, strcpy_s(cacheInfo.networkId, NETWORK_ID_BUF_LEN, NETWORKID));
    EXPECT_EQ(EOK, strcpy_s(cacheInfo.deviceInfo.deviceVersion, DEVICE_VERSION_SIZE_MAX, SOFTBUSVERSION));
    PrintSyncNodeInfo(nullptr);
    PrintSyncNodeInfo(&cacheInfo);
    NiceMock<LnnDataCloudSyncInterfaceMock> DataCloudSyncMock;
    EXPECT_CALL(DataCloudSyncMock, LnnUnPackCloudSyncDeviceInfo).WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(DoAll(SetArgPointee<1>(cacheInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(DataCloudSyncMock, LnnGenerateHexStringHash).WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(DataCloudSyncMock, LnnRetrieveDeviceInfo).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(DataCloudSyncMock, LnnGetLocalCacheNodeInfo).WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    const char *key = "key";
    const char *value = TMPMSG;
    EXPECT_EQ(LnnDBDataChangeSyncToCacheInner(key, value), SOFTBUS_ERR);
    EXPECT_EQ(LnnDBDataChangeSyncToCacheInner(key, value), SOFTBUS_ERR);
    EXPECT_EQ(LnnDBDataChangeSyncToCacheInner(key, value), SOFTBUS_ERR);
    EXPECT_EQ(LnnDBDataChangeSyncToCacheInner(key, value), SOFTBUS_OK);
    EXPECT_EQ(LnnDBDataChangeSyncToCacheInner(key, value), SOFTBUS_OK);
    EXPECT_EQ(LnnDBDataChangeSyncToCacheInner(nullptr, value), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnDBDataChangeSyncToCacheInner(key, nullptr), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnLedgerDataChangeSyncToDB_Test_001
 * @tc.desc: LnnLedgerDataChangeSyncToDB
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDataCloudSyncMockTest, LnnLedgerDataChangeSyncToDB_Test_001, TestSize.Level1)
{
    NodeInfo localCaheInfo = { .accountId = 0, .stateVersion = 12, };
    EXPECT_EQ(EOK, strcpy_s(localCaheInfo.deviceInfo.deviceUdid, UDID_BUF_LEN, PEERUDID));
    NiceMock<LnnDataCloudSyncInterfaceMock> DataCloudSyncMock;
    EXPECT_CALL(DataCloudSyncMock, LnnGetLocalCacheNodeInfo).WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(DoAll(SetArgPointee<0>(localCaheInfo), Return(SOFTBUS_OK)));
    const char key[] = "key";
    const char value[] = "value";
    size_t valueLength = strlen(value);
    EXPECT_EQ(LnnLedgerDataChangeSyncToDB(key, value, valueLength), SOFTBUS_ERR);
    EXPECT_EQ(LnnLedgerDataChangeSyncToDB(key, value, valueLength), SOFTBUS_OK);
    EXPECT_EQ(LnnLedgerDataChangeSyncToDB(nullptr, value, valueLength), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnLedgerDataChangeSyncToDB(key, nullptr, valueLength), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnLedgerDataChangeSyncToDB(key, value, KEY_MAX_LEN), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: PackBroadcastCipherKeyInner_Test_001
 * @tc.desc: PackBroadcastCipherKeyInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDataCloudSyncMockTest, PackBroadcastCipherKeyInner_Test_001, TestSize.Level1)
{
    CloudSyncInfo syncInfo;
    (void)memset_s(&syncInfo, sizeof(CloudSyncInfo), 0, sizeof(CloudSyncInfo));
    syncInfo.broadcastCipherKey = reinterpret_cast<char *>(SoftBusCalloc(TMP_LEN));
    ASSERT_TRUE(syncInfo.broadcastCipherKey != nullptr);
    NiceMock<LnnDataCloudSyncInterfaceMock> DataCloudSyncMock;
    EXPECT_CALL(DataCloudSyncMock, LnnPackCloudSyncDeviceInfo).WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(DataCloudSyncMock, LnnGetLocalBroadcastCipherInfo).WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(DoAll(SetArgPointee<0>(syncInfo), Return(SOFTBUS_OK)));
    cJSON *json = cJSON_CreateObject();
    ASSERT_TRUE(json != nullptr);
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_NE(PackBroadcastCipherKeyInner(json, &info), SOFTBUS_OK);
    EXPECT_NE(PackBroadcastCipherKeyInner(json, &info), SOFTBUS_OK);
    EXPECT_EQ(PackBroadcastCipherKeyInner(json, &info), SOFTBUS_OK);
    cJSON_Delete(json);
}
} // namespace OHOS