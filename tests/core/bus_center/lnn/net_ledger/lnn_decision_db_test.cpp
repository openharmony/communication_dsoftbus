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

#include "lnn_decision_db.c"
#include "lnn_decision_db.h"
#include "lnn_decision_db_deps_mock.h"
#include "lnn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;
constexpr char NODE_UDID[] = "123456ABCDEF";
constexpr int32_t DEFAULT_USERID = 100;
#define WAIT_ONE_HOUR_QUERY_INTERVAL   (60 * 60 * 1000)
#define WAIT_SEVEN_DAYS_QUERY_INTERVAL (7 * 24 * 60 * 60 * 1000)
#define TEST_LEN 10
using namespace testing;
class LNNDbMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNDbMockTest::SetUpTestCase() { }

void LNNDbMockTest::TearDownTestCase() { }

void LNNDbMockTest::SetUp()
{
    LNN_LOGI(LNN_TEST, "LNNDbMockTest start");
}

void LNNDbMockTest::TearDown()
{
    LNN_LOGI(LNN_TEST, "LNNDbMockTest finish");
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_001
 * @tc.desc: Verify LnnInitDecisionDbDelay returns SOFTBUS_GENERATE_KEY_FAIL
 *           when LnnGenerateKeyByHuks fails
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_001, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_))
        .WillRepeatedly(Return(SOFTBUS_HUKS_GENERATE_KEY_ERR));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_TRUE(ret == SOFTBUS_GENERATE_KEY_FAIL);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_002
 * @tc.desc: Verify LnnInitDecisionDbDelay returns SOFTBUS_NETWORK_GET_PATH_FAILED
 *           when OpenDatabase and LnnGetFullStoragePath fail
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_002, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGenerateCeKeyByHuks(_, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_NETWORK_DATABASE_FAILED));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_NETWORK_GET_PATH_FAILED));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_GET_PATH_FAILED);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_003
 * @tc.desc: Verify LnnInitDecisionDbDelay returns SOFTBUS_NETWORK_GET_PATH_FAILED
 *           when LnnGetFullStoragePath fails after database open
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_003, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGenerateCeKeyByHuks(_, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_NETWORK_GET_PATH_FAILED));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_GET_PATH_FAILED);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_004
 * @tc.desc: Verify LnnInitDecisionDbDelay returns SOFTBUS_NETWORK_INIT_TRUST_DEV_INFO_FAILED
 *           when SoftBusReadFullFile fails
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_004, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGenerateCeKeyByHuks(_, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusAccessFile(_, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusReadFullFile(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_FILE_ERR));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_INIT_TRUST_DEV_INFO_FAILED);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_005
 * @tc.desc: Verify LnnInitDecisionDbDelay returns SOFTBUS_NETWORK_INIT_TRUST_DEV_INFO_FAILED
 *           when LnnDecryptDataByHuks fails
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_005, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGenerateCeKeyByHuks(_, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusAccessFile(_, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusReadFullFile(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDecryptDataByHuks(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_DECRYPT_ERR));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_INIT_TRUST_DEV_INFO_FAILED);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_006
 * @tc.desc: Verify LnnInitDecisionDbDelay returns SOFTBUS_NETWORK_INIT_TRUST_DEV_INFO_FAILED
 *           when EncryptedDb fails
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_006, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGenerateCeKeyByHuks(_, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusAccessFile(_, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusReadFullFile(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDecryptDataByHuks(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, EncryptedDb(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_ENCRYPT_ERR));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_INIT_TRUST_DEV_INFO_FAILED);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_007
 * @tc.desc: Verify LnnInitDecisionDbDelay initializes decision db delay
 *           with valid mock return values
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_007, TestSize.Level1)
{
    NiceMock<DecisionDbDepsInterfaceMock> decisionDbMock;
    int64_t nowTime = 10000000;
    int64_t hukTime = nowTime - WAIT_SEVEN_DAYS_QUERY_INTERVAL + 10000;
    ON_CALL(decisionDbMock, LnnGenerateRandomByHuks(_, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnGenerateCeKeyByHuks(_, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnEncryptDataByHuks(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, SoftBusWriteFile(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, UpdateDbPassword(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, CheckTableExist(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, CreateTable(_, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, GetRecordNumByKey(_, _, _))
        .WillByDefault(Return(0));
    ON_CALL(decisionDbMock, LnnGenerateKeyByHuks(_))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, OpenDatabase(_))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, SoftBusAccessFile(_, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, SoftBusReadFullFile(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnDecryptDataByHuks(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, EncryptedDb(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnDeleteKeyByHuks(_))
        .WillByDefault(Return(SOFTBUS_HUKS_DELETE_KEY_ERR));
    ON_CALL(decisionDbMock, CloseDatabase(_))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, SoftBusGetRealTimeMs())
        .WillByDefault(Return(nowTime));
    ON_CALL(decisionDbMock, LnnGetLocalNum64Info(NUM_KEY_HUKS_TIME, _))
        .WillByDefault(DoAll(SetArgPointee<1>(hukTime), Return(SOFTBUS_OK)));
    ON_CALL(decisionDbMock, GetLooper(_)).WillByDefault(Return(nullptr));
    ON_CALL(decisionDbMock, LnnAsyncCallbackDelayHelper(_, _, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_008
 * @tc.desc: lnn init decision db delay test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_008, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGenerateCeKeyByHuks(_, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_NETWORK_GET_PATH_FAILED));
    EXPECT_CALL(decisionDbMock, SoftBusAccessFile(_, _))
        .WillRepeatedly(Return(SOFTBUS_FILE_ERR));
    EXPECT_CALL(decisionDbMock, LnnGenerateRandomByHuks(_, _))
        .WillRepeatedly(Return(SOFTBUS_HUKS_GENERATE_RANDOM_ERR));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_GET_PATH_FAILED);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_009
 * @tc.desc: lnn init decision db delay test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_009, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGenerateCeKeyByHuks(_, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGenerateRandomByHuks(_, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusAccessFile(_, _))
        .WillRepeatedly(Return(SOFTBUS_FILE_ERR));
    EXPECT_CALL(decisionDbMock, LnnEncryptDataByHuks(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_ENCRYPT_ERR));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_INIT_TRUST_DEV_INFO_FAILED);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_010
 * @tc.desc: lnn init decision db delay test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_010, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGenerateCeKeyByHuks(_, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGenerateRandomByHuks(_, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnEncryptDataByHuks(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusAccessFile(_, _))
        .WillRepeatedly(Return(SOFTBUS_FILE_ERR));
    EXPECT_CALL(decisionDbMock, SoftBusWriteFile(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_FILE_ERR));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_INIT_TRUST_DEV_INFO_FAILED);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_011
 * @tc.desc: lnn init decision db delay test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_011, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGenerateCeKeyByHuks(_, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusAccessFile(_, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusReadFullFile(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDecryptDataByHuks(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, EncryptedDb(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_ENCRYPT_ERR));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_INIT_TRUST_DEV_INFO_FAILED);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_012
 * @tc.desc: lnn init decision db delay test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_012, TestSize.Level1)
{
    NiceMock<DecisionDbDepsInterfaceMock> decisionDbMock;
    int64_t nowTime = 10000000;
    int64_t hukTime = 0;
    ON_CALL(decisionDbMock, LnnGenerateRandomByHuks(_, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnGenerateCeKeyByHuks(_, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnEncryptDataByHuks(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, SoftBusWriteFile(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, UpdateDbPassword(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, CheckTableExist(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, CreateTable(_, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, GetRecordNumByKey(_, _, _))
        .WillByDefault(Return(0));
    ON_CALL(decisionDbMock, LnnGenerateKeyByHuks(_))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, OpenDatabase(_))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, SoftBusAccessFile(_, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, SoftBusReadFullFile(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnDecryptDataByHuks(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, EncryptedDb(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnDeleteKeyByHuks(_))
        .WillByDefault(Return(SOFTBUS_HUKS_DELETE_KEY_ERR));
    ON_CALL(decisionDbMock, CloseDatabase(_)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, SoftBusGetRealTimeMs()).WillByDefault(Return(nowTime));
    ON_CALL(decisionDbMock, LnnGetLocalNum64Info(NUM_KEY_HUKS_TIME, _))
        .WillByDefault(DoAll(SetArgPointee<1>(hukTime), Return(SOFTBUS_INVALID_PARAM)));
    ON_CALL(decisionDbMock, GetLooper(_)).WillByDefault(Return(nullptr));
    ON_CALL(decisionDbMock, LnnAsyncCallbackDelayHelper(_, _, _, _)).WillByDefault(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_013
 * @tc.desc: lnn init decision db delay test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_013, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGenerateCeKeyByHuks(_, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusAccessFile(_, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusReadFullFile(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDecryptDataByHuks(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, EncryptedDb(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDeleteKeyByHuks(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGenerateRandomByHuks(_, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnEncryptDataByHuks(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusWriteFile(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, UpdateDbPassword(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_INIT_TRUST_DEV_INFO_FAILED);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_014
 * @tc.desc: lnn init decision db delay test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_014, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGenerateCeKeyByHuks(_, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusAccessFile(_, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusReadFullFile(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDecryptDataByHuks(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, EncryptedDb(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDeleteKeyByHuks(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGenerateRandomByHuks(_, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnEncryptDataByHuks(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusWriteFile(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, UpdateDbPassword(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, CheckTableExist(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_INIT_TRUST_DEV_INFO_FAILED);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_015
 * @tc.desc: lnn init decision db delay test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_015, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGenerateCeKeyByHuks(_, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusAccessFile(_, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusReadFullFile(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDecryptDataByHuks(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, EncryptedDb(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDeleteKeyByHuks(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGenerateRandomByHuks(_, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnEncryptDataByHuks(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusWriteFile(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, UpdateDbPassword(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, CheckTableExist(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, CreateTable(_, _))
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_INIT_TRUST_DEV_INFO_FAILED);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_016
 * @tc.desc: lnn init decision db delay test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_016, TestSize.Level1)
{
    NiceMock<DecisionDbDepsInterfaceMock> decisionDbMock;
    int64_t nowTime = 10000000;
    int64_t hukTime = nowTime - WAIT_SEVEN_DAYS_QUERY_INTERVAL + 10000;
    ON_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, GetRecordNumByKey(_, _, _)).WillByDefault(Return(0));
    ON_CALL(decisionDbMock, LnnGenerateKeyByHuks(_)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnGenerateCeKeyByHuks(_, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, OpenDatabase(_))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, SoftBusAccessFile(_, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, SoftBusReadFullFile(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnDecryptDataByHuks(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, EncryptedDb(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnDeleteKeyByHuks(_))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnGenerateRandomByHuks(_, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnEncryptDataByHuks(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, SoftBusWriteFile(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, UpdateDbPassword(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, CheckTableExist(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, CreateTable(_, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, CloseDatabase(_))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, SoftBusGetRealTimeMs())
        .WillByDefault(Return(nowTime));
    ON_CALL(decisionDbMock, LnnGetLocalNum64Info(NUM_KEY_HUKS_TIME, _))
        .WillByDefault(DoAll(SetArgPointee<1>(hukTime), Return(SOFTBUS_OK)));
    ON_CALL(decisionDbMock, GetLooper(_))
        .WillByDefault(Return(nullptr));
    ON_CALL(decisionDbMock, LnnAsyncCallbackDelayHelper(_, _, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_017
 * @tc.desc: lnn init update key and local info test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_017, TestSize.Level1)
{
    NiceMock<DecisionDbDepsInterfaceMock> decisionDbMock;
    ON_CALL(decisionDbMock, LnnGetLocalDevInfo(_))
        .WillByDefault(Return(SOFTBUS_NOT_IMPLEMENT));
    ON_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_REMOTE_DEVINFO, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_DEVICE_KEY, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_BLE_BROADCAST_KEY, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_PTK_KEY, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_LOCAL_BROADCAST_KEY, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, OpenDatabase(_))
        .WillByDefault(Return(SOFTBUS_INVALID_PARAM));
    int32_t result = UpdateKeyAndLocalInfo();
    EXPECT_EQ(result, SOFTBUS_NOT_IMPLEMENT);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_018
 * @tc.desc: lnn init update key and local info test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_018, TestSize.Level1)
{
    NiceMock<DecisionDbDepsInterfaceMock> decisionDbMock;
    int64_t nowTime = 10000000;
    ON_CALL(decisionDbMock, LnnGetLocalDevInfo(_))
        .WillByDefault(Return(SOFTBUS_NOT_IMPLEMENT));
    ON_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_REMOTE_DEVINFO, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_DEVICE_KEY, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_BLE_BROADCAST_KEY, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_PTK_KEY, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_LOCAL_BROADCAST_KEY, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, OpenDatabase(_))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnDeleteKeyByHuks(_))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnDeleteCeKeyByHuks(_, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnGenerateKeyByHuks(_))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnGenerateCeKeyByHuks(_, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, SoftBusAccessFile(_, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnGenerateRandomByHuks(_, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnEncryptDataByHuks(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, SoftBusWriteFile(_, _, _))
        .WillByDefault(Return(SOFTBUS_FILE_ERR));
    ON_CALL(decisionDbMock, SoftBusReadFullFile(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnDecryptDataByHuks(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, UpdateDbPassword(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, CloseDatabase(_))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, SoftBusGetRealTimeMs())
        .WillByDefault(Return(nowTime));
    ON_CALL(decisionDbMock, LnnSetLocalNum64Info(_, _))
        .WillByDefault(Return(SOFTBUS_INVALID_PARAM));
    int32_t result = UpdateKeyAndLocalInfo();
    EXPECT_EQ(result, SOFTBUS_NOT_IMPLEMENT);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_019
 * @tc.desc: lnn init update key and local info test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_019, TestSize.Level1)
{
    NiceMock<DecisionDbDepsInterfaceMock> decisionDbMock;
    int64_t nowTime = 10000000;
    ON_CALL(decisionDbMock, LnnGetLocalDevInfo(_)).WillByDefault(Return(SOFTBUS_NOT_IMPLEMENT));
    ON_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_REMOTE_DEVINFO, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_DEVICE_KEY, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_BLE_BROADCAST_KEY, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_PTK_KEY, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_LOCAL_BROADCAST_KEY, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, OpenDatabase(_)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnDeleteKeyByHuks(_)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnDeleteCeKeyByHuks(_, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnGenerateKeyByHuks(_)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnGenerateCeKeyByHuks(_, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, SoftBusAccessFile(_, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnGenerateRandomByHuks(_, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnEncryptDataByHuks(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, SoftBusWriteFile(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, SoftBusReadFullFile(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnDecryptDataByHuks(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, UpdateDbPassword(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, CloseDatabase(_))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, SoftBusGetRealTimeMs())
        .WillByDefault(Return(nowTime));
    ON_CALL(decisionDbMock, LnnSetLocalNum64Info(_, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnSaveLocalDeviceInfo(_))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnSaveDeviceData(_, LNN_DATA_TYPE_REMOTE_DEVINFO))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnSaveDeviceData(_, LNN_DATA_TYPE_DEVICE_KEY))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnSaveDeviceData(_, LNN_DATA_TYPE_BLE_BROADCAST_KEY))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnSaveDeviceData(_, LNN_DATA_TYPE_PTK_KEY))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnSaveDeviceData(_, LNN_DATA_TYPE_LOCAL_BROADCAST_KEY))
        .WillByDefault(Return(SOFTBUS_OK));
    int32_t result = UpdateKeyAndLocalInfo();
    EXPECT_EQ(result, SOFTBUS_NOT_IMPLEMENT);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_020
 * @tc.desc: lnn init update key and local info test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_020, TestSize.Level1)
{
    NiceMock<DecisionDbDepsInterfaceMock> decisionDbMock;
    int64_t nowTime = 10000000;
    int64_t hukTime = nowTime - WAIT_SEVEN_DAYS_QUERY_INTERVAL - 1;
    ON_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, GetRecordNumByKey(_, _, _)).WillByDefault(Return(0));
    ON_CALL(decisionDbMock, LnnGenerateKeyByHuks(_)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnGenerateCeKeyByHuks(_, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, OpenDatabase(_)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, SoftBusAccessFile(_, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, SoftBusReadFullFile(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnDecryptDataByHuks(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, EncryptedDb(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnDeleteKeyByHuks(_)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnGenerateRandomByHuks(_, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnEncryptDataByHuks(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, SoftBusWriteFile(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, UpdateDbPassword(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, CheckTableExist(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, CreateTable(_, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, CloseDatabase(_))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, SoftBusGetRealTimeMs())
        .WillByDefault(Return(nowTime));
    ON_CALL(decisionDbMock, LnnGetLocalNum64Info(NUM_KEY_HUKS_TIME, _))
        .WillByDefault(DoAll(SetArgPointee<1>(hukTime), Return(SOFTBUS_OK)));
    ON_CALL(decisionDbMock, LnnGetLocalDevInfo(_))
        .WillByDefault(Return(SOFTBUS_NOT_IMPLEMENT));
    ON_CALL(decisionDbMock, LnnRetrieveDeviceData(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnDeleteCeKeyByHuks(_, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnSetLocalNum64Info(_, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnSaveLocalDeviceInfo(_))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnSaveDeviceData(_, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnAsyncCallbackDelayHelper(_, _, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_021
 * @tc.desc: lnn init decision db delay test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_021, TestSize.Level1)
{
    NiceMock<DecisionDbDepsInterfaceMock> decisionDbMock;
    int64_t nowTime = 10000000;
    int64_t hukTime = 0;
    ON_CALL(decisionDbMock, LnnGenerateRandomByHuks(_, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnGenerateCeKeyByHuks(_, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnEncryptDataByHuks(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, SoftBusWriteFile(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, UpdateDbPassword(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, CheckTableExist(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, CreateTable(_, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, GetRecordNumByKey(_, _, _))
        .WillByDefault(Return(0));
    ON_CALL(decisionDbMock, LnnGenerateKeyByHuks(_))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, OpenDatabase(_))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, SoftBusAccessFile(_, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, SoftBusReadFullFile(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnDecryptDataByHuks(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, EncryptedDb(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnDeleteKeyByHuks(_))
        .WillByDefault(Return(SOFTBUS_HUKS_DELETE_KEY_ERR));
    ON_CALL(decisionDbMock, CloseDatabase(_))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, SoftBusGetRealTimeMs())
        .WillByDefault(Return(nowTime));
    ON_CALL(decisionDbMock, LnnGetLocalNum64Info(NUM_KEY_HUKS_TIME, _))
        .WillByDefault(DoAll(SetArgPointee<1>(hukTime), Return(SOFTBUS_OK)));
    ON_CALL(decisionDbMock, LnnSetLocalNum64Info(_, _))
        .WillByDefault(Return(SOFTBUS_INVALID_PARAM));
    ON_CALL(decisionDbMock, GetLooper(_)).WillByDefault(Return(nullptr));
    ON_CALL(decisionDbMock, LnnAsyncCallbackDelayHelper(_, _, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_022
 * @tc.desc: lnn init decision db delay test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_022, TestSize.Level1)
{
    NiceMock<DecisionDbDepsInterfaceMock> decisionDbMock;
    int64_t nowTime = 10000000;
    int64_t hukTime = nowTime - WAIT_SEVEN_DAYS_QUERY_INTERVAL + 10000;
    ON_CALL(decisionDbMock, LnnGenerateRandomByHuks(_, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnGenerateCeKeyByHuks(_, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnEncryptDataByHuks(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, SoftBusWriteFile(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, UpdateDbPassword(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, CheckTableExist(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, CreateTable(_, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, GetRecordNumByKey(_, _, _))
        .WillByDefault(Return(0));
    ON_CALL(decisionDbMock, LnnGenerateKeyByHuks(_))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, OpenDatabase(_))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, SoftBusAccessFile(_, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, SoftBusReadFullFile(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnDecryptDataByHuks(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, EncryptedDb(_, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnDeleteKeyByHuks(_))
        .WillByDefault(Return(SOFTBUS_HUKS_DELETE_KEY_ERR));
    ON_CALL(decisionDbMock, CloseDatabase(_))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, SoftBusGetRealTimeMs())
        .WillByDefault(Return(nowTime));
    ON_CALL(decisionDbMock, LnnGetLocalNum64Info(NUM_KEY_HUKS_TIME, _))
        .WillByDefault(DoAll(SetArgPointee<1>(hukTime), Return(SOFTBUS_OK)));
    ON_CALL(decisionDbMock, GetLooper(_)).WillByDefault(Return(nullptr));
    ON_CALL(decisionDbMock, LnnAsyncCallbackDelayHelper(_, _, _, _))
        .WillByDefault(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_INSERT_SPECIFIC_TRUSTED_DEVICEINFO_Test_001
 * @tc.desc: lnn insert specific trusted devInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INSERT_SPECIFIC_TRUSTED_DEVICEINFO_Test_001, TestSize.Level1)
{
    int32_t ret = LnnInsertSpecificTrustedDevInfo(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, GetLooper(_)).WillOnce(Return(nullptr));
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnAsyncCallbackHelper(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_NETWORK_ASYNC_CALLBACK_FAILED));
    ret = LnnInsertSpecificTrustedDevInfo(NODE_UDID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_INSERT_SPECIFIC_TRUSTED_DEVICEINFO_Test_002
 * @tc.desc: lnn insert specific trusted devInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INSERT_SPECIFIC_TRUSTED_DEVICEINFO_Test_002, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, GetLooper(_))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnAsyncCallbackHelper(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInsertSpecificTrustedDevInfo(NODE_UDID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_INSERT_SPECIFIC_TRUSTED_DEVICEINFO_Test_003
 * @tc.desc: lnn insert specific trusted devInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INSERT_SPECIFIC_TRUSTED_DEVICEINFO_Test_003, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, GetLooper(_))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(decisionDbMock, LnnAsyncCallbackHelper(_, _, _))
        .WillRepeatedly(decisionDbMock.DecisionDbAsyncCallbackHelper);
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR));
    int32_t ret = LnnInsertSpecificTrustedDevInfo(NODE_UDID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_INSERT_SPECIFIC_TRUSTED_DEVICEINFO_Test_004
 * @tc.desc: lnn insert specific trusted devInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INSERT_SPECIFIC_TRUSTED_DEVICEINFO_Test_004, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, GetLooper(_))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(decisionDbMock, LnnAsyncCallbackHelper(_, _, _))
        .WillRepeatedly(decisionDbMock.DecisionDbAsyncCallbackHelper);
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _))
        .WillRepeatedly(Return(SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR));
    int32_t ret = LnnInsertSpecificTrustedDevInfo(NODE_UDID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_INSERT_SPECIFIC_TRUSTED_DEVICEINFO_Test_005
 * @tc.desc: lnn insert specific trusted devInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INSERT_SPECIFIC_TRUSTED_DEVICEINFO_Test_005, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, GetLooper(_))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(decisionDbMock, LnnAsyncCallbackHelper(_, _, _))
        .WillRepeatedly(decisionDbMock.DecisionDbAsyncCallbackHelper);
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_NETWORK_DATABASE_FAILED));
    int32_t ret = LnnInsertSpecificTrustedDevInfo(NODE_UDID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_INSERT_SPECIFIC_TRUSTED_DEVICEINFO_Test_006
 * @tc.desc: lnn insert specific trusted devInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INSERT_SPECIFIC_TRUSTED_DEVICEINFO_Test_006, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, GetLooper(_))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(decisionDbMock, LnnAsyncCallbackHelper(_, _, _))
        .WillRepeatedly(decisionDbMock.DecisionDbAsyncCallbackHelper);
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_NETWORK_GET_PATH_FAILED));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInsertSpecificTrustedDevInfo(NODE_UDID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_INSERT_SPECIFIC_TRUSTED_DEVICEINFO_Test_007
 * @tc.desc: lnn insert specific trusted devInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INSERT_SPECIFIC_TRUSTED_DEVICEINFO_Test_007, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, GetLooper(_))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(decisionDbMock, LnnAsyncCallbackHelper(_, _, _))
        .WillRepeatedly(decisionDbMock.DecisionDbAsyncCallbackHelper);
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_NETWORK_GET_PATH_FAILED));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_NETWORK_DATABASE_FAILED));
    int32_t ret = LnnInsertSpecificTrustedDevInfo(NODE_UDID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_DELETE_SPECIFIC_TRUSTED_DEVICEINFO_Test_001
 * @tc.desc: lnn delete specific trusted devInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_DELETE_SPECIFIC_TRUSTED_DEVICEINFO_Test_001, TestSize.Level1)
{
    int32_t ret = LnnDeleteSpecificTrustedDevInfo(nullptr, DEFAULT_USERID);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, GetLooper(_))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnAsyncCallbackHelper(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_NETWORK_ASYNC_CALLBACK_FAILED));
    ret = LnnDeleteSpecificTrustedDevInfo(NODE_UDID, DEFAULT_USERID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_DELETE_SPECIFIC_TRUSTED_DEVICEINFO_Test_002
 * @tc.desc: lnn delete specific trusted devInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_DELETE_SPECIFIC_TRUSTED_DEVICEINFO_Test_002, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, GetLooper(_))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnAsyncCallbackHelper(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnDeleteSpecificTrustedDevInfo(NODE_UDID, DEFAULT_USERID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_DELETE_SPECIFIC_TRUSTED_DEVICEINFO_Test_003
 * @tc.desc: lnn delete specific trusted devInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_DELETE_SPECIFIC_TRUSTED_DEVICEINFO_Test_003, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, GetLooper(_))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(decisionDbMock, LnnAsyncCallbackHelper(_, _, _))
        .WillRepeatedly(decisionDbMock.DecisionDbAsyncCallbackHelper);
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR));
    int32_t ret = LnnDeleteSpecificTrustedDevInfo(NODE_UDID, DEFAULT_USERID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_DELETE_SPECIFIC_TRUSTED_DEVICEINFO_Test_004
 * @tc.desc: lnn delete specific trusted devInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_DELETE_SPECIFIC_TRUSTED_DEVICEINFO_Test_004, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, GetLooper(_))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(decisionDbMock, LnnAsyncCallbackHelper(_, _, _))
        .WillRepeatedly(decisionDbMock.DecisionDbAsyncCallbackHelper);
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _))
        .WillRepeatedly(Return(SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_NETWORK_DATABASE_FAILED));
    int32_t ret = LnnDeleteSpecificTrustedDevInfo(NODE_UDID, DEFAULT_USERID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_DELETE_SPECIFIC_TRUSTED_DEVICEINFO_Test_005
 * @tc.desc: lnn delete specific trusted devInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_DELETE_SPECIFIC_TRUSTED_DEVICEINFO_Test_005, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, GetLooper(_))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(decisionDbMock, LnnAsyncCallbackHelper(_, _, _))
        .WillRepeatedly(decisionDbMock.DecisionDbAsyncCallbackHelper);
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_NETWORK_DATABASE_FAILED));
    int32_t ret = LnnDeleteSpecificTrustedDevInfo(NODE_UDID, DEFAULT_USERID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_DELETE_SPECIFIC_TRUSTED_DEVICEINFO_Test_006
 * @tc.desc: lnn delete specific trusted devInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_DELETE_SPECIFIC_TRUSTED_DEVICEINFO_Test_006, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, GetLooper(_))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(decisionDbMock, LnnAsyncCallbackHelper(_, _, _))
        .WillRepeatedly(decisionDbMock.DecisionDbAsyncCallbackHelper);
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_NETWORK_GET_PATH_FAILED));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnDeleteSpecificTrustedDevInfo(NODE_UDID, DEFAULT_USERID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_DELETE_SPECIFIC_TRUSTED_DEVICEINFO_Test_007
 * @tc.desc: lnn delete specific trusted devInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_DELETE_SPECIFIC_TRUSTED_DEVICEINFO_Test_007, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, GetLooper(_))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(decisionDbMock, LnnAsyncCallbackHelper(_, _, _))
        .WillRepeatedly(decisionDbMock.DecisionDbAsyncCallbackHelper);
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_NETWORK_GET_PATH_FAILED));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_)).WillRepeatedly(Return(SOFTBUS_NETWORK_DATABASE_FAILED));
    int32_t ret = LnnDeleteSpecificTrustedDevInfo(NODE_UDID, DEFAULT_USERID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_TRUSTED_DEVICEINFO_Test_001
 * @tc.desc: lnn get trusted devInfo from db test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_GET_TRUSTED_DEVICEINFO_Test_001, TestSize.Level1)
{
    char *udid = nullptr;
    uint32_t num = 0;
    int32_t ret = LnnGetTrustedDevInfoFromDb(nullptr, &num);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnGetTrustedDevInfoFromDb(&udid, &num);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_TRUSTED_DEVICEINFO_Test_002
 * @tc.desc: lnn get trusted devInfo from db test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_GET_TRUSTED_DEVICEINFO_Test_002, TestSize.Level1)
{
    char *udid = nullptr;
    uint32_t num = 0;
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _))
        .WillRepeatedly(Return(SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR));
    int32_t ret = LnnGetTrustedDevInfoFromDb(&udid, &num);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_TRUSTED_DEVICEINFO_Test_003
 * @tc.desc: lnn get trusted devInfo from db test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_GET_TRUSTED_DEVICEINFO_Test_003, TestSize.Level1)
{
    char *udid = nullptr;
    uint32_t num = 0;
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = LnnGetTrustedDevInfoFromDb(&udid, &num);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_TRUSTED_DEVICEINFO_Test_004
 * @tc.desc: lnn get trusted devInfo from db test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_GET_TRUSTED_DEVICEINFO_Test_004, TestSize.Level1)
{
    char *udid = nullptr;
    uint32_t num = 0;
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnGetTrustedDevInfoFromDb(&udid, &num);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_TRUSTED_DEVICEINFO_Test_005
 * @tc.desc: lnn get trusted devInfo from db test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_GET_TRUSTED_DEVICEINFO_Test_005, TestSize.Level1)
{
    char *udid = nullptr;
    uint32_t num = 0;
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusAccessFile(_, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusReadFullFile(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDecryptDataByHuks(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, EncryptedDb(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, GetRecordNumByKey(_, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnGetTrustedDevInfoFromDb(&udid, &num);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_TRUSTED_DEVICEINFO_Test_006
 * @tc.desc: lnn get trusted devInfo from db test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_GET_TRUSTED_DEVICEINFO_Test_006, TestSize.Level1)
{
    char *udid = nullptr;
    uint32_t num = 0;
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusAccessFile(_, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusReadFullFile(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDecryptDataByHuks(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, EncryptedDb(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, GetRecordNumByKey(_, _, _))
        .WillRepeatedly(Return(2));
    EXPECT_CALL(decisionDbMock, QueryRecordByKey(_, _, _, _, _))
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnGetTrustedDevInfoFromDb(&udid, &num);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_TRUSTED_DEVICEINFO_Test_007
 * @tc.desc: lnn get trusted devInfo from db test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_GET_TRUSTED_DEVICEINFO_Test_007, TestSize.Level1)
{
    char *udid = nullptr;
    uint32_t num = 0;
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusAccessFile(_, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusReadFullFile(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDecryptDataByHuks(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, EncryptedDb(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, GetRecordNumByKey(_, _, _))
        .WillRepeatedly(Return(2));
    EXPECT_CALL(decisionDbMock, QueryRecordByKey(_, _, _, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = LnnGetTrustedDevInfoFromDb(&udid, &num);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: DB_LOCK_AND_DB_UNLOCK_Test_001
 * @tc.desc: DbLock and DbUnlock test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, DB_LOCK_AND_DB_UNLOCK_Test_001, TestSize.Level1)
{
    int32_t ret = DbLock();
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(DbUnlock());
}

/*
 * @tc.name: RECOVERY_TRUSTED_DEVINFO_PROCESS_Test_001
 * @tc.desc: RecoveryTrustedDevInfoProcess test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, RECOVERY_TRUSTED_DEVINFO_PROCESS_Test_001, TestSize.Level1)
{
    NiceMock<DecisionDbDepsInterfaceMock> decisionDbMock;
    EXPECT_CALL(decisionDbMock, SelectAllAcl(_, _))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = RecoveryTrustedDevInfoProcess();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR);

    EXPECT_CALL(decisionDbMock, SelectAllAcl(_, _))
        .WillRepeatedly(decisionDbMock.ActionOfSelectAllAcl);
    ret = RecoveryTrustedDevInfoProcess();
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(ClearRecoveryDeviceList());
}

/*
 * @tc.name: LNN_UPDATE_DECISION_DB_KEY_Test_001
 * @tc.desc: LnnUpdateDecisionDbKey test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_UPDATE_DECISION_DB_KEY_Test_001, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, OpenDatabase(_))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = LnnUpdateDecisionDbKey();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_DATABASE_FAILED);

    EXPECT_CALL(decisionDbMock, OpenDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDeleteKeyByHuks(_))
        .WillOnce(Return(SOFTBUS_HUKS_DELETE_KEY_ERR));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnUpdateDecisionDbKey();
    EXPECT_EQ(ret, SOFTBUS_HUKS_UPDATE_ERR);

    EXPECT_CALL(decisionDbMock, LnnDeleteKeyByHuks(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDeleteCeKeyByHuks(_, _))
        .WillOnce(Return(SOFTBUS_HUKS_DELETE_KEY_ERR));
    ret = LnnUpdateDecisionDbKey();
    EXPECT_EQ(ret, SOFTBUS_HUKS_UPDATE_ERR);

    EXPECT_CALL(decisionDbMock, LnnDeleteCeKeyByHuks(_, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_))
        .WillOnce(Return(SOFTBUS_HUKS_GENERATE_KEY_ERR));
    ret = LnnUpdateDecisionDbKey();
    EXPECT_EQ(ret, SOFTBUS_HUKS_UPDATE_ERR);

    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGenerateCeKeyByHuks(_, _))
        .WillOnce(Return(SOFTBUS_HUKS_GENERATE_KEY_ERR));
    ret = LnnUpdateDecisionDbKey();
    EXPECT_EQ(ret, SOFTBUS_HUKS_UPDATE_ERR);
}

/*
 * @tc.name: LNN_UPDATE_DECISION_DB_KEY_Test_002
 * @tc.desc: LnnUpdateDecisionDbKey test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_UPDATE_DECISION_DB_KEY_Test_002, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, OpenDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDeleteKeyByHuks(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDeleteCeKeyByHuks(_, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGenerateCeKeyByHuks(_, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_NETWORK_GET_PATH_FAILED));
    int32_t ret = LnnUpdateDecisionDbKey();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_PATH_FAILED);
}

/*
 * @tc.name: RETRIEVE_DEVICE_INFO_AND_KEYS_Test_001
 * @tc.desc: RetrieveDeviceInfoAndKeys test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, RETRIEVE_DEVICE_INFO_AND_KEYS_Test_001, TestSize.Level1)
{
    int32_t ret = RetrieveDeviceInfoAndKeys(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    UpdateKeyRes res = { 0 };
    ret = RetrieveDeviceInfoAndKeys(&res);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/*
 * @tc.name: RETRIEVE_DEVICE_INFO_AND_KEYS_Test_002
 * @tc.desc: RetrieveDeviceInfoAndKeys test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, RETRIEVE_DEVICE_INFO_AND_KEYS_Test_002, TestSize.Level1)
{
    NiceMock<DecisionDbDepsInterfaceMock> decisionDbMock;
    ON_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_REMOTE_DEVINFO, _, _))
        .WillByDefault(Return(SOFTBUS_INVALID_PARAM));
    UpdateKeyRes res = { 0 };
    int32_t ret = RetrieveDeviceInfoAndKeys(&res);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/*
 * @tc.name: RETRIEVE_DEVICE_INFO_AND_KEYS_Test_003
 * @tc.desc: RetrieveDeviceInfoAndKeys test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, RETRIEVE_DEVICE_INFO_AND_KEYS_Test_003, TestSize.Level1)
{
    NiceMock<DecisionDbDepsInterfaceMock> decisionDbMock;
    ON_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_REMOTE_DEVINFO, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_DEVICE_KEY, _, _))
        .WillByDefault(Return(SOFTBUS_INVALID_PARAM));
    UpdateKeyRes res = { 0 };
    int32_t ret = RetrieveDeviceInfoAndKeys(&res);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/*
 * @tc.name: RETRIEVE_DEVICE_INFO_AND_KEYS_Test_004
 * @tc.desc: RetrieveDeviceInfoAndKeys test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, RETRIEVE_DEVICE_INFO_AND_KEYS_Test_004, TestSize.Level1)
{
    NiceMock<DecisionDbDepsInterfaceMock> decisionDbMock;
    ON_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_REMOTE_DEVINFO, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_DEVICE_KEY, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_BLE_BROADCAST_KEY, _, _))
        .WillByDefault(Return(SOFTBUS_INVALID_PARAM));
    UpdateKeyRes res = { 0 };
    int32_t ret = RetrieveDeviceInfoAndKeys(&res);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/*
 * @tc.name: RETRIEVE_DEVICE_INFO_AND_KEYS_Test_005
 * @tc.desc: retrieve device info but retrieve device data once err
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, RETRIEVE_DEVICE_INFO_AND_KEYS_Test_005, TestSize.Level1)
{
    NiceMock<DecisionDbDepsInterfaceMock> decisionDbMock;
    ON_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_REMOTE_DEVINFO, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_DEVICE_KEY, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_BLE_BROADCAST_KEY, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_PTK_KEY, _, _))
        .WillByDefault(Return(SOFTBUS_INVALID_PARAM));
    UpdateKeyRes res = { 0 };
    int32_t ret = RetrieveDeviceInfoAndKeys(&res);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/*
 * @tc.name: RETRIEVE_DEVICE_INFO_AND_KEYS_Test_006
 * @tc.desc: retrieve device info and keys test return not ok
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, RETRIEVE_DEVICE_INFO_AND_KEYS_Test_006, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_REMOTE_DEVINFO, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_DEVICE_KEY, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_BLE_BROADCAST_KEY, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_PTK_KEY, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_LOCAL_BROADCAST_KEY, _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    UpdateKeyRes res = { 0 };
    int32_t ret = RetrieveDeviceInfoAndKeys(&res);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/*
 * @tc.name: SAVE_DEVICE_INFO_AND_KEYS_Test_001
 * @tc.desc: SaveDeviceInfoAndKeys test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, SAVE_DEVICE_INFO_AND_KEYS_Test_001, TestSize.Level1)
{
    int32_t ret = SaveDeviceInfoAndKeys(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    UpdateKeyRes res;
    (void)memset_s(&res, sizeof(UpdateKeyRes), 0, sizeof(UpdateKeyRes));
    ret = SaveDeviceInfoAndKeys(&res);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/*
 * @tc.name: SAVE_DEVICE_INFO_AND_KEYS_Test_002
 * @tc.desc: save device info and keys test but save remote device key info failed
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, SAVE_DEVICE_INFO_AND_KEYS_Test_002, TestSize.Level1)
{
    NiceMock<DecisionDbDepsInterfaceMock> decisionDbMock;
    ON_CALL(decisionDbMock, LnnSaveDeviceData(_, LNN_DATA_TYPE_REMOTE_DEVINFO))
        .WillByDefault(Return(SOFTBUS_INVALID_PARAM));
    UpdateKeyRes res = { 0 };
    int32_t ret = SaveDeviceInfoAndKeys(&res);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/*
 * @tc.name: SAVE_DEVICE_INFO_AND_KEYS_Test_003
 * @tc.desc: save device info and keys test but save device key info failed
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, SAVE_DEVICE_INFO_AND_KEYS_Test_003, TestSize.Level1)
{
    NiceMock<DecisionDbDepsInterfaceMock> decisionDbMock;
    ON_CALL(decisionDbMock, LnnSaveDeviceData(_, LNN_DATA_TYPE_REMOTE_DEVINFO))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnSaveDeviceData(_, LNN_DATA_TYPE_DEVICE_KEY))
        .WillByDefault(Return(SOFTBUS_INVALID_PARAM));
    UpdateKeyRes res = { 0 };
    int32_t ret = SaveDeviceInfoAndKeys(&res);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/*
 * @tc.name: SAVE_DEVICE_INFO_AND_KEYS_Test_004
 * @tc.desc: SaveDeviceInfoAndKeys test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, SAVE_DEVICE_INFO_AND_KEYS_Test_004, TestSize.Level1)
{
    NiceMock<DecisionDbDepsInterfaceMock> decisionDbMock;
    ON_CALL(decisionDbMock, LnnSaveDeviceData(_, LNN_DATA_TYPE_REMOTE_DEVINFO))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnSaveDeviceData(_, LNN_DATA_TYPE_DEVICE_KEY))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnSaveDeviceData(_, LNN_DATA_TYPE_BLE_BROADCAST_KEY))
        .WillByDefault(Return(SOFTBUS_INVALID_PARAM));
    UpdateKeyRes res = { 0 };
    int32_t ret = SaveDeviceInfoAndKeys(&res);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/*
 * @tc.name: SAVE_DEVICE_INFO_AND_KEYS_Test_005
 * @tc.desc: SaveDeviceInfoAndKeys test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, SAVE_DEVICE_INFO_AND_KEYS_Test_005, TestSize.Level1)
{
    NiceMock<DecisionDbDepsInterfaceMock> decisionDbMock;
    ON_CALL(decisionDbMock, LnnSaveDeviceData(_, LNN_DATA_TYPE_REMOTE_DEVINFO))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnSaveDeviceData(_, LNN_DATA_TYPE_DEVICE_KEY))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnSaveDeviceData(_, LNN_DATA_TYPE_BLE_BROADCAST_KEY))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnSaveDeviceData(_, LNN_DATA_TYPE_PTK_KEY))
        .WillByDefault(Return(SOFTBUS_INVALID_PARAM));
    UpdateKeyRes res = { 0 };
    int32_t ret = SaveDeviceInfoAndKeys(&res);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/*
 * @tc.name: SAVE_DEVICE_INFO_AND_KEYS_Test_006
 * @tc.desc: save device info and keys test but save local broadcast key info failed
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, SAVE_DEVICE_INFO_AND_KEYS_Test_006, TestSize.Level1)
{
    NiceMock<DecisionDbDepsInterfaceMock> decisionDbMock;
    ON_CALL(decisionDbMock, LnnSaveDeviceData(_, LNN_DATA_TYPE_REMOTE_DEVINFO))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnSaveDeviceData(_, LNN_DATA_TYPE_DEVICE_KEY))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnSaveDeviceData(_, LNN_DATA_TYPE_BLE_BROADCAST_KEY))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnSaveDeviceData(_, LNN_DATA_TYPE_PTK_KEY))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnSaveDeviceData(_, LNN_DATA_TYPE_LOCAL_BROADCAST_KEY))
        .WillByDefault(Return(SOFTBUS_INVALID_PARAM));
    UpdateKeyRes res = { 0 };
    int32_t ret = SaveDeviceInfoAndKeys(&res);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/*
 * @tc.name: SAVE_DEVICE_INFO_AND_KEYS_Test_007
 * @tc.desc: save device info and keys test return not ok
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, SAVE_DEVICE_INFO_AND_KEYS_Test_007, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnSaveDeviceData(_, LNN_DATA_TYPE_REMOTE_DEVINFO))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnSaveDeviceData(_, LNN_DATA_TYPE_DEVICE_KEY))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnSaveDeviceData(_, LNN_DATA_TYPE_BLE_BROADCAST_KEY))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnSaveDeviceData(_, LNN_DATA_TYPE_PTK_KEY))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnSaveDeviceData(_, LNN_DATA_TYPE_LOCAL_BROADCAST_KEY))
        .WillRepeatedly(Return(SOFTBUS_OK));
    UpdateKeyRes res = { 0 };
    int32_t ret = SaveDeviceInfoAndKeys(&res);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/*
 * @tc.name: FREE_UPDATE_KEY_RESOURCES_Test_001
 * @tc.desc: FreeUpdateKeyResources test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, FREE_UPDATE_KEY_RESOURCES_Test_001, TestSize.Level1)
{
    UpdateKeyRes res = {
        .remoteDevinfoData = nullptr,
        .remoteDevinfoLen = 0,
        .deviceKey = nullptr,
        .deviceKeyLen = 0,
        .broadcastKey = nullptr,
        .broadcastKeyLen = 0,
        .ptkKey = nullptr,
        .ptkKeyLen = 0,
        .localBroadcastKey = nullptr,
        .localBroadcastKeyLen = 0,
    };
    EXPECT_NO_FATAL_FAILURE(FreeUpdateKeyResources(&res));
    res.remoteDevinfoData = reinterpret_cast<char *>(SoftBusCalloc(TEST_LEN));
    ASSERT_TRUE(res.remoteDevinfoData != nullptr);
    res.remoteDevinfoLen = TEST_LEN;
    res.deviceKey = reinterpret_cast<char *>(SoftBusCalloc(TEST_LEN));
    ASSERT_TRUE(res.deviceKey != nullptr);
    res.deviceKeyLen = TEST_LEN;
    res.broadcastKey = reinterpret_cast<char *>(SoftBusCalloc(TEST_LEN));
    ASSERT_TRUE(res.broadcastKey != nullptr);
    res.broadcastKeyLen = TEST_LEN;
    res.ptkKey = reinterpret_cast<char *>(SoftBusCalloc(TEST_LEN));
    ASSERT_TRUE(res.ptkKey != nullptr);
    res.ptkKeyLen = TEST_LEN;
    res.localBroadcastKey = reinterpret_cast<char *>(SoftBusCalloc(TEST_LEN));
    ASSERT_TRUE(res.localBroadcastKey != nullptr);
    res.localBroadcastKeyLen = TEST_LEN;
    EXPECT_NO_FATAL_FAILURE(FreeUpdateKeyResources(&res));
}

/*
 * @tc.name: UPDATE_KEY_AND_LOCAL_INFO_Test_001
 * @tc.desc: UpdateKeyAndLocalInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, UPDATE_KEY_AND_LOCAL_INFO_Test_001, TestSize.Level1)
{
    NiceMock<DecisionDbDepsInterfaceMock> decisionDbMock;
    ON_CALL(decisionDbMock, LnnGetLocalDevInfo(_))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_REMOTE_DEVINFO, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_DEVICE_KEY, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_BLE_BROADCAST_KEY, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_PTK_KEY, _, _))
        .WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(decisionDbMock, LnnRetrieveDeviceData(LNN_DATA_TYPE_LOCAL_BROADCAST_KEY, _, _))
        .WillByDefault(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = UpdateKeyAndLocalInfo();
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}
} // namespace OHOS
