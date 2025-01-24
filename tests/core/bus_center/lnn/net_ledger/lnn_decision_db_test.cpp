/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
 * @tc.desc: lnn init decision db delay test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_001, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_)).WillRepeatedly(Return(SOFTBUS_HUKS_GENERATE_KEY_ERR));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_TRUE(ret == SOFTBUS_GENERATE_KEY_FAIL);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_002
 * @tc.desc: lnn init decision db delay test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_002, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_)).WillRepeatedly(Return(SOFTBUS_NETWORK_DATABASE_FAILED));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _)).WillRepeatedly(Return(SOFTBUS_NETWORK_GET_PATH_FAILED));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_GET_PATH_FAILED);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_003
 * @tc.desc: lnn init decision db delay test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_003, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _)).WillRepeatedly(Return(SOFTBUS_NETWORK_GET_PATH_FAILED));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_GET_PATH_FAILED);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_004
 * @tc.desc: lnn init decision db delay test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_004, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusAccessFile(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusReadFullFile(_, _, _)).WillRepeatedly(Return(SOFTBUS_FILE_ERR));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_INIT_TRUST_DEV_INFO_FAILED);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_005
 * @tc.desc: lnn init decision db delay test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_005, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusAccessFile(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusReadFullFile(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDecryptDataByHuks(_, _, _)).WillRepeatedly(Return(SOFTBUS_DECRYPT_ERR));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_INIT_TRUST_DEV_INFO_FAILED);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_006
 * @tc.desc: lnn init decision db delay test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_006, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusAccessFile(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusReadFullFile(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDecryptDataByHuks(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, EncryptedDb(_, _, _)).WillRepeatedly(Return(SOFTBUS_ENCRYPT_ERR));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_INIT_TRUST_DEV_INFO_FAILED);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_007
 * @tc.desc: lnn init decision db delay test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_007, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGenerateRandomByHuks(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnEncryptDataByHuks(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusWriteFile(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, UpdateDbPassword(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, CheckTableExist(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, CreateTable(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, GetRecordNumByKey(_, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusAccessFile(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusReadFullFile(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDecryptDataByHuks(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, EncryptedDb(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDeleteKeyByHuks(_)).WillRepeatedly(Return(SOFTBUS_HUKS_DELETE_KEY_ERR));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_008
 * @tc.desc: lnn init decision db delay test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_008, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _)).WillRepeatedly(Return(SOFTBUS_NETWORK_GET_PATH_FAILED));
    EXPECT_CALL(decisionDbMock, SoftBusAccessFile(_, _)).WillRepeatedly(Return(SOFTBUS_FILE_ERR));
    EXPECT_CALL(decisionDbMock, LnnGenerateRandomByHuks(_, _)).WillRepeatedly(Return(SOFTBUS_HUKS_GENERATE_RANDOM_ERR));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_GET_PATH_FAILED);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_009
 * @tc.desc: lnn init decision db delay test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_009, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGenerateRandomByHuks(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusAccessFile(_, _)).WillRepeatedly(Return(SOFTBUS_FILE_ERR));
    EXPECT_CALL(decisionDbMock, LnnEncryptDataByHuks(_, _, _)).WillRepeatedly(Return(SOFTBUS_ENCRYPT_ERR));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_INIT_TRUST_DEV_INFO_FAILED);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_010
 * @tc.desc: lnn init decision db delay test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_010, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGenerateRandomByHuks(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnEncryptDataByHuks(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusAccessFile(_, _)).WillRepeatedly(Return(SOFTBUS_FILE_ERR));
    EXPECT_CALL(decisionDbMock, SoftBusWriteFile(_, _, _)).WillRepeatedly(Return(SOFTBUS_FILE_ERR));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_INIT_TRUST_DEV_INFO_FAILED);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_011
 * @tc.desc: lnn init decision db delay test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_011, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusAccessFile(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusReadFullFile(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDecryptDataByHuks(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, EncryptedDb(_, _, _)).WillRepeatedly(Return(SOFTBUS_ENCRYPT_ERR));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_INIT_TRUST_DEV_INFO_FAILED);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_012
 * @tc.desc: lnn init decision db delay test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_012, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGenerateRandomByHuks(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnEncryptDataByHuks(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusWriteFile(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, UpdateDbPassword(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, CheckTableExist(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, CreateTable(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, GetRecordNumByKey(_, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusAccessFile(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusReadFullFile(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDecryptDataByHuks(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, EncryptedDb(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDeleteKeyByHuks(_)).WillRepeatedly(Return(SOFTBUS_HUKS_DELETE_KEY_ERR));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_013
 * @tc.desc: lnn init decision db delay test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_013, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusAccessFile(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusReadFullFile(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDecryptDataByHuks(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, EncryptedDb(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDeleteKeyByHuks(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGenerateRandomByHuks(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnEncryptDataByHuks(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusWriteFile(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, UpdateDbPassword(_, _, _)).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_INIT_TRUST_DEV_INFO_FAILED);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_014
 * @tc.desc: lnn init decision db delay test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_014, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusAccessFile(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusReadFullFile(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDecryptDataByHuks(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, EncryptedDb(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDeleteKeyByHuks(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGenerateRandomByHuks(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnEncryptDataByHuks(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusWriteFile(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, UpdateDbPassword(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, CheckTableExist(_, _, _)).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_INIT_TRUST_DEV_INFO_FAILED);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_015
 * @tc.desc: lnn init decision db delay test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_015, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusAccessFile(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusReadFullFile(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDecryptDataByHuks(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, EncryptedDb(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDeleteKeyByHuks(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGenerateRandomByHuks(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnEncryptDataByHuks(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusWriteFile(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, UpdateDbPassword(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, CheckTableExist(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, CreateTable(_, _)).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_INIT_TRUST_DEV_INFO_FAILED);
}

/*
 * @tc.name: LNN_INIT_DECISION_DB_DELAY_Test_016
 * @tc.desc: lnn init decision db delay test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INIT_DECISION_DB_DELAY_Test_016, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, GetRecordNumByKey(_, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(decisionDbMock, LnnGenerateKeyByHuks(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusAccessFile(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusReadFullFile(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDecryptDataByHuks(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, EncryptedDb(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDeleteKeyByHuks(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGenerateRandomByHuks(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnEncryptDataByHuks(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusWriteFile(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, UpdateDbPassword(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, CheckTableExist(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, CreateTable(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDecisionDbDelay();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_INSERT_SPECIFIC_TRUSTED_DEVICEINFO_Test_001
 * @tc.desc: lnn insert specific trusted devInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INSERT_SPECIFIC_TRUSTED_DEVICEINFO_Test_001, TestSize.Level1)
{
    int32_t ret = LnnInsertSpecificTrustedDevInfo(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnAsyncCallbackHelper(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_NETWORK_ASYNC_CALLBACK_FAILED));
    ret = LnnInsertSpecificTrustedDevInfo(NODE_UDID);
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_ASYNC_CALLBACK_FAILED);
}

/*
 * @tc.name: LNN_INSERT_SPECIFIC_TRUSTED_DEVICEINFO_Test_002
 * @tc.desc: lnn insert specific trusted devInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INSERT_SPECIFIC_TRUSTED_DEVICEINFO_Test_002, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnAsyncCallbackHelper(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInsertSpecificTrustedDevInfo(NODE_UDID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_INSERT_SPECIFIC_TRUSTED_DEVICEINFO_Test_003
 * @tc.desc: lnn insert specific trusted devInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INSERT_SPECIFIC_TRUSTED_DEVICEINFO_Test_003, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnAsyncCallbackHelper(_, _, _))
        .WillRepeatedly(decisionDbMock.DecisionDbAsyncCallbackHelper);
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR));
    int32_t ret = LnnInsertSpecificTrustedDevInfo(NODE_UDID);
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR);
}

/*
 * @tc.name: LNN_INSERT_SPECIFIC_TRUSTED_DEVICEINFO_Test_004
 * @tc.desc: lnn insert specific trusted devInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INSERT_SPECIFIC_TRUSTED_DEVICEINFO_Test_004, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnAsyncCallbackHelper(_, _, _))
        .WillRepeatedly(decisionDbMock.DecisionDbAsyncCallbackHelper);
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _))
        .WillRepeatedly(Return(SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR));
    int32_t ret = LnnInsertSpecificTrustedDevInfo(NODE_UDID);
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR);
}

/*
 * @tc.name: LNN_INSERT_SPECIFIC_TRUSTED_DEVICEINFO_Test_005
 * @tc.desc: lnn insert specific trusted devInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INSERT_SPECIFIC_TRUSTED_DEVICEINFO_Test_005, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnAsyncCallbackHelper(_, _, _))
        .WillRepeatedly(decisionDbMock.DecisionDbAsyncCallbackHelper);
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_)).WillRepeatedly(Return(SOFTBUS_NETWORK_DATABASE_FAILED));
    int32_t ret = LnnInsertSpecificTrustedDevInfo(NODE_UDID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_INSERT_SPECIFIC_TRUSTED_DEVICEINFO_Test_006
 * @tc.desc: lnn insert specific trusted devInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INSERT_SPECIFIC_TRUSTED_DEVICEINFO_Test_006, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnAsyncCallbackHelper(_, _, _))
        .WillRepeatedly(decisionDbMock.DecisionDbAsyncCallbackHelper);
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _)).WillRepeatedly(Return(SOFTBUS_NETWORK_GET_PATH_FAILED));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInsertSpecificTrustedDevInfo(NODE_UDID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_INSERT_SPECIFIC_TRUSTED_DEVICEINFO_Test_007
 * @tc.desc: lnn insert specific trusted devInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_INSERT_SPECIFIC_TRUSTED_DEVICEINFO_Test_007, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnAsyncCallbackHelper(_, _, _))
        .WillRepeatedly(decisionDbMock.DecisionDbAsyncCallbackHelper);
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _)).WillRepeatedly(Return(SOFTBUS_NETWORK_GET_PATH_FAILED));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_)).WillRepeatedly(Return(SOFTBUS_NETWORK_DATABASE_FAILED));
    int32_t ret = LnnInsertSpecificTrustedDevInfo(NODE_UDID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_DELETE_SPECIFIC_TRUSTED_DEVICEINFO_Test_001
 * @tc.desc: lnn delete specific trusted devInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_DELETE_SPECIFIC_TRUSTED_DEVICEINFO_Test_001, TestSize.Level1)
{
    int32_t ret = LnnDeleteSpecificTrustedDevInfo(nullptr, DEFAULT_USERID);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnAsyncCallbackHelper(_, _, _))
        .WillRepeatedly(Return(SOFTBUS_NETWORK_ASYNC_CALLBACK_FAILED));
    ret = LnnDeleteSpecificTrustedDevInfo(NODE_UDID, DEFAULT_USERID);
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_ASYNC_CALLBACK_FAILED);
}

/*
 * @tc.name: LNN_DELETE_SPECIFIC_TRUSTED_DEVICEINFO_Test_002
 * @tc.desc: lnn delete specific trusted devInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_DELETE_SPECIFIC_TRUSTED_DEVICEINFO_Test_002, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnAsyncCallbackHelper(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnDeleteSpecificTrustedDevInfo(NODE_UDID, DEFAULT_USERID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_DELETE_SPECIFIC_TRUSTED_DEVICEINFO_Test_003
 * @tc.desc: lnn delete specific trusted devInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_DELETE_SPECIFIC_TRUSTED_DEVICEINFO_Test_003, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
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
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_DELETE_SPECIFIC_TRUSTED_DEVICEINFO_Test_004, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnAsyncCallbackHelper(_, _, _))
        .WillRepeatedly(decisionDbMock.DecisionDbAsyncCallbackHelper);
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _))
        .WillRepeatedly(Return(SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_)).WillRepeatedly(Return(SOFTBUS_NETWORK_DATABASE_FAILED));
    int32_t ret = LnnDeleteSpecificTrustedDevInfo(NODE_UDID, DEFAULT_USERID);
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR);
}

/*
 * @tc.name: LNN_DELETE_SPECIFIC_TRUSTED_DEVICEINFO_Test_005
 * @tc.desc: lnn delete specific trusted devInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_DELETE_SPECIFIC_TRUSTED_DEVICEINFO_Test_005, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnAsyncCallbackHelper(_, _, _))
        .WillRepeatedly(decisionDbMock.DecisionDbAsyncCallbackHelper);
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_)).WillRepeatedly(Return(SOFTBUS_NETWORK_DATABASE_FAILED));
    int32_t ret = LnnDeleteSpecificTrustedDevInfo(NODE_UDID, DEFAULT_USERID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_DELETE_SPECIFIC_TRUSTED_DEVICEINFO_Test_006
 * @tc.desc: lnn delete specific trusted devInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_DELETE_SPECIFIC_TRUSTED_DEVICEINFO_Test_006, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnAsyncCallbackHelper(_, _, _))
        .WillRepeatedly(decisionDbMock.DecisionDbAsyncCallbackHelper);
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _)).WillRepeatedly(Return(SOFTBUS_NETWORK_GET_PATH_FAILED));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnDeleteSpecificTrustedDevInfo(NODE_UDID, DEFAULT_USERID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_DELETE_SPECIFIC_TRUSTED_DEVICEINFO_Test_007
 * @tc.desc: lnn delete specific trusted devInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_DELETE_SPECIFIC_TRUSTED_DEVICEINFO_Test_007, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnAsyncCallbackHelper(_, _, _))
        .WillRepeatedly(decisionDbMock.DecisionDbAsyncCallbackHelper);
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _)).WillRepeatedly(Return(SOFTBUS_NETWORK_GET_PATH_FAILED));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_)).WillRepeatedly(Return(SOFTBUS_NETWORK_DATABASE_FAILED));
    int32_t ret = LnnDeleteSpecificTrustedDevInfo(NODE_UDID, DEFAULT_USERID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_TRUSTED_DEVICEINFO_Test_001
 * @tc.desc: lnn get trusted devInfo from db test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_GET_TRUSTED_DEVICEINFO_Test_001, TestSize.Level1)
{
    char *udid = nullptr;
    uint32_t num = 0;
    int32_t ret = LnnGetTrustedDevInfoFromDb(nullptr, &num);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnGetTrustedDevInfoFromDb(&udid, &num);
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
}

/*
 * @tc.name: LNN_GET_TRUSTED_DEVICEINFO_Test_002
 * @tc.desc: lnn get trusted devInfo from db test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_GET_TRUSTED_DEVICEINFO_Test_002, TestSize.Level1)
{
    char *udid = nullptr;
    uint32_t num = 0;
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _))
        .WillRepeatedly(Return(SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR));
    int32_t ret = LnnGetTrustedDevInfoFromDb(&udid, &num);
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
}

/*
 * @tc.name: LNN_GET_TRUSTED_DEVICEINFO_Test_003
 * @tc.desc: lnn get trusted devInfo from db test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_GET_TRUSTED_DEVICEINFO_Test_003, TestSize.Level1)
{
    char *udid = nullptr;
    uint32_t num = 0;
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_)).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = LnnGetTrustedDevInfoFromDb(&udid, &num);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_TRUSTED_DEVICEINFO_Test_004
 * @tc.desc: lnn get trusted devInfo from db test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_GET_TRUSTED_DEVICEINFO_Test_004, TestSize.Level1)
{
    char *udid = nullptr;
    uint32_t num = 0;
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _)).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnGetTrustedDevInfoFromDb(&udid, &num);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_TRUSTED_DEVICEINFO_Test_005
 * @tc.desc: lnn get trusted devInfo from db test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_GET_TRUSTED_DEVICEINFO_Test_005, TestSize.Level1)
{
    char *udid = nullptr;
    uint32_t num = 0;
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusAccessFile(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusReadFullFile(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDecryptDataByHuks(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, EncryptedDb(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, GetRecordNumByKey(_, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnGetTrustedDevInfoFromDb(&udid, &num);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_TRUSTED_DEVICEINFO_Test_006
 * @tc.desc: lnn get trusted devInfo from db test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_GET_TRUSTED_DEVICEINFO_Test_006, TestSize.Level1)
{
    char *udid = nullptr;
    uint32_t num = 0;
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusAccessFile(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusReadFullFile(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDecryptDataByHuks(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, EncryptedDb(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, GetRecordNumByKey(_, _, _)).WillRepeatedly(Return(2));
    EXPECT_CALL(decisionDbMock, QueryRecordByKey(_, _, _, _, _)).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnGetTrustedDevInfoFromDb(&udid, &num);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_TRUSTED_DEVICEINFO_Test_007
 * @tc.desc: lnn get trusted devInfo from db test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDbMockTest, LNN_GET_TRUSTED_DEVICEINFO_Test_007, TestSize.Level1)
{
    char *udid = nullptr;
    uint32_t num = 0;
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGetLocalByteInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, ConvertBytesToHexString(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, OpenDatabase(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusAccessFile(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, SoftBusReadFullFile(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, LnnDecryptDataByHuks(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, EncryptedDb(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, GetRecordNumByKey(_, _, _)).WillRepeatedly(Return(2));
    EXPECT_CALL(decisionDbMock, QueryRecordByKey(_, _, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(decisionDbMock, CloseDatabase(_)).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = LnnGetTrustedDevInfoFromDb(&udid, &num);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}
} // namespace OHOS
