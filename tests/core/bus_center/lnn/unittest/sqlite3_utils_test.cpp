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

#include <gtest/gtest.h>
#include <securec.h>

#include "lnn_sqlite3_utils.h"
#include "softbus_adapter_mem.h"
#include "softbus_bus_center.h"
#include "softbus_errcode.h"

namespace OHOS {
using namespace testing::ext;

constexpr char DEVICE1_HASH[] = "123456ABCDEF";
constexpr char DEVICE2_HASH[] = "235689BNHFCF";
constexpr char USER1_ID[] = "haha";
constexpr char USER2_ID[] = "hehe";
constexpr char password[] = "123456789";

LnnTrustDeviceInfoRecord g_user1, g_user2, g_user3;

class Sqlite3UtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void Sqlite3UtilsTest::SetUpTestCase()
{
    (void)strcpy_s(g_user1.userID, USER_ID_MAX_LEN, USER1_ID);
    (void)strcpy_s(g_user1.deviceHash, UDID_BUF_LEN, DEVICE1_HASH);
    (void)strcpy_s(g_user2.userID, USER_ID_MAX_LEN, USER1_ID);
    (void)strcpy_s(g_user2.deviceHash, UDID_BUF_LEN, DEVICE2_HASH);
    (void)strcpy_s(g_user3.userID, USER_ID_MAX_LEN, USER2_ID);
    (void)strcpy_s(g_user3.deviceHash, UDID_BUF_LEN, DEVICE1_HASH);
}

void Sqlite3UtilsTest::TearDownTestCase()
{
}

void Sqlite3UtilsTest::SetUp()
{
}

void Sqlite3UtilsTest::TearDown()
{
}

/*
* @tc.name: Create_and_Encrypt_Database_Test_001
* @tc.desc: create and encrypt database test
* @tc.type: FUNC
* @tc.require: AR000FK6J3
*/
HWTEST_F(Sqlite3UtilsTest, Create_and_Encrypt_Database_Test_001, TestSize.Level0)
{
    LnnDbContext *ctx = NULL;

    EXPECT_TRUE(LnnOpenDatabase(&ctx) == SOFTBUS_OK);
    EXPECT_TRUE(ctx != NULL);
    EXPECT_TRUE(LnnEncryptedDb(ctx, password, strlen(password)) == SOFTBUS_OK);
    EXPECT_TRUE(LnnCreateTable(ctx, TABLE_TRUST_DEVICE_INFO) == SOFTBUS_OK);
    EXPECT_TRUE(LnnDeleteTable(ctx, TABLE_TRUST_DEVICE_INFO) == SOFTBUS_OK);
    EXPECT_TRUE(LnnCloseDatabase(ctx) == SOFTBUS_OK);
}

/*
* @tc.name: Insert_data_Inerface_Test_001
* @tc.desc: insert data interface test
* @tc.type: FUNC
* @tc.require: AR000FK6J3
*/
HWTEST_F(Sqlite3UtilsTest, Insert_data_Inerface_Test_001, TestSize.Level0)
{
    bool isExist;
    LnnDbContext *ctx = NULL;

    EXPECT_TRUE(LnnOpenDatabase(&ctx) == SOFTBUS_OK);
    EXPECT_TRUE(ctx != NULL);
    EXPECT_TRUE(LnnEncryptedDb(ctx, password, strlen(password)) == SOFTBUS_OK);
    EXPECT_TRUE(LnnCheckTableExist(ctx, TABLE_TRUST_DEVICE_INFO, &isExist) == SOFTBUS_OK);
    EXPECT_TRUE(isExist == false);
    EXPECT_TRUE(LnnCreateTable(ctx, TABLE_TRUST_DEVICE_INFO) == SOFTBUS_OK);
    EXPECT_TRUE(LnnCheckTableExist(ctx, TABLE_TRUST_DEVICE_INFO, &isExist) == SOFTBUS_OK);
    EXPECT_TRUE(isExist == true);
    EXPECT_TRUE(LnnGetRecordNumByKey(ctx, TABLE_TRUST_DEVICE_INFO, (uint8_t *)USER1_ID) == 0);
    EXPECT_TRUE(LnnInsertRecord(ctx, TABLE_TRUST_DEVICE_INFO, (uint8_t *)&g_user1) == SOFTBUS_OK);
    EXPECT_TRUE(LnnGetRecordNumByKey(ctx, TABLE_TRUST_DEVICE_INFO, (uint8_t *)USER1_ID) == 1);
    EXPECT_TRUE(LnnDeleteTable(ctx, TABLE_TRUST_DEVICE_INFO) == SOFTBUS_OK);
    EXPECT_TRUE(LnnCheckTableExist(ctx, TABLE_TRUST_DEVICE_INFO, &isExist) == SOFTBUS_OK);
    EXPECT_TRUE(isExist == false);
    EXPECT_TRUE(LnnCloseDatabase(ctx) == SOFTBUS_OK);
}

/*
* @tc.name: Insert_data_Inerface_Test_002
* @tc.desc: insert data interface test
* @tc.type: FUNC
* @tc.require: AR000FK6J3
*/
HWTEST_F(Sqlite3UtilsTest, Insert_data_Inerface_Test_002, TestSize.Level0)
{
    LnnDbContext *ctx = NULL;

    EXPECT_TRUE(LnnOpenDatabase(&ctx) == SOFTBUS_OK);
    EXPECT_TRUE(ctx != NULL);
    EXPECT_TRUE(LnnEncryptedDb(ctx, password, strlen(password)) == SOFTBUS_OK);
    EXPECT_TRUE(LnnCreateTable(ctx, TABLE_TRUST_DEVICE_INFO) == SOFTBUS_OK);
    EXPECT_TRUE(LnnInsertRecord(ctx, TABLE_TRUST_DEVICE_INFO, (uint8_t *)&g_user1) == SOFTBUS_OK);
    EXPECT_TRUE(LnnInsertRecord(ctx, TABLE_TRUST_DEVICE_INFO, (uint8_t *)&g_user1) != SOFTBUS_OK);
    EXPECT_TRUE(LnnInsertRecord(ctx, TABLE_TRUST_DEVICE_INFO, (uint8_t *)&g_user2) == SOFTBUS_OK);
    EXPECT_TRUE(LnnInsertRecord(ctx, TABLE_TRUST_DEVICE_INFO, (uint8_t *)&g_user3) == SOFTBUS_OK);
    EXPECT_TRUE(LnnDeleteTable(ctx, TABLE_TRUST_DEVICE_INFO) == SOFTBUS_OK);
    EXPECT_TRUE(LnnCloseDatabase(ctx) == SOFTBUS_OK);
}

/*
* @tc.name: Remove_data_Inerface_Test_001
* @tc.desc: remove data interface test
* @tc.type: FUNC
* @tc.require: AR000FK6J3
*/
HWTEST_F(Sqlite3UtilsTest, Remove_data_Inerface_Test_001, TestSize.Level0)
{
    LnnDbContext *ctx = NULL;

    EXPECT_TRUE(LnnOpenDatabase(&ctx) == SOFTBUS_OK);
    EXPECT_TRUE(ctx != NULL);
    EXPECT_TRUE(LnnEncryptedDb(ctx, password, strlen(password)) == SOFTBUS_OK);
    EXPECT_TRUE(LnnCreateTable(ctx, TABLE_TRUST_DEVICE_INFO) == SOFTBUS_OK);
    EXPECT_TRUE(LnnInsertRecord(ctx, TABLE_TRUST_DEVICE_INFO, (uint8_t *)&g_user1) == SOFTBUS_OK);
    EXPECT_TRUE(LnnRemoveAllRecord(ctx, TABLE_TRUST_DEVICE_INFO) == SOFTBUS_OK);
    EXPECT_TRUE(LnnInsertRecord(ctx, TABLE_TRUST_DEVICE_INFO, (uint8_t *)&g_user1) == SOFTBUS_OK);
    EXPECT_TRUE(LnnDeleteTable(ctx, TABLE_TRUST_DEVICE_INFO) == SOFTBUS_OK);
    EXPECT_TRUE(LnnCloseDatabase(ctx) == SOFTBUS_OK);
}

/*
* @tc.name: Remove_data_Inerface_Test_002
* @tc.desc: remove data interface test
* @tc.type: FUNC
* @tc.require: AR000FK6J3
*/
HWTEST_F(Sqlite3UtilsTest, Remove_data_Inerface_Test_002, TestSize.Level0)
{
    LnnDbContext *ctx = NULL;

    EXPECT_TRUE(LnnOpenDatabase(&ctx) == SOFTBUS_OK);
    EXPECT_TRUE(ctx != NULL);
    EXPECT_TRUE(LnnEncryptedDb(ctx, password, strlen(password)) == SOFTBUS_OK);
    EXPECT_TRUE(LnnCreateTable(ctx, TABLE_TRUST_DEVICE_INFO) == SOFTBUS_OK);
    EXPECT_TRUE(LnnInsertRecord(ctx, TABLE_TRUST_DEVICE_INFO, (uint8_t *)&g_user1) == SOFTBUS_OK);
    EXPECT_TRUE(LnnRemoveRecordByKey(ctx, TABLE_TRUST_DEVICE_INFO, (uint8_t *)&g_user1) == SOFTBUS_OK);
    EXPECT_TRUE(LnnInsertRecord(ctx, TABLE_TRUST_DEVICE_INFO, (uint8_t *)&g_user1) == SOFTBUS_OK);
    EXPECT_TRUE(LnnDeleteTable(ctx, TABLE_TRUST_DEVICE_INFO) == SOFTBUS_OK);
    EXPECT_TRUE(LnnCloseDatabase(ctx) == SOFTBUS_OK);
}

/*
* @tc.name: Query_data_Inerface_Test_001
* @tc.desc: query data interface test
* @tc.type: FUNC
* @tc.require: AR000FK6J3
*/
HWTEST_F(Sqlite3UtilsTest, Query_data_Inerface_Test_001, TestSize.Level0)
{
    int32_t num = 0;
    LnnDbContext *ctx = NULL;
    char *record;

    EXPECT_TRUE(LnnOpenDatabase(&ctx) == SOFTBUS_OK);
    EXPECT_TRUE(ctx != NULL);
    EXPECT_TRUE(LnnEncryptedDb(ctx, password, strlen(password)) == SOFTBUS_OK);
    EXPECT_TRUE(LnnCreateTable(ctx, TABLE_TRUST_DEVICE_INFO) == SOFTBUS_OK);
    EXPECT_TRUE(LnnInsertRecord(ctx, TABLE_TRUST_DEVICE_INFO, (uint8_t *)&g_user1) == SOFTBUS_OK);
    num = LnnGetRecordNumByKey(ctx, TABLE_TRUST_DEVICE_INFO, (uint8_t *)USER1_ID);
    EXPECT_TRUE(num != 0);
    record = (char *)SoftBusCalloc(num * UDID_BUF_LEN);
    EXPECT_TRUE(LnnQueryRecordByKey(ctx, TABLE_TRUST_DEVICE_INFO, (uint8_t *)USER1_ID,
        (uint8_t **)&record, num)== SOFTBUS_OK);
    EXPECT_TRUE(strncmp(record, DEVICE1_HASH, strlen(DEVICE1_HASH)) == EOK);
    EXPECT_TRUE(LnnDeleteTable(ctx, TABLE_TRUST_DEVICE_INFO) == SOFTBUS_OK);
    EXPECT_TRUE(LnnCloseDatabase(ctx) == SOFTBUS_OK);
}

/*
* @tc.name: Query_data_Inerface_Test_002
* @tc.desc: query data interface test
* @tc.type: FUNC
* @tc.require: AR000FK6J3
*/
HWTEST_F(Sqlite3UtilsTest, Query_data_Inerface_Test_002, TestSize.Level0)
{
    int32_t num;
    LnnDbContext *ctx = NULL;
    char *record;

    EXPECT_TRUE(LnnOpenDatabase(&ctx) == SOFTBUS_OK);
    EXPECT_TRUE(ctx != NULL);
    EXPECT_TRUE(LnnEncryptedDb(ctx, password, strlen(password)) == SOFTBUS_OK);
    EXPECT_TRUE(LnnCreateTable(ctx, TABLE_TRUST_DEVICE_INFO) == SOFTBUS_OK);
    EXPECT_TRUE(LnnInsertRecord(ctx, TABLE_TRUST_DEVICE_INFO, (uint8_t *)&g_user1) == SOFTBUS_OK);
    EXPECT_TRUE(LnnInsertRecord(ctx, TABLE_TRUST_DEVICE_INFO, (uint8_t *)&g_user2) == SOFTBUS_OK);
    EXPECT_TRUE(LnnInsertRecord(ctx, TABLE_TRUST_DEVICE_INFO, (uint8_t *)&g_user3) == SOFTBUS_OK);

    num = LnnGetRecordNumByKey(ctx, TABLE_TRUST_DEVICE_INFO, (uint8_t *)USER1_ID);
    EXPECT_TRUE(num != 0);
    record = (char *)SoftBusCalloc(num * UDID_BUF_LEN);
    EXPECT_TRUE(LnnQueryRecordByKey(ctx, TABLE_TRUST_DEVICE_INFO, (uint8_t *)USER1_ID,
        (uint8_t **)&record, num)== SOFTBUS_OK);
    EXPECT_TRUE(strncmp(record, DEVICE1_HASH, strlen(DEVICE1_HASH)) == EOK);
    EXPECT_TRUE(strncmp(record + UDID_BUF_LEN, DEVICE2_HASH, strlen(DEVICE2_HASH)) == EOK);
    SoftBusFree(record);
    EXPECT_TRUE(LnnDeleteTable(ctx, TABLE_TRUST_DEVICE_INFO) == SOFTBUS_OK);
    EXPECT_TRUE(LnnCloseDatabase(ctx) == SOFTBUS_OK);
}

/*
* @tc.name: Open_and_Close_Transaction_Test_001
* @tc.desc: open and close transaction test
* @tc.type: FUNC
* @tc.require: AR000FK6J3
*/
HWTEST_F(Sqlite3UtilsTest, Open_and_Close_Transaction_Test_001, TestSize.Level0)
{
    LnnDbContext *ctx = NULL;

    EXPECT_TRUE(LnnOpenDatabase(&ctx) == SOFTBUS_OK);
    EXPECT_TRUE(ctx != NULL);
    EXPECT_TRUE(LnnEncryptedDb(ctx, password, strlen(password)) == SOFTBUS_OK);
    EXPECT_TRUE(LnnCreateTable(ctx, TABLE_TRUST_DEVICE_INFO) == SOFTBUS_OK);
    EXPECT_TRUE(LnnOpenTransaction(ctx) == SOFTBUS_OK);
    EXPECT_TRUE(LnnInsertRecord(ctx, TABLE_TRUST_DEVICE_INFO, (uint8_t *)&g_user1) == SOFTBUS_OK);
    EXPECT_TRUE(LnnCloseTransaction(ctx, CLOSE_TRANS_ROLLBACK) == SOFTBUS_OK);
    EXPECT_TRUE(LnnGetRecordNumByKey(ctx, TABLE_TRUST_DEVICE_INFO, (uint8_t *)USER1_ID) == 0);
    EXPECT_TRUE(LnnDeleteTable(ctx, TABLE_TRUST_DEVICE_INFO) == SOFTBUS_OK);
    EXPECT_TRUE(LnnCloseDatabase(ctx) == SOFTBUS_OK);
}

/*
* @tc.name: Open_and_Close_Transaction_Test_002
* @tc.desc: open and close transaction test
* @tc.type: FUNC
* @tc.require: AR000FK6J3
*/
HWTEST_F(Sqlite3UtilsTest, Open_and_Close_Transaction_Test_002, TestSize.Level0)
{
    int32_t num;
    LnnDbContext *ctx = NULL;
    char *record;

    EXPECT_TRUE(LnnOpenDatabase(&ctx) == SOFTBUS_OK);
    EXPECT_TRUE(ctx != NULL);
    EXPECT_TRUE(LnnEncryptedDb(ctx, password, strlen(password)) == SOFTBUS_OK);
    EXPECT_TRUE(LnnCreateTable(ctx, TABLE_TRUST_DEVICE_INFO) == SOFTBUS_OK);
    EXPECT_TRUE(LnnOpenTransaction(ctx) == SOFTBUS_OK);
    EXPECT_TRUE(LnnInsertRecord(ctx, TABLE_TRUST_DEVICE_INFO, (uint8_t *)&g_user1) == SOFTBUS_OK);
    EXPECT_TRUE(LnnCloseTransaction(ctx, CLOSE_TRANS_COMMIT) == SOFTBUS_OK);
    num = LnnGetRecordNumByKey(ctx, TABLE_TRUST_DEVICE_INFO, (uint8_t *)USER1_ID);
    EXPECT_TRUE(num != 0);
    record = (char *)SoftBusCalloc(num * UDID_BUF_LEN);
    EXPECT_TRUE(LnnQueryRecordByKey(ctx, TABLE_TRUST_DEVICE_INFO, (uint8_t *)USER1_ID,
        (uint8_t **)&record, num)== SOFTBUS_OK);
    EXPECT_TRUE(strncmp(record, DEVICE1_HASH, strlen(DEVICE1_HASH)) == EOK);
    EXPECT_TRUE(LnnDeleteTable(ctx, TABLE_TRUST_DEVICE_INFO) == SOFTBUS_OK);
    EXPECT_TRUE(LnnCloseDatabase(ctx) == SOFTBUS_OK);
}
} // namespace OHOS
