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

#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>

#include "sqlite3_utils.h"
#include "softbus_adapter_file.h"
#include "softbus_adapter_mem.h"
#include "softbus_bus_center.h"
#include "softbus_errcode.h"

namespace OHOS {
using namespace testing::ext;

constexpr char DEVICE1_HASH[] = "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b";
constexpr char DEVICE2_HASH[] = "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35";
constexpr char USER1_ID[] = "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce";
constexpr char USER2_ID[] = "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a";
constexpr uint8_t PASSWORD1[] = "ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d";
constexpr uint8_t PASSWORD2[] = "e7f6c011776e8db7cd330b54174fd76f7d0216b612387a5ffcfb81e6f0919683";

static TrustedDevInfoRecord g_record1, g_record2, g_record3;

class Sqlite3UtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void Sqlite3UtilsTest::SetUpTestCase()
{
    (void)strcpy_s(g_record1.accountHexHash, SHA_256_HEX_HASH_LEN, USER1_ID);
    (void)strcpy_s(g_record1.udid, UDID_BUF_LEN, DEVICE1_HASH);
    (void)strcpy_s(g_record2.accountHexHash, SHA_256_HEX_HASH_LEN, USER1_ID);
    (void)strcpy_s(g_record2.udid, UDID_BUF_LEN, DEVICE2_HASH);
    (void)strcpy_s(g_record3.accountHexHash, SHA_256_HEX_HASH_LEN, USER2_ID);
    (void)strcpy_s(g_record3.udid, UDID_BUF_LEN, DEVICE1_HASH);
}

void Sqlite3UtilsTest::TearDownTestCase()
{
}

void Sqlite3UtilsTest::SetUp()
{
}

void Sqlite3UtilsTest::TearDown()
{
    SoftBusRemoveFile(DATABASE_NAME);
}

/*
* @tc.name: Open_Database_Test_001
* @tc.desc: open database test
* @tc.type: FUNC
* @tc.require: I5PIFW
*/
HWTEST_F(Sqlite3UtilsTest, Open_Database_Test_01, TestSize.Level0)
{
    DbContext **ctxPtr = nullptr;

    EXPECT_EQ(OpenDatabase(ctxPtr), SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: Open_Database_Test_002
* @tc.desc: open database test
* @tc.type: FUNC
* @tc.require: I5PIFW
*/
HWTEST_F(Sqlite3UtilsTest, Open_Database_Test_02, TestSize.Level0)
{
    DbContext *ctx = nullptr;

    EXPECT_EQ(OpenDatabase(&ctx), SOFTBUS_OK);
    ASSERT_TRUE(ctx != nullptr);
    EXPECT_EQ(CloseDatabase(ctx), SOFTBUS_OK);
}

/*
* @tc.name: Open_Database_Test_003
* @tc.desc: open database test
* @tc.type: FUNC
* @tc.require: I5PIFW
*/
HWTEST_F(Sqlite3UtilsTest, Open_Database_Test_03, TestSize.Level0)
{
    DbContext *ctx = nullptr;

    EXPECT_EQ(OpenDatabase(&ctx), SOFTBUS_OK);
    ASSERT_TRUE(ctx != nullptr);
    EXPECT_EQ(CloseDatabase(ctx), SOFTBUS_OK);
    EXPECT_EQ(OpenDatabase(&ctx), SOFTBUS_OK);
    ASSERT_TRUE(ctx != nullptr);
    EXPECT_EQ(CloseDatabase(ctx), SOFTBUS_OK);
}

/*
* @tc.name: Create_Table_Test_001
* @tc.desc: create table test
* @tc.type: FUNC
* @tc.require: I5PIFW
*/
HWTEST_F(Sqlite3UtilsTest, Create_Table_Test_001, TestSize.Level0)
{
    DbContext *ctx = nullptr;

    EXPECT_EQ(CreateTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DeleteTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: Create_Table_Test_002
* @tc.desc: create table test
* @tc.type: FUNC
* @tc.require: I5PIFW
*/
HWTEST_F(Sqlite3UtilsTest, Create_Table_Test_002, TestSize.Level0)
{
    bool isExist = false;
    DbContext *ctx = nullptr;

    EXPECT_EQ(OpenDatabase(&ctx), SOFTBUS_OK);
    ASSERT_TRUE(ctx != nullptr);
    EXPECT_EQ(CheckTableExist(ctx, TABLE_TRUSTED_DEV_INFO, &isExist), SOFTBUS_OK);
    EXPECT_TRUE(!isExist);
    EXPECT_EQ(CreateTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(CheckTableExist(ctx, TABLE_TRUSTED_DEV_INFO, &isExist), SOFTBUS_OK);
    EXPECT_TRUE(isExist);
    EXPECT_EQ(DeleteTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(CheckTableExist(ctx, TABLE_TRUSTED_DEV_INFO, &isExist), SOFTBUS_OK);
    EXPECT_TRUE(!isExist);
    EXPECT_EQ(CloseDatabase(ctx), SOFTBUS_OK);
}

/*
* @tc.name: Create_and_Encrypt_Database_Test_001
* @tc.desc: create and encrypt database test
* @tc.type: FUNC
* @tc.require: I5PIFW
*/
HWTEST_F(Sqlite3UtilsTest, Create_and_Encrypt_Database_Test_001, TestSize.Level0)
{
    bool isExist = false;
    DbContext *ctx = nullptr;

    EXPECT_EQ(OpenDatabase(&ctx), SOFTBUS_OK);
    ASSERT_TRUE(ctx != nullptr);
    EXPECT_EQ(EncryptedDb(ctx, PASSWORD1, sizeof(PASSWORD1)), SOFTBUS_OK);
    EXPECT_EQ(CheckTableExist(ctx, TABLE_TRUSTED_DEV_INFO, &isExist), SOFTBUS_OK);
    EXPECT_TRUE(!isExist);
    EXPECT_EQ(CreateTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(CheckTableExist(ctx, TABLE_TRUSTED_DEV_INFO, &isExist), SOFTBUS_OK);
    EXPECT_TRUE(isExist);
    EXPECT_EQ(DeleteTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(CheckTableExist(ctx, TABLE_TRUSTED_DEV_INFO, &isExist), SOFTBUS_OK);
    EXPECT_TRUE(!isExist);
    EXPECT_EQ(CloseDatabase(ctx), SOFTBUS_OK);
}

/*
* @tc.name: Create_and_Encrypt_Database_Test_002
* @tc.desc: create and encrypt database test
* @tc.type: FUNC
* @tc.require: I5PIFW
*/
HWTEST_F(Sqlite3UtilsTest, Create_and_Encrypt_Database_Test_002, TestSize.Level0)
{
    DbContext *ctx = nullptr;

    EXPECT_EQ(OpenDatabase(&ctx), SOFTBUS_OK);
    ASSERT_TRUE(ctx != nullptr);
    EXPECT_EQ(EncryptedDb(ctx, PASSWORD1, sizeof(PASSWORD1)), SOFTBUS_OK);
    EXPECT_EQ(CreateTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(DeleteTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(CloseDatabase(ctx), SOFTBUS_OK);

    EXPECT_EQ(OpenDatabase(&ctx), SOFTBUS_OK);
    ASSERT_TRUE(ctx != nullptr);
    EXPECT_NE(CreateTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_NE(DeleteTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(CloseDatabase(ctx), SOFTBUS_OK);

    EXPECT_EQ(OpenDatabase(&ctx), SOFTBUS_OK);
    ASSERT_TRUE(ctx != nullptr);
    EXPECT_EQ(EncryptedDb(ctx, PASSWORD1, sizeof(PASSWORD1)), SOFTBUS_OK);
    EXPECT_EQ(CreateTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(DeleteTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(CloseDatabase(ctx), SOFTBUS_OK);

    EXPECT_EQ(OpenDatabase(&ctx), SOFTBUS_OK);
    ASSERT_TRUE(ctx != nullptr);
    EXPECT_NE(CreateTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_NE(DeleteTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(CloseDatabase(ctx), SOFTBUS_OK);
}

/*
* @tc.name: Create_and_Encrypt_Database_Test_003
* @tc.desc: create and encrypt database test
* @tc.type: FUNC
* @tc.require: I5PIFW
*/
HWTEST_F(Sqlite3UtilsTest, Create_and_Encrypt_Database_Test_003, TestSize.Level0)
{
    DbContext *ctx = nullptr;

    EXPECT_EQ(OpenDatabase(&ctx), SOFTBUS_OK);
    ASSERT_TRUE(ctx != nullptr);
    EXPECT_EQ(EncryptedDb(ctx, PASSWORD1, sizeof(PASSWORD1)), SOFTBUS_OK);
    EXPECT_EQ(CreateTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(DeleteTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(CloseDatabase(ctx), SOFTBUS_OK);

    EXPECT_EQ(OpenDatabase(&ctx), SOFTBUS_OK);
    ASSERT_TRUE(ctx != nullptr);
    EXPECT_EQ(EncryptedDb(ctx, PASSWORD2, sizeof(PASSWORD2)), SOFTBUS_OK);
    EXPECT_NE(CreateTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_NE(DeleteTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(CloseDatabase(ctx), SOFTBUS_OK);

    EXPECT_EQ(OpenDatabase(&ctx), SOFTBUS_OK);
    ASSERT_TRUE(ctx != nullptr);
    EXPECT_EQ(EncryptedDb(ctx, PASSWORD1, sizeof(PASSWORD1)), SOFTBUS_OK);
    EXPECT_EQ(CreateTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(DeleteTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(CloseDatabase(ctx), SOFTBUS_OK);

    EXPECT_EQ(OpenDatabase(&ctx), SOFTBUS_OK);
    ASSERT_TRUE(ctx != nullptr);
    EXPECT_EQ(EncryptedDb(ctx, PASSWORD2, sizeof(PASSWORD2)), SOFTBUS_OK);
    EXPECT_NE(CreateTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_NE(DeleteTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(CloseDatabase(ctx), SOFTBUS_OK);
}

/*
* @tc.name: Create_and_Encrypt_Database_Test_004
* @tc.desc: create and encrypt database test
* @tc.type: FUNC
* @tc.require: I5PIFW
*/
HWTEST_F(Sqlite3UtilsTest, Create_and_Encrypt_Database_Test_004, TestSize.Level0)
{
    DbContext *ctx = nullptr;

    EXPECT_EQ(OpenDatabase(&ctx), SOFTBUS_OK);
    ASSERT_TRUE(ctx != nullptr);
    EXPECT_EQ(EncryptedDb(ctx, PASSWORD1, sizeof(PASSWORD1)), SOFTBUS_OK);
    EXPECT_EQ(CreateTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(DeleteTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(CloseDatabase(ctx), SOFTBUS_OK);

    EXPECT_EQ(OpenDatabase(&ctx), SOFTBUS_OK);
    ASSERT_TRUE(ctx != nullptr);
    EXPECT_EQ(UpdateDbPassword(ctx, PASSWORD1, sizeof(PASSWORD1)), SOFTBUS_OK);
    EXPECT_NE(CreateTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_NE(DeleteTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(CloseDatabase(ctx), SOFTBUS_OK);

    EXPECT_EQ(OpenDatabase(&ctx), SOFTBUS_OK);
    ASSERT_TRUE(ctx != nullptr);
    EXPECT_EQ(EncryptedDb(ctx, PASSWORD1, sizeof(PASSWORD1)), SOFTBUS_OK);
    EXPECT_EQ(CreateTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(DeleteTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(CloseDatabase(ctx), SOFTBUS_OK);

    EXPECT_EQ(OpenDatabase(&ctx), SOFTBUS_OK);
    ASSERT_TRUE(ctx != nullptr);
    EXPECT_EQ(UpdateDbPassword(ctx, PASSWORD1, sizeof(PASSWORD1)), SOFTBUS_OK);
    EXPECT_NE(CreateTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_NE(DeleteTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(CloseDatabase(ctx), SOFTBUS_OK);
}

/*
* @tc.name: Create_and_Encrypt_Database_Test_005
* @tc.desc: create and encrypt database test
* @tc.type: FUNC
* @tc.require: I5PIFW
*/
HWTEST_F(Sqlite3UtilsTest, Create_and_Encrypt_Database_Test_005, TestSize.Level0)
{
    DbContext *ctx = nullptr;

    EXPECT_EQ(OpenDatabase(&ctx), SOFTBUS_OK);
    ASSERT_TRUE(ctx != nullptr);
    EXPECT_EQ(EncryptedDb(ctx, PASSWORD1, sizeof(PASSWORD1)), SOFTBUS_OK);
    EXPECT_EQ(CreateTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(DeleteTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(CloseDatabase(ctx), SOFTBUS_OK);

    EXPECT_EQ(OpenDatabase(&ctx), SOFTBUS_OK);
    ASSERT_TRUE(ctx != nullptr);
    EXPECT_EQ(EncryptedDb(ctx, PASSWORD1, sizeof(PASSWORD1)), SOFTBUS_OK);
    EXPECT_EQ(UpdateDbPassword(ctx, PASSWORD2, sizeof(PASSWORD2)), SOFTBUS_OK);
    EXPECT_EQ(CreateTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(DeleteTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(CloseDatabase(ctx), SOFTBUS_OK);

    EXPECT_EQ(OpenDatabase(&ctx), SOFTBUS_OK);
    ASSERT_TRUE(ctx != nullptr);
    EXPECT_EQ(EncryptedDb(ctx, PASSWORD1, sizeof(PASSWORD1)), SOFTBUS_OK);
    EXPECT_NE(CreateTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_NE(DeleteTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(CloseDatabase(ctx), SOFTBUS_OK);

    EXPECT_EQ(OpenDatabase(&ctx), SOFTBUS_OK);
    ASSERT_TRUE(ctx != nullptr);
    EXPECT_EQ(EncryptedDb(ctx, PASSWORD2, sizeof(PASSWORD2)), SOFTBUS_OK);
    EXPECT_EQ(CreateTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(DeleteTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(CloseDatabase(ctx), SOFTBUS_OK);
}

/*
* @tc.name: Insert_data_Inerface_Test_001
* @tc.desc: insert data interface test
* @tc.type: FUNC
* @tc.require: I5PIFW
*/
HWTEST_F(Sqlite3UtilsTest, Insert_data_Inerface_Test_001, TestSize.Level0)
{
    DbContext *ctx = nullptr;

    EXPECT_EQ(OpenDatabase(&ctx), SOFTBUS_OK);
    ASSERT_TRUE(ctx != nullptr);
    EXPECT_EQ(EncryptedDb(ctx, PASSWORD1, sizeof(PASSWORD1)), SOFTBUS_OK);
    EXPECT_EQ(GetRecordNumByKey(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)USER1_ID), 0);
    EXPECT_EQ(CreateTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(GetRecordNumByKey(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)USER1_ID), 0);
    EXPECT_EQ(InsertRecord(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)&g_record1), SOFTBUS_OK);
    EXPECT_EQ(GetRecordNumByKey(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)USER1_ID), 1);
    EXPECT_EQ(DeleteTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(GetRecordNumByKey(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)USER1_ID), 0);
    EXPECT_EQ(CloseDatabase(ctx), SOFTBUS_OK);
}

/*
* @tc.name: Insert_data_Inerface_Test_002
* @tc.desc: insert data interface test
* @tc.type: FUNC
* @tc.require: I5PIFW
*/
HWTEST_F(Sqlite3UtilsTest, Insert_data_Inerface_Test_002, TestSize.Level0)
{
    DbContext *ctx = nullptr;

    EXPECT_EQ(OpenDatabase(&ctx), SOFTBUS_OK);
    ASSERT_TRUE(ctx != nullptr);
    EXPECT_EQ(EncryptedDb(ctx, PASSWORD1, sizeof(PASSWORD1)), SOFTBUS_OK);
    EXPECT_EQ(CreateTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(InsertRecord(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)&g_record1), SOFTBUS_OK);
    EXPECT_NE(InsertRecord(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)&g_record1), SOFTBUS_OK);
    EXPECT_EQ(GetRecordNumByKey(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)USER1_ID), 1);
    EXPECT_EQ(InsertRecord(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)&g_record2), SOFTBUS_OK);
    EXPECT_EQ(GetRecordNumByKey(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)USER1_ID), 2);
    EXPECT_EQ(InsertRecord(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)&g_record3), SOFTBUS_OK);
    EXPECT_EQ(GetRecordNumByKey(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)USER2_ID), 1);
    EXPECT_EQ(DeleteTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(CloseDatabase(ctx), SOFTBUS_OK);
}

/*
* @tc.name: Remove_data_Inerface_Test_001
* @tc.desc: remove data interface test
* @tc.type: FUNC
* @tc.require: I5PIFW
*/
HWTEST_F(Sqlite3UtilsTest, Remove_data_Inerface_Test_001, TestSize.Level0)
{
    DbContext *ctx = nullptr;

    EXPECT_EQ(OpenDatabase(&ctx), SOFTBUS_OK);
    ASSERT_TRUE(ctx != nullptr);
    EXPECT_EQ(EncryptedDb(ctx, PASSWORD1, sizeof(PASSWORD1)), SOFTBUS_OK);
    EXPECT_EQ(CreateTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(InsertRecord(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)&g_record1), SOFTBUS_OK);
    EXPECT_EQ(GetRecordNumByKey(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)USER1_ID), 1);
    EXPECT_EQ(RemoveAllRecord(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(GetRecordNumByKey(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)USER1_ID), 0);
    EXPECT_EQ(InsertRecord(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)&g_record1), SOFTBUS_OK);
    EXPECT_EQ(GetRecordNumByKey(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)USER1_ID), 1);
    EXPECT_EQ(DeleteTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(CloseDatabase(ctx), SOFTBUS_OK);
}

/*
* @tc.name: Remove_data_Inerface_Test_002
* @tc.desc: remove data interface test
* @tc.type: FUNC
* @tc.require: I5PIFW
*/
HWTEST_F(Sqlite3UtilsTest, Remove_data_Inerface_Test_002, TestSize.Level0)
{
    DbContext *ctx = nullptr;

    EXPECT_EQ(OpenDatabase(&ctx), SOFTBUS_OK);
    ASSERT_TRUE(ctx != nullptr);
    EXPECT_EQ(EncryptedDb(ctx, PASSWORD1, sizeof(PASSWORD1)), SOFTBUS_OK);
    EXPECT_EQ(CreateTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(InsertRecord(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)&g_record1), SOFTBUS_OK);
    EXPECT_EQ(GetRecordNumByKey(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)USER1_ID), 1);
    EXPECT_EQ(RemoveRecordByKey(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)&g_record1), SOFTBUS_OK);
    EXPECT_EQ(GetRecordNumByKey(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)USER1_ID), 0);
    EXPECT_EQ(InsertRecord(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)&g_record1), SOFTBUS_OK);
    EXPECT_EQ(GetRecordNumByKey(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)USER1_ID), 1);
    EXPECT_EQ(DeleteTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(CloseDatabase(ctx), SOFTBUS_OK);
}

/*
* @tc.name: Remove_data_Inerface_Test_003
* @tc.desc: remove data interface test
* @tc.type: FUNC
* @tc.require: I5PIFW
*/
HWTEST_F(Sqlite3UtilsTest, Remove_data_Inerface_Test_003, TestSize.Level0)
{
    DbContext *ctx = nullptr;

    EXPECT_EQ(OpenDatabase(&ctx), SOFTBUS_OK);
    ASSERT_TRUE(ctx != nullptr);
    EXPECT_EQ(EncryptedDb(ctx, PASSWORD1, sizeof(PASSWORD1)), SOFTBUS_OK);
    EXPECT_EQ(CreateTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(InsertRecord(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)&g_record1), SOFTBUS_OK);
    EXPECT_EQ(GetRecordNumByKey(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)USER1_ID), 1);
    EXPECT_EQ(RemoveRecordByKey(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)&g_record2), SOFTBUS_OK);
    EXPECT_EQ(GetRecordNumByKey(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)USER1_ID), 1);
    EXPECT_EQ(InsertRecord(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)&g_record2), SOFTBUS_OK);
    EXPECT_EQ(GetRecordNumByKey(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)USER1_ID), 2);
    EXPECT_EQ(DeleteTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(CloseDatabase(ctx), SOFTBUS_OK);
}

/*
* @tc.name: Query_data_Inerface_Test_001
* @tc.desc: query data interface test
* @tc.type: FUNC
* @tc.require: I5PIFW
*/
HWTEST_F(Sqlite3UtilsTest, Query_data_Inerface_Test_001, TestSize.Level0)
{
    int32_t num;
    DbContext *ctx = nullptr;
    char *record;

    EXPECT_EQ(OpenDatabase(&ctx), SOFTBUS_OK);
    ASSERT_TRUE(ctx != nullptr);
    EXPECT_EQ(EncryptedDb(ctx, PASSWORD1, sizeof(PASSWORD1)), SOFTBUS_OK);
    EXPECT_EQ(CreateTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(InsertRecord(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)&g_record1), SOFTBUS_OK);
    num = GetRecordNumByKey(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)USER1_ID);
    ASSERT_TRUE(num != 0);
    record = (char *)SoftBusCalloc(num * UDID_BUF_LEN);
    ASSERT_TRUE(record != nullptr);
    EXPECT_EQ(QueryRecordByKey(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)USER1_ID,
        (uint8_t **)&record, num), SOFTBUS_OK);
    EXPECT_STREQ(record, DEVICE1_HASH);
    SoftBusFree(record);
    EXPECT_EQ(DeleteTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(CloseDatabase(ctx), SOFTBUS_OK);
}

/*
* @tc.name: Query_data_Inerface_Test_002
* @tc.desc: query data interface test
* @tc.type: FUNC
* @tc.require: I5PIFW
*/
HWTEST_F(Sqlite3UtilsTest, Query_data_Inerface_Test_002, TestSize.Level0)
{
    int32_t num;
    DbContext *ctx = nullptr;
    char *record;

    EXPECT_EQ(OpenDatabase(&ctx), SOFTBUS_OK);
    ASSERT_TRUE(ctx != nullptr);
    EXPECT_EQ(EncryptedDb(ctx, PASSWORD1, sizeof(PASSWORD1)), SOFTBUS_OK);
    EXPECT_EQ(CreateTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(InsertRecord(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)&g_record1), SOFTBUS_OK);
    EXPECT_EQ(InsertRecord(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)&g_record2), SOFTBUS_OK);
    EXPECT_EQ(InsertRecord(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)&g_record3), SOFTBUS_OK);
    num = GetRecordNumByKey(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)USER1_ID);
    ASSERT_TRUE(num != 0);
    record = (char *)SoftBusCalloc(num * UDID_BUF_LEN);
    ASSERT_TRUE(record != nullptr);
    EXPECT_EQ(QueryRecordByKey(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)USER1_ID,
        (uint8_t **)&record, num), SOFTBUS_OK);
    EXPECT_STREQ(record, DEVICE1_HASH);
    EXPECT_STREQ(record + UDID_BUF_LEN, DEVICE2_HASH);
    SoftBusFree(record);
    EXPECT_EQ(DeleteTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(CloseDatabase(ctx), SOFTBUS_OK);
}

/*
* @tc.name: Open_and_Close_Transaction_Test_001
* @tc.desc: open and close transaction test
* @tc.type: FUNC
* @tc.require: I5PIFW
*/
HWTEST_F(Sqlite3UtilsTest, Open_and_Close_Transaction_Test_001, TestSize.Level0)
{
    DbContext *ctx = nullptr;

    EXPECT_EQ(OpenDatabase(&ctx), SOFTBUS_OK);
    ASSERT_TRUE(ctx != nullptr);
    EXPECT_EQ(EncryptedDb(ctx, PASSWORD1, sizeof(PASSWORD1)), SOFTBUS_OK);
    EXPECT_EQ(CreateTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(OpenTransaction(ctx), SOFTBUS_OK);
    EXPECT_EQ(InsertRecord(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)&g_record1), SOFTBUS_OK);
    EXPECT_EQ(CloseTransaction(ctx, CLOSE_TRANS_ROLLBACK), SOFTBUS_OK);
    EXPECT_EQ(GetRecordNumByKey(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)USER1_ID), 0);
    EXPECT_EQ(DeleteTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(CloseDatabase(ctx), SOFTBUS_OK);
}

/*
* @tc.name: Open_and_Close_Transaction_Test_002
* @tc.desc: open and close transaction test
* @tc.type: FUNC
* @tc.require: I5PIFW
*/
HWTEST_F(Sqlite3UtilsTest, Open_and_Close_Transaction_Test_002, TestSize.Level0)
{
    int32_t num;
    DbContext *ctx = nullptr;
    char *record;

    EXPECT_EQ(OpenDatabase(&ctx), SOFTBUS_OK);
    ASSERT_TRUE(ctx != nullptr);
    EXPECT_EQ(EncryptedDb(ctx, PASSWORD1, sizeof(PASSWORD1)), SOFTBUS_OK);
    EXPECT_EQ(CreateTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(OpenTransaction(ctx), SOFTBUS_OK);
    EXPECT_EQ(InsertRecord(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)&g_record1), SOFTBUS_OK);
    EXPECT_EQ(CloseTransaction(ctx, CLOSE_TRANS_COMMIT), SOFTBUS_OK);
    num = GetRecordNumByKey(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)USER1_ID);
    ASSERT_TRUE(num != 0);
    record = (char *)SoftBusCalloc(num * UDID_BUF_LEN);
    ASSERT_TRUE(record != nullptr);
    EXPECT_EQ(QueryRecordByKey(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)USER1_ID,
        (uint8_t **)&record, num), SOFTBUS_OK);
    EXPECT_STREQ(record, DEVICE1_HASH);
    SoftBusFree(record);
    EXPECT_EQ(DeleteTable(ctx, TABLE_TRUSTED_DEV_INFO), SOFTBUS_OK);
    EXPECT_EQ(CloseDatabase(ctx), SOFTBUS_OK);
}
} // namespace OHOS
