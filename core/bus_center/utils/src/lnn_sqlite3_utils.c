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

#include "lnn_sqlite3_utils.h"

#include <securec.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lnn_file_utils.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

#define SOFTBUS_SQLITE_PATH_LEN 256
#define DB_CONTEXT_STATE_QUERYING 0x01
#define DB_CONTEXT_STATE_TRANSACTION 0x02
#define SOFTBUS_SQL_DEFAULT_LEN 256

#define DATABASE_NAME "device.db3"
#define TRUSTDEVICEINFO_TABLE_NAME "TrustDeviceInfo"
#define CREATE_TRUSTDEVICEINFO_TABLE_SQL "CREATE TABLE IF NOT EXISTS TrustDeviceInfo (" \
    "UserID TEXT NOT NULL," \
    "DeviceHash TEXT NOT NULL," \
    "primary key(UserID, DeviceHash));"
#define TRUSTDEVICEINFO_INSERT_TABLE "INSERT INTO TrustDeviceInfo (UserID, DeviceHash) VALUES (?, ?)"
#define TRUSTDEVICEINFO_SEARCH_BY_ID "SELECT DeviceHash FROM TrustDeviceInfo WHERE UserID = ?"
#define TRUSTDEVICEINFO_REMOVE_BY_ID "DELETE FROM TrustDeviceInfo WHERE UserID = ? AND DeviceHash = ?"
#define REMOVE_ALL_RECORD "DELETE FROM "
#define DROP_TABLE "DROP TABLE "
#define SEARCH_IF_TABLE_EXIST "SELECT * FROM sqlite_master WHERE type ='table' AND name = '%s'"

typedef int32_t (*BindParaCallBack)(LnnDbContext *ctx, int32_t paraNum, uint8_t *data);
typedef int32_t (*QueryDataCallBack)(LnnDbContext *ctx, uint8_t *data, int32_t idx);

typedef struct {
    const char *tableName;
    const char *createSql;
    const char *insertSql;
    const char *searchSqlByKey;
    const char *removeSqlByKey;
    BindParaCallBack insertBindParaCb;
    BindParaCallBack searchBindParaCb;
    BindParaCallBack removeBindParaCb;
    QueryDataCallBack searchGetParaCb;
} SqlLedger;

static char g_sqliteFilePath[SOFTBUS_SQLITE_PATH_LEN] = {0};

static int32_t GetTrustDeviceInfoByIdCb(LnnDbContext *ctx, uint8_t *data, int32_t idx)
{
    int32_t i = 0;
    char *info = (char *)data + idx * UDID_BUF_LEN;
    if (LnnGetQueryResultColText(ctx, i, info, UDID_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnGetQueryResultColText failed");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "info:%s", info);
    return SOFTBUS_OK;
}

static int32_t BindInsertTrustDeviceInfoCb(LnnDbContext *ctx, int32_t paraNum, uint8_t *data)
{
    int32_t rc, idx = 1;
    if (data == NULL) {
        return SQLITE_ERROR;
    }
    LnnTrustDeviceInfoRecord *record = (LnnTrustDeviceInfoRecord *)data;
    rc = LnnBindParaText(ctx, idx, record->userID, strlen(record->userID));
    if (rc != SOFTBUS_OK) {
        return rc;
    }
    return LnnBindParaText(ctx, ++idx, record->deviceHash, strlen(record->deviceHash));
}

static int32_t BindSelectTrustDeviceInfoCb(LnnDbContext *ctx, int32_t paraNum, uint8_t *data)
{
    int32_t idx = 1;
    if (data == NULL) {
        return SQLITE_ERROR;
    }
    
    return LnnBindParaText(ctx, idx, (char *)data, strlen((char *)data));
}

static SqlLedger g_sqlLedger[TABLE_NAME_ID_MAX] = {
    [TABLE_TRUST_DEVICE_INFO] = {
        .tableName = TRUSTDEVICEINFO_TABLE_NAME,
        .createSql = CREATE_TRUSTDEVICEINFO_TABLE_SQL,
        .insertSql = TRUSTDEVICEINFO_INSERT_TABLE,
        .searchSqlByKey = TRUSTDEVICEINFO_SEARCH_BY_ID,
        .removeSqlByKey = TRUSTDEVICEINFO_REMOVE_BY_ID,
        .insertBindParaCb = BindInsertTrustDeviceInfoCb,
        .searchBindParaCb = BindSelectTrustDeviceInfoCb,
        .removeBindParaCb = BindInsertTrustDeviceInfoCb,
        .searchGetParaCb = GetTrustDeviceInfoByIdCb,
    },
};

static int32_t ExecuteSql(LnnDbContext *ctx, const char *sql, uint32_t len, BindParaCallBack cb, uint8_t *data)
{
    int32_t paraNum;
    int32_t rc;
    if (sql == NULL || strlen(sql) <= 0) {
        return SOFTBUS_SQLITE_MISUSE;
    }

    rc = sqlite3_prepare_v2(ctx->db, sql, len, &ctx->stmt, NULL);
    if (rc != SOFTBUS_OK || ctx->stmt == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "sqlite3_prepare_v2 failed");
        return sqlite3_errcode(ctx->db);
    }
    paraNum = sqlite3_bind_parameter_count(ctx->stmt);
    if (paraNum > 0 && cb == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "need cd for binding parameter");
        (void)sqlite3_finalize(ctx->stmt);
        ctx->stmt = NULL;
        return SOFTBUS_SQLITE_MISUSE;
    }
    if (paraNum <= 0) {
        return sqlite3_step(ctx->stmt);
    }
    rc = cb(ctx, paraNum, data);
    if (rc != SQLITE_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "binding parameter cd fail");
        (void)sqlite3_finalize(ctx->stmt);
        ctx->stmt = NULL;
        return sqlite3_errcode(ctx->db);
    }
    return sqlite3_step(ctx->stmt);
}

static int32_t QueryData(LnnDbContext *ctx, const char *sql, uint32_t len, BindParaCallBack cb, uint8_t *data)
{
    int32_t rc;
    rc = ExecuteSql(ctx, sql, len, cb, data);
    if (rc != SQLITE_ROW) {
        (void)sqlite3_finalize(ctx->stmt);
        ctx->stmt = NULL;
    } else {
        ctx->state |= DB_CONTEXT_STATE_QUERYING;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "QueryData done, state: %d", ctx->state);
    return rc;
}

static int32_t QueryDataNext(LnnDbContext *ctx)
{
    int32_t rc;
    rc = sqlite3_step(ctx->stmt);
    if (rc != SQLITE_ROW) {
        ctx->state &= ~DB_CONTEXT_STATE_QUERYING;
        (void)sqlite3_finalize(ctx->stmt);
        ctx->stmt = NULL;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "QueryDataNext done, state: %d", ctx->state);
    return rc;
}

int32_t LnnOpenDatabase(LnnDbContext **ctx)
{
    sqlite3 *sqlite = NULL;
    int32_t rc;
    if (ctx == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strlen(g_sqliteFilePath) <= 0) {
        rc = LnnGetFullStoragePath(LNN_FILE_ID_SQLITE, g_sqliteFilePath, SOFTBUS_SQLITE_PATH_LEN);
        if (rc != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get sqlite path fail");
            return SOFTBUS_ERR;
        }
    }

    if (strncat_s(g_sqliteFilePath, SOFTBUS_SQLITE_PATH_LEN, DATABASE_NAME, strlen(DATABASE_NAME)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "strncat_s sqlite path fail");
        return SOFTBUS_ERR;
    }

    rc = sqlite3_open_v2(g_sqliteFilePath, &sqlite, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (rc != SOFTBUS_OK || sqlite == NULL) {
        if (sqlite != NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "sqlite3_open_v2 fail: %s", sqlite3_errmsg(sqlite));
        } else {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "sqlite3_open_v2 fail: unknown");
        }
        (void)sqlite3_close_v2(sqlite);
        return SOFTBUS_ERR;
    }
    *ctx = (LnnDbContext *)SoftBusCalloc(sizeof(LnnDbContext));
    if (*ctx == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc LnnDbContext fail");
        (void)sqlite3_close_v2(sqlite);
        return SOFTBUS_ERR;
    } else {
        (*ctx)->db = sqlite;
    }
    return SOFTBUS_OK;
}

int32_t LnnCloseDatabase(LnnDbContext *ctx)
{
    if (ctx == NULL || ctx->db == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    (void)sqlite3_close_v2(ctx->db);
    SoftBusFree(ctx);
    return SOFTBUS_OK;
}

int32_t LnnCreateTable(LnnDbContext *ctx, TableNameID id)
{
    int32_t rc;
    char *errMsg = NULL;
    if (ctx == NULL || ctx->db == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    const char *sql = g_sqlLedger[id].createSql;
    if (sql == NULL || strlen(sql) <= 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "createsql is not impl");
        return SOFTBUS_ERR;
    }
    rc = sqlite3_exec(ctx->db, sql, NULL, NULL, &errMsg);
    if (rc != SQLITE_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "sqlite_exec fail: %s", errMsg);
        sqlite3_free(errMsg);
        return SOFTBUS_SQLITE_MISUSE;
    }
    return SOFTBUS_OK;
}

int32_t LnnDeleteTable(LnnDbContext *ctx, TableNameID id)
{
    int32_t rc;
    char sql[SOFTBUS_SQL_DEFAULT_LEN] = {0};
    if (ctx == NULL || ctx->db == NULL || ctx->stmt != NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    rc = sprintf_s(sql, SOFTBUS_SQL_DEFAULT_LEN, "%s%s", DROP_TABLE, g_sqlLedger[id].tableName);
    if (rc < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "sprintf_s sql fail");
        return SOFTBUS_ERR;
    }
    rc = ExecuteSql(ctx, sql, strlen(sql), NULL, NULL);
    if (rc != SQLITE_DONE) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "delete table fail");
        rc = SOFTBUS_ERR;
    } else {
        rc = SOFTBUS_OK;
    }
    (void)sqlite3_finalize(ctx->stmt);
    ctx->stmt = NULL;
    return rc;
}

int32_t LnnCheckTableExist(LnnDbContext *ctx, TableNameID id, bool *isExist)
{
    int32_t rc;
    char sql[SOFTBUS_SQL_DEFAULT_LEN] = {0};
    if (ctx == NULL || isExist == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    if (ctx->db == NULL || ctx->stmt != NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid db context state");
        return SOFTBUS_SQLITE_MISUSE;
    }

    rc = sprintf_s(sql, SOFTBUS_SQL_DEFAULT_LEN, SEARCH_IF_TABLE_EXIST, g_sqlLedger[id].tableName);
    if (rc < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "sprintf_s sql fail");
        return SOFTBUS_ERR;
    }
    *isExist = false;
    rc = ExecuteSql(ctx, sql, strlen(sql), NULL, NULL);
    if (rc == SQLITE_ROW && sqlite3_column_count(ctx->stmt) != 0) {
        *isExist = true;
    }
    (void)sqlite3_finalize(ctx->stmt);
    ctx->stmt = NULL;
    return SOFTBUS_OK;
}

int32_t LnnInsertRecord(LnnDbContext *ctx, TableNameID id, uint8_t *data)
{
    int32_t rc;
    if (ctx == NULL || data == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    if (ctx->db == NULL || ctx->stmt != NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid db context state");
        return SOFTBUS_SQLITE_MISUSE;
    }

    rc = ExecuteSql(ctx, g_sqlLedger[id].insertSql, strlen(g_sqlLedger[id].insertSql),
        g_sqlLedger[id].insertBindParaCb, data);
    if (rc != SQLITE_DONE) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "insert data failed");
        rc = SOFTBUS_ERR;
    } else {
        rc = SOFTBUS_OK;
    }
    (void)sqlite3_finalize(ctx->stmt);
    ctx->stmt = NULL;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "insert data done");
    return rc;
}

int32_t LnnRemoveRecordByKey(LnnDbContext *ctx, TableNameID id, uint8_t *data)
{
    int32_t rc;
    if (ctx == NULL || data == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    if (ctx->db == NULL || ctx->stmt != NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid db context state");
        return SOFTBUS_SQLITE_MISUSE;
    }
    rc = ExecuteSql(ctx, g_sqlLedger[id].removeSqlByKey, strlen(g_sqlLedger[id].removeSqlByKey),
        g_sqlLedger[id].removeBindParaCb, data);
    if (rc != SQLITE_DONE) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remove data failed");
        rc = SOFTBUS_ERR;
    } else {
        rc = SOFTBUS_OK;
    }
    (void)sqlite3_finalize(ctx->stmt);
    ctx->stmt = NULL;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "remove data done");
    return rc;
}

int32_t LnnRemoveAllRecord(LnnDbContext *ctx, TableNameID id)
{
    int32_t rc;
    char sql[SOFTBUS_SQL_DEFAULT_LEN] = {0};
    if (ctx == NULL || ctx->db == NULL || ctx->stmt != NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    rc = sprintf_s(sql, SOFTBUS_SQL_DEFAULT_LEN, "%s%s", REMOVE_ALL_RECORD, g_sqlLedger[id].tableName);
    if (rc < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "sprintf_s sql fail");
        return SOFTBUS_ERR;
    }
    rc = ExecuteSql(ctx, sql, strlen(sql), NULL, NULL);
    if (rc != SQLITE_DONE) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remove data failed");
        rc = SOFTBUS_ERR;
    } else {
        rc = SOFTBUS_OK;
    }
    (void)sqlite3_finalize(ctx->stmt);
    ctx->stmt = NULL;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "remove data done");
    return rc;
}

int32_t LnnGetRecordNumByKey(LnnDbContext *ctx, TableNameID id, uint8_t *data)
{
    int32_t rc, num = 0;
    if (ctx == NULL || ctx->db == NULL || ctx->stmt != NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    rc = QueryData(ctx, g_sqlLedger[id].searchSqlByKey, strlen(g_sqlLedger[id].searchSqlByKey),
        g_sqlLedger[id].searchBindParaCb, data);
    if (rc != SQLITE_ROW) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "find no match data");
        return 0;
    }
    do {
        num++;
        rc = QueryDataNext(ctx);
    } while (rc == SQLITE_ROW);
    if (rc != SQLITE_DONE) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetQueryDataNum failed");
        return 0;
    }
    return num;
}

int32_t LnnQueryRecordByKey(LnnDbContext *ctx, TableNameID id, uint8_t *data, uint8_t **replyInfo, int infoNum)
{
    int32_t rc, idx = 0;
    if (ctx == NULL || replyInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    if (ctx->db == NULL || ctx->stmt != NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid db context state");
        return SOFTBUS_SQLITE_MISUSE;
    }
    rc = QueryData(ctx, g_sqlLedger[id].searchSqlByKey, strlen(g_sqlLedger[id].searchSqlByKey),
        g_sqlLedger[id].searchBindParaCb, data);
    if (rc != SQLITE_ROW) {
        return SOFTBUS_ERR;
    }
    do {
        if (g_sqlLedger[id].searchGetParaCb != NULL) {
            g_sqlLedger[id].searchGetParaCb(ctx, *replyInfo, idx);
        }
        rc = QueryDataNext(ctx);
        idx++;
    } while (rc == SQLITE_ROW && idx < infoNum);
    if (rc != SQLITE_DONE) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnQueryData failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnOpenTransaction(LnnDbContext *ctx)
{
    int32_t rc;
    const char *sql = "BEGIN TRANSACTION";
    if (ctx == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    if (ctx->db == NULL || ctx->stmt != NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid db context state");
        return SOFTBUS_SQLITE_MISUSE;
    }
    if ((ctx->state & DB_CONTEXT_STATE_TRANSACTION) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "already open the transaction: %d", ctx->state);
        return SOFTBUS_OK;
    }
    rc = ExecuteSql(ctx, sql, strlen(sql), NULL, NULL);
    if (rc != SQLITE_DONE) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "open transaction failed");
        rc = SOFTBUS_ERR;
    } else {
        ctx->state |= DB_CONTEXT_STATE_TRANSACTION;
        rc = SOFTBUS_OK;
    }
    (void)sqlite3_finalize(ctx->stmt);
    ctx->stmt = NULL;
    return rc;
}

int32_t LnnCloseTransaction(LnnDbContext *ctx, LnnCloseTransactionType type)
{
    int32_t rc;
    const char *sql = "COMMIT TRANSACTION";
    if (ctx == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    if (ctx->db == NULL || ctx->stmt != NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid db context state");
        return SOFTBUS_SQLITE_MISUSE;
    }
    if ((ctx->state & DB_CONTEXT_STATE_TRANSACTION) == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "the transaction already closed: %d", ctx->state);
        return SOFTBUS_OK;
    }

    if (type == CLOSE_TRANS_ROLLBACK) {
        sql = "ROLLBACK TRANSACTION";
    }
    rc = ExecuteSql(ctx, sql, strlen(sql), NULL, NULL);
    if (rc != SQLITE_DONE) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "close transaction failed");
        rc = SOFTBUS_ERR;
    } else {
        rc = SOFTBUS_OK;
    }
    ctx->state &= ~DB_CONTEXT_STATE_TRANSACTION;
    (void)sqlite3_finalize(ctx->stmt);
    ctx->stmt = NULL;
    return rc;
}

int32_t LnnEncryptedDb(LnnDbContext *ctx, const char *password, uint32_t len)
{
    int32_t rc;
    if (ctx == NULL || password == NULL || strlen(password) != len) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    if (ctx->db == NULL || ctx->stmt != NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid db context state");
        return SOFTBUS_SQLITE_MISUSE;
    }
    rc = sqlite3_key(ctx->db, password, len);
    if (rc != SQLITE_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "config key failed: %d", rc);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnUpdateDbPassword(LnnDbContext *ctx, const char *password, uint32_t len)
{
    int32_t rc;
    if (ctx == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    if (ctx->db == NULL || ctx->stmt != NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid db context state");
        return SOFTBUS_SQLITE_MISUSE;
    }
    if (password == NULL || len == 0) {
        rc = sqlite3_rekey(ctx->db, NULL, 0);
    } else {
        rc = sqlite3_rekey(ctx->db, password, len);
    }
    if (rc != SQLITE_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "update key failed: %d", rc);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnBindParaInt(LnnDbContext *ctx, int32_t idx, int32_t value)
{
    int32_t rc;
    if (ctx == NULL || idx <= 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    if (ctx->db == NULL || ctx->stmt == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid db context state");
        return SOFTBUS_SQLITE_MISUSE;
    }
    rc = sqlite3_bind_int(ctx->stmt, idx, value);
    if (rc != SQLITE_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "sqlite3_bind_int failed: %d", rc);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnBindParaInt64(LnnDbContext *ctx, int32_t idx, int64_t value)
{
    int32_t rc;
    if (ctx == NULL || idx <= 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    if (ctx->db == NULL || ctx->stmt == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid db context state");
        return SOFTBUS_SQLITE_MISUSE;
    }
    rc = sqlite3_bind_int64(ctx->stmt, idx, value);
    if (rc != SQLITE_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "sqlite3_bind_int64 failed: %d", rc);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnBindParaText(LnnDbContext *ctx, int32_t idx, const char *value, uint32_t valueLen)
{
    int32_t rc;
    if (ctx == NULL || idx <= 0 || value == NULL || strlen(value) != valueLen) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    if (ctx->db == NULL || ctx->stmt == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid db context state");
        return SOFTBUS_SQLITE_MISUSE;
    }
    rc = sqlite3_bind_text(ctx->stmt, idx, value, valueLen, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "sqlite3_bind_text failed: %d", rc);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnBindParaDouble(LnnDbContext *ctx, int32_t idx, double value)
{
    int32_t rc;
    if (ctx == NULL || idx <= 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    if (ctx->db == NULL || ctx->stmt == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid db context state");
        return SOFTBUS_SQLITE_MISUSE;
    }
    rc = sqlite3_bind_double(ctx->stmt, idx, value);
    if (rc != SQLITE_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "sqlite3_bind_double failed: %d", rc);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnGetQueryResultColCount(LnnDbContext *ctx, int32_t *count)
{
    if (ctx == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    if (ctx->db == NULL || ctx->stmt == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid db context state");
        return SOFTBUS_SQLITE_MISUSE;
    }
    if ((ctx->state & DB_CONTEXT_STATE_QUERYING) == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "the query already closed: %d", ctx->state);
        return SOFTBUS_ERR;
    }
    *count = sqlite3_column_count(ctx->stmt);
    return SOFTBUS_OK;
}

int32_t LnnGetQueryResultColText(LnnDbContext *ctx, int32_t cidx, char *text, uint32_t len)
{
    const unsigned char *result;
    if (ctx == NULL || cidx < 0 || text == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    if (ctx->db == NULL || ctx->stmt == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid db context state");
        return SOFTBUS_SQLITE_MISUSE;
    }
    if ((ctx->state & DB_CONTEXT_STATE_QUERYING) == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "the query already closed: %d", ctx->state);
        return SOFTBUS_ERR;
    }
    if (sqlite3_column_type(ctx->stmt, cidx) != SQLITE_TEXT) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "column type not match");
        return SOFTBUS_ERR;
    }
    result = sqlite3_column_text(ctx->stmt, cidx);
    if (strcpy_s(text, len, (const char *)result) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "strcpy_s fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnGetQueryResultColInt(LnnDbContext *ctx, int32_t cidx, int32_t *value)
{
    if (ctx == NULL || cidx < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    if (ctx->db == NULL || ctx->stmt == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid db context state");
        return SOFTBUS_SQLITE_MISUSE;
    }
    if ((ctx->state & DB_CONTEXT_STATE_QUERYING) == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "the query already closed: %d", ctx->state);
        return SOFTBUS_ERR;
    }
    if (sqlite3_column_type(ctx->stmt, cidx) != SQLITE_INTEGER) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "column type not match");
        return SOFTBUS_ERR;
    }
    *value = sqlite3_column_int(ctx->stmt, cidx);
    return SOFTBUS_OK;
}

int32_t LnnGetQueryResultColInt64(LnnDbContext *ctx, int32_t cidx, int64_t *value)
{
    if (ctx == NULL || cidx < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    if (ctx->db == NULL || ctx->stmt == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid db context state");
        return SOFTBUS_SQLITE_MISUSE;
    }
    if ((ctx->state & DB_CONTEXT_STATE_QUERYING) == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "the query already closed: %d", ctx->state);
        return SOFTBUS_ERR;
    }
    if (sqlite3_column_type(ctx->stmt, cidx) != SQLITE_INTEGER) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "column type not match");
        return SOFTBUS_ERR;
    }
    *value = sqlite3_column_int64(ctx->stmt, cidx);
    return SOFTBUS_OK;
}

int32_t LnnGetQueryResultColDouble(LnnDbContext *ctx, int32_t cidx, double *value)
{
    if (ctx == NULL || cidx < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    if (ctx->db == NULL || ctx->stmt == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid db context state");
        return SOFTBUS_SQLITE_MISUSE;
    }
    if ((ctx->state & DB_CONTEXT_STATE_QUERYING) == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "the query already closed: %d", ctx->state);
        return SOFTBUS_ERR;
    }
    if (sqlite3_column_type(ctx->stmt, cidx) != SQLITE_FLOAT) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "column type not match");
        return SOFTBUS_ERR;
    }
    *value = sqlite3_column_double(ctx->stmt, cidx);
    return SOFTBUS_OK;
}