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

#include "sqlite3_utils.h"

#include <securec.h>
#include <string.h>
#include <sys/stat.h>

#include "comm_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

#define SQL_DEFAULT_LEN 256

/* The index of database context state */
#define DB_STATE_QUERYING    (0x1)
#define DB_STATE_TRANSACTION (0x1 << 1)

typedef int32_t (*BindParaCb)(DbContext *ctx, int32_t paraNum, uint8_t *data);
typedef int32_t (*QueryDataCb)(DbContext *ctx, uint8_t *data, int32_t idx);

typedef struct {
    const char *tableName;
    const char *sqlForCreate;
    const char *sqlForInsert;
    const char *sqlForSearchByKey;
    const char *sqlForRemoveByKey;
    BindParaCb insertCb;
    BindParaCb searchCb;
    BindParaCb removeCb;
    QueryDataCb queryDataCb;
} SqliteManager;

/* The default SQL statement */
#define SQL_DROP_TABLE            "DROP TABLE "
#define SQL_REMOVE_ALL_RECORD     "DELETE FROM "
#define SQL_BEGIN_TRANSACTION     "BEGIN TRANSACTION"
#define SQL_COMMIT_TRANSACTION    "COMMIT TRANSACTION"
#define SQL_ROLLBACK_TRANSACTION  "ROLLBACK TRANSACTION"
#define SQL_SEARCH_IF_TABLE_EXIST "SELECT * FROM sqlite_master WHERE type ='table' AND name = '%s'"

/**
 * @brief The SQL statement of TrustedDeviceInfo table.
 *
 * This table is used to store the trusted relationship, and its name is TrustedDeviceInfo in {@link DATABASE_NAME}.
 * After each networking, record the udid value according to the device account.
 */
#define TABLE_NAME_OF_TRUSTED_DEV_INFO "TrustedDeviceInfo"
#define SQL_CREATE_TRUSTED_DEV_INFO_TABLE "CREATE TABLE IF NOT EXISTS "TABLE_NAME_OF_TRUSTED_DEV_INFO" \
    (accountHash TEXT NOT NULL, \
    udid TEXT NOT NULL, \
    primary key(accountHash, udid));"
#define SQL_INSERT_TRUSTED_DEV_INFO "INSERT INTO "TABLE_NAME_OF_TRUSTED_DEV_INFO" \
    (accountHash, udid) VALUES (?, ?)"
#define SQL_SEARCH_TRUSTED_DEV_INFO_BY_ID "SELECT udid FROM "TABLE_NAME_OF_TRUSTED_DEV_INFO" \
    WHERE accountHash = ?"
#define SQL_REMOVE_TRUSTED_DEV_INFO_BY_ID "DELETE FROM "TABLE_NAME_OF_TRUSTED_DEV_INFO" \
    WHERE accountHash = ? AND udid = ?"

static int32_t BindInsertTrustedDevInfoCb(DbContext *ctx, int32_t paraNum, uint8_t *data);
static int32_t BindSelectTrustedDevInfoCb(DbContext *ctx, int32_t paraNum, uint8_t *data);
static int32_t GetTrustedDevInfoByIdCb(DbContext *ctx, uint8_t *data, int32_t idx);

static SqliteManager g_sqliteMgr[TABLE_NAME_ID_MAX] = {
    [TABLE_TRUSTED_DEV_INFO] = {
        .tableName = TABLE_NAME_OF_TRUSTED_DEV_INFO,
        .sqlForCreate = SQL_CREATE_TRUSTED_DEV_INFO_TABLE,
        .sqlForInsert = SQL_INSERT_TRUSTED_DEV_INFO,
        .sqlForSearchByKey = SQL_SEARCH_TRUSTED_DEV_INFO_BY_ID,
        .sqlForRemoveByKey = SQL_REMOVE_TRUSTED_DEV_INFO_BY_ID,
        .insertCb = BindInsertTrustedDevInfoCb,
        .searchCb = BindSelectTrustedDevInfoCb,
        .removeCb = BindInsertTrustedDevInfoCb,
        .queryDataCb = GetTrustedDevInfoByIdCb,
    },
};

static int32_t GetTrustedDevInfoByIdCb(DbContext *ctx, uint8_t *data, int32_t idx)
{
    int32_t i = 0;
    char *info = (char *)data + idx * UDID_BUF_LEN;

    if (GetQueryResultColText(ctx, i, info, UDID_BUF_LEN) != SOFTBUS_OK) {
        COMM_LOGE(COMM_UTILS, "get query result failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t BindInsertTrustedDevInfoCb(DbContext *ctx, int32_t paraNum, uint8_t *data)
{
    int32_t rc;
    int32_t idx = 1;

    if (data == NULL) {
        return SQLITE_ERROR;
    }
    const TrustedDevInfoRecord *record = (TrustedDevInfoRecord *)data;
    rc = BindParaText(ctx, idx, record->accountHexHash, strlen(record->accountHexHash));
    if (rc != SQLITE_OK) {
        return rc;
    }
    return BindParaText(ctx, ++idx, record->udid, strlen(record->udid));
}

static int32_t BindSelectTrustedDevInfoCb(DbContext *ctx, int32_t paraNum, uint8_t *data)
{
    int32_t idx = 1;

    if (data == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid param");
        return SQLITE_ERROR;
    }
    return BindParaText(ctx, idx, (char *)data, strlen((char *)data));
}

static int32_t ExecuteSql(DbContext *ctx, const char *sql, uint32_t len, BindParaCb cb, uint8_t *data)
{
    int32_t paraNum;
    int32_t rc;

    if (sql == NULL || sql[0] == '\0') {
        COMM_LOGE(COMM_UTILS, "execute sql get invalid param");
        return SQLITE_ERROR;
    }
    rc = sqlite3_prepare_v2(ctx->db, sql, len, &ctx->stmt, NULL);
    if (rc != SQLITE_OK || ctx->stmt == NULL) {
        COMM_LOGE(COMM_UTILS, "sqlite3_prepare_v2 failed, errmsg=%{public}s", sqlite3_errmsg(ctx->db));
        return sqlite3_errcode(ctx->db);
    }
    paraNum = sqlite3_bind_parameter_count(ctx->stmt);
    if (paraNum <= 0) {
        rc = sqlite3_step(ctx->stmt);
        if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
            COMM_LOGE(COMM_UTILS, "sqlite3_step <= 0 failed, errmsg=%{public}s", sqlite3_errmsg(ctx->db));
        }
        return rc;
    }
    if (cb == NULL) {
        COMM_LOGE(COMM_UTILS, "need cd for binding parameter");
        (void)sqlite3_finalize(ctx->stmt);
        ctx->stmt = NULL;
        return SQLITE_ERROR;
    }
    rc = cb(ctx, paraNum, data);
    if (rc != SQLITE_OK) {
        COMM_LOGE(COMM_UTILS, "binding parameter cd fail");
        (void)sqlite3_finalize(ctx->stmt);
        ctx->stmt = NULL;
        return sqlite3_errcode(ctx->db);
    }
    rc = sqlite3_step(ctx->stmt);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
        COMM_LOGE(COMM_UTILS, "sqlite3_step > 0 failed, errmsg=%{public}s", sqlite3_errmsg(ctx->db));
    }
    return rc;
}

static int32_t QueryData(DbContext *ctx, const char *sql, uint32_t len, BindParaCb cb, uint8_t *data)
{
    int32_t rc;

    rc = ExecuteSql(ctx, sql, len, cb, data);
    if (rc != SQLITE_ROW) {
        (void)sqlite3_finalize(ctx->stmt);
        ctx->stmt = NULL;
    } else {
        ctx->state |= DB_STATE_QUERYING;
    }
    COMM_LOGD(COMM_UTILS, "QueryData done, state=%{public}d", ctx->state);
    return rc;
}

static int32_t QueryDataNext(DbContext *ctx)
{
    int32_t rc;

    rc = sqlite3_step(ctx->stmt);
    if (rc != SQLITE_ROW) {
        ctx->state &= ~DB_STATE_QUERYING;
        (void)sqlite3_finalize(ctx->stmt);
        ctx->stmt = NULL;
    }
    COMM_LOGD(COMM_UTILS, "QueryDataNext done, state=%{public}d", ctx->state);
    return rc;
}

static bool CheckDbContextParam(const DbContext *ctx)
{
    if (ctx == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid parameters");
        return false;
    }
    if (ctx->db == NULL || ctx->stmt != NULL) {
        COMM_LOGE(COMM_UTILS, "invalid db context state");
        return false;
    }
    return true;
}

static bool CheckBindOrQueryParam(const DbContext *ctx)
{
    if (ctx == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid db context parameters");
        return false;
    }
    if (ctx->db == NULL || ctx->stmt == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid db context state");
        return false;
    }
    return true;
}

int32_t OpenDatabase(DbContext **ctx)
{
    int32_t rc;
    sqlite3 *sqlite = NULL;

    if (ctx == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    mode_t mode = S_IRUSR | S_IWUSR;
    rc =
        sqlite3_open_v2(DATABASE_NAME, &sqlite, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX, NULL);
    if (rc != SQLITE_OK || sqlite == NULL || chmod(DATABASE_NAME, mode) != SOFTBUS_OK) {
        COMM_LOGE(COMM_UTILS, "sqlite3_open_v2 fail: errmsg=%{public}s", sqlite3_errmsg(sqlite));
        (void)sqlite3_close_v2(sqlite);
        return SOFTBUS_ERR;
    }
    *ctx = (DbContext *)SoftBusCalloc(sizeof(DbContext));
    if (*ctx == NULL) {
        COMM_LOGE(COMM_UTILS, "malloc DbContext fail");
        (void)sqlite3_close_v2(sqlite);
        return SOFTBUS_MALLOC_ERR;
    } else {
        (*ctx)->db = sqlite;
    }
    return SOFTBUS_OK;
}

int32_t CloseDatabase(DbContext *ctx)
{
    if (!CheckDbContextParam(ctx)) {
        COMM_LOGE(COMM_UTILS, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    (void)sqlite3_close_v2(ctx->db);
    SoftBusFree(ctx);
    return SOFTBUS_OK;
}

int32_t CreateTable(DbContext *ctx, TableNameID id)
{
    int32_t rc;
    char *errMsg = NULL;

    if (!CheckDbContextParam(ctx)) {
        COMM_LOGE(COMM_UTILS, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    const char *sql = g_sqliteMgr[id].sqlForCreate;
    if (sql == NULL || sql[0] == '\0') {
        COMM_LOGE(COMM_UTILS, "createsql is not impl");
        return SOFTBUS_ERR;
    }
    rc = sqlite3_exec(ctx->db, sql, NULL, NULL, &errMsg);
    if (rc != SQLITE_OK && errMsg != NULL) {
        COMM_LOGE(COMM_UTILS, "sqlite_exec fail: errmsg=%{public}s", errMsg);
        sqlite3_free(errMsg);
    }
    return rc == SQLITE_OK ? SOFTBUS_OK : SOFTBUS_SQLITE_ERR;
}

int32_t DeleteTable(DbContext *ctx, TableNameID id)
{
    int32_t rc;
    char sql[SQL_DEFAULT_LEN] = { 0 };

    if (!CheckDbContextParam(ctx)) {
        COMM_LOGE(COMM_UTILS, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    rc = sprintf_s(sql, SQL_DEFAULT_LEN, "%s%s", SQL_DROP_TABLE, g_sqliteMgr[id].tableName);
    if (rc < 0) {
        COMM_LOGE(COMM_UTILS, "sprintf_s sql fail");
        return SOFTBUS_ERR;
    }
    rc = ExecuteSql(ctx, sql, strlen(sql), NULL, NULL);
    if (rc != SQLITE_DONE) {
        COMM_LOGE(COMM_UTILS, "delete table fail");
        rc = SOFTBUS_ERR;
    } else {
        rc = SOFTBUS_OK;
    }
    (void)sqlite3_finalize(ctx->stmt);
    ctx->stmt = NULL;
    return rc;
}

int32_t CheckTableExist(DbContext *ctx, TableNameID id, bool *isExist)
{
    int32_t rc;
    char sql[SQL_DEFAULT_LEN] = { 0 };

    if (!CheckDbContextParam(ctx) || isExist == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    rc = sprintf_s(sql, SQL_DEFAULT_LEN, SQL_SEARCH_IF_TABLE_EXIST, g_sqliteMgr[id].tableName);
    if (rc < 0) {
        COMM_LOGE(COMM_UTILS, "sprintf_s sql fail");
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

int32_t InsertRecord(DbContext *ctx, TableNameID id, uint8_t *data)
{
    int32_t rc;

    if (!CheckDbContextParam(ctx) || data == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    rc = ExecuteSql(
        ctx, g_sqliteMgr[id].sqlForInsert, strlen(g_sqliteMgr[id].sqlForInsert), g_sqliteMgr[id].insertCb, data);
    if (rc != SQLITE_DONE) {
        COMM_LOGE(COMM_UTILS, "insert data failed");
        rc = SOFTBUS_ERR;
    } else {
        rc = SOFTBUS_OK;
    }
    (void)sqlite3_finalize(ctx->stmt);
    ctx->stmt = NULL;
    COMM_LOGD(COMM_UTILS, "insert data done");
    return rc;
}

int32_t RemoveRecordByKey(DbContext *ctx, TableNameID id, uint8_t *data)
{
    int32_t rc;

    if (!CheckDbContextParam(ctx) || data == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    rc = ExecuteSql(ctx, g_sqliteMgr[id].sqlForRemoveByKey, strlen(g_sqliteMgr[id].sqlForRemoveByKey),
        g_sqliteMgr[id].removeCb, data);
    if (rc != SQLITE_DONE) {
        COMM_LOGE(COMM_UTILS, "remove data failed");
        rc = SOFTBUS_ERR;
    } else {
        rc = SOFTBUS_OK;
    }
    (void)sqlite3_finalize(ctx->stmt);
    ctx->stmt = NULL;
    COMM_LOGD(COMM_UTILS, "remove data done");
    return rc;
}

int32_t RemoveAllRecord(DbContext *ctx, TableNameID id)
{
    int32_t rc;
    char sql[SQL_DEFAULT_LEN] = { 0 };

    if (!CheckDbContextParam(ctx)) {
        COMM_LOGE(COMM_UTILS, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    rc = sprintf_s(sql, SQL_DEFAULT_LEN, "%s%s", SQL_REMOVE_ALL_RECORD, g_sqliteMgr[id].tableName);
    if (rc < 0) {
        COMM_LOGE(COMM_UTILS, "sprintf_s sql fail");
        return SOFTBUS_ERR;
    }
    rc = ExecuteSql(ctx, sql, strlen(sql), NULL, NULL);
    if (rc != SQLITE_DONE) {
        COMM_LOGE(COMM_UTILS, "remove data failed");
        rc = SOFTBUS_ERR;
    } else {
        rc = SOFTBUS_OK;
    }
    (void)sqlite3_finalize(ctx->stmt);
    ctx->stmt = NULL;
    COMM_LOGD(COMM_UTILS, "remove data done");
    return rc;
}

int32_t GetRecordNumByKey(DbContext *ctx, TableNameID id, uint8_t *data)
{
    int32_t rc;
    int32_t num = 0;

    if (!CheckDbContextParam(ctx) || data == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid parameters");
        return 0;
    }
    rc = QueryData(ctx, g_sqliteMgr[id].sqlForSearchByKey, strlen(g_sqliteMgr[id].sqlForSearchByKey),
        g_sqliteMgr[id].searchCb, data);
    if (rc != SQLITE_ROW) {
        COMM_LOGE(COMM_UTILS, "find no match data");
        return 0;
    }
    do {
        num++;
        rc = QueryDataNext(ctx);
    } while (rc == SQLITE_ROW);
    if (rc != SQLITE_DONE) {
        COMM_LOGE(COMM_UTILS, "GetQueryDataNum failed");
        return 0;
    }
    return num;
}

int32_t QueryRecordByKey(DbContext *ctx, TableNameID id, uint8_t *data,
    uint8_t **replyInfo, int32_t infoNum)
{
    int32_t rc;
    int32_t num = 0;

    if (!CheckDbContextParam(ctx) || replyInfo == NULL || data == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    rc = QueryData(ctx, g_sqliteMgr[id].sqlForSearchByKey, strlen(g_sqliteMgr[id].sqlForSearchByKey),
        g_sqliteMgr[id].searchCb, data);
    if (rc != SQLITE_ROW) {
        return SOFTBUS_ERR;
    }
    do {
        if (g_sqliteMgr[id].queryDataCb != NULL) {
            g_sqliteMgr[id].queryDataCb(ctx, *replyInfo, num);
        }
        rc = QueryDataNext(ctx);
        num++;
    } while (rc == SQLITE_ROW && num < infoNum);
    if (rc != SQLITE_DONE) {
        if (rc == SQLITE_ROW) {
            ctx->state &= ~DB_STATE_QUERYING;
            (void)sqlite3_finalize(ctx->stmt);
            ctx->stmt = NULL;
        }
        COMM_LOGE(COMM_UTILS, "QueryData failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t OpenTransaction(DbContext *ctx)
{
    int32_t rc;

    if (!CheckDbContextParam(ctx)) {
        COMM_LOGE(COMM_UTILS, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    if ((ctx->state & DB_STATE_TRANSACTION) != 0) {
        COMM_LOGE(COMM_UTILS, "already open the transaction: state=%{public}d", ctx->state);
        return SOFTBUS_OK;
    }
    rc = ExecuteSql(ctx, SQL_BEGIN_TRANSACTION, strlen(SQL_BEGIN_TRANSACTION), NULL, NULL);
    if (rc != SQLITE_DONE) {
        COMM_LOGE(COMM_UTILS, "open transaction failed");
        rc = SOFTBUS_ERR;
    } else {
        ctx->state |= DB_STATE_TRANSACTION;
        rc = SOFTBUS_OK;
    }
    (void)sqlite3_finalize(ctx->stmt);
    ctx->stmt = NULL;
    return rc;
}

int32_t CloseTransaction(DbContext *ctx, CloseTransactionType type)
{
    int32_t rc;
    const char *sql = SQL_COMMIT_TRANSACTION;

    if (!CheckDbContextParam(ctx)) {
        COMM_LOGE(COMM_UTILS, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    if ((ctx->state & DB_STATE_TRANSACTION) == 0) {
        COMM_LOGE(COMM_UTILS, "the transaction already closed: state=%{public}d", ctx->state);
        return SOFTBUS_OK;
    }
    if (type == CLOSE_TRANS_ROLLBACK) {
        sql = SQL_ROLLBACK_TRANSACTION;
    }
    rc = ExecuteSql(ctx, sql, strlen(sql), NULL, NULL);
    if (rc != SQLITE_DONE) {
        COMM_LOGE(COMM_UTILS, "close transaction failed");
        rc = SOFTBUS_ERR;
    } else {
        rc = SOFTBUS_OK;
    }
    ctx->state &= ~DB_STATE_TRANSACTION;
    (void)sqlite3_finalize(ctx->stmt);
    ctx->stmt = NULL;
    return rc;
}

int32_t EncryptedDb(DbContext *ctx, const uint8_t *password, uint32_t len)
{
    int32_t rc;

    if (!CheckDbContextParam(ctx) || password == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    rc = sqlite3_key(ctx->db, password, len);
    if (rc != SQLITE_OK) {
        COMM_LOGE(COMM_UTILS, "config key failed: errmsg=%{public}s", sqlite3_errmsg(ctx->db));
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t UpdateDbPassword(DbContext *ctx, const uint8_t *password, uint32_t len)
{
    int32_t rc;

    if (!CheckDbContextParam(ctx) || password == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    rc = sqlite3_rekey(ctx->db, password, len);
    if (rc != SQLITE_OK) {
        COMM_LOGE(COMM_UTILS, "update key failed: errmsg=%{public}s", sqlite3_errmsg(ctx->db));
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t BindParaInt(DbContext *ctx, int32_t idx, int32_t value)
{
    int32_t rc;

    if (!CheckBindOrQueryParam(ctx) || idx <= 0) {
        COMM_LOGE(COMM_UTILS, "invalid parameters");
        return SQLITE_ERROR;
    }
    rc = sqlite3_bind_int(ctx->stmt, idx, value);
    if (rc != SQLITE_OK) {
        COMM_LOGE(COMM_UTILS, "sqlite3_bind_int failed: errmsg=%{public}s", sqlite3_errmsg(ctx->db));
    }
    return rc;
}

int32_t BindParaInt64(DbContext *ctx, int32_t idx, int64_t value)
{
    int32_t rc;

    if (!CheckBindOrQueryParam(ctx) || idx <= 0) {
        COMM_LOGE(COMM_UTILS, "invalid parameters");
        return SQLITE_ERROR;
    }
    rc = sqlite3_bind_int64(ctx->stmt, idx, value);
    if (rc != SQLITE_OK) {
        COMM_LOGE(COMM_UTILS, "sqlite3_bind_int64 failed: errmsg=%{public}s", sqlite3_errmsg(ctx->db));
    }
    return rc;
}

int32_t BindParaText(DbContext *ctx, int32_t idx, const char *value, uint32_t valueLen)
{
    int32_t rc;

    if (!CheckBindOrQueryParam(ctx) || idx <= 0 || value == NULL || value[0] == '\0' || strlen(value) != valueLen) {
        COMM_LOGE(COMM_UTILS, "invalid parameters");
        return SQLITE_ERROR;
    }
    rc = sqlite3_bind_text(ctx->stmt, idx, value, valueLen, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        COMM_LOGE(COMM_UTILS, "sqlite3_bind_text failed: errmsg=%{public}s", sqlite3_errmsg(ctx->db));
    }
    return rc;
}

int32_t BindParaDouble(DbContext *ctx, int32_t idx, double value)
{
    int32_t rc;

    if (!CheckBindOrQueryParam(ctx) || idx <= 0) {
        COMM_LOGE(COMM_UTILS, "invalid parameters");
        return SQLITE_ERROR;
    }
    rc = sqlite3_bind_double(ctx->stmt, idx, value);
    if (rc != SQLITE_OK) {
        COMM_LOGE(COMM_UTILS, "sqlite3_bind_double failed: errmsg=%{public}s", sqlite3_errmsg(ctx->db));
    }
    return rc;
}

int32_t GetQueryResultColCount(DbContext *ctx, int32_t *count)
{
    if (!CheckBindOrQueryParam(ctx)) {
        COMM_LOGE(COMM_UTILS, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    if ((ctx->state & DB_STATE_QUERYING) == 0) {
        COMM_LOGE(COMM_UTILS, "the query already closed: state=%{public}d", ctx->state);
        return SOFTBUS_ERR;
    }
    *count = sqlite3_column_count(ctx->stmt);
    return SOFTBUS_OK;
}

int32_t GetQueryResultColText(DbContext *ctx, int32_t iCol, char *text, uint32_t len)
{
    const unsigned char *result;

    if (!CheckBindOrQueryParam(ctx) || iCol < 0 || text == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    if ((ctx->state & DB_STATE_QUERYING) == 0) {
        COMM_LOGE(COMM_UTILS, "the query already closed: state=%{public}d", ctx->state);
        return SOFTBUS_ERR;
    }
    if (sqlite3_column_type(ctx->stmt, iCol) != SQLITE_TEXT) {
        COMM_LOGE(COMM_UTILS, "column type not match");
        return SOFTBUS_ERR;
    }
    result = sqlite3_column_text(ctx->stmt, iCol);
    if (strcpy_s(text, len, (const char *)result) != EOK) {
        COMM_LOGE(COMM_UTILS, "strcpy_s fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t GetQueryResultColInt(DbContext *ctx, int32_t iCol, int32_t *value)
{
    if (!CheckBindOrQueryParam(ctx) || iCol < 0 || value == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    if ((ctx->state & DB_STATE_QUERYING) == 0) {
        COMM_LOGE(COMM_UTILS, "the query already closed: state=%{public}d", ctx->state);
        return SOFTBUS_ERR;
    }
    if (sqlite3_column_type(ctx->stmt, iCol) != SQLITE_INTEGER) {
        COMM_LOGE(COMM_UTILS, "column type not match");
        return SOFTBUS_ERR;
    }
    *value = sqlite3_column_int(ctx->stmt, iCol);
    return SOFTBUS_OK;
}

int32_t GetQueryResultColInt64(DbContext *ctx, int32_t iCol, int64_t *value)
{
    if (!CheckBindOrQueryParam(ctx) || iCol < 0 || value == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    if ((ctx->state & DB_STATE_QUERYING) == 0) {
        COMM_LOGE(COMM_UTILS, "the query already closed: state=%{public}d", ctx->state);
        return SOFTBUS_ERR;
    }
    if (sqlite3_column_type(ctx->stmt, iCol) != SQLITE_INTEGER) {
        COMM_LOGE(COMM_UTILS, "column type not match");
        return SOFTBUS_ERR;
    }
    *value = sqlite3_column_int64(ctx->stmt, iCol);
    return SOFTBUS_OK;
}

int32_t GetQueryResultColDouble(DbContext *ctx, int32_t iCol, double *value)
{
    if (!CheckBindOrQueryParam(ctx) || iCol < 0 || value == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    if ((ctx->state & DB_STATE_QUERYING) == 0) {
        COMM_LOGE(COMM_UTILS, "the query already closed: state=%{public}d", ctx->state);
        return SOFTBUS_ERR;
    }
    if (sqlite3_column_type(ctx->stmt, iCol) != SQLITE_FLOAT) {
        COMM_LOGE(COMM_UTILS, "column type not match");
        return SOFTBUS_ERR;
    }
    *value = sqlite3_column_double(ctx->stmt, iCol);
    return SOFTBUS_OK;
}
