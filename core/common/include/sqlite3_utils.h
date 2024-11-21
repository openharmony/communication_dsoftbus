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

#ifndef SQLITE3_UTILS_H
#define SQLITE3_UTILS_H

#ifndef _WIN32
#include <sqlite3sym.h>
#else
#include <sqlite3.h>
#endif
#include <stdbool.h>
#include <stdint.h>

#include "softbus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef DEFAULT_STORAGE_PATH
#define DEFAULT_STORAGE_PATH "/data/service/el1/public"
#endif

#define DATABASE_NAME DEFAULT_STORAGE_PATH"/dsoftbus/dsoftbus.db3"
#define LNN_DEFAULT_USERID 100
#define LNN_INT32_NUM_STR_MAX_LEN 11

typedef struct {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    uint32_t state;
} DbContext;

typedef enum {
    TABLE_TRUSTED_DEV_INFO,
    TABLE_NAME_ID_MAX,
} TableNameID;

typedef struct {
    char accountHexHash[SHA_256_HEX_HASH_LEN + LNN_INT32_NUM_STR_MAX_LEN + 1];
    char udid[UDID_BUF_LEN];
    int32_t userId;
} TrustedDevInfoRecord;

typedef enum {
    CLOSE_TRANS_COMMIT = 0,
    CLOSE_TRANS_ROLLBACK
} CloseTransactionType;

/* read supports multithreading, and write only supports single thread {@link LOOP_TYPE_DEFAULT}. */
int32_t OpenDatabase(DbContext **ctx);
int32_t CloseDatabase(DbContext *ctx);

int32_t CreateTable(DbContext *ctx, TableNameID id);
int32_t DeleteTable(DbContext *ctx, TableNameID id);
int32_t CheckTableExist(DbContext *ctx, TableNameID id, bool *isExist);

int32_t InsertRecord(DbContext *ctx, TableNameID id, uint8_t *data);
int32_t RemoveRecordByKey(DbContext *ctx, TableNameID id, uint8_t *data);
int32_t RemoveAllRecord(DbContext *ctx, TableNameID id);
int32_t GetRecordNumByKey(DbContext *ctx, TableNameID id, uint8_t *data);
int32_t QueryRecordByKey(DbContext *ctx, TableNameID id, uint8_t *data, uint8_t **replyInfo, int infoNum);

int32_t OpenTransaction(DbContext *ctx);
int32_t CloseTransaction(DbContext *ctx, CloseTransactionType type);
int32_t EncryptedDb(DbContext *ctx, const uint8_t *password, uint32_t len);
int32_t UpdateDbPassword(DbContext *ctx, const uint8_t *password, uint32_t len);

int32_t BindParaInt(DbContext *ctx, int32_t idx, int32_t value);
int32_t BindParaInt64(DbContext *ctx, int32_t idx, int64_t value);
int32_t BindParaText(DbContext *ctx, int32_t idx, const char *value, uint32_t valueLen);
int32_t BindParaDouble(DbContext *ctx, int32_t idx, double value);

int32_t GetQueryResultColCount(DbContext *ctx, int32_t *count);
int32_t GetQueryResultColText(DbContext *ctx, int32_t cidx, char *text, uint32_t len);
int32_t GetQueryResultColInt(DbContext *ctx, int32_t cidx, int32_t *value);
int32_t GetQueryResultColInt64(DbContext *ctx, int32_t cidx, int64_t *value);
int32_t GetQueryResultColDouble(DbContext *ctx, int32_t cidx, double *value);

#ifdef __cplusplus
}
#endif
#endif