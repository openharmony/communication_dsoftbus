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

#ifndef LNN_SQLITE3_UTILS_H
#define LNN_SQLITE3_UTILS_H

#include <sqlite3sym.h>
#include <stdbool.h>
#include <stdint.h>

#include "softbus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define USER_ID_MAX_LEN 256

typedef struct {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int32_t state;
} LnnDbContext;

typedef enum {
    TABLE_TRUST_DEVICE_INFO,
    TABLE_NAME_ID_MAX,
} TableNameID;

typedef struct {
    char userID[USER_ID_MAX_LEN];
    char deviceHash[UDID_BUF_LEN];
} LnnTrustDeviceInfoRecord;

typedef enum {
    CLOSE_TRANS_COMMIT = 0,
    CLOSE_TRANS_ROLLBACK
} LnnCloseTransactionType;

int32_t LnnOpenDatabase(LnnDbContext **ctx);
int32_t LnnCloseDatabase(LnnDbContext *ctx);
int32_t LnnCreateTable(LnnDbContext *ctx, TableNameID id);
int32_t LnnDeleteTable(LnnDbContext *ctx, TableNameID id);
int32_t LnnCheckTableExist(LnnDbContext *ctx, TableNameID id, bool *isExist);

int32_t LnnInsertRecord(LnnDbContext *ctx, TableNameID id, uint8_t *data);
int32_t LnnRemoveRecordByKey(LnnDbContext *ctx, TableNameID id, uint8_t *data);
int32_t LnnRemoveAllRecord(LnnDbContext *ctx, TableNameID id);
int32_t LnnGetRecordNumByKey(LnnDbContext *ctx, TableNameID id, uint8_t *data);
int32_t LnnQueryRecordByKey(LnnDbContext *ctx, TableNameID id, uint8_t *data, uint8_t **replyInfo, int infoNum);

int32_t LnnOpenTransaction(LnnDbContext *ctx);
int32_t LnnCloseTransaction(LnnDbContext *ctx, LnnCloseTransactionType type);
int32_t LnnEncryptedDb(LnnDbContext *ctx, const char *password, uint32_t len);
int32_t LnnUpdateDbPassword(LnnDbContext *ctx, const char *password, uint32_t len);

int32_t LnnBindParaInt(LnnDbContext *ctx, int32_t idx, int32_t value);
int32_t LnnBindParaInt64(LnnDbContext *ctx, int32_t idx, int64_t value);
int32_t LnnBindParaText(LnnDbContext *ctx, int32_t idx, const char *value, uint32_t valueLen);
int32_t LnnBindParaDouble(LnnDbContext *ctx, int32_t idx, double value);

int32_t LnnGetQueryResultColCount(LnnDbContext *ctx, int32_t *count);
int32_t LnnGetQueryResultColText(LnnDbContext *ctx, int32_t cidx, char *text, uint32_t len);
int32_t LnnGetQueryResultColInt(LnnDbContext *ctx, int32_t cidx, int32_t *value);
int32_t LnnGetQueryResultColInt64(LnnDbContext *ctx, int32_t cidx, int64_t *value);
int32_t LnnGetQueryResultColDouble(LnnDbContext *ctx, int32_t cidx, double *value);

#ifdef __cplusplus
}
#endif
#endif