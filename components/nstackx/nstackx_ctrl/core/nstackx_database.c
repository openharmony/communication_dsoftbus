/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "nstackx_database.h"
#include <stdint.h>
#include <malloc.h>
#include <string.h>
#include <securec.h>

#include "nstackx_log.h"
#include "nstackx_error.h"

#define TAG "nStackXDFinder"

#define NSTACKX_USEDMAP_ROW_SIZE 32U /* Row size suit for uint32_t */

typedef struct {
    uint8_t *blk;
    uint32_t *usedMap;
    uint32_t mapSize;
    uint32_t useCount;
    uint32_t maxCount;
    size_t recSize;
    RecCompareCallback cb;
} DatabaseInfo;

static inline int64_t GetRecordIndex(const DatabaseInfo *db, const void *rec)
{
    if (db->recSize == 0) {
        return -1;
    }
    return ((uint8_t *)rec - db->blk) / db->recSize;
}

/* Make sure that recNum is valid */
static uint8_t IsRecordOccupied(const DatabaseInfo *db, uint32_t recNum, uint32_t *iptr, uint32_t *offptr)
{
    uint32_t i;
    uint32_t off;

    i = recNum / NSTACKX_USEDMAP_ROW_SIZE;
    off = recNum % NSTACKX_USEDMAP_ROW_SIZE;
    if (iptr != NULL) {
        *iptr = i;
    }
    if (offptr != NULL) {
        *offptr = off;
    }
    if (db->usedMap[i] & (1U << off)) {
        return NSTACKX_TRUE;
    }
    return NSTACKX_FALSE;
}

static inline void *GetRecord(const DatabaseInfo *db, uint32_t index)
{
    return db->blk + (index * db->recSize);
}

void *DatabaseSearchRecord(const void *dbptr, void *ptr)
{
    const DatabaseInfo *db = dbptr;
    void *rec = NULL;
    uint32_t i, j;

    if (dbptr == NULL || ptr == NULL || db->cb == NULL) {
        return NULL;
    }

    for (i = 0; i < db->mapSize; i++) {
        if (!db->usedMap[i]) {
            continue;
        }
        for (j = 0; j < NSTACKX_USEDMAP_ROW_SIZE; j++) {
            if (!(db->usedMap[i] & (1U << j))) {
                continue;
            }
            rec = GetRecord(db, i * NSTACKX_USEDMAP_ROW_SIZE + j);
            if (db->cb(rec, ptr)) {
                return rec;
            }
        }
    }
    return NULL;
}

uint32_t GetDatabaseUseCount(const void *dbptr)
{
    if (dbptr == NULL) {
        return 0;
    }

    return ((const DatabaseInfo *)dbptr)->useCount;
}

void *DatabaseGetNextRecord(void *dbptr, int64_t *idx)
{
    DatabaseInfo *db = dbptr;
    void *rec = NULL;
    uint32_t i;

    if (dbptr == NULL || idx == NULL || *idx >= UINT32_MAX) {
        return NULL;
    }
    if (*idx >= 0) {
        *idx = *idx + 1;
    } else {
        *idx = 0;
    }

    for (i = (uint32_t)(*idx); i < db->maxCount; i++) {
        if (IsRecordOccupied(db, i, NULL, NULL)) {
            rec = GetRecord(db, i);
            *idx = (int64_t)i;
            return rec;
        }
    }
    return NULL;
}

void *DatabaseAllocRecord(void *dbptr)
{
    DatabaseInfo *db = dbptr;
    void *rec = NULL;
    uint32_t i, j;

    if (dbptr == NULL) {
        return NULL;
    }

    if (db->useCount >= db->maxCount) {
        LOGE(TAG, "DB max limit exceeded maxcnt:%u, usecnt:%u", db->maxCount, db->useCount);
        return NULL;
    }

    for (i = 0; i < db->mapSize; i++) {
        if (db->usedMap[i] == ~(uint32_t)0) {
            continue;
        }
        for (j = 0; j < NSTACKX_USEDMAP_ROW_SIZE; j++) {
            if (db->usedMap[i] & (1U << j)) {
                continue;
            }
            rec = GetRecord(db, i * NSTACKX_USEDMAP_ROW_SIZE + j);
            if (memset_s(rec, db->recSize, 0, db->recSize) != EOK) {
                return NULL;
            } else {
                db->usedMap[i] |= (1U << j);
                db->useCount++;
                return rec;
            }
        }
    }
    return NULL;
}

void DatabaseFreeRecord(void *dbptr, const void *ptr)
{
    DatabaseInfo *db = dbptr;
    uint32_t i, off;
    int64_t recNum;

    if (dbptr == NULL || ptr == NULL || db->useCount == 0) {
        LOGE(TAG, "Sanity chk failed");
        return;
    }

    recNum = GetRecordIndex(db, ptr);
    if (recNum < 0 || recNum >= db->maxCount) {
        LOGE(TAG, "Invalid record");
        return;
    }
    if (!IsRecordOccupied(db, (uint32_t)recNum, &i, &off)) {
        LOGE(TAG, "Unused record");
        return;
    }

    db->usedMap[i] &= ~(1U << off);
    db->useCount--;
}

void DatabaseClean(void *ptr)
{
    DatabaseInfo *db = ptr;
    if (db == NULL) {
        return;
    }
    free(db->blk);
    free(db->usedMap);
    free(db);
}

void *DatabaseInit(uint32_t recNumber, size_t recSize, RecCompareCallback cb)
{
    DatabaseInfo *db = NULL;

    if (recNumber == 0 || recSize == 0) {
        return NULL;
    }

    db = (DatabaseInfo *)calloc(1U, sizeof(DatabaseInfo));
    if (db == NULL) {
        LOGE(TAG, "calloc dbinfo failed");
        return NULL;
    }

    db->mapSize = recNumber / NSTACKX_USEDMAP_ROW_SIZE + 1;
    db->usedMap = calloc(db->mapSize, sizeof(uint32_t));
    if (db->usedMap == NULL) {
        LOGE(TAG, "calloc usedmap failed");
        free(db);
        return NULL;
    }

    db->blk = (uint8_t *)malloc(recNumber * recSize);
    if (db->blk == NULL) {
        LOGE(TAG, "malloc %u %zu failed", recNumber, recSize);
        free(db->usedMap);
        free(db);
        return NULL;
    }

    db->maxCount = recNumber;
    db->useCount = 0;
    db->recSize = recSize;
    db->cb = cb;

    return db;
}