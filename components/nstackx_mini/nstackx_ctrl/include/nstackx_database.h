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

#ifndef NSTACKX_DATABASE_H
#define NSTACKX_DATABASE_H

#include <stdio.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef uint8_t (*RecCompareCallback)(void *, void *);

void *DatabaseInit(uint32_t recnum, size_t recsz, RecCompareCallback cb);
void DatabaseClean(void *ptr);
uint32_t GetDatabaseUseCount(const void *dbptr);
void *DatabaseAllocRecord(void *dbptr);
void DatabaseFreeRecord(void *dbptr, const void *ptr);
void *DatabaseSearchRecord(const void *dbptr, void *ptr);
void *DatabaseGetNextRecord(void *dbptr, int64_t *state);

#ifdef __cplusplus
}
#endif
#endif /* #ifndef NSTACKX_DATABASE_H */