/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_ADAPTER_JSON_H
#define SOFTBUS_ADAPTER_JSON_H

#include <stdio.h>
#include <stdbool.h>
#include "stdint.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct {
    void *context;
} JsonObj;

JsonObj *JSON_CreateObject(void);

void JSON_Delete(JsonObj *obj);

void JSON_Free(void *obj);

/* Note: must use JSON_Free to release memory */
char *JSON_PrintUnformatted(const JsonObj *obj);

JsonObj *JSON_Parse(const char *str, uint32_t len);

bool JSON_AddBoolToObject(JsonObj *obj, const char *key, bool value);

bool JSON_GetBoolFromOject(const JsonObj *obj, const char *key, bool *value);

bool JSON_AddInt16ToObject(JsonObj *obj, const char *key, int16_t value);

bool JSON_GetInt16FromOject(const JsonObj *obj, const char *key, int16_t *value);

bool JSON_AddInt32ToObject(JsonObj *obj, const char *key, int32_t value);

bool JSON_GetInt32FromOject(const JsonObj *obj, const char *key, int32_t *value);

bool JSON_AddInt64ToObject(JsonObj *obj, const char *key, int64_t value);

bool JSON_GetInt64FromOject(const JsonObj *obj, const char *key, int64_t *value);

bool JSON_AddStringToObject(JsonObj *obj, const char *key, const char *value);

bool JSON_GetStringFromOject(const JsonObj *obj, const char *key, char *value, uint32_t size);

bool JSON_AddStringArrayToObject(JsonObj *obj, const char *key, const char **value, int32_t len);

/* use input parameter len to limit value's max array num and return as real value's max array num */
bool JSON_GetStringArrayFromOject(const JsonObj *obj, const char *key, char **value, int32_t *len);

bool JSON_AddBytesToObject(JsonObj *obj, const char *key, uint8_t *value, uint32_t size);

bool JSON_GetBytesFromObject(const JsonObj *obj, const char *key, uint8_t *value, uint32_t bufLen, uint32_t *size);

bool JSON_IsArrayExist(const JsonObj *obj, const char *key);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif // SOFTBUS_ADAPTER_JSON_H