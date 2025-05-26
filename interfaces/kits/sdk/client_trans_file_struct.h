/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef CLIENT_TRANS_FILE_STRUCT_H
#define CLIENT_TRANS_FILE_STRUCT_H

#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SCHEMASEPARATORLENGTH 2
#define SCHEMA_MAX_LENGTH 32

typedef struct {
    const char name[SCHEMA_MAX_LENGTH];
    int (*OpenFd)(const char *filename, int32_t flag, int32_t mode);
    int (*CloseFd)(int32_t fd);
    int (*RemoveFd)(const char *pathName);
} FileSchema;

typedef struct {
    ListNode node;
    char mySessionName[SESSION_NAME_SIZE_MAX];
    FileSchema schema;
} FileSchemaListener;

#ifdef __cplusplus
}
#endif
#endif // CLIENT_TRANS_FILE_STRUCT_H