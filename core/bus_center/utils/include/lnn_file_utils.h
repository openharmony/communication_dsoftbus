/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef LNN_FILE_UTILS_H
#define LNN_FILE_UTILS_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    LNN_FILE_ID_UUID,
    LNN_FILE_ID_DB_KEY,
    LNN_FILE_ID_LOCAL_DEVICE,
    LNN_FILE_ID_REMOTE_DEVICE,
    LNN_FILE_ID_COMM_KEY,
    LNN_FILE_ID_BROADCAST_KEY,
    LNN_FILE_ID_PTK_KEY,
    LNN_FILE_ID_IRK_KEY,
    LNN_FILE_ID_BROADCAST_CIPHER,
    LNN_FILE_ID_MAX
} LnnFileId;

int32_t LnnGetFullStoragePath(LnnFileId id, char *path, uint32_t len);

#ifdef __cplusplus
}
#endif
#endif /* LNN_FILE_UTILS_H */
