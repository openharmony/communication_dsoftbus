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
    LNN_FILE_ID_MAX
} LnnFileId;

typedef struct {
    LnnFileId fileId;
    const char *filePath;
} LnnFilePath;

#define LNN_PATH_SEPRATOR '/'
#define LNN_MAX_DIR_PATH_LEN 256

int32_t LnnFileCreate(LnnFileId id);
int32_t LnnFileOpen(LnnFileId id);
int32_t LnnFileClose(int32_t fd);

int32_t LnnFileRead(int32_t fd, uint8_t *dst, uint32_t len, bool needReadAll);
int32_t LnnFileWrite(int32_t fd, const uint8_t *src, uint32_t len, bool needWriteAll);

#ifdef __cplusplus
}
#endif
#endif /* LNN_FILE_UTILS_H */
