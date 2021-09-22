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

#include "nstackx_file_manager.h"
#include "nstackx_log.h"

#define TAG "nStackXDFile"

void FileSync(const FileInfo *fileInfo)
{
    if (fileInfo == NULL || fileInfo->fd == NSTACKX_INVALID_FD) {
        return;
    }
    if (fsync(fileInfo->fd) != 0) {
        LOGE(TAG, "fsync failed. error %d", errno);
    }
}
