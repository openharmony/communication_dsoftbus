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

#ifndef NSTACKX_FILE_MANAGER_CLIENT_H
#define NSTACKX_FILE_MANAGER_CLIENT_H

#include "nstackx_file_manager.h"
#include "nstackx_list.h"

#ifdef __cplusplus
extern "C" {
#endif

void SendTaskProcess(FileManager *fileManager, FileListTask *fileList);

void ClearSendFileList(FileManager *fileManager, FileListTask *fileList);

int32_t InitSendBlockLists(FileManager *fileManager);

uint32_t GetMaxSendListSize(uint16_t connType);

uint16_t GetSendListNum(void);

void ClearSendFrameList(FileManager *fileManager);

#ifdef __cplusplus
}
#endif

#endif
