/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef CLIENT_TRANS_PROXY_FILE_COMMON_H
#define CLIENT_TRANS_PROXY_FILE_COMMON_H

#include <stdint.h>

#define MAX_FILE_PATH_NAME_LEN 512
#define INVALID_FD (-1)

#define SOFTBUS_F_RDLCK 0
#define SOFTBUS_F_WRLCK 1

#define BYTE_INT_NUM 4
#define BIT_INT_NUM 32
#define BIT_BYTE_NUM 8

#define FRAME_NUM_0 0
#define FRAME_NUM_1 1
#define FRAME_NUM_2 2

#define OH_TYPE 10
#define PATH_SEPARATOR '/'

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t *buffer;
    uint32_t bufferSize;
} FileListBuffer;

bool IsPathValid(char *filePath);
int32_t GetAndCheckRealPath(const char *filePath, char *absPath);
bool CheckDestFilePathValid(const char *destFile);
int32_t FrameIndexToType(uint64_t index, uint64_t frameNumber);

char *BufferToFileList(uint8_t *buffer, uint32_t bufferSize, int32_t *fileCount);
int32_t FileListToBuffer(const char **destFile, uint32_t fileCnt, FileListBuffer *outbufferInfo);

const char* TransGetFileName(const char* path);

uint16_t RTU_CRC(const unsigned char *puchMsg, uint16_t usDataLen);

int32_t FileLock(int32_t fd, int32_t type, bool isBlock);
int32_t TryFileLock(int32_t fd, int32_t type, int32_t retryTimes);
int32_t FileUnLock(int32_t fd);

#ifdef __cplusplus
}
#endif
#endif // CLIENT_TRANS_PROXY_FILE_COMMON_H
