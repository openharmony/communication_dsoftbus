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

#ifndef SOFTBUS_ADAPTER_FILE_H
#define SOFTBUS_ADAPTER_FILE_H

#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define SOFTBUS_PATH_SEPRATOR '/'
#define SOFTBUS_MAX_PATH_LEN 256

/* unistd.h */
#define SOFTBUS_F_OK (0)
#define SOFTBUS_X_OK (1)
#define SOFTBUS_W_OK (2)
#define SOFTBUS_R_OK (4)

/* fcntl.h */
#define SOFTBUS_O_RDONLY (00)
#define SOFTBUS_O_WRONLY (01)
#define SOFTBUS_O_RDWR (02)
#define SOFTBUS_O_CREATE (0100)
#define SOFTBUS_O_TRUNC (01000)

#define SOFTBUS_S_IRUSR (0400)
#define SOFTBUS_S_IWUSR (0200)
#define SOFTBUS_S_IXUSR (0100)
/* File operation */
int32_t SoftBusReadFile(int32_t fd, void *readBuf, uint32_t maxLen);
int32_t SoftBusReadFullFile(const char *fileName, char *readBuf, uint32_t maxLen);
int32_t SoftBusWriteFile(const char *fileName, const char *writeBuf, uint32_t len);
int32_t SoftBusWriteFileFd(int32_t fd, const char *writeBuf, uint32_t len);
int32_t SoftBusOpenFile(const char *fileName, int32_t flags);
int32_t SoftBusOpenFileWithPerms(const char *fileName, int32_t flags, int32_t perms);
void SoftBusRemoveFile(const char *fileName);
void SoftBusCloseFile(int32_t fd);
int64_t SoftBusPreadFile(int32_t fd, void *buf, uint64_t readBytes, uint64_t offset);
int64_t SoftBusPwriteFile(int32_t fd, const void *buf, uint64_t writeBytes, uint64_t offset);
int32_t SoftBusAccessFile(const char *pathName, int32_t mode);
int32_t SoftBusMakeDir(const char *pathName, int32_t mode);
int32_t SoftBusGetFileSize(const char *fileName, uint64_t *fileSize);
char *SoftBusRealPath(const char *path, char *absPath);
int32_t SoftBusReadFullFileAndSize(const char *fileName, char *readBuf, uint32_t maxLen, int32_t *size);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif // SOFTBUS_ADAPTER_FILE_H