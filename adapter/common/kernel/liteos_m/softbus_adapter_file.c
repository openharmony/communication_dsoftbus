/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "softbus_adapter_file.h"

#include "cmsis_os2.h"
#include "comm_log.h"
#include "softbus_adapter_errcode.h"
#include "softbus_error_code.h"
#include "utils_file.h"

int32_t SoftBusReadFile(int32_t fd, void *readBuf, uint32_t maxLen)
{
    (void)fd;
    (void)readBuf;
    (void)maxLen;
    return -1;
}

int32_t SoftBusReadFullFile(const char *fileName, char *readBuf, uint32_t maxLen)
{
    if (fileName == NULL || readBuf == NULL || maxLen == 0) {
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t fileLen = 0;
    int32_t fd = UtilsFileOpen(fileName, O_RDONLY_FS, 0);
    if (fd < 0) {
        COMM_LOGE(COMM_ADAPTER, "Read UtilsFileOpen fail");
        return SOFTBUS_FILE_ERR;
    }
    int32_t ret = UtilsFileStat(fileName, &fileLen);
    if (ret < 0) {
        COMM_LOGE(COMM_ADAPTER, "Read UtilsFileStat fail, ret=%{public}d", ret);
        UtilsFileClose(fd);
        return SOFTBUS_FILE_ERR;
    }
    ret = UtilsFileSeek(fd, 0, SEEK_SET_FS);
    if (ret < 0) {
        COMM_LOGE(COMM_ADAPTER, "Read UtilsFileSeek fail, ret=%{public}d", ret);
        UtilsFileClose(fd);
        return SOFTBUS_FILE_ERR;
    }
    if (fileLen > maxLen) {
        COMM_LOGE(COMM_ADAPTER, "Read file len not legal, clear buf");
        UtilsFileClose(fd);
        return SOFTBUS_FILE_ERR;
    }
    ret = UtilsFileRead(fd, readBuf, maxLen);
    if (ret < 0) {
        COMM_LOGE(COMM_ADAPTER, "Read UtilsFileRead, ret=%{public}d", ret);
        UtilsFileClose(fd);
        return SOFTBUS_FILE_ERR;
    }
    UtilsFileClose(fd);
    return SOFTBUS_OK;
}

int32_t SoftBusWriteFile(const char *fileName, const char *writeBuf, uint32_t len)
{
    if (fileName == NULL || writeBuf == NULL) {
        COMM_LOGE(COMM_ADAPTER, "param is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret;
    int32_t fd;
    fd = UtilsFileOpen(fileName, O_RDWR_FS | O_CREAT_FS | O_TRUNC_FS, 0);
    if (fd < 0) {
        COMM_LOGE(COMM_ADAPTER, "UtilsFileOpen fail");
        return SOFTBUS_FILE_ERR;
    }
    ret = UtilsFileWrite(fd, writeBuf, len);
    if (ret != (int32_t)len) {
        COMM_LOGE(COMM_ADAPTER, "UtilsFileWrite fail, ret=%{public}d", ret);
        UtilsFileClose(fd);
        return SOFTBUS_FILE_ERR;
    }
    UtilsFileClose(fd);
    return SOFTBUS_OK;
}

int32_t SoftBusWriteFileFd(int32_t fd, const char *writeBuf, uint32_t len)
{
    (void)fd;
    (void)writeBuf;
    (void)len;
    return SOFTBUS_INVALID_FD;
}

int32_t SoftBusOpenFile(const char *fileName, int32_t flags)
{
    (void)fileName;
    (void)flags;
    return SOFTBUS_INVALID_FD;
}

int32_t SoftBusOpenFileWithPerms(const char *fileName, int32_t flags, int32_t perms)
{
    (void)fileName;
    (void)flags;
    (void)perms;
    return SOFTBUS_INVALID_FD;
}

void SoftBusRemoveFile(const char *fileName)
{
    (void)fileName;
}

void SoftBusCloseFile(int32_t fd)
{
    (void)fd;
}

int64_t SoftBusPreadFile(int32_t fd, void *buf, uint64_t readBytes, uint64_t offset)
{
    (void)fd;
    (void)buf;
    (void)readBytes;
    (void)offset;
    return -1;
}

int64_t SoftBusPwriteFile(int32_t fd, const void *buf, uint64_t writeBytes, uint64_t offset)
{
    (void)fd;
    (void)buf;
    (void)writeBytes;
    (void)offset;
    return -1;
}

int32_t SoftBusAccessFile(const char *pathName, int32_t mode)
{
    (void)pathName;
    (void)mode;
    return SOFTBUS_ERR;
}

int32_t SoftBusMakeDir(const char *pathName, int32_t mode)
{
    (void)pathName;
    (void)mode;
    return SOFTBUS_ADAPTER_ERR;
}
int32_t SoftBusGetFileSize(const char *fileName, uint64_t *fileSize)
{
    (void)fileName;
    (void)fileSize;
    return SOFTBUS_ERR;
}

char *SoftBusRealPath(const char *path, char *absPath)
{
    (void)path;
    (void)absPath;
    return NULL;
}
