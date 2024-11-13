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

#include <errno.h>
#include <fcntl.h>
#include <securec.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "comm_log.h"
#include "softbus_adapter_errcode.h"
#include "softbus_error_code.h"

static int32_t SoftBusCreateFile(const char *fileName)
{
    if (fileName == NULL) {
        return SOFTBUS_FILE_ERR;
    }
    char dirPath[SOFTBUS_MAX_PATH_LEN] = {0};

    char *dir = (char *)fileName;
    while ((dir = strchr(dir, SOFTBUS_PATH_SEPRATOR)) != NULL) {
        uint32_t len = (uint32_t)(dir - fileName);
        if (len == 0) { // skip root
            dir++;
            continue;
        }
        if (memcpy_s(dirPath, sizeof(dirPath), fileName, len) != EOK) {
            COMM_LOGE(COMM_ADAPTER, "memory copy dir name failed");
            return SOFTBUS_ERR;
        }
        dirPath[len] = 0;
        if (access(dirPath, F_OK) != 0) {
            int32_t ret = mkdir(dirPath, S_IRWXU);
            if (ret != 0) {
                COMM_LOGE(COMM_ADAPTER, "make dir failed, ret=%{public}d", ret);
                return SOFTBUS_ERR;
            }
        }
        dir++;
    }
    int32_t fd = open(fileName, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        COMM_LOGE(COMM_ADAPTER, "create file failed, errno=%{public}d", errno);
        return SOFTBUS_ERR;
    }
    close(fd);
    return SOFTBUS_OK;
}

int32_t SoftBusReadFile(int32_t fd, void *readBuf, uint32_t maxLen)
{
    if (readBuf == NULL) {
        COMM_LOGE(COMM_ADAPTER, "softbus read file [buff is null]");
        return SOFTBUS_INVALID_PARAM;
    }
    int64_t len = read(fd, readBuf, maxLen);
    if (len < 0) {
        COMM_LOGE(COMM_ADAPTER, "softbus read file fail. errno=%{public}s", strerror(errno));
    }
    return len;
}

static int32_t ReadFullFile(const char *fileName, char *readBuf, uint32_t maxLen, int32_t *size)
{
    if (fileName == NULL || readBuf == NULL || maxLen == 0 || size == NULL) {
        COMM_LOGE(COMM_ADAPTER, "ReadFile fail param is invalid");
        return SOFTBUS_FILE_ERR;
    }

    int32_t fd = open(fileName, O_RDONLY, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        COMM_LOGE(COMM_ADAPTER, "ReadFile open file fail, errno=%{public}s", strerror(errno));
        return SOFTBUS_FILE_ERR;
    }
    int32_t fileLen = lseek(fd, 0, SEEK_END);
    if (fileLen <= 0) {
        COMM_LOGE(COMM_ADAPTER, "ReadFile len error, fileLen=%{public}d, errno=%{public}s", fileLen, strerror(errno));
        close(fd);
        return SOFTBUS_FILE_ERR;
    }
    if (fileLen > (int32_t)maxLen) {
        COMM_LOGE(COMM_ADAPTER, "ReadFile over max len, fileLen=%{public}d, maxLen=%{public}u", fileLen, maxLen);
        close(fd);
        return SOFTBUS_FILE_ERR;
    }
    int32_t ret = lseek(fd, 0, SEEK_SET);
    if (ret < 0) {
        COMM_LOGE(COMM_ADAPTER, "ReadFile lseek file fail, ret=%{public}d, errno=%{public}s", ret, strerror(errno));
        close(fd);
        return SOFTBUS_FILE_ERR;
    }
    ret = read(fd, readBuf, fileLen);
    if (ret < 0) {
        COMM_LOGE(COMM_ADAPTER, "ReadFile read fail, ret=%{public}d, errno=%{public}s", ret, strerror(errno));
        close(fd);
        return SOFTBUS_FILE_ERR;
    }
    close(fd);
    *size = fileLen;
    return SOFTBUS_OK;
}

int32_t SoftBusReadFullFileAndSize(const char *fileName, char *readBuf, uint32_t maxLen, int32_t *size)
{
    return ReadFullFile(fileName, readBuf, maxLen, size);
}

int32_t SoftBusReadFullFile(const char *fileName, char *readBuf, uint32_t maxLen)
{
    int32_t size = 0;
    return ReadFullFile(fileName, readBuf, maxLen, &size);
}

int32_t SoftBusWriteFile(const char *fileName, const char *writeBuf, uint32_t len)
{
    if (fileName == NULL || writeBuf == NULL || len == 0) {
        COMM_LOGE(COMM_ADAPTER, "softbus write file para is invalid");
        return SOFTBUS_FILE_ERR;
    }
    if (access(fileName, F_OK) != 0 && SoftBusCreateFile(fileName) != SOFTBUS_OK) {
        COMM_LOGE(COMM_ADAPTER, "create file fail");
        return SOFTBUS_FILE_ERR;
    }
    int32_t fd = open(fileName, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        COMM_LOGE(COMM_ADAPTER, "WriteFile open file fail errno=%{public}s", strerror(errno));
        return SOFTBUS_FILE_ERR;
    }
    int32_t ret = write(fd, writeBuf, len);
    if (len > INT32_MAX || ret != (int32_t)len) {
        COMM_LOGE(COMM_ADAPTER, "WriteFile write fail, len=%{public}u, ret=%{public}d, errno=%{public}s",
            len, ret, strerror(errno));
        close(fd);
        return SOFTBUS_FILE_ERR;
    }
    fsync(fd);
    close(fd);
    return SOFTBUS_OK;
}

int32_t SoftBusWriteFileFd(int32_t fd, const char *writeBuf, uint32_t len)
{
    if (writeBuf == NULL || len == 0) {
        COMM_LOGE(COMM_ADAPTER, "softbus write file fd para is invalid");
        return SOFTBUS_FILE_ERR;
    }
    int32_t ret = write(fd, writeBuf, len);
    if (ret != (int32_t)len) {
        COMM_LOGE(COMM_ADAPTER, "WriteFileFd write fail, len=%{public}u, ret=%{public}d, errno=%{public}s",
            len, ret, strerror(errno));
    }
    return ret;
}

int32_t SoftBusOpenFile(const char *fileName, int32_t flags)
{
    if (fileName == NULL) {
        COMM_LOGE(COMM_ADAPTER, "softbus open file [fileName is null]");
        return SOFTBUS_INVALID_FD;
    }
    int32_t fd = open(fileName, flags);
    if (fd < 0) {
        COMM_LOGE(COMM_ADAPTER, "softbus open file [open fail], errno=%{public}s", strerror(errno));
        return SOFTBUS_INVALID_FD;
    }
    return fd;
}

int32_t SoftBusOpenFileWithPerms(const char *fileName, int32_t flags, int32_t perms)
{
    if (fileName == NULL) {
        COMM_LOGE(COMM_ADAPTER, "softbus open with perms file [fileName is null]");
        return SOFTBUS_INVALID_FD;
    }
    int32_t fd = open(fileName, flags, perms);
    if (fd < 0) {
        COMM_LOGE(COMM_ADAPTER, "softbus open with perms file [open fail], errno=%{public}s", strerror(errno));
        return SOFTBUS_INVALID_FD;
    }
    return fd;
}

void SoftBusRemoveFile(const char *fileName)
{
    if (fileName == NULL) {
        COMM_LOGE(COMM_ADAPTER, "softbus remove file [fileName is null]");
        return;
    }
    if (remove(fileName) != 0) {
        COMM_LOGE(COMM_ADAPTER, "softbus remove file fail. errno=%{public}s", strerror(errno));
        return;
    }
}

void SoftBusCloseFile(int32_t fd)
{
    if (fd <= SOFTBUS_INVALID_FD) {
        COMM_LOGE(COMM_ADAPTER, "softbus close file [fd is invalid]");
        return;
    }
    if (close(fd) != 0) {
        COMM_LOGE(COMM_ADAPTER, "softbus close file fail. errno=%{public}s", strerror(errno));
        return;
    }
}

int64_t SoftBusPreadFile(int32_t fd, void *buf, uint64_t readBytes, uint64_t offset)
{
    if (buf == NULL) {
        COMM_LOGE(COMM_ADAPTER, "softbus pread file [buff is null]");
        return SOFTBUS_ERR;
    }
    int64_t len = pread(fd, buf, readBytes, offset);
    if (len < 0) {
        COMM_LOGE(COMM_ADAPTER, "softbus pread file fail. errno=%{public}s", strerror(errno));
    }
    return len;
}

int64_t SoftBusPwriteFile(int32_t fd, const void *buf, uint64_t writeBytes, uint64_t offset)
{
    if (buf == NULL) {
        COMM_LOGE(COMM_ADAPTER, "softbus pwrite file [buff is null]");
        return SOFTBUS_ERR;
    }
    int64_t len = pwrite(fd, buf, writeBytes, offset);
    if (len < 0) {
        COMM_LOGE(COMM_ADAPTER, "softbus pwrite file fail. errno=%{public}s", strerror(errno));
    }
    return len;
}

int32_t SoftBusAccessFile(const char *pathName, int32_t mode)
{
    if (pathName == NULL) {
        COMM_LOGE(COMM_ADAPTER, "softbus access path [pathName is null]");
        return SOFTBUS_ERR;
    }

    int32_t ret = access(pathName, mode);
    if (ret != 0) {
        COMM_LOGE(COMM_ADAPTER, "softbus access path fail, ret=%{public}d, errno=%{public}s", ret, strerror(errno));
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusMakeDir(const char *pathName, int32_t mode)
{
    if (pathName == NULL) {
        COMM_LOGE(COMM_ADAPTER, "softbus mkdir file [pathName is null]");
        return SOFTBUS_ERR;
    }

    int32_t ret = mkdir(pathName, mode);
    if (ret == 0) {
        return SOFTBUS_ADAPTER_OK;
    } else if ((ret == -1) && (errno == EEXIST)) {
        return SOFTBUS_ADAPTER_FILE_EXIST;
    } else {
        return SOFTBUS_ADAPTER_ERR;
    }
}
int32_t SoftBusGetFileSize(const char *fileName, uint64_t *fileSize)
{
    if ((fileName == NULL) || (fileSize == NULL)) {
        COMM_LOGE(COMM_ADAPTER, "softbus mkdir file [fileName or fileSize is null]");
        return SOFTBUS_ERR;
    }

    struct stat statBuff;
    if (stat(fileName, &statBuff) < 0) {
        COMM_LOGE(COMM_ADAPTER, "stat file fail");
        return SOFTBUS_ERR;
    } else {
        *fileSize = statBuff.st_size;
    }

    return SOFTBUS_OK;
}

char *SoftBusRealPath(const char *path, char *absPath)
{
    if ((path == NULL) || (absPath == NULL)) {
        COMM_LOGE(COMM_ADAPTER, "softbus realpath [path or absPath is null]");
        return NULL;
    }

    char *realPath = NULL;
    if (realpath(path, absPath) == NULL) {
        COMM_LOGE(COMM_ADAPTER, "realpath failed, errno=%{public}s", strerror(errno));
        return NULL;
    } else {
        realPath = absPath;
    }
    return realPath;
}
