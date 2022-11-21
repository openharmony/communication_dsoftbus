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

#include "softbus_adapter_file.h"

#include <errno.h>
#include <fcntl.h>
#include <securec.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "softbus_adapter_log.h"
#include "softbus_def.h"
#include "softbus_errcode.h"

static int32_t SoftBusCreateFile(const char *fileName)
{
    char dirPath[SOFTBUS_MAX_PATH_LEN] = {0};

    if (fileName == NULL) {
        return SOFTBUS_FILE_ERR;
    }

    char *dir = (char *)fileName;
    while ((dir = strchr(dir, SOFTBUS_PATH_SEPRATOR)) != NULL) {
        uint32_t len = (uint32_t)(dir - fileName);
        if (len == 0) { // skip root
            dir++;
            continue;
        }
        if (memcpy_s(dirPath, sizeof(dirPath), fileName, len) != EOK) {
            HILOG_ERROR(SOFTBUS_HILOG_ID, "memory copy dir name failed");
            return SOFTBUS_ERR;
        }
        dirPath[len] = 0;
        if (access(dirPath, F_OK) != 0) {
            int32_t ret = mkdir(dirPath, S_IRWXU);
            if (ret != 0) {
                HILOG_ERROR(SOFTBUS_HILOG_ID, "make dir failed, err code %{public}d", ret);
                return SOFTBUS_ERR;
            }
        }
        dir++;
    }
    int32_t fd = open(fileName, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "crate file failed, errno = %{public}d", errno);
        return SOFTBUS_ERR;
    }
    close(fd);
    return SOFTBUS_OK;
}

int32_t SoftBusReadFile(const char *fileName, char *readBuf, uint32_t maxLen)
{
    if (fileName == NULL || readBuf == NULL || maxLen == 0) {
        return SOFTBUS_FILE_ERR;
    }

    int32_t fd = open(fileName, O_RDONLY, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "ReadFile open file fail");
        return SOFTBUS_FILE_ERR;
    }
    int32_t fileLen = lseek(fd, 0, SEEK_END);
    if (fileLen <= 0 || fileLen > (int32_t)maxLen) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "ReadFile maxLen failed or over maxLen");
        close(fd);
        return SOFTBUS_FILE_ERR;
    }
    int32_t ret = lseek(fd, 0, SEEK_SET);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "ReadFile lseek file fail");
        close(fd);
        return SOFTBUS_FILE_ERR;
    }
    ret = read(fd, readBuf, fileLen);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "ReadFile read fail, ret=%{public}d", ret);
        close(fd);
        return SOFTBUS_FILE_ERR;
    }
    close(fd);
    return SOFTBUS_OK;
}

int32_t SoftBusWriteFile(const char *fileName, const char *writeBuf, uint32_t len)
{
    if (fileName == NULL || writeBuf == NULL || len == 0) {
        return SOFTBUS_FILE_ERR;
    }
    if (access(fileName, F_OK) != 0 && SoftBusCreateFile(fileName) != SOFTBUS_OK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "create file fail");
        return SOFTBUS_FILE_ERR;
    }
    int32_t fd = open(fileName, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "WriteFile open file fail");
        return SOFTBUS_FILE_ERR;
    }
    int32_t ret = write(fd, writeBuf, len);
    if (len > INT32_MAX || ret != (int32_t)len) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "WriteFile write fail");
        close(fd);
        return SOFTBUS_FILE_ERR;
    }
    fsync(fd);
    close(fd);
    return SOFTBUS_OK;
}
