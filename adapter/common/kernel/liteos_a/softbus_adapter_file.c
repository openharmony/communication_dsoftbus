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
#include <signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "softbus_adapter_log.h"
#include "softbus_def.h"
#include "softbus_errcode.h"

int SoftBusReadFile(const char *fileName, char *readBuf, int maxLen)
{
    if (fileName == NULL || readBuf == NULL || maxLen <= 0) {
        return SOFTBUS_FILE_ERR;
    }

    int fd = open(fileName, O_RDONLY, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "ReadFile get deviceid open file fail");
        return SOFTBUS_FILE_ERR;
    }
    int fileLen = lseek(fd, 0, SEEK_END);
    if (fileLen <= 0 || fileLen > maxLen) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "ReadFile maxLen failed or over maxLen");
        close(fd);
        return SOFTBUS_FILE_ERR;
    }
    int ret = lseek(fd, 0, SEEK_SET);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "ReadFile get deviceid lseek file fail");
        close(fd);
        return SOFTBUS_FILE_ERR;
    }
    ret = read(fd, readBuf, fileLen);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "ReadFile read deviceid fail, ret=%{public}d", ret);
        close(fd);
        return SOFTBUS_FILE_ERR;
    }
    close(fd);
    return SOFTBUS_OK;
}

int SoftBusWriteFile(const char *fileName, const char *writeBuf, int len)
{
    if (fileName == NULL || writeBuf == NULL || len <= 0) {
        return SOFTBUS_FILE_ERR;
    }

    int fd = open(fileName, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "WriteDeviceId open file fail");
        return SOFTBUS_FILE_ERR;
    }
    int ret = write(fd, writeBuf, len);
    if (ret != len) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "WriteDeviceId write fail");
        close(fd);
        return SOFTBUS_FILE_ERR;
    }
    close(fd);
    return SOFTBUS_OK;
}
