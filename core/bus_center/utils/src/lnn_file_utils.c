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

#include "lnn_file_utils.h"

#include <fcntl.h>
#include <securec.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "softbus_errcode.h"
#include "softbus_log.h"

static LnnFilePath g_filePath[LNN_FILE_ID_MAX] = {
    { LNN_FILE_ID_UUID, "/data/data/dsoftbus/uuid" }
};

int32_t LnnFileCreate(LnnFileId id)
{
    int32_t ret;
    char *dir = NULL;
    char dirPath[LNN_MAX_DIR_PATH_LEN];
    int32_t fd = -1;

    if (id >= LNN_FILE_ID_MAX) {
        LOG_ERR("invalid create file id: %d", id);
        return SOFTBUS_ERR;
    }
    dir = (char *)g_filePath[id].filePath;
    while ((dir = strchr(dir, LNN_PATH_SEPRATOR)) != NULL) {
        uint32_t len = (uint32_t)(dir - g_filePath[id].filePath);
        if (len == 0) { // skip root
            dir++;
            continue;
        }
        if (memcpy_s(dirPath, sizeof(dirPath), g_filePath[id].filePath, len) != EOK) {
            LOG_ERR("memory copy dir name failed");
            return SOFTBUS_ERR;
        }
        dirPath[len] = 0;
        if (access(dirPath, F_OK) != 0) {
            ret = mkdir(dirPath, S_IRWXU);
            if (ret != 0) {
                LOG_ERR("make dir failed, err code %d", ret);
                return SOFTBUS_ERR;
            }
        }
        dir++;
    }
    fd = open(g_filePath[id].filePath, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        LOG_ERR("crate file failed, errno = %d", errno);
        return SOFTBUS_ERR;
    }
    close(fd);
    return SOFTBUS_OK;
}

int32_t LnnFileOpen(LnnFileId id)
{
    if (id >= LNN_FILE_ID_MAX) {
        LOG_ERR("invalid open file id: %d", id);
        return SOFTBUS_ERR;
    }
    return open(g_filePath[id].filePath, O_RDWR);
}

int32_t LnnFileClose(int32_t fd)
{
    return close(fd);
}

int32_t LnnFileRead(int32_t fd, uint8_t *dst, uint32_t len, bool needReadAll)
{
    int32_t ret;
    uint32_t pos = 0;

    if (fd < 0 || dst == NULL) {
        LOG_ERR("invalid file read arguments");
        return SOFTBUS_INVALID_PARAM;
    }
    while (pos < len) {
        ret = read(fd, dst + pos, len - pos);
        if (ret < 0 && errno == EAGAIN) {
            continue;
        }
        if (ret < 0) {
            LOG_ERR("read file failed");
            return SOFTBUS_ERR;
        }
        if (ret == 0) {
            break;
        }
        pos += ret;
        if (pos > 0 && !needReadAll) {
            break;
        }
    }
    return pos;
}

int32_t LnnFileWrite(int32_t fd, const uint8_t *src, uint32_t len, bool needWriteAll)
{
    int32_t ret;
    uint32_t pos = 0;

    if (fd < 0 || src == NULL) {
        LOG_ERR("invalid file read arguments");
        return SOFTBUS_INVALID_PARAM;
    }
    while (pos < len) {
        ret = write(fd, src + pos, len - pos);
        if (ret < 0 && errno == EAGAIN) {
            continue;
        }
        if (ret < 0) {
            LOG_ERR("write file failed, errno=%d", errno);
            return SOFTBUS_ERR;
        }
        pos += ret;
        if (pos > 0 && !needWriteAll) {
            break;
        }
    }
    return pos;
}
