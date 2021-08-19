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
#include <limits.h>
#include <securec.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log.h"

#define DEFAULT_STORAGE_PATH "/data/data"

static char g_storagePath[LNN_MAX_DIR_PATH_LEN] = {0};

static LnnFilePath g_filePath[LNN_FILE_ID_MAX] = {
    { LNN_FILE_ID_UUID, "/dsoftbus/uuid" }
};

static int32_t InitStorageConfigPath(void)
{
    char *path = NULL;
    char canonicalizedPath[PATH_MAX];

    if (SoftbusGetConfig(SOFTBUS_STR_STORAGE_DIRECTORY, (uint8_t *)g_storagePath,
        LNN_MAX_DIR_PATH_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "read storage path fail");
        if (strncpy_s(g_storagePath, LNN_MAX_DIR_PATH_LEN, DEFAULT_STORAGE_PATH,
            strlen(DEFAULT_STORAGE_PATH)) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy default storage path fail");
            g_storagePath[0] = '\0';
            return SOFTBUS_ERR;
        }
    }
    path = realpath(g_storagePath, canonicalizedPath);
    if (path == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "realpath %s fail", g_storagePath);
        g_storagePath[0] = '\0';
        return SOFTBUS_ERR;
    }
    if (strncpy_s(g_storagePath, LNN_MAX_DIR_PATH_LEN, canonicalizedPath, strlen(canonicalizedPath)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy canonicalized storage path fail");
        g_storagePath[0] = '\0';
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t GetFullStoragePath(LnnFileId id, char *path, int32_t len)
{
    if (strlen(g_storagePath) == 0) {
        if (InitStorageConfigPath() != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "init storage config path fail");
            return SOFTBUS_ERR;
        }
    }
    if (strncpy_s(path, len, g_storagePath, strlen(g_storagePath)) != EOK ||
        strncat_s(path, len, g_filePath[id].filePath, strlen(g_filePath[id].filePath)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "splice full path for %d fail", id);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "full path for %d is %s", id, path);
    return SOFTBUS_OK;
}

int32_t LnnFileCreate(LnnFileId id)
{
    int32_t ret;
    char *dir = NULL;
    char dirPath[LNN_MAX_DIR_PATH_LEN];
    char fullPath[LNN_MAX_DIR_PATH_LEN];
    int32_t fd = -1;

    if (id >= LNN_FILE_ID_MAX) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid create file id: %d", id);
        return SOFTBUS_ERR;
    }
    if (GetFullStoragePath(id, fullPath, LNN_MAX_DIR_PATH_LEN) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    dir = (char *)fullPath;
    while ((dir = strchr(dir, LNN_PATH_SEPRATOR)) != NULL) {
        uint32_t len = (uint32_t)(dir - fullPath);
        if (len == 0) { // skip root
            dir++;
            continue;
        }
        if (memcpy_s(dirPath, sizeof(dirPath), fullPath, len) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "memory copy dir name failed");
            return SOFTBUS_ERR;
        }
        dirPath[len] = 0;
        if (access(dirPath, F_OK) != 0) {
            ret = mkdir(dirPath, S_IRWXU);
            if (ret != 0) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "make dir failed, err code %d", ret);
                return SOFTBUS_ERR;
            }
        }
        dir++;
    }
    fd = open(fullPath, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "crate file failed, errno = %d", errno);
        return SOFTBUS_ERR;
    }
    close(fd);
    return SOFTBUS_OK;
}

int32_t LnnFileOpen(LnnFileId id)
{
    char path[LNN_MAX_DIR_PATH_LEN] = {0};

    if (id >= LNN_FILE_ID_MAX) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid open file id: %d", id);
        return SOFTBUS_ERR;
    }
    if (GetFullStoragePath(id, path, LNN_MAX_DIR_PATH_LEN) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    return open(path, O_RDWR);
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid file read arguments");
        return SOFTBUS_INVALID_PARAM;
    }
    while (pos < len) {
        ret = read(fd, dst + pos, len - pos);
        if (ret < 0 && errno == EAGAIN) {
            continue;
        }
        if (ret < 0) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "read file failed");
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid file read arguments");
        return SOFTBUS_INVALID_PARAM;
    }
    while (pos < len) {
        ret = write(fd, src + pos, len - pos);
        if (ret < 0 && errno == EAGAIN) {
            continue;
        }
        if (ret < 0) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write file failed, errno=%d", errno);
            return SOFTBUS_ERR;
        }
        pos += ret;
        if (pos > 0 && !needWriteAll) {
            break;
        }
    }
    fsync(fd);
    return pos;
}
