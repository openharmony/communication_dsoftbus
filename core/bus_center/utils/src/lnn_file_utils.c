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

#include <securec.h>

#include "softbus_adapter_file.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log.h"

#define DEFAULT_STORAGE_PATH "/data/service/el1/public"

typedef struct {
    LnnFileId fileId;
    const char *filePath;
} FilePathInfo;

static char g_storagePath[SOFTBUS_MAX_PATH_LEN] = {0};

static FilePathInfo g_filePath[LNN_FILE_ID_MAX] = {
    { LNN_FILE_ID_UUID, "/dsoftbus/uuid" },
    { LNN_FILE_ID_DB_KEY, "/dsoftbus/dbKey" },
};

static int32_t InitStorageConfigPath(void)
{
    if (SoftbusGetConfig(SOFTBUS_STR_STORAGE_DIRECTORY, (uint8_t *)g_storagePath,
        SOFTBUS_MAX_PATH_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "read storage path fail");
        if (strncpy_s(g_storagePath, SOFTBUS_MAX_PATH_LEN, DEFAULT_STORAGE_PATH,
            strlen(DEFAULT_STORAGE_PATH)) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy default storage path fail");
            g_storagePath[0] = '\0';
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

int32_t LnnGetFullStoragePath(LnnFileId id, char *path, uint32_t len)
{
    if (path == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s: path is null", __func__);
        return SOFTBUS_INVALID_PARAM;
    }
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
