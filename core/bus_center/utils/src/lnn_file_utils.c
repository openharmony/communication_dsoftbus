/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "anonymizer.h"
#include "lnn_log.h"
#include "softbus_adapter_file.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"

#define DEFAULT_STORAGE_PATH "/data/service/el1/public"

typedef struct {
    LnnFileId fileId;
    const char *filePath;
} FilePathInfo;

static char g_storagePath[SOFTBUS_MAX_PATH_LEN] = {0};

static FilePathInfo g_filePath[LNN_FILE_ID_MAX] = {
    { LNN_FILE_ID_UUID, "/dsoftbus/uuid" },
    { LNN_FILE_ID_DB_KEY, "/dsoftbus/dbKey" },
    { LNN_FILE_ID_LOCAL_DEVICE, "/dsoftbus/localdevinfo" },
    { LNN_FILE_ID_REMOTE_DEVICE, "/dsoftbus/deviceinfo" },
    { LNN_FILE_ID_COMM_KEY, "/dsoftbus/devicecommkey" },
    { LNN_FILE_ID_BROADCAST_KEY, "/dsoftbus/broadcastkey" },
    { LNN_FILE_ID_PTK_KEY, "/dsoftbus/ptkkey" },
    { LNN_FILE_ID_IRK_KEY, "/dsoftbus/irk" },
    { LNN_FILE_ID_BROADCAST_CIPHER, "/dsoftbus/cipher" },
};

static int32_t InitStorageConfigPath(void)
{
    if (SoftbusGetConfig(SOFTBUS_STR_STORAGE_DIRECTORY, (uint8_t *)g_storagePath,
        SOFTBUS_MAX_PATH_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "read storage path fail");
        if (strncpy_s(g_storagePath, SOFTBUS_MAX_PATH_LEN, DEFAULT_STORAGE_PATH,
            strlen(DEFAULT_STORAGE_PATH)) != EOK) {
            LNN_LOGE(LNN_STATE, "copy default storage path fail");
            g_storagePath[0] = '\0';
            return SOFTBUS_STRCPY_ERR;
        }
    }
    return SOFTBUS_OK;
}

int32_t LnnGetFullStoragePath(LnnFileId id, char *path, uint32_t len)
{
    if (path == NULL) {
        LNN_LOGE(LNN_STATE, "path is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strlen(g_storagePath) == 0) {
        int32_t ret = InitStorageConfigPath();
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "init storage config path fail");
            return ret;
        }
    }
    if (strncpy_s(path, len, g_storagePath, strlen(g_storagePath)) != EOK ||
        strncat_s(path, len, g_filePath[id].filePath, strlen(g_filePath[id].filePath)) != EOK) {
        LNN_LOGE(LNN_STATE, "splice full path fail. id=%{public}d", id);
        return SOFTBUS_MEM_ERR;
    }
    char *anonyPath = NULL;
    Anonymize(path, &anonyPath);
    LNN_LOGI(LNN_STATE, "full path id=%{public}d, path=%{public}s", id, AnonymizeWrapper(anonyPath));
    AnonymizeFree(anonyPath);
    return SOFTBUS_OK;
}
