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

#include "lnn_network_id.h"

#include <stdbool.h>
#include <stdlib.h>

#include <securec.h>

#include "anonymizer.h"
#include "lnn_file_utils.h"
#include "lnn_log.h"
#include "lnn_node_info.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_file.h"
#include "softbus_bus_center.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

static int32_t GetUuidFromFile(char *id, uint32_t len)
{
    int32_t rc;
    char uuidFilePath[SOFTBUS_MAX_PATH_LEN] = {0};

    rc = LnnGetFullStoragePath(LNN_FILE_ID_UUID, uuidFilePath, SOFTBUS_MAX_PATH_LEN);
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "get uuid save path fail");
        return rc;
    }
    if (SoftBusReadFullFile(uuidFilePath, id, len) != SOFTBUS_OK) {
        rc = GenerateRandomStr(id, len);
        if (rc != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "generate uuid id fail");
            return rc;
        }
        rc = SoftBusWriteFile(uuidFilePath, id, len);
        if (rc != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "write uuid to file failed");
            return rc;
        }
    }
    if (id[len - 1] != '\0' || strlen(id) != (len - 1)) {
        LNN_LOGE(LNN_STATE, "uuid is invalid format");
        return SOFTBUS_NETWORK_GET_UUID_FROM_FILE_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t LnnGenLocalNetworkId(char *networkId, uint32_t len)
{
    if (networkId == NULL || len < NETWORK_ID_BUF_LEN) {
        LNN_LOGE(LNN_STATE, "invalid prama");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t rc = GenerateRandomStr(networkId, NETWORK_ID_BUF_LEN);
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "generate network id fail");
        return rc;
    }
    networkId[len - 1] = '\0';
    return SOFTBUS_OK;
}

int32_t LnnGenLocalUuid(char *uuid, uint32_t len)
{
    static bool isGenerated = false;
    static char localUuid[UUID_BUF_LEN] = {0};

    if (uuid == NULL || len < UUID_BUF_LEN) {
        LNN_LOGE(LNN_STATE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (isGenerated == false) {
        if (GetUuidFromFile(localUuid, UUID_BUF_LEN) != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "get uuid from file failed");
            return SOFTBUS_NETWORK_GET_UUID_FROM_FILE_FAILED;
        }
        isGenerated = true;
    }
    if (strncpy_s(uuid, len, localUuid, UUID_BUF_LEN) != EOK) {
        LNN_LOGE(LNN_STATE, "copy uuid id fail");
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t GetIrkFromFile(unsigned char *irk, uint32_t len)
{
    int32_t rc;
    char irkFilePath[SOFTBUS_MAX_PATH_LEN] = {0};

    rc = LnnGetFullStoragePath(LNN_FILE_ID_IRK_KEY, irkFilePath, SOFTBUS_MAX_PATH_LEN);
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "get irk save path fail");
        return rc;
    }
    if (SoftBusReadFullFile(irkFilePath, (char *)irk, len) != SOFTBUS_OK) {
        rc = SoftBusGenerateRandomArray(irk, len);
        if (rc != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "generate irk id fail");
            return rc;
        }
        rc = SoftBusWriteFile(irkFilePath, (char *)irk, len);
        if (rc != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "write irk to file failed");
            return rc;
        }
    }
    return SOFTBUS_OK;
}

int32_t LnnGenLocalIrk(unsigned char *irk, uint32_t len)
{
    static bool isIrkGenerated = false;
    static char locaIrk[LFINDER_IRK_LEN] = {0};

    if (irk == NULL || len < LFINDER_IRK_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (!isIrkGenerated) {
        if (GetIrkFromFile((unsigned char *)locaIrk, LFINDER_IRK_LEN) != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "get irk from file failed");
            return SOFTBUS_GET_IRK_FAIL;
        }
        isIrkGenerated = true;
    }
    if (memcpy_s(irk, len, locaIrk, LFINDER_IRK_LEN) != EOK) {
        LNN_LOGE(LNN_STATE, "copy irk id fail");
        isIrkGenerated = false;
        (void)memset_s(locaIrk, LFINDER_IRK_LEN, 0, LFINDER_IRK_LEN);
        return SOFTBUS_MEM_ERR;
    }
    char irkStr[LFINDER_IRK_STR_LEN] = {0};
    if (ConvertBytesToHexString(irkStr, LFINDER_IRK_STR_LEN, irk, LFINDER_IRK_LEN) != SOFTBUS_OK) {
        LNN_LOGW(LNN_STATE, "convert irk to string fail, just is dump, ignore this warning");
        return SOFTBUS_OK;
    }
    char *anonyIrk = NULL;
    Anonymize(irkStr, &anonyIrk);
    LNN_LOGI(LNN_STATE, "get irk success:irk=%{public}s", AnonymizeWrapper(anonyIrk));
    AnonymizeFree(anonyIrk);
    (void)memset_s(irkStr, LFINDER_IRK_STR_LEN, 0, LFINDER_IRK_STR_LEN);
    return SOFTBUS_OK;
}