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

#include "lnn_network_id.h"

#include <stdbool.h>
#include <stdlib.h>

#include <securec.h>

#include "lnn_file_utils.h"
#include "softbus_bus_center.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

static int32_t GetUuidFromFile(char *id, uint32_t len)
{
    int32_t fd;
    bool needWrite = false;

    fd = LnnFileOpen(LNN_FILE_ID_UUID);
    if (fd < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "create uuid file");
        if (LnnFileCreate(LNN_FILE_ID_UUID) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "create file failed");
            return SOFTBUS_ERR;
        }
        fd = LnnFileOpen(LNN_FILE_ID_UUID);
        if (fd < 0) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "open uuid file failed");
            return SOFTBUS_ERR;
        }
        needWrite = true;
    }
    if (needWrite) {
        if (GenerateRandomStr(id, len) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "generate uuid id fail");
            LnnFileClose(fd);
            return SOFTBUS_ERR;
        }
        if (LnnFileWrite(fd, (uint8_t *)id, len, true) != (int32_t)len) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write uuid to file failed");
            LnnFileClose(fd);
            return SOFTBUS_ERR;
        }
    } else {
        if (LnnFileRead(fd, (uint8_t *)id, len, true) != (int32_t)len) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "read uuid from file failed");
            LnnFileClose(fd);
            return SOFTBUS_ERR;
        }
        if (id[len - 1] != '\0' || strlen(id) != (len - 1)) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "uuid is invalid format from file");
            LnnFileClose(fd);
            return SOFTBUS_ERR;
        }
    }
    LnnFileClose(fd);
    return SOFTBUS_OK;
}

int32_t LnnGenLocalNetworkId(char *networkId, uint32_t len)
{
    if (networkId == NULL || len < NETWORK_ID_BUF_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (GenerateRandomStr(networkId, NETWORK_ID_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "generate network id fail");
        return SOFTBUS_ERR;
    }
    networkId[len - 1] = '\0';
    return SOFTBUS_OK;
}

int32_t LnnGenLocalUuid(char *uuid, uint32_t len)
{
    static bool isGenerated = false;
    static char localUuid[UUID_BUF_LEN] = {0};

    if (uuid == NULL || len < UUID_BUF_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (isGenerated == false) {
        if (GetUuidFromFile(localUuid, UUID_BUF_LEN) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get uuid from file failed");
            return SOFTBUS_ERR;
        }
        isGenerated = true;
    }
    if (strncpy_s(uuid, len, localUuid, UUID_BUF_LEN) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy uuid id fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}