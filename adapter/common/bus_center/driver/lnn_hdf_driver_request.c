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

#include "lnn_driver_request.h"

#include <hdf_io_service.h>
#include <hdf_sbuf.h>
#include <securec.h>

#include "lnn_log.h"
#include "softbus_error_code.h"

#define DRIVER_SERVICE_NAME "hdf_dsoftbus"

static int32_t ParseReply(struct HdfSBuf *rspData, uint8_t *reply, uint32_t replyLen)
{
    uint8_t *data = NULL;
    uint32_t dataSize;

    if (reply == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (!HdfSbufReadBuffer(rspData, (const void **)&data, &dataSize)) {
        LNN_LOGE(LNN_STATE, "read cmd reply fail");
        return SOFTBUS_READ_BUFFER_FAIL;
    }
    if (dataSize > replyLen) {
        LNN_LOGE(LNN_STATE, "no enough space save reply");
        return SOFTBUS_NO_ENOUGH_DATA;
    }
    if (memcpy_s(reply, replyLen, data, dataSize) != EOK) {
        LNN_LOGE(LNN_STATE, "memcpy reply fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnSendCmdToDriver(int32_t moduleId, const uint8_t *cmd, uint32_t cmdLen,
    uint8_t *reply, uint32_t replyLen)
{
    int32_t rc = SOFTBUS_DRIVER_SERVICE_FAIL;
    struct HdfIoService *softbusService = NULL;
    struct HdfSBuf *reqData = NULL;
    struct HdfSBuf *rspData = NULL;

    if (cmd == NULL) {
        LNN_LOGW(LNN_STATE, "invalid cmd for module=%{public}d", moduleId);
        return SOFTBUS_INVALID_PARAM;
    }
    softbusService = HdfIoServiceBind(DRIVER_SERVICE_NAME);
    if (softbusService == NULL) {
        LNN_LOGE(LNN_STATE, "bind hdf softbus fail for module=%{public}d", moduleId);
        return SOFTBUS_BIND_DRIVER_FAIL;
    }
    if (softbusService->dispatcher == NULL ||
        softbusService->dispatcher->Dispatch == NULL) {
        LNN_LOGE(LNN_STATE, "dispatcher is null, bind hdf softbus fail for module=%{public}d", moduleId);
        HdfIoServiceRecycle(softbusService);
        return SOFTBUS_BIND_DRIVER_FAIL;
    }
    reqData = HdfSbufObtainDefaultSize();
    rspData = HdfSbufObtainDefaultSize();
    do {
        if (reqData == NULL || rspData == NULL) {
            LNN_LOGE(LNN_STATE, "obtain sbuf fail for module=%{public}d", moduleId);
            break;
        }
        if (!HdfSbufWriteBuffer(reqData, cmd, cmdLen)) {
            LNN_LOGE(LNN_STATE, "write sbuf fail for module=%{public}d", moduleId);
            break;
        }
        rc = softbusService->dispatcher->Dispatch(&softbusService->object, moduleId, reqData, rspData);
        if (rc != 0) {
            LNN_LOGE(LNN_STATE, "send command fail for module=%{public}d", moduleId);
        }
    } while (false);
    if (rc == SOFTBUS_OK) {
        rc = ParseReply(rspData, reply, replyLen);
    }
    if (reqData != NULL) {
        HdfSbufRecycle(reqData);
    }
    if (rspData != NULL) {
        HdfSbufRecycle(rspData);
    }
    HdfIoServiceRecycle(softbusService);
    return rc;
}