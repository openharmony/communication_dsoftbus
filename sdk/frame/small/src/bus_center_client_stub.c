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

#include "bus_center_client_stub.h"

#include <stdint.h>
#include "client_bus_center_manager.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

int32_t ClientOnJoinLNNResult(IpcIo *reply, const IpcContext *ctx, void *ipcMsg)
{
    if (reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param.");
        FreeBuffer(ctx, ipcMsg);
        return SOFTBUS_ERR;
    }

    uint32_t addrSize;
    void *addr = (void *)IpcIoPopFlatObj(reply, &addrSize);
    if (addr == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ClientOnJoinLNNResult read addr failed!");
        FreeBuffer(ctx, ipcMsg);
        return SOFTBUS_ERR;
    }
    int32_t retCode = IpcIoPopInt32(reply);
    size_t networkIdLen;
    const char *networkId = NULL;
    if (retCode == 0) {
        networkId = (const char *)IpcIoPopString(reply, &networkIdLen);
        if (networkId == NULL) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ClientOnJoinLNNResult read networkId failed!");
            FreeBuffer(ctx, ipcMsg);
            return SOFTBUS_ERR;
        }
    }
    int32_t retReply = LnnOnJoinResult(addr, networkId, retCode);
    if (retReply != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ClientOnJoinLNNResult LnnOnJoinResult failed!");
        FreeBuffer(ctx, ipcMsg);
        return SOFTBUS_ERR;
    }
    FreeBuffer(ctx, ipcMsg);
    return SOFTBUS_OK;
}

int32_t ClientOnLeaveLNNResult(IpcIo *reply, const IpcContext *ctx, void *ipcMsg)
{
    if (reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param.");
        FreeBuffer(ctx, ipcMsg);
        return SOFTBUS_ERR;
    }
    size_t networkIdLen;
    const char *networkId = (const char *)IpcIoPopString(reply, &networkIdLen);
    if (networkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ClientOnLeaveLNNResult read networkId failed!");
        FreeBuffer(ctx, ipcMsg);
        return SOFTBUS_ERR;
    }
    int32_t retCode = IpcIoPopInt32(reply);
    int32_t retReply = LnnOnLeaveResult(networkId, retCode);
    if (retReply != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ClientOnLeaveLNNResult LnnOnLeaveResult failed!");
        FreeBuffer(ctx, ipcMsg);
        return SOFTBUS_ERR;
    }
    FreeBuffer(ctx, ipcMsg);
    return SOFTBUS_OK;
}

int32_t ClientOnNodeOnlineStateChanged(IpcIo *reply, const IpcContext *ctx, void *ipcMsg)
{
    if (reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param.");
        FreeBuffer(ctx, ipcMsg);
        return SOFTBUS_ERR;
    }
    bool isOnline = IpcIoPopBool(reply);
    uint32_t infoSize;
    void *info = (void *)IpcIoPopFlatObj(reply, &infoSize);
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ClientOnNodeOnlineStateChanged read basic info failed!");
        FreeBuffer(ctx, ipcMsg);
        return SOFTBUS_ERR;
    }
    int32_t retReply = LnnOnNodeOnlineStateChanged(isOnline, info);
    if (retReply != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR,
            "ClientOnNodeOnlineStateChanged LnnOnNodeOnlineStateChanged failed!");
        FreeBuffer(ctx, ipcMsg);
        return SOFTBUS_ERR;
    }
    FreeBuffer(ctx, ipcMsg);
    return SOFTBUS_OK;
}

int32_t ClientOnNodeBasicInfoChanged(IpcIo *reply, const IpcContext *ctx, void *ipcMsg)
{
    if (reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param.");
        FreeBuffer(ctx, ipcMsg);
        return SOFTBUS_ERR;
    }

    int32_t type = IpcIoPopInt32(reply);
    uint32_t infoSize;
    void *info = (void *)IpcIoPopFlatObj(reply, &infoSize);
    int32_t retReply = LnnOnNodeBasicInfoChanged(info, type);
    if (retReply != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR,
            "ClientOnNodeBasicInfoChanged LnnOnNodeBasicInfoChanged failed!");
        FreeBuffer(ctx, ipcMsg);
        return SOFTBUS_ERR;
    }
    FreeBuffer(ctx, ipcMsg);
    return SOFTBUS_OK;
}

int32_t ClientOnTimeSyncResult(IpcIo *reply, const IpcContext *ctx, void *ipcMsg)
{
    if (reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param.");
        FreeBuffer(ctx, ipcMsg);
        return SOFTBUS_ERR;
    }

    uint32_t infoSize;
    void *info = (void *)IpcIoPopFlatObj(reply, &infoSize);
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ClientOnTimeSyncResult read info failed!");
        FreeBuffer(ctx, ipcMsg);
        return SOFTBUS_ERR;
    }
    int32_t retCode = IpcIoPopInt32(reply);

    int32_t retReply = LnnOnTimeSyncResult(info, retCode);
    if (retReply != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ClientOnTimeSyncResult LnnOnTimeSyncResult failed!");
        FreeBuffer(ctx, ipcMsg);
        return SOFTBUS_ERR;
    }
    FreeBuffer(ctx, ipcMsg);
    return SOFTBUS_OK;
}
