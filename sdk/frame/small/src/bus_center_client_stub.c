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
#include "ipc_skeleton.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

int32_t ClientOnJoinLNNResult(IpcIo *data, IpcIo *reply)
{
    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return SOFTBUS_ERR;
    }

    uint32_t addrSize;
    ReadUint32(data, &addrSize);
    if (addrSize != sizeof(ConnectionAddr)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ClientOnJoinLNNResult read addrSize:%d failed!", addrSize);
        return SOFTBUS_ERR;
    }
    void *addr = (void *)ReadBuffer(data, addrSize);
    if (addr == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ClientOnJoinLNNResult read addr failed!");
        return SOFTBUS_ERR;
    }
    int32_t retCode = 0;
    ReadInt32(data, &retCode);
    size_t networkIdLen;
    const char *networkId = NULL;
    if (retCode == 0) {
        networkId = (const char *)ReadString(data, &networkIdLen);
        if (networkId == NULL) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ClientOnJoinLNNResult read networkId failed!");
            return SOFTBUS_ERR;
        }
    }
    int32_t retReply = LnnOnJoinResult(addr, networkId, retCode);
    if (retReply != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ClientOnJoinLNNResult LnnOnJoinResult failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ClientOnJoinMetaNodeResult(IpcIo *data, IpcIo *reply)
{
    (void)data;
    (void)reply;
    return SOFTBUS_OK;
}

int32_t ClientOnLeaveLNNResult(IpcIo *data, IpcIo *reply)
{
    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return SOFTBUS_ERR;
    }
    size_t networkIdLen;
    const char *networkId = (const char *)ReadString(data, &networkIdLen);
    if (networkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ClientOnLeaveLNNResult read networkId failed!");
        return SOFTBUS_ERR;
    }
    int32_t retCode = 0;
    ReadInt32(data, &retCode);
    int32_t retReply = LnnOnLeaveResult(networkId, retCode);
    if (retReply != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ClientOnLeaveLNNResult LnnOnLeaveResult failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ClientOnLeaveMetaNodeResult(IpcIo *data, IpcIo *reply)
{
    (void)data;
    (void)reply;
    return SOFTBUS_OK;
}

int32_t ClientOnNodeOnlineStateChanged(IpcIo *data, IpcIo *reply)
{
    if (data== NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return SOFTBUS_ERR;
    }
    bool isOnline;
    ReadBool(data, &isOnline);
    uint32_t infoSize = 0;
    ReadUint32(data, &infoSize);
    if (infoSize != sizeof(NodeBasicInfo)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR,
            "ClientOnNodeOnlineStateChanged read infoSize:%d failed!", infoSize);
        return SOFTBUS_ERR;
    }
    void *info = (void *)ReadBuffer(data, infoSize);
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ClientOnNodeOnlineStateChanged read basic info failed!");
        return SOFTBUS_ERR;
    }
    int32_t retReply = LnnOnNodeOnlineStateChanged(isOnline, info);
    if (retReply != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR,
            "ClientOnNodeOnlineStateChanged LnnOnNodeOnlineStateChanged failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ClientOnNodeBasicInfoChanged(IpcIo *data, IpcIo *reply)
{
    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return SOFTBUS_ERR;
    }

    int32_t type = 0;
    ReadInt32(data, &type);
    uint32_t infoSize = 0;
    ReadUint32(data, &infoSize);
    if (infoSize != sizeof(NodeBasicInfo)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR,
            "ClientOnNodeBasicInfoChanged read infoSize:%d failed!", infoSize);
        return SOFTBUS_ERR;
    }
    void *info = (void *)ReadBuffer(data, infoSize);
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ClientOnNodeBasicInfoChanged read basic info failed!");
        return SOFTBUS_ERR;
    }
    int32_t retReply = LnnOnNodeBasicInfoChanged(info, type);
    if (retReply != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR,
            "ClientOnNodeBasicInfoChanged LnnOnNodeBasicInfoChanged failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ClientOnTimeSyncResult(IpcIo *data, IpcIo *reply)
{
    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return SOFTBUS_ERR;
    }

    uint32_t infoSize = 0;
    ReadUint32(data, &infoSize);
    if (infoSize != sizeof(TimeSyncResultInfo)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ClientOnTimeSyncResult read infoSize:%d failed!", infoSize);
        return SOFTBUS_ERR;
    }
    void *info = (void *)ReadBuffer(data, infoSize);
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ClientOnTimeSyncResult read info failed!");
        return SOFTBUS_ERR;
    }
    int32_t retCode = 0;
    ReadInt32(data, &retCode);

    int32_t retReply = LnnOnTimeSyncResult(info, retCode);
    if (retReply != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ClientOnTimeSyncResult LnnOnTimeSyncResult failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void ClientOnPublishLNNResult(IpcIo *data, IpcIo *reply)
{
    if (reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return;
    }
    int32_t publishId;
    ReadInt32(data, &publishId);
    int32_t reason;
    ReadInt32(data, &reason);
    LnnOnPublishLNNResult(publishId, reason);
}

void ClientOnRefreshLNNResult(IpcIo *data, IpcIo *reply)
{
    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return;
    }
    int32_t refreshId;
    ReadInt32(data, &refreshId);
    int32_t reason;
    ReadInt32(data, &reason);
    LnnOnRefreshLNNResult(refreshId, reason);
}

void ClientOnRefreshDeviceFound(IpcIo *data, IpcIo *reply)
{
    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return;
    }
    uint32_t infoSize;
    ReadUint32(data, &infoSize);
    if (infoSize != sizeof(DeviceInfo)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR,
            "ClientOnRefreshDeviceFound read infoSize:%d failed!", infoSize);
        return;
    }
    void *info = (void *)ReadBuffer(data, infoSize);
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ClientOnRefreshDeviceFound read info failed!");
        return;
    }
    LnnOnRefreshDeviceFound(info);
}
