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
#include "lnn_log.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

int32_t ClientOnJoinLNNResult(IpcIo *data, IpcIo *reply)
{
    if (data == NULL) {
        LNN_LOGE(LNN_EVENT, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    uint32_t addrSize;
    ReadUint32(data, &addrSize);
    if (addrSize != sizeof(ConnectionAddr)) {
        LNN_LOGE(LNN_EVENT, "read addr failed. addrSize=%{public}d", addrSize);
        return SOFTBUS_NETWORK_READINT32_FAILED;
    }
    void *addr = (void *)ReadBuffer(data, addrSize);
    if (addr == NULL) {
        LNN_LOGE(LNN_EVENT, "read addr failed");
        return SOFTBUS_MEM_ERR;
    }
    int32_t retCode = 0;
    ReadInt32(data, &retCode);
    size_t networkIdLen;
    const char *networkId = NULL;
    if (retCode == 0) {
        networkId = (const char *)ReadString(data, &networkIdLen);
        if (networkId == NULL) {
            LNN_LOGE(LNN_EVENT, "read networkId failed");
            return SOFTBUS_NETWORK_READCSTRING_FAILED;
        }
    }
    int32_t retReply = LnnOnJoinResult(addr, networkId, retCode);
    if (retReply != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "LnnOnJoinResult failed");
        return retReply;
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
        LNN_LOGE(LNN_EVENT, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    size_t networkIdLen;
    const char *networkId = (const char *)ReadString(data, &networkIdLen);
    if (networkId == NULL) {
        LNN_LOGE(LNN_EVENT, "read networkId failed");
        return SOFTBUS_NETWORK_READCSTRING_FAILED;
    }
    int32_t retCode = 0;
    ReadInt32(data, &retCode);
    int32_t retReply = LnnOnLeaveResult(networkId, retCode);
    if (retReply != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "LnnOnLeaveResult failed");
        return retReply;
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
        LNN_LOGE(LNN_EVENT, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    bool isOnline;
    ReadBool(data, &isOnline);
    uint32_t infoSize = 0;
    ReadUint32(data, &infoSize);
    if (infoSize != sizeof(NodeBasicInfo)) {
        LNN_LOGE(LNN_EVENT,
            "read basic info failed. infoSize=%{public}d", infoSize);
        return SOFTBUS_NETWORK_READINT32_FAILED;
    }
    void *info = (void *)ReadBuffer(data, infoSize);
    if (info == NULL) {
        LNN_LOGE(LNN_EVENT, "read basic info failed");
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t retReply = LnnOnNodeOnlineStateChanged("", isOnline, info);
    if (retReply != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "LnnOnNodeOnlineStateChanged failed");
        return retReply;
    }
    return SOFTBUS_OK;
}

int32_t ClientOnNodeBasicInfoChanged(IpcIo *data, IpcIo *reply)
{
    if (data == NULL) {
        LNN_LOGE(LNN_EVENT, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t type = 0;
    ReadInt32(data, &type);
    uint32_t infoSize = 0;
    ReadUint32(data, &infoSize);
    if (infoSize != sizeof(NodeBasicInfo)) {
        LNN_LOGE(LNN_EVENT,
            "read basic info failed. infoSize=%{public}d", infoSize);
        return SOFTBUS_NETWORK_READINT32_FAILED;
    }
    void *info = (void *)ReadBuffer(data, infoSize);
    if (info == NULL) {
        LNN_LOGE(LNN_EVENT, "read basic info failed");
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t retReply = LnnOnNodeBasicInfoChanged("", info, type);
    if (retReply != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT,
            "LnnOnNodeBasicInfoChanged failed");
        return retReply;
    }
    return SOFTBUS_OK;
}

int32_t ClientOnTimeSyncResult(IpcIo *data, IpcIo *reply)
{
    if (data == NULL) {
        LNN_LOGE(LNN_EVENT, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    uint32_t infoSize = 0;
    ReadUint32(data, &infoSize);
    if (infoSize != sizeof(TimeSyncResultInfo)) {
        LNN_LOGE(LNN_EVENT, "read info failed. infoSize=%{public}d", infoSize);
        return SOFTBUS_NETWORK_READINT32_FAILED;
    }
    void *info = (void *)ReadBuffer(data, infoSize);
    if (info == NULL) {
        LNN_LOGE(LNN_EVENT, "read info failed");
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t retCode = 0;
    ReadInt32(data, &retCode);

    int32_t retReply = LnnOnTimeSyncResult(info, retCode);
    if (retReply != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "LnnOnTimeSyncResult failed");
        return retReply;
    }
    return SOFTBUS_OK;
}

void ClientOnPublishLNNResult(IpcIo *data, IpcIo *reply)
{
    if (reply == NULL) {
        LNN_LOGE(LNN_EVENT, "invalid param");
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
        LNN_LOGE(LNN_EVENT, "invalid param");
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
        LNN_LOGE(LNN_EVENT, "invalid param");
        return;
    }
    uint32_t infoSize;
    ReadUint32(data, &infoSize);
    if (infoSize != sizeof(DeviceInfo)) {
        LNN_LOGE(LNN_EVENT,
            "read info failed. infoSize=%{public}d", infoSize);
        return;
    }
    void *info = (void *)ReadBuffer(data, infoSize);
    if (info == NULL) {
        LNN_LOGE(LNN_EVENT, "read info failed");
        return;
    }
    LnnOnRefreshDeviceFound(info);
}
