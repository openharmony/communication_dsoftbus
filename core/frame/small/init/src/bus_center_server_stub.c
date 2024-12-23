/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "bus_center_server_stub.h"

#include <stdint.h>

#include "ipc_skeleton.h"
#include "lnn_bus_center_ipc.h"
#include "lnn_log.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_bus_center.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_permission.h"

static int32_t CheckPermission(const char *pkgName, int32_t uid)
{
    if (pkgName == NULL) {
        LNN_LOGE(LNN_STATE, "pkgName is null");
        return SOFTBUS_INVALID_PKGNAME;
    }
    if (!CheckBusCenterPermission(uid, pkgName)) {
        LNN_LOGE(LNN_STATE, "no permission");
        return SOFTBUS_PERMISSION_DENIED;
    }
    return SOFTBUS_OK;
}

int32_t ServerJoinLNN(IpcIo *req, IpcIo *reply)
{
    LNN_LOGD(LNN_STATE, "ipc server pop");
    if (req == NULL || reply == NULL) {
        LNN_LOGE(LNN_STATE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    size_t len;
    const char *pkgName = (const char *)ReadString(req, &len);
    if (pkgName == NULL || len >= PKG_NAME_SIZE_MAX) {
        LNN_LOGE(LNN_STATE, "read pkgName failed");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t addrTypeLen;
    ReadUint32(req, &addrTypeLen);
    if (addrTypeLen != sizeof(ConnectionAddr)) {
        LNN_LOGE(LNN_STATE, "read addrTypeLen=%{public}d failed", addrTypeLen);
        return SOFTBUS_INVALID_PARAM;
    }
    void *addr = (void *)ReadBuffer(req, addrTypeLen);
    if (addr == NULL) {
        LNN_LOGE(LNN_STATE, "read addr is null");
        return SOFTBUS_IPC_ERR;
    }
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "no permission");
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = LnnIpcServerJoin(pkgName, 0, addr, addrTypeLen);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "LnnIpcServerJoin failed");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ServerJoinMetaNode(IpcIo *req, IpcIo *reply)
{
    (void)req;
    (void)reply;
    return SOFTBUS_OK;
}

int32_t ServerLeaveLNN(IpcIo *req, IpcIo *reply)
{
    LNN_LOGI(LNN_STATE, "ipc server pop");
    size_t len;
    const char *pkgName = (const char *)ReadString(req, &len);
    if (pkgName == NULL || len >= PKG_NAME_SIZE_MAX) {
        LNN_LOGE(LNN_STATE, "read pkgName failed");
        return SOFTBUS_INVALID_PARAM;
    }
    const char *networkId = (const char *)ReadString(req, &len);
    if (networkId == NULL || len >= NETWORK_ID_BUF_LEN) {
        LNN_LOGE(LNN_STATE, "read networkId failed");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "no permission");
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = LnnIpcServerLeave(pkgName, 0, networkId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "LnnIpcServerLeave failed");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ServerLeaveMetaNode(IpcIo *req, IpcIo *reply)
{
    (void)req;
    (void)reply;
    return SOFTBUS_OK;
}

int32_t ServerGetAllOnlineNodeInfo(IpcIo *req, IpcIo *reply)
{
    LNN_LOGI(LNN_STATE, "ipc server pop");
    void *nodeInfo = NULL;
    int32_t infoNum = 0;
    size_t len;
    const char *pkgName = (const char *)ReadString(req, &len);
    if (pkgName == NULL || len >= PKG_NAME_SIZE_MAX) {
        LNN_LOGE(LNN_STATE, "read pkgName failed");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t infoTypeLen;
    ReadUint32(req, &infoTypeLen);
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "no permission");
        WriteInt32(reply, SOFTBUS_PERMISSION_DENIED);
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = LnnIpcGetAllOnlineNodeInfo(pkgName, &nodeInfo, infoTypeLen, &infoNum);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "get info failed");
        WriteInt32(reply, ret);
        return ret;
    }
    if (infoNum < 0 || (infoNum > 0 && nodeInfo == NULL)) {
        LNN_LOGE(LNN_STATE, "node info is invalid");
        if (!(WriteInt32(reply, SOFTBUS_NETWORK_GET_ALL_NODE_INFO_ERR))) {
            LNN_LOGE(LNN_STATE, "write reply failed!");
            SoftBusFree(nodeInfo);
            return SOFTBUS_NETWORK_WRITEINT32_FAILED;
        }
    }
    if (!(WriteInt32(reply, infoNum))) {
        LNN_LOGE(LNN_STATE, "write infoNum failed!");
        SoftBusFree(nodeInfo);
        return SOFTBUS_NETWORK_WRITEINT32_FAILED;
    }
    if (infoNum > 0) {
        WriteUint32(reply, infoTypeLen * infoNum);
        WriteBuffer(reply, nodeInfo, infoTypeLen * infoNum);
        SoftBusFree(nodeInfo);
    }
    return SOFTBUS_OK;
}

int32_t ServerGetLocalDeviceInfo(IpcIo *req, IpcIo *reply)
{
    LNN_LOGD(LNN_STATE, "ipc server pop");
    void *nodeInfo = NULL;
    size_t len;
    const char *pkgName = (const char *)ReadString(req, &len);
    if (pkgName == NULL || len >= PKG_NAME_SIZE_MAX) {
        LNN_LOGE(LNN_STATE, "read pkgName failed");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "no permission");
        return SOFTBUS_PERMISSION_DENIED;
    }
    uint32_t infoTypeLen;
    ReadUint32(req, &infoTypeLen);
    if (infoTypeLen != sizeof(NodeBasicInfo)) {
        LNN_LOGE(LNN_STATE, "read infoTypeLen failed, infoTypeLen=%{public}u", infoTypeLen);
        return SOFTBUS_INVALID_PARAM;
    }
    nodeInfo = SoftBusCalloc(infoTypeLen);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_STATE, "malloc info type length failed");
        return SOFTBUS_MEM_ERR;
    }
    int32_t ret = LnnIpcGetLocalDeviceInfo(pkgName, nodeInfo, infoTypeLen);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "get local info failed");
        SoftBusFree(nodeInfo);
        return ret;
    }
    if (!(WriteUint32(reply, infoTypeLen))) {
        LNN_LOGE(LNN_STATE, "write reply failed!");
        SoftBusFree(nodeInfo);
        return SOFTBUS_NETWORK_WRITEINT32_FAILED;
    }
    WriteBuffer(reply, nodeInfo, infoTypeLen);
    SoftBusFree(nodeInfo);
    return SOFTBUS_OK;
}

static int32_t ServerRecoverGetNodeKeyInfo(void *buf, IpcIo *reply, int32_t infoLen)
{
    if (!(WriteInt32(reply, infoLen))) {
        LNN_LOGE(LNN_STATE, "write reply failed!");
        return SOFTBUS_NETWORK_WRITEINT32_FAILED;
    }
    WriteBuffer(reply, buf, infoLen);
    return SOFTBUS_OK;
}

int32_t ServerGetNodeKeyInfo(IpcIo *req, IpcIo *reply)
{
    LNN_LOGD(LNN_STATE, "ipc server pop");
    size_t length;
    const char *pkgName = (const char *)ReadString(req, &length);
    if (pkgName == NULL || length >= PKG_NAME_SIZE_MAX) {
        LNN_LOGE(LNN_STATE, "read pkgName failed");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "no permission");
        return SOFTBUS_PERMISSION_DENIED;
    }
    const char *networkId = (const char *)ReadString(req, &length);
    if (networkId == NULL || length >= NETWORK_ID_BUF_LEN) {
        LNN_LOGE(LNN_STATE, "read networkId failed");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t key;
    ReadInt32(req, &key);
    int32_t infoLen  = LnnIpcGetNodeKeyInfoLen(key);
    if (infoLen == SOFTBUS_INVALID_NUM) {
        LNN_LOGE(LNN_STATE, "get infoLen failed");
        return SOFTBUS_INVALID_NUM;
    }
    uint32_t len;
    ReadUint32(req, &len);
    if (len < (uint32_t)infoLen) {
        LNN_LOGE(LNN_STATE, "read len is invalid param, len=%{public}u, infoLen=%{public}d", len,
            infoLen);
        return SOFTBUS_INVALID_PARAM;
    }
    void *buf = SoftBusCalloc(infoLen);
    if (buf == NULL) {
        LNN_LOGE(LNN_STATE, "malloc buffer failed");
        return SOFTBUS_MEM_ERR;
    }
    int32_t ret = LnnIpcGetNodeKeyInfo(pkgName, networkId, key, (unsigned char *)buf, infoLen);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "get local info failed");
        SoftBusFree(buf);
        return ret;
    }
    ret = ServerRecoverGetNodeKeyInfo(buf, reply, infoLen);
    SoftBusFree(buf);
    return ret;
}

int32_t ServerSetNodeDataChangeFlag(IpcIo *req, IpcIo *reply)
{
    LNN_LOGD(LNN_STATE, "ipc server pop");
    size_t length;
    const char *pkgName = (const char *)ReadString(req, &length);
    if (pkgName == NULL || length >= PKG_NAME_SIZE_MAX) {
        LNN_LOGE(LNN_STATE, "read pkgName failed");
        return SOFTBUS_INVALID_PARAM;
    }
    const char *networkId = (const char *)ReadString(req, &length);
    if (networkId == NULL || length >= NETWORK_ID_BUF_LEN) {
        LNN_LOGE(LNN_STATE, "read networkId failed");
        return SOFTBUS_INVALID_PARAM;
    }
    int16_t dataChangeFlag;
    ReadInt16(req, &dataChangeFlag);
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "no permission");
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = LnnIpcSetNodeDataChangeFlag(pkgName, networkId, dataChangeFlag);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "get local info failed");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ServerRegDataLevelChangeCb(IpcIo *req, IpcIo *reply)
{
    (void)req;
    (void)reply;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t ServerUnregDataLevelChangeCb(IpcIo *req, IpcIo *reply)
{
    (void)req;
    (void)reply;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t ServerSetDataLevel(IpcIo *req, IpcIo *reply)
{
    (void)req;
    (void)reply;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t ServerStartTimeSync(IpcIo *req, IpcIo *reply)
{
    LNN_LOGD(LNN_STATE, "ipc server pop");
    size_t length;
    const char *pkgName = (const char *)ReadString(req, &length);
    if (pkgName == NULL || length >= PKG_NAME_SIZE_MAX) {
        LNN_LOGE(LNN_STATE, "read pkgName failed");
        return SOFTBUS_INVALID_PARAM;
    }
    const char *targetNetworkId = (const char *)ReadString(req, &length);
    if (targetNetworkId == NULL || length >= NETWORK_ID_BUF_LEN) {
        LNN_LOGE(LNN_STATE, "read targetNetworkId failed");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t accuracy;
    int32_t period;
    ReadInt32(req, &accuracy);
    ReadInt32(req, &period);
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "no permission");
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = LnnIpcStartTimeSync(pkgName, 0, targetNetworkId, accuracy, period);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "start time sync failed");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ServerStopTimeSync(IpcIo *req, IpcIo *reply)
{
    LNN_LOGI(LNN_STATE, "ipc server pop");
    size_t length;
    const char *pkgName = (const char *)ReadString(req, &length);
    if (pkgName == NULL || length >= PKG_NAME_SIZE_MAX) {
        LNN_LOGE(LNN_STATE, "read pkgName failed");
        return SOFTBUS_INVALID_PARAM;
    }
    const char *targetNetworkId = (const char *)ReadString(req, &length);
    if (targetNetworkId == NULL || length >= NETWORK_ID_BUF_LEN) {
        LNN_LOGE(LNN_STATE, "read targetNetworkId failed");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "no permission");
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = LnnIpcStopTimeSync(pkgName, targetNetworkId, 0);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "start time sync failed");
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t ServerRecoverPublishLNN(const char *pkgName, PublishInfo *info, IpcIo *reply)
{
    int32_t ret = LnnIpcPublishLNN(pkgName, info);
    WriteInt32(reply, ret);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "LnnIpcPublishLNN failed");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ServerPublishLNN(IpcIo *req, IpcIo *reply)
{
    LNN_LOGD(LNN_STATE, "ipc server pop");
    if (req == NULL || reply == NULL) {
        LNN_LOGE(LNN_STATE, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    size_t len;
    const char *pkgName = (const char *)ReadString(req, &len);
    if (pkgName == NULL || len >= PKG_NAME_SIZE_MAX) {
        LNN_LOGE(LNN_STATE, "read pkgName failed");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "no permission");
        return SOFTBUS_PERMISSION_DENIED;
    }
    PublishInfo info;
    (void)memset_s(&info, sizeof(PublishInfo), 0, sizeof(PublishInfo));
    ReadInt32(req, &info.publishId);
    int32_t mode, medium, freq;
    ReadInt32(req, &mode);
    ReadInt32(req, &medium);
    ReadInt32(req, &freq);
    info.mode = (DiscoverMode)mode;
    info.medium = (ExchangeMedium)medium;
    info.freq = (ExchangeFreq)freq;
    info.capability = (const char *)ReadString(req, &len);
    if (info.capability == NULL) {
        LNN_LOGE(LNN_STATE, "read capability is null");
        return SOFTBUS_IPC_ERR;
    }
    ReadUint32(req, &info.dataLen);
    if (info.dataLen > 0 && info.dataLen < MAX_CAPABILITYDATA_LEN) {
        info.capabilityData = (unsigned char *)ReadString(req, &len);
        if (info.capabilityData == NULL) {
            LNN_LOGE(LNN_STATE, "read capabilityData is null");
            return SOFTBUS_IPC_ERR;
        }
    } else {
        info.capabilityData = NULL;
        info.dataLen = 0;
    }
    ReadBool(req, &info.ranging);
    return ServerRecoverPublishLNN(pkgName, &info, reply);
}

int32_t ServerStopPublishLNN(IpcIo *req, IpcIo *reply)
{
    LNN_LOGD(LNN_STATE, "ipc server pop");
    if (req == NULL || reply == NULL) {
        LNN_LOGE(LNN_STATE, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    size_t len;
    const char *pkgName = (const char *)ReadString(req, &len);
    if (pkgName == NULL || len >= PKG_NAME_SIZE_MAX) {
        LNN_LOGE(LNN_STATE, "read pkgName failed");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t publishId;
    ReadInt32(req, &publishId);
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "no permission");
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = LnnIpcStopPublishLNN(pkgName, publishId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "LnnIpcStopPublishLNN failed");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ServerRefreshLNN(IpcIo *req, IpcIo *reply)
{
    LNN_LOGD(LNN_STATE, "ipc server pop");
    LNN_CHECK_AND_RETURN_RET_LOGE((req != NULL && reply != NULL), SOFTBUS_INVALID_PARAM, LNN_STATE, "invalid param");

    size_t len;
    const char *pkgName = (const char *)ReadString(req, &len);
    if (pkgName == NULL || len >= PKG_NAME_SIZE_MAX) {
        LNN_LOGE(LNN_STATE, "read pkgName failed");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t callingUid = GetCallingUid();
    LNN_CHECK_AND_RETURN_RET_LOGE((
        CheckPermission(pkgName, callingUid) == SOFTBUS_OK), SOFTBUS_PERMISSION_DENIED, LNN_STATE, "no permission");

    SubscribeInfo info;
    int32_t mode;
    int32_t medium;
    int32_t freq;
    (void)memset_s(&info, sizeof(SubscribeInfo), 0, sizeof(SubscribeInfo));
    LNN_CHECK_AND_RETURN_RET_LOGE(
        ReadInt32(req, &info.subscribeId), SOFTBUS_IPC_ERR, LNN_STATE, "read subscribeId failed");
    LNN_CHECK_AND_RETURN_RET_LOGE(ReadInt32(req, &mode), SOFTBUS_IPC_ERR, LNN_STATE, "read mode failed");
    LNN_CHECK_AND_RETURN_RET_LOGE(ReadInt32(req, &medium), SOFTBUS_IPC_ERR, LNN_STATE, "read medium failed");
    LNN_CHECK_AND_RETURN_RET_LOGE(ReadInt32(req, &freq), SOFTBUS_IPC_ERR, LNN_STATE, "read freq failed");
    info.mode = (DiscoverMode)mode;
    info.medium = (ExchangeMedium)medium;
    info.freq = (ExchangeFreq)freq;
    LNN_CHECK_AND_RETURN_RET_LOGE(
        ReadBool(req, &info.isSameAccount), SOFTBUS_IPC_ERR, LNN_STATE, "read isSameAccount failed");
    LNN_CHECK_AND_RETURN_RET_LOGE(
        ReadBool(req, &info.isWakeRemote), SOFTBUS_IPC_ERR, LNN_STATE, "read isWakeRemote failed");
    info.capability = (const char *)ReadString(req, &len);
    LNN_CHECK_AND_RETURN_RET_LOGE((info.capability != NULL), SOFTBUS_IPC_ERR, LNN_STATE, "read capability failed");
    LNN_CHECK_AND_RETURN_RET_LOGE(
        ReadUint32(req, &info.dataLen), SOFTBUS_IPC_ERR, LNN_STATE, "read dataLen failed");
    if (info.dataLen > 0 && info.dataLen < MAX_CAPABILITYDATA_LEN) {
        info.capabilityData = (unsigned char *)ReadString(req, &len);
        LNN_CHECK_AND_RETURN_RET_LOGE(
            (info.capabilityData != NULL), SOFTBUS_IPC_ERR, LNN_STATE, "read capabilityData failed");
    } else {
        info.capabilityData = NULL;
        info.dataLen = 0;
    }
    int32_t ret = LnnIpcRefreshLNN(pkgName, 0, &info);
    LNN_CHECK_AND_RETURN_RET_LOGE(WriteInt32(reply, ret), ret, LNN_STATE, "write reply failed");
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "refresh LNN failed, ret = %{public}d", ret);
    }
    return ret;
}

int32_t ServerStopRefreshLNN(IpcIo *req, IpcIo *reply)
{
    LNN_LOGD(LNN_STATE, "ipc server pop");
    if (req == NULL || reply == NULL) {
        LNN_LOGE(LNN_STATE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    size_t len;
    const char *pkgName = (const char *)ReadString(req, &len);
    if (pkgName == NULL || len >= PKG_NAME_SIZE_MAX) {
        LNN_LOGE(LNN_STATE, "read pkgName failed");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t refreshId;
    ReadInt32(req, &refreshId);
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "no permission");
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = LnnIpcStopRefreshLNN(pkgName, 0, refreshId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "LnnIpcStopRefreshLNN failed");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ServerActiveMetaNode(IpcIo *req, IpcIo *reply)
{
    size_t size;
    const char *pkgName = (const char *)ReadString(req, &size);
    if (pkgName == NULL || size >= PKG_NAME_SIZE_MAX) {
        LNN_LOGE(LNN_STATE, "read pkgName failed");
        return SOFTBUS_INVALID_PARAM;
    }
    MetaNodeConfigInfo *info = (MetaNodeConfigInfo *)ReadRawData(req, sizeof(MetaNodeConfigInfo));
    if (info == NULL) {
        LNN_LOGE(LNN_STATE, "read meta node config info failed");
        WriteInt32(reply, SOFTBUS_INVALID_PARAM);
        return SOFTBUS_IPC_ERR;
    }
    int32_t ret = CheckPermission(pkgName, GetCallingUid());
    if (ret != SOFTBUS_OK) {
        WriteInt32(reply, ret);
        return ret;
    }
    char metaNodeId[NETWORK_ID_BUF_LEN] = {0};
    ret = LnnIpcActiveMetaNode(info, metaNodeId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "LnnIpcActiveMetaNode failed");
        WriteInt32(reply, ret);
        return ret;
    }
    if (!(WriteInt32(reply, SOFTBUS_OK))) {
        LNN_LOGE(LNN_STATE, "write SOFTBUS_OK to reply failed!");
        return SOFTBUS_NETWORK_WRITEINT32_FAILED;
    }
    if (!(WriteString(reply, metaNodeId))) {
        LNN_LOGE(LNN_STATE, "write metaNodeId to reply failed!");
        return SOFTBUS_NETWORK_WRITEINT32_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t ServerDeactiveMetaNode(IpcIo *req, IpcIo *reply)
{
    size_t size;
    const char *pkgName = (const char *)ReadString(req, &size);
    if (pkgName == NULL || size >= PKG_NAME_SIZE_MAX) {
        LNN_LOGE(LNN_STATE, "read pkgName failed");
        return SOFTBUS_INVALID_PARAM;
    }
    const char *metaNodeId = (const char *)ReadString(req, &size);
    if (metaNodeId == NULL || size != (NETWORK_ID_BUF_LEN - 1)) {
        LNN_LOGE(LNN_STATE, "read meta node id failed, size=%{public}d", size);
        WriteInt32(reply, SOFTBUS_INVALID_PARAM);
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CheckPermission(pkgName, GetCallingUid());
    if (ret != SOFTBUS_OK) {
        WriteInt32(reply, ret);
        return ret;
    }
    ret = LnnIpcDeactiveMetaNode(metaNodeId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "LnnIpcDeactiveMetaNode failed");
        WriteInt32(reply, ret);
        return ret;
    }
    WriteInt32(reply, SOFTBUS_OK);
    return SOFTBUS_OK;
}

int32_t ServerGetAllMetaNodeInfo(IpcIo *req, IpcIo *reply)
{
    size_t size;
    const char *pkgName = (const char *)ReadString(req, &size);
    if (pkgName == NULL || size >= PKG_NAME_SIZE_MAX) {
        LNN_LOGE(LNN_STATE, "read pkgName failed");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t infoNum;
    if (!(ReadInt32(req, &infoNum))) {
        LNN_LOGE(LNN_STATE, "read infoNum failed!");
        return SOFTBUS_INVALID_PARAM;
    }
    if ((uint32_t)infoNum > MAX_META_NODE_NUM) {
        LNN_LOGE(LNN_STATE, "inivalid param, infoNum=%{public}d, maxNum=%{public}d", infoNum, MAX_META_NODE_NUM);
        return SOFTBUS_INVALID_PARAM;
    }
    MetaNodeInfo infos[MAX_META_NODE_NUM];
    int32_t ret = CheckPermission(pkgName, GetCallingUid());
    if (ret != SOFTBUS_OK) {
        WriteInt32(reply, ret);
        return ret;
    }
    ret = LnnIpcGetAllMetaNodeInfo(infos, &infoNum);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "LnnIpcGetAllMetaNodeInfo failed");
        WriteInt32(reply, ret);
        return ret;
    }
    if (!(WriteInt32(reply, SOFTBUS_OK))) {
        LNN_LOGE(LNN_STATE, "write SOFTBUS_OK to reply failed!");
        return SOFTBUS_NETWORK_WRITEINT32_FAILED;
    }
    if (!(WriteInt32(reply, infoNum))) {
        LNN_LOGE(LNN_STATE, "write infoNum to reply failed!");
        return SOFTBUS_NETWORK_WRITEINT32_FAILED;
    }
    if (infoNum > 0) {
        WriteUint32(reply, infoNum * sizeof(MetaNodeInfo));
        WriteBuffer(reply, infos, infoNum * sizeof(MetaNodeInfo));
    }
    return SOFTBUS_OK;
}

int32_t ServerShiftLnnGear(IpcIo *req, IpcIo *reply)
{
    size_t len;
    bool targetNetworkIdIsNULL = false;
    const char *targetNetworkId = NULL;

    const char *pkgName = (const char *)ReadString(req, &len);
    if (pkgName == NULL || len >= PKG_NAME_SIZE_MAX) {
        LNN_LOGE(LNN_STATE, "read pkgName failed");
        goto ERR_RETURN;
    }
    const char *callerId = (const char *)ReadString(req, &len);
    if (callerId == NULL || len == 0 || len >= CALLER_ID_MAX_LEN) {
        LNN_LOGE(LNN_STATE, "read callerId failed");
        goto ERR_RETURN;
    }
    if (!ReadBool(req, &targetNetworkIdIsNULL)) {
        LNN_LOGE(LNN_STATE, "read targetNetworkIdIsNULL failed");
        goto ERR_RETURN;
    }
    if (!targetNetworkIdIsNULL) {
        targetNetworkId = (const char *)ReadString(req, &len);
        if (targetNetworkId == NULL || len != NETWORK_ID_BUF_LEN - 1) {
            LNN_LOGE(LNN_STATE, "read targetNetworkId failed");
            goto ERR_RETURN;
        }
    }
    const GearMode *mode = (GearMode *)ReadRawData(req, sizeof(GearMode));
    if (mode == NULL) {
        LNN_LOGE(LNN_STATE, "read gear mode info failed");
        goto ERR_RETURN;
    }
    int32_t ret = CheckPermission(pkgName, GetCallingUid());
    if (ret != SOFTBUS_OK) {
        WriteInt32(reply, ret);
        return SOFTBUS_PERMISSION_DENIED;
    }
    ret = LnnIpcShiftLNNGear(pkgName, callerId, targetNetworkId, mode);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "LnnIpcShiftLNNGear failed");
        WriteInt32(reply, ret);
        return ret;
    }
    if (!(WriteInt32(reply, SOFTBUS_OK))) {
        LNN_LOGE(LNN_STATE, "write reply failed!");
        return SOFTBUS_NETWORK_WRITEINT32_FAILED;
    }
    return SOFTBUS_OK;

ERR_RETURN:
    WriteInt32(reply, SOFTBUS_INVALID_PARAM);
    return SOFTBUS_IPC_ERR;
}
