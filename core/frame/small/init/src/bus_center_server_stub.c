/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include "softbus_errcode.h"
#include "softbus_permission.h"

static int32_t CheckPermission(const char *pkgName, int32_t uid)
{
    if (pkgName == NULL) {
        LNN_LOGE(LNN_STATE, "pkgName is null");
        return SOFTBUS_ERR;
    }
    if (!CheckBusCenterPermission(uid, pkgName)) {
        LNN_LOGE(LNN_STATE, "no permission");
        return SOFTBUS_PERMISSION_DENIED;
    }
    return SOFTBUS_OK;
}

int32_t ServerJoinLNN(IpcIo *req, IpcIo *reply)
{
    LNN_LOGD(LNN_STATE, "ServerJoinLNN ipc server pop");
    if (req == NULL || reply == NULL) {
        LNN_LOGE(LNN_STATE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    size_t len;
    const char *pkgName = (const char*)ReadString(req, &len);
    uint32_t addrTypeLen;
    ReadUint32(req, &addrTypeLen);
    if (addrTypeLen != sizeof(ConnectionAddr)) {
        LNN_LOGE(LNN_STATE, "ServerJoinLNN read addrTypeLen=%{public}d failed", addrTypeLen);
        return SOFTBUS_ERR;
    }
    void *addr = (void *)ReadBuffer(req, addrTypeLen);
    if (addr == NULL) {
        LNN_LOGE(LNN_STATE, "ServerJoinLNN read addr is null");
        return SOFTBUS_IPC_ERR;
    }
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "ServerJoinLNN no permission");
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = LnnIpcServerJoin(pkgName, 0, addr, addrTypeLen);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "ServerJoinLNN failed");
        return SOFTBUS_ERR;
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
    LNN_LOGI(LNN_STATE, "ServerLeaveLNN ipc server pop");
    size_t len;
    const char *pkgName = (const char*)ReadString(req, &len);
    const char *networkId = (const char*)ReadString(req, &len);
    if (networkId == NULL) {
        LNN_LOGE(LNN_STATE, "ServerLeaveLNN read networkId failed");
        return SOFTBUS_ERR;
    }
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "ServerLeaveLNN no permission");
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = LnnIpcServerLeave(pkgName, 0, networkId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "ServerLeaveLNN failed");
        return SOFTBUS_ERR;
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
    LNN_LOGI(LNN_STATE, "ServerGetAllOnlineNodeInfo ipc server pop");
    void *nodeInfo = NULL;
    int32_t infoNum = 0;
    size_t len;
    const char *pkgName = (const char*)ReadString(req, &len);
    uint32_t infoTypeLen;
    ReadUint32(req, &infoTypeLen);
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "ServerGetAllOnlineNodeInfo no permission");
        WriteInt32(reply, SOFTBUS_PERMISSION_DENIED);
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = LnnIpcGetAllOnlineNodeInfo(pkgName, &nodeInfo, infoTypeLen, &infoNum);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "ServerGetAllOnlineNodeInfo get info failed");
        WriteInt32(reply, SOFTBUS_ERR);
        return SOFTBUS_ERR;
    }
    if (infoNum < 0 || (infoNum > 0 && nodeInfo == NULL)) {
        LNN_LOGE(LNN_STATE, "ServerGetAllOnlineNodeInfo node info is invalid");
        if (!(WriteInt32(reply, SOFTBUS_ERR))) {
            LNN_LOGE(LNN_STATE, "ServerGetAllOnlineNodeInfo write reply failed!");
            SoftBusFree(nodeInfo);
            return SOFTBUS_ERR;
        }
    }
    if (!(WriteInt32(reply, infoNum))) {
        LNN_LOGE(LNN_STATE, "ServerGetAllOnlineNodeInfo write infoNum failed!");
        SoftBusFree(nodeInfo);
        return SOFTBUS_ERR;
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
    LNN_LOGD(LNN_STATE, "ServerGetLocalDeviceInfo ipc server pop");
    void *nodeInfo = NULL;
    size_t len;
    const char *pkgName = (const char*)ReadString(req, &len);
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "ServerGetLocalDeviceInfo no permission");
        return SOFTBUS_PERMISSION_DENIED;
    }
    uint32_t infoTypeLen = sizeof(NodeBasicInfo);
    nodeInfo = SoftBusCalloc(infoTypeLen);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_STATE, "ServerGetLocalDeviceInfo malloc info type length failed");
        return SOFTBUS_MEM_ERR;
    }
    int32_t ret = LnnIpcGetLocalDeviceInfo(pkgName, nodeInfo, infoTypeLen);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "ServerGetLocalDeviceInfo get local info failed");
        SoftBusFree(nodeInfo);
        return SOFTBUS_ERR;
    }
    if (!(WriteUint32(reply, infoTypeLen))) {
        LNN_LOGE(LNN_STATE, "ServerGetLocalDeviceInfo write reply failed!");
        SoftBusFree(nodeInfo);
        return SOFTBUS_ERR;
    }
    WriteBuffer(reply, nodeInfo, infoTypeLen);
    SoftBusFree(nodeInfo);
    return SOFTBUS_OK;
}

int32_t ServerGetNodeKeyInfo(IpcIo *req, IpcIo *reply)
{
    LNN_LOGD(LNN_STATE, "ServerGetNodeKeyInfo ipc server pop");
    size_t length;
    const char *pkgName = (const char*)ReadString(req, &length);
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "ServerGetNodeKeyInfo no permission");
        return SOFTBUS_PERMISSION_DENIED;
    }
    const char *networkId = (const char*)ReadString(req, &length);
    if (networkId == NULL) {
        LNN_LOGE(LNN_STATE, "GetNodeKeyInfoInner read networkId failed");
        return SOFTBUS_ERR;
    }
    int32_t key;
    ReadInt32(req, &key);
    int32_t infoLen  = LnnIpcGetNodeKeyInfoLen(key);
    if (infoLen == SOFTBUS_ERR) {
        LNN_LOGE(LNN_STATE, "GetNodeKeyInfoInner get infoLen failed");
        return SOFTBUS_ERR;
    }
    int32_t len;
    ReadInt32(req, &len);
    if (len < infoLen) {
        LNN_LOGE(LNN_STATE, "GetNodeKeyInfoInner read len is invalid param, len=%{public}d, infoLen=%{public}d", len,
            infoLen);
        return SOFTBUS_ERR;
    }
    void *buf = SoftBusCalloc(infoLen);
    if (buf == NULL) {
        LNN_LOGE(LNN_STATE, "ServerGetNodeKeyInfo malloc buffer failed");
        return SOFTBUS_MEM_ERR;
    }
    int32_t ret = LnnIpcGetNodeKeyInfo(pkgName, networkId, key, (unsigned char *)buf, infoLen);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "ServerGetNodeKeyInfo get local info failed");
        SoftBusFree(buf);
        return SOFTBUS_ERR;
    }
    if (!(WriteInt32(reply, infoLen))) {
        LNN_LOGE(LNN_STATE, "GetNodeKeyInfoInner write reply failed!");
        SoftBusFree(buf);
        return SOFTBUS_ERR;
    }
    WriteBuffer(reply, buf, infoLen);
    SoftBusFree(buf);
    return SOFTBUS_OK;
}

int32_t ServerSetNodeDataChangeFlag(IpcIo *req, IpcIo *reply)
{
    LNN_LOGD(LNN_STATE, "ServerSetNodeDataChangeFlag ipc server pop");
    size_t length;
    const char *pkgName = (const char*)ReadString(req, &length);
    const char *networkId = (const char*)ReadString(req, &length);
    if (networkId == NULL) {
        LNN_LOGE(LNN_STATE, "SetNodeDataChangeFlag read networkId failed");
        return SOFTBUS_ERR;
    }
    int16_t dataChangeFlag;
    ReadInt16(req, &dataChangeFlag);
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "ServerSetNodeDataChangeFlag no permission");
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = LnnIpcSetNodeDataChangeFlag(pkgName, networkId, dataChangeFlag);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "ServerSetNodeDataChangeFlag get local info failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ServerStartTimeSync(IpcIo *req, IpcIo *reply)
{
    LNN_LOGD(LNN_STATE, "ServerStartTimeSync ipc server pop");
    size_t length;
    const char *pkgName = (const char*)ReadString(req, &length);
    const char *targetNetworkId = (const char*)ReadString(req, &length);
    if (targetNetworkId == NULL) {
        LNN_LOGE(LNN_STATE, "ServerStartTimeSync read targetNetworkId failed");
        return SOFTBUS_ERR;
    }
    int32_t accuracy;
    int32_t period;
    ReadInt32(req, &accuracy);
    ReadInt32(req, &period);
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "ServerStartTimeSync no permission");
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = LnnIpcStartTimeSync(pkgName, 0, targetNetworkId, accuracy, period);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "ServerStartTimeSync start time sync failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ServerStopTimeSync(IpcIo *req, IpcIo *reply)
{
    LNN_LOGI(LNN_STATE, "ServerStopTimeSync ipc server pop");
    size_t length;
    const char *pkgName = (const char*)ReadString(req, &length);
    const char *targetNetworkId = (const char*)ReadString(req, &length);
    if (targetNetworkId == NULL) {
        LNN_LOGE(LNN_STATE, "ServerStopTimeSync read targetNetworkId failed");
        return SOFTBUS_ERR;
    }
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "ServerStopTimeSync no permission");
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = LnnIpcStopTimeSync(pkgName, targetNetworkId, 0);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "ServerStopTimeSync start time sync failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ServerPublishLNN(IpcIo *req, IpcIo *reply)
{
    LNN_LOGD(LNN_STATE, "ServerPublishLNN ipc server pop");
    if (req == NULL || reply == NULL) {
        LNN_LOGE(LNN_STATE, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    size_t len;
    const char *pkgName = (const char*)ReadString(req, &len);
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "ServerPublishLNN no permission");
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
        LNN_LOGE(LNN_STATE, "ServerPublishLNN read capability is null");
        return SOFTBUS_IPC_ERR;
    }
    ReadUint32(req, &info.dataLen);
    if (info.dataLen > 0 && info.dataLen < MAX_CAPABILITYDATA_LEN) {
        info.capabilityData = (unsigned char *)ReadString(req, &len);
        if (info.capabilityData == NULL) {
            LNN_LOGE(LNN_STATE, "ServerPublishLNN read capabilityData is null");
            return SOFTBUS_IPC_ERR;
        }
    } else {
        info.capabilityData = NULL;
        info.dataLen = 0;
    }
    ReadBool(req, &info.ranging);
    int32_t ret = LnnIpcPublishLNN(pkgName, &info);
    WriteInt32(reply, ret);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "ServerPublishLNN failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ServerStopPublishLNN(IpcIo *req, IpcIo *reply)
{
    LNN_LOGD(LNN_STATE, "ServerStopPublishLNN ipc server pop");
    if (req == NULL || reply == NULL) {
        LNN_LOGE(LNN_STATE, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    size_t len;
    const char *pkgName = (const char*)ReadString(req, &len);
    int32_t publishId;
    ReadInt32(req, &publishId);
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "ServerStopPublishLNN no permission");
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = LnnIpcStopPublishLNN(pkgName, publishId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "ServerStopPublishLNN failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ServerRefreshLNN(IpcIo *req, IpcIo *reply)
{
    LNN_LOGD(LNN_STATE, "ServerRefreshLNN ipc server pop");
    if (req == NULL || reply == NULL) {
        LNN_LOGE(LNN_STATE, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    size_t len;
    const char *pkgName = (const char*)ReadString(req, &len);
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "ServerRefreshLNN no permission");
        return SOFTBUS_PERMISSION_DENIED;
    }

    SubscribeInfo info;
    (void)memset_s(&info, sizeof(SubscribeInfo), 0, sizeof(SubscribeInfo));
    if (!(ReadInt32(req, &info.subscribeId))) {
        LNN_LOGE(LNN_STATE, "ServerRefreshLNN read subscribeId failed!");
        return SOFTBUS_ERR;
    }
    int32_t mode;
    int32_t medium;
    int32_t freq;
    if (!(ReadInt32(req, &mode))) {
        LNN_LOGE(LNN_STATE, "ServerRefreshLNN read mode failed!");
        return SOFTBUS_ERR;
    }
    if (!(ReadInt32(req, &medium))) {
        LNN_LOGE(LNN_STATE, "ServerRefreshLNN read medium failed!");
        return SOFTBUS_ERR;
    }
    if (!(ReadInt32(req, &freq))) {
        LNN_LOGE(LNN_STATE, "ServerRefreshLNN read freq failed!");
        return SOFTBUS_ERR;
    }
    info.mode = (DiscoverMode)mode;
    info.medium = (ExchangeMedium)medium;
    info.freq = (ExchangeFreq)freq;
    ReadBool(req, &info.isSameAccount);
    ReadBool(req, &info.isWakeRemote);
    info.capability = (const char *)ReadString(req, &len);
    if (info.capability == NULL) {
        LNN_LOGE(LNN_STATE, "ServerRefreshLNN read capability is null");
        return SOFTBUS_IPC_ERR;
    }
    ReadUint32(req, &info.dataLen);
    if (info.dataLen > 0 && info.dataLen < MAX_CAPABILITYDATA_LEN) {
        info.capabilityData = (unsigned char *)ReadString(req, &len);
        if (info.capabilityData == NULL) {
            LNN_LOGE(LNN_STATE, "ServerRefreshLNN read capabilityData is null");
            return SOFTBUS_IPC_ERR;
        }
    } else {
        info.capabilityData = NULL;
        info.dataLen = 0;
    }
    int32_t ret = LnnIpcRefreshLNN(pkgName, 0, &info);
    WriteInt32(reply, ret);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "ServerRefreshLNN failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ServerStopRefreshLNN(IpcIo *req, IpcIo *reply)
{
    LNN_LOGD(LNN_STATE, "ServerStopRefreshLNN ipc server pop");
    if (req == NULL || reply == NULL) {
        LNN_LOGE(LNN_STATE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    size_t len;
    const char *pkgName = (const char*)ReadString(req, &len);
    int32_t refreshId;
    ReadInt32(req, &refreshId);
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "ServerStopRefreshLNN no permission");
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = LnnIpcStopRefreshLNN(pkgName, 0, refreshId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "ServerStopRefreshLNN failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ServerActiveMetaNode(IpcIo *req, IpcIo *reply)
{
    uint32_t size;
    const char *pkgName = (const char*)ReadString(req, &size);
    MetaNodeConfigInfo *info = (MetaNodeConfigInfo *)ReadRawData(req, sizeof(MetaNodeConfigInfo));
    if (info == NULL || size != sizeof(MetaNodeConfigInfo)) {
        LNN_LOGE(LNN_STATE, "ServerActiveMetaNode read meta node config info failed");
        WriteInt32(reply, SOFTBUS_INVALID_PARAM);
        return SOFTBUS_ERR;
    }
    int32_t ret = CheckPermission(pkgName, GetCallingUid());
    if (ret != SOFTBUS_OK) {
        WriteInt32(reply, ret);
        return SOFTBUS_ERR;
    }
    char metaNodeId[NETWORK_ID_BUF_LEN] = {0};
    ret = LnnIpcActiveMetaNode(info, metaNodeId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "ServerActiveMetaNode failed");
        WriteInt32(reply, ret);
        return SOFTBUS_ERR;
    }
    if (!(WriteInt32(reply, SOFTBUS_OK))) {
        LNN_LOGE(LNN_STATE, "ServerActiveMetaNode write SOFTBUS_OK to reply failed!");
        return SOFTBUS_ERR;
    }
    if (!(WriteString(reply, metaNodeId))) {
        LNN_LOGE(LNN_STATE, "ServerActiveMetaNode write metaNodeId to reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ServerDeactiveMetaNode(IpcIo *req, IpcIo *reply)
{
    uint32_t size;
    const char *pkgName = (const char*)ReadString(req, &size);
    const char *metaNodeId = (const char*)ReadString(req, &size);
    if (metaNodeId == NULL || size != (NETWORK_ID_BUF_LEN - 1)) {
        LNN_LOGE(LNN_STATE, "ServerDeactiveMetaNode read meta node id failed, size=%{public}d", size);
        WriteInt32(reply, SOFTBUS_INVALID_PARAM);
        return SOFTBUS_ERR;
    }
    int32_t ret = CheckPermission(pkgName, GetCallingUid());
    if (ret != SOFTBUS_OK) {
        WriteInt32(reply, ret);
        return SOFTBUS_ERR;
    }
    ret = LnnIpcDeactiveMetaNode(metaNodeId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "ServerDeactiveMetaNode failed");
        WriteInt32(reply, ret);
        return SOFTBUS_ERR;
    }
    WriteInt32(reply, SOFTBUS_OK);
    return SOFTBUS_OK;
}

int32_t ServerGetAllMetaNodeInfo(IpcIo *req, IpcIo *reply)
{
    uint32_t size;
    const char *pkgName = (const char*)ReadString(req, &size);
    int32_t infoNum;
    if (!(ReadInt32(req, &infoNum))) {
        LNN_LOGE(LNN_STATE, "ServerGetAllMetaNodeInfo read infoNum failed!");
        return SOFTBUS_ERR;
    }
    MetaNodeInfo infos[MAX_META_NODE_NUM];
    int32_t ret = CheckPermission(pkgName, GetCallingUid());
    if (ret != SOFTBUS_OK) {
        WriteInt32(reply, ret);
        return SOFTBUS_ERR;
    }
    ret = LnnIpcGetAllMetaNodeInfo(infos, &infoNum);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "ServerGetAllMetaNodeInfo failed");
        WriteInt32(reply, ret);
        return SOFTBUS_ERR;
    }
    if (!(WriteInt32(reply, SOFTBUS_OK))) {
        LNN_LOGE(LNN_STATE, "ServerGetAllMetaNodeInfo write SOFTBUS_OK to reply failed!");
        return SOFTBUS_ERR;
    }
    if (!(WriteInt32(reply, infoNum))) {
        LNN_LOGE(LNN_STATE, "ServerGetAllMetaNodeInfo write infoNum to reply failed!");
        return SOFTBUS_ERR;
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

    const char *pkgName = (const char*)ReadString(req, &len);
    if (pkgName == NULL || len >= PKG_NAME_SIZE_MAX) {
        LNN_LOGE(LNN_STATE, "ServerShiftLnnGear read pkgName failed");
        WriteInt32(reply, SOFTBUS_INVALID_PARAM);
        return SOFTBUS_ERR;
    }
    const char *callerId = (const char*)ReadString(req, &len);
    if (callerId == NULL || len == 0 || len >= CALLER_ID_MAX_LEN) {
        LNN_LOGE(LNN_STATE, "ServerShiftLnnGear read callerId failed");
        WriteInt32(reply, SOFTBUS_INVALID_PARAM);
        return SOFTBUS_ERR;
    }
    if (!ReadBool(req, &targetNetworkIdIsNULL)) {
        LNN_LOGE(LNN_STATE, "ServerShiftLnnGear read targetNetworkIdIsNULL failed");
        WriteInt32(reply, SOFTBUS_INVALID_PARAM);
        return SOFTBUS_ERR;
    }
    if (!targetNetworkIdIsNULL) {
        targetNetworkId = (const char*)ReadString(req, &len);
        if (targetNetworkId == NULL || len != NETWORK_ID_BUF_LEN - 1) {
            LNN_LOGE(LNN_STATE, "ServerShiftLnnGear read targetNetworkId failed");
            WriteInt32(reply, SOFTBUS_INVALID_PARAM);
            return SOFTBUS_ERR;
        }
    }
    const GearMode *mode = (GearMode *)ReadRawData(req, sizeof(GearMode));
    if (mode == NULL) {
        LNN_LOGE(LNN_STATE, "ServerShiftLnnGear read gear mode info failed");
        WriteInt32(reply, SOFTBUS_INVALID_PARAM);
        return SOFTBUS_ERR;
    }
    int32_t ret = CheckPermission(pkgName, GetCallingUid());
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "ServerShiftLnnGear no permission");
        WriteInt32(reply, ret);
        return SOFTBUS_PERMISSION_DENIED;
    }
    ret = LnnIpcShiftLNNGear(pkgName, callerId, targetNetworkId, mode);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "ServerShiftLnnGear failed");
        WriteInt32(reply, ret);
        return SOFTBUS_ERR;
    }
    if (!(WriteInt32(reply, SOFTBUS_OK))) {
        LNN_LOGE(LNN_STATE, "ServerShiftLnnGear write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}
