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

#include "bus_center_server_stub.h"

#include <stdint.h>

#include "ipc_skeleton.h"
#include "lnn_bus_center_ipc.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_bus_center.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_permission.h"

static int32_t CheckPermission(const char *pkgName, int32_t uid)
{
    if (pkgName == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "pkgName is null");
        return SOFTBUS_ERR;
    }
    if (!CheckBusCenterPermission(uid, pkgName)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "no permission.");
        return SOFTBUS_PERMISSION_DENIED;
    }
    return SOFTBUS_OK;
}

int32_t ServerJoinLNN(IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ServerJoinLNN ipc server pop.");
    if (req == NULL || reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return SOFTBUS_INVALID_PARAM;
    }
    size_t len;
    const char *pkgName = (const char*)ReadString(req, &len);
    uint32_t addrTypeLen;
    ReadUint32(req, &addrTypeLen);
    if (addrTypeLen != sizeof(ConnectionAddr)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerJoinLNN read addrTypeLen:%d failed!", addrTypeLen);
        return SOFTBUS_ERR;
    }
    void *addr = (void *)ReadBuffer(req, addrTypeLen);
    if (addr == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerJoinLNN read addr is null.");
        return SOFTBUS_ERR;
    }
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerJoinLNN no permission.");
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = LnnIpcServerJoin(pkgName, addr, addrTypeLen);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerJoinLNN failed.");
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
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ServerLeaveLNN ipc server pop.");
    size_t len;
    const char *pkgName = (const char*)ReadString(req, &len);
    const char *networkId = (const char*)ReadString(req, &len);
    if (networkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerLeaveLNN read networkId failed!");
        return SOFTBUS_ERR;
    }
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerLeaveLNN no permission.");
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = LnnIpcServerLeave(pkgName, networkId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerLeaveLNN failed.");
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
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ServerGetAllOnlineNodeInfo ipc server pop.");
    void *nodeInfo = NULL;
    int32_t infoNum = 0;
    size_t len;
    const char *pkgName = (const char*)ReadString(req, &len);
    uint32_t infoTypeLen;
    ReadUint32(req, &infoTypeLen);
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerGetAllOnlineNodeInfo no permission.");
        WriteInt32(reply, SOFTBUS_PERMISSION_DENIED);
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = LnnIpcGetAllOnlineNodeInfo(pkgName, &nodeInfo, infoTypeLen, &infoNum);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerGetAllOnlineNodeInfo get info failed.");
        WriteInt32(reply, SOFTBUS_ERR);
        return SOFTBUS_ERR;
    }
    if (infoNum < 0 || (infoNum > 0 && nodeInfo == NULL)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerGetAllOnlineNodeInfo node info is invalid");
        WriteInt32(reply, SOFTBUS_ERR);
        return SOFTBUS_ERR;
    }
    WriteInt32(reply, infoNum);
    if (infoNum > 0) {
        WriteUint32(reply, infoTypeLen * infoNum);
        WriteBuffer(reply, nodeInfo, infoTypeLen * infoNum);
        SoftBusFree(nodeInfo);
    }
    return SOFTBUS_OK;
}

int32_t ServerGetLocalDeviceInfo(IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ServerGetLocalDeviceInfo ipc server pop.");
    void *nodeInfo = NULL;
    size_t len;
    const char *pkgName = (const char*)ReadString(req, &len);
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerGetLocalDeviceInfo no permission.");
        return SOFTBUS_PERMISSION_DENIED;
    }
    uint32_t infoTypeLen = sizeof(NodeBasicInfo);
    nodeInfo = SoftBusCalloc(infoTypeLen);
    if (nodeInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerGetLocalDeviceInfo malloc info type length failed");
        return SOFTBUS_ERR;
    }
    int32_t ret = LnnIpcGetLocalDeviceInfo(pkgName, nodeInfo, infoTypeLen);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerGetLocalDeviceInfo get local info failed.");
        SoftBusFree(nodeInfo);
        return SOFTBUS_ERR;
    }
    WriteUint32(reply, infoTypeLen);
    WriteBuffer(reply, nodeInfo, infoTypeLen);
    SoftBusFree(nodeInfo);
    return SOFTBUS_OK;
}

int32_t ServerGetNodeKeyInfo(IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ServerGetNodeKeyInfo ipc server pop.");
    size_t length;
    const char *pkgName = (const char*)ReadString(req, &length);
    const char *networkId = (const char*)ReadString(req, &length);
    if (networkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetNodeKeyInfoInner read networkId failed!");
        return SOFTBUS_ERR;
    }
    int32_t key;
    ReadInt32(req, &key);
    int32_t infoLen  = LnnIpcGetNodeKeyInfoLen(key);
    if (infoLen == SOFTBUS_ERR) {
        return SOFTBUS_ERR;
    }
    int32_t len;
    ReadInt32(req, &len);
    if (len < infoLen) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetNodeKeyInfoInner read len is invalid param!");
        return SOFTBUS_ERR;
    }
    void *buf = SoftBusCalloc(infoLen);
    if (buf == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerGetNodeKeyInfo malloc buffer failed!");
        return SOFTBUS_ERR;
    }
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerGetNodeKeyInfo no permission.");
        SoftBusFree(buf);
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = LnnIpcGetNodeKeyInfo(pkgName, networkId, key, (unsigned char *)buf, infoLen);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerGetNodeKeyInfo get local info failed.");
        SoftBusFree(buf);
        return SOFTBUS_ERR;
    }
    WriteInt32(reply, infoLen);
    WriteBuffer(reply, buf, infoLen);
    SoftBusFree(buf);
    return SOFTBUS_OK;
}

int32_t ServerSetNodeDataChangeFlag(IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ServerSetNodeDataChangeFlag ipc server pop.");
    size_t length;
    const char *pkgName = (const char*)ReadString(req, &length);
    const char *networkId = (const char*)ReadString(req, &length);
    if (networkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SetNodeDataChangeFlag read networkId failed!");
        return SOFTBUS_ERR;
    }
    int16_t dataChangeFlag;
    ReadInt16(req, &dataChangeFlag);
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerSetNodeDataChangeFlag no permission.");
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = LnnIpcSetNodeDataChangeFlag(pkgName, networkId, dataChangeFlag);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerSetNodeDataChangeFlag get local info failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ServerStartTimeSync(IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ServerStartTimeSync ipc server pop.");
    size_t length;
    const char *pkgName = (const char*)ReadString(req, &length);
    const char *targetNetworkId = (const char*)ReadString(req, &length);
    if (targetNetworkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerStartTimeSync read targetNetworkId failed!");
        return SOFTBUS_ERR;
    }
    int32_t accuracy;
    int32_t period;
    ReadInt32(req, &accuracy);
    ReadInt32(req, &period);
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerStartTimeSync no permission.");
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = LnnIpcStartTimeSync(pkgName, targetNetworkId, accuracy, period);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerStartTimeSync start time sync failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ServerStopTimeSync(IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ServerStopTimeSync ipc server pop.");
    size_t length;
    const char *pkgName = (const char*)ReadString(req, &length);
    const char *targetNetworkId = (const char*)ReadString(req, &length);
    if (targetNetworkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerStopTimeSync read targetNetworkId failed!");
        return SOFTBUS_ERR;
    }
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerStopTimeSync no permission.");
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = LnnIpcStopTimeSync(pkgName, targetNetworkId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerStopTimeSync start time sync failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ServerPublishLNN(IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ServerPublishLNN ipc server pop.");
    if (req == NULL || reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return SOFTBUS_INVALID_PARAM;
    }
    size_t len;
    const char *pkgName = (const char*)ReadString(req, &len);
    uint32_t infoLen;
    ReadUint32(req, &infoLen);
    void *info = (void*)ReadBuffer(req, infoLen);
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerPublishLNN read info is null.");
        return SOFTBUS_ERR;
    }
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerPublishLNN no permission.");
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = LnnIpcPublishLNN(pkgName, info, infoLen);
    WriteInt32(reply, ret);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerPublishLNN failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ServerStopPublishLNN(IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ServerStopPublishLNN ipc server pop.");
    if (req == NULL || reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return SOFTBUS_INVALID_PARAM;
    }
    size_t len;
    const char *pkgName = (const char*)ReadString(req, &len);
    int32_t publishId;
    ReadInt32(req, &publishId);
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerStopPublishLNN no permission.");
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = LnnIpcStopPublishLNN(pkgName, publishId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerStopPublishLNN failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ServerRefreshLNN(IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ServerRefreshLNN ipc server pop.");
    if (req == NULL || reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return SOFTBUS_INVALID_PARAM;
    }
    size_t len;
    const char *pkgName = (const char*)ReadString(req, &len);
    uint32_t infoTypeLen;
    ReadUint32(req, &infoTypeLen);
    void *info = (void*)ReadBuffer(req, infoTypeLen);
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerRefreshLNN read info is null.");
        return SOFTBUS_ERR;
    }
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerRefreshLNN no permission.");
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = LnnIpcRefreshLNN(pkgName, info, infoTypeLen);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerRefreshLNN failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ServerStopRefreshLNN(IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ServerStopRefreshLNN ipc server pop.");
    if (req == NULL || reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return SOFTBUS_INVALID_PARAM;
    }
    size_t len;
    const char *pkgName = (const char*)ReadString(req, &len);
    int32_t refreshId;
    ReadInt32(req, &refreshId);
    int32_t callingUid = GetCallingUid();
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerStopRefreshLNN no permission.");
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = LnnIpcStopRefreshLNN(pkgName, refreshId);
    WriteInt32(reply, ret);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerStopRefreshLNN failed.");
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
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerActiveMetaNode read meta node config info failed!");
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
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerActiveMetaNode failed!");
        WriteInt32(reply, ret);
        return SOFTBUS_ERR;
    }
    WriteInt32(reply, SOFTBUS_OK);
    WriteString(reply, metaNodeId);
    return SOFTBUS_OK;
}

int32_t ServerDeactiveMetaNode(IpcIo *req, IpcIo *reply)
{
    uint32_t size;
    const char *pkgName = (const char*)ReadString(req, &size);
    const char *metaNodeId = (const char*)ReadString(req, &size);
    if (metaNodeId == NULL || size != (NETWORK_ID_BUF_LEN - 1)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR,
            "ServerDeactiveMetaNode read meta node id failed, size=%d", size);
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
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerDeactiveMetaNode failed!");
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
    ReadInt32(req, &infoNum);
    MetaNodeInfo infos[MAX_META_NODE_NUM];
    int32_t ret = CheckPermission(pkgName, GetCallingUid());
    if (ret != SOFTBUS_OK) {
        WriteInt32(reply, ret);
        return SOFTBUS_ERR;
    }
    ret = LnnIpcGetAllMetaNodeInfo(infos, &infoNum);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerGetAllMetaNodeInfo failed!");
        WriteInt32(reply, ret);
        return SOFTBUS_ERR;
    }
    WriteInt32(reply, SOFTBUS_OK);
    WriteInt32(reply, infoNum);
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
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerShiftLnnGear read pkgName failed!");
        WriteInt32(reply, SOFTBUS_INVALID_PARAM);
        return SOFTBUS_ERR;
    }
    const char *callerId = (const char*)ReadString(req, &len);
    if (callerId == NULL || len == 0 || len >= CALLER_ID_MAX_LEN) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerShiftLnnGear read callerId failed!");
        WriteInt32(reply, SOFTBUS_INVALID_PARAM);
        return SOFTBUS_ERR;
    }
    if (!ReadBool(req, &targetNetworkIdIsNULL)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerShiftLnnGear read targetNetworkIdIsNULL failed!");
        WriteInt32(reply, SOFTBUS_INVALID_PARAM);
        return SOFTBUS_ERR;
    }
    if (!targetNetworkIdIsNULL) {
        targetNetworkId = (const char*)ReadString(req, &len);
        if (targetNetworkId == NULL || len != NETWORK_ID_BUF_LEN - 1) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerShiftLnnGear read targetNetworkId failed!");
            WriteInt32(reply, SOFTBUS_INVALID_PARAM);
            return SOFTBUS_ERR;
        }
    }
    const GearMode *mode = (GearMode *)ReadRawData(req, sizeof(GearMode));
    if (mode == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerShiftLnnGear read gear mode info failed!");
        WriteInt32(reply, SOFTBUS_INVALID_PARAM);
        return SOFTBUS_ERR;
    }
    int32_t ret = CheckPermission(pkgName, GetCallingUid());
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerShiftLnnGear no permission.");
        WriteInt32(reply, ret);
        return SOFTBUS_PERMISSION_DENIED;
    }
    ret = LnnIpcShiftLNNGear(pkgName, callerId, targetNetworkId, mode);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerShiftLnnGear failed!");
        WriteInt32(reply, ret);
        return SOFTBUS_ERR;
    }
    WriteInt32(reply, SOFTBUS_OK);
    return SOFTBUS_OK;
}
