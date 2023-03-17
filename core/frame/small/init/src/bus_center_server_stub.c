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

#include "liteipc_adapter.h"
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

int32_t ServerJoinLNN(const void *origin, IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ServerJoinLNN ipc server pop.");
    if (req == NULL || reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    size_t len;
    uint32_t size;
    const char *pkgName = (const char*)IpcIoPopString(req, &len);
    uint32_t addrTypeLen = IpcIoPopUint32(req);
    void *addr = (void*)IpcIoPopFlatObj(req, &size);
    if (addr == NULL || addrTypeLen != sizeof(ConnectionAddr) || size != sizeof(ConnectionAddr)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerJoinLNN read addr is null.");
        return SOFTBUS_ERR;
    }
    int32_t callingUid = GetCallingUid(origin);
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

int32_t ServerLeaveLNN(const void *origin, IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ServerLeaveLNN ipc server pop.");
    size_t len;
    const char *pkgName = (const char*)IpcIoPopString(req, &len);
    const char *networkId = (const char*)IpcIoPopString(req, &len);
    if (networkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerLeaveLNN read networkId failed!");
        return SOFTBUS_ERR;
    }
    int32_t callingUid = GetCallingUid(origin);
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

int32_t ServerGetAllOnlineNodeInfo(const void *origin, IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ServerGetAllOnlineNodeInfo ipc server pop.");
    void *nodeInfo = NULL;
    int32_t infoNum = 0;
    size_t len;
    const char *pkgName = (const char*)IpcIoPopString(req, &len);
    uint32_t infoTypeLen = IpcIoPopUint32(req);
    int32_t callingUid = GetCallingUid(origin);
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerGetAllOnlineNodeInfo no permission.");
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = LnnIpcGetAllOnlineNodeInfo(pkgName, &nodeInfo, infoTypeLen, &infoNum);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerGetAllOnlineNodeInfo get info failed.");
        return SOFTBUS_ERR;
    }
    if (infoNum < 0 || (infoNum > 0 && nodeInfo == NULL)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerGetAllOnlineNodeInfo node info is invalid");
        return SOFTBUS_ERR;
    }
    IpcIoPushInt32(reply, infoNum);
    if (infoNum > 0) {
        IpcIoPushFlatObj(reply, nodeInfo, infoTypeLen * infoNum);
        SoftBusFree(nodeInfo);
    }
    return SOFTBUS_OK;
}

int32_t ServerGetLocalDeviceInfo(const void *origin, IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ServerGetLocalDeviceInfo ipc server pop.");
    void *nodeInfo = NULL;
    size_t len;
    const char *pkgName = (const char*)IpcIoPopString(req, &len);

    int32_t callingUid = GetCallingUid(origin);
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerGetLocalDeviceInfo no permission.");
        return SOFTBUS_PERMISSION_DENIED;
    }

    uint32_t infoTypeLen = sizeof(NodeBasicInfo);
    nodeInfo = SoftBusCalloc(infoTypeLen);
    if (nodeInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerGetLocalDeviceInfo malloc info type length failed");
        return SOFTBUS_MEM_ERR;
    }

    int32_t ret = LnnIpcGetLocalDeviceInfo(pkgName, nodeInfo, infoTypeLen);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerGetLocalDeviceInfo get local info failed.");
        SoftBusFree(nodeInfo);
        return SOFTBUS_ERR;
    }
    IpcIoPushFlatObj(reply, nodeInfo, infoTypeLen);
    SoftBusFree(nodeInfo);
    return SOFTBUS_OK;
}

int32_t ServerGetNodeKeyInfo(const void *origin, IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ServerGetNodeKeyInfo ipc server pop.");
    size_t length;
    const char *pkgName = (const char*)IpcIoPopString(req, &length);
    int32_t callingUid = GetCallingUid(origin);
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerGetNodeKeyInfo no permission.");
        return SOFTBUS_PERMISSION_DENIED;
    }
    const char *networkId = (const char*)IpcIoPopString(req, &length);
    if (networkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetNodeKeyInfoInner read networkId failed!");
        return SOFTBUS_ERR;
    }
    int32_t key = IpcIoPopInt32(req);
    int32_t infoLen  = LnnIpcGetNodeKeyInfoLen(key);
    if (infoLen == SOFTBUS_ERR) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetNodeKeyInfoInner get infoLen failed!");
        return SOFTBUS_ERR;
    }
    int32_t len = IpcIoPopInt32(req);
    if (len < infoLen) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetNodeKeyInfoInner read len is invalid param!");
        return SOFTBUS_ERR;
    }
    void *buf = SoftBusCalloc(infoLen);
    if (buf == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerGetNodeKeyInfo malloc buffer failed!");
        return SOFTBUS_MEM_ERR;
    }
    int32_t ret = LnnIpcGetNodeKeyInfo(pkgName, networkId, key, (unsigned char *)buf, infoLen);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerGetNodeKeyInfo get local info failed.");
        SoftBusFree(buf);
        return SOFTBUS_ERR;
    }
    IpcIoPushFlatObj(reply, buf, infoLen);
    SoftBusFree(buf);
    return SOFTBUS_OK;
}

int32_t ServerStartTimeSync(const void *origin, IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ServerStartTimeSync ipc server pop.");
    size_t length;
    const char *pkgName = (const char*)IpcIoPopString(req, &length);
    const char *targetNetworkId = (const char*)IpcIoPopString(req, &length);
    if (targetNetworkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerStartTimeSync read targetNetworkId failed!");
        return SOFTBUS_ERR;
    }
    int32_t accuracy = IpcIoPopInt32(req);
    int32_t period = IpcIoPopInt32(req);

    int32_t callingUid = GetCallingUid(origin);
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

int32_t ServerStopTimeSync(const void *origin, IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ServerStopTimeSync ipc server pop.");
    size_t length;
    const char *pkgName = (const char*)IpcIoPopString(req, &length);
    const char *targetNetworkId = (const char*)IpcIoPopString(req, &length);
    if (targetNetworkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerStopTimeSync read targetNetworkId failed!");
        return SOFTBUS_ERR;
    }
    int32_t callingUid = GetCallingUid(origin);
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

int32_t ServerPublishLNN(const void *origin, IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ServerPublishLNN ipc server pop.");
    if (req == NULL || reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    size_t len;
    uint32_t size;
    const char *pkgName = (const char*)IpcIoPopString(req, &len);
    int32_t callingUid = GetCallingUid(origin);
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerPublishLNN no permission.");
        return SOFTBUS_PERMISSION_DENIED;
    }

    PublishInfo info;
    (void)memset_s(&info, sizeof(PublishInfo), 0, sizeof(PublishInfo));
    info.publishId = IpcIoPopInt32(req);
    int32_t mode = IpcIoPopInt32(req);
    int32_t medium = IpcIoPopInt32(req);
    int32_t freq = IpcIoPopInt32(req);
    info.mode = (DiscoverMode)mode;
    info.medium = (ExchanageMedium)medium;
    info.freq = (ExchangeFreq)freq;
    info.capability = (const char *)IpcIoPopString(req, &len);
    if (info.capability == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerPublishLNN read capability is null.");
        return SOFTBUS_ERR;
    }
    info.dataLen = IpcIoPopUint32(req);
    if (info.dataLen > 0 && info.dataLen < MAX_CAPABILITYDATA_LEN) {
        info.capabilityData = (unsigned char *)IpcIoPopFlatObj(req, &size);
        if (info.capabilityData == NULL) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerPublishLNN read capabilityData is null.");
            return SOFTBUS_ERR;
        }
    } else {
        info.capabilityData = NULL;
        info.dataLen = 0;
    }
    int32_t ret = LnnIpcPublishLNN(pkgName, &info);
    IpcIoPushInt32(reply, ret);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerPublishLNN failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ServerStopPublishLNN(const void *origin, IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ServerStopPublishLNN ipc server pop.");
    if (req == NULL || reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    size_t len;
    const char *pkgName = (const char*)IpcIoPopString(req, &len);
    int32_t publishId = IpcIoPopInt32(req);
    int32_t callingUid = GetCallingUid(origin);
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

int32_t ServerRefreshLNN(const void *origin, IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ServerRefreshLNN ipc server pop.");
    if (req == NULL || reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    size_t len;
    uint32_t size;
    const char *pkgName = (const char*)IpcIoPopString(req, &len);
    int32_t callingUid = GetCallingUid(origin);
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerRefreshLNN no permission.");
        return SOFTBUS_PERMISSION_DENIED;
    }

    SubscribeInfo info;
    (void)memset_s(&info, sizeof(SubscribeInfo), 0, sizeof(SubscribeInfo));
    info.subscribeId = IpcIoPopInt32(req);
    int32_t mode = IpcIoPopInt32(req);
    int32_t medium = IpcIoPopInt32(req);
    int32_t freq = IpcIoPopInt32(req);
    info.mode = (DiscoverMode)mode;
    info.medium = (ExchanageMedium)medium;
    info.freq = (ExchangeFreq)freq;
    info.isSameAccount = IpcIoPopBool(req);
    info.isWakeRemote = IpcIoPopBool(req);
    info.capability = (const char *)IpcIoPopString(req, &len);
    if (info.capability == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerRefreshLNN read capability is null.");
        return SOFTBUS_ERR;
    }
    info.dataLen = IpcIoPopUint32(req);
    if (info.dataLen > 0 && info.dataLen < MAX_CAPABILITYDATA_LEN) {
        info.capabilityData = (unsigned char *)IpcIoPopFlatObj(req, &size);
        if (info.capabilityData == NULL) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerRefreshLNN read capabilityData is null.");
            return SOFTBUS_ERR;
        }
    } else {
        info.capabilityData = NULL;
        info.dataLen = 0;
    }
    int32_t ret = LnnIpcRefreshLNN(pkgName, &info);
    IpcIoPushInt32(reply, ret);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerRefreshLNN failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ServerStopRefreshLNN(const void *origin, IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ServerStopRefreshLNN ipc server pop.");
    if (req == NULL || reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    size_t len;
    const char *pkgName = (const char*)IpcIoPopString(req, &len);
    int32_t refreshId = IpcIoPopInt32(req);
    int32_t callingUid = GetCallingUid(origin);
    if (CheckPermission(pkgName, callingUid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerStopRefreshLNN no permission.");
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = LnnIpcStopRefreshLNN(pkgName, refreshId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerStopRefreshLNN failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ServerActiveMetaNode(const void *origin, IpcIo *req, IpcIo *reply)
{
    uint32_t size;
    const char *pkgName = (const char*)IpcIoPopString(req, &size);
    MetaNodeConfigInfo *info = (MetaNodeConfigInfo *)IpcIoPopFlatObj(req, &size);
    if (info == NULL || size != sizeof(MetaNodeConfigInfo)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerActiveMetaNode read meta node config info failed!");
        IpcIoPushInt32(reply, SOFTBUS_INVALID_PARAM);
        return SOFTBUS_ERR;
    }
    int32_t ret = CheckPermission(pkgName, GetCallingUid(origin));
    if (ret != SOFTBUS_OK) {
        IpcIoPushInt32(reply, ret);
        return SOFTBUS_ERR;
    }
    char metaNodeId[NETWORK_ID_BUF_LEN] = {0};
    ret = LnnIpcActiveMetaNode(info, metaNodeId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerActiveMetaNode failed!");
        IpcIoPushInt32(reply, ret);
        return SOFTBUS_ERR;
    }
    IpcIoPushInt32(reply, SOFTBUS_OK);
    IpcIoPushString(reply, metaNodeId);
    return SOFTBUS_OK;
}

int32_t ServerDeactiveMetaNode(const void *origin, IpcIo *req, IpcIo *reply)
{
    uint32_t size;
    const char *pkgName = (const char*)IpcIoPopString(req, &size);
    const char *metaNodeId = (const char*)IpcIoPopString(req, &size);
    if (metaNodeId == NULL || size != (NETWORK_ID_BUF_LEN - 1)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR,
            "ServerDeactiveMetaNode read meta node id failed, size=%d", size);
        IpcIoPushInt32(reply, SOFTBUS_INVALID_PARAM);
        return SOFTBUS_ERR;
    }
    int32_t ret = CheckPermission(pkgName, GetCallingUid(origin));
    if (ret != SOFTBUS_OK) {
        IpcIoPushInt32(reply, ret);
        return SOFTBUS_ERR;
    }
    ret = LnnIpcDeactiveMetaNode(metaNodeId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerDeactiveMetaNode failed!");
        IpcIoPushInt32(reply, ret);
        return SOFTBUS_ERR;
    }
    IpcIoPushInt32(reply, SOFTBUS_OK);
    return SOFTBUS_OK;
}

int32_t ServerGetAllMetaNodeInfo(const void *origin, IpcIo *req, IpcIo *reply)
{
    uint32_t size;
    const char *pkgName = (const char*)IpcIoPopString(req, &size);
    int32_t infoNum = IpcIoPopInt32(req);
    MetaNodeInfo infos[MAX_META_NODE_NUM];
    int32_t ret = CheckPermission(pkgName, GetCallingUid(origin));
    if (ret != SOFTBUS_OK) {
        IpcIoPushInt32(reply, ret);
        return SOFTBUS_ERR;
    }
    ret = LnnIpcGetAllMetaNodeInfo(infos, &infoNum);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerGetAllMetaNodeInfo failed!");
        IpcIoPushInt32(reply, ret);
        return SOFTBUS_ERR;
    }
    IpcIoPushInt32(reply, SOFTBUS_OK);
    IpcIoPushInt32(reply, infoNum);
    if (infoNum > 0) {
        IpcIoPushFlatObj(reply, infos, infoNum * sizeof(MetaNodeInfo));
    }
    return SOFTBUS_OK;
}
