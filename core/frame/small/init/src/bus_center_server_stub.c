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

#include "lnn_bus_center_ipc.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_permission.h"

int32_t ServerJoinLNN(void *origin, IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ServerJoinLNN ipc server pop.");
    if (req == NULL || reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    size_t len;
    uint32_t size;
    const char *pkgName = (const char*)IpcIoPopString(req, &len);
    if (pkgName == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerJoinLNN read pkgName failed!");
        return SOFTBUS_ERR;
    }
    uint32_t addrTypeLen = IpcIoPopUint32(req);
    void *addr = (void*)IpcIoPopFlatObj(req, &size);
    if (addr == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerJoinLNN read addr is null.");
        return SOFTBUS_ERR;
    }
    int32_t callingUid = GetCallingUid(origin);
    if (!CheckBusCenterPermission(callingUid, pkgName)) {
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

int32_t ServerLeaveLNN(void *origin, IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ServerLeaveLNN ipc server pop.");
    size_t len;
    const char *pkgName = (const char*)IpcIoPopString(req, &len);
    if (pkgName == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerLeaveLNN read pkgName failed!");
        return SOFTBUS_ERR;
    }
    const char *networkId = (const char*)IpcIoPopString(req, &len);
    if (networkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerLeaveLNN read networkId failed!");
        return SOFTBUS_ERR;
    }
    int32_t callingUid = GetCallingUid(origin);
    if (!CheckBusCenterPermission(callingUid, pkgName)) {
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

int32_t ServerGetAllOnlineNodeInfo(void *origin, IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ServerGetAllOnlineNodeInfo ipc server pop.");
    void *nodeInfo = NULL;
    int32_t infoNum = 0;
    size_t len;
    const char *pkgName = (const char*)IpcIoPopString(req, &len);
    if (pkgName == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerGetAllOnlineNodeInfo read pkgName failed!");
        return SOFTBUS_ERR;
    }

    uint32_t infoTypeLen = IpcIoPopUint32(req);
    int32_t callingUid = GetCallingUid(origin);
    if (!CheckBusCenterPermission(callingUid, pkgName)) {
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

int32_t ServerGetLocalDeviceInfo(void *origin, IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ServerGetLocalDeviceInfo ipc server pop.");
    void *nodeInfo = NULL;
    size_t len;
    const char *pkgName = (const char*)IpcIoPopString(req, &len);
    if (pkgName == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerGetLocalDeviceInfo read pkgName failed!");
        return SOFTBUS_ERR;
    }

    uint32_t infoTypeLen = IpcIoPopUint32(req);
    nodeInfo = SoftBusCalloc(infoTypeLen);
    if (nodeInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerGetLocalDeviceInfo malloc info type length failed");
        return SOFTBUS_ERR;
    }
    int32_t callingUid = GetCallingUid(origin);
    if (!CheckBusCenterPermission(callingUid, pkgName)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerGetLocalDeviceInfo no permission.");
        SoftBusFree(nodeInfo);
        return SOFTBUS_PERMISSION_DENIED;
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

int32_t ServerGetNodeKeyInfo(void *origin, IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ServerGetNodeKeyInfo ipc server pop.");
    size_t length;
    const char *pkgName = (const char*)IpcIoPopString(req, &length);
    if (pkgName == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerLeaveLNN read pkgName failed!");
        return SOFTBUS_ERR;
    }

    const char *networkId = (const char*)IpcIoPopString(req, &length);
    if (networkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetNodeKeyInfoInner read networkId failed!");
        return SOFTBUS_ERR;
    }
    int32_t key = IpcIoPopInt32(req);
    int32_t len = IpcIoPopInt32(req);
    void *buf = SoftBusMalloc(len);
    if (buf == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerGetNodeKeyInfo malloc buffer failed!");
        return SOFTBUS_ERR;
    }
    int32_t callingUid = GetCallingUid(origin);
    if (!CheckBusCenterPermission(callingUid, pkgName)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerGetNodeKeyInfo no permission.");
        SoftBusFree(buf);
        return SOFTBUS_PERMISSION_DENIED;
    }

    int32_t ret = LnnIpcGetNodeKeyInfo(pkgName, networkId, key, (unsigned char *)buf, len);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerGetNodeKeyInfo get local info failed.");
        SoftBusFree(buf);
        return SOFTBUS_ERR;
    }
    IpcIoPushFlatObj(reply, buf, len);
    SoftBusFree(buf);
    return SOFTBUS_OK;
}

int32_t ServerStartTimeSync(void *origin, IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ServerStartTimeSync ipc server pop.");
    size_t length;
    const char *pkgName = (const char*)IpcIoPopString(req, &length);
    if (pkgName == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerStartTimeSync read pkgName failed!");
        return SOFTBUS_ERR;
    }

    const char *targetNetworkId = (const char*)IpcIoPopString(req, &length);
    if (targetNetworkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerStartTimeSync read targetNetworkId failed!");
        return SOFTBUS_ERR;
    }
    int32_t accuracy = IpcIoPopInt32(req);
    int32_t period = IpcIoPopInt32(req);

    int32_t callingUid = GetCallingUid(origin);
    if (!CheckBusCenterPermission(callingUid, pkgName)) {
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

int32_t ServerStopTimeSync(void *origin, IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ServerStopTimeSync ipc server pop.");
    size_t length;
    const char *pkgName = (const char*)IpcIoPopString(req, &length);
    if (pkgName == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerStopTimeSync read pkgName failed!");
        return SOFTBUS_ERR;
    }

    const char *targetNetworkId = (const char*)IpcIoPopString(req, &length);
    if (targetNetworkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerStopTimeSync read targetNetworkId failed!");
        return SOFTBUS_ERR;
    }

    int32_t callingUid = GetCallingUid(origin);
    if (!CheckBusCenterPermission(callingUid, pkgName)) {
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
