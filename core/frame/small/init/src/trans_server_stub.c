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

#include "trans_server_stub.h"

#include "ipc_skeleton.h"
#include "lnn_connection_addr_utils.h"
#include "securec.h"
#include "softbus_common.h"
#include "softbus_conn_interface.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_permission.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_trans_def.h"
#include "trans_auth_manager.h"
#include "trans_channel_manager.h"
#include "trans_session_manager.h"
#include "trans_session_service.h"


int32_t ServerCreateSessionServer(IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "create session server ipc server pop");
    if (req == NULL || reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t size;
    const char *pkgName = (const char*)ReadString(req, &size);
    const char *sessionName = (const char *)ReadString(req, &size);
    int32_t callingUid = GetCallingUid();
    int32_t callingPid = GetCallingPid();
    if (CheckTransPermission(callingUid, callingPid, pkgName, sessionName, ACTION_CREATE) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerCreateSessionServer no permission");
        WriteInt32(reply, SOFTBUS_PERMISSION_DENIED);
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = TransCreateSessionServer(pkgName, sessionName, callingUid, callingPid);
    WriteInt32(reply, ret);
    return ret;
}

int32_t ServerRemoveSessionServer(IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "remove session server ipc server pop");
    if (req == NULL || reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t size;
    const char *pkgName = (const char*)ReadString(req, &size);
    const char *sessionName = (const char *)ReadString(req, &size);
    int32_t callingUid = GetCallingUid();
    int32_t callingPid = GetCallingPid();
    if (CheckTransPermission(callingUid, callingPid, pkgName, sessionName, ACTION_CREATE) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerRemoveSessionServer no permission");
        WriteInt32(reply, SOFTBUS_PERMISSION_DENIED);
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = TransRemoveSessionServer(pkgName, sessionName);
    WriteInt32(reply, ret);
    return ret;
}

static int32_t CheckOpenSessionPremission(const char *sessionName, const char *peerSessionName)
{
    char pkgName[PKG_NAME_SIZE_MAX];
    if (TransGetPkgNameBySessionName(sessionName, pkgName, PKG_NAME_SIZE_MAX) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OpenSession TransGetPkgNameBySessionName failed");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t callingUid = GetCallingUid();
    int32_t callingPid = GetCallingPid();
    if (CheckTransPermission(callingUid, callingPid, pkgName, sessionName, ACTION_OPEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OpenSession no permission");
        return SOFTBUS_PERMISSION_DENIED;
    }

    if (CheckTransSecLevel(sessionName, peerSessionName) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OpenSession sec level invalid");
        return SOFTBUS_PERMISSION_DENIED;
    }
    return SOFTBUS_OK;
}

int32_t ServerOpenSession(IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "open session ipc server pop");
    if (req == NULL || reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret;
    uint32_t size;
    SessionParam param;
    TransSerializer transSerializer;
    transSerializer.transInfo.channelId = INVALID_CHANNEL_ID;
    transSerializer.transInfo.channelType = CHANNEL_TYPE_BUTT;
    param.sessionName = (const char*)ReadString(req, &size);
    param.peerSessionName = (const char *)ReadString(req, &size);
    param.peerDeviceId = (const char *)ReadString(req, &size);
    param.groupId = (const char *)ReadString(req, &size);
    param.attr = (SessionAttribute *)ReadRawData(req, sizeof(SessionAttribute));

    ret = CheckOpenSessionPremission(param.sessionName, param.peerSessionName);
    if (ret != SOFTBUS_OK) {
        transSerializer.ret = ret;
        WriteUint32(reply, sizeof(TransSerializer));
        bool value = WriteBuffer(reply, (void *)&transSerializer, sizeof(TransSerializer));
        if (!value) {
            return SOFTBUS_ERR;
        }
        return ret;
    }

    ret = TransOpenSession(&param, &(transSerializer.transInfo));
    transSerializer.ret = ret;
    WriteUint32(reply, sizeof(TransSerializer));
    bool value = WriteBuffer(reply, (void *)&transSerializer, sizeof(TransSerializer));
    if (!value) {
        return SOFTBUS_ERR;
    }
    return ret;
}

int32_t ServerOpenAuthSession(IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "open non encrypt session ipc server pop");
    if (req == NULL || reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret;
    uint32_t size;
    ConnectOption connOpt;
    const char *sessionName = (const char*)ReadString(req, &size);
    ConnectionAddr *addr = (ConnectionAddr *)ReadRawData(req, sizeof(ConnectionAddr));
    if (!LnnConvertAddrToOption(addr, &connOpt)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "LnnConvertAddrToOption fail");
        WriteInt32(reply, SOFTBUS_ERR);
        return SOFTBUS_ERR;
    }
    ret = CheckOpenSessionPremission(sessionName, sessionName);
    if (ret != SOFTBUS_OK) {
        WriteInt32(reply, ret);
        return ret;
    }
    ret = TransOpenAuthChannel(sessionName, &connOpt);
    WriteInt32(reply, ret);
    return ret;
}

int32_t ServerNotifyAuthSuccess(IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "set auth result server pop");
    if (req == NULL || reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t channelId = 0;
    int32_t channelType = -1;
    ReadInt32(req, &channelId);
    ReadInt32(req, &channelType);
    int32_t callingUid = GetCallingUid();
    int32_t callingPid = GetCallingPid();
    char pkgName[PKG_NAME_SIZE_MAX];
    char sessionName[SESSION_NAME_SIZE_MAX];
    if (TransAuthGetNameByChanId(channelId, pkgName, sessionName,
        PKG_NAME_SIZE_MAX, SESSION_NAME_SIZE_MAX) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "get session name fail");
        WriteInt32(reply, SOFTBUS_TRANS_UDP_CLOSE_CHANNELID_INVALID);
        return SOFTBUS_TRANS_UDP_CLOSE_CHANNELID_INVALID;
    }
    if (CheckTransPermission(callingUid, callingPid, pkgName, sessionName, ACTION_OPEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerCloseChannel no permission");
        WriteInt32(reply, SOFTBUS_PERMISSION_DENIED);
        return SOFTBUS_PERMISSION_DENIED;
    }

    int32_t ret = TransNotifyAuthSuccess(channelId, channelType);
    WriteInt32(reply, ret);
    return ret;
}

int32_t ServerCloseChannel(IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "close channel ipc server pop");
    if (req == NULL || reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret;
    TransInfo info;
    int32_t channelId = 0;
    int32_t channelType = 0;
    ReadInt32(req, &channelId);
    ReadInt32(req, &channelType);

    info.channelId = channelId;
    info.channelType = channelType;
    ret = TransCloseChannel(channelId, channelType);

    WriteInt32(reply, ret);
    return ret;
}

int32_t ServerSendSessionMsg(IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "server send session msg ipc server pop");
    if (req == NULL || reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t channelId = 0;
    int32_t channelType = 0;
    int32_t msgType = 0;
    ReadInt32(req, &channelId);
    ReadInt32(req, &channelType);
    ReadInt32(req, &msgType);
    uint32_t size = 0;
    ReadUint32(req, &size);
    const void *data = (const void *)ReadBuffer(req, size);
    int32_t ret = TransSendMsg(channelId, channelType, data, size, msgType);
    WriteInt32(reply, ret);
    return ret;
}
