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

#include "liteipc_adapter.h"
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

int32_t ServerCreateSessionServer(const void *origin, IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "create session server ipc server pop");
    if (req == NULL || reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t size;
    const char *pkgName = (const char*)IpcIoPopString(req, &size);
    const char *sessionName = (const char *)IpcIoPopString(req, &size);
    int32_t callingUid = GetCallingUid(origin);
    int32_t callingPid = GetCallingPid(origin);
    if (CheckTransPermission(callingUid, callingPid, pkgName, sessionName, ACTION_CREATE) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerCreateSessionServer no permission");
        IpcIoPushInt32(reply, SOFTBUS_PERMISSION_DENIED);
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = TransCreateSessionServer(pkgName, sessionName, callingUid, callingPid);
    IpcIoPushInt32(reply, ret);
    return ret;
}

int32_t ServerRemoveSessionServer(const void *origin, IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "remove session server ipc server pop");
    if (req == NULL || reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t size;
    const char *pkgName = (const char*)IpcIoPopString(req, &size);
    const char *sessionName = (const char *)IpcIoPopString(req, &size);
    int32_t callingUid = GetCallingUid(origin);
    int32_t callingPid = GetCallingPid(origin);
    if (CheckTransPermission(callingUid, callingPid, pkgName, sessionName, ACTION_CREATE) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerRemoveSessionServer no permission");
        IpcIoPushInt32(reply, SOFTBUS_PERMISSION_DENIED);
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = TransRemoveSessionServer(pkgName, sessionName);
    IpcIoPushInt32(reply, ret);
    return ret;
}

int32_t ServerOpenSession(const void *origin, IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "open session ipc server pop");
    if (req == NULL || reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t size;
    SessionParam param;
    TransSerializer transSerializer;
    transSerializer.transInfo.channelId = INVALID_CHANNEL_ID;
    transSerializer.transInfo.channelType = CHANNEL_TYPE_BUTT;
    param.sessionName = (const char*)IpcIoPopString(req, &size);
    param.peerSessionName = (const char*)IpcIoPopString(req, &size);
    param.peerDeviceId = (const char*)IpcIoPopString(req, &size);
    param.groupId = (const char*)IpcIoPopString(req, &size);
    param.attr = (SessionAttribute*)IpcIoPopFlatObj(req, &size);
    int32_t callingUid = GetCallingUid(origin);
    int32_t callingPid = GetCallingPid(origin);
    char pkgName[PKG_NAME_SIZE_MAX];
    if (TransGetPkgNameBySessionName(param.sessionName, pkgName, PKG_NAME_SIZE_MAX) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "TransGetPkgNameBySessionName failed");
        transSerializer.ret = SOFTBUS_TRANS_PROXY_SEND_CHANNELID_INVALID;
        IpcIoPushFlatObj(reply, (void*)&transSerializer, sizeof(TransSerializer));
        return SOFTBUS_TRANS_PROXY_SEND_CHANNELID_INVALID;
    }
    if (CheckTransPermission(callingUid, callingPid, pkgName, param.sessionName, ACTION_OPEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerOpenSession no permission");
        transSerializer.ret = SOFTBUS_PERMISSION_DENIED;
        IpcIoPushFlatObj(reply, (void*)&transSerializer, sizeof(TransSerializer));
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = TransOpenSession(&param, &(transSerializer.transInfo));
    transSerializer.ret = ret;
    IpcIoPushFlatObj(reply, (void*)&transSerializer, sizeof(TransSerializer));
    return ret;
}

int32_t ServerOpenAuthSession(const void *origin, IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "open non encrypt session ipc server pop");
    if (req == NULL || reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret;
    uint32_t size;
    ConnectOption connOpt;
    const char *sessionName = (const char*)IpcIoPopString(req, &size);
    ConnectionAddr *addr = (ConnectionAddr *)IpcIoPopFlatObj(req, &size);
    if (!LnnConvertAddrToOption(addr, &connOpt)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "LnnConvertAddrToOption fail");
        IpcIoPushInt32(reply, SOFTBUS_ERR);
        return SOFTBUS_ERR;
    }
    ret = TransOpenAuthChannel(sessionName, &connOpt);
    IpcIoPushInt32(reply, ret);
    return ret;
}

int32_t ServerNotifyAuthSuccess(const void *origin, IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "set auth result server pop");
    if (req == NULL || reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t channelId = IpcIoPopInt32(req);
    int32_t callingUid = GetCallingUid(origin);
    int32_t callingPid = GetCallingPid(origin);
    char pkgName[PKG_NAME_SIZE_MAX];
    char sessionName[SESSION_NAME_SIZE_MAX];
    if (TransAuthGetNameByChanId(channelId, pkgName, sessionName,
        PKG_NAME_SIZE_MAX, SESSION_NAME_SIZE_MAX) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "get session name fail");
        IpcIoPushInt32(reply, SOFTBUS_TRANS_UDP_CLOSE_CHANNELID_INVALID);
        return SOFTBUS_TRANS_UDP_CLOSE_CHANNELID_INVALID;
    }
    if (CheckTransPermission(callingUid, callingPid, pkgName, sessionName, ACTION_OPEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerCloseChannel no permission");
        IpcIoPushInt32(reply, SOFTBUS_PERMISSION_DENIED);
        return SOFTBUS_PERMISSION_DENIED;
    }

    int32_t ret = TransNotifyAuthSuccess(channelId);
    IpcIoPushInt32(reply, ret);
    return ret;
}

int32_t ServerCloseChannel(const void *origin, IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "close channel ipc server pop");
    if (req == NULL || reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t channelId = IpcIoPopInt32(req);
    int32_t channelType = IpcIoPopInt32(req);
    int32_t callingUid = GetCallingUid(origin);
    int32_t callingPid = GetCallingPid(origin);
    char pkgName[PKG_NAME_SIZE_MAX];
    char sessionName[SESSION_NAME_SIZE_MAX];

    switch (channelType) {
        case CHANNEL_TYPE_PROXY:
            if (TransProxyGetNameByChanId(channelId, pkgName, sessionName,
                PKG_NAME_SIZE_MAX, SESSION_NAME_SIZE_MAX) != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "get session name fail");
                IpcIoPushInt32(reply, SOFTBUS_TRANS_PROXY_SEND_CHANNELID_INVALID);
                return SOFTBUS_TRANS_PROXY_SEND_CHANNELID_INVALID;
            }
            break;
        case CHANNEL_TYPE_UDP:
            if (TransUdpGetNameByChanId(channelId, pkgName, sessionName,
                PKG_NAME_SIZE_MAX, SESSION_NAME_SIZE_MAX) != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "get session name fail");
                IpcIoPushInt32(reply, SOFTBUS_TRANS_UDP_CLOSE_CHANNELID_INVALID);
                return SOFTBUS_TRANS_UDP_CLOSE_CHANNELID_INVALID;
            }
            break;
        case CHANNEL_TYPE_AUTH:
            if (TransAuthGetNameByChanId(channelId, pkgName, sessionName,
                PKG_NAME_SIZE_MAX, SESSION_NAME_SIZE_MAX) != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "get session name fail");
                IpcIoPushInt32(reply, SOFTBUS_TRANS_UDP_CLOSE_CHANNELID_INVALID);
                return SOFTBUS_TRANS_UDP_CLOSE_CHANNELID_INVALID;
            }
            break;
        default:
            IpcIoPushInt32(reply, SOFTBUS_TRANS_INVALID_CLOSE_CHANNEL_ID);
            return SOFTBUS_TRANS_INVALID_CLOSE_CHANNEL_ID;
    }

    if (CheckTransPermission(callingUid, callingPid, pkgName, sessionName, ACTION_OPEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ServerCloseChannel no permission");
        IpcIoPushInt32(reply, SOFTBUS_PERMISSION_DENIED);
        return SOFTBUS_PERMISSION_DENIED;
    }

    int32_t ret = TransCloseChannel(channelId, channelType);
    IpcIoPushInt32(reply, ret);
    return ret;
}

int32_t ServerSendSessionMsg(const void *origin, IpcIo *req, IpcIo *reply)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "server send session msg ipc server pop");
    if (req == NULL || reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t channelId = IpcIoPopInt32(req);
    int32_t channelType = IpcIoPopInt32(req);
    int32_t msgType = IpcIoPopInt32(req);
    uint32_t size = 0;
    const void *data = (const void *)IpcIoPopFlatObj(req, &size);
    int32_t ret = TransSendMsg(channelId, channelType, data, size, msgType);
    IpcIoPushInt32(reply, ret);
    return ret;
}
