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

#include "trans_server_stub.h"

#include "ipc_skeleton.h"
#include "lnn_connection_addr_utils.h"
#include "securec.h"
#include "softbus_common.h"
#include "softbus_conn_interface.h"
#include "softbus_errcode.h"
#include "softbus_permission.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_trans_def.h"
#include "trans_auth_manager.h"
#include "trans_channel_manager.h"
#include "trans_log.h"
#include "trans_session_manager.h"
#include "trans_session_service.h"

int32_t ServerCreateSessionServer(IpcIo *req, IpcIo *reply)
{
    TRANS_LOGI(TRANS_CTRL, "ipc server pop");
    if (req == NULL || reply == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t size;
    const char *pkgName = (const char*)ReadString(req, &size);
    if (pkgName == NULL) {
        TRANS_LOGE(TRANS_CTRL, "ServerCreateSessionServer pkgName is null");
        return SOFTBUS_ERR;
    }
    const char *sessionName = (const char *)ReadString(req, &size);
    if (sessionName == NULL) {
        TRANS_LOGE(TRANS_CTRL, "sessionName pkgName is null");
        return SOFTBUS_ERR;
    }
    int32_t callingUid = GetCallingUid();
    int32_t callingPid = GetCallingPid();
    if (CheckTransPermission(callingUid, callingPid, pkgName, sessionName, ACTION_CREATE) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "no permission");
        WriteInt32(reply, SOFTBUS_PERMISSION_DENIED);
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = TransCreateSessionServer(pkgName, sessionName, callingUid, callingPid);
    (void)WriteInt32(reply, ret);
    return ret;
}

int32_t ServerRemoveSessionServer(IpcIo *req, IpcIo *reply)
{
    TRANS_LOGI(TRANS_CTRL, "ipc server pop");
    if (req == NULL || reply == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t size;
    const char *pkgName = (const char*)ReadString(req, &size);
    if (pkgName == NULL) {
        TRANS_LOGE(TRANS_CTRL, "ServerRemoveSessionServer pkgName is null");
        return SOFTBUS_ERR;
    }
    const char *sessionName = (const char *)ReadString(req, &size);
    if (sessionName == NULL) {
        TRANS_LOGE(TRANS_CTRL, "ServerRemoveSessionServer sessionName is null");
        return SOFTBUS_ERR;
    }
    int32_t callingUid = GetCallingUid();
    int32_t callingPid = GetCallingPid();
    if (CheckTransPermission(callingUid, callingPid, pkgName, sessionName, ACTION_CREATE) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "no permission");
        WriteInt32(reply, SOFTBUS_PERMISSION_DENIED);
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret = TransRemoveSessionServer(pkgName, sessionName);
    WriteInt32(reply, ret);
    return ret;
}

static int32_t CheckOpenSessionPremission(const char *sessionName, const char *peerSessionName)
{
    char pkgName[PKG_NAME_SIZE_MAX] = {0};
    if (TransGetPkgNameBySessionName(sessionName, pkgName, PKG_NAME_SIZE_MAX) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "TransGetPkgNameBySessionName failed");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t callingUid = GetCallingUid();
    int32_t callingPid = GetCallingPid();
    if (CheckTransPermission(callingUid, callingPid, pkgName, sessionName, ACTION_OPEN) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "no permission");
        return SOFTBUS_PERMISSION_DENIED;
    }

    if (CheckTransSecLevel(sessionName, peerSessionName) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "sec level invalid");
        return SOFTBUS_PERMISSION_DENIED;
    }
    return SOFTBUS_OK;
}

static void ServerReadSessionAttrs(IpcIo *req, SessionAttribute *getAttr)
{
    if (getAttr == NULL || req == NULL) {
        TRANS_LOGE(TRANS_CTRL, "getAttr and req is NULL");
        return;
    }
    LinkType *pGetArr = NULL;

    if (!ReadInt32(req, &getAttr->dataType)) {
        TRANS_LOGE(TRANS_CTRL, "read dataType failed");
        return;
    }

    if (!ReadInt32(req, &getAttr->linkTypeNum)) {
        TRANS_LOGE(TRANS_CTRL, "read linkTypeNum failed");
        return;
    }

    if (getAttr->linkTypeNum > 0) {
        pGetArr = (LinkType *)ReadBuffer(req, sizeof(LinkType) * getAttr->linkTypeNum);
    }

    if (pGetArr != NULL && getAttr->linkTypeNum <= LINK_TYPE_MAX) {
        (void)memcpy_s(getAttr->linkType, sizeof(LinkType) * LINK_TYPE_MAX,
                       pGetArr, sizeof(LinkType) * getAttr->linkTypeNum);
    }

    if (!ReadInt32(req, &getAttr->attr.streamAttr.streamType)) {
        TRANS_LOGE(TRANS_CTRL, "read streamType failed");
        return;
    }

    if (!ReadUint16(req, &getAttr->fastTransDataSize)) {
        TRANS_LOGE(TRANS_CTRL, "read fastTransDataSize failed");
        return;
    }

    if (getAttr->fastTransDataSize != 0) {
        getAttr->fastTransData = (uint8_t *)ReadRawData(req, getAttr->fastTransDataSize);
    }
}

int32_t ServerOpenSession(IpcIo *req, IpcIo *reply)
{
    TRANS_LOGI(TRANS_CTRL, "ipc server pop");
    if (req == NULL || reply == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret;
    uint32_t size;
    SessionParam param;
    SessionAttribute getAttr;
    (void)memset_s(&param, sizeof(SessionParam), 0, sizeof(SessionParam));
    (void)memset_s(&getAttr, sizeof(SessionAttribute), 0, sizeof(SessionAttribute));
    TransSerializer transSerializer;
    transSerializer.transInfo.channelId = INVALID_CHANNEL_ID;
    transSerializer.transInfo.channelType = CHANNEL_TYPE_BUTT;
    param.sessionName = (const char*)ReadString(req, &size);
    param.peerSessionName = (const char *)ReadString(req, &size);
    param.peerDeviceId = (const char *)ReadString(req, &size);
    param.groupId = (const char *)ReadString(req, &size);
    ServerReadSessionAttrs(req, &getAttr);
    param.attr = &getAttr;

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
    TRANS_LOGD(TRANS_CTRL, "ipc server pop");
    if (req == NULL || reply == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret;
    uint32_t size;
    ConnectOption connOpt;
    const char *sessionName = (const char*)ReadString(req, &size);
    ConnectionAddr *addr = (ConnectionAddr *)ReadRawData(req, sizeof(ConnectionAddr));
    if (!LnnConvertAddrToOption(addr, &connOpt)) {
        TRANS_LOGE(TRANS_CTRL, "LnnConvertAddrToOption fail");
        WriteInt32(reply, SOFTBUS_ERR);
        return SOFTBUS_ERR;
    }
    ret = CheckOpenSessionPremission(sessionName, sessionName);
    if (ret != SOFTBUS_OK) {
        WriteInt32(reply, ret);
        return ret;
    }
    ret = TransOpenAuthChannel(sessionName, &connOpt, "");
    WriteInt32(reply, ret);
    return ret;
}

int32_t ServerNotifyAuthSuccess(IpcIo *req, IpcIo *reply)
{
    TRANS_LOGI(TRANS_CTRL, "ipc server pop");
    if (req == NULL || reply == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param");
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
        TRANS_LOGE(TRANS_CTRL, "get session name fail");
        WriteInt32(reply, SOFTBUS_TRANS_UDP_CLOSE_CHANNELID_INVALID);
        return SOFTBUS_TRANS_UDP_CLOSE_CHANNELID_INVALID;
    }
    if (CheckTransPermission(callingUid, callingPid, pkgName, sessionName, ACTION_OPEN) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "ServerCloseChannel no permission");
        WriteInt32(reply, SOFTBUS_PERMISSION_DENIED);
        return SOFTBUS_PERMISSION_DENIED;
    }

    int32_t ret = TransNotifyAuthSuccess(channelId, channelType);
    WriteInt32(reply, ret);
    return ret;
}

int32_t ServerCloseChannel(IpcIo *req, IpcIo *reply)
{
    TRANS_LOGI(TRANS_CTRL, "ipc server pop");
    if (req == NULL || reply == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret;
    int32_t channelId = 0;
    int32_t channelType = 0;
    ReadInt32(req, &channelId);
    ReadInt32(req, &channelType);

    ret = TransCloseChannel(channelId, channelType);

    WriteInt32(reply, ret);
    return ret;
}

int32_t ServerSendSessionMsg(IpcIo *req, IpcIo *reply)
{
    TRANS_LOGI(TRANS_CTRL, "ipc server pop");
    if (req == NULL || reply == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t channelId = 0;
    int32_t channelType = 0;
    int32_t msgType = 0;
    (void)ReadInt32(req, &channelId);
    (void)ReadInt32(req, &channelType);
    (void)ReadInt32(req, &msgType);
    uint32_t size = 0;
    ReadUint32(req, &size);
    const void *data = (const void *)ReadBuffer(req, size);
    int32_t ret = TransSendMsg(channelId, channelType, data, size, msgType);
    WriteInt32(reply, ret);
    return ret;
}
