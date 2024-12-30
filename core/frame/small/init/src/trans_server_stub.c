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

#include "trans_server_stub.h"

#include "ipc_skeleton.h"
#include "lnn_connection_addr_utils.h"
#include "securec.h"
#include "softbus_common.h"
#include "softbus_conn_interface.h"
#include "softbus_error_code.h"
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
    size_t size;
    const char *pkgName = (const char*)ReadString(req, &size);
    if (pkgName == NULL) {
        TRANS_LOGE(TRANS_CTRL, "ServerCreateSessionServer pkgName is null");
        return SOFTBUS_IPC_ERR;
    }
    const char *sessionName = (const char *)ReadString(req, &size);
    if (sessionName == NULL) {
        TRANS_LOGE(TRANS_CTRL, "sessionName pkgName is null");
        return SOFTBUS_IPC_ERR;
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
    size_t size;
    const char *pkgName = (const char*)ReadString(req, &size);
    if (pkgName == NULL) {
        TRANS_LOGE(TRANS_CTRL, "ServerRemoveSessionServer pkgName is null");
        return SOFTBUS_IPC_ERR;
    }
    const char *sessionName = (const char *)ReadString(req, &size);
    if (sessionName == NULL) {
        TRANS_LOGE(TRANS_CTRL, "ServerRemoveSessionServer sessionName is null");
        return SOFTBUS_IPC_ERR;
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

static bool ReadQosInfo(IpcIo *req, SessionParam *param)
{
    if (req == NULL || param == NULL) {
        TRANS_LOGE(TRANS_CTRL, "param or req is NULL");
        return false;
    }

    if (!ReadBool(req, &param->isQosLane)) {
        TRANS_LOGE(TRANS_SDK, "read qos flag failed!");
        return false;
    }

    if (!param->isQosLane) {
        return true;
    }

    if (!ReadUint32(req, &param->qosCount)) {
        TRANS_LOGE(TRANS_SDK, "read count of qos failed!");
        return false;
    }
    
    if (param->qosCount == 0) {
        return true;
    }

    if (param->qosCount > QOS_TYPE_BUTT) {
        TRANS_LOGE(TRANS_SDK, "read invalid qosCount=%{public}" PRIu32, param->qosCount);
        return false;
    }

    const QosTV *qosInfo = (QosTV *)ReadBuffer(req, sizeof(QosTV) * param->qosCount);
    if (qosInfo == NULL) {
        COMM_LOGE(COMM_SVC, "failed to read qos data");
        return false;
    }

    if (memcpy_s(param->qos, sizeof(QosTV) * QOS_TYPE_BUTT, qosInfo, sizeof(QosTV) * param->qosCount) != EOK) {
        COMM_LOGE(COMM_SVC, "failed memcpy qos info");
        return false;
    }

    return true;
}

int32_t ServerOpenSession(IpcIo *req, IpcIo *reply)
{
    TRANS_LOGI(TRANS_CTRL, "ipc server pop");
    if (req == NULL || reply == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret;
    size_t size;
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
    ReadBool(req, &param.isAsync);
    ReadInt32(req, &param.sessionId);
    ServerReadSessionAttrs(req, &getAttr);
    param.attr = &getAttr;
    if (!ReadQosInfo(req, &param)) {
        TRANS_LOGE(TRANS_CTRL, "failed to read qos info");
        return SOFTBUS_IPC_ERR;
    }

    ret = CheckOpenSessionPremission(param.sessionName, param.peerSessionName);
    if (ret != SOFTBUS_OK) {
        transSerializer.ret = ret;
        WriteUint32(reply, sizeof(TransSerializer));
        bool value = WriteBuffer(reply, (void *)&transSerializer, sizeof(TransSerializer));
        if (!value) {
            return SOFTBUS_TRANS_PROXY_WRITERAWDATA_FAILED;
        }
        return ret;
    }

    ret = TransOpenSession(&param, &(transSerializer.transInfo));
    transSerializer.ret = ret;
    WriteUint32(reply, sizeof(TransSerializer));
    bool value = WriteBuffer(reply, (void *)&transSerializer, sizeof(TransSerializer));
    if (!value) {
        return SOFTBUS_TRANS_PROXY_WRITERAWDATA_FAILED;
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
    size_t size;
    ConnectOption connOpt;
    const char *sessionName = (const char*)ReadString(req, &size);
    ConnectionAddr *addr = (ConnectionAddr *)ReadRawData(req, sizeof(ConnectionAddr));
    if (!LnnConvertAddrToOption(addr, &connOpt)) {
        TRANS_LOGE(TRANS_CTRL, "LnnConvertAddrToOption fail");
        WriteInt32(reply, SOFTBUS_NO_INIT);
        return SOFTBUS_NO_INIT;
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
        WriteInt32(reply, SOFTBUS_TRANS_UDP_INVALID_CHANNEL_ID);
        return SOFTBUS_TRANS_UDP_INVALID_CHANNEL_ID;
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
    const char *sessionName = NULL;
    uint32_t size;
    ReadInt32(req, &channelId);
    ReadInt32(req, &channelType);
    if (channelType == CHANNEL_TYPE_UNDEFINED) {
        sessionName = (const char*)ReadString(req, &size);
        if (sessionName == NULL) {
            TRANS_LOGE(TRANS_CTRL, "ServerCloseChannel sessionName is null");
            return SOFTBUS_IPC_ERR;
        }
    }
    ret = TransCloseChannel(sessionName, channelId, channelType);

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

int32_t ServerReleaseResources(IpcIo *req, IpcIo *reply)
{
    TRANS_LOGI(TRANS_CTRL, "ipc server pop");
    if (req == NULL || reply == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t channelId = 0;
    if (!ReadInt32(req, &channelId)) {
        TRANS_LOGE(TRANS_CTRL, "failed to read channelId");
        return SOFTBUS_IPC_ERR;
    }

    int32_t ret = TransReleaseUdpResources(channelId);
    return ret;
}

int32_t ServerPrivilegeCloseChannel(IpcIo *req, IpcIo *reply)
{
#define DMS_CALLING_UID 5522
    TRANS_LOGI(TRANS_CTRL, "ipc server pop");
    if (req == NULL || reply == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t callingUid = GetCallingUid();
    if (callingUid != DMS_CALLING_UID) {
        TRANS_LOGE(TRANS_CTRL, "uid check failed");
        return SOFTBUS_PERMISSION_DENIED;
    }
    int32_t ret;
    uint64_t tokenId = 0;
    int32_t pid = 0;
    const char *peerNetworkId = NULL;
    uint32_t size;
    if (ReadUint64(req, &tokenId)) {
        TRANS_LOGE(TRANS_CTRL, "failed to read tokenId");
        return SOFTBUS_IPC_ERR;
    }
    if (ReadInt32(req, &pid)) {
        TRANS_LOGE(TRANS_CTRL, "failed to read pid");
        return SOFTBUS_IPC_ERR;
    }
    peerNetworkId = (const char*)ReadString(req, &size);
    if (peerNetworkId == NULL) {
        TRANS_LOGE(TRANS_CTRL, "peerNetWorkId is null");
        return SOFTBUS_IPC_ERR;
    }
    ret = TransPrivilegeCloseChannel(tokenId, pid, peerNetworkId);
    WriteInt32(reply, ret);
    return ret;
}