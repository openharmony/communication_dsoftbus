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

#include "softbus_server_stub.h"

#include "discovery_service.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_bus_center.h"
#include "softbus_conn_interface.h"
#include "softbus_errcode.h"
#include "softbus_ipc_def.h"
#include "softbus_log.h"
#include "softbus_permission.h"
#include "softbus_server.h"
#include "softbus_server_frame.h"
#include "trans_channel_manager.h"
#include "trans_session_manager.h"

namespace OHOS {
int32_t SoftBusServerStub::CheckOpenSessionPermission(const SessionParam *param)
{
    char pkgName[PKG_NAME_SIZE_MAX] = {0};
    if ((param == nullptr) ||
        (TransGetPkgNameBySessionName(param->sessionName, pkgName, PKG_NAME_SIZE_MAX) != SOFTBUS_OK)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OpenSession TransGetPkgNameBySessionName failed");
        return SOFTBUS_INVALID_PARAM;
    }

    pid_t callingUid = OHOS::IPCSkeleton::GetCallingUid();
    pid_t callingPid = OHOS::IPCSkeleton::GetCallingPid();
    if (CheckTransPermission(callingUid, callingPid, pkgName, param->sessionName, ACTION_OPEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OpenSession no permission");
        return SOFTBUS_PERMISSION_DENIED;
    }

    if (CheckTransSecLevel(param->sessionName, param->peerSessionName) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OpenSession sec level invalid");
        return SOFTBUS_PERMISSION_DENIED;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::CheckChannelPermission(int32_t channelId, int32_t channelType)
{
    char pkgName[PKG_NAME_SIZE_MAX] = {0};
    char sessionName[SESSION_NAME_SIZE_MAX] = {0};
    int32_t ret = SOFTBUS_OK;
    TransInfo info;
    info.channelId = channelId;
    info.channelType = channelType;
    ret = TransGetNameByChanId(&info, pkgName, sessionName, PKG_NAME_SIZE_MAX, SESSION_NAME_SIZE_MAX);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "ServerCloseChannel invalid channel info");
        return ret;
    }

    pid_t callingUid = OHOS::IPCSkeleton::GetCallingUid();
    pid_t callingPid = OHOS::IPCSkeleton::GetCallingPid();
    if (CheckTransPermission(callingUid, callingPid, pkgName, sessionName, ACTION_OPEN) != SOFTBUS_OK) {
        return SOFTBUS_PERMISSION_DENIED;
    }
    return SOFTBUS_OK;
}

SoftBusServerStub::SoftBusServerStub()
{
    memberFuncMap_[SERVER_START_DISCOVERY] =
        &SoftBusServerStub::StartDiscoveryInner;
    memberFuncMap_[SERVER_STOP_DISCOVERY] =
        &SoftBusServerStub::StopDiscoveryInner;
    memberFuncMap_[SERVER_PUBLISH_SERVICE] =
        &SoftBusServerStub::PublishServiceInner;
    memberFuncMap_[SERVER_UNPUBLISH_SERVICE] =
        &SoftBusServerStub::UnPublishServiceInner;
    memberFuncMap_[MANAGE_REGISTER_SERVICE] =
        &SoftBusServerStub::SoftbusRegisterServiceInner;
    memberFuncMap_[SERVER_CREATE_SESSION_SERVER] =
        &SoftBusServerStub::CreateSessionServerInner;
    memberFuncMap_[SERVER_REMOVE_SESSION_SERVER] =
        &SoftBusServerStub::RemoveSessionServerInner;
    memberFuncMap_[SERVER_OPEN_SESSION] =
        &SoftBusServerStub::OpenSessionInner;
    memberFuncMap_[SERVER_OPEN_AUTH_SESSION] =
        &SoftBusServerStub::OpenAuthSessionInner;
    memberFuncMap_[SERVER_NOTIFY_AUTH_SUCCESS] =
        &SoftBusServerStub::NotifyAuthSuccessInner;
    memberFuncMap_[SERVER_CLOSE_CHANNEL] =
        &SoftBusServerStub::CloseChannelInner;
    memberFuncMap_[SERVER_SESSION_SENDMSG] =
        &SoftBusServerStub::SendMessageInner;
    memberFuncMap_[SERVER_JOIN_LNN] =
        &SoftBusServerStub::JoinLNNInner;
    memberFuncMap_[SERVER_LEAVE_LNN] =
        &SoftBusServerStub::LeaveLNNInner;
    memberFuncMap_[SERVER_GET_ALL_ONLINE_NODE_INFO] =
        &SoftBusServerStub::GetAllOnlineNodeInfoInner;
    memberFuncMap_[SERVER_GET_LOCAL_DEVICE_INFO] =
        &SoftBusServerStub::GetLocalDeviceInfoInner;
    memberFuncMap_[SERVER_GET_NODE_KEY_INFO] =
        &SoftBusServerStub::GetNodeKeyInfoInner;
    memberFuncMap_[SERVER_START_TIME_SYNC] =
        &SoftBusServerStub::StartTimeSyncInner;
    memberFuncMap_[SERVER_STOP_TIME_SYNC] =
        &SoftBusServerStub::StopTimeSyncInner;
    memberFuncMap_[SERVER_QOS_REPORT] =
        &SoftBusServerStub::QosReportInner;
    memberFuncMap_[SERVER_PUBLISH_LNN] =
        &SoftBusServerStub::PublishLNNInner;
    memberFuncMap_[SERVER_STOP_PUBLISH_LNN] =
        &SoftBusServerStub::StopPublishLNNInner;
    memberFuncMap_[SERVER_REFRESH_LNN] =
        &SoftBusServerStub::RefreshLNNInner;
    memberFuncMap_[SERVER_STOP_REFRESH_LNN] =
        &SoftBusServerStub::StopRefreshLNNInner;
    memberFuncMap_[SERVER_ACTIVE_META_NODE] =
        &SoftBusServerStub::ActiveMetaNodeInner;
    memberFuncMap_[SERVER_DEACTIVE_META_NODE] =
        &SoftBusServerStub::DeactiveMetaNodeInner;
    memberFuncMap_[SERVER_GET_ALL_META_NODE_INFO] =
        &SoftBusServerStub::GetAllMetaNodeInfoInner;
}

int32_t SoftBusServerStub::OnRemoteRequest(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "SoftBusServerStub::OnReceived, code = %u", code);
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SOFTBUS_SERVER_NOT_INIT ReadInterfaceToken failed!");
        return SOFTBUS_ERR;
    }
    if (GetServerIsInit() == false) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "server not init");
        if (!reply.WriteInt32(SOFTBUS_SERVER_NOT_INIT)) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SOFTBUS_SERVER_NOT_INIT write reply failed!");
        }
        return SOFTBUS_ERR;
    }
    auto itFunc = memberFuncMap_.find(code);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            return (this->*memberFunc)(data, reply);
        }
    }
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "SoftBusServerStub:: default case, need check.");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t SoftBusServerStub::StartDiscoveryInner(MessageParcel &data, MessageParcel &reply)
{
    SubscribeInfo subInfo;
    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "StartDiscoveryInner read pkgName failed!");
        return SOFTBUS_ERR;
    }
    subInfo.subscribeId = data.ReadInt32();
    subInfo.mode = (DiscoverMode)data.ReadInt32();
    subInfo.medium = (ExchanageMedium)data.ReadInt32();
    subInfo.freq = (ExchangeFreq)data.ReadInt32();
    subInfo.isSameAccount = data.ReadBool();
    subInfo.isWakeRemote = data.ReadBool();
    subInfo.capability = data.ReadCString();
    if (subInfo.capability == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "StartDiscoveryInner read capability failed!");
        return SOFTBUS_ERR;
    }
    subInfo.dataLen = data.ReadUint32();
    if (subInfo.dataLen > 0 && subInfo.dataLen < MAX_CAPABILITYDATA_LEN) {
        subInfo.capabilityData = (unsigned char *)data.ReadCString();
        if (subInfo.capabilityData == nullptr) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "StartDiscoveryInner read capabilityData failed!");
            return SOFTBUS_ERR;
        }
    } else {
        subInfo.capabilityData = nullptr;
        subInfo.dataLen = 0;
    }
    int32_t retReply = StartDiscovery(pkgName, &subInfo);
    if (!reply.WriteInt32(retReply)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "StartDiscoveryInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::StopDiscoveryInner(MessageParcel &data, MessageParcel &reply)
{
    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "StopDiscoveryInner read pkgName failed!");
        return SOFTBUS_ERR;
    }
    int32_t subscribeId = data.ReadInt32();
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "StopDiscoveryInner %s, %d!\n", pkgName, subscribeId);
    int32_t retReply = StopDiscovery(pkgName, subscribeId);
    if (!reply.WriteInt32(retReply)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "StopDiscoveryInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::PublishServiceInner(MessageParcel &data, MessageParcel &reply)
{
    PublishInfo pubInfo;
    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "PublishServiceInner read pkgName failed!");
        return SOFTBUS_ERR;
    }
    pubInfo.publishId = data.ReadInt32();
    pubInfo.mode = (DiscoverMode)data.ReadInt32();
    pubInfo.medium = (ExchanageMedium)data.ReadInt32();
    pubInfo.freq = (ExchangeFreq)data.ReadInt32();
    pubInfo.capability = data.ReadCString();
    if (pubInfo.capability == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "PublishServiceInner read capability failed!");
        return SOFTBUS_ERR;
    }
    pubInfo.dataLen = data.ReadUint32();
    if (pubInfo.dataLen > 0 && pubInfo.dataLen < MAX_CAPABILITYDATA_LEN) {
        pubInfo.capabilityData = (unsigned char *)data.ReadCString();
        if (pubInfo.capabilityData == nullptr) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "PublishServiceInner read capabilityData failed!");
            return SOFTBUS_ERR;
        }
    } else {
        pubInfo.capabilityData = nullptr;
        pubInfo.dataLen = 0;
    }
    int32_t retReply = PublishService(pkgName, &pubInfo);
    if (!reply.WriteInt32(retReply)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "PublishServiceInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::UnPublishServiceInner(MessageParcel &data, MessageParcel &reply)
{
    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "UnPublishServiceInner read pkgName failed!");
        return SOFTBUS_ERR;
    }
    int32_t publishId = data.ReadInt32();
    int32_t retReply = UnPublishService(pkgName, publishId);
    if (!reply.WriteInt32(retReply)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "UnPublishServiceInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::SoftbusRegisterServiceInner(MessageParcel &data, MessageParcel &reply)
{
    auto remote = data.ReadRemoteObject();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftbusRegisterServiceInner read systemAbilityId failed!");
        return SOFTBUS_ERR;
    }
    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftbusRegisterServiceInner read pkgName failed!");
        return SOFTBUS_ERR;
    }
    int32_t retReply = SoftbusRegisterService(pkgName, remote);
    if (!reply.WriteInt32(retReply)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftbusRegisterServiceInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::CreateSessionServerInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t retReply;
    pid_t callingUid;
    pid_t callingPid;
    const char *pkgName = data.ReadCString();
    const char *sessionName = data.ReadCString();
    if (pkgName == nullptr || sessionName == nullptr) {
        retReply = SOFTBUS_INVALID_PARAM;
        goto EXIT;
    }
    callingUid = OHOS::IPCSkeleton::GetCallingUid();
    callingPid = OHOS::IPCSkeleton::GetCallingPid();
    if (CheckTransPermission(callingUid, callingPid, pkgName, sessionName, ACTION_CREATE) != SOFTBUS_OK) {
        retReply = SOFTBUS_PERMISSION_DENIED;
        goto EXIT;
    }
    retReply = CreateSessionServer(pkgName, sessionName);
EXIT:
    if (!reply.WriteInt32(retReply)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "CreateSessionServerInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::RemoveSessionServerInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t retReply;
    pid_t callingUid;
    pid_t callingPid;
    const char *pkgName = data.ReadCString();
    const char *sessionName = data.ReadCString();
    if (pkgName == nullptr || sessionName == nullptr) {
        retReply = SOFTBUS_INVALID_PARAM;
        goto EXIT;
    }

    callingUid = OHOS::IPCSkeleton::GetCallingUid();
    callingPid = OHOS::IPCSkeleton::GetCallingPid();
    if (CheckTransPermission(callingUid, callingPid, pkgName, sessionName, ACTION_CREATE) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "RemoveSessionServerInner check perm failed");
        retReply = SOFTBUS_PERMISSION_DENIED;
        goto EXIT;
    }

    retReply = RemoveSessionServer(pkgName, sessionName);
EXIT:
    if (!reply.WriteInt32(retReply)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "RemoveSessionServerInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::OpenSessionInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t retReply;
    SessionParam param;
    TransSerializer transSerializer;
    param.sessionName = data.ReadCString();
    param.peerSessionName = data.ReadCString();
    param.peerDeviceId = data.ReadCString();
    param.groupId = data.ReadCString();
    param.attr = (SessionAttribute *)data.ReadRawData(sizeof(SessionAttribute));
    if (param.sessionName == nullptr || param.peerSessionName == nullptr || param.peerDeviceId == nullptr ||
        param.groupId == nullptr || param.attr == nullptr) {
        retReply = SOFTBUS_INVALID_PARAM;
        goto EXIT;
    }
    if (CheckOpenSessionPermission(&param) != SOFTBUS_OK) {
        retReply = SOFTBUS_PERMISSION_DENIED;
        goto EXIT;
    }
    retReply = OpenSession(&param, &(transSerializer.transInfo));

EXIT:
    transSerializer.ret = retReply;
    if (!reply.WriteRawData(&transSerializer, sizeof(TransSerializer))) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OpenSessionInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::OpenAuthSessionInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t retReply;
    const char *sessionName = data.ReadCString();
    ConnectionAddr *addrInfo = (ConnectionAddr *)data.ReadRawData(sizeof(ConnectionAddr));
    if (sessionName == nullptr || addrInfo == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OpenAuthSessionInner get param failed!");
        return SOFTBUS_ERR;
    }
    SessionParam param;
    param.sessionName = sessionName;
    param.peerSessionName = sessionName;
    retReply = CheckOpenSessionPermission(&param);
    if (retReply != SOFTBUS_OK) {
        goto EXIT;
    }
    retReply = OpenAuthSession(sessionName, addrInfo);
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "OpenAuthSession retReply:%d!", retReply);
EXIT:
    if (!reply.WriteInt32(retReply)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OpenSessionInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::NotifyAuthSuccessInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t channelId;
    if (!data.ReadInt32(channelId)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "NotifyAuthSuccessInner read channel Id failed!");
        return SOFTBUS_ERR;
    }
    int32_t retReply = NotifyAuthSuccess(channelId);
    if (!reply.WriteInt32(retReply)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "NotifyAuthSuccessInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::CloseChannelInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t channelId;
    if (!data.ReadInt32(channelId)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "CloseChannelInner read channel Id failed!");
        return SOFTBUS_ERR;
    }
    int32_t channelType;
    if (!data.ReadInt32(channelType)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "CloseChannelInner read channel channel type failed!");
        return SOFTBUS_ERR;
    }

    int32_t retReply = CloseChannel(channelId, channelType);
    if (!reply.WriteInt32(retReply)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "CloseChannelInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::SendMessageInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t channelId;
    if (!data.ReadInt32(channelId)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SendMessage read channel Id failed!");
        return SOFTBUS_ERR;
    }
    int32_t channelType;
    if (!data.ReadInt32(channelType)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SendMessage read channel type failed!");
        return SOFTBUS_ERR;
    }
    uint32_t len;
    if (!data.ReadUint32(len)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SendMessage dataInfo len failed!");
        return SOFTBUS_ERR;
    }
    void *dataInfo = (void *)data.ReadRawData(len);
    if (dataInfo == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SendMessage read dataInfo failed!");
        return SOFTBUS_ERR;
    }
    int32_t msgType;
    if (!data.ReadInt32(msgType)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SendMessage message type failed!");
        return SOFTBUS_ERR;
    }
    if (CheckChannelPermission(channelId, channelType) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SendMessage permission check failed!");
        return SOFTBUS_PERMISSION_DENIED;
    }

    int32_t retReply = SendMessage(channelId, channelType, dataInfo, len, msgType);
    if (!reply.WriteInt32(retReply)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SendMessage write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::JoinLNNInner(MessageParcel &data, MessageParcel &reply)
{
    const char *clientName = data.ReadCString();
    if (clientName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftbusJoinLNNInner read clientName failed!");
        return SOFTBUS_ERR;
    }
    uint32_t addrTypeLen;
    if (!data.ReadUint32(addrTypeLen) || addrTypeLen != sizeof(ConnectionAddr)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR,
            "SoftbusJoinLNNInner read addr type length:%d failed!", addrTypeLen);
        return SOFTBUS_ERR;
    }
    void *addr = (void *)data.ReadRawData(addrTypeLen);
    if (addr == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftbusJoinLNNInner read addr failed!");
        return SOFTBUS_ERR;
    }
    int32_t retReply = JoinLNN(clientName, addr, addrTypeLen);
    if (!reply.WriteInt32(retReply)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftbusJoinLNNInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::LeaveLNNInner(MessageParcel &data, MessageParcel &reply)
{
    const char *clientName = data.ReadCString();
    if (clientName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftbusLeaveLNNInner read clientName failed!");
        return SOFTBUS_ERR;
    }
    const char *networkId = data.ReadCString();
    if (networkId == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftbusLeaveLNNInner read networkId failed!");
        return SOFTBUS_ERR;
    }
    int32_t retReply = LeaveLNN(clientName, networkId);
    if (!reply.WriteInt32(retReply)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftbusJoinLNNInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::GetAllOnlineNodeInfoInner(MessageParcel &data, MessageParcel &reply)
{
    void *nodeInfo = nullptr;
    int32_t infoNum;
    uint32_t infoTypeLen;

    const char *clientName = data.ReadCString();
    if (clientName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetAllOnlineNodeInfoInner read clientName failed!");
        return SOFTBUS_ERR;
    }
    if (!data.ReadUint32(infoTypeLen)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetAllOnlineNodeInfoInner read info type length failed");
        return SOFTBUS_ERR;
    }
    if (GetAllOnlineNodeInfo(clientName, &nodeInfo, infoTypeLen, &infoNum) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetAllOnlineNodeInfoInner get info failed");
        return SOFTBUS_ERR;
    }
    if (infoNum < 0 || (infoNum > 0 && nodeInfo == nullptr)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetAllOnlineNodeInfoInner node info is invalid");
        return SOFTBUS_ERR;
    }
    if (!reply.WriteInt32(infoNum)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetAllOnlineNodeInfoInner write infoNum failed!");
        SoftBusFree(nodeInfo);
        return SOFTBUS_ERR;
    }
    int32_t ret = SOFTBUS_OK;
    if (infoNum > 0) {
        if (!reply.WriteRawData(nodeInfo, (int32_t)infoTypeLen * infoNum)) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetAllOnlineNodeInfoInner write node info failed!");
            ret = SOFTBUS_ERR;
        }
        SoftBusFree(nodeInfo);
    }
    return ret;
}

int32_t SoftBusServerStub::GetLocalDeviceInfoInner(MessageParcel &data, MessageParcel &reply)
{
    void *nodeInfo = nullptr;
    uint32_t infoTypeLen;

    const char *clientName = data.ReadCString();
    if (clientName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetLocalDeviceInfoInner read clientName failed!");
        return SOFTBUS_ERR;
    }
    
    infoTypeLen = sizeof(NodeBasicInfo);
    nodeInfo = SoftBusCalloc(infoTypeLen);
    if (nodeInfo == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetLocalDeviceInfoInner malloc info type length failed");
        return SOFTBUS_ERR;
    }
    if (GetLocalDeviceInfo(clientName, nodeInfo, infoTypeLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetLocalDeviceInfoInner get local info failed");
        SoftBusFree(nodeInfo);
        return SOFTBUS_ERR;
    }
    if (!reply.WriteRawData(nodeInfo, infoTypeLen)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetLocalDeviceInfoInner write node info failed!");
        SoftBusFree(nodeInfo);
        return SOFTBUS_ERR;
    }
    SoftBusFree(nodeInfo);
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::GetNodeKeyInfoLen(int32_t key)
{
    return LnnGetNodeKeyInfoLen(key);
}

int32_t SoftBusServerStub::GetNodeKeyInfoInner(MessageParcel &data, MessageParcel &reply)
{
    const char *clientName = data.ReadCString();
    if (clientName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetNodeKeyInfoInner read clientName failed!");
        return SOFTBUS_ERR;
    }
    const char *networkId = data.ReadCString();
    if (networkId == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetNodeKeyInfoInner read networkId failed!");
        return SOFTBUS_ERR;
    }
    int32_t key;
    if (!data.ReadInt32(key)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetNodeKeyInfoInner read key failed!");
        return SOFTBUS_ERR;
    }
    int32_t infoLen = GetNodeKeyInfoLen(key);
    if (infoLen == SOFTBUS_ERR) {
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t len;
    if (!data.ReadInt32(len)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetNodeKeyInfoInner read len failed!");
        return SOFTBUS_ERR;
    }
    if (len < infoLen) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetNodeKeyInfoInner read len is invalid param!");
        return SOFTBUS_INVALID_PARAM;
    }
    void *buf = SoftBusCalloc(infoLen);
    if (buf == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetNodeKeyInfoInner malloc buffer failed!");
        return SOFTBUS_ERR;
    }
    if (GetNodeKeyInfo(clientName, networkId, key, (unsigned char *)buf, infoLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetNodeKeyInfoInner get key info failed!");
        SoftBusFree(buf);
        return SOFTBUS_ERR;
    }
    if (!reply.WriteInt32(infoLen)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetNodeKeyInfoInner write info length failed!");
        SoftBusFree(buf);
        return SOFTBUS_ERR;
    }
    if (!reply.WriteRawData(buf, infoLen)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetNodeKeyInfoInner write key info failed!");
        SoftBusFree(buf);
        return SOFTBUS_ERR;
    }
    SoftBusFree(buf);
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::StartTimeSyncInner(MessageParcel &data, MessageParcel &reply)
{
    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "StartTimeSyncInner read pkgName failed!");
        return SOFTBUS_ERR;
    }
    const char *targetNetworkId = data.ReadCString();
    if (targetNetworkId == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "StartTimeSyncInner read targetNetworkId failed!");
        return SOFTBUS_ERR;
    }
    int32_t accuracy;
    if (!data.ReadInt32(accuracy)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "StartTimeSyncInner read accuracy failed!");
        return SOFTBUS_ERR;
    }
    int32_t period;
    if (!data.ReadInt32(period)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "StartTimeSyncInner read period failed!");
        return SOFTBUS_ERR;
    }
    int32_t retReply = StartTimeSync(pkgName, targetNetworkId, accuracy, period);
    if (!reply.WriteInt32(retReply)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "StartTimeSyncInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::StopTimeSyncInner(MessageParcel &data, MessageParcel &reply)
{
    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "StopTimeSyncInner read pkgName failed!");
        return SOFTBUS_ERR;
    }
    const char *targetNetworkId = data.ReadCString();
    if (targetNetworkId == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "StopTimeSyncInner read targetNetworkId failed!");
        return SOFTBUS_ERR;
    }
    int32_t retReply = StopTimeSync(pkgName, targetNetworkId);
    if (!reply.WriteInt32(retReply)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "StopTimeSyncInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::QosReportInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t channelId;
    if (!data.ReadInt32(channelId)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "QosReportInner read channel Id failed!");
        return SOFTBUS_ERR;
    }
    int32_t channelType;
    if (!data.ReadInt32(channelType)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "QosReportInner read channel channel type failed!");
        return SOFTBUS_ERR;
    }
    int32_t appType;
    if (!data.ReadInt32(appType)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "QosReportInner read channel appType failed!");
        return SOFTBUS_ERR;
    }
    int32_t quality;
    if (!data.ReadInt32(quality)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "QosReportInner read quality failed!");
        return SOFTBUS_ERR;
    }

    int32_t retReply = QosReport(channelId, channelType, appType, quality);
    if (!reply.WriteInt32(retReply)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "QosReportInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::PublishLNNInner(MessageParcel &data, MessageParcel &reply)
{
    const char *clientName = data.ReadCString();
    if (clientName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftbusPublishLNNInner read clientName failed!");
        return SOFTBUS_ERR;
    }
    PublishInfo info;
    int32_t mode, medium, freq;
    (void)memset_s(&info, sizeof(PublishInfo), 0, sizeof(PublishInfo));
    if (!data.ReadInt32(info.publishId) || !data.ReadInt32(mode) || !data.ReadInt32(medium) ||
        !data.ReadInt32(freq)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftbusPublishLNNInner read common publish info failed!");
        return SOFTBUS_ERR;
    }
    info.mode = (DiscoverMode)mode;
    info.medium = (ExchanageMedium)medium;
    info.freq = (ExchangeFreq)freq;
    info.capability = data.ReadCString();
    if (info.capability == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftbusPublishLNNInner read capability failed!");
        return SOFTBUS_ERR;
    }
    if (!data.ReadUint32(info.dataLen)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftbusPublishLNNInner read dataLen failed!");
        return SOFTBUS_ERR;
    }
    if (info.dataLen > 0 && info.dataLen < MAX_CAPABILITYDATA_LEN) {
        info.capabilityData = (unsigned char *)data.ReadRawData(info.dataLen);
        if (info.capabilityData == nullptr) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftbusPublishLNNInner read capabilityData failed!");
            return SOFTBUS_ERR;
        }
    } else {
        info.capabilityData = nullptr;
        info.dataLen = 0;
    }
    int32_t retReply = PublishLNN(clientName, &info);
    if (!reply.WriteInt32(retReply)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftbusPublishLNNInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::StopPublishLNNInner(MessageParcel &data, MessageParcel &reply)
{
    const char *clientName = data.ReadCString();
    if (clientName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftbusStopPublishLNNInner read clientName failed!");
        return SOFTBUS_ERR;
    }
    int32_t publishId;
    if (!data.ReadInt32(publishId)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftbusStopPublishLNNInner read publishId failed!");
        return SOFTBUS_ERR;
    }
    int32_t retReply = StopPublishLNN(clientName, publishId);
    if (!reply.WriteInt32(retReply)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftbusStopPublishLNNInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::RefreshLNNInner(MessageParcel &data, MessageParcel &reply)
{
    const char *clientName = data.ReadCString();
    if (clientName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftbusRefreshLNNInner read clientName failed!");
        return SOFTBUS_ERR;
    }
    SubscribeInfo info;
    int32_t mode, medium, freq;
    (void)memset_s(&info, sizeof(SubscribeInfo), 0, sizeof(SubscribeInfo));
    if (!data.ReadInt32(info.subscribeId) || !data.ReadInt32(mode) || !data.ReadInt32(medium) ||
        !data.ReadInt32(freq)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftbusRefreshLNNInner read common subscribe info failed!");
        return SOFTBUS_ERR;
    }
    info.mode = (DiscoverMode)mode;
    info.medium = (ExchanageMedium)medium;
    info.freq = (ExchangeFreq)freq;
    if (!data.ReadBool(info.isSameAccount) || !data.ReadBool(info.isWakeRemote)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftbusRefreshLNNInner read subscribe info flag failed!");
        return SOFTBUS_ERR;
    }
    info.capability = data.ReadCString();
    if (info.capability == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftbusRefreshLNNInner read capability failed!");
        return SOFTBUS_ERR;
    }
    if (!data.ReadUint32(info.dataLen)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftbusRefreshLNNInner read dataLen failed!");
        return SOFTBUS_ERR;
    }
    if (info.dataLen > 0 && info.dataLen < MAX_CAPABILITYDATA_LEN) {
        info.capabilityData = (unsigned char *)data.ReadRawData(info.dataLen);
        if (info.capabilityData == nullptr) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftbusRefreshLNNInner read capabilityData failed!");
            return SOFTBUS_ERR;
        }
    } else {
        info.capabilityData = nullptr;
        info.dataLen = 0;
    }
    int32_t retReply = RefreshLNN(clientName, &info);
    if (!reply.WriteInt32(retReply)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftbusRefreshLNNInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::StopRefreshLNNInner(MessageParcel &data, MessageParcel &reply)
{
    const char *clientName = data.ReadCString();
    if (clientName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftbusStopRefreshLNNInner read clientName failed!");
        return SOFTBUS_ERR;
    }
    int32_t refreshId;
    if (!data.ReadInt32(refreshId)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftbusStopRefreshLNNInner read refreshId failed!");
        return SOFTBUS_ERR;
    }
    int32_t retReply = StopRefreshLNN(clientName, refreshId);
    if (!reply.WriteInt32(retReply)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftbusStopRefreshLNNInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::ActiveMetaNodeInner(MessageParcel &data, MessageParcel &reply)
{
    MetaNodeConfigInfo *info = (MetaNodeConfigInfo *)data.ReadRawData(sizeof(MetaNodeConfigInfo));
    if (info == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ActiveMetaNode read meta node config info failed!");
        return SOFTBUS_ERR;
    }
    char metaNodeId[NETWORK_ID_BUF_LEN] = {0};
    if (ActiveMetaNode(info, metaNodeId) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (!reply.WriteCString(metaNodeId)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ActiveMetaNode write meta node id failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::DeactiveMetaNodeInner(MessageParcel &data, MessageParcel &reply)
{
    const char *metaNodeId = (const char *)data.ReadCString();
    if (metaNodeId == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "DeactiveMetaNode read meta node id failed!");
        return SOFTBUS_ERR;
    }
    if (DeactiveMetaNode(metaNodeId) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::GetAllMetaNodeInfoInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t infoNum;
    MetaNodeInfo infos[MAX_META_NODE_NUM];

    if (!data.ReadInt32(infoNum)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetAllMetaNodeInfo read infoNum failed!");
        return SOFTBUS_ERR;
    }
    if (GetAllMetaNodeInfo(infos, &infoNum) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (!reply.WriteInt32(infoNum)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetAllMetaNodeInfo write infoNum failed!");
        return SOFTBUS_ERR;
    }
    if (infoNum > 0 && !reply.WriteRawData(infos, infoNum * sizeof(MetaNodeInfo))) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetAllMetaNodeInfo write meta node info failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}
} // namespace OHOS
