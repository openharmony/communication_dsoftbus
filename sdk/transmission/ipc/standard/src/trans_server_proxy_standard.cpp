/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "trans_server_proxy_standard.h"

#include "ipc_skeleton.h"
#include "ipc_types.h"

#include "message_parcel.h"
#include "softbus_errcode.h"
#include "softbus_ipc_def.h"
#include "softbus_log.h"

namespace OHOS {
static uint32_t g_getSystemAbilityId = 2;
const std::u16string SAMANAGER_INTERFACE_TOKEN = u"ohos.samgr.accessToken";
static sptr<IRemoteObject> GetSystemAbility()
{
    MessageParcel data;

    if (!data.WriteInterfaceToken(SAMANAGER_INTERFACE_TOKEN)) {
        return nullptr;
    }

    data.WriteInt32(SOFTBUS_SERVER_SA_ID_INNER);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> samgr = IPCSkeleton::GetContextObject();
    int32_t err = samgr->SendRequest(g_getSystemAbilityId, data, reply, option);
    if (err != 0) {
        LOG_ERR("Get GetSystemAbility failed!\n");
        return nullptr;
    }
    return reply.ReadRemoteObject();
}

int32_t TransServerProxy::StartDiscovery(const char *pkgName, const SubscribeInfo *subInfo)
{
    (void)pkgName;
    (void)subInfo;
    return SOFTBUS_OK;
}

int32_t TransServerProxy::StopDiscovery(const char *pkgName, int subscribeId)
{
    (void)pkgName;
    (void)subscribeId;
    return SOFTBUS_OK;
}

int32_t TransServerProxy::PublishService(const char *pkgName, const PublishInfo *pubInfo)
{
    (void)pkgName;
    (void)pubInfo;
    return SOFTBUS_OK;
}

int32_t TransServerProxy::UnPublishService(const char *pkgName, int publishId)
{
    (void)pkgName;
    (void)publishId;
    return SOFTBUS_OK;
}

int32_t TransServerProxy::SoftbusRegisterService(const char *clientPkgName, const sptr<IRemoteObject>& object)
{
    (void)clientPkgName;
    (void)object;
    return SOFTBUS_OK;
}

int32_t TransServerProxy::CreateSessionServer(const char *pkgName, const char *sessionName)
{
    if (pkgName == nullptr || sessionName == nullptr) {
        return SOFTBUS_ERR;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "CreateSessionServer write InterfaceToken failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "CreateSessionServer write pkg name failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(sessionName)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "CreateSessionServer write session name failed!");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_CREATE_SESSION_SERVER, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "CreateSessionServer send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "CreateSessionServer read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t TransServerProxy::RemoveSessionServer(const char *pkgName, const char *sessionName)
{
    if (pkgName == nullptr || sessionName == nullptr) {
        return SOFTBUS_ERR;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_TRANS_PROXY_REMOTE_NULL;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "RemoveSessionServer write InterfaceToken failed!");
        return SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED;
    }
    if (!data.WriteCString(pkgName)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "RemoveSessionServer write pkg name failed!");
        return SOFTBUS_TRANS_PROXY_WRITECSTRING_FAILED;
    }
    if (!data.WriteCString(sessionName)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "RemoveSessionServer session name failed!");
        return SOFTBUS_TRANS_PROXY_WRITECSTRING_FAILED;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_REMOVE_SESSION_SERVER, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "RemoveSessionServer send request failed!");
        return SOFTBUS_TRANS_PROXY_SEND_REQUEST_FAILED;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "RemoveSessionServer read serverRet failed!");
        return SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED;
    }
    return serverRet;
}

int32_t TransServerProxy::OpenSession(const SessionParam *param, TransInfo *info)
{
    if (param->sessionName == nullptr || param->peerSessionName == nullptr ||
        param->peerDeviceId == nullptr || param->groupId == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_TRANS_PROXY_REMOTE_NULL;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenSession write InterfaceToken failed!");
        return SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED;
    }
    if (!data.WriteCString(param->sessionName)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenSession write my session name failed!");
        return SOFTBUS_TRANS_PROXY_WRITECSTRING_FAILED;
    }
    if (!data.WriteCString(param->peerSessionName)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenSession write peer session name failed!");
        return SOFTBUS_TRANS_PROXY_WRITECSTRING_FAILED;
    }
    if (!data.WriteCString(param->peerDeviceId)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenSession write addr type length failed!");
        return SOFTBUS_TRANS_PROXY_WRITECSTRING_FAILED;
    }
    if (!data.WriteCString(param->groupId)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenSession write addr type length failed!");
        return SOFTBUS_TRANS_PROXY_WRITECSTRING_FAILED;
    }

    if (!data.WriteRawData(param->attr, sizeof(SessionAttribute))) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenSession write addr type length failed!");
        return SOFTBUS_TRANS_PROXY_WRITERAWDATA_FAILED;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_OPEN_SESSION, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenSession send request failed!");
        return SOFTBUS_TRANS_PROXY_SEND_REQUEST_FAILED;
    }
    TransSerializer *transSerializer = (TransSerializer *)reply.ReadRawData(sizeof(TransSerializer));
    if (transSerializer == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OpenSession read TransSerializer failed!");
        return SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED;
    }
    info->channelId = transSerializer->transInfo.channelId;
    info->channelType = transSerializer->transInfo.channelType;
    return transSerializer->ret;
}

int32_t TransServerProxy::OpenAuthSession(const char *sessionName, const ConnectionAddr *addrInfo)
{
    if (sessionName == nullptr || addrInfo == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "%s ServerIpcOpenAuthSession begin", sessionName);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenSession write InterfaceToken failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(sessionName)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenSession write my session name failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteRawData((void *)addrInfo, sizeof(ConnectionAddr))) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenSession write ConnectionAddr failed!");
        return SOFTBUS_ERR;
    }

    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_OPEN_AUTH_SESSION, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenSession send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t channelId = 0;
    if (!reply.ReadInt32(channelId)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenSession read channelId failed!");
        return SOFTBUS_ERR;
    }
    return channelId;
}

int32_t TransServerProxy::NotifyAuthSuccess(int32_t channelId, int32_t channelType)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "ServerIpcNotifyAuthSuccess write InterfaceToken failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(channelId)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "ServerIpcNotifyAuthSuccess write channel id failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(channelType)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "ServerIpcNotifyAuthSuccess write channel type failed!");
        return SOFTBUS_ERR;
    }

    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_NOTIFY_AUTH_SUCCESS, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "ServerIpcNotifyAuthSuccess send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "ServerIpcNotifyAuthSuccess read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t TransServerProxy::CloseChannel(int32_t channelId, int32_t channelType)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "CloseChannel write InterfaceToken failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(channelId)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "CloseChannel write channel id failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(channelType)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "CloseChannel write channel type failed!");
        return SOFTBUS_ERR;
    }

    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_CLOSE_CHANNEL, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "CloseChannel send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "CloseChannel read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t TransServerProxy::SendMessage(int32_t channelId, int32_t channelType, const void *dataInfo,
    uint32_t len, int32_t msgType)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SendMessage write InterfaceToken failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(channelId)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SendMessage write channel id failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(channelType)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SendMessage write channel type failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteUint32(len)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SendMessage write dataInfo len failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteRawData(dataInfo, len)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SendMessage write dataInfo failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(msgType)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SendMessage msgType failed!");
        return SOFTBUS_ERR;
    }

    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_SESSION_SENDMSG, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SendMessage send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SendMessage read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t TransServerProxy::QosReport(int32_t channelId, int32_t chanType, int32_t appType, int32_t quality)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "QosReport write InterfaceToken failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(channelId)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "QosReport channelId failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(chanType)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "QosReport chanType failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(appType)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "QosReport appType failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(quality)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "QosReport quality failed!");
        return SOFTBUS_ERR;
    }

    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_QOS_REPORT, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "QosReport send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "QosReport read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t TransServerProxy::StreamStats(int32_t channelId, int32_t channelType, const StreamSendStats *statsData)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "StreamStats write InterfaceToken failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(channelId)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "StreamStats channelId failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(channelType)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "StreamStats channelType failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteRawData((void *)statsData, sizeof(StreamSendStats))) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write streamSendStats failed!");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(SERVER_STREAM_STATS, data, reply, option);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "StreamStats send request failed, ret:%d", ret);
        return SOFTBUS_ERR;
    }
    if (!reply.ReadInt32(ret)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "StreamStats read serverRet failed");
        return SOFTBUS_ERR;
    }
    return ret;
}

int32_t TransServerProxy::RippleStats(int32_t channelId, int32_t channelType, const TrafficStats *statsData)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "RippleStats write InterfaceToken failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(channelId)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "RippleStats channelId failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(channelType)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "RippleStats channelType failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteRawData((void *)statsData, sizeof(TrafficStats))) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "write RippleStats failed!");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(SERVER_RIPPLE_STATS, data, reply, option);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "RippleStats send request failed, ret:%d", ret);
        return SOFTBUS_ERR;
    }
    if (!reply.ReadInt32(ret)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "RippleStats read serverRet failed");
        return SOFTBUS_ERR;
    }
    return ret;
}

int32_t TransServerProxy::GrantPermission(int uid, int pid, const char *sessionName)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GrantPermission write InterfaceToken failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(uid)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GrantPermission write uid failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(pid)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GrantPermission write pid failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(sessionName)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GrantPermission write sessionName failed!");
        return SOFTBUS_ERR;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(SERVER_GRANT_PERMISSION, data, reply, option);
    if (ret != ERR_NONE) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GrantPermission send request failed, ret=%d", ret);
        return SOFTBUS_ERR;
    }
    if (!reply.ReadInt32(ret)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GrantPermission read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return ret;
}

int32_t TransServerProxy::RemovePermission(const char *sessionName)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "RemovePermission write InterfaceToken failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(sessionName)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "RemovePermission write sessionName failed!");
        return SOFTBUS_ERR;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(SERVER_REMOVE_PERMISSION, data, reply, option);
    if (ret != ERR_NONE) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "RemovePermission send request failed, ret=%d", ret);
        return SOFTBUS_ERR;
    }
    if (!reply.ReadInt32(ret)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "RemovePermission read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return ret;
}

int32_t TransServerProxy::JoinLNN(const char *pkgName, void *addr, uint32_t addrTypeLen)
{
    (void)pkgName;
    (void)addr;
    (void)addrTypeLen;
    return SOFTBUS_OK;
}

int32_t TransServerProxy::JoinMetaNode(const char *pkgName, void *addr, CustomData *customData, uint32_t addrTypeLen)
{
    (void)pkgName;
    (void)addr;
    (void)customData;
    (void)addrTypeLen;
    return SOFTBUS_OK;
}

int32_t TransServerProxy::LeaveLNN(const char *pkgName, const char *networkId)
{
    (void)pkgName;
    (void)networkId;
    return SOFTBUS_OK;
}

int32_t TransServerProxy::LeaveMetaNode(const char *pkgName, const char *networkId)
{
    (void)pkgName;
    (void)networkId;
    return SOFTBUS_OK;
}

int32_t TransServerProxy::GetAllOnlineNodeInfo(const char *pkgName, void **info, uint32_t infoTypeLen, int *infoNum)
{
    (void)pkgName;
    (void)info;
    (void)infoTypeLen;
    (void)infoNum;
    return SOFTBUS_OK;
}

int32_t TransServerProxy::GetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen)
{
    (void)pkgName;
    (void)info;
    (void)infoTypeLen;
    return SOFTBUS_OK;
}

int32_t TransServerProxy::GetNodeKeyInfo(const char *pkgName, const char *networkId, int key, unsigned char *buf,
    uint32_t len)
{
    (void)pkgName;
    (void)networkId;
    (void)key;
    (void)buf;
    (void)len;
    return SOFTBUS_OK;
}

int32_t TransServerProxy::SetNodeDataChangeFlag(const char *pkgName, const char *networkId, uint16_t dataChangeFlag)
{
    (void)pkgName;
    (void)networkId;
    (void)dataChangeFlag;
    return SOFTBUS_OK;
}

int32_t TransServerProxy::StartTimeSync(const char *pkgName, const char *targetNetworkId, int32_t accuracy,
    int32_t period)
{
    (void)pkgName;
    (void)targetNetworkId;
    (void)accuracy;
    (void)period;
    return SOFTBUS_OK;
}

int32_t TransServerProxy::StopTimeSync(const char *pkgName, const char *targetNetworkId)
{
    (void)pkgName;
    (void)targetNetworkId;
    return SOFTBUS_OK;
}
} // namespace OHOS
