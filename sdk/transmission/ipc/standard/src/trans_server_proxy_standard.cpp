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

#include "trans_server_proxy_standard.h"

#include "anonymizer.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "message_parcel.h"
#include "softbus_error_code.h"
#include "softbus_server_ipc_interface_code.h"
#include "trans_log.h"

#define WRITE_PARCEL_WITH_RET(parcel, type, data, retval)                              \
    do {                                                                               \
        if (!(parcel).Write##type(data)) {                                             \
            TRANS_LOGE(TRANS_SDK, "write data failed.");                               \
            return (retval);                                                           \
        }                                                                              \
    } while (false)

#define CHANNEL_TYPE_UNDEFINED (-1)

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
    if (samgr == nullptr) {
        TRANS_LOGE(TRANS_SDK, "Get samgr failed!");
        return nullptr;
    }
    int32_t err = samgr->SendRequest(g_getSystemAbilityId, data, reply, option);
    if (err != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "Get GetSystemAbility failed!");
        return nullptr;
    }
    return reply.ReadRemoteObject();
}

int32_t TransServerProxy::SoftbusRegisterService(const char *clientPkgName, const sptr<IRemoteObject> &object)
{
    (void)clientPkgName;
    (void)object;
    return SOFTBUS_OK;
}

int32_t TransServerProxy::CreateSessionServer(const char *pkgName, const char *sessionName)
{
    if (pkgName == nullptr || sessionName == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        TRANS_LOGE(TRANS_SDK, "remote is nullptr!");
        return SOFTBUS_TRANS_PROXY_REMOTE_NULL;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TRANS_LOGE(TRANS_SDK, "write InterfaceToken failed!");
        return SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED;
    }
    if (!data.WriteCString(pkgName)) {
        TRANS_LOGE(TRANS_SDK, "write pkg name failed!");
        return SOFTBUS_TRANS_PROXY_WRITECSTRING_FAILED;
    }
    if (!data.WriteCString(sessionName)) {
        TRANS_LOGE(TRANS_SDK, "write session name failed!");
        return SOFTBUS_TRANS_PROXY_WRITECSTRING_FAILED;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(SERVER_CREATE_SESSION_SERVER, data, reply, option);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "send request failed! ret=%{public}d", ret);
        return ret;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        TRANS_LOGE(TRANS_SDK, "read serverRet failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    return serverRet;
}

int32_t TransServerProxy::RemoveSessionServer(const char *pkgName, const char *sessionName)
{
    if (pkgName == nullptr || sessionName == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        TRANS_LOGE(TRANS_SDK, "remote is nullptr!");
        return SOFTBUS_TRANS_PROXY_REMOTE_NULL;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TRANS_LOGE(TRANS_SDK, "write InterfaceToken failed!");
        return SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED;
    }
    if (!data.WriteCString(pkgName)) {
        TRANS_LOGE(TRANS_SDK, "write pkg name failed!");
        return SOFTBUS_TRANS_PROXY_WRITECSTRING_FAILED;
    }
    if (!data.WriteCString(sessionName)) {
        TRANS_LOGE(TRANS_SDK, "session name failed!");
        return SOFTBUS_TRANS_PROXY_WRITECSTRING_FAILED;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(SERVER_REMOVE_SESSION_SERVER, data, reply, option);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "send request failed! ret=%{public}d", ret);
        return ret;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        TRANS_LOGE(TRANS_SDK, "read serverRet failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    return serverRet;
}

int32_t TransServerProxy::ReleaseResources(int32_t channelId)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        TRANS_LOGD(TRANS_SDK, "remote is nullptr!");
        return SOFTBUS_TRANS_PROXY_REMOTE_NULL;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TRANS_LOGE(TRANS_SDK, "failed to write InterfaceToken");
        return SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED;
    }
    if (!data.WriteInt32(channelId)) {
        TRANS_LOGE(TRANS_SDK, "failed to write channelId");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(SERVER_RELEASE_RESOURCES, data, reply, option);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "failed to send request ret=%{public}d", ret);
        return ret;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        TRANS_LOGE(TRANS_SDK, "failed to read serverRet failed");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    return SOFTBUS_OK;
}

static bool TransWriteSessionAttrs(const SessionAttribute *attrs, MessageParcel &data)
{
    if (attrs == nullptr) {
        TRANS_LOGE(TRANS_SDK, "attrs is nullptr!");
        return false;
    }

    if (!data.WriteInt32(attrs->dataType)) {
        TRANS_LOGE(TRANS_SDK, "OpenSession write my attrs dataType failed!");
        return false;
    }

    if (!data.WriteInt32(attrs->linkTypeNum)) {
        TRANS_LOGE(TRANS_SDK, "OpenSession write my attrs linkTypeNum failed!");
        return false;
    }

    if (attrs->linkTypeNum > 0) {
        if (!data.WriteBuffer(attrs->linkType, sizeof(LinkType) * attrs->linkTypeNum)) {
            TRANS_LOGE(TRANS_SDK, "OpenSession write my attrs linkType failed!");
            return false;
        }
    }

    if (!data.WriteInt32(attrs->attr.streamAttr.streamType)) {
        TRANS_LOGE(TRANS_SDK, "OpenSession write my attrs streamAttr failed!");
        return false;
    }

    if (attrs->fastTransData != nullptr) {
        if (!data.WriteUint16(attrs->fastTransDataSize)) {
            TRANS_LOGE(TRANS_SDK, "OpenSession write my attrs fastTransDataSize failed!");
            return false;
        }
        if (!data.WriteRawData(attrs->fastTransData, attrs->fastTransDataSize)) {
            TRANS_LOGE(TRANS_SDK, "OpenSession write my attrs fastTransData failed!");
            return false;
        }
    } else {
        if (!data.WriteUint16(0)) {
            TRANS_LOGE(TRANS_SDK, "OpenSession write my attrs fastTransDataSize failed!");
            return false;
        }
    }

    return true;
}

static bool WriteQosInfo(const SessionParam *param, MessageParcel &data)
{
    if (!data.WriteBool(param->isQosLane)) {
        TRANS_LOGE(TRANS_SDK, "OpenSession write qos flag failed!");
        return false;
    }

    if (!param->isQosLane) {
        return true;
    }

    if (!data.WriteUint32(param->qosCount)) {
        TRANS_LOGE(TRANS_SDK, "OpenSession write count of qos failed!");
        return false;
    }

    if (param->qosCount > 0) {
        if (!data.WriteBuffer(param->qos, sizeof(QosTV) * param->qosCount)) {
            TRANS_LOGE(TRANS_SDK, "OpenSession write qos info failed!");
            return false;
        }
    }

    return true;
}

int32_t TransServerProxy::OpenSession(const SessionParam *param, TransInfo *info)
{
    if (param->sessionName == nullptr || param->peerSessionName == nullptr ||
        param->peerDeviceId == nullptr || param->groupId == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        TRANS_LOGE(TRANS_SDK, "remote is nullptr!");
        return SOFTBUS_TRANS_PROXY_REMOTE_NULL;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TRANS_LOGE(TRANS_SDK, "OpenSession write InterfaceToken failed!");
        return SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED;
    }
    WRITE_PARCEL_WITH_RET(data, CString, param->sessionName, SOFTBUS_TRANS_PROXY_WRITECSTRING_FAILED);
    WRITE_PARCEL_WITH_RET(data, CString, param->peerSessionName, SOFTBUS_TRANS_PROXY_WRITECSTRING_FAILED);
    WRITE_PARCEL_WITH_RET(data, CString, param->peerDeviceId, SOFTBUS_TRANS_PROXY_WRITECSTRING_FAILED);
    WRITE_PARCEL_WITH_RET(data, CString, param->groupId, SOFTBUS_TRANS_PROXY_WRITECSTRING_FAILED);
    WRITE_PARCEL_WITH_RET(data, Bool, param->isAsync, SOFTBUS_TRANS_PROXY_WRITERAWDATA_FAILED);
    WRITE_PARCEL_WITH_RET(data, Int32, param->sessionId, SOFTBUS_TRANS_PROXY_WRITERAWDATA_FAILED);
    WRITE_PARCEL_WITH_RET(data, Uint32, param->actionId, SOFTBUS_TRANS_PROXY_WRITEINT_FAILED);
    if (!TransWriteSessionAttrs(param->attr, data)) {
        TRANS_LOGE(TRANS_SDK, "OpenSession write attr failed!");
        return SOFTBUS_TRANS_PROXY_WRITERAWDATA_FAILED;
    }

    if (!WriteQosInfo(param, data)) {
        TRANS_LOGE(TRANS_SDK, "OpenSession write qos failed!");
        return SOFTBUS_TRANS_PROXY_WRITECSTRING_FAILED;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(SERVER_OPEN_SESSION, data, reply, option);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "OpenSession send request failed! ret=%{public}d", ret);
        return ret;
    }
    TransSerializer *transSerializer = (TransSerializer *)reply.ReadRawData(sizeof(TransSerializer));
    if (transSerializer == nullptr) {
        TRANS_LOGE(TRANS_SDK, "OpenSession read TransSerializer failed!");
        return SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED;
    }
    if (param->isAsync) {
        return transSerializer->ret;
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
    char *tmpName = nullptr;
    Anonymize(sessionName, &tmpName);
    TRANS_LOGI(TRANS_SDK, "ServerIpcOpenAuthSession begin. sessionName=%{public}s", AnonymizeWrapper(tmpName));
    AnonymizeFree(tmpName);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TRANS_LOGE(TRANS_SDK, "remote is nullptr!");
        return SOFTBUS_TRANS_PROXY_REMOTE_NULL;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TRANS_LOGE(TRANS_SDK, "OpenSession write InterfaceToken failed!");
        return SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED;
    }
    if (!data.WriteCString(sessionName)) {
        TRANS_LOGE(TRANS_SDK, "OpenSession write my session name failed!");
        return SOFTBUS_TRANS_PROXY_WRITECSTRING_FAILED;
    }
    if (!data.WriteRawData((void *)addrInfo, sizeof(ConnectionAddr))) {
        TRANS_LOGE(TRANS_SDK, "OpenSession write ConnectionAddr failed!");
        return SOFTBUS_TRANS_PROXY_WRITERAWDATA_FAILED;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(SERVER_OPEN_AUTH_SESSION, data, reply, option);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "OpenSession send request failed! ret=%{public}d", ret);
        return ret;
    }
    int32_t channelId = 0;
    if (!reply.ReadInt32(channelId)) {
        TRANS_LOGE(TRANS_SDK, "OpenSession read channelId failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    return channelId;
}

int32_t TransServerProxy::NotifyAuthSuccess(int32_t channelId, int32_t channelType)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        TRANS_LOGE(TRANS_SDK, "remote is nullptr!");
        return SOFTBUS_TRANS_PROXY_REMOTE_NULL;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TRANS_LOGE(TRANS_SDK, "ServerIpcNotifyAuthSuccess write InterfaceToken failed!");
        return SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED;
    }
    if (!data.WriteInt32(channelId)) {
        TRANS_LOGE(TRANS_SDK, "ServerIpcNotifyAuthSuccess write channel id failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    if (!data.WriteInt32(channelType)) {
        TRANS_LOGE(TRANS_SDK, "ServerIpcNotifyAuthSuccess write channel type failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(SERVER_NOTIFY_AUTH_SUCCESS, data, reply, option);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "ServerIpcNotifyAuthSuccess send request failed! ret=%{public}d", ret);
        return ret;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        TRANS_LOGE(TRANS_SDK, "ServerIpcNotifyAuthSuccess read serverRet failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    return serverRet;
}

int32_t TransServerProxy::CloseChannel(const char *sessionName, int32_t channelId, int32_t channelType)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        TRANS_LOGE(TRANS_SDK, "remote is nullptr!");
        return SOFTBUS_TRANS_PROXY_REMOTE_NULL;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TRANS_LOGE(TRANS_SDK, "CloseChannel write InterfaceToken failed!");
        return SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED;
    }
    if (!data.WriteInt32(channelId)) {
        TRANS_LOGE(TRANS_SDK, "CloseChannel write channel id failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    if (!data.WriteInt32(channelType)) {
        TRANS_LOGE(TRANS_SDK, "CloseChannel write channel type failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    if (channelType == CHANNEL_TYPE_UNDEFINED) {
        if (!data.WriteCString(sessionName)) {
            TRANS_LOGE(TRANS_SDK, "CloseChannel write session name failed!");
            return SOFTBUS_TRANS_PROXY_WRITECSTRING_FAILED;
        }
    }
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(SERVER_CLOSE_CHANNEL, data, reply, option);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "CloseChannel send request failed! ret=%{public}d", ret);
        return ret;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        TRANS_LOGE(TRANS_SDK, "CloseChannel read serverRet failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    return serverRet;
}

int32_t TransServerProxy::CloseChannelWithStatistics(int32_t channelId, int32_t channelType, uint64_t laneId,
    const void *dataInfo, uint32_t len)
{
    if (dataInfo == nullptr) {
        TRANS_LOGE(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        TRANS_LOGE(TRANS_SDK, "remote is nullptr!");
        return SOFTBUS_TRANS_PROXY_REMOTE_NULL;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TRANS_LOGE(TRANS_SDK, "CloseChannelWithStatistics write InterfaceToken failed!");
        return SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED;
    }
    if (!data.WriteInt32(channelId)) {
        TRANS_LOGE(TRANS_SDK, "CloseChannelWithStatistics write channel id failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    if (!data.WriteInt32(channelType)) {
        TRANS_LOGE(TRANS_SDK, "CloseChannelWithStatistics write channel type failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    if (!data.WriteUint64(laneId)) {
        TRANS_LOGE(TRANS_SDK, "CloseChannelWithStatistics write lane id failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    if (!data.WriteUint32(len)) {
        TRANS_LOGE(TRANS_SDK, "CloseChannelWithStatistics write dataInfo len failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    if (!data.WriteRawData(dataInfo, len)) {
        TRANS_LOGE(TRANS_SDK, "CloseChannelWithStatistics write dataInfo failed!");
        return SOFTBUS_TRANS_PROXY_WRITERAWDATA_FAILED;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(SERVER_CLOSE_CHANNEL_STATISTICS, data, reply, option);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "CloseChannelWithStatistics send request failed! ret=%{public}d", ret);
        return ret;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        TRANS_LOGE(TRANS_SDK, "CloseChannelWithStatistics read serverRet failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    return serverRet;
}

int32_t TransServerProxy::SendMessage(int32_t channelId, int32_t channelType, const void *dataInfo,
    uint32_t len, int32_t msgType)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TRANS_LOGE(TRANS_SDK, "remote is nullptr!");
        return SOFTBUS_TRANS_PROXY_REMOTE_NULL;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TRANS_LOGE(TRANS_SDK, "SendMessage write InterfaceToken failed!");
        return SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED;
    }
    if (!data.WriteInt32(channelId)) {
        TRANS_LOGE(TRANS_SDK, "SendMessage write channel id failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    if (!data.WriteInt32(channelType)) {
        TRANS_LOGE(TRANS_SDK, "SendMessage write channel type failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    if (!data.WriteUint32(len)) {
        TRANS_LOGE(TRANS_SDK, "SendMessage write dataInfo len failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    if (!data.WriteRawData(dataInfo, len)) {
        TRANS_LOGE(TRANS_SDK, "SendMessage write dataInfo failed!");
        return SOFTBUS_TRANS_PROXY_WRITERAWDATA_FAILED;
    }
    if (!data.WriteInt32(msgType)) {
        TRANS_LOGE(TRANS_SDK, "SendMessage msgType failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(SERVER_SESSION_SENDMSG, data, reply, option);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "SendMessage send request failed! ret=%{public}d", ret);
        return ret;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        TRANS_LOGE(TRANS_SDK, "SendMessage read serverRet failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    return serverRet;
}

int32_t TransServerProxy::QosReport(int32_t channelId, int32_t chanType, int32_t appType, int32_t quality)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        TRANS_LOGE(TRANS_SDK, "remote is nullptr!");
        return SOFTBUS_TRANS_PROXY_REMOTE_NULL;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TRANS_LOGE(TRANS_SDK, "QosReport write InterfaceToken failed!");
        return SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED;
    }
    if (!data.WriteInt32(channelId)) {
        TRANS_LOGE(TRANS_SDK, "QosReport channelId failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    if (!data.WriteInt32(chanType)) {
        TRANS_LOGE(TRANS_SDK, "QosReport chanType failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    if (!data.WriteInt32(appType)) {
        TRANS_LOGE(TRANS_SDK, "QosReport appType failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    if (!data.WriteInt32(quality)) {
        TRANS_LOGE(TRANS_SDK, "QosReport quality failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(SERVER_QOS_REPORT, data, reply, option);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "QosReport send request failed! ret=%{public}d", ret);
        return ret;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        TRANS_LOGE(TRANS_SDK, "QosReport read serverRet failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    return serverRet;
}

int32_t TransServerProxy::StreamStats(int32_t channelId, int32_t channelType, const StreamSendStats *statsData)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        TRANS_LOGE(TRANS_SDK, "remote is nullptr!");
        return SOFTBUS_TRANS_PROXY_REMOTE_NULL;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TRANS_LOGE(TRANS_SDK, "StreamStats write InterfaceToken failed!");
        return SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED;
    }
    if (!data.WriteInt32(channelId)) {
        TRANS_LOGE(TRANS_SDK, "StreamStats channelId failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    if (!data.WriteInt32(channelType)) {
        TRANS_LOGE(TRANS_SDK, "StreamStats channelType failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    if (!data.WriteRawData((void *)statsData, sizeof(StreamSendStats))) {
        TRANS_LOGE(TRANS_SDK, "write streamSendStats failed!");
        return SOFTBUS_TRANS_PROXY_WRITERAWDATA_FAILED;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(SERVER_STREAM_STATS, data, reply, option);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "StreamStats send request failed, ret=%{public}d", ret);
        return SOFTBUS_TRANS_PROXY_SEND_REQUEST_FAILED;
    }
    if (!reply.ReadInt32(ret)) {
        TRANS_LOGE(TRANS_SDK, "StreamStats read serverRet failed");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    return ret;
}

int32_t TransServerProxy::RippleStats(int32_t channelId, int32_t channelType, const TrafficStats *statsData)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        TRANS_LOGE(TRANS_SDK, "remote is nullptr!");
        return SOFTBUS_TRANS_PROXY_REMOTE_NULL;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TRANS_LOGE(TRANS_SDK, "RippleStats write InterfaceToken failed!");
        return SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED;
    }
    if (!data.WriteInt32(channelId)) {
        TRANS_LOGE(TRANS_SDK, "RippleStats channelId failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    if (!data.WriteInt32(channelType)) {
        TRANS_LOGE(TRANS_SDK, "RippleStats channelType failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    if (!data.WriteRawData((void *)statsData, sizeof(TrafficStats))) {
        TRANS_LOGE(TRANS_SDK, "write RippleStats failed!");
        return SOFTBUS_TRANS_PROXY_WRITERAWDATA_FAILED;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(SERVER_RIPPLE_STATS, data, reply, option);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "RippleStats send request failed, ret=%{public}d", ret);
        return ret;
    }
    if (!reply.ReadInt32(ret)) {
        TRANS_LOGE(TRANS_SDK, "RippleStats read serverRet failed");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    return ret;
}

int32_t TransServerProxy::GrantPermission(int32_t uid, int32_t pid, const char *sessionName)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        TRANS_LOGE(TRANS_SDK, "remote is nullptr!");
        return SOFTBUS_TRANS_PROXY_REMOTE_NULL;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TRANS_LOGE(TRANS_SDK, "GrantPermission write InterfaceToken failed!");
        return SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED;
    }
    if (!data.WriteInt32(uid)) {
        TRANS_LOGE(TRANS_SDK, "GrantPermission write uid failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    if (!data.WriteInt32(pid)) {
        TRANS_LOGE(TRANS_SDK, "GrantPermission write pid failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    if (!data.WriteCString(sessionName)) {
        TRANS_LOGE(TRANS_SDK, "GrantPermission write sessionName failed!");
        return SOFTBUS_TRANS_PROXY_WRITECSTRING_FAILED;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(SERVER_GRANT_PERMISSION, data, reply, option);
    if (ret != ERR_NONE) {
        TRANS_LOGE(TRANS_SDK, "GrantPermission send request failed, ret=%{public}d", ret);
        return SOFTBUS_TRANS_PROXY_SEND_REQUEST_FAILED;
    }
    if (!reply.ReadInt32(ret)) {
        TRANS_LOGE(TRANS_SDK, "GrantPermission read serverRet failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    return ret;
}

int32_t TransServerProxy::RemovePermission(const char *sessionName)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        TRANS_LOGE(TRANS_SDK, "remote is nullptr!");
        return SOFTBUS_TRANS_PROXY_REMOTE_NULL;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TRANS_LOGE(TRANS_SDK, "RemovePermission write InterfaceToken failed!");
        return SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED;
    }
    if (!data.WriteCString(sessionName)) {
        TRANS_LOGE(TRANS_SDK, "RemovePermission write sessionName failed!");
        return SOFTBUS_TRANS_PROXY_WRITECSTRING_FAILED;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(SERVER_REMOVE_PERMISSION, data, reply, option);
    if (ret != ERR_NONE) {
        TRANS_LOGE(TRANS_SDK, "RemovePermission send request failed, ret=%{public}d", ret);
        return SOFTBUS_TRANS_PROXY_SEND_REQUEST_FAILED;
    }
    if (!reply.ReadInt32(ret)) {
        TRANS_LOGE(TRANS_SDK, "RemovePermission read serverRet failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
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

int32_t TransServerProxy::LeaveLNN(const char *pkgName, const char *networkId)
{
    (void)pkgName;
    (void)networkId;
    return SOFTBUS_OK;
}

int32_t TransServerProxy::GetAllOnlineNodeInfo(const char *pkgName, void **info, uint32_t infoTypeLen, int32_t *infoNum)
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

int32_t TransServerProxy::GetNodeKeyInfo(const char *pkgName, const char *networkId, int32_t key, unsigned char *buf,
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

int32_t TransServerProxy::RegDataLevelChangeCb(const char *pkgName)
{
    (void)pkgName;
    return SOFTBUS_OK;
}

int32_t TransServerProxy::UnregDataLevelChangeCb(const char *pkgName)
{
    (void)pkgName;
    return SOFTBUS_OK;
}

int32_t TransServerProxy::SetDataLevel(const DataLevel *dataLevel)
{
    (void)dataLevel;
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

int32_t TransServerProxy::GetSoftbusSpecObject(sptr<IRemoteObject> &object)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        TRANS_LOGE(TRANS_SDK, "remote is null");
        return SOFTBUS_TRANS_PROXY_REMOTE_NULL;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TRANS_LOGE(TRANS_SDK, "GetSoftbusSpecObject write InterfaceToken failed!");
        return SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(SERVER_GET_SOFTBUS_SPEC_OBJECT, data, reply, option);
    if (ret != ERR_NONE) {
        TRANS_LOGE(TRANS_SDK, "GetSoftbusSpecObject send request failed, ret=%{public}d", ret);
        return ret;
    }
    if (!reply.ReadInt32(ret)) {
        TRANS_LOGE(TRANS_SDK, "GetSoftbusSpecObject send ret failed");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    if (ret == SOFTBUS_OK) {
        object = reply.ReadRemoteObject();
    }
    return ret;
}

int32_t TransServerProxy::EvaluateQos(const char *peerNetworkId, TransDataType dataType, const QosTV *qos,
    uint32_t qosCount)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        TRANS_LOGE(TRANS_SDK, "remote is null");
        return SOFTBUS_TRANS_PROXY_REMOTE_NULL;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TRANS_LOGE(TRANS_SDK, "EvaluateQos write InterfaceToken failed!");
        return SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED;
    }

    if (!data.WriteCString(peerNetworkId)) {
        TRANS_LOGE(TRANS_SDK, "EvaluateQos write peerNetworkId failed!");
        return SOFTBUS_TRANS_PROXY_WRITECSTRING_FAILED;
    }

    if (!data.WriteInt32(dataType)) {
        TRANS_LOGE(TRANS_SDK, "EvaluateQos write dataType failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }

    if (!data.WriteUint32(qosCount)) {
        TRANS_LOGE(TRANS_SDK, "EvaluateQos write count of qos failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }

    if (qosCount > 0) {
        if (!data.WriteBuffer(qos, sizeof(QosTV) * qosCount)) {
            TRANS_LOGE(TRANS_SDK, "EvaluateQos write qos info failed!");
            return SOFTBUS_IPC_ERR;
        }
    }

    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(SERVER_EVALUATE_QOS, data, reply, option);
    if (ret != ERR_NONE) {
        TRANS_LOGE(TRANS_SDK, "EvaluateQos request failed, ret=%{public}d", ret);
        return ret;
    }

    if (!reply.ReadInt32(ret)) {
        TRANS_LOGE(TRANS_SDK, "EvaluateQos read ret failed");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }

    return ret;
}

int32_t TransServerProxy::ProcessInnerEvent(int32_t eventType, uint8_t *buf, uint32_t len)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        TRANS_LOGE(TRANS_SDK, "remote is null");
        return SOFTBUS_TRANS_PROXY_REMOTE_NULL;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TRANS_LOGE(TRANS_SDK, "write InterfaceToken failed!");
        return SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED;
    }

    if (!data.WriteInt32(eventType)) {
        TRANS_LOGE(TRANS_SDK, "write eventType failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }

    if (!data.WriteUint32(len)) {
        TRANS_LOGE(TRANS_SDK, "write len failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }

    if (!data.WriteRawData(buf, len)) {
        TRANS_LOGE(TRANS_SDK, "write buf failed!");
        return SOFTBUS_TRANS_PROXY_WRITERAWDATA_FAILED;
    }

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    int32_t ret = remote->SendRequest(SERVER_PROCESS_INNER_EVENT, data, reply, option);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "send request failed, ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t TransServerProxy::PrivilegeCloseChannel(uint64_t tokenId, int32_t pid, const char *peerNetworkId)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        TRANS_LOGE(TRANS_SDK, "remote is null");
        return SOFTBUS_TRANS_PROXY_REMOTE_NULL;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TRANS_LOGE(TRANS_SDK, "write InterfaceToken failed!");
        return SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED;
    }

    if (!data.WriteUint64(tokenId)) {
        TRANS_LOGE(TRANS_SDK, "write tokenId failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }

    if (!data.WriteInt32(pid)) {
        TRANS_LOGE(TRANS_SDK, "write pid failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }

    if (!data.WriteCString(peerNetworkId)) {
        TRANS_LOGE(TRANS_SDK, "write peerNetworkId failed!");
        return SOFTBUS_TRANS_PROXY_WRITECSTRING_FAILED;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(SERVER_PRIVILEGE_CLOSE_CHANNEL, data, reply, option);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "request failed, ret=%{public}d", ret);
        return ret;
    }

    if (!reply.ReadInt32(ret)) {
        TRANS_LOGE(TRANS_SDK, "EvaluateQos read ret failed");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    return ret;
}
} // namespace OHOS
