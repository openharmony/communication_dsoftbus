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

#include "softbus_server_proxy.h"

#include <securec.h>

#include "discovery_service.h"
#include "message_parcel.h"
#include "softbus_client_stub.h"
#include "softbus_errcode.h"
#include "softbus_interface.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"

namespace OHOS {
sptr<IRemoteObject> SoftBusServerProxy::clientCallbackStub_;
std::mutex SoftBusServerProxy::instanceLock;

sptr<IRemoteObject> SoftBusServerProxy::GetRemoteInstance()
{
    if (clientCallbackStub_ == nullptr) {
        std::lock_guard<std::mutex> autoLock(instanceLock);
        if (clientCallbackStub_ == nullptr) {
            clientCallbackStub_ = sptr<IRemoteObject>(new (std::nothrow) SoftBusClientStub());
        }
    }
    return clientCallbackStub_;
}

int32_t SoftBusServerProxy::StartDiscovery(const char *pkgName, const void *info)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    SubscribeInfo *subInfo = (SubscribeInfo *)info;

    data.WriteCString(pkgName);
    data.WriteInt32(subInfo->subscribeId);
    data.WriteInt32(subInfo->mode);
    data.WriteInt32(subInfo->medium);
    data.WriteInt32(subInfo->freq);
    data.WriteBool(subInfo->isSameAccount);
    data.WriteBool(subInfo->isWakeRemote);
    data.WriteCString(subInfo->capability);
    data.WriteCString((char *)subInfo->capabilityData);
    data.WriteUint32(subInfo->dataLen);

    MessageParcel reply;
    MessageOption option;
    int32_t err = remote->SendRequest(SERVER_START_DISCOVERY, data, reply, option);
    if (err != 0) {
        LOG_ERR("StartDiscovery send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    int32_t ret = reply.ReadInt32(serverRet);
    if (!ret) {
        LOG_ERR("StartDiscovery read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t SoftBusServerProxy::StopDiscovery(const char *pkgName, int subscribeId)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;

    data.WriteCString(pkgName);
    data.WriteInt32(subscribeId);

    MessageParcel reply;
    MessageOption option;
    int32_t err = remote->SendRequest(SERVER_STOP_DISCOVERY, data, reply, option);
    LOG_ERR("StopDiscovery send request ret = %d!", err);
    if (err != 0) {
        LOG_ERR("StopDiscovery send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    int32_t ret = reply.ReadInt32(serverRet);
    if (!ret) {
        LOG_ERR("StopDiscovery read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t SoftBusServerProxy::PublishService(const char *pkgName, const void *info)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    PublishInfo *pubInfo = (PublishInfo *)info;

    data.WriteCString(pkgName);
    data.WriteInt32(pubInfo->publishId);
    data.WriteInt32(pubInfo->mode);
    data.WriteInt32(pubInfo->medium);
    data.WriteInt32(pubInfo->freq);
    data.WriteCString(pubInfo->capability);
    data.WriteCString((char *)pubInfo->capabilityData);
    data.WriteUint32(pubInfo->dataLen);

    MessageParcel reply;
    MessageOption option;
    int32_t err = remote->SendRequest(SERVER_PUBLISH_SERVICE, data, reply, option);
    LOG_ERR("PublishService send request ret = %d!", err);
    if (err != 0) {
        LOG_ERR("PublishService send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    int32_t ret = reply.ReadInt32(serverRet);
    if (!ret) {
        LOG_ERR("PublishService read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t SoftBusServerProxy::UnPublishService(const char *pkgName, int publishId)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;

    data.WriteCString(pkgName);
    data.WriteInt32(publishId);

    MessageParcel reply;
    MessageOption option;
    int32_t err = remote->SendRequest(SERVER_UNPUBLISH_SERVICE, data, reply, option);
    LOG_ERR("UnPublishService send request ret = %d!", err);
    if (err != 0) {
        LOG_ERR("UnPublishService send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    int32_t ret = reply.ReadInt32(serverRet);
    if (!ret) {
        LOG_ERR("UnPublishService read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t SoftBusServerProxy::SoftbusRegisterService(const char *clientPkgName, const sptr<IRemoteObject>& object)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    int ret = data.WriteRemoteObject(SoftBusServerProxy::GetRemoteInstance());
    if (!ret) {
        LOG_ERR("SoftbusRegisterService write remote object failed!");
        return SOFTBUS_ERR;
    }
    ret = data.WriteCString(clientPkgName);
    if (!ret) {
        LOG_ERR("SoftbusRegisterService write clientPkgName failed!");
        return SOFTBUS_ERR;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t err = remote->SendRequest(MANAGE_REGISTER_SERVICE, data, reply, option);
    if (err != 0) {
        LOG_ERR("SoftbusRegisterService send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    ret = reply.ReadInt32(serverRet);
    if (!ret) {
        LOG_ERR("SoftbusRegisterService read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerProxy::CreateSessionServer(const char *pkgName, const char *sessionName)
{
    if (pkgName == nullptr || sessionName == nullptr) {
        return SOFTBUS_ERR;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    if (!data.WriteCString(pkgName)) {
        LOG_ERR("CreateSessionServer write pkg name failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(sessionName)) {
        LOG_ERR("CreateSessionServer write session name failed!");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_CREATE_SESSION_SERVER, data, reply, option) != 0) {
        LOG_ERR("CreateSessionServer send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        LOG_ERR("CreateSessionServer read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t SoftBusServerProxy::RemoveSessionServer(const char *pkgName, const char *sessionName)
{
    if (pkgName == nullptr || sessionName == nullptr) {
        return SOFTBUS_ERR;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    if (!data.WriteCString(pkgName)) {
        LOG_ERR("RemoveSessionServer write pkg name failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(sessionName)) {
        LOG_ERR("RemoveSessionServer session name failed!");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_REMOVE_SESSION_SERVER, data, reply, option) != 0) {
        LOG_ERR("RemoveSessionServer send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        LOG_ERR("RemoveSessionServer read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t SoftBusServerProxy::OpenSession(const char *mySessionName, const char *peerSessionName,
    const char *peerDeviceId, const char *groupId, int32_t flags)
{
    if (mySessionName == nullptr || peerSessionName == nullptr || peerDeviceId == nullptr || groupId == nullptr) {
        return SOFTBUS_ERR;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    if (!data.WriteCString(mySessionName)) {
        LOG_ERR("OpenSession write my session name failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(peerSessionName)) {
        LOG_ERR("OpenSession write peer session name failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(peerDeviceId)) {
        LOG_ERR("OpenSession write addr type length failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(groupId)) {
        LOG_ERR("OpenSession write addr type length failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(flags)) {
        LOG_ERR("OpenSession write addr type length failed!");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_OPEN_SESSION, data, reply, option) != 0) {
        LOG_ERR("OpenSession send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t channelId = 0;
    if (!reply.ReadInt32(channelId)) {
        LOG_ERR("OpenSession read channelId failed!");
        return SOFTBUS_ERR;
    }
    return channelId;
}

int32_t SoftBusServerProxy::CloseChannel(int32_t channelId)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr!");
        return SOFTBUS_ERR;
    }
    MessageParcel data;
    if (!data.WriteInt32(channelId)) {
        LOG_ERR("CloseChannel write channel id failed!");
        return SOFTBUS_ERR;
    }

    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_CLOSE_CHANNEL, data, reply, option) != 0) {
        LOG_ERR("CloseChannel send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        LOG_ERR("CloseChannel read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t SoftBusServerProxy::SendMessage(int32_t channelId, const void *dataInfo, uint32_t len, int32_t msgType)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr!");
        return SOFTBUS_ERR;
    }
    MessageParcel data;
    if (!data.WriteInt32(channelId)) {
        LOG_ERR("SendMessage write channel id failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteUint32(len)) {
        LOG_ERR("SendMessage write dataInfo len failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteRawData(dataInfo, len)) {
        LOG_ERR("SendMessage write dataInfo failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(msgType)) {
        LOG_ERR("SendMessage msgType failed!");
        return SOFTBUS_ERR;
    }

    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_SESSION_SENDMSG, data, reply, option) != 0) {
        LOG_ERR("SendMessage send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        LOG_ERR("SendMessage read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t SoftBusServerProxy::JoinLNN(const char *pkgName, void *addr, uint32_t addrTypeLen)
{
    if (pkgName == nullptr || addr == nullptr) {
        return SOFTBUS_ERR;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    if (!data.WriteCString(pkgName)) {
        LOG_ERR("JoinLNN write client name failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteUint32(addrTypeLen)) {
        LOG_ERR("JoinLNN write addr type length failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteRawData(addr, addrTypeLen)) {
        LOG_ERR("JoinLNN write addr failed!");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_JOIN_LNN, data, reply, option) != 0) {
        LOG_ERR("JoinLNN send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        LOG_ERR("JoinLNN read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t SoftBusServerProxy::LeaveLNN(const char *pkgName, const char *networkId)
{
    if (pkgName == nullptr || networkId == nullptr) {
        return SOFTBUS_ERR;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    int32_t ret = data.WriteCString(pkgName);
    if (!ret) {
        LOG_ERR("LeaveLNN write client name failed!");
        return SOFTBUS_ERR;
    }
    ret = data.WriteCString(networkId);
    if (!ret) {
        LOG_ERR("LeaveLNN write networkId failed!");
        return SOFTBUS_ERR;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t err = remote->SendRequest(SERVER_LEAVE_LNN, data, reply, option);
    if (err != 0) {
        LOG_ERR("LeaveLNN send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    ret = reply.ReadInt32(serverRet);
    if (!ret) {
        LOG_ERR("LeaveLNN read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t SoftBusServerProxy::GetAllOnlineNodeInfo(const char *pkgName, void **info, uint32_t infoTypeLen,
    int32_t *infoNum)
{
    if (info == nullptr || infoNum == nullptr) {
        return SOFTBUS_ERR;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    int32_t ret = data.WriteCString(pkgName);
    if (!ret) {
        LOG_ERR("GetAllOnlineNodeInfo write client name failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteUint32(infoTypeLen)) {
        LOG_ERR("GetAllOnlineNodeInfo write info type length failed!");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_GET_ALL_ONLINE_NODE_INFO, data, reply, option) != 0) {
        LOG_ERR("GetAllOnlineNodeInfo send request failed!");
        return SOFTBUS_ERR;
    }
    if (!reply.ReadInt32(*infoNum)) {
        LOG_ERR("GetAllOnlineNodeInfo read infoNum failed!");
        return SOFTBUS_ERR;
    }
    int32_t infoSize = (*infoNum) * (int32_t)infoTypeLen;
    *info = nullptr;
    if (infoSize > 0) {
        void *nodeInfo = (void *)reply.ReadRawData(infoSize);
        if (nodeInfo == nullptr) {
            LOG_ERR("GetAllOnlineNodeInfo read node info failed!");
            return SOFTBUS_ERR;
        }
        *info = SoftBusMalloc(infoSize);
        if (*info == nullptr) {
            LOG_ERR("GetAllOnlineNodeInfo malloc failed!");
            return SOFTBUS_ERR;
        }
        if (memcpy_s(*info, infoSize, nodeInfo, infoSize) != EOK) {
            LOG_ERR("GetAllOnlineNodeInfo copy node info failed!");
            SoftBusFree(*info);
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerProxy::GetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen)
{
    if (info == nullptr) {
        return SOFTBUS_ERR;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    int32_t ret = data.WriteCString(pkgName);
    if (!ret) {
        LOG_ERR("GetLocalDeviceInfo write client name failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteUint32(infoTypeLen)) {
        LOG_ERR("GetLocalDeviceInfo write info type length failed!");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_GET_LOCAL_DEVICE_INFO, data, reply, option) != 0) {
        LOG_ERR("GetLocalDeviceInfo send request failed!");
        return SOFTBUS_ERR;
    }
    void *nodeInfo = (void *)reply.ReadRawData(infoTypeLen);
    if (nodeInfo == nullptr) {
        LOG_ERR("GetLocalDeviceInfo read node info failed!");
        return SOFTBUS_ERR;
    }
    if (memcpy_s(info, infoTypeLen, nodeInfo, infoTypeLen) != EOK) {
        LOG_ERR("GetLocalDeviceInfo copy node info failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerProxy::GetNodeKeyInfo(const char *pkgName, const char *networkId, int key, unsigned char *buf,
    uint32_t len)
{
    if (networkId == nullptr || buf == nullptr) {
        LOG_ERR("params are nullptr!");
        return SOFTBUS_ERR;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    int32_t ret = data.WriteCString(pkgName);
    if (!ret) {
        LOG_ERR("GetNodeKeyInfo write client name failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(networkId)) {
        LOG_ERR("GetNodeKeyInfo write networkId failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(key)) {
        LOG_ERR("GetNodeKeyInfo write key failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(len)) {
        LOG_ERR("GetNodeKeyInfo write buf len failed!");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_GET_NODE_KEY_INFO, data, reply, option) != 0) {
        LOG_ERR("GetNodeKeyInfo send request failed!");
        return SOFTBUS_ERR;
    }
    void *retBuf = (void *)reply.ReadRawData(len);
    if (retBuf == nullptr) {
        LOG_ERR("GetNodeKeyInfo read retBuf failed!");
        return SOFTBUS_ERR;
    }
    if (memcpy_s(buf, len, retBuf, len) != EOK) {
        LOG_ERR("GetNodeKeyInfo copy node key info failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}
} // namespace OHOS
