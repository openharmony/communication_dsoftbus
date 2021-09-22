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
#include "softbus_conn_interface.h"
#include "softbus_errcode.h"
#include "softbus_ipc_def.h"
#include "softbus_log.h"
#include "softbus_server.h"

namespace OHOS {
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
}

int32_t SoftBusServerStub::OnRemoteRequest(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "SoftBusServerStub::OnReceived, code = %u", code);
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
    subInfo.subscribeId = data.ReadInt32();
    subInfo.mode = (DiscoverMode)data.ReadInt32();
    subInfo.medium = (ExchanageMedium)data.ReadInt32();
    subInfo.freq = (ExchangeFreq)data.ReadInt32();
    subInfo.isSameAccount = data.ReadBool();
    subInfo.isWakeRemote = data.ReadBool();
    subInfo.capability = data.ReadCString();
    subInfo.dataLen = data.ReadUint32();
    if (subInfo.dataLen != 0) {
        subInfo.capabilityData = (unsigned char *)data.ReadCString();
    } else {
        subInfo.capabilityData = NULL;
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
    pubInfo.publishId = data.ReadInt32();
    pubInfo.mode = (DiscoverMode)data.ReadInt32();
    pubInfo.medium = (ExchanageMedium)data.ReadInt32();
    pubInfo.freq = (ExchangeFreq)data.ReadInt32();
    pubInfo.capability = data.ReadCString();
    pubInfo.dataLen = data.ReadUint32();
    if (pubInfo.dataLen != 0) {
        pubInfo.capabilityData = (unsigned char *)data.ReadCString();
    } else {
        pubInfo.capabilityData = NULL;
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
    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "CreateSessionServerInner read pkgName failed!");
        return SOFTBUS_ERR;
    }
    const char *sessionName = data.ReadCString();
    if (sessionName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "CreateSessionServerInner read sessionName failed!");
        return SOFTBUS_ERR;
    }
    int32_t retReply = CreateSessionServer(pkgName, sessionName);
    if (!reply.WriteInt32(retReply)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "CreateSessionServerInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::RemoveSessionServerInner(MessageParcel &data, MessageParcel &reply)
{
    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "RemoveSessionServerInner read pkgName failed!");
        return SOFTBUS_ERR;
    }
    const char *sessionName = data.ReadCString();
    if (sessionName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "RemoveSessionServerInner read sessionName failed!");
        return SOFTBUS_ERR;
    }
    int32_t retReply = RemoveSessionServer(pkgName, sessionName);
    if (!reply.WriteInt32(retReply)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "RemoveSessionServerInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::OpenSessionInner(MessageParcel &data, MessageParcel &reply)
{
    SessionParam param;
    TransSerializer transSerializer;
    param.sessionName = data.ReadCString();
    if (param.sessionName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OpenSessionInner read my session name failed!");
        return SOFTBUS_ERR;
    }
    param.peerSessionName = data.ReadCString();
    if (param.peerSessionName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OpenSessionInner read peer session name failed!");
        return SOFTBUS_ERR;
    }
    param.peerDeviceId = data.ReadCString();
    if (param.peerDeviceId == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OpenSessionInner read peeer deviceid failed!");
        return SOFTBUS_ERR;
    }
    param.groupId = data.ReadCString();
    if (param.groupId == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OpenSessionInner read group id failed!");
        return SOFTBUS_ERR;
    }
    param.attr = (SessionAttribute*)data.ReadRawData(sizeof(SessionAttribute));
    if (param.attr == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OpenSessionInner read SessionAttribute failed!");
        return SOFTBUS_ERR;
    }
    int32_t retReply = OpenSession(&param, &(transSerializer.transInfo));
    transSerializer.ret = retReply;
    if (!reply.WriteRawData(&transSerializer, sizeof(TransSerializer))) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OpenSessionInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::OpenAuthSessionInner(MessageParcel &data, MessageParcel &reply)
{
    const char *sessionName = data.ReadCString();
    if (sessionName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OpenAuthSessionInner read session name failed!");
        return SOFTBUS_ERR;
    }
    ConnectionAddr addrInfo;
    addrInfo.type = static_cast<ConnectionAddrType>(data.ReadInt32());
    const char *addr = data.ReadCString();
    if (addr == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "OpenAuthSessionInner read type failed!");
        return SOFTBUS_ERR;
    }
    if (addrInfo.type == CONNECTION_ADDR_ETH || addrInfo.type == CONNECTION_ADDR_WLAN) {
        if (memcpy_s(addrInfo.info.ip.ip, IP_LEN, addr, IP_LEN) != EOK) {
            return SOFTBUS_MEM_ERR;
        }
        addrInfo.info.ip.port = static_cast<uint16_t>(data.ReadInt16());
    } else if (addrInfo.type == CONNECTION_ADDR_BLE) {
        if (memcpy_s(addrInfo.info.ble.bleMac, BT_MAC_LEN, addr, BT_MAC_LEN) != EOK) {
            return SOFTBUS_MEM_ERR;
        }
    } else if (addrInfo.type == CONNECTION_ADDR_BR) {
        if (memcpy_s(addrInfo.info.br.brMac, BT_MAC_LEN, addr, BT_MAC_LEN) != EOK) {
            return SOFTBUS_MEM_ERR;
        }
    } else {
        return SOFTBUS_ERR;
    }
    int32_t retReply = OpenAuthSession(sessionName, &addrInfo);
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
    if (!data.ReadUint32(addrTypeLen)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftbusJoinLNNInner read addr type length failed!");
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
        if (nodeInfo != nullptr) {
            SoftBusFree(nodeInfo);
        }
        return SOFTBUS_ERR;
    }
    int32_t ret = SOFTBUS_OK;
    if (infoNum > 0) {
        if (!reply.WriteRawData(nodeInfo, infoTypeLen * infoNum)) {
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
    if (!data.ReadUint32(infoTypeLen)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetLocalDeviceInfoInner read info type length failed");
        return SOFTBUS_ERR;
    }
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
    int32_t len;
    if (!data.ReadInt32(len)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetNodeKeyInfoInner read len failed!");
        return SOFTBUS_ERR;
    }
    void *buf = SoftBusMalloc(len);
    if (buf == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetNodeKeyInfoInner malloc buffer failed!");
        return SOFTBUS_ERR;
    }
    if (GetNodeKeyInfo(clientName, networkId, key, (unsigned char *)buf, len) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetNodeKeyInfoInner get key info failed!");
        SoftBusFree(buf);
        return SOFTBUS_ERR;
    }
    if (!reply.WriteRawData(buf, len)) {
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
} // namespace OHOS
