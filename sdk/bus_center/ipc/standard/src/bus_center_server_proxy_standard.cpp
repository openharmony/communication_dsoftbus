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

#include "bus_center_server_proxy_standard.h"

#include <securec.h>
#include "bus_center_server_proxy.h"
#include "discovery_service.h"
#include "ipc_skeleton.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "message_parcel.h"
#include "softbus_adapter_mem.h"
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Get GetSystemAbility failed!\n");
        return nullptr;
    }
    return reply.ReadRemoteObject();
}

int32_t BusCenterServerProxy::StartDiscovery(const char *pkgName, const SubscribeInfo *subInfo)
{
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::StopDiscovery(const char *pkgName, int subscribeId)
{
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::PublishService(const char *pkgName, const PublishInfo *pubInfo)
{
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::UnPublishService(const char *pkgName, int publishId)
{
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::SoftbusRegisterService(const char *clientPkgName, const sptr<IRemoteObject>& object)
{
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::CreateSessionServer(const char *pkgName, const char *sessionName)
{
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::RemoveSessionServer(const char *pkgName, const char *sessionName)
{
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::OpenSession(const SessionParam *param, TransInfo *info)
{
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::OpenAuthSession(const char *sessionName, const ConnectionAddr *addrInfo)
{
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::NotifyAuthSuccess(int32_t channelId, int32_t channelType)
{
    (void)channelId;
    (void)channelType;
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::CloseChannel(int32_t channelId, int32_t channelType)
{
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::SendMessage(int32_t channelId, int32_t channelType, const void *data,
    uint32_t len, int32_t msgType)
{
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::QosReport(int32_t channelId, int32_t chanType, int32_t appType, int quality)
{
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::StreamStats(int32_t channelId, int32_t channelType, const StreamSendStats *data)
{
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::RippleStats(int32_t channelId, int32_t channelType, const TrafficStats *data)
{
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::JoinLNN(const char *pkgName, void *addr, uint32_t addrTypeLen)
{
    if (pkgName == nullptr || addr == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "JoinLNN write InterfaceToken failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "JoinLNN write client name failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteUint32(addrTypeLen)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "JoinLNN write addr type length failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteRawData(addr, addrTypeLen)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "JoinLNN write addr failed!");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_JOIN_LNN, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "JoinLNN send request failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "JoinLNN read serverRet failed!");
        return SOFTBUS_IPC_ERR;
    }
    return serverRet;
}

int32_t BusCenterServerProxy::JoinMetaNode(const char *pkgName, void *addr, CustomData *customData, uint32_t addrTypeLen)
{
    if (pkgName == nullptr || addr == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "JoinMetaNode write InterfaceToken failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "JoinMetaNode write client name failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteUint32(addrTypeLen)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "JoinMetaNode write addr type length failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteRawData(addr, addrTypeLen)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "JoinMetaNode write addr failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteRawData(customData, sizeof(CustomData))) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "JoinMetaNode write addr failed!");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_JOIN_METANODE, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "JoinMetaNode send request failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "JoinMetaNode read serverRet failed!");
        return SOFTBUS_IPC_ERR;
    }
    return serverRet;
}

int32_t BusCenterServerProxy::LeaveLNN(const char *pkgName, const char *networkId)
{
    if (pkgName == nullptr || networkId == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LeaveLNN write InterfaceToken failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t ret = data.WriteCString(pkgName);
    if (!ret) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LeaveLNN write client name failed!");
        return SOFTBUS_IPC_ERR;
    }
    ret = data.WriteCString(networkId);
    if (!ret) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LeaveLNN write networkId failed!");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t err = remote->SendRequest(SERVER_LEAVE_LNN, data, reply, option);
    if (err != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LeaveLNN send request failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t serverRet = 0;
    ret = reply.ReadInt32(serverRet);
    if (!ret) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LeaveLNN read serverRet failed!");
        return SOFTBUS_IPC_ERR;
    }
    return serverRet;
}

int32_t BusCenterServerProxy::LeaveMetaNode(const char *pkgName, const char *networkId)
{
    if (pkgName == nullptr || networkId == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LeaveMetaNode write InterfaceToken failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t ret = data.WriteCString(pkgName);
    if (!ret) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LeaveMetaNode write client name failed!");
        return SOFTBUS_IPC_ERR;
    }
    ret = data.WriteCString(networkId);
    if (!ret) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LeaveMetaNode write networkId failed!");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t err = remote->SendRequest(SERVER_LEAVE_METANODE, data, reply, option);
    if (err != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LeaveMetaNode send request failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t serverRet = 0;
    ret = reply.ReadInt32(serverRet);
    if (!ret) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LeaveMetaNode read serverRet failed!");
        return SOFTBUS_IPC_ERR;
    }
    return serverRet;
}

int32_t BusCenterServerProxy::GetAllOnlineNodeInfo(const char *pkgName, void **info, uint32_t infoTypeLen, int *infoNum)
{
    if (info == nullptr || infoNum == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetAllOnlineNodeInfo write InterfaceToken failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t ret = data.WriteCString(pkgName);
    if (!ret) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetAllOnlineNodeInfo write client name failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteUint32(infoTypeLen)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetAllOnlineNodeInfo write info type length failed!");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_GET_ALL_ONLINE_NODE_INFO, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetAllOnlineNodeInfo send request failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!reply.ReadInt32(*infoNum)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetAllOnlineNodeInfo read infoNum failed!");
        return SOFTBUS_IPC_ERR;
    }

    *info = nullptr;
    if ((*infoNum) > 0) {
        uint32_t infoSize = (uint32_t)(*infoNum) * infoTypeLen;
        void *nodeInfo = const_cast<void *>(reply.ReadRawData(infoSize));
        if (nodeInfo == nullptr) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetAllOnlineNodeInfo read node info failed!");
            return SOFTBUS_IPC_ERR;
        }
        *info = SoftBusMalloc(infoSize);
        if (*info == nullptr) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetAllOnlineNodeInfo malloc failed!");
            return SOFTBUS_MALLOC_ERR;
        }
        if (memcpy_s(*info, infoSize, nodeInfo, infoSize) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetAllOnlineNodeInfo copy node info failed!");
            SoftBusFree(*info);
            return SOFTBUS_MEM_ERR;
        }
    }
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::GetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen)
{
    if (info == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetLocalDeviceInfo write InterfaceToken failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t ret = data.WriteCString(pkgName);
    if (!ret) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetLocalDeviceInfo write client name failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteUint32(infoTypeLen)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetLocalDeviceInfo write info type length failed!");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_GET_LOCAL_DEVICE_INFO, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetLocalDeviceInfo send request failed!");
        return SOFTBUS_IPC_ERR;
    }
    void *nodeInfo = const_cast<void *>(reply.ReadRawData(infoTypeLen));
    if (nodeInfo == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetLocalDeviceInfo read node info failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (memcpy_s(info, infoTypeLen, nodeInfo, infoTypeLen) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetLocalDeviceInfo copy node info failed!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::GetNodeKeyInfo(const char *pkgName, const char *networkId, int key, unsigned char *buf,
    uint32_t len)
{
    if (networkId == nullptr || buf == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "params are nullptr!");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetNodeKeyInfo write InterfaceToken failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetNodeKeyInfo write client name failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(networkId)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetNodeKeyInfo write networkId failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteInt32(key)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetNodeKeyInfo write key failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteInt32(len)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetNodeKeyInfo write buf len failed!");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_GET_NODE_KEY_INFO, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetNodeKeyInfo send request failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t infoLen;
    if (!reply.ReadInt32(infoLen)) {
        return SOFTBUS_IPC_ERR;
    }
    void *retBuf = const_cast<void *>(reply.ReadRawData(infoLen));
    if (retBuf == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetNodeKeyInfo read retBuf failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (memcpy_s(buf, len, retBuf, infoLen) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetNodeKeyInfo copy node key info failed");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::SetNodeDataChangeFlag(const char *pkgName, const char *networkId, uint16_t dataChangeFlag)
{
    if (networkId == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "params are nullptr!");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "SetNodeDataChangeFlag write InterfaceToken failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "SetNodeDataChangeFlag write client name failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(networkId)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "SetNodeDataChangeFlag write networkId failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteInt16(dataChangeFlag)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "SetNodeDataChangeFlag write key failed!");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_SET_NODE_DATA_CHANGE_FLAG, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "SetNodeDataChangeFlag send request failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "SetNodeDataChangeFlag read serverRet failed!");
        return SOFTBUS_IPC_ERR;
    }
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::StartTimeSync(const char *pkgName, const char *targetNetworkId, int32_t accuracy,
    int32_t period)
{
    if (pkgName == nullptr || targetNetworkId == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "StartTimeSync write InterfaceToken failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "StartTimeSync write client name failed!");
        return SOFTBUS_IPC_ERR;
    }

    if (!data.WriteCString(targetNetworkId)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "StartTimeSync write networkId failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteInt32(accuracy)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "StartTimeSync write accuracy failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteInt32(period)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "StartTimeSync write period failed!");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_START_TIME_SYNC, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "StartTimeSync send request failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "StartTimeSync read serverRet failed!");
        return SOFTBUS_IPC_ERR;
    }
    return serverRet;
}

int32_t BusCenterServerProxy::StopTimeSync(const char *pkgName, const char *targetNetworkId)
{
    if (pkgName == nullptr || targetNetworkId == nullptr) {
        return SOFTBUS_ERR;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "StopTimeSync write InterfaceToken failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "StopTimeSync write client name failed!");
        return SOFTBUS_IPC_ERR;
    }

    if (!data.WriteCString(targetNetworkId)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "StopTimeSync write networkId failed!");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_STOP_TIME_SYNC, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "StopTimeSync send request failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "StopTimeSync read serverRet failed!");
        return SOFTBUS_IPC_ERR;
    }
    return serverRet;
}

int32_t BusCenterServerProxy::PublishLNN(const char *pkgName, const void *info, uint32_t infoTypeLen)
{
    if (pkgName == nullptr || info == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "PublishLNN write InterfaceToken failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "PublishLNN write client name failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteUint32(infoTypeLen)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "PublishLNN write info type length failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteRawData(info, infoTypeLen)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "PublishLNN write info failed!");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_PUBLISH_LNN, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "PublishLNN send request failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t ret;
    if (!reply.ReadInt32(ret)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "PublishLNN send error ret = %d!", ret);
        return SOFTBUS_IPC_ERR;
    }
    return ret;
}

int32_t BusCenterServerProxy::StopPublishLNN(const char *pkgName, int32_t publishId)
{
    if (pkgName == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "PublishLNN write InterfaceToken failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "PublishLNN write client name failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteInt32(publishId)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "PublishLNN write publishId failed!");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_STOP_PUBLISH_LNN, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "StopPublishLNN send request failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "StopPublishLNN read serverRet failed!");
        return SOFTBUS_IPC_ERR;
    }
    return serverRet;
}

int32_t BusCenterServerProxy::RefreshLNN(const char *pkgName, const void *info, uint32_t infoTypeLen)
{
    if (pkgName == nullptr || info == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "RefreshLNN write InterfaceToken failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "RefreshLNN write client name failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteUint32(infoTypeLen)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "RefreshLNN write info type length failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteRawData(info, infoTypeLen)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "RefreshLNN write info failed!");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_REFRESH_LNN, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "RefreshLNN send request failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t ret;
    if (!reply.ReadInt32(ret)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "RefreshLNN send error ret = %d!", ret);
        return SOFTBUS_IPC_ERR;
    }
    return ret;
}

int32_t BusCenterServerProxy::StopRefreshLNN(const char *pkgName, int32_t refreshId)
{
    if (pkgName == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "StopRefreshLNN write InterfaceToken failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "StopRefreshLNN write client name failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteInt32(refreshId)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "StopRefreshLNN write refreshId failed!");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_STOP_REFRESH_LNN, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "StopRefreshLNN send request failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "StopPublishLNN read serverRet failed!");
        return SOFTBUS_IPC_ERR;
    }
    return serverRet;
}

int32_t BusCenterServerProxy::ActiveMetaNode(const MetaNodeConfigInfo *info, char *metaNodeId)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ActiveMetaNode write InterfaceToken failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteRawData(info, sizeof(MetaNodeConfigInfo))) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ActiveMetaNode write meta node config failed!");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_ACTIVE_META_NODE, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ActiveMetaNode send request failed!");
        return SOFTBUS_IPC_ERR;
    }
    char *retBuf = const_cast<char *>(reply.ReadCString());
    if (retBuf == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ActiveMetaNode read meta node id failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (strncpy_s(metaNodeId, NETWORK_ID_BUF_LEN, retBuf, strlen(retBuf)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ActiveMetaNode copy meta node id failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::DeactiveMetaNode(const char *metaNodeId)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "DeactiveMetaNode write InterfaceToken failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(metaNodeId)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "DeactiveMetaNode write meta node id failed!");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_DEACTIVE_META_NODE, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "DeactiveMetaNode send request failed!");
        return SOFTBUS_IPC_ERR;
    }
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::GetAllMetaNodeInfo(MetaNodeInfo *infos, int32_t *infoNum)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetAllMetaNodeInfo write InterfaceToken failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteInt32(*infoNum)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetAllMetaNodeInfo write infoNum failed!");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_GET_ALL_META_NODE_INFO, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetAllMetaNodeInfo send request failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t retInfoNum;
    if (!reply.ReadInt32(retInfoNum)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetAllMetaNodeInfo read infoNum failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (retInfoNum > 0) {
        char *retBuf = reinterpret_cast<char *>(const_cast<void *>(
            reply.ReadRawData(retInfoNum * sizeof(MetaNodeInfo))));
        if (retBuf == nullptr) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetAllMetaNodeInfo read meta node failed!");
            return SOFTBUS_IPC_ERR;
        }
        if (memcpy_s(infos, *infoNum * sizeof(MetaNodeInfo), retBuf, retInfoNum * sizeof(MetaNodeInfo)) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetAllMetaNodeInfo copy meta node info failed");
            return SOFTBUS_MEM_ERR;
        }
    }
    *infoNum = retInfoNum;
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::ShiftLNNGear(const char *pkgName, const char *callerId, const char *targetNetworkId,
    const GearMode *mode)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_ERR;
    }

    bool targetNetworkIdIsNull = targetNetworkId == NULL ? true : false;
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ShiftLNNGear write InterfaceToken failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ShiftLNNGear write pkg name failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(callerId)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ShiftLNNGear write callerId failed!");
        return SOFTBUS_ERR;
    }
    if (!targetNetworkIdIsNull && (!data.WriteBool(targetNetworkIdIsNull) || !data.WriteCString(targetNetworkId))) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ShiftLNNGear write target networkid failed!");
        return SOFTBUS_ERR;
    } else if (targetNetworkIdIsNull && !data.WriteBool(targetNetworkIdIsNull)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ShiftLNNGear write null target networkid failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteRawData(mode, sizeof(GearMode))) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ShiftLNNGear write gear node config failed!");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_SHIFT_LNN_GEAR, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ShiftLNNGear send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ShiftLNNGear read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return serverRet;
}
} // namespace OHOS