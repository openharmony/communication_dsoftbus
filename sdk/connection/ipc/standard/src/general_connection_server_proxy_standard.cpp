/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "general_connection_server_proxy_standard.h"

#include "conn_log.h"
#include "general_connection_server_proxy.h"
#include "ipc_skeleton.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "message_parcel.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_server_ipc_interface_code.h"
#include <securec.h>

namespace OHOS {
static uint32_t g_getSystemAbilityId = 2;
const std::u16string SAMANAGER_INTERFACE_TOKEN = u"ohos.samgr.accessToken";
static sptr<IRemoteObject> GetSystemAbility()
{
    MessageParcel data;

    if (!data.WriteInterfaceToken(SAMANAGER_INTERFACE_TOKEN)) {
        return nullptr;
    }

    if (!data.WriteInt32(SOFTBUS_SERVER_SA_ID_INNER)) {
        CONN_LOGE(CONN_COMMON, "write SOFTBUS_SERVER_SA_ID_INNER fail");
        return nullptr;
    }
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> samgr = IPCSkeleton::GetContextObject();
    if (samgr == nullptr) {
        CONN_LOGE(CONN_COMMON, "Get samgr fail");
        return nullptr;
    }
    int32_t err = samgr->SendRequest(g_getSystemAbilityId, data, reply, option);
    if (err != 0) {
        CONN_LOGE(CONN_COMMON, "GetSystemAbility fail=%{public}d", err);
        return nullptr;
    }
    return reply.ReadRemoteObject();
}

int32_t ConnectionServerProxy::SoftbusRegisterService(const char *clientPkgName, const sptr<IRemoteObject> &object)
{
    (void)clientPkgName;
    (void)object;
    return SOFTBUS_OK;
}

int32_t ConnectionServerProxy::CreateSessionServer(const char *pkgName, const char *sessionName, uint64_t timestamp)
{
    (void)pkgName;
    (void)sessionName;
    (void)timestamp;
    return SOFTBUS_OK;
}

int32_t ConnectionServerProxy::RemoveSessionServer(const char *pkgName, const char *sessionName, uint64_t timestamp)
{
    (void)pkgName;
    (void)sessionName;
    (void)timestamp;
    return SOFTBUS_OK;
}

int32_t ConnectionServerProxy::OpenSession(const SessionParam *param, TransInfo *info)
{
    (void)param;
    (void)info;
    return SOFTBUS_OK;
}

int32_t ConnectionServerProxy::OpenAuthSession(const char *sessionName, const ConnectionAddr *addrInfo)
{
    (void)sessionName;
    (void)addrInfo;
    return SOFTBUS_OK;
}

int32_t ConnectionServerProxy::NotifyAuthSuccess(int32_t channelId, int32_t channelType)
{
    (void)channelId;
    (void)channelType;
    return SOFTBUS_OK;
}

int32_t ConnectionServerProxy::ReleaseResources(int32_t channelId)
{
    (void)channelId;
    return SOFTBUS_OK;
}

int32_t ConnectionServerProxy::CloseChannel(const char *sessionName, int32_t channelId, int32_t channelType)
{
    (void)sessionName;
    (void)channelId;
    (void)channelType;
    return SOFTBUS_OK;
}

int32_t ConnectionServerProxy::CloseChannelWithStatistics(
    int32_t channelId, int32_t channelType, uint64_t laneId, const void *dataInfo, uint32_t len)
{
    (void)channelId;
    (void)channelType;
    (void)laneId;
    (void)dataInfo;
    (void)len;
    return SOFTBUS_OK;
}

int32_t ConnectionServerProxy::SendMessage(
    int32_t channelId, int32_t channelType, const void *data, uint32_t len, int32_t msgType)
{
    (void)channelId;
    (void)channelType;
    (void)data;
    (void)len;
    (void)msgType;
    return SOFTBUS_OK;
}

int32_t ConnectionServerProxy::QosReport(int32_t channelId, int32_t chanType, int32_t appType, int32_t quality)
{
    (void)channelId;
    (void)chanType;
    (void)appType;
    (void)quality;
    return SOFTBUS_OK;
}

int32_t ConnectionServerProxy::StreamStats(int32_t channelId, int32_t channelType, const StreamSendStats *data)
{
    (void)channelId;
    (void)channelType;
    (void)data;
    return SOFTBUS_OK;
}

int32_t ConnectionServerProxy::RippleStats(int32_t channelId, int32_t channelType, const TrafficStats *data)
{
    (void)channelId;
    (void)channelType;
    (void)data;
    return SOFTBUS_OK;
}

int32_t ConnectionServerProxy::RegisterRangeCallbackForMsdp(const char *pkgName)
{
    (void)pkgName;
    return SOFTBUS_OK;
}

int32_t ConnectionServerProxy::UnregisterRangeCallbackForMsdp(const char *pkgName)
{
    (void)pkgName;
    return SOFTBUS_OK;
}

int32_t ConnectionServerProxy::JoinLNN(const char *pkgName, void *addr, uint32_t addrTypeLen, bool isForceJoin)
{
    (void)pkgName;
    (void)addr;
    (void)addrTypeLen;
    (void)isForceJoin;
    return SOFTBUS_OK;
}

int32_t ConnectionServerProxy::LeaveLNN(const char *pkgName, const char *networkId)
{
    (void)pkgName;
    (void)networkId;
    return SOFTBUS_OK;
}

int32_t ConnectionServerProxy::GetAllOnlineNodeInfo(
    const char *pkgName, void **info, uint32_t infoTypeLen, int32_t *infoNum)
{
    (void)pkgName;
    (void)info;
    (void)infoTypeLen;
    (void)infoNum;
    return SOFTBUS_OK;
}

int32_t ConnectionServerProxy::GetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen)
{
    (void)pkgName;
    (void)info;
    (void)infoTypeLen;
    return SOFTBUS_OK;
}

int32_t ConnectionServerProxy::GetNodeKeyInfo(
    const char *pkgName, const char *networkId, int32_t key, unsigned char *buf, uint32_t len)
{
    (void)pkgName;
    (void)networkId;
    (void)key;
    (void)buf;
    (void)len;
    return SOFTBUS_OK;
}

int32_t ConnectionServerProxy::SetNodeKeyInfo(
    const char *pkgName, const char *networkId, int32_t key, unsigned char *buf, uint32_t len)
{
    (void)pkgName;
    (void)networkId;
    (void)key;
    (void)buf;
    (void)len;
    return SOFTBUS_OK;
}

int32_t ConnectionServerProxy::SetNodeDataChangeFlag(
    const char *pkgName, const char *networkId, uint16_t dataChangeFlag)
{
    (void)pkgName;
    (void)networkId;
    (void)dataChangeFlag;
    return SOFTBUS_OK;
}

int32_t ConnectionServerProxy::RegDataLevelChangeCb(const char *pkgName)
{
    (void)pkgName;
    return SOFTBUS_OK;
}

int32_t ConnectionServerProxy::UnregDataLevelChangeCb(const char *pkgName)
{
    (void)pkgName;
    return SOFTBUS_OK;
}

int32_t ConnectionServerProxy::SetDataLevel(const DataLevel *dataLevel)
{
    (void)dataLevel;
    return SOFTBUS_OK;
}

int32_t ConnectionServerProxy::StartTimeSync(
    const char *pkgName, const char *targetNetworkId, int32_t accuracy, int32_t period)
{
    (void)pkgName;
    (void)targetNetworkId;
    (void)accuracy;
    (void)period;
    return SOFTBUS_OK;
}

int32_t ConnectionServerProxy::StopTimeSync(const char *pkgName, const char *targetNetworkId)
{
    (void)pkgName;
    (void)targetNetworkId;
    return SOFTBUS_OK;
}

int32_t ConnectionServerProxy::EvaluateQos(
    const char *peerNetworkId, TransDataType dataType, const QosTV *qos, uint32_t qosCount)
{
    (void)peerNetworkId;
    (void)dataType;
    (void)qos;
    (void)qosCount;
    return SOFTBUS_OK;
}

int32_t ConnectionServerProxy::ProcessInnerEvent(int32_t eventType, uint8_t *buf, uint32_t len)
{
    (void)eventType;
    (void)buf;
    (void)len;
    return SOFTBUS_OK;
}

int32_t ConnectionServerProxy::PrivilegeCloseChannel(uint64_t tokenId, int32_t pid, const char *peerNetworkId)
{
    (void)tokenId;
    (void)pid;
    (void)peerNetworkId;
    return SOFTBUS_OK;
}

int32_t ConnectionServerProxy::CreateServer(const char *pkgName, const char *name)
{
    if (pkgName == nullptr || name == nullptr) {
        CONN_LOGE(CONN_COMMON, "pkgName or name is null");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        CONN_LOGE(CONN_COMMON, "remote is null");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        CONN_LOGE(CONN_COMMON, "write InterfaceToken fail");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        CONN_LOGE(CONN_COMMON, "write package name fail");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(name)) {
        CONN_LOGE(CONN_COMMON, "write name fail");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(SERVER_GENERAL_CREATE_SERVER, data, reply, option);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "send request fail, err=%{public}d", ret);
        return ret;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        CONN_LOGE(CONN_COMMON, "read serverRet fail");
        return SOFTBUS_IPC_ERR;
    }
    return serverRet;
}

int32_t ConnectionServerProxy::RemoveServer(const char *pkgName, const char *name)
{
    if (pkgName == nullptr || name == nullptr) {
        CONN_LOGE(CONN_COMMON, "pkgName or name is null");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        CONN_LOGE(CONN_COMMON, "remote is null");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        CONN_LOGE(CONN_COMMON, "write InterfaceToken fail");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        CONN_LOGE(CONN_COMMON, "write package name fail");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(name)) {
        CONN_LOGE(CONN_COMMON, "write name fail");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(SERVER_GENERAL_REMOVE_SERVER, data, reply, option);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "send request fail, err=%{public}d", ret);
        return ret;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        CONN_LOGE(CONN_COMMON, "read serverRet fail");
        return SOFTBUS_IPC_ERR;
    }
    return serverRet;
}

int32_t ConnectionServerProxy::Connect(const char *pkgName, const char *name, const Address *address)
{
    if (pkgName == nullptr || name == nullptr || address == nullptr) {
        CONN_LOGE(CONN_COMMON, "pkgName or name or address is null");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        CONN_LOGE(CONN_COMMON, "remote is null");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        CONN_LOGE(CONN_COMMON, "write InterfaceToken fail");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        CONN_LOGE(CONN_COMMON, "write package name fail");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(name)) {
        CONN_LOGE(CONN_COMMON, "write name fail");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(address->addr.ble.mac)) {
        CONN_LOGE(CONN_COMMON, "write address fail");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteInt32(address->addrType)) {
        CONN_LOGE(CONN_COMMON, "write addrType fail");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(SERVER_GENERAL_CONNECT, data, reply, option);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "send request fail, err=%{public}d", ret);
        return ret;
    }
    int32_t handle = 0;
    if (!reply.ReadInt32(handle)) {
        CONN_LOGE(CONN_COMMON, "read handle fail");
        return SOFTBUS_IPC_ERR;
    }
    return handle;
}

int32_t ConnectionServerProxy::Disconnect(uint32_t handle)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        CONN_LOGE(CONN_COMMON, "remote is null");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        CONN_LOGE(CONN_COMMON, "write InterfaceToken fail");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteUint32(handle)) {
        CONN_LOGE(CONN_COMMON, "write handle fail");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(SERVER_GENERAL_DISCONNECT, data, reply, option);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "send request fail, err=%{public}d", ret);
        return ret;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        CONN_LOGE(CONN_COMMON, "read serverRet fail");
        return SOFTBUS_IPC_ERR;
    }
    return serverRet;
}

int32_t ConnectionServerProxy::Send(uint32_t handle, const uint8_t *data, uint32_t len)
{
    if (data == nullptr) {
        CONN_LOGE(CONN_COMMON, "data is null");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        CONN_LOGE(CONN_COMMON, "remote is null");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel dataParcel;
    if (!dataParcel.WriteInterfaceToken(GetDescriptor())) {
        CONN_LOGE(CONN_COMMON, "write InterfaceToken fail");
        return SOFTBUS_IPC_ERR;
    }
    if (!dataParcel.WriteUint32(handle)) {
        CONN_LOGE(CONN_COMMON, "write handle fail");
        return SOFTBUS_IPC_ERR;
    }
    if (!dataParcel.WriteUint32(len)) {
        CONN_LOGE(CONN_COMMON, "write data len fail");
        return SOFTBUS_IPC_ERR;
    }
    if (!dataParcel.WriteRawData((void *)data, len)) {
        CONN_LOGE(CONN_COMMON, "write data fail");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(SERVER_GENERAL_SEND, dataParcel, reply, option);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "send request fail, err=%{public}d", ret);
        return ret;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        CONN_LOGE(CONN_COMMON, "read serverRet fail");
        return SOFTBUS_IPC_ERR;
    }
    return serverRet;
}

int32_t ConnectionServerProxy::ConnGetPeerDeviceId(uint32_t handle, char *deviceId, uint32_t len)
{
    if (deviceId == nullptr) {
        CONN_LOGE(CONN_COMMON, "deviceId is null");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        CONN_LOGE(CONN_COMMON, "remote is null");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel dataParcel;
    if (!dataParcel.WriteInterfaceToken(GetDescriptor())) {
        CONN_LOGE(CONN_COMMON, "write InterfaceToken fail");
        return SOFTBUS_IPC_ERR;
    }
    if (!dataParcel.WriteUint32(handle)) {
        CONN_LOGE(CONN_COMMON, "write handle fail");
        return SOFTBUS_IPC_ERR;
    }
    if (!dataParcel.WriteUint32(len)) {
        CONN_LOGE(CONN_COMMON, "write deviceId len fail");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(SERVER_GENERAL_GET_PEER_DEVICE_ID, dataParcel, reply, option);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "send request fail, err=%{public}d", ret);
        return ret;
    }
    char *tmp = (char *)reply.ReadRawData(len);
    if (tmp == nullptr) {
        CONN_LOGE(CONN_COMMON, "read deviceId fail");
        return SOFTBUS_IPC_ERR;
    }
    if (strcpy_s(deviceId, len, tmp) != EOK) {
        CONN_LOGE(CONN_COMMON, "copy deviceId fail");
        return SOFTBUS_STRCPY_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        CONN_LOGE(CONN_COMMON, "read serverRet fail");
        return SOFTBUS_IPC_ERR;
    }
    if (serverRet != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "get peer device id fail");
        return serverRet;
    }
    return serverRet;
}
} // namespace OHOS