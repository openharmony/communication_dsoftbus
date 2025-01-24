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

#include "bus_center_server_proxy_standard.h"

#include <securec.h>
#include "bus_center_server_proxy.h"
#include "ipc_skeleton.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "lnn_log.h"
#include "message_parcel.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_server_ipc_interface_code.h"

namespace OHOS {
sptr<IRemoteObject> g_remoteProxy = nullptr;
uint32_t g_getSystemAbilityId = 2;
const std::u16string SAMANAGER_INTERFACE_TOKEN = u"ohos.samgr.accessToken";
static sptr<IRemoteObject> GetSystemAbility()
{
    MessageParcel data;

    if (!data.WriteInterfaceToken(SAMANAGER_INTERFACE_TOKEN)) {
        return nullptr;
    }

    if (!data.WriteInt32(SOFTBUS_SERVER_SA_ID_INNER)) {
        LNN_LOGE(LNN_EVENT, "write SOFTBUS_SERVER_SA_ID_INNER failed");
        return nullptr;
    }
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> samgr = IPCSkeleton::GetContextObject();
    if (samgr == nullptr) {
        LNN_LOGE(LNN_EVENT, "Get samgr failed");
        return nullptr;
    }
    int32_t err = samgr->SendRequest(g_getSystemAbilityId, data, reply, option);
    if (err != 0) {
        LNN_LOGE(LNN_EVENT, "GetSystemAbility failed=%{public}d", err);
        return nullptr;
    }
    return reply.ReadRemoteObject();
}

int32_t BusCenterServerProxy::BusCenterServerProxyStandardInit(void)
{
    if (g_remoteProxy != nullptr) {
        LNN_LOGE(LNN_EVENT, "init success");
        return SOFTBUS_OK;
    }
    g_remoteProxy = GetSystemAbility();
    if (g_remoteProxy == nullptr) {
        LNN_LOGE(LNN_EVENT, "get system ability fail");
        return SOFTBUS_SERVER_NOT_INIT;
    }
    return SOFTBUS_OK;
}

void BusCenterServerProxy::BusCenterServerProxyStandardDeInit(void)
{
    g_remoteProxy.clear();
}

int32_t BusCenterServerProxy::SoftbusRegisterService(const char *clientPkgName, const sptr<IRemoteObject>& object)
{
    (void)clientPkgName;
    (void)object;
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::CreateSessionServer(const char *pkgName, const char *sessionName)
{
    (void)pkgName;
    (void)sessionName;
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::RemoveSessionServer(const char *pkgName, const char *sessionName)
{
    (void)pkgName;
    (void)sessionName;
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::OpenSession(const SessionParam *param, TransInfo *info)
{
    (void)param;
    (void)info;
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::OpenAuthSession(const char *sessionName, const ConnectionAddr *addrInfo)
{
    (void)sessionName;
    (void)addrInfo;
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::NotifyAuthSuccess(int32_t channelId, int32_t channelType)
{
    (void)channelId;
    (void)channelType;
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::ReleaseResources(int32_t channelId)
{
    (void)channelId;
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::CloseChannel(const char *sessionName, int32_t channelId, int32_t channelType)
{
    (void)sessionName;
    (void)channelId;
    (void)channelType;
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::CloseChannelWithStatistics(int32_t channelId, int32_t channelType, uint64_t laneId,
    const void *dataInfo, uint32_t len)
{
    (void)channelId;
    (void)channelType;
    (void)laneId;
    (void)dataInfo;
    (void)len;
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::SendMessage(int32_t channelId, int32_t channelType, const void *data,
    uint32_t len, int32_t msgType)
{
    (void)channelId;
    (void)channelType;
    (void)data;
    (void)len;
    (void)msgType;
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::QosReport(int32_t channelId, int32_t chanType, int32_t appType, int32_t quality)
{
    (void)channelId;
    (void)chanType;
    (void)appType;
    (void)quality;
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::StreamStats(int32_t channelId, int32_t channelType, const StreamSendStats *data)
{
    (void)channelId;
    (void)channelType;
    (void)data;
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::RippleStats(int32_t channelId, int32_t channelType, const TrafficStats *data)
{
    (void)channelId;
    (void)channelType;
    (void)data;
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::JoinLNN(const char *pkgName, void *addr, uint32_t addrTypeLen)
{
    if (pkgName == nullptr || addr == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        LNN_LOGE(LNN_EVENT, "write client name failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteUint32(addrTypeLen)) {
        LNN_LOGE(LNN_EVENT, "write addr type length failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteRawData(addr, addrTypeLen)) {
        LNN_LOGE(LNN_EVENT, "write addr failed");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_JOIN_LNN, data, reply, option) != 0) {
        LNN_LOGE(LNN_EVENT, "send request failed");
        return SOFTBUS_IPC_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        LNN_LOGE(LNN_EVENT, "read serverRet failed");
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
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed");
        return SOFTBUS_IPC_ERR;
    }
    int32_t ret = data.WriteCString(pkgName);
    if (!ret) {
        LNN_LOGE(LNN_EVENT, "write client name failed");
        return SOFTBUS_IPC_ERR;
    }
    ret = data.WriteCString(networkId);
    if (!ret) {
        LNN_LOGE(LNN_EVENT, "write networkId failed");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t err = remote->SendRequest(SERVER_LEAVE_LNN, data, reply, option);
    if (err != 0) {
        LNN_LOGE(LNN_EVENT, "send request failed");
        return SOFTBUS_IPC_ERR;
    }
    int32_t serverRet = 0;
    ret = reply.ReadInt32(serverRet);
    if (!ret) {
        LNN_LOGE(LNN_EVENT, "read serverRet failed");
        return SOFTBUS_IPC_ERR;
    }
    return serverRet;
}

static bool WriteSendRequestMessage(const char *pkgName, MessageParcel *data, uint32_t infoTypeLen)
{
    if (!data->WriteInterfaceToken(BusCenterServerProxy::GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed");
        return false;
    }
    int32_t ret = data->WriteCString(pkgName);
    if (!ret) {
        LNN_LOGE(LNN_EVENT, "write client name failed");
        return false;
    }
    if (!data->WriteUint32(infoTypeLen)) {
        LNN_LOGE(LNN_EVENT, "write info type length failed");
        return false;
    }
    return true;
}

static int32_t ReadIPCReceiveOnlineNodeInfo(void **info, uint32_t infoTypeLen, int32_t *infoNum, MessageParcel* reply)
{
    if (!reply->ReadInt32(*infoNum)) {
        LNN_LOGE(LNN_EVENT, "read infoNum failed");
        return SOFTBUS_IPC_ERR;
    }
    uint32_t maxConnCount = UINT32_MAX;
    if (SoftbusGetConfig(SOFTBUS_INT_MAX_LNN_CONNECTION_CNT, reinterpret_cast<unsigned char *>(&maxConnCount),
        sizeof(maxConnCount)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "softbus get config failed");
        return SOFTBUS_IPC_ERR;
    }

    if ((*infoNum) < 0 || (uint32_t)(*infoNum) > maxConnCount) {
        LNN_LOGE(LNN_EVENT, "invalid param, infoNum=%{public}d, maxConnCount=%{public}u", *infoNum, maxConnCount);
        return SOFTBUS_IPC_ERR;
    }
    *info = nullptr;
    if ((*infoNum) > 0 && static_cast<uint32_t>(*infoNum) <= maxConnCount) {
        uint32_t infoSize = static_cast<uint32_t>(*infoNum) * infoTypeLen;
        void *nodeInfo = const_cast<void *>(reply->ReadRawData(infoSize));
        if (nodeInfo == nullptr) {
            LNN_LOGE(LNN_EVENT, "read node info failed");
            return SOFTBUS_IPC_ERR;
        }
        *info = SoftBusMalloc(infoSize);
        if (*info == nullptr) {
            LNN_LOGE(LNN_EVENT, "malloc failed");
            return SOFTBUS_MALLOC_ERR;
        }
        if (memcpy_s(*info, infoSize, nodeInfo, infoSize) != EOK) {
            LNN_LOGE(LNN_EVENT, "copy node info failed");
            SoftBusFree(*info);
            *info = nullptr;
            return SOFTBUS_MEM_ERR;
        }
    }
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::GetAllOnlineNodeInfo(const char *pkgName, void **info, uint32_t infoTypeLen,
    int32_t *infoNum)
{
    if (pkgName == nullptr || info == nullptr || infoNum == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel data;
    if (!WriteSendRequestMessage(pkgName, &data, infoTypeLen)) {
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_GET_ALL_ONLINE_NODE_INFO, data, reply, option) != 0) {
        LNN_LOGE(LNN_EVENT, "send request failed");
        return SOFTBUS_IPC_ERR;
    }
    return ReadIPCReceiveOnlineNodeInfo(info, infoTypeLen, infoNum, &reply);
}

int32_t BusCenterServerProxy::GetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen)
{
    if (pkgName == nullptr || info == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_remoteProxy == nullptr) {
        LNN_LOGE(LNN_EVENT, "g_remoteProxy is nullptr");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        LNN_LOGE(LNN_EVENT, "write client name failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteUint32(infoTypeLen)) {
        LNN_LOGE(LNN_EVENT, "write info type length failed");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (g_remoteProxy->SendRequest(SERVER_GET_LOCAL_DEVICE_INFO, data, reply, option) != 0) {
        LNN_LOGE(LNN_EVENT, "send request failed");
        return SOFTBUS_IPC_ERR;
    }
    void *nodeInfo = const_cast<void *>(reply.ReadRawData(infoTypeLen));
    if (nodeInfo == nullptr) {
        LNN_LOGE(LNN_EVENT, "read node info failed");
        return SOFTBUS_IPC_ERR;
    }
    if (memcpy_s(info, infoTypeLen, nodeInfo, infoTypeLen) != EOK) {
        LNN_LOGE(LNN_EVENT, "copy node info failed");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::GetNodeKeyInfo(const char *pkgName, const char *networkId, int32_t key,
    unsigned char *buf, uint32_t len)
{
    if (pkgName == nullptr || networkId == nullptr || buf == nullptr) {
        LNN_LOGE(LNN_EVENT, "params are nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(pkgName) || !data.WriteCString(networkId)) {
        LNN_LOGE(LNN_EVENT, "write client name or networkId failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteInt32(key) || !data.WriteUint32(len)) {
        LNN_LOGE(LNN_EVENT, "write key or buf len failed");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_GET_NODE_KEY_INFO, data, reply, option) != 0) {
        LNN_LOGE(LNN_EVENT, "send request failed");
        return SOFTBUS_IPC_ERR;
    }
    int32_t infoLen;
    if (!reply.ReadInt32(infoLen) || infoLen <= 0 || static_cast<uint32_t>(infoLen) > len) {
        LNN_LOGE(LNN_EVENT,
            "read infoLen failed, len=%{public}u, infoLen=%{public}d", len, infoLen);
        return SOFTBUS_IPC_ERR;
    }
    void *retBuf = const_cast<void *>(reply.ReadRawData(infoLen));
    if (retBuf == nullptr) {
        LNN_LOGE(LNN_EVENT, "read retBuf failed");
        return SOFTBUS_IPC_ERR;
    }
    if (memcpy_s(buf, len, retBuf, infoLen) != EOK) {
        LNN_LOGE(LNN_EVENT, "copy node key info failed");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::SetNodeDataChangeFlag(const char *pkgName, const char *networkId, uint16_t dataChangeFlag)
{
    if (pkgName == nullptr || networkId == nullptr) {
        LNN_LOGE(LNN_EVENT, "params are nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        LNN_LOGE(LNN_EVENT, "write client name failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(networkId)) {
        LNN_LOGE(LNN_EVENT, "write networkId failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteUint16(dataChangeFlag)) {
        LNN_LOGE(LNN_EVENT, "write key failed");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_SET_NODE_DATA_CHANGE_FLAG, data, reply, option) != 0) {
        LNN_LOGE(LNN_EVENT, "send request failed");
        return SOFTBUS_IPC_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        LNN_LOGE(LNN_EVENT, "read serverRet failed");
        return SOFTBUS_IPC_ERR;
    }
    return serverRet;
}

int32_t BusCenterServerProxy::RegDataLevelChangeCb(const char *pkgName)
{
    if (pkgName == nullptr) {
        LNN_LOGE(LNN_EVENT, "pkgName is nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        LNN_LOGE(LNN_EVENT, "write pkgName failed");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t serverRet = remote->SendRequest(SERVER_REG_DATA_LEVEL_CHANGE_CB, data, reply, option);
    if (serverRet != 0) {
        LNN_LOGE(LNN_EVENT, "send request failed");
        return serverRet;
    }

    if (!reply.ReadInt32(serverRet)) {
        LNN_LOGE(LNN_EVENT, "read serverRet failed");
        return SOFTBUS_IPC_ERR;
    }
    return serverRet;
}

int32_t BusCenterServerProxy::UnregDataLevelChangeCb(const char *pkgName)
{
    if (pkgName == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        LNN_LOGE(LNN_EVENT, "write pkgName failed");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t serverRet = remote->SendRequest(SERVER_UNREG_DATA_LEVEL_CHANGE_CB, data, reply, option);
    if (serverRet != 0) {
        LNN_LOGE(LNN_EVENT, "send request failed");
        return serverRet;
    }

    if (!reply.ReadInt32(serverRet)) {
        LNN_LOGE(LNN_EVENT, "read serverRet failed");
        return SOFTBUS_IPC_ERR;
    }
    return serverRet;
}

int32_t BusCenterServerProxy::SetDataLevel(const DataLevel *dataLevel)
{
    if (dataLevel == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }

    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteRawData((void*)dataLevel, sizeof(DataLevel))) {
        LNN_LOGE(LNN_EVENT, "write data level failed");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t serverRet = remote->SendRequest(SERVER_SET_DATA_LEVEL, data, reply, option);
    if (serverRet != 0) {
        LNN_LOGE(LNN_EVENT, "send request failed");
        return serverRet;
    }

    if (!reply.ReadInt32(serverRet)) {
        LNN_LOGE(LNN_EVENT, "read serverRet failed");
        return SOFTBUS_IPC_ERR;
    }
    return serverRet;
}

int32_t BusCenterServerProxy::StartTimeSync(const char *pkgName, const char *targetNetworkId, int32_t accuracy,
    int32_t period)
{
    if (pkgName == nullptr || targetNetworkId == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        LNN_LOGE(LNN_EVENT, "write client name failed");
        return SOFTBUS_IPC_ERR;
    }

    if (!data.WriteCString(targetNetworkId)) {
        LNN_LOGE(LNN_EVENT, "write networkId failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteInt32(accuracy)) {
        LNN_LOGE(LNN_EVENT, "write accuracy failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteInt32(period)) {
        LNN_LOGE(LNN_EVENT, "write period failed");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_START_TIME_SYNC, data, reply, option) != 0) {
        LNN_LOGE(LNN_EVENT, "send request failed");
        return SOFTBUS_IPC_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        LNN_LOGE(LNN_EVENT, "read serverRet failed");
        return SOFTBUS_IPC_ERR;
    }
    return serverRet;
}

int32_t BusCenterServerProxy::StopTimeSync(const char *pkgName, const char *targetNetworkId)
{
    if (pkgName == nullptr || targetNetworkId == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        LNN_LOGE(LNN_EVENT, "write client name failed");
        return SOFTBUS_IPC_ERR;
    }

    if (!data.WriteCString(targetNetworkId)) {
        LNN_LOGE(LNN_EVENT, "write networkId failed");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_STOP_TIME_SYNC, data, reply, option) != 0) {
        LNN_LOGE(LNN_EVENT, "send request failed");
        return SOFTBUS_IPC_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        LNN_LOGE(LNN_EVENT, "read serverRet failed");
        return SOFTBUS_IPC_ERR;
    }
    return serverRet;
}

int32_t BusCenterServerProxy::PublishLNN(const char *pkgName, const PublishInfo *info)
{
    if (pkgName == nullptr || info == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        LNN_LOGE(LNN_EVENT, "write client name failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteInt32(info->publishId) || !data.WriteInt32(info->mode) || !data.WriteInt32(info->medium) ||
        !data.WriteInt32(info->freq) || !data.WriteCString(info->capability)) {
        LNN_LOGE(LNN_EVENT, "write publish common info failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteUint32(info->dataLen)) {
        LNN_LOGE(LNN_EVENT, "write capabilityData length failed");
        return SOFTBUS_IPC_ERR;
    }
    if (info->dataLen != 0 && !data.WriteCString(reinterpret_cast<const char *>(info->capabilityData))) {
        LNN_LOGE(LNN_EVENT, "write capabilityData failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteBool(info->ranging)) {
        LNN_LOGE(LNN_EVENT, "write ranging failed");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_PUBLISH_LNN, data, reply, option) != 0) {
        LNN_LOGE(LNN_EVENT, "send request failed");
        return SOFTBUS_IPC_ERR;
    }
    int32_t serverRet;
    if (!reply.ReadInt32(serverRet)) {
        LNN_LOGE(LNN_EVENT, "read serverRet failed");
        return SOFTBUS_IPC_ERR;
    }
    return serverRet;
}

int32_t BusCenterServerProxy::StopPublishLNN(const char *pkgName, int32_t publishId)
{
    if (pkgName == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        LNN_LOGE(LNN_EVENT, "write client name failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteInt32(publishId)) {
        LNN_LOGE(LNN_EVENT, "write publishId failed");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_STOP_PUBLISH_LNN, data, reply, option) != 0) {
        LNN_LOGE(LNN_EVENT, "send request failed");
        return SOFTBUS_IPC_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        LNN_LOGE(LNN_EVENT, "read serverRet failed");
        return SOFTBUS_IPC_ERR;
    }
    return serverRet;
}

int32_t BusCenterServerProxy::RefreshLNN(const char *pkgName, const SubscribeInfo *info)
{
    if (pkgName == nullptr || info == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        LNN_LOGE(LNN_EVENT, "write client name failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteInt32(info->subscribeId) || !data.WriteInt32(info->mode) || !data.WriteInt32(info->medium) ||
        !data.WriteInt32(info->freq)) {
        LNN_LOGE(LNN_EVENT, "write subscribe common info failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteBool(info->isSameAccount) || !data.WriteBool(info->isWakeRemote) ||
        !data.WriteCString(info->capability)) {
        LNN_LOGE(LNN_EVENT, "write flag and capability failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteUint32(info->dataLen)) {
        LNN_LOGE(LNN_EVENT, "write capabilityData length failed");
        return SOFTBUS_IPC_ERR;
    }
    if (info->dataLen != 0 && !data.WriteCString(reinterpret_cast<const char *>(info->capabilityData))) {
        LNN_LOGE(LNN_EVENT, "write capabilityData failed");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_REFRESH_LNN, data, reply, option) != 0) {
        LNN_LOGE(LNN_EVENT, "send request failed");
        return SOFTBUS_IPC_ERR;
    }
    int32_t serverRet;
    if (!reply.ReadInt32(serverRet)) {
        LNN_LOGE(LNN_EVENT, "read serverRet failed");
        return SOFTBUS_IPC_ERR;
    }
    return serverRet;
}

int32_t BusCenterServerProxy::StopRefreshLNN(const char *pkgName, int32_t refreshId)
{
    if (pkgName == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        LNN_LOGE(LNN_EVENT, "write client name failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteInt32(refreshId)) {
        LNN_LOGE(LNN_EVENT, "write refreshId failed");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_STOP_REFRESH_LNN, data, reply, option) != 0) {
        LNN_LOGE(LNN_EVENT, "send request failed");
        return SOFTBUS_IPC_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        LNN_LOGE(LNN_EVENT, "read serverRet failed");
        return SOFTBUS_IPC_ERR;
    }
    return serverRet;
}

int32_t BusCenterServerProxy::ActiveMetaNode(const MetaNodeConfigInfo *info, char *metaNodeId)
{
    if (info == nullptr || metaNodeId == nullptr) {
        LNN_LOGE(LNN_EVENT, "params are nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteRawData(info, sizeof(MetaNodeConfigInfo))) {
        LNN_LOGE(LNN_EVENT, "write meta node config failed");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_ACTIVE_META_NODE, data, reply, option) != 0) {
        LNN_LOGE(LNN_EVENT, "send request failed");
        return SOFTBUS_IPC_ERR;
    }
    char *retBuf = const_cast<char *>(reply.ReadCString());
    if (retBuf == nullptr) {
        LNN_LOGE(LNN_EVENT, "read meta node id failed");
        return SOFTBUS_IPC_ERR;
    }
    if (strncpy_s(metaNodeId, NETWORK_ID_BUF_LEN, retBuf, strlen(retBuf)) != EOK) {
        LNN_LOGE(LNN_EVENT, "copy meta node id failed");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::DeactiveMetaNode(const char *metaNodeId)
{
    if (metaNodeId == nullptr) {
        LNN_LOGE(LNN_EVENT, "params are nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(metaNodeId)) {
        LNN_LOGE(LNN_EVENT, "write meta node id failed");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_DEACTIVE_META_NODE, data, reply, option) != 0) {
        LNN_LOGE(LNN_EVENT, "send request failed");
        return SOFTBUS_IPC_ERR;
    }
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::GetAllMetaNodeInfo(MetaNodeInfo *infos, int32_t *infoNum)
{
    if (infos == nullptr || infoNum == nullptr) {
        LNN_LOGE(LNN_EVENT, "params are nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteInt32(*infoNum)) {
        LNN_LOGE(LNN_EVENT, "write infoNum failed");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_GET_ALL_META_NODE_INFO, data, reply, option) != 0) {
        LNN_LOGE(LNN_EVENT, "send request failed");
        return SOFTBUS_IPC_ERR;
    }
    int32_t retInfoNum;
    if (!reply.ReadInt32(retInfoNum)) {
        LNN_LOGE(LNN_EVENT, "read infoNum failed");
        return SOFTBUS_IPC_ERR;
    }
    if (retInfoNum > 0) {
        char *retBuf = reinterpret_cast<char *>(const_cast<void *>(
            reply.ReadRawData(retInfoNum * sizeof(MetaNodeInfo))));
        if (retBuf == nullptr) {
            LNN_LOGE(LNN_EVENT, "read meta node failed");
            return SOFTBUS_IPC_ERR;
        }
        if (memcpy_s(infos, *infoNum * sizeof(MetaNodeInfo), retBuf, retInfoNum * sizeof(MetaNodeInfo)) != EOK) {
            LNN_LOGE(LNN_EVENT, "copy meta node info failed");
            return SOFTBUS_MEM_ERR;
        }
    }
    *infoNum = retInfoNum;
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::ShiftLNNGear(const char *pkgName, const char *callerId, const char *targetNetworkId,
    const GearMode *mode)
{
    if (pkgName == nullptr || callerId == nullptr || mode == nullptr) {
        LNN_LOGE(LNN_EVENT, "params are nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return SOFTBUS_SERVER_NOT_INIT;
    }

    bool targetNetworkIdIsNull = targetNetworkId == nullptr ? true : false;
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed");
        return SOFTBUS_NETWORK_WRITETOKEN_FAILED;
    }
    if (!data.WriteCString(pkgName)) {
        LNN_LOGE(LNN_EVENT, "write pkg name failed");
        return SOFTBUS_NETWORK_WRITECSTRING_FAILED;
    }
    if (!data.WriteCString(callerId)) {
        LNN_LOGE(LNN_EVENT, "write callerId failed");
        return SOFTBUS_NETWORK_WRITECSTRING_FAILED;
    }
    if (!targetNetworkIdIsNull && (!data.WriteBool(targetNetworkIdIsNull) || !data.WriteCString(targetNetworkId))) {
        LNN_LOGE(LNN_EVENT, "write target networkid failed");
        return SOFTBUS_NETWORK_WRITECSTRING_FAILED;
    } else if (targetNetworkIdIsNull && !data.WriteBool(targetNetworkIdIsNull)) {
        LNN_LOGE(LNN_EVENT, "write null target networkid failed");
        return SOFTBUS_NETWORK_WRITEBOOL_FAILED;
    }
    if (!data.WriteRawData(mode, sizeof(GearMode))) {
        LNN_LOGE(LNN_EVENT, "write gear node config failed");
        return SOFTBUS_NETWORK_WRITERAWDATA_FAILED;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_SHIFT_LNN_GEAR, data, reply, option) != 0) {
        LNN_LOGE(LNN_EVENT, "send request failed");
        return SOFTBUS_NETWORK_SEND_REQUEST_FAILED;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        LNN_LOGE(LNN_EVENT, "read serverRet failed");
        return SOFTBUS_NETWORK_READINT32_FAILED;
    }
    return serverRet;
}

int32_t BusCenterServerProxy::SyncTrustedRelationShip(const char *pkgName, const char *msg, uint32_t msgLen)
{
    if (pkgName == nullptr || msg == nullptr || msgLen == 0) {
        LNN_LOGE(LNN_EVENT, "params are nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return SOFTBUS_TRANS_PROXY_REMOTE_NULL;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    if (!data.WriteCString(pkgName)) {
        LNN_LOGE(LNN_EVENT, "write pkg name failed");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    if (!data.WriteCString(msg)) {
        LNN_LOGE(LNN_EVENT, "write msg failed");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    if (!data.WriteUint32(msgLen)) {
        LNN_LOGE(LNN_EVENT, "write msg length failed");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(SERVER_SYNC_TRUSTED_RELATION, data, reply, option);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "send request failed, ret=%{public}d", ret);
        return SOFTBUS_IPC_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        LNN_LOGE(LNN_EVENT, "read serverRet failed");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    return serverRet;
}

int32_t BusCenterServerProxy::SetDisplayName(const char *pkgName, const char *nameData, uint32_t len)
{
    if (pkgName == nullptr || nameData == nullptr || len == 0) {
        LNN_LOGE(LNN_EVENT, "params are nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return SOFTBUS_TRANS_PROXY_REMOTE_NULL;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    if (!data.WriteCString(pkgName)) {
        LNN_LOGE(LNN_EVENT, "write pkg name failed");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    if (!data.WriteCString(nameData)) {
        LNN_LOGE(LNN_EVENT, "write nameData failed");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    if (!data.WriteUint32(len)) {
        LNN_LOGE(LNN_EVENT, "write length failed");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(SERVER_SET_DISPLAY_NAME, data, reply, option);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "send request failed, ret=%{public}d", ret);
        return SOFTBUS_IPC_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        LNN_LOGE(LNN_EVENT, "read serverRet failed");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    return serverRet;
}

int32_t BusCenterServerProxy::GetBusCenterExObj(sptr<IRemoteObject> &object)
{
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is null");
        return SOFTBUS_SERVER_NOT_INIT;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "GetBusCenterExObj write InterfaceToken failed!");
        return SOFTBUS_NETWORK_WRITETOKEN_FAILED;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(SERVER_GET_BUS_CENTER_EX_OBJ, data, reply, option);
    if (ret != ERR_NONE) {
        LNN_LOGE(LNN_EVENT, "send request failed, ret=%{public}d", ret);
        return SOFTBUS_NETWORK_SEND_REQUEST_FAILED;
    }
    if (!reply.ReadInt32(ret)) {
        LNN_LOGE(LNN_EVENT, "GetBusCenterExObj send ret failed");
        return SOFTBUS_NETWORK_READINT32_FAILED;
    }
    if (ret == SOFTBUS_OK) {
        object = reply.ReadRemoteObject();
    }
    return ret;
}

int32_t BusCenterServerProxy::EvaluateQos(const char *peerNetworkId, TransDataType dataType, const QosTV *qos,
    uint32_t qosCount)
{
    (void)peerNetworkId;
    (void)dataType;
    (void)qos;
    (void)qosCount;
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::ProcessInnerEvent(int32_t eventType, uint8_t *buf, uint32_t len)
{
    (void)eventType;
    (void)buf;
    (void)len;
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::PrivilegeCloseChannel(uint64_t tokenId, int32_t pid, const char *peerNetworkId)
{
    (void)tokenId;
    (void)pid;
    (void)peerNetworkId;
    return SOFTBUS_OK;
}
} // namespace OHOS