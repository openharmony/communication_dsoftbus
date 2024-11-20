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

#include "bus_center_client_proxy_standard.h"

#include "lnn_log.h"
#include "message_parcel.h"
#include "softbus_error_code.h"
#include "softbus_server_ipc_interface_code.h"

namespace OHOS {
int32_t BusCenterClientProxy::OnChannelOpened(const char *sessionName, const ChannelInfo *info)
{
    return SOFTBUS_OK;
}

int32_t BusCenterClientProxy::OnChannelOpenFailed(int32_t channelId, int32_t channelType, int32_t errCode)
{
    return SOFTBUS_OK;
}

int32_t BusCenterClientProxy::OnChannelLinkDown(const char *networkId, int32_t routeType)
{
    return SOFTBUS_OK;
}

int32_t BusCenterClientProxy::OnChannelClosed(int32_t channelId, int32_t channelType, int32_t messageType)
{
    return SOFTBUS_OK;
}

int32_t BusCenterClientProxy::OnChannelMsgReceived(int32_t channelId, int32_t channelType,
    const void *dataInfo, uint32_t len, int32_t type)
{
    return SOFTBUS_OK;
}

int32_t BusCenterClientProxy::OnChannelQosEvent(int32_t channelId, int32_t channelType,
    int32_t eventId, int32_t tvCount, const QosTv *tvList)
{
    return SOFTBUS_OK;
}

int32_t BusCenterClientProxy::OnJoinLNNResult(void *addr, uint32_t addrTypeLen, const char *networkId, int retCode)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return SOFTBUS_NETWORK_REMOTE_NULL;
    }
    if (addr == nullptr || (retCode == 0 && networkId == nullptr)) {
        LNN_LOGE(LNN_EVENT, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed!");
        return SOFTBUS_NETWORK_WRITETOKEN_FAILED;
    }
    if (!data.WriteUint32(addrTypeLen)) {
        LNN_LOGE(LNN_EVENT, "write addr type length failed");
        return SOFTBUS_NETWORK_WRITEINT32_FAILED;
    }
    if (!data.WriteRawData(addr, addrTypeLen)) {
        LNN_LOGE(LNN_EVENT, "write addr failed");
        return SOFTBUS_NETWORK_WRITERAWDATA_FAILED;
    }
    if (!data.WriteInt32(retCode)) {
        LNN_LOGE(LNN_EVENT, "write retCode failed");
        return SOFTBUS_NETWORK_WRITEINT32_FAILED;
    }
    if (retCode == 0 && !data.WriteCString(networkId)) {
        LNN_LOGE(LNN_EVENT, "write networkId failed");
        return SOFTBUS_NETWORK_WRITECSTRING_FAILED;
    }
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    if (remote->SendRequest(CLIENT_ON_JOIN_RESULT, data, reply, option) != 0) {
        LNN_LOGE(LNN_EVENT, "send request failed");
        return SOFTBUS_NETWORK_SEND_REQUEST_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t BusCenterClientProxy::OnJoinMetaNodeResult(void *addr, uint32_t addrTypeLen, void *metaInfo,
    uint32_t infoLen, int retCode)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr || metaInfo == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return SOFTBUS_NETWORK_REMOTE_NULL;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed!");
        return SOFTBUS_NETWORK_WRITETOKEN_FAILED;
    }
    if (addr != nullptr) {
        if (!data.WriteUint32(addrTypeLen)) {
            LNN_LOGE(LNN_EVENT, "write addr type length failed");
            return SOFTBUS_NETWORK_WRITEINT32_FAILED;
        }
        if (!data.WriteRawData(addr, addrTypeLen)) {
            LNN_LOGE(LNN_EVENT, "write addr failed");
            return SOFTBUS_NETWORK_WRITERAWDATA_FAILED;
        }
    } else {
        if (!data.WriteUint32(0)) {
            LNN_LOGE(LNN_EVENT, "write addr type length failed");
            return SOFTBUS_NETWORK_WRITEINT32_FAILED;
        }
    }
    if (!data.WriteUint32(infoLen)) {
        LNN_LOGE(LNN_EVENT, "write infoLen failed");
        return SOFTBUS_NETWORK_WRITEINT32_FAILED;
    }
    if (!data.WriteRawData(metaInfo, infoLen)) {
        LNN_LOGE(LNN_EVENT, "write metaInfo failed");
        return SOFTBUS_NETWORK_WRITERAWDATA_FAILED;
    }
    if (!data.WriteInt32(retCode)) {
        LNN_LOGE(LNN_EVENT, "write retCode failed");
        return SOFTBUS_NETWORK_WRITEINT32_FAILED;
    }
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    if (remote->SendRequest(CLIENT_ON_JOIN_METANODE_RESULT, data, reply, option) != 0) {
        LNN_LOGE(LNN_EVENT, "OnJoinMetaNodeResult send request failed");
        return SOFTBUS_NETWORK_SEND_REQUEST_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t BusCenterClientProxy::OnLeaveLNNResult(const char *networkId, int retCode)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return SOFTBUS_NETWORK_REMOTE_NULL;
    }
    if (networkId == nullptr) {
        LNN_LOGE(LNN_EVENT, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed!");
        return SOFTBUS_NETWORK_WRITETOKEN_FAILED;
    }
    if (!data.WriteCString(networkId)) {
        LNN_LOGE(LNN_EVENT, "write networkId failed");
        return SOFTBUS_NETWORK_WRITECSTRING_FAILED;
    }
    if (!data.WriteInt32(retCode)) {
        LNN_LOGE(LNN_EVENT, "write retCode failed");
        return SOFTBUS_NETWORK_WRITEINT32_FAILED;
    }
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    if (remote->SendRequest(CLIENT_ON_LEAVE_RESULT, data, reply, option) != 0) {
        LNN_LOGE(LNN_EVENT, "send request fail");
        return SOFTBUS_NETWORK_SEND_REQUEST_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t BusCenterClientProxy::OnLeaveMetaNodeResult(const char *networkId, int retCode)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return SOFTBUS_NETWORK_REMOTE_NULL;
    }
    if (networkId == nullptr) {
        LNN_LOGE(LNN_EVENT, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed!");
        return SOFTBUS_NETWORK_WRITETOKEN_FAILED;
    }
    if (!data.WriteCString(networkId)) {
        LNN_LOGE(LNN_EVENT, "write networkId failed");
        return SOFTBUS_NETWORK_WRITECSTRING_FAILED;
    }
    if (!data.WriteInt32(retCode)) {
        LNN_LOGE(LNN_EVENT, "write retCode failed");
        return SOFTBUS_NETWORK_WRITEINT32_FAILED;
    }
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    if (remote->SendRequest(CLIENT_ON_LEAVE_METANODE_RESULT, data, reply, option) != 0) {
        LNN_LOGE(LNN_EVENT, "send request fail");
        return SOFTBUS_NETWORK_SEND_REQUEST_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t BusCenterClientProxy::OnNodeOnlineStateChanged(const char *pkgName, bool isOnline,
    void *info, uint32_t infoTypeLen)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return SOFTBUS_NETWORK_REMOTE_NULL;
    }
    if (pkgName == nullptr) {
        LNN_LOGE(LNN_EVENT, "pkgName is nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    if (info == nullptr) {
        LNN_LOGE(LNN_EVENT, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed!");
        return SOFTBUS_NETWORK_WRITETOKEN_FAILED;
    }
    if (!data.WriteCString(pkgName)) {
        LNN_LOGE(LNN_EVENT, "write pkgName failed");
        return SOFTBUS_NETWORK_WRITECSTRING_FAILED;
    }
    if (!data.WriteBool(isOnline)) {
        LNN_LOGE(LNN_EVENT, "write online state failed");
        return SOFTBUS_NETWORK_WRITEBOOL_FAILED;
    }
    if (!data.WriteUint32(infoTypeLen)) {
        LNN_LOGE(LNN_EVENT, "write info type length failed");
        return SOFTBUS_NETWORK_WRITEINT32_FAILED;
    }
    if (!data.WriteRawData(info, infoTypeLen)) {
        LNN_LOGE(LNN_EVENT, "write node info failed");
        return SOFTBUS_NETWORK_WRITERAWDATA_FAILED;
    }
    MessageParcel reply;
    MessageOption option;
    int ret = remote->SendRequest(CLIENT_ON_NODE_ONLINE_STATE_CHANGED, data, reply, option);
    if (ret != 0) {
        LNN_LOGE(LNN_EVENT, "send request failed, ret=%{public}d", ret);
        return SOFTBUS_NETWORK_SEND_REQUEST_FAILED;
    }
    int32_t serverRet;
    if (!reply.ReadInt32(serverRet)) {
        LNN_LOGE(LNN_EVENT, "read serverRet failed");
        return SOFTBUS_NETWORK_READINT32_FAILED;
    }
    return serverRet;
}

int32_t BusCenterClientProxy::OnNodeBasicInfoChanged(const char *pkgName, void *info,
    uint32_t infoTypeLen, int32_t type)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return SOFTBUS_NETWORK_REMOTE_NULL;
    }
    if (pkgName == nullptr) {
        LNN_LOGE(LNN_EVENT, "pkgName is nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    if (info == nullptr) {
        LNN_LOGE(LNN_EVENT, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed!");
        return SOFTBUS_NETWORK_WRITETOKEN_FAILED;
    }
    if (!data.WriteCString(pkgName)) {
        LNN_LOGE(LNN_EVENT, "write pkgName failed");
        return SOFTBUS_NETWORK_WRITECSTRING_FAILED;
    }
    if (!data.WriteInt32(type)) {
        LNN_LOGE(LNN_EVENT, "write type failed");
        return SOFTBUS_NETWORK_WRITEINT32_FAILED;
    }
    if (!data.WriteUint32(infoTypeLen)) {
        LNN_LOGE(LNN_EVENT, "write info type length failed");
        return SOFTBUS_NETWORK_WRITEINT32_FAILED;
    }
    if (!data.WriteRawData(info, infoTypeLen)) {
        LNN_LOGE(LNN_EVENT, "write node info failed");
        return SOFTBUS_NETWORK_WRITERAWDATA_FAILED;
    }
    MessageParcel reply;
    MessageOption option;
    int ret = remote->SendRequest(CLIENT_ON_NODE_BASIC_INFO_CHANGED, data, reply, option);
    if (ret != 0) {
        LNN_LOGE(LNN_EVENT, "send request failed, ret=%{public}d", ret);
        return SOFTBUS_NETWORK_SEND_REQUEST_FAILED;
    }
    int32_t serverRet;
    if (!reply.ReadInt32(serverRet)) {
        LNN_LOGE(LNN_EVENT, "read serverRet failed");
        return SOFTBUS_NETWORK_READINT32_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t BusCenterClientProxy::OnNodeStatusChanged(const char *pkgName, void *info,
    uint32_t infoTypeLen, int32_t type)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return SOFTBUS_NETWORK_REMOTE_NULL;
    }
    if (pkgName == nullptr || info == nullptr) {
        LNN_LOGE(LNN_EVENT, "pkgName or info is nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed!");
        return SOFTBUS_NETWORK_WRITETOKEN_FAILED;
    }
    if (!data.WriteCString(pkgName)) {
        LNN_LOGE(LNN_EVENT, "write pkgName failed");
        return SOFTBUS_NETWORK_WRITECSTRING_FAILED;
    }
    if (!data.WriteInt32(type)) {
        LNN_LOGE(LNN_EVENT, "write type failed");
        return SOFTBUS_NETWORK_WRITEINT32_FAILED;
    }
    if (!data.WriteUint32(infoTypeLen)) {
        LNN_LOGE(LNN_EVENT, "write info type length failed");
        return SOFTBUS_NETWORK_WRITEINT32_FAILED;
    }
    if (!data.WriteRawData(info, infoTypeLen)) {
        LNN_LOGE(LNN_EVENT, "write node info failed");
        return SOFTBUS_NETWORK_WRITERAWDATA_FAILED;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(CLIENT_ON_NODE_STATUS_CHANGED, data, reply, option);
    if (ret != 0) {
        LNN_LOGE(LNN_EVENT, "send request failed, ret=%{public}d", ret);
        return SOFTBUS_NETWORK_SEND_REQUEST_FAILED;
    }
    int32_t serverRet;
    if (!reply.ReadInt32(serverRet)) {
        LNN_LOGE(LNN_EVENT, "read serverRet failed");
        return SOFTBUS_NETWORK_PROXY_READINT_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t BusCenterClientProxy::OnLocalNetworkIdChanged(const char *pkgName)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return SOFTBUS_NETWORK_REMOTE_NULL;
    }
    if (pkgName == nullptr) {
        LNN_LOGE(LNN_EVENT, "pkgName is nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        LNN_LOGE(LNN_EVENT, "write pkgName failed");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(CLIENT_ON_LOCAL_NETWORK_ID_CHANGED, data, reply, option);
    if (ret != 0) {
        LNN_LOGE(LNN_EVENT, "send request failed, ret=%{public}d", ret);
        return SOFTBUS_IPC_ERR;
    }
    int32_t serverRet;
    if (!reply.ReadInt32(serverRet)) {
        LNN_LOGE(LNN_EVENT, "read serverRet failed");
        return SOFTBUS_IPC_ERR;
    }
    return SOFTBUS_OK;
}

int32_t BusCenterClientProxy::OnNodeDeviceTrustedChange(const char *pkgName, int32_t type,
    const char *msg, uint32_t msgLen)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return SOFTBUS_NETWORK_REMOTE_NULL;
    }
    if (pkgName == nullptr|| msg == nullptr) {
        LNN_LOGE(LNN_EVENT, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(pkgName)) {
        LNN_LOGE(LNN_EVENT, "write pkgName failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteInt32(type)) {
        LNN_LOGE(LNN_EVENT, "write type failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(msg)) {
        LNN_LOGE(LNN_EVENT, "write msg failed");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteUint32(msgLen)) {
        LNN_LOGE(LNN_EVENT, "write msg length failed");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    if (remote->SendRequest(CLIENT_ON_NODE_DEVICE_TRUST_CHANGED, data, reply, option) != 0) {
        LNN_LOGE(LNN_EVENT, "send request failed");
        return SOFTBUS_IPC_ERR;
    }
    return SOFTBUS_OK;
}

int32_t BusCenterClientProxy::OnHichainProofException(
    const char *pkgName, const char *proofInfo, uint32_t proofLen, uint16_t deviceTypeId, int32_t errCode)
{
    if (pkgName == nullptr) {
        LNN_LOGE(LNN_EVENT, "invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return SOFTBUS_NETWORK_REMOTE_NULL;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed!");
        return SOFTBUS_NETWORK_WRITETOKEN_FAILED;
    }
    if (!data.WriteCString(pkgName)) {
        LNN_LOGE(LNN_EVENT, "write pkgName failed");
        return SOFTBUS_NETWORK_WRITECSTRING_FAILED;
    }
    if (!data.WriteUint32(proofLen)) {
        LNN_LOGE(LNN_EVENT, "write proofInfo length failed");
        return SOFTBUS_NETWORK_WRITEINT32_FAILED;
    }
    if (proofInfo != nullptr && proofLen != 0 && !data.WriteRawData(proofInfo, proofLen)) {
        LNN_LOGE(LNN_EVENT, "write proofInfo failed");
        return SOFTBUS_NETWORK_WRITERAWDATA_FAILED;
    }
    if (!data.WriteUint16(deviceTypeId)) {
        LNN_LOGE(LNN_EVENT, "write deviceTypeId failed");
        return SOFTBUS_NETWORK_WRITEINT16_FAILED;
    }
    if (!data.WriteInt32(errCode)) {
        LNN_LOGE(LNN_EVENT, "write errcode failed");
        return SOFTBUS_NETWORK_WRITEINT32_FAILED;
    }
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    if (remote->SendRequest(CLIENT_ON_HICHAIN_PROOF_EXCEPTION, data, reply, option) != 0) {
        LNN_LOGE(LNN_EVENT, "send request failed");
        return SOFTBUS_IPC_ERR;
    }
    return SOFTBUS_OK;
}

int32_t BusCenterClientProxy::OnTimeSyncResult(const void *info, uint32_t infoTypeLen, int32_t retCode)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return SOFTBUS_NETWORK_REMOTE_NULL;
    }
    if (info == nullptr) {
        LNN_LOGE(LNN_EVENT, "invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed!");
        return SOFTBUS_NETWORK_WRITETOKEN_FAILED;
    }
    if (!data.WriteUint32(infoTypeLen)) {
        LNN_LOGE(LNN_EVENT, "write info length failed");
        return SOFTBUS_NETWORK_WRITEINT32_FAILED;
    }
    if (!data.WriteRawData(info, infoTypeLen)) {
        LNN_LOGE(LNN_EVENT, "write info failed");
        return SOFTBUS_NETWORK_WRITERAWDATA_FAILED;
    }
    if (!data.WriteInt32(retCode)) {
        LNN_LOGE(LNN_EVENT, "write retCode failed");
        return SOFTBUS_NETWORK_WRITEINT32_FAILED;
    }
    MessageParcel reply;
    MessageOption option;
    int ret = remote->SendRequest(CLIENT_ON_TIME_SYNC_RESULT, data, reply, option);
    if (ret != 0) {
        LNN_LOGE(LNN_EVENT, "send request failed, ret=%{public}d", ret);
        return SOFTBUS_NETWORK_SEND_REQUEST_FAILED;
    }
    int32_t serverRet;
    if (!reply.ReadInt32(serverRet)) {
        LNN_LOGE(LNN_EVENT, "read serverRet failed");
        return SOFTBUS_NETWORK_READINT32_FAILED;
    }
    return SOFTBUS_OK;
}

void BusCenterClientProxy::OnPublishLNNResult(int32_t publishId, int32_t reason)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed!");
        return;
    }
    if (!data.WriteInt32(publishId)) {
        LNN_LOGE(LNN_EVENT, "write publishId failed");
        return;
    }
    if (!data.WriteInt32(reason)) {
        LNN_LOGE(LNN_EVENT, "write reason failed");
        return;
    }
    MessageParcel reply;
    MessageOption option;
    int ret = remote->SendRequest(CLIENT_ON_PUBLISH_LNN_RESULT, data, reply, option);
    if (ret != 0) {
        LNN_LOGE(LNN_EVENT, "send request failed, ret=%{public}d", ret);
    }
}

void BusCenterClientProxy::OnRefreshLNNResult(int32_t refreshId, int32_t reason)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed!");
        return;
    }
    if (!data.WriteInt32(refreshId)) {
        LNN_LOGE(LNN_EVENT, "write refreshId failed");
        return;
    }
    if (!data.WriteInt32(reason)) {
        LNN_LOGE(LNN_EVENT, "write reason failed");
        return;
    }
    MessageParcel reply;
    MessageOption option;
    int ret = remote->SendRequest(CLIENT_ON_REFRESH_LNN_RESULT, data, reply, option);
    if (ret != 0) {
        LNN_LOGE(LNN_EVENT, "send request failed, ret=%{public}d", ret);
    }
}

void BusCenterClientProxy::OnRefreshDeviceFound(const void *device, uint32_t deviceLen)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed!");
        return;
    }
    if (!data.WriteUint32(deviceLen)) {
        LNN_LOGE(LNN_EVENT, "write device length failed");
        return;
    }
    if (!data.WriteRawData(device, deviceLen)) {
        LNN_LOGE(LNN_EVENT, "write device failed");
        return;
    }
    MessageParcel reply;
    MessageOption option;
    int ret = remote->SendRequest(CLIENT_ON_REFRESH_DEVICE_FOUND, data, reply, option);
    if (ret != 0) {
        LNN_LOGE(LNN_EVENT, "send request failed, ret=%{public}d", ret);
    }
}

void BusCenterClientProxy::OnDataLevelChanged(const char *networkId, const DataLevelInfo *dataLevelInfo)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LNN_LOGE(LNN_EVENT, "remote is nullptr");
        return;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LNN_LOGE(LNN_EVENT, "write InterfaceToken failed");
        return;
    }
    if (!data.WriteCString(networkId)) {
        LNN_LOGE(LNN_EVENT, "write networkId failed");
        return;
    }
    if (!data.WriteRawData(dataLevelInfo, sizeof(DataLevelInfo))) {
        LNN_LOGE(LNN_EVENT, "write data level info failed");
        return;
    }

    MessageParcel reply;
    MessageOption option;
    int ret = remote->SendRequest(CLIENT_ON_DATA_LEVEL_CHANGED, data, reply, option);
    if (ret != 0) {
        LNN_LOGE(LNN_EVENT, "send request failed, ret=%{public}d", ret);
    }
}
} // namespace OHOS
