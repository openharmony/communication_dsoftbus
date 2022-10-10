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

#include "bus_center_client_proxy_standard.h"

#include "message_parcel.h"
#include "softbus_errcode.h"
#include "softbus_ipc_def.h"
#include "softbus_log.h"

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

int32_t BusCenterClientProxy::OnChannelClosed(int32_t channelId, int32_t channelType)
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

void BusCenterClientProxy::OnDeviceFound(const DeviceInfo *deviceInfo)
{
}

void BusCenterClientProxy::OnDiscoverFailed(int subscribeId, int failReason)
{
}

void BusCenterClientProxy::OnDiscoverySuccess(int subscribeId)
{
}

void BusCenterClientProxy::OnPublishSuccess(int publishId)
{
}

void BusCenterClientProxy::OnPublishFail(int publishId, int reason)
{
}

int32_t BusCenterClientProxy::OnJoinLNNResult(void *addr, uint32_t addrTypeLen, const char *networkId, int retCode)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr");
        return SOFTBUS_ERR;
    }
    if (addr == nullptr || (retCode == 0 && networkId == nullptr)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write InterfaceToken failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteUint32(addrTypeLen)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write addr type length failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteRawData(addr, addrTypeLen)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write addr failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(retCode)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write retCode failed");
        return SOFTBUS_ERR;
    }
    if (retCode == 0 && !data.WriteCString(networkId)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write networkId failed");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    if (remote->SendRequest(CLIENT_ON_JOIN_RESULT, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OnJoinLNNResult send request failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t BusCenterClientProxy::OnJoinMetaNodeResult(void *addr, uint32_t addrTypeLen, const char *networkId, int retCode)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr");
        return SOFTBUS_ERR;
    }
    if ((retCode == 0 && networkId == nullptr) || addr == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write InterfaceToken failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteUint32(addrTypeLen)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write addr type length failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteRawData(addr, addrTypeLen)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write addr failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(retCode)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write retCode failed");
        return SOFTBUS_ERR;
    }
    if (retCode == 0 && !data.WriteCString(networkId)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write networkId failed");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    if (remote->SendRequest(CLIENT_ON_JOIN_METANODE_RESULT, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OnJoinMetaNodeResult send request failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t BusCenterClientProxy::OnLeaveLNNResult(const char *networkId, int retCode)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr");
        return SOFTBUS_ERR;
    }
    if (networkId == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write InterfaceToken failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(networkId)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write networkId failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(retCode)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write retCode failed");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    if (remote->SendRequest(CLIENT_ON_LEAVE_RESULT, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OnLeaveLNNResult send request failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t BusCenterClientProxy::OnLeaveMetaNodeResult(const char *networkId, int retCode)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr");
        return SOFTBUS_ERR;
    }
    if (networkId == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write InterfaceToken failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(networkId)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write networkId failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(retCode)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write retCode failed");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    if (remote->SendRequest(CLIENT_ON_LEAVE_METANODE_RESULT, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OnLeaveMetaNodeResult send request failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t BusCenterClientProxy::OnNodeOnlineStateChanged(bool isOnline, void *info, uint32_t infoTypeLen)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr");
        return SOFTBUS_ERR;
    }
    if (info == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write InterfaceToken failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteBool(isOnline)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write online state failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteUint32(infoTypeLen)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write info type length failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteRawData(info, infoTypeLen)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write node info failed");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(CLIENT_ON_NODE_ONLINE_STATE_CHANGED, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OnNodeOnlineStateChanged send request failed");
        return SOFTBUS_ERR;
    }
    int32_t serverRet;
    if (!reply.ReadInt32(serverRet)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OnNodeOnlineStateChanged read serverRet failed");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t BusCenterClientProxy::OnNodeBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr");
        return SOFTBUS_ERR;
    }
    if (info == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_ERR;
    }
    MessageParcel data;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "OnNodeBasicInfoChanged type: %d", type);
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write InterfaceToken failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(type)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write type failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteUint32(infoTypeLen)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write info type length failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteRawData(info, infoTypeLen)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write node info failed");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(CLIENT_ON_NODE_BASIC_INFO_CHANGED, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OnNodeBasicInfoChanged send request failed");
        return SOFTBUS_ERR;
    }
    int32_t serverRet;
    if (!reply.ReadInt32(serverRet)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OnNodeBasicInfoChanged read serverRet failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t BusCenterClientProxy::OnTimeSyncResult(const void *info, uint32_t infoTypeLen, int32_t retCode)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr");
        return SOFTBUS_ERR;
    }
    if (info == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write InterfaceToken failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteUint32(infoTypeLen)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write info length failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteRawData(info, infoTypeLen)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write info failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(retCode)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write retCode failed");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(CLIENT_ON_TIME_SYNC_RESULT, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OnTimeSyncResult send request failed");
        return SOFTBUS_ERR;
    }
    int32_t serverRet;
    if (!reply.ReadInt32(serverRet)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OnTimeSyncResult read serverRet failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void BusCenterClientProxy::OnPublishLNNResult(int32_t publishId, int32_t reason)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr");
        return;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write InterfaceToken failed!");
        return;
    }
    if (!data.WriteInt32(publishId)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write publishId failed");
        return;
    }
    if (!data.WriteInt32(reason)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write reason failed");
        return;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(CLIENT_ON_PUBLISH_LNN_RESULT, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OnPublishLNNResult send request failed");
    }
}

void BusCenterClientProxy::OnRefreshLNNResult(int32_t refreshId, int32_t reason)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr");
        return;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write InterfaceToken failed!");
        return;
    }
    if (!data.WriteInt32(refreshId)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write refreshId failed");
        return;
    }
    if (!data.WriteInt32(reason)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write reason failed");
        return;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(CLIENT_ON_REFRESH_LNN_RESULT, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OnRefreshLNNResult send request failed");
    }
}

void BusCenterClientProxy::OnRefreshDeviceFound(const void *device, uint32_t deviceLen)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr");
        return;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write InterfaceToken failed!");
        return;
    }
    if (!data.WriteUint32(deviceLen)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write device length failed");
        return;
    }
    if (!data.WriteRawData(device, deviceLen)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "write device failed");
        return;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(CLIENT_ON_REFRESH_DEVICE_FOUND, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OnRefreshDeviceFound send request failed");
    }
}
} // namespace OHOS