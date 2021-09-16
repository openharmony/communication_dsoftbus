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

int32_t BusCenterClientProxy::OnChannelOpenFailed(int32_t channelId, int32_t channelType)
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
        LOG_ERR("remote is nullptr");
        return SOFTBUS_ERR;
    }
    if (addr == nullptr || (retCode == 0 && networkId == nullptr)) {
        LOG_ERR("invalid parameters");
        return SOFTBUS_ERR;
    }
    MessageParcel data;
    if (!data.WriteUint32(addrTypeLen)) {
        LOG_ERR("write addr type length failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteRawData(addr, addrTypeLen)) {
        LOG_ERR("write addr failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(retCode)) {
        LOG_ERR("write retCode failed");
        return SOFTBUS_ERR;
    }
    if (retCode == 0 && !data.WriteCString(networkId)) {
        LOG_ERR("write networkId failed");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(CLIENT_ON_JOIN_RESULT, data, reply, option) != 0) {
        LOG_ERR("OnJoinLNNResult send request failed");
        return SOFTBUS_ERR;
    }
    int32_t serverRet;
    if (!reply.ReadInt32(serverRet)) {
        LOG_ERR("SoftbusLeaveLNN read serverRet failed");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t BusCenterClientProxy::OnLeaveLNNResult(const char *networkId, int retCode)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr");
        return SOFTBUS_ERR;
    }
    if (networkId == nullptr) {
        LOG_ERR("invalid parameters");
        return SOFTBUS_ERR;
    }
    MessageParcel data;
    if (!data.WriteCString(networkId)) {
        LOG_ERR("write networkId failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(retCode)) {
        LOG_ERR("write retCode failed");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(CLIENT_ON_LEAVE_RESULT, data, reply, option) != 0) {
        LOG_ERR("OnLeaveLNNResult send request failed");
        return SOFTBUS_ERR;
    }
    int32_t serverRet;
    if (!reply.ReadInt32(serverRet)) {
        LOG_ERR("OnLeaveLNNResult read serverRet failed");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t BusCenterClientProxy::OnNodeOnlineStateChanged(bool isOnline, void *info, uint32_t infoTypeLen)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr");
        return SOFTBUS_ERR;
    }
    if (info == nullptr) {
        LOG_ERR("invalid parameters");
        return SOFTBUS_ERR;
    }
    MessageParcel data;
    if (!data.WriteBool(isOnline)) {
        LOG_ERR("write online state failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteUint32(infoTypeLen)) {
        LOG_ERR("write info type length failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteRawData(info, infoTypeLen)) {
        LOG_ERR("write node info failed");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(CLIENT_ON_NODE_ONLINE_STATE_CHANGED, data, reply, option) != 0) {
        LOG_ERR("OnNodeOnlineStateChanged send request failed");
        return SOFTBUS_ERR;
    }
    int32_t serverRet;
    if (!reply.ReadInt32(serverRet)) {
        LOG_ERR("OnNodeOnlineStateChanged read serverRet failed");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t BusCenterClientProxy::OnNodeBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr");
        return SOFTBUS_ERR;
    }
    if (info == nullptr) {
        LOG_ERR("invalid parameters");
        return SOFTBUS_ERR;
    }
    MessageParcel data;
    LOG_ERR("OnNodeBasicInfoChanged type: %d", type);
    if (!data.WriteInt32(type)) {
        LOG_ERR("write type failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteUint32(infoTypeLen)) {
        LOG_ERR("write info type length failed");
        return SOFTBUS_ERR;
    }
    if (!data.WriteRawData(info, infoTypeLen)) {
        LOG_ERR("write node info failed");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(CLIENT_ON_NODE_BASIC_INFO_CHANGED, data, reply, option) != 0) {
        LOG_ERR("OnNodeBasicInfoChanged send request failed");
        return SOFTBUS_ERR;
    }
    int32_t serverRet;
    if (!reply.ReadInt32(serverRet)) {
        LOG_ERR("OnNodeBasicInfoChanged read serverRet failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}
} // namespace OHOS