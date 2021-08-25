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

#include "disc_client_proxy_standard.h"

#include "discovery_service.h"
#include "message_parcel.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_ipc_def.h"
#include "softbus_log.h"

namespace OHOS {
int32_t DiscClientProxy::OnChannelOpened(const char *sessionName, const ChannelInfo *info)
{
    return SOFTBUS_OK;
}

int32_t DiscClientProxy::OnChannelOpenFailed(int32_t channelId, int32_t channelType)
{
    return SOFTBUS_OK;
}

int32_t DiscClientProxy::OnChannelClosed(int32_t channelId, int32_t channelType)
{
    return SOFTBUS_OK;
}

int32_t DiscClientProxy::OnChannelMsgReceived(int32_t channelId, int32_t channelType, const void *dataInfo,
    uint32_t len, int32_t type)
{
    return SOFTBUS_OK;
}

void DiscClientProxy::OnDeviceFound(const DeviceInfo *deviceInfo)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "remote is nullptr");
        return;
    }

    MessageParcel data;
    data.WriteBuffer(deviceInfo, sizeof(DeviceInfo));

    MessageParcel reply;
    MessageOption option;
    int32_t err = remote->SendRequest(CLIENT_DISCOVERY_DEVICE_FOUND, data, reply, option);
    if (err != 0) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "OnDeviceFound send request failed");
        return;
    }
}

void DiscClientProxy::OnDiscoverFailed(int subscribeId, int failReason)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "remote is nullptr");
        return;
    }

    MessageParcel data;
    data.WriteInt32(subscribeId);
    data.WriteInt32(failReason);

    MessageParcel reply;
    MessageOption option;
    int32_t err = remote->SendRequest(CLIENT_DISCOVERY_FAIL, data, reply, option);
    if (err != 0) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "OnDiscoverFailed send request failed");
        return;
    }
}

void DiscClientProxy::OnDiscoverySuccess(int subscribeId)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "remote is nullptr");
        return;
    }

    MessageParcel data;
    data.WriteInt32(subscribeId);

    MessageParcel reply;
    MessageOption option;
    int32_t err = remote->SendRequest(CLIENT_DISCOVERY_SUCC, data, reply, option);
    if (err != 0) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "OnDiscoverySuccess send request failed");
        return;
    }
}

void DiscClientProxy::OnPublishSuccess(int publishId)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "remote is nullptr");
        return;
    }

    MessageParcel data;
    data.WriteInt32(publishId);

    MessageParcel reply;
    MessageOption option;
    int32_t err = remote->SendRequest(CLIENT_PUBLISH_SUCC, data, reply, option);
    if (err != 0) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "OnPublishSuccess send request failed");
        return;
    }
}

void DiscClientProxy::OnPublishFail(int publishId, int reason)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "remote is nullptr");
        return;
    }

    MessageParcel data;
    data.WriteInt32(publishId);
    data.WriteInt32(reason);

    MessageParcel reply;
    MessageOption option;
    int32_t err = remote->SendRequest(CLIENT_PUBLISH_FAIL, data, reply, option);
    if (err != 0) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "OnPublishFail send request failed");
        return;
    }
}

int32_t DiscClientProxy::OnJoinLNNResult(void *addr, uint32_t addrTypeLen, const char *networkId, int retCode)
{
    return SOFTBUS_OK;
}

int32_t DiscClientProxy::OnLeaveLNNResult(const char *networkId, int retCode)
{
    return SOFTBUS_OK;
}

int32_t DiscClientProxy::OnNodeOnlineStateChanged(bool isOnline, void *info, uint32_t infoTypeLen)
{
    return SOFTBUS_OK;
}

int32_t DiscClientProxy::OnNodeBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type)
{
    return SOFTBUS_OK;
}

int32_t DiscClientProxy::OnTimeSyncResult(const void *info, uint32_t infoTypeLen, int32_t retCode)
{
    return SOFTBUS_OK;
}
} // namespace OHOS