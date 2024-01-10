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
#include "disc_log.h"
#include "softbus_server_ipc_interface_code.h"

namespace OHOS {
DiscClientProxy::DiscClientProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<ISoftBusClient>(impl)
{
    DISC_LOGI(DISC_CONTROL, "construct");
}

DiscClientProxy::~DiscClientProxy()
{
    DISC_LOGI(DISC_CONTROL, "destroy");
}

void DiscClientProxy::OnDeviceFound(const DeviceInfo *deviceInfo)
{
    MessageParcel data;
    DISC_CHECK_AND_RETURN_LOGE(data.WriteInterfaceToken(GetDescriptor()), DISC_CONTROL, "write InterfaceToken failed");
    DISC_CHECK_AND_RETURN_LOGE(data.WriteBuffer(deviceInfo, sizeof(DeviceInfo)), DISC_CONTROL,
        "write device info failed");
    
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        DISC_LOGE(DISC_CONTROL, "remote is nullptr");
        return;
    }
    MessageParcel reply;
    MessageOption option { MessageOption::TF_ASYNC };
    DISC_CHECK_AND_RETURN_LOGE(remote->SendRequest(CLIENT_DISCOVERY_DEVICE_FOUND, data, reply, option) == SOFTBUS_OK,
        DISC_CONTROL, "send request failed");
}

void DiscClientProxy::OnDiscoverFailed(int subscribeId, int reason)
{
    MessageParcel data;
    DISC_CHECK_AND_RETURN_LOGE(data.WriteInterfaceToken(GetDescriptor()), DISC_CONTROL, "write InterfaceToken failed");
    DISC_CHECK_AND_RETURN_LOGE(data.WriteInt32(subscribeId), DISC_CONTROL, "write subscribe id failed");
    DISC_CHECK_AND_RETURN_LOGE(data.WriteInt32(reason), DISC_CONTROL, "write reason failed");

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        DISC_LOGE(DISC_LNN, "remote is nullptr");
        return;
    }
    MessageParcel reply;
    MessageOption option { MessageOption::TF_ASYNC };
    DISC_CHECK_AND_RETURN_LOGE(remote->SendRequest(CLIENT_DISCOVERY_FAIL, data, reply, option) == SOFTBUS_OK,
        DISC_CONTROL, "send request failed");
}

void DiscClientProxy::OnDiscoverySuccess(int subscribeId)
{
    MessageParcel data;
    DISC_CHECK_AND_RETURN_LOGE(data.WriteInterfaceToken(GetDescriptor()), DISC_CONTROL, "write InterfaceToken failed");
    DISC_CHECK_AND_RETURN_LOGE(data.WriteInt32(subscribeId), DISC_CONTROL, "write subscribe id failed");

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        DISC_LOGE(DISC_LNN, "remote is nullptr");
        return;
    }
    MessageParcel reply;
    MessageOption option { MessageOption::TF_ASYNC };
    DISC_CHECK_AND_RETURN_LOGE(remote->SendRequest(CLIENT_DISCOVERY_SUCC, data, reply, option) == SOFTBUS_OK,
        DISC_CONTROL, "send request failed");
}

void DiscClientProxy::OnPublishSuccess(int publishId)
{
    MessageParcel data;
    DISC_CHECK_AND_RETURN_LOGE(data.WriteInterfaceToken(GetDescriptor()), DISC_CONTROL, "write InterfaceToken failed");
    DISC_CHECK_AND_RETURN_LOGE(data.WriteInt32(publishId), DISC_CONTROL, "write publish id failed");

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        DISC_LOGE(DISC_LNN, "remote is nullptr");
        return;
    }
    MessageParcel reply;
    MessageOption option { MessageOption::TF_ASYNC };
    DISC_CHECK_AND_RETURN_LOGE(remote->SendRequest(CLIENT_PUBLISH_SUCC, data, reply, option) == 0,
        DISC_CONTROL, "send request failed");
}

void DiscClientProxy::OnPublishFail(int publishId, int reason)
{
    MessageParcel data;
    DISC_CHECK_AND_RETURN_LOGE(data.WriteInterfaceToken(GetDescriptor()), DISC_CONTROL, "write InterfaceToken failed");
    DISC_CHECK_AND_RETURN_LOGE(data.WriteInt32(publishId), DISC_CONTROL, "write publish id failed");
    DISC_CHECK_AND_RETURN_LOGE(data.WriteInt32(reason), DISC_CONTROL, "write reason failed");

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        DISC_LOGE(DISC_LNN, "remote is nullptr");
        return;
    }
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    DISC_CHECK_AND_RETURN_LOGE(remote->SendRequest(CLIENT_PUBLISH_FAIL, data, reply, option) == SOFTBUS_OK,
        DISC_CONTROL, "send request failed");
}
}