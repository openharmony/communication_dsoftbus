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
#include "softbus_server_ipc_interface_code.h"
#include "softbus_log.h"

namespace OHOS {
DiscClientProxy::DiscClientProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<ISoftBusClient>(impl)
{
    DLOGI("construct");
}

DiscClientProxy::~DiscClientProxy()
{
    DLOGI("destroy");
}

void DiscClientProxy::OnDeviceFound(const DeviceInfo *deviceInfo)
{
    MessageParcel data;
    DISC_CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write InterfaceToken failed");
    DISC_CHECK_AND_RETURN_LOG(data.WriteBuffer(deviceInfo, sizeof(DeviceInfo)), "write device info failed");
    
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr");
        return;
    }
    MessageParcel reply;
    MessageOption option { MessageOption::TF_ASYNC };
    DISC_CHECK_AND_RETURN_LOG(remote->SendRequest(CLIENT_DISCOVERY_DEVICE_FOUND, data, reply, option) == ERR_OK,
                              "send request failed");
}

void DiscClientProxy::OnDiscoverFailed(int subscribeId, int reason)
{
    MessageParcel data;
    DISC_CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write InterfaceToken failed");
    DISC_CHECK_AND_RETURN_LOG(data.WriteInt32(subscribeId), "write subscribe id failed");
    DISC_CHECK_AND_RETURN_LOG(data.WriteInt32(reason), "write reason failed");

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr");
        return;
    }
    MessageParcel reply;
    MessageOption option { MessageOption::TF_ASYNC };
    DISC_CHECK_AND_RETURN_LOG(remote->SendRequest(CLIENT_DISCOVERY_FAIL, data, reply, option) == ERR_OK,
                              "send request failed");
}

void DiscClientProxy::OnDiscoverySuccess(int subscribeId)
{
    MessageParcel data;
    DISC_CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write InterfaceToken failed");
    DISC_CHECK_AND_RETURN_LOG(data.WriteInt32(subscribeId), "write subscribe id failed");

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr");
        return;
    }
    MessageParcel reply;
    MessageOption option { MessageOption::TF_ASYNC };
    DISC_CHECK_AND_RETURN_LOG(remote->SendRequest(CLIENT_DISCOVERY_SUCC, data, reply, option) == ERR_OK,
                              "send request failed");
}

void DiscClientProxy::OnPublishSuccess(int publishId)
{
    MessageParcel data;
    DISC_CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write InterfaceToken failed");
    DISC_CHECK_AND_RETURN_LOG(data.WriteInt32(publishId), "write publish id failed");

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr");
        return;
    }
    MessageParcel reply;
    MessageOption option { MessageOption::TF_ASYNC };
    DISC_CHECK_AND_RETURN_LOG(remote->SendRequest(CLIENT_PUBLISH_SUCC, data, reply, option) == ERR_OK,
                              "send request failed");
}

void DiscClientProxy::OnPublishFail(int publishId, int reason)
{
    MessageParcel data;
    DISC_CHECK_AND_RETURN_LOG(data.WriteInterfaceToken(GetDescriptor()), "write InterfaceToken failed");
    DISC_CHECK_AND_RETURN_LOG(data.WriteInt32(publishId), "write publish id failed");
    DISC_CHECK_AND_RETURN_LOG(data.WriteInt32(reason), "write reason failed");

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr");
        return;
    }
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    DISC_CHECK_AND_RETURN_LOG(remote->SendRequest(CLIENT_PUBLISH_FAIL, data, reply, option) == ERR_OK,
                              "send request failed");
}
}