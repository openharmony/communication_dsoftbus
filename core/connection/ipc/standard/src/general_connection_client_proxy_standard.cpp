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

#include "general_connection_client_proxy_standard.h"

#include "conn_log.h"
#include "message_parcel.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_server_ipc_interface_code.h"

namespace OHOS {
int32_t ConnectionClientProxy::OnConnectionStateChange(uint32_t handle, int32_t state, int32_t reason)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        CONN_LOGE(CONN_COMMON, "remote is nullptr");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        CONN_LOGE(CONN_COMMON, "write InterfaceToken failed.");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteUint32(handle)) {
        CONN_LOGE(CONN_COMMON, "write handle failed.");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteInt32(state)) {
        CONN_LOGE(CONN_COMMON, "write state failed.");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteInt32(reason)) {
        CONN_LOGE(CONN_COMMON, "write reason failed.");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    int32_t ret = remote->SendRequest(CLIENT_GENERAL_CONNECTION_STATE_CHANGE, data, reply, option);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "OnConnectionStateChange send request failed, ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ConnectionClientProxy::OnAcceptConnect(const char *name, uint32_t handle)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        CONN_LOGE(CONN_COMMON, "remote is nullptr");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        CONN_LOGE(CONN_COMMON, "write InterfaceToken failed.");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteCString(name)) {
        CONN_LOGE(CONN_COMMON, "write name failed.");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.WriteUint32(handle)) {
        CONN_LOGE(CONN_COMMON, "write handle failed.");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    int32_t ret = remote->SendRequest(CLIENT_GENERAL_ACCEPT_CONNECT, data, reply, option);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "OnAcceptConnect send request failed, ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ConnectionClientProxy::OnDataReceived(uint32_t handle, const uint8_t *data, uint32_t len)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        CONN_LOGE(CONN_COMMON, "remote is nullptr");
        return SOFTBUS_IPC_ERR;
    }
    MessageParcel dataParcel;
    if (!dataParcel.WriteInterfaceToken(GetDescriptor())) {
        CONN_LOGE(CONN_COMMON, "write InterfaceToken failed.");
        return SOFTBUS_IPC_ERR;
    }
    if (!dataParcel.WriteUint32(handle)) {
        CONN_LOGE(CONN_COMMON, "write handle failed.");
        return SOFTBUS_IPC_ERR;
    }
    if (!dataParcel.WriteUint32(len)) {
        CONN_LOGE(CONN_COMMON, "write len failed.");
        return SOFTBUS_IPC_ERR;
    }
    if (!dataParcel.WriteBuffer(data, len)) {
        CONN_LOGE(CONN_COMMON, "write data failed.");
        return SOFTBUS_IPC_ERR;
    }

    MessageParcel replyParcel;
    MessageOption option = { MessageOption::TF_ASYNC };
    int32_t ret = remote->SendRequest(CLIENT_GENERAL_DATA_RECEIVED, dataParcel, replyParcel, option);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "OnDataReceived send request failed, ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}
} // namespace OHOS