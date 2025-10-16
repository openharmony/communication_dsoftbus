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

#include "general_connection_server_proxy.h"

#include <mutex>
#include "conn_log.h"
#include "general_connection_server_proxy_standard.h"
#include "ipc_skeleton.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "softbus_error_code.h"
#include "softbus_server_ipc_interface_code.h"

using namespace OHOS;
namespace {
sptr<ConnectionServerProxy> g_serverProxy = nullptr;
uint32_t g_getSystemAbilityId = 2;
const std::u16string SAMANAGER_INTERFACE_TOKEN = u"ohos.samgr.accessToken";
std::mutex g_mutex;
} // namespace

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
        CONN_LOGE(CONN_COMMON, "get samgr fail");
        return nullptr;
    }
    int32_t err = samgr->SendRequest(g_getSystemAbilityId, data, reply, option);
    if (err != 0) {
        CONN_LOGE(CONN_COMMON, "get GetSystemAbility fail, err=%{public}d", err);
        return nullptr;
    }
    return reply.ReadRemoteObject();
}

int32_t ConnectionServerProxyInit(void)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_serverProxy != nullptr) {
        CONN_LOGI(CONN_INIT, "Init succ");
        return SOFTBUS_OK;
    }
    sptr<IRemoteObject> object = GetSystemAbility();
    if (object == nullptr) {
        CONN_LOGE(CONN_INIT, "Get remote softbus object fail");
        return SOFTBUS_SERVER_NOT_INIT;
    }
    g_serverProxy = new (std::nothrow) ConnectionServerProxy(object);
    if (g_serverProxy == nullptr) {
        CONN_LOGE(CONN_INIT, "Create connection server proxy fail");
        return SOFTBUS_SERVER_NOT_INIT;
    }
    return SOFTBUS_OK;
}

void ConnectionServerProxyDeInit(void)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_serverProxy == nullptr) {
        CONN_LOGE(CONN_INIT, "g_serverProxy is null");
        return;
    }
    g_serverProxy.clear();
}

int32_t ServerIpcCreateServer(const char *pkgName, const char *name)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(
        g_serverProxy != nullptr, SOFTBUS_NO_INIT, CONN_COMMON, "softbus server g_serverProxy is null");

    return g_serverProxy->CreateServer(pkgName, name);
}

int32_t ServerIpcRemoveServer(const char *pkgName, const char *name)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(
        g_serverProxy != nullptr, SOFTBUS_NO_INIT, CONN_COMMON, "softbus server g_serverProxy is null");

    return g_serverProxy->RemoveServer(pkgName, name);
}

int32_t ServerIpcConnect(const char *pkgName, const char *name, const Address *address)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(
        g_serverProxy != nullptr, SOFTBUS_NO_INIT, CONN_COMMON, "softbus server g_serverProxy is null");

    return g_serverProxy->Connect(pkgName, name, address);
}

int32_t ServerIpcDisconnect(uint32_t handle)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(
        g_serverProxy != nullptr, SOFTBUS_NO_INIT, CONN_COMMON, "softbus server g_serverProxy is null");

    return g_serverProxy->Disconnect(handle);
}

int32_t ServerIpcSend(uint32_t handle, const uint8_t *data, uint32_t len)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(
        g_serverProxy != nullptr, SOFTBUS_NO_INIT, CONN_COMMON, "softbus server g_serverProxy is null");

    return g_serverProxy->Send(handle, data, len);
}

int32_t ServerIpcGetPeerDeviceId(uint32_t handle, char *deviceId, uint32_t len)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(
        g_serverProxy != nullptr, SOFTBUS_NO_INIT, CONN_COMMON, "softbus server g_serverProxy is null");

    return g_serverProxy->ConnGetPeerDeviceId(handle, deviceId, len);
}