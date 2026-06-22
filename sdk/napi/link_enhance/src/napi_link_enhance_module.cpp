/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include <map>
#include <string>

#include "conn_log.h"
#include "napi_link_enhance_error_code.h"
#include "napi_link_enhance_connection.h"
#include "napi_link_enhance_server.h"
#include "napi_link_enhance_utils.h"
#include "napi_link_enhance_object.h"
#include "softbus_adapter_mem.h"
#include "softbus_connection.h"
#include "softbus_utils.h"

namespace Communication {
namespace OHOS::Softbus {

EXTERN_C_START

static NapiLinkEnhanceConnection *FindConnectionByHandle(uint32_t handle)
{
    for (auto iter = NapiLinkEnhanceConnection::connectionList_.begin();
        iter != NapiLinkEnhanceConnection::connectionList_.end(); ++iter) {
        if ((*iter)->handle_ == handle) {
            return *iter;
        }
    }
    return nullptr;
}

static NapiLinkEnhanceServer *FindServerByName(const std::string &serverName)
{
    auto iter = NapiLinkEnhanceServer::enhanceServerMap_.find(serverName);
    if (iter != NapiLinkEnhanceServer::enhanceServerMap_.end() && iter->second != nullptr) {
        return iter->second;
    }
    return nullptr;
}

static void EraseConnectionFromList(NapiLinkEnhanceConnection *conn)
{
    std::lock_guard<std::mutex> guard(NapiLinkEnhanceConnection::connectionListMutex_);
    for (auto it = NapiLinkEnhanceConnection::connectionList_.begin();
        it != NapiLinkEnhanceConnection::connectionList_.end(); ++it) {
        if (*it == conn) {
            NapiLinkEnhanceConnection::connectionList_.erase(it);
            break;
        }
    }
}

static void EraseServerFromMap(const std::string &serverName)
{
    std::lock_guard<std::mutex> guard(NapiLinkEnhanceServer::serverMapMutex_);
    NapiLinkEnhanceServer::enhanceServerMap_.erase(serverName);
}

static int32_t OnAcceptConnectAdapter(const char *name, uint32_t handle)
{
    COMM_CHECK_AND_RETURN_RET_LOGE(name != nullptr, SOFTBUS_INVALID_PARAM, COMM_SDK, "name is nullptr");
    COMM_LOGI(COMM_SDK, "accept new conn, handle=%{public}u", handle);
    std::string serverName = name;
    std::string deviceId = "";
    std::lock_guard<std::mutex> guard(NapiLinkEnhanceServer::serverMapMutex_);
    NapiLinkEnhanceServer *enhanceServer = FindServerByName(serverName);
    if (enhanceServer == nullptr || enhanceServer->env_ == nullptr) {
        COMM_LOGE(COMM_SDK, "server status err, name=%{public}s", name);
        return LINK_ENHANCE_PARAMETER_INVALID;
    }
    napi_env env = enhanceServer->env_;
    uint32_t inHandle = handle;
    auto func = [serverName, deviceId, inHandle]() {
        NapiLinkEnhanceServer *enhanceServer = FindServerByName(serverName);
        if (enhanceServer == nullptr || !enhanceServer->IsAcceptedEnable()) {
            COMM_LOGE(COMM_SDK, "server not found or accept not enable, name=%{public}s", serverName.c_str());
            return;
        }
        napi_value argvOut[ARGS_SIZE_ONE] = { nullptr };
        size_t argc = ARGS_SIZE_THREE;
        napi_value nHandle = nullptr;
        napi_status status = napi_create_uint32(enhanceServer->env_, inHandle, &nHandle);
        if (status != napi_ok) {
            return;
        }

        napi_value argv[ARGS_SIZE_THREE] = { nullptr };
        argv[PARAM0] = NapiGetStringRet(enhanceServer->env_, deviceId),
        argv[PARAM1] = NapiGetStringRet(enhanceServer->env_, serverName),
        argv[PARAM2] = nHandle;

        napi_value constructor = nullptr;
        if (napi_get_reference_value(enhanceServer->env_,
            NapiLinkEnhanceConnection::consRef_, &constructor) != napi_ok) {
            COMM_LOGE(COMM_SDK, "get conn constructor fail");
            return;
        }
        if (napi_new_instance(enhanceServer->env_, constructor, argc, argv, &argvOut[ARGS_SIZE_ZERO]) != napi_ok) {
            COMM_LOGE(COMM_SDK, "create js new conn object fail");
            return;
        }
        NapiCallFunction(enhanceServer->env_, enhanceServer->acceptConnectRef_, argvOut, ARGS_SIZE_ONE);
    };
    return DoInJsMainThread(env, std::move(func));
}

static int32_t NotifyDisconnected(NapiLinkEnhanceConnection *connection, int32_t reason)
{
    COMM_LOGI(COMM_SDK, "disconnected, handle=%{public}u, reason=%{public}d", connection->handle_, reason);
    uint32_t handle = connection->handle_;
    napi_env env = connection->env_;
    auto func = [handle, reason]() {
        NapiLinkEnhanceConnection *conn = FindConnectionByHandle(handle);
        if (conn == nullptr || !conn->IsDisconnectEnable()) {
            COMM_LOGE(COMM_SDK, "conn not found or disconnect not enable, handle=%{public}u", handle);
            return;
        }
        napi_value disconnectReason = NapiGetInt32Ret(conn->env_, reason);
        napi_value argv[ARGS_SIZE_ONE] = { nullptr };
        argv[ARGS_SIZE_ZERO] = disconnectReason;
        NapiCallFunction(conn->env_, conn->disconnectRef_, argv, ARGS_SIZE_ONE);
        EraseConnectionFromList(conn);
    };
    return DoInJsMainThread(env, std::move(func));
}

static int32_t NotifyConnectResult(NapiLinkEnhanceConnection *connection, bool success, int32_t reason, bool isClear)
{
    COMM_LOGI(COMM_SDK, "find conn object, handle=%{public}u, success=%{public}d, isClear=%{public}d",
        connection->handle_, success, isClear);
    connection->state_ = success ? ConnectionState::STATE_CONNECTED : ConnectionState::STATE_DISCONNECTED;
    int32_t napiReason = reason;
    if (napiReason != 0) {
        napiReason = ConvertToJsErrcode(reason);
    }
    uint32_t handle = connection->handle_;
    napi_env env = connection->env_;
    auto func = [handle, success, napiReason, isClear]() {
        NapiLinkEnhanceConnection *conn = FindConnectionByHandle(handle);
        if (conn == nullptr || !conn->IsConnectResultEnable()) {
            COMM_LOGE(COMM_SDK, "conn not found or connect result not enable, handle=%{public}u", handle);
            return;
        }
        auto changeState = std::make_shared<NapiConnectionChangeState>(conn->deviceId_,
            success, napiReason);
        napi_value argv[ARGS_SIZE_ONE] = { nullptr };
        argv[ARGS_SIZE_ZERO] = changeState->ToNapiValue(conn->env_);
        NapiCallFunction(conn->env_, conn->connectResultRef_, argv, ARGS_SIZE_ONE);
        if (!success || isClear) {
            COMM_LOGI(COMM_SDK, "erase conn in js thread, handle=%{public}u", handle);
            EraseConnectionFromList(conn);
        }
    };
    return DoInJsMainThread(env, std::move(func));
}

static int32_t NotifyConnectionStateChange(NapiLinkEnhanceConnection *connection, int32_t status, int32_t reason,
    bool isClear)
{
    if (connection->state_ == ConnectionState::STATE_CONNECTING) {
        bool success = (status == CONNECTION_STATE_CONNECTED_SUCCESS);
        return NotifyConnectResult(connection, success, reason, isClear);
    }
    if (status == CONNECTION_STATE_DISCONNECTED) {
        return NotifyDisconnected(connection, reason);
    }
    return LINK_ENHANCE_PARAMETER_INVALID;
}

static int32_t OnConnectionStateChangeAdapter(uint32_t handle, int32_t status, int32_t reason)
{
    COMM_LOGI(COMM_SDK, "conn state change, handle=%{public}u, state=%{public}d, reason=%{public}d", handle,
        status, reason);
    std::lock_guard<std::mutex> guard(NapiLinkEnhanceConnection::connectionListMutex_);
    int32_t ret = LINK_ENHANCE_PARAMETER_INVALID;
    bool isClear = (handle == 0);
    for (auto iter = NapiLinkEnhanceConnection::connectionList_.begin();
        iter != NapiLinkEnhanceConnection::connectionList_.end(); ++iter) {
        NapiLinkEnhanceConnection *connection = *iter;
        if (isClear) {
            ret = NotifyConnectionStateChange(connection, status, reason, isClear);
            continue;
        }
        if (connection->handle_ == handle) {
            ret = NotifyConnectionStateChange(connection, status, reason, isClear);
            return ret;
        }
    }
    return ret;
}

static void NotifyDataReceived(NapiLinkEnhanceConnection *connection, const uint8_t *data, uint32_t len)
{
    auto outData = std::shared_ptr<uint8_t>(new uint8_t[len], std::default_delete<uint8_t[]>());
    if (outData == nullptr || memcpy_s(outData.get(), len, data, len) != EOK) {
        return;
    }
    uint32_t handle = connection->handle_;
    napi_env env = connection->env_;
    auto func = [handle, outData, len]() {
        NapiLinkEnhanceConnection *conn = FindConnectionByHandle(handle);
        if (conn == nullptr || !conn->IsDataReceiveEnable()) {
            COMM_LOGE(COMM_SDK, "conn not found or data receive not enable, handle=%{public}u", handle);
            return;
        }
        napi_value arrayBuffer = nullptr;
        void *dataBuffer = nullptr;
        int32_t status = napi_create_arraybuffer(conn->env_, len, &dataBuffer, &arrayBuffer);
        if (status != napi_ok) {
            COMM_LOGE(COMM_SDK, "create data array object fail");
            return;
        }
        (void)memcpy_s(dataBuffer, len, outData.get(), len);
        napi_value argv[ARGS_SIZE_ONE] = { nullptr };
        argv[ARGS_SIZE_ZERO] = arrayBuffer;
        NapiCallFunction(conn->env_, conn->dataReceivedRef_, argv, ARGS_SIZE_ONE);
    };
    (void)DoInJsMainThread(env, std::move(func));
}

static void OnDataReceivedAdapter(uint32_t handle, const uint8_t *data, uint32_t len)
{
    COMM_CHECK_AND_RETURN_LOGE(data != nullptr, COMM_SDK, "data is null");
    COMM_LOGI(COMM_SDK, "conn data received, handle=%{public}u, len=%{public}u", handle, len);
    std::lock_guard<std::mutex> guard(NapiLinkEnhanceConnection::connectionListMutex_);
    for (uint32_t i = 0; i < NapiLinkEnhanceConnection::connectionList_.size(); i++) {
        NapiLinkEnhanceConnection *connection = NapiLinkEnhanceConnection::connectionList_[i];
        if (connection->handle_ == handle) {
            COMM_LOGI(COMM_SDK, "find conn object, handle=%{public}u", handle);
            NotifyDataReceived(connection, data, len);
            return;
        }
    }
    return;
}

static void OnServiceDiedAdapter(void)
{
    COMM_LOGI(COMM_SDK, "service died");
    std::lock_guard<std::mutex> guard(NapiLinkEnhanceServer::serverMapMutex_);
    for (auto iter = NapiLinkEnhanceServer::enhanceServerMap_.begin();
        iter != NapiLinkEnhanceServer::enhanceServerMap_.end(); ++iter) {
        std::string serverName = iter->first;
        NapiLinkEnhanceServer *server = iter->second;
        if (server == nullptr || server->env_ == nullptr) {
            COMM_LOGI(COMM_SDK, "server name not found or invalid");
            continue;
        }
        auto func = [serverName]() {
            NapiLinkEnhanceServer *server = FindServerByName(serverName);
            if (server == nullptr) {
                COMM_LOGE(COMM_SDK, "server not found, name=%{public}s", serverName.c_str());
                return;
            }
            if (!server->IsStopEnable()) {
                COMM_LOGI(COMM_SDK, "server not enable stop listener, name=%{public}s", serverName.c_str());
                EraseServerFromMap(serverName);
                return;
            }
            napi_value closeReason = NapiGetInt32Ret(server->env_, LINK_ENHANCE_SERVER_DIED);
            napi_value argv[ARGS_SIZE_ONE] = { nullptr };
            argv[ARGS_SIZE_ZERO] = closeReason;
            NapiCallFunction(server->env_, server->serverStopRef_, argv, ARGS_SIZE_ONE);
            EraseServerFromMap(serverName);
        };
        (void)DoInJsMainThread(server->env_, std::move(func));
    }
}

static void OnServiceStoppedAdapter(const char *name)
{
    COMM_LOGI(COMM_SDK, "service stopped");
    if (name == nullptr) {
        COMM_LOGE(COMM_SDK, "invalid service name");
        return;
    }
    std::string serverName = name;
    std::lock_guard<std::mutex> guard(NapiLinkEnhanceServer::serverMapMutex_);
    NapiLinkEnhanceServer *server = FindServerByName(serverName);
    if (server == nullptr || server->env_ == nullptr) {
        COMM_LOGI(COMM_SDK, "server name not found or invalid");
        return;
    }
    napi_env env = server->env_;
    auto func = [serverName]() {
        NapiLinkEnhanceServer *server = FindServerByName(serverName);
        if (server == nullptr) {
            COMM_LOGE(COMM_SDK, "server not found, name=%{public}s", serverName.c_str());
            return;
        }
        if (!server->IsStopEnable()) {
            COMM_LOGI(COMM_SDK, "server not enable stop listener, name=%{public}s", serverName.c_str());
            EraseServerFromMap(serverName);
            return;
        }
        napi_value closeReason = NapiGetInt32Ret(server->env_, LINK_ENHANCE_SERVER_STOPPED);
        napi_value argv[ARGS_SIZE_ONE] = { nullptr };
        argv[ARGS_SIZE_ZERO] = closeReason;
        NapiCallFunction(server->env_, server->serverStopRef_, argv, ARGS_SIZE_ONE);
        EraseServerFromMap(serverName);
    };
    (void)DoInJsMainThread(env, std::move(func));
}

static IGeneralListener g_listener = {
    .OnAcceptConnect = OnAcceptConnectAdapter,
    .OnConnectionStateChange = OnConnectionStateChangeAdapter,
    .OnDataReceived = OnDataReceivedAdapter,
    .OnServiceDied = OnServiceDiedAdapter,
    .OnServiceStopped = OnServiceStoppedAdapter,
};

/*
 * Module initialization function
 */
static napi_value Init(napi_env env, napi_value exports)
{
    COMM_LOGI(COMM_SDK, "enhance manager init start");
    NapiLinkEnhanceServer::DefineJSClass(env);
    NapiLinkEnhanceConnection::DefineJSClass(env);
    PropertyInit(env, exports);
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("createServer", NapiLinkEnhanceServer::Create),
        DECLARE_NAPI_FUNCTION("createConnection", NapiLinkEnhanceConnection::Create),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);

    int32_t ret = GeneralRegisterListener(&g_listener);
    if (ret != 0) {
        COMM_LOGE(COMM_SDK, "enhance manager register listener fail ret=%{public}d", ret);
    }
    return exports;
}
EXTERN_C_END
/*
 * Module define
 */
static napi_module enhanceConnectionModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "distributedsched.linkEnhance",
    .nm_priv = ((void *)0),
    .reserved = { 0 }
};
/*
 * Module register function
 */
extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    COMM_LOGI(
        COMM_SDK, "Register enhanceConnectionModule nm_modname:%{public}s", enhanceConnectionModule.nm_modname);
    napi_module_register(&enhanceConnectionModule);
}
} // namespace Softbus
} // namespace Communication