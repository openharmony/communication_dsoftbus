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

static int32_t OnAcceptConnectAdapter(const char *name, uint32_t handle)
{
    COMM_LOGI(COMM_SDK, "accept new connection, handle=%{public}u", handle);
    std::string serverName = name;
    std::string deviceId = "";
    NapiLinkEnhanceServer *enhanceServer = nullptr;
    if (NapiLinkEnhanceServer::enhanceServerMap_.count(serverName) > 0) {
        enhanceServer = NapiLinkEnhanceServer::enhanceServerMap_[serverName];
    }
    if (enhanceServer == nullptr || enhanceServer->env_ == nullptr ||
        !enhanceServer->IsAcceptedEnable()) {
        COMM_LOGE(COMM_SDK, "server status error, name=%{public}s", name);
        return LINK_ENHANCE_PARAMETER_INVALID;
    }
    uint32_t inHandle = handle;
    auto func = [enhanceServer, serverName, deviceId, inHandle]() {
        napi_value argvOut[ARGS_SIZE_ONE] = { nullptr };
        size_t argc = ARGS_SIZE_THREE;
        napi_value nHandle = nullptr;
        napi_status status = napi_create_uint32(enhanceServer->env_, inHandle, &nHandle);
        napi_valuetype valuetype;
        napi_typeof(enhanceServer->env_, nHandle, &valuetype);
        if (status != napi_ok) {
            return;
        }
        napi_value argv[ARGS_SIZE_THREE];
        argv[PARAM0] = NapiGetStringRet(enhanceServer->env_, deviceId),
        argv[PARAM1] = NapiGetStringRet(enhanceServer->env_, serverName),
        argv[PARAM2] = nHandle;

        napi_value constructor = nullptr;
        if (napi_get_reference_value(enhanceServer->env_,
            NapiLinkEnhanceConnection::consRef_, &constructor) != napi_ok) {
            COMM_LOGE(COMM_SDK, "get connection constructor failed");
            return;
        }
        if (napi_new_instance(enhanceServer->env_, constructor, argc, argv, &argvOut[ARGS_SIZE_ZERO]) != napi_ok) {
            COMM_LOGE(COMM_SDK, "create js new connection object failed");
            return;
        }
        NapiCallFunction(enhanceServer->env_, enhanceServer->acceptConnectRef_, argvOut, ARGS_SIZE_ONE);
    };
    return DoInJsMainThread(enhanceServer->env_, std::move(func));
}

static int32_t NotifyDisconnected(NapiLinkEnhanceConnection *connection, int32_t reason)
{
    COMM_LOGI(COMM_SDK, "disconnected, handle=%{public}u, reason=%{public}d", connection->handle_, reason);
    if (!connection->IsDisconnectEnable()) {
        COMM_LOGW(COMM_SDK, "not register disconnect listener");
        return SOFTBUS_CONN_GENERAL_LISTENER_NOT_ENABLE;
    }
    auto func = [connection, reason]() {
        napi_value disconnectReason = NapiGetInt32Ret(connection->env_, reason);
        napi_value argv[ARGS_SIZE_ONE] = { nullptr };
        argv[ARGS_SIZE_ZERO] = disconnectReason;
        NapiCallFunction(connection->env_, connection->disconnectRef_, argv, ARGS_SIZE_ONE);
    };
    return DoInJsMainThread(connection->env_, std::move(func));
}

static int32_t NotifyConnectResult(NapiLinkEnhanceConnection *connection, bool success, int32_t reason)
{
    if (!connection->IsConnectResultEnable()) {
        COMM_LOGE(COMM_SDK, "not register connect result listener");
        return SOFTBUS_CONN_GENERAL_LISTENER_NOT_ENABLE;
    }
    int32_t napiReason = ConvertToJsErrcode(reason);
    auto func = [connection, success, napiReason]() {
        NapiConnectionChangeState *changeState = new NapiConnectionChangeState(connection->deviceId_,
            success, napiReason);
        napi_value argv[ARGS_SIZE_ONE] = { nullptr };
        argv[ARGS_SIZE_ZERO] = changeState->ToNapiValue(connection->env_);
        NapiCallFunction(connection->env_, connection->connectResultRef_, argv, ARGS_SIZE_ONE);
    };
    return DoInJsMainThread(connection->env_, std::move(func));
}

static int32_t OnConnectionStateChangeAdapter(uint32_t handle, int32_t status, int32_t reason)
{
    COMM_LOGI(COMM_SDK, "connection state change, handle=%{public}u, state=%{public}d, reason=%{public}d", handle,
        status, reason);
    std::lock_guard<std::mutex> guard(NapiLinkEnhanceConnection::connectionListMutex_);
    for (auto iter = NapiLinkEnhanceConnection::connectionList_.begin();
        iter != NapiLinkEnhanceConnection::connectionList_.end(); ++iter) {
        NapiLinkEnhanceConnection *connection = *iter;
        if (connection->handle_ == handle && (status == CONNECTION_STATE_CONNECTED_SUCCESS ||
            status == CONNECTION_STATE_CONNECTED_FAILED)) {
            bool success = (status == CONNECTION_STATE_CONNECTED_SUCCESS);
            COMM_LOGI(COMM_SDK, "find connection object, handle=%{public}u, success=%{public}d", handle, success);
            connection->state_ = success ? ConnectionState::STATE_CONNECTED : ConnectionState::STATE_DISCONNECTED;
            int32_t ret = NotifyConnectResult(connection, success, reason);
            if (!success) {
                NapiLinkEnhanceConnection::connectionList_.erase(iter);
            }
            return ret;
        }
        if (connection->handle_ == handle && status == CONNECTION_STATE_DISCONNECTED) {
            int32_t ret = NotifyDisconnected(connection, reason);
            NapiLinkEnhanceConnection::connectionList_.erase(iter);
            return ret;
        }
        if (handle == 0) {
            if (connection->state_ == ConnectionState::STATE_CONNECTING) {
                (void)NotifyConnectResult(connection, false, reason);
            } else if (connection->state_ == ConnectionState::STATE_CONNECTED) {
                (void)NotifyDisconnected(connection, reason);
            }
            NapiLinkEnhanceConnection::connectionList_.erase(iter);
        }
    }
    return LINK_ENHANCE_PARAMETER_INVALID;
}

static void NotifyDataReceived(NapiLinkEnhanceConnection *connection, uint8_t *outData, uint32_t len)
{
    if (!connection->IsDataReceiveEnable()) {
        COMM_LOGE(COMM_SDK, "not register data recv listener");
        return;
    }
    auto func = [connection, outData, len]() {
        napi_value arrayBuffer;
        void *dataBuffer;
        int32_t status = napi_create_arraybuffer(connection->env_, len, &dataBuffer, &arrayBuffer);
        if (status != napi_ok) {
            COMM_LOGE(COMM_SDK, "create data array object failed");
            delete[]outData;
            return;
        }
        for (uint32_t i = 0; i < len; i++) {
            ((uint8_t *)dataBuffer)[i] = outData[i];
        }
        delete[]outData;
        napi_value argv[ARGS_SIZE_ONE] = { nullptr };
        argv[ARGS_SIZE_ZERO] = arrayBuffer;
        NapiCallFunction(connection->env_, connection->dataReceivedRef_, argv, ARGS_SIZE_ONE);
    };
    (void)DoInJsMainThread(connection->env_, std::move(func));
}

static void OnDataReceivedAdapter(uint32_t handle, const uint8_t *data, uint32_t len)
{
    COMM_LOGI(COMM_SDK, "connection data received, handle=%{public}u, len=%{public}u", handle, len);
    std::lock_guard<std::mutex> guard(NapiLinkEnhanceConnection::connectionListMutex_);
    for (uint32_t i = 0; i < NapiLinkEnhanceConnection::connectionList_.size(); i++) {
        NapiLinkEnhanceConnection *connection = NapiLinkEnhanceConnection::connectionList_[i];
        
        if (connection->handle_ == handle) {
            COMM_LOGI(COMM_SDK, "find connection object, handle=%{public}u", handle);
            uint8_t *outData = new uint8_t[len];
            if (outData == nullptr || memcpy_s(outData, len, data, len) != EOK) {
                delete[]outData;
                return;
            }
            NotifyDataReceived(connection, outData, len);
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
        NapiLinkEnhanceServer *server = iter->second;
        if (!server->IsStopEnable()) {
            COMM_LOGI(COMM_SDK, "server close, server name =%{public}s", server->name_.c_str());
            NapiLinkEnhanceServer::enhanceServerMap_.erase(iter);
            continue;
        }
        auto func = [server]() {
            napi_value closeReason = NapiGetInt32Ret(server->env_, LINK_ENHANCE_SERVER_DIED);
            napi_value argv[ARGS_SIZE_ONE] = { nullptr };
            argv[ARGS_SIZE_ZERO] = closeReason;
            NapiCallFunction(server->env_, server->serverStopRef_, argv, ARGS_SIZE_ONE);
        };
        (void)DoInJsMainThread(server->env_, std::move(func));
        NapiLinkEnhanceServer::enhanceServerMap_.erase(iter);
    }
}

static IGeneralListener g_listener = {
    .OnAcceptConnect = OnAcceptConnectAdapter,
    .OnConnectionStateChange = OnConnectionStateChangeAdapter,
    .OnDataReceived = OnDataReceivedAdapter,
    .OnServiceDied = OnServiceDiedAdapter,
};

/*
 * Module initialization function
 */

static napi_value Init(napi_env env, napi_value exports)
{
    COMM_LOGI(COMM_SDK, "----enhance manager init start------");
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
        COMM_LOGE(COMM_SDK, "----enhance manager register listener failed------");
    }

    COMM_LOGI(COMM_SDK, "----enhance manager init end------");
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