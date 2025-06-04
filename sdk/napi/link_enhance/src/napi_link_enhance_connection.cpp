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

#include "napi_link_enhance_connection.h"

#include "conn_log.h"
#include "napi_link_enhance_error_code.h"
#include "napi_link_enhance_utils.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_connection.h"
#include "softbus_error_code.h"

namespace Communication {
namespace OHOS::Softbus {

thread_local napi_ref NapiLinkEnhanceConnection::consRef_ = nullptr;

std::vector<NapiLinkEnhanceConnection *> NapiLinkEnhanceConnection::connectionList_;
std::mutex NapiLinkEnhanceConnection::connectionListMutex_;

static napi_status CheckCreateConnectionParams(napi_env env, napi_callback_info info, napi_value &outResult)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = { 0 };

    NAPI_SOFTBUS_CALL_RETURN(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    NAPI_SOFTBUS_RETURN_IF(
        argc != ARGS_SIZE_TWO && argc != ARGS_SIZE_THREE, "expect 2 or 3 args", napi_invalid_arg);

    std::string deviceId {};
    if (!ParseString(env, deviceId, argv[ARGS_SIZE_ZERO])) {
        COMM_LOGE(COMM_SDK, "expect string");
        return napi_string_expected;
    }

    std::string name {};
    if (!ParseString(env, name, argv[ARGS_SIZE_ONE])) {
        COMM_LOGE(COMM_SDK, "expect string");
        return napi_string_expected;
    }

    if (deviceId.length() == 0 || name.length() == 0) {
        COMM_LOGE(COMM_SDK, "name or deviceId is null");
        return napi_invalid_arg;
    }

    if (argc == ARGS_SIZE_THREE) {
        int32_t handle;
        if (!ParseInt32(env, handle, argv[ARGS_SIZE_TWO])) {
            COMM_LOGE(COMM_SDK, "expect int");
            return napi_invalid_arg;
        }
    }

    napi_value constructor = nullptr;
    NAPI_SOFTBUS_CALL_RETURN(napi_get_reference_value(env, NapiLinkEnhanceConnection::consRef_, &constructor));
    NAPI_SOFTBUS_CALL_RETURN(napi_new_instance(env, constructor, argc, argv, &outResult));
    return napi_ok;
}

napi_value NapiLinkEnhanceConnection::Create(napi_env env, napi_callback_info info)
{
    COMM_LOGD(COMM_SDK, "enter");
    if (!CheckAccessToken()) {
        HandleSyncErr(env, LINK_ENHANCE_PERMISSION_DENIED);
        return NapiGetUndefinedRet(env);
    }
    napi_value result;
    auto status = CheckCreateConnectionParams(env, info, result);
    if (status != napi_ok) {
        HandleSyncErr(env, LINK_ENHANCE_PARAMETER_INVALID);
        return NapiGetUndefinedRet(env);
    }
    return result;
}

void NapiLinkEnhanceConnection::DefineJSClass(napi_env env)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("connect", Connect),
        DECLARE_NAPI_FUNCTION("disconnect", Disconnect),
        DECLARE_NAPI_FUNCTION("close", Close),
        DECLARE_NAPI_FUNCTION("getPeerDeviceId", GetPeerDeviceId),
        DECLARE_NAPI_FUNCTION("sendData", SendData),

        DECLARE_NAPI_FUNCTION("on", On),
        DECLARE_NAPI_FUNCTION("off", Off),
    };

    napi_value constructor = nullptr;
    napi_define_class(env, "Connection", NAPI_AUTO_LENGTH, Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    napi_create_reference(env, constructor, 1, &consRef_);
}

napi_value NapiLinkEnhanceConnection::Constructor(napi_env env, napi_callback_info info)
{
    COMM_LOGD(COMM_SDK, "enter");
    napi_value thisVar = nullptr;

    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = { 0 };

    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != ARGS_SIZE_TWO && argc != ARGS_SIZE_THREE) {
        COMM_LOGE(COMM_SDK, "unexpected args");
        return NapiGetUndefinedRet(env);
    }
    std::string deviceId;
    std::string name;
    if (!ParseString(env, deviceId, argv[PARAM0]) || !ParseString(env, name, argv[PARAM1])) {
        COMM_LOGE(COMM_SDK, "ParseString failed");
        return NapiGetUndefinedRet(env);
    };
    NapiLinkEnhanceConnection *connection = nullptr;
    if (argc == ARGS_SIZE_THREE) {
        uint32_t handle;
        ParseUInt32(env, handle, argv[PARAM2]);
        connection = new NapiLinkEnhanceConnection(deviceId, name, handle);
    } else {
        connection = new NapiLinkEnhanceConnection(deviceId, name);
    }
    CONN_CHECK_AND_RETURN_RET_LOGE(connection != nullptr, thisVar, COMM_SDK, "new link enhance connection failed");
    auto status = napi_wrap(
        env, thisVar, connection,
        [](napi_env env, void *data, void *hint) {
            NapiLinkEnhanceConnection *connection = static_cast<NapiLinkEnhanceConnection *>(data);
            if (connection) {
                delete connection;
                connection = nullptr;
            }
        },
        nullptr, nullptr);
    if (status != napi_ok) {
        COMM_LOGE(COMM_SDK, "napi_wrap failed");
        delete connection;
        connection = nullptr;
        return thisVar;
    }

    connection->env_ = env;
    {
        std::lock_guard<std::mutex> guard(connectionListMutex_);
        connectionList_.push_back(connection);
    }
    return thisVar;
}

static NapiLinkEnhanceConnection *NapiGetEnhanceConnection(napi_env env, napi_value thisVar)
{
    NapiLinkEnhanceConnection *connection = nullptr;
    auto status = napi_unwrap(env, thisVar, (void **)&connection);
    if (status != napi_ok) {
        return nullptr;
    }
    return connection;
}

static NapiLinkEnhanceConnection *NapiGetEnhanceConnection(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value thisVar = nullptr;
    if (napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr) != napi_ok) {
        return nullptr;
    }
    return NapiGetEnhanceConnection(env, thisVar);
}

static bool CheckAccessTokenAndParams(napi_env env, napi_callback_info info, std::string &funcName)
{
    if (!CheckAccessToken()) {
        HandleSyncErr(env, LINK_ENHANCE_PERMISSION_DENIED);
        return false;
    }
    size_t argc = ARGS_SIZE_TWO;
    napi_value args[ARGS_SIZE_TWO];
    napi_status status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (status != napi_ok || argc != ARGS_SIZE_TWO) {
        HandleSyncErr(env, LINK_ENHANCE_PARAMETER_INVALID);
        return false;
    }

    napi_valuetype valueType = napi_null;
    napi_typeof(env, args[PARAM1], &valueType);
    if (valueType != napi_function) {
        HandleSyncErr(env, LINK_ENHANCE_PARAMETER_INVALID);
        return false;
    }

    size_t typeLen = 0;
    status = napi_get_value_string_utf8(env, args[ARGS_SIZE_ZERO], nullptr, -1, &typeLen);
    if (status != napi_ok || typeLen >= ARGS_TYPE_MAX_LEN) {
        HandleSyncErr(env, LINK_ENHANCE_PARAMETER_INVALID);
        return false;
    }
    char type[ARGS_TYPE_MAX_LEN];
    status = napi_get_value_string_utf8(env, args[ARGS_SIZE_ZERO], type, sizeof(type), &typeLen);
    if (status != napi_ok) {
        HandleSyncErr(env, LINK_ENHANCE_PARAMETER_INVALID);
        return false;
    }
    funcName = type;
    return true;
}

napi_value NapiLinkEnhanceConnection::On(napi_env env, napi_callback_info info)
{
    std::string funcName = "";
    if (!CheckAccessTokenAndParams(env, info, funcName)) {
        return NapiGetUndefinedRet(env);
    }
    NapiLinkEnhanceConnection *connection = NapiGetEnhanceConnection(env, info);
    size_t argc = ARGS_SIZE_TWO;
    napi_value args[ARGS_SIZE_TWO];
    napi_status status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (status != napi_ok || argc != ARGS_SIZE_TWO || connection == nullptr) {
        HandleSyncErr(env, LINK_ENHANCE_PARAMETER_INVALID);
        return NapiGetUndefinedRet(env);
    }
    if (strcmp(funcName.c_str(), "connectResult") == 0) {
        COMM_LOGI(COMM_SDK, "register connectResult");
        if (connection->connectResultRef_ != nullptr) {
            napi_delete_reference(env, connection->connectResultRef_);
        }
        napi_create_reference(env, args[ARGS_SIZE_ONE], 1, &(connection->connectResultRef_));
        connection->SetConnectResultEnable(true);
    } else if (strcmp(funcName.c_str(), "dataReceived") == 0) {
        COMM_LOGI(COMM_SDK, "register dataReceived");
        if (connection->dataReceivedRef_ != nullptr) {
            napi_delete_reference(env, connection->dataReceivedRef_);
        }
        napi_create_reference(env, args[ARGS_SIZE_ONE], 1, &(connection->dataReceivedRef_));
        connection->SetEnableData(true);
    } else if (strcmp(funcName.c_str(), "disconnected") == 0) {
        COMM_LOGI(COMM_SDK, "register disconnected");
        if (connection->disconnectRef_ != nullptr) {
            napi_delete_reference(env, connection->disconnectRef_);
        }
        napi_create_reference(env, args[ARGS_SIZE_ONE], 1, &(connection->disconnectRef_));
        connection->SetEnableDisconnect(true);
    } else {
        HandleSyncErr(env, LINK_ENHANCE_PARAMETER_INVALID);
        return NapiGetUndefinedRet(env);
    }
    return NapiGetUndefinedRet(env);
}

napi_value NapiLinkEnhanceConnection::Off(napi_env env, napi_callback_info info)
{
    std::string funcName = "";
    if (!CheckAccessTokenAndParams(env, info, funcName)) {
        return NapiGetUndefinedRet(env);
    }
    NapiLinkEnhanceConnection *connection = NapiGetEnhanceConnection(env, info);
    if (connection == nullptr) {
        HandleSyncErr(env, LINK_ENHANCE_PARAMETER_INVALID);
        return NapiGetUndefinedRet(env);
    }
    if (strcmp(funcName.c_str(), "connectResult") == 0 && connection->connectResultRef_ != nullptr) {
        COMM_LOGI(COMM_SDK, "unregister connectResult");
        napi_delete_reference(env, connection->connectResultRef_);
        connection->connectResultRef_ = nullptr;
        connection->SetConnectResultEnable(false);
    } else if (strcmp(funcName.c_str(), "dataReceived") == 0 && connection->dataReceivedRef_ != nullptr) {
        COMM_LOGI(COMM_SDK, "unregister dataReceived");
        napi_delete_reference(env, connection->dataReceivedRef_);
        connection->dataReceivedRef_ = nullptr;
        connection->SetEnableData(false);
    } else if (strcmp(funcName.c_str(), "disconnected") == 0 && connection->disconnectRef_ != nullptr) {
        COMM_LOGI(COMM_SDK, "unregister disconnected");
        napi_delete_reference(env, connection->disconnectRef_);
        connection->disconnectRef_ = nullptr;
        connection->SetEnableDisconnect(false);
    } else {
        HandleSyncErr(env, LINK_ENHANCE_PARAMETER_INVALID);
        return NapiGetUndefinedRet(env);
    }
    return NapiGetUndefinedRet(env);
}

napi_value NapiLinkEnhanceConnection::Connect(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_status status = napi_get_cb_info(env, info, &argc, nullptr, nullptr, nullptr);
    if (status != napi_ok || argc > ARGS_SIZE_ZERO) {
        HandleSyncErr(env, LINK_ENHANCE_PARAMETER_INVALID);
        return NapiGetUndefinedRet(env);
    }
    if (!CheckAccessToken()) {
        HandleSyncErr(env, LINK_ENHANCE_PERMISSION_DENIED);
        return NapiGetUndefinedRet(env);
    }
    NapiLinkEnhanceConnection *connection = NapiGetEnhanceConnection(env, info);
    if (connection == nullptr) {
        HandleSyncErr(env, LINK_ENHANCE_PARAMETER_INVALID);
        return NapiGetUndefinedRet(env);
    }
    Address address = {
        .addrType = CONNECTION_ADDR_BLE,
    };
    if (strcpy_s(address.addr.ble.mac, BT_MAC_LEN, connection->deviceId_.c_str()) != 0) {
        HandleSyncErr(env, LINK_ENHANCE_INTERVAL_ERR);
        return NapiGetUndefinedRet(env);
    }
    
    int32_t handle = GeneralConnect(PKG_NAME.c_str(), connection->name_.c_str(), &address);
    if (handle <= 0) {
        COMM_LOGE(COMM_SDK, "connect failed, err=%{public}d", handle);
        int32_t errcode = ConvertToJsErrcode(handle);
        HandleSyncErr(env, errcode);
        return NapiGetUndefinedRet(env);
    }
    connection->handle_ = (uint32_t)handle;
    connection->state_ = ConnectionState::STATE_CONNECTING;
    COMM_LOGI(COMM_SDK, "start connect handle=%{public}u", handle);
    return NapiGetUndefinedRet(env);
}

napi_value NapiLinkEnhanceConnection::Disconnect(napi_env env, napi_callback_info info)
{
    if (!CheckAccessToken()) {
        HandleSyncErr(env, LINK_ENHANCE_PERMISSION_DENIED);
        return NapiGetUndefinedRet(env);
    }
    size_t argc = 0;
    napi_status status = napi_get_cb_info(env, info, &argc, nullptr, nullptr, nullptr);
    if (status != napi_ok || argc > ARGS_SIZE_ZERO) {
        return NapiGetUndefinedRet(env);
    }
    NapiLinkEnhanceConnection *connection = NapiGetEnhanceConnection(env, info);
    if (connection == nullptr) {
        return NapiGetUndefinedRet(env);
    }
    std::lock_guard<std::mutex> guard(connectionListMutex_);
    for (auto iter = connectionList_.begin(); iter != connectionList_.end(); ++iter) {
        if ((*iter)->handle_ == connection->handle_) {
            COMM_LOGI(COMM_SDK, "disconnect connection, handle=%{public}u", connection->handle_);
            int32_t errCode = ConvertToJsErrcode(GeneralDisconnect(connection->handle_));
            if (errCode == LINK_ENHANCE_PERMISSION_DENIED) {
                HandleSyncErr(env, errCode);
            }
            connectionList_.erase(iter);
            break;
        }
    }
    
    return NapiGetUndefinedRet(env);
}

napi_value NapiLinkEnhanceConnection::Close(napi_env env, napi_callback_info info)
{
    if (!CheckAccessToken()) {
        HandleSyncErr(env, LINK_ENHANCE_PERMISSION_DENIED);
        return NapiGetUndefinedRet(env);
    }
    size_t argc = 0;
    napi_status status = napi_get_cb_info(env, info, &argc, nullptr, nullptr, nullptr);
    if (status != napi_ok || argc > ARGS_SIZE_ZERO) {
        COMM_LOGE(COMM_SDK, "no needed arguments");
        return NapiGetUndefinedRet(env);
    }
    NapiLinkEnhanceConnection *connection = NapiGetEnhanceConnection(env, info);
    if (connection == nullptr) {
        COMM_LOGE(COMM_SDK, "get connection failed");
        return NapiGetUndefinedRet(env);
    }
    COMM_LOGI(COMM_SDK, "close connection, handle=%{public}u", connection->handle_);
    connection->lock_.lock();
    connection->isEnableConnectResult_ = false;
    connection->isEnableData_ = false;
    connection->isEnableDisconnect_ = false;
    connection->lock_.unlock();
    if (connection->connectResultRef_ != nullptr) {
        COMM_LOGI(COMM_SDK, "unregister connectResult");
        napi_delete_reference(env, connection->connectResultRef_);
        connection->connectResultRef_ = nullptr;
    }
    if (connection->dataReceivedRef_ != nullptr) {
        COMM_LOGI(COMM_SDK, "unregister dataReceived");
        napi_delete_reference(env, connection->dataReceivedRef_);
        connection->dataReceivedRef_ = nullptr;
    }
    if (connection->disconnectRef_ != nullptr) {
        COMM_LOGI(COMM_SDK, "unregister disconnected");
        napi_delete_reference(env, connection->disconnectRef_);
        connection->disconnectRef_ = nullptr;
    }

    (void)GeneralDisconnect(connection->handle_);
    std::lock_guard<std::mutex> guard(connectionListMutex_);
    for (auto iter = connectionList_.begin(); iter != connectionList_.end(); ++iter) {
        if ((*iter)->handle_ == connection->handle_) {
            COMM_LOGI(COMM_SDK, "erase connection, handle=%{public}u", connection->handle_);
            connectionList_.erase(iter);
            break;
        }
    }
    return NapiGetUndefinedRet(env);
}

napi_value NapiLinkEnhanceConnection::GetPeerDeviceId(napi_env env, napi_callback_info info)
{
    if (!CheckAccessToken()) {
        HandleSyncErr(env, LINK_ENHANCE_PERMISSION_DENIED);
        return NapiGetUndefinedRet(env);
    }
    std::string deviceId = "";
    size_t argc = 0;
    napi_status status = napi_get_cb_info(env, info, &argc, nullptr, nullptr, nullptr);
    if (status != napi_ok || argc > ARGS_SIZE_ZERO) {
        COMM_LOGI(COMM_SDK, "no needed arguments");
        return NapiGetStringRet(env, deviceId);
    }
    NapiLinkEnhanceConnection *connection = NapiGetEnhanceConnection(env, info);
    if (connection == nullptr) {
        COMM_LOGI(COMM_SDK, "get connection failed");
        return NapiGetStringRet(env, deviceId);
    }

    uint32_t handle = connection->handle_;
    if (handle == 0) {
        COMM_LOGI(COMM_SDK, "invalid connection");
        return NapiGetStringRet(env, deviceId);
    }
    char cDeviceId[BT_MAC_LEN] = { 0 };
    int32_t ret = GeneralGetPeerDeviceId(handle, cDeviceId, BT_MAC_LEN);
    if (ret != 0) {
        COMM_LOGI(COMM_SDK, "get peer deviceId failed, handle=%{public}u", connection->handle_);
        if (ConvertToJsErrcode(ret) == LINK_ENHANCE_PERMISSION_DENIED) {
            HandleSyncErr(env, LINK_ENHANCE_PERMISSION_DENIED);
        }
        return NapiGetStringRet(env, deviceId);
    }
    return NapiGetStringRet(env, cDeviceId);
}

napi_value NapiLinkEnhanceConnection::SendData(napi_env env, napi_callback_info info)
{
    if (!CheckAccessToken()) {
        HandleSyncErr(env, LINK_ENHANCE_PERMISSION_DENIED);
        return NapiGetUndefinedRet(env);
    }
    size_t argc = ARGS_SIZE_ONE;
    napi_value args[ARGS_SIZE_ONE] = { 0 };
    napi_status status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (status != napi_ok || argc != ARGS_SIZE_ONE) {
        HandleSyncErr(env, LINK_ENHANCE_PARAMETER_INVALID);
        return NapiGetUndefinedRet(env);
    }
    NapiLinkEnhanceConnection *connection = NapiGetEnhanceConnection(env, info);
    if (connection == nullptr) {
        HandleSyncErr(env, LINK_ENHANCE_PARAMETER_INVALID);
        return NapiGetUndefinedRet(env);
    }

    napi_value arrayBuffer = args[ARGS_SIZE_ZERO];
    if (arrayBuffer == nullptr) {
        HandleSyncErr(env, LINK_ENHANCE_PARAMETER_INVALID);
        return NapiGetUndefinedRet(env);
    }

    void *bufferData;
    size_t dataLen = 0;
    status = napi_get_arraybuffer_info(env, arrayBuffer, (void **)&bufferData, &dataLen);
    if (status != napi_ok || dataLen == 0) {
        COMM_LOGE(COMM_SDK, "get arraybuffer info failed, dataLen=%{public}zu", dataLen);
        HandleSyncErr(env, LINK_ENHANCE_PARAMETER_INVALID);
        return NapiGetUndefinedRet(env);
    }
    uint8_t *data = (uint8_t *)SoftBusCalloc(dataLen);
    if (data == nullptr || memcpy_s(data, dataLen, bufferData, dataLen) != EOK) {
        SoftBusFree(data);
        HandleSyncErr(env, LINK_ENHANCE_INTERVAL_ERR);
        return NapiGetUndefinedRet(env);
    }
    COMM_LOGI(COMM_SDK, "call send func handle=%{public}u, len=%{public}u", connection->handle_, (uint32_t)dataLen);
    int32_t ret = GeneralSend(connection->handle_, data, (uint32_t)dataLen);
    if (ret != 0) {
        SoftBusFree(data);
        int32_t errcode = ConvertToJsErrcode(ret);
        HandleSyncErr(env, errcode);
        return NapiGetUndefinedRet(env);
    }
    SoftBusFree(data);
    return NapiGetUndefinedRet(env);
}

bool NapiLinkEnhanceConnection::IsConnectResultEnable()
{
    this->lock_.lock();
    bool isEnableConnectResult = this->isEnableConnectResult_;
    this->lock_.unlock();
    return isEnableConnectResult;
}

bool NapiLinkEnhanceConnection::IsDataReceiveEnable()
{
    this->lock_.lock();
    bool isEnableData = this->isEnableData_;
    this->lock_.unlock();
    return isEnableData;
}

bool NapiLinkEnhanceConnection::IsDisconnectEnable()
{
    this->lock_.lock();
    bool isEnableDisconnect = this->isEnableDisconnect_;
    this->lock_.unlock();
    return isEnableDisconnect;
}
} // namespace Softbus
} // namespace Communication
