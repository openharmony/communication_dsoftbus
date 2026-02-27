/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "ohos.distributedsched.linkEnhance.proj.hpp"
#include "ohos.distributedsched.linkEnhance.impl.hpp"
#include "stdexcept"
#include <thread>
#include "conn_log.h"
#include "napi_link_enhance_error_code.h"
#include "securec.h"
#include "softbus_access_token_adapter.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "link_enhance_utils_taihe.h"
#include "softbus_connection.h"

namespace Communication {
namespace OHOS::Softbus {
class ServerImpl;
class ConnectionImpl;
static std::vector<::ohos::distributedsched::linkEnhance::Connection> connectionList_;
static std::mutex connectionLock_;
static std::vector<::ohos::distributedsched::linkEnhance::Server> serverList_;
static std::mutex serverLock_;

class ServerImpl {
public:
    explicit ServerImpl()
    {
    }
    explicit ServerImpl(const std::string name)
    {
        this->name_ = name;
    }
    void Start()
    {
        if (!CheckAccessToken()) {
            ThrowException(SOFTBUS_ACCESS_TOKEN_DENIED);
            return;
        }
        int32_t ret = GeneralCreateServer(PKG_NAME.c_str(), this->name_.c_str());
        if (ret != 0) {
            COMM_LOGE(COMM_SDK, "create server fail, ret=%{public}d", ret);
            ThrowException(ret);
        }
        return;
    }

    void Stop()
    {
        if (!CheckAccessToken()) {
            ThrowException(SOFTBUS_ACCESS_TOKEN_DENIED);
            return;
        }
        int32_t ret = GeneralRemoveServer(PKG_NAME.c_str(), this->name_.c_str());
        if (ret != 0) {
            COMM_LOGE(COMM_SDK, "remove server fail, ret=%{public}d", ret);
            if (ret == SOFTBUS_ACCESS_TOKEN_DENIED) {
                ThrowException(SOFTBUS_ACCESS_TOKEN_DENIED);
            }
        }
    }

    void Close()
    {
        if (!CheckAccessToken()) {
            ThrowException(SOFTBUS_ACCESS_TOKEN_DENIED);
            return;
        }
        int32_t ret = GeneralRemoveServer(PKG_NAME.c_str(), this->name_.c_str());
        if (ret != 0) {
            COMM_LOGE(COMM_SDK, "remove server fail, ret=%{public}d", ret);
            if (ret == SOFTBUS_ACCESS_TOKEN_DENIED) {
                ThrowException(SOFTBUS_ACCESS_TOKEN_DENIED);
            }
        }
        std::lock_guard<std::mutex> guard(serverLock_);
        for (auto it = serverList_.begin(); it != serverList_.end(); it++) {
            auto server = *it;
            auto serverImpl = reinterpret_cast<ServerImpl *>(server->GetServerImpl());
            if (serverImpl != nullptr && serverImpl->name_ == this->name_) {
                COMM_LOGI(COMM_SDK, "remove server, name=%{public}s", serverImpl->name_.c_str());
                serverList_.erase(it);
                break;
            }
        }
    }

    void OnConnectionAccepted(::taihe::callback_view<void(
        ::ohos::distributedsched::linkEnhance::weak::Connection connection)> callback)
    {
        if (!CheckAccessToken()) {
            ThrowException(SOFTBUS_ACCESS_TOKEN_DENIED);
            return;
        }
        auto acceptCallback = std::make_shared<::taihe::callback<void(
            ::ohos::distributedsched::linkEnhance::weak::Connection connection)>>(callback);
        std::lock_guard<std::mutex> guard(serverLock_);
        for (auto it : serverList_) {
            auto serverImpl = reinterpret_cast<ServerImpl *>(it->GetServerImpl());
            if (serverImpl->name_ == this->name_) {
                serverImpl->SetAcceptedCallback(acceptCallback);
                break;
            }
        }
    }

    void OffConnectionAccepted(::taihe::optional_view<::taihe::callback<void(
        ::ohos::distributedsched::linkEnhance::weak::Connection connection)>> callback)
    {
        if (!CheckAccessToken()) {
            ThrowException(SOFTBUS_ACCESS_TOKEN_DENIED);
            return;
        }
        std::lock_guard<std::mutex> guard(serverLock_);
        for (auto it : serverList_) {
            auto serverImpl = reinterpret_cast<ServerImpl *>(it->GetServerImpl());
            if (serverImpl->name_ == this->name_) {
                serverImpl->SetAcceptedCallback(nullptr);
                break;
            }
        }
    }

    void OnServerStopped(::taihe::callback_view<void(int32_t result)> callback)
    {
        if (!CheckAccessToken()) {
            ThrowException(SOFTBUS_ACCESS_TOKEN_DENIED);
            return;
        }
        auto stopCallback = std::make_shared<::taihe::callback<void(int32_t result)>>(callback);
        std::lock_guard<std::mutex> guard(serverLock_);
        for (auto it : serverList_) {
            auto serverImpl = reinterpret_cast<ServerImpl *>(it->GetServerImpl());
            if (serverImpl->name_ == this->name_) {
                serverImpl->SetStopCallback(stopCallback);
                break;
            }
        }
    }

    void OffServerStopped(::taihe::optional_view<::taihe::callback<void(int32_t result)>> callback)
    {
        if (!CheckAccessToken()) {
            ThrowException(SOFTBUS_ACCESS_TOKEN_DENIED);
            return;
        }
        std::lock_guard<std::mutex> guard(serverLock_);
        for (auto it : serverList_) {
            auto serverImpl = reinterpret_cast<ServerImpl *>(it->GetServerImpl());
            if (serverImpl->name_ == this->name_) {
                serverImpl->SetStopCallback(nullptr);
                break;
            }
        }
    }
    
    int64_t GetServerImpl()
    {
        return reinterpret_cast<int64_t>(this);
    }

    std::shared_ptr<::taihe::callback<void(
        ::ohos::distributedsched::linkEnhance::weak::Connection connection)>> GetAcceptedCallback()
    {
        this->lock_.lock();
        std::shared_ptr<::taihe::callback<void(
            ::ohos::distributedsched::linkEnhance::weak::Connection connection)>> cb = this->acceptCallback_;
        this->lock_.unlock();
        return cb;
    }

    std::shared_ptr<::taihe::callback<void(int32_t result)>> GetStopCallback()
    {
        this->lock_.lock();
        std::shared_ptr<::taihe::callback<void(int32_t result)>> cb = this->stopCallback_;
        this->lock_.unlock();
        return cb;
    }

    std::string name_ = "";
    
private:
    std::recursive_timed_mutex lock_;
    std::shared_ptr<::taihe::callback<void(int32_t result)>> stopCallback_;
    std::shared_ptr<::taihe::callback<void(
        ::ohos::distributedsched::linkEnhance::weak::Connection connection)>> acceptCallback_;
    void SetAcceptedCallback(std::shared_ptr<::taihe::callback<void(
        ::ohos::distributedsched::linkEnhance::weak::Connection connection)>> callback)
    {
        this->lock_.lock();
        this->acceptCallback_ = callback;
        this->lock_.unlock();
    }
    void SetStopCallback(std::shared_ptr<::taihe::callback<void(int32_t result)>> callback)
    {
        this->lock_.lock();
        this->stopCallback_ = callback;
        this->lock_.unlock();
    }
};

class ConnectionImpl {
public:
    explicit ConnectionImpl()
    {
    }
    explicit ConnectionImpl(const std::string name, uint32_t handle)
    {
        this->name_ = name;
        this->handle_ = handle;
    }
    explicit ConnectionImpl(const std::string deviceId, const std::string name)
    {
        this->deviceId_ = deviceId;
        this->name_ = name;
    }
    void Connect()
    {
        if (!CheckAccessToken()) {
            ThrowException(SOFTBUS_ACCESS_TOKEN_DENIED);
            return;
        }
        Address address = {
            .addrType = CONNECTION_ADDR_BLE,
        };
        if (strcpy_s(address.addr.ble.mac, BT_MAC_LEN, this->deviceId_.c_str()) != EOK) {
            ThrowException(LINK_ENHANCE_INTERNAL_ERR);
            return;
        }
        int32_t handle = GeneralConnect(PKG_NAME.c_str(), this->name_.c_str(), &address);
        if (handle <= 0) {
            COMM_LOGE(COMM_SDK, "connect fail, err=%{public}d", handle);
            ThrowException(handle);
            return;
        }
        this->handle_ = static_cast<uint32_t>(handle);
        std::lock_guard<std::mutex> guard(connectionLock_);
        for (auto it : connectionList_) {
            auto conn = reinterpret_cast<ConnectionImpl *>(it->GetConnectionImpl());
            if (conn != nullptr && conn->name_ == this->name_ && conn->deviceId_ == this->deviceId_) {
                conn->state_ = ConnectionState::STATE_CONNECTING;
                conn->handle_ = static_cast<uint32_t>(handle);
                break;
            }
        }
        COMM_LOGI(COMM_SDK, "connect handle=%{public}u", handle);
    }

    void Disconnect()
    {
        if (!CheckAccessToken()) {
            ThrowException(SOFTBUS_ACCESS_TOKEN_DENIED);
            return;
        }
        COMM_LOGI(COMM_SDK, "disconnect conn, handle=%{public}u", this->handle_);
        int32_t errCode = GeneralDisconnect(this->handle_);
        if (errCode == SOFTBUS_ACCESS_TOKEN_DENIED) {
            ThrowException(SOFTBUS_ACCESS_TOKEN_DENIED);
        }
    }

    void Close()
    {
        if (!CheckAccessToken()) {
            ThrowException(SOFTBUS_ACCESS_TOKEN_DENIED);
            return;
        }
        COMM_LOGI(COMM_SDK, "close conn, handle=%{public}u", this->handle_);
        (void)GeneralDisconnect(this->handle_);
        std::lock_guard<std::mutex> guard(connectionLock_);
        for (auto iter = connectionList_.begin(); iter != connectionList_.end();) {
            auto connection = *iter;
            auto connImpl = reinterpret_cast<ConnectionImpl *>(connection->GetConnectionImpl());
            if (connImpl != nullptr && connImpl->handle_ == this->handle_) {
                connectionList_.erase(iter);
                break;
            } else {
                iter++;
            }
        }
    }

    ::taihe::string GetPeerDeviceId()
    {
        if (!CheckAccessToken()) {
            ThrowException(SOFTBUS_ACCESS_TOKEN_DENIED);
            return taihe::string("");
        }
        uint32_t handle = this->handle_;
        char cDeviceId[BT_MAC_LEN] = { 0 };
        int32_t ret = GeneralGetPeerDeviceId(handle, cDeviceId, BT_MAC_LEN);
        if (ret != 0) {
            COMM_LOGE(COMM_SDK, "get peer deviceId fail, handle=%{public}u", handle);
            if (ConvertToJsErrcode(ret) == LINK_ENHANCE_PERMISSION_DENIED) {
                ThrowException(SOFTBUS_ACCESS_TOKEN_DENIED);
                return taihe::string("");
            }
        }
        taihe::string text(cDeviceId);
        return text;
    }

    void SendData(::taihe::array_view<uint8_t> data)
    {
        if (!CheckAccessToken()) {
            ThrowException(SOFTBUS_ACCESS_TOKEN_DENIED);
            return;
        }
        COMM_LOGI(COMM_SDK, "send data, handle=%{public}u", this->handle_);
        if (data.empty()) {
            ThrowException(SOFTBUS_INVALID_PARAM);
            return;
        }
        int32_t ret = GeneralSend(this->handle_, data.data(), (uint32_t)data.size());
        if (ret != 0) {
            ThrowException(ret);
            return;
        }
    }

    void OnConnectResult(::taihe::callback_view<void(
        ::ohos::distributedsched::linkEnhance::ConnectResult const& connectResult)> callback)
    {
        if (!CheckAccessToken()) {
            ThrowException(SOFTBUS_ACCESS_TOKEN_DENIED);
            return;
        }
        auto connCallback = std::make_shared<::taihe::callback<void(
            ::ohos::distributedsched::linkEnhance::ConnectResult const& connectResult)>>(callback);
        std::lock_guard<std::mutex> guard(connectionLock_);
        for (auto it : connectionList_) {
            auto connImpl = reinterpret_cast<ConnectionImpl *>(it->GetConnectionImpl());
            if (connImpl != nullptr && connImpl->handle_ == this->handle_) {
                connImpl->SetConnectCallback(connCallback);
                break;
            }
        }
    }

    void OffConnectResult(::taihe::optional_view<::taihe::callback<void(
        ::ohos::distributedsched::linkEnhance::ConnectResult const& connectResult)>> callback)
    {
        if (!CheckAccessToken()) {
            ThrowException(SOFTBUS_ACCESS_TOKEN_DENIED);
            return;
        }
        std::lock_guard<std::mutex> guard(connectionLock_);
        for (auto it : connectionList_) {
            auto connImpl = reinterpret_cast<ConnectionImpl *>(it->GetConnectionImpl());
            if (connImpl != nullptr && connImpl->handle_ == this->handle_) {
                connImpl->SetConnectCallback(nullptr);
                break;
            }
        }
    }
    
    void OnDisconnected(::taihe::callback_view<void(int32_t result)> callback)
    {
        if (!CheckAccessToken()) {
            ThrowException(SOFTBUS_ACCESS_TOKEN_DENIED);
            return;
        }
        auto disconnCallback = std::make_shared<::taihe::callback<void(int32_t result)>>(callback);
        std::lock_guard<std::mutex> guard(connectionLock_);
        for (auto it : connectionList_) {
            auto connImpl = reinterpret_cast<ConnectionImpl *>(it->GetConnectionImpl());
            if (connImpl != nullptr && connImpl->handle_ == this->handle_) {
                connImpl->SetDisConnectCallback(disconnCallback);
                break;
            }
        }
    }

    void OffDisconnected(::taihe::optional_view<::taihe::callback<void(int32_t result)>> callback)
    {
        if (!CheckAccessToken()) {
            ThrowException(SOFTBUS_ACCESS_TOKEN_DENIED);
            return;
        }
        std::lock_guard<std::mutex> guard(connectionLock_);
        for (auto it : connectionList_) {
            auto connImpl = reinterpret_cast<ConnectionImpl *>(it->GetConnectionImpl());
            if (connImpl != nullptr && connImpl->handle_ == this->handle_) {
                connImpl->SetDisConnectCallback(nullptr);
                break;
            }
        }
    }

    void OnDataReceived(::taihe::callback_view<void(::taihe::array_view<uint8_t> arrayBuffer)> callback)
    {
        if (!CheckAccessToken()) {
            ThrowException(SOFTBUS_ACCESS_TOKEN_DENIED);
            return;
        }
        COMM_LOGI(COMM_SDK, "OnDataReceived, handle=%{public}u", this->handle_);
        auto recvCallback = std::make_shared<::taihe::callback<void(
            ::taihe::array_view<uint8_t> arrayBuffer)>>(callback);
        std::lock_guard<std::mutex> guard(connectionLock_);
        for (auto it : connectionList_) {
            auto connImpl = reinterpret_cast<ConnectionImpl *>(it->GetConnectionImpl());
            if (connImpl != nullptr && connImpl->handle_ == this->handle_) {
                connImpl->SetDataReceiveCallback(recvCallback);
                break;
            }
        }
    }

    void OffDataReceived(::taihe::optional_view<::taihe::callback<void(
        ::taihe::array_view<uint8_t> arrayBuffer)>> callback)
    {
        if (!CheckAccessToken()) {
            ThrowException(SOFTBUS_ACCESS_TOKEN_DENIED);
            return;
        }
        std::lock_guard<std::mutex> guard(connectionLock_);
        for (auto it : connectionList_) {
            auto connImpl = reinterpret_cast<ConnectionImpl *>(it->GetConnectionImpl());
            if (connImpl != nullptr && connImpl->handle_ == this->handle_) {
                connImpl->SetDataReceiveCallback(nullptr);
                break;
            }
        }
    }

    int64_t GetConnectionImpl()
    {
        return reinterpret_cast<int64_t>(this);
    }

    std::shared_ptr<::taihe::callback<void(
        ::ohos::distributedsched::linkEnhance::ConnectResult const& connectResult)>> GetConnCallback()
    {
        this->lock_.lock();
        std::shared_ptr<::taihe::callback<void(
            ::ohos::distributedsched::linkEnhance::ConnectResult const& connectResult)>> cb = this->connCallback_;
        this->lock_.unlock();
        return cb;
    }

    std::shared_ptr<::taihe::callback<void(int32_t result)>> GetDisconnCallback()
    {
        this->lock_.lock();
        std::shared_ptr<::taihe::callback<void(int32_t result)>> cb = this->disconnCallback_;
        this->lock_.unlock();
        return cb;
    }

    std::shared_ptr<::taihe::callback<void(::taihe::array_view<uint8_t> arrayBuffer)>> GetDataReceiveCallback()
    {
        this->lock_.lock();
        std::shared_ptr<::taihe::callback<void(::taihe::array_view<uint8_t> arrayBuffer)>> cb = this->recvCallback_;
        this->lock_.unlock();
        return cb;
    }
    std::string deviceId_ = "";
    std::string name_ = "";
    uint32_t handle_ = 0;
    enum ConnectionState state_ = ConnectionState::STATE_BASE;
    
private:
    std::recursive_timed_mutex lock_;
    std::shared_ptr<::taihe::callback<void(
        ::ohos::distributedsched::linkEnhance::ConnectResult const& connectResult)>> connCallback_;
    std::shared_ptr<::taihe::callback<void(int32_t result)>> disconnCallback_;
    std::shared_ptr<::taihe::callback<void(::taihe::array_view<uint8_t> arrayBuffer)>> recvCallback_;
    void SetConnectCallback(std::shared_ptr<::taihe::callback<void(
        ::ohos::distributedsched::linkEnhance::ConnectResult const& connectResult)>> callback)
    {
        this->lock_.lock();
        this->connCallback_ = callback;
        this->lock_.unlock();
    }

    void SetDisConnectCallback(std::shared_ptr<::taihe::callback<void(int32_t result)>> callback)
    {
        this->lock_.lock();
        this->disconnCallback_ = callback;
        this->lock_.unlock();
    }

    void SetDataReceiveCallback(
        std::shared_ptr<::taihe::callback<void(::taihe::array_view<uint8_t> arrayBuffer)>> callback)
    {
        this->lock_.lock();
        this->recvCallback_ = callback;
        this->lock_.unlock();
    }
};

::ohos::distributedsched::linkEnhance::Server CreateServer(::taihe::string_view name)
{
    auto server = taihe::make_holder<ServerImpl,
       ::ohos::distributedsched::linkEnhance::Server>((const std::string) name);
    if (!CheckAccessToken()) {
        ThrowException(SOFTBUS_ACCESS_TOKEN_DENIED);
        return server;
    }
    auto nameStr = std::string(name);
    if (nameStr.size() == 0 || nameStr.size() > SOFTBUS_NAME_MAX_LEN) {
        COMM_LOGE(COMM_SDK, "invalid parameter, name=%{public}s", name.c_str());
        ThrowException(SOFTBUS_INVALID_PARAM);
        return server;
    }
    bool isExist = false;
    std::lock_guard<std::mutex> guard(serverLock_);
    for (auto it : serverList_) {
        auto serverImpl = reinterpret_cast<ServerImpl *>(it->GetServerImpl());
        if (serverImpl != nullptr && serverImpl->name_ == nameStr) {
            COMM_LOGI(COMM_SDK, "server is exist, name=%{public}s", name.c_str());
            isExist = true;
            break;
        }
    }
    if (isExist) {
        ThrowException(SOFTBUS_CONN_GENERAL_DUPLICATE_SERVER);
        return server;
    }
    serverList_.push_back(server);
    return server;
}

::ohos::distributedsched::linkEnhance::Connection CreateConnection(
    ::taihe::string_view deviceId, ::taihe::string_view name)
{
    auto connection = taihe::make_holder<ConnectionImpl,
        ::ohos::distributedsched::linkEnhance::Connection>((const std::string)deviceId, (const std::string)name);
    if (!CheckAccessToken()) {
        ThrowException(SOFTBUS_ACCESS_TOKEN_DENIED);
        return connection;
    }
    auto nameStr = std::string(name);
    auto deviceIdStr = std::string(deviceId);
    if (deviceIdStr.size() == 0 || nameStr.size() == 0 || nameStr.size() > SOFTBUS_NAME_MAX_LEN) {
        COMM_LOGE(COMM_SDK, "invalid parameter, name=%{public}s", name.c_str());
        ThrowException(SOFTBUS_INVALID_PARAM);
        return connection;
    }
    std::lock_guard<std::mutex> guard(connectionLock_);
    connectionList_.push_back(connection);
    return connection;
}

extern "C" {
static int32_t OnAcceptConnectAdapter(const char *name, uint32_t handle)
{
    COMM_LOGI(COMM_SDK, "accept new conn, handle=%{public}u", handle);
    auto connection = taihe::make_holder<ConnectionImpl,
        ::ohos::distributedsched::linkEnhance::Connection>((const std::string)name, handle);
    {
        std::lock_guard<std::mutex> guard(connectionLock_);
        connectionList_.push_back(connection);
    }
    {
        std::lock_guard<std::mutex> guard(serverLock_);
        for (auto it : serverList_) {
            auto serverImpl = reinterpret_cast<ServerImpl *>(it->GetServerImpl());
            if (serverImpl != nullptr && serverImpl->name_ == name) {
                if (serverImpl->GetAcceptedCallback() == nullptr) {
                    COMM_LOGE(COMM_SDK, "server status err, name=%{public}s", name);
                    return LINK_ENHANCE_PARAMETER_INVALID;
                }
                (*serverImpl->GetAcceptedCallback())(connection);
                break;
            }
        }
    }
    return SOFTBUS_OK;
}

static int32_t NotifyDisconnected(ConnectionImpl *connection, int32_t reason)
{
    COMM_LOGI(COMM_SDK, "disconnected, handle=%{public}u, reason=%{public}d", connection->handle_, reason);
    if (connection->GetDisconnCallback() == nullptr) {
        COMM_LOGE(COMM_SDK, "not register disconnect listener");
        return SOFTBUS_CONN_GENERAL_LISTENER_NOT_ENABLE;
    }
    (*connection->GetDisconnCallback())(reason);
    return SOFTBUS_OK;
}

static int32_t NotifyConnectResult(ConnectionImpl *connection, bool success, int32_t reason)
{
    if (connection->GetConnCallback() == nullptr) {
        COMM_LOGE(COMM_SDK, "not register connect result listener");
        return SOFTBUS_CONN_GENERAL_LISTENER_NOT_ENABLE;
    }
    COMM_LOGI(COMM_SDK, "notify conn result, handle=%{public}u, success=%{public}d", connection->handle_, success);
    connection->state_ = success ? ConnectionState::STATE_CONNECTED : ConnectionState::STATE_DISCONNECTED;
    int32_t ret = 0;
    if (reason != 0) {
        ret = ConvertToJsErrcode(reason);
    }
    ::ohos::distributedsched::linkEnhance::ConnectResult result = {
        .deviceId = connection->deviceId_,
        .reason = ret,
        .success = success,
    };
    (*connection->GetConnCallback())(result);
    return SOFTBUS_OK;
}

static int32_t NotifyConnectionStateChange(ConnectionImpl *connection, int32_t status, int32_t reason)
{
    if (connection->state_ == ConnectionState::STATE_CONNECTING) {
        bool success = (status == CONNECTION_STATE_CONNECTED_SUCCESS);
        return NotifyConnectResult(connection, success, reason);
    }
    if (status == CONNECTION_STATE_DISCONNECTED) {
        return NotifyDisconnected(connection, reason);
    }
    return LINK_ENHANCE_PARAMETER_INVALID;
}

static int32_t OnConnectionStateChangeAdapter(uint32_t handle, int32_t status, int32_t reason)
{
    COMM_LOGI(COMM_SDK, "conn state change, handle=%{public}u", handle);
    int32_t ret = LINK_ENHANCE_PARAMETER_INVALID;
    std::lock_guard<std::mutex> guard(connectionLock_);
    for (auto iter = connectionList_.begin(); iter != connectionList_.end();) {
        COMM_LOGI(COMM_SDK, "find connection");
        auto connection = *iter;
        auto connImpl = reinterpret_cast<ConnectionImpl *>(connection->GetConnectionImpl());
        if (handle == 0) {
            // indicates that server is died and clear all connections
            ret = NotifyConnectionStateChange(connImpl, status, reason);
            iter = connectionList_.erase(iter);
            continue;
        }
        if (connImpl->handle_ == handle) {
            ret = NotifyConnectionStateChange(connImpl, status, reason);
            if (status == CONNECTION_STATE_DISCONNECTED) {
                COMM_LOGI(COMM_SDK, "disconnect server connection");
                iter = connectionList_.erase(iter);
            }
            return ret;
        } else {
            iter++;
        }
    }
    return ret;
}

static void NotifyDataReceived(std::shared_ptr<::taihe::callback<void(
    ::taihe::array_view<uint8_t> arrayBuffer)>> callback, const uint8_t *data, uint32_t len)
{
    if (callback == nullptr) {
        COMM_LOGE(COMM_SDK, "callback is null");
        return;
    }
    std::vector<uint8_t> buffer(data, data + len);
    taihe::array<uint8_t> bufferView = taihe::array<uint8_t>(buffer);
    (*callback)(bufferView);
}

static void OnDataReceivedAdapter(uint32_t handle, const uint8_t *data, uint32_t len)
{
    CONN_CHECK_AND_RETURN_LOGE(data != nullptr, COMM_SDK, "data is null");
    COMM_LOGI(COMM_SDK, "on data receive, handle=%{public}u", handle);
    std::lock_guard<std::mutex> guard(connectionLock_);
    for (auto it : connectionList_) {
        auto conn = reinterpret_cast<ConnectionImpl *>(it->GetConnectionImpl());
        if (conn != nullptr && conn->handle_ == handle) {
            COMM_LOGI(COMM_SDK, "find the connection");
            if (conn->GetDataReceiveCallback() == nullptr) {
                COMM_LOGE(COMM_SDK, "not register data recv listener");
                return;
            }
            NotifyDataReceived(conn->GetDataReceiveCallback(), data, len);
            return;
        }
    }
}

static void OnServiceDiedAdapter(void)
{
    COMM_LOGI(COMM_SDK, "server died");
    std::lock_guard<std::mutex> guard(serverLock_);
    for (auto it = serverList_.begin(); it != serverList_.end();) {
        auto server = *it;
        auto serverImpl = reinterpret_cast<ServerImpl *>(server->GetServerImpl());
        if (serverImpl->GetStopCallback() == nullptr) {
            it = serverList_.erase(it);
            continue;
        }
        (*serverImpl->GetStopCallback())((int32_t)LINK_ENHANCE_SERVER_DIED);
        it = serverList_.erase(it);
    }
}

static IGeneralListener g_listener = {
    .OnAcceptConnect = OnAcceptConnectAdapter,
    .OnConnectionStateChange = OnConnectionStateChangeAdapter,
    .OnDataReceived = OnDataReceivedAdapter,
    .OnServiceDied = OnServiceDiedAdapter,
};
}

int32_t Init()
{
    int32_t ret = GeneralRegisterListener(&g_listener);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "enhance manager register listener fail ret=%{public}d", ret);
    }
    return ret;
}
}
}

TH_EXPORT_CPP_API_CreateServer(Communication::OHOS::Softbus::CreateServer);
TH_EXPORT_CPP_API_CreateConnection(Communication::OHOS::Softbus::CreateConnection);