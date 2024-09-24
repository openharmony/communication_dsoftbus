/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <algorithm>
#include <cinttypes>
#include <chrono>
#include <thread>

#include "common.h"
#include "tmessenger.h"

namespace OHOS {
static constexpr uint32_t WAIT_RESP_TIME = 1;

std::string Request::Encode() const
{
    return std::to_string(static_cast<int32_t>(cmd_));
}

std::shared_ptr<Request> Request::Decode(const std::string &data)
{
    if (data.empty()) {
        LOGE("the data is empty");
        return nullptr;
    }

    Cmd cmd = static_cast<Cmd>(std::stoi(data));
    if (cmd < Cmd::QUERY_RESULT || cmd > Cmd::QUERY_RESULT) {
        LOGE("invalid cmd=%d", static_cast<int32_t>(cmd));
        return nullptr;
    }
    return std::make_shared<Request>(cmd);
}

std::string Response::Encode() const
{
    std::string data = std::to_string(isEncrypt_ ? 1 : 0);
    return data + SEPARATOR + recvData_;
}

std::shared_ptr<Response> Response::Decode(const std::string &data)
{
    if (data.empty()) {
        LOGE("the data is empty");
        return nullptr;
    }

    size_t pos = data.find(SEPARATOR);
    if (pos == std::string::npos) {
        LOGE("can not find separator in the string data");
        return nullptr;
    }

    int32_t isEncryptVal = static_cast<int32_t>(std::stoi(data.substr(0, pos)));
    bool isEncrypt = (isEncryptVal == 1);
    std::string recvData = data.substr(pos + 1);

    return std::make_shared<Response>(isEncrypt, recvData);
}

Message::~Message()
{
    if (msgType_ == MsgType::MSG_SEQ && request != nullptr) {
        delete request;
    }
    if (msgType_ == MsgType::MSG_RSP && response != nullptr) {
        delete response;
    }
}

std::string Message::Encode() const
{
    std::string data = std::to_string(static_cast<int32_t>(msgType_));
    switch (msgType_) {
        case MsgType::MSG_SEQ:
            return request == nullptr ? "" : data + SEPARATOR + request->Encode();
        case MsgType::MSG_RSP:
            return response == nullptr ? "" : data + SEPARATOR + response->Encode();
        default:
            LOGE("invalid msgType=%d", static_cast<int32_t>(msgType_));
            return "";
    }
}

std::shared_ptr<Message> Message::Decode(const std::string &data)
{
    size_t pos = data.find(SEPARATOR);
    if (pos == std::string::npos) {
        return nullptr;
    }

    MsgType msgType = static_cast<MsgType>(std::stoi(data.substr(0, pos)));
    switch (msgType) {
        case MsgType::MSG_SEQ: {
            std::shared_ptr<Request> req = Request::Decode(data.substr(pos + 1));
            if (req == nullptr) {
                return nullptr;
            }
            return std::make_shared<Message>(*req);
        }
        case MsgType::MSG_RSP: {
            std::shared_ptr<Response> rsp = Response::Decode(data.substr(pos + 1));
            if (rsp == nullptr) {
                return nullptr;
            }
            return std::make_shared<Message>(*rsp);
        }
        default:
            LOGE("invalid msgType=%d", static_cast<int32_t>(msgType));
            return nullptr;
    }
}

int32_t TMessenger::Open(
    const std::string &pkgName, const std::string &myName, const std::string &peerName, bool isServer)
{
    isServer_ = isServer;
    return isServer_ ? StartListen(pkgName, myName) : StartConnect(pkgName, myName, peerName);
}

void TMessenger::Close()
{
    if (socket_ > 0) {
        Shutdown(socket_);
        socket_ = -1;
    }

    if (listenSocket_ > 0) {
        Shutdown(listenSocket_);
        listenSocket_ = -1;
    }

    pkgName_.clear();
    myName_.clear();
    peerName_.clear();
    peerNetworkId_.clear();
    msgList_.clear();
}

int32_t TMessenger::StartListen(const std::string &pkgName, const std::string &myName)
{
    if (listenSocket_ > 0) {
        return SOFTBUS_OK;
    }

    SocketInfo info = {
        .pkgName = (char *)(pkgName.c_str()),
        .name = (char *)(myName.c_str()),
    };
    int32_t socket = Socket(info);
    if (socket <= 0) {
        LOGE("failed to create socket, ret=%d", socket);
        return socket;
    }
    LOGI("create listen socket=%d", socket);

    QosTV qosInfo[] = {
        {.qos = QOS_TYPE_MIN_BW,       .value = 80  },
        { .qos = QOS_TYPE_MAX_LATENCY, .value = 4000},
        { .qos = QOS_TYPE_MIN_LATENCY, .value = 2000},
    };
    static ISocketListener listener = {
        .OnBind = TMessenger::OnBind,
        .OnMessage = TMessenger::OnMessage,
        .OnShutdown = TMessenger::OnShutdown,
    };

    int32_t ret = Listen(socket, qosInfo, sizeof(qosInfo) / sizeof(qosInfo[0]), &listener);
    if (ret != SOFTBUS_OK) {
        LOGE("failed to listen, socket=%d", socket);
        Shutdown(socket);
        return ret;
    }
    listenSocket_ = socket;
    pkgName_ = pkgName;
    myName_ = myName;
    return SOFTBUS_OK;
}

int32_t TMessenger::StartConnect(const std::string &pkgName, const std::string &myName, const std::string &peerName)
{
    if (socket_ > 0) {
        return SOFTBUS_OK;
    }

    SocketInfo info = {
        .pkgName = const_cast<char *>(pkgName.c_str()),
        .name = const_cast<char *>(myName.c_str()),
        .peerName = const_cast<char *>(peerName.c_str()),
        .peerNetworkId = nullptr,
        .dataType = DATA_TYPE_MESSAGE,
    };
    info.peerNetworkId = OHOS::WaitOnLineAndGetNetWorkId();

    int32_t socket = Socket(info);
    if (socket <= 0) {
        LOGE("failed to create socket, ret=%d", socket);
        return socket;
    }
    LOGI("create bind socket=%d", socket);

    QosTV qosInfo[] = {
        {.qos = QOS_TYPE_MIN_BW,       .value = 80  },
        { .qos = QOS_TYPE_MAX_LATENCY, .value = 4000},
        { .qos = QOS_TYPE_MIN_LATENCY, .value = 2000},
    };

    static ISocketListener listener = {
        .OnMessage = OnMessage,
        .OnShutdown = OnShutdown,
    };

    int32_t ret = Bind(socket, qosInfo, sizeof(qosInfo) / sizeof(qosInfo[0]), &listener);
    if (ret != SOFTBUS_OK) {
        LOGE("failed to bind, socket=%d, ret=%d", socket, ret);
        Shutdown(socket);
        return ret;
    }

    pkgName_ = pkgName;
    myName_ = myName;
    peerNetworkId_ = info.peerNetworkId;
    peerName_ = peerName;
    socket_ = socket;
    return SOFTBUS_OK;
}

void TMessenger::OnBind(int32_t socket, PeerSocketInfo info)
{
    TMessenger::GetInstance().SetConnectSocket(socket, info);
}

void TMessenger::OnMessage(int32_t socket, const void *data, uint32_t dataLen)
{
    std::string result(static_cast<const char *>(data), dataLen);
    TMessenger::GetInstance().OnMessageRecv(result);
}

void TMessenger::OnShutdown(int32_t socket, ShutdownReason reason)
{
    TMessenger::GetInstance().CloseSocket(socket);
}

void TMessenger::SetConnectSocket(int32_t socket, PeerSocketInfo info)
{
    if (socket_ > 0) {
        return;
    }

    socket_ = socket;
    peerName_ = info.name;
    peerNetworkId_ = info.networkId;
}

void TMessenger::OnMessageRecv(const std::string &result)
{
    std::shared_ptr<Message> msg = Message::Decode(result);
    if (msg == nullptr) {
        LOGE("receive invalid message");
        return;
    }

    switch (msg->msgType_) {
        case Message::MsgType::MSG_SEQ: {
            OnRequest();
            break;
        }
        case Message::MsgType::MSG_RSP: {
            std::unique_lock<std::mutex> lock(recvMutex_);
            msgList_.push_back(msg);
            lock.unlock();
            recvCond_.notify_one();
            break;
        }
        default:
            break;
    }
}

void TMessenger::OnRequest()
{
    std::thread t([&] {
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_RESP_TIME));
        std::shared_ptr<Response> resp = onQuery_();
        Message msg { *resp };
        int32_t ret = Send(msg);
        if (ret != SOFTBUS_OK) {
            LOGE("failed to send response");
        }
    });
    t.detach();
}

void TMessenger::CloseSocket(int32_t socket)
{
    if (socket_ == socket) {
        Shutdown(socket_);
        socket_ = -1;
    }
}

std::shared_ptr<Response> TMessenger::QueryResult(uint32_t timeout)
{
    Request req { Request::Cmd::QUERY_RESULT };
    Message msg { req };
    int32_t ret = Send(msg);
    if (ret != SOFTBUS_OK) {
        LOGE("failed to query result, ret=%d", ret);
        return nullptr;
    }

    return WaitResponse(timeout);
}

int32_t TMessenger::Send(const Message &msg)
{
    std::string data = msg.Encode();
    if (data.empty()) {
        LOGE("the data is empty");
        return SOFTBUS_MEM_ERR;
    }

    int32_t ret = SendMessage(socket_, data.c_str(), data.size());
    if (ret != SOFTBUS_OK) {
        LOGE("failed to send message, socket=%d, ret=%d", socket_, ret);
    }
    return ret;
}

std::shared_ptr<Response> TMessenger::WaitResponse(uint32_t timeout)
{
    std::unique_lock<std::mutex> lock(recvMutex_);
    std::shared_ptr<Response> rsp = nullptr;
    if (recvCond_.wait_for(lock, std::chrono::seconds(timeout), [&] {
            rsp = GetMessageFromRecvList(Message::MsgType::MSG_RSP);
            return rsp != nullptr;
        })) {
        return rsp;
    }
    LOGE("no result received");
    return nullptr;
}

std::shared_ptr<Response> TMessenger::GetMessageFromRecvList(Message::MsgType type)
{
    auto it = std::find_if(msgList_.begin(), msgList_.end(), [type] (const std::shared_ptr<Message> &it) {
        return it->msgType_ == type;
    });

    if (it == msgList_.end() || *it == nullptr) {
        return nullptr;
    }

    const Response *rsp = (*it)->response;
    if (rsp == nullptr) {
        msgList_.erase(it);
        return nullptr;
    }

    std::shared_ptr<Response> resp = std::make_shared<Response>(*rsp);
    msgList_.erase(it);
    return resp;
}

void TMessenger::RegisterOnQuery(TMessenger::OnQueryCallback callback)
{
    onQuery_ = callback;
}
} // namespace OHOS
