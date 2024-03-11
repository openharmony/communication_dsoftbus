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

#ifndef TMESSENGER_H
#define TMESSENGER_H

#include <condition_variable>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <string>

#include "common.h"
#include "socket.h"

#define SEPARATOR "|"

namespace OHOS {
class Request {
public:
    enum class Cmd {
        QUERY_RESULT,
    };

    explicit Request(Request::Cmd cmd) : cmd_(cmd) { }
    std::string Encode() const;
    static std::shared_ptr<Request> Decode(const std::string &data);

    Cmd cmd_;
};

class Response {
public:
    Response(bool isEncrypt, const std::string &recvData) : isEncrypt_(isEncrypt), recvData_(recvData) { }
    std::string Encode() const;
    static std::shared_ptr<Response> Decode(const std::string &data);
    bool isEncrypt_;
    std::string recvData_;
};

class Message {
public:
    enum class MsgType : int32_t {
        MSG_SEQ,
        MSG_RSP,
    };

    explicit Message(const Request &req) : msgType_(MsgType::MSG_SEQ), request(new Request(req)) { }
    explicit Message(const Response &rsp) : msgType_(MsgType::MSG_RSP), response(new Response(rsp)) { }
    ~Message();
    std::string Encode() const;
    static std::shared_ptr<Message> Decode(const std::string &data);

    MsgType msgType_;
    union {
        Request *request;
        Response *response;
    };
};

// class 'TMessenger' is used to notify test result
class TMessenger {
public:
    static TMessenger &GetInstance()
    {
        static TMessenger instance;
        return instance;
    }

    // Start a client or server
    int32_t Open(const std::string &pkgName, const std::string &myName, const std::string &peerName, bool isServer);
    void Close();

    std::shared_ptr<Response> QueryResult(uint32_t timeout);

    using OnQueryCallback = std::function<std::shared_ptr<Response>(void)>;
    void RegisterOnQuery(OnQueryCallback callback);

private:
    TMessenger() = default;
    TMessenger(const TMessenger &other) = delete;
    TMessenger(const TMessenger &&other) = delete;
    TMessenger &operator=(const TMessenger &other) = delete;
    TMessenger &operator=(const TMessenger &&other) = delete;

    int32_t StartListen(const std::string &pkgName, const std::string &myName);
    int32_t StartConnect(const std::string &pkgName, const std::string &myName, const std::string &peerName);

    static void OnBind(int32_t socket, PeerSocketInfo info);
    static void OnMessage(int32_t socket, const void *data, uint32_t dataLen);
    static void OnShutdown(int32_t socket, ShutdownReason reason);

    void SetConnectSocket(int32_t socket, PeerSocketInfo info);
    void OnMessageRecv(const std::string &result);
    void OnRequest();

    void CloseSocket(int32_t socket);

    int32_t Send(const Message &msg);
    std::shared_ptr<Response> WaitResponse(uint32_t timeout);
    std::shared_ptr<Response> GetMessageFromRecvList(Message::MsgType type);

    std::string pkgName_ { "" };
    std::string myName_ { "" };
    std::string peerNetworkId_ { "" };
    std::string peerName_ { "" };
    bool isServer_ { false };     // Indicates the instance is a client or server.
    int32_t listenSocket_ { -1 }; // Used to listen the connection from client side.
    int32_t socket_ { -1 };       // Indicates the client socket.

    std::mutex recvMutex_;
    std::condition_variable recvCond_;
    std::list<std::shared_ptr<Message>> msgList_;

    OnQueryCallback onQuery_;
};
} // namespace OHOS
#endif // TMESSENGER_H