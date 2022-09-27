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

#include "stream_manager.h"

#include "session.h"
#include "vtp_stream_socket.h"

namespace Communication {
namespace SoftBus {
std::shared_ptr<IStreamManager> IStreamManager::GetInstance(std::shared_ptr<IStreamMsgManager> msgManager,
    std::shared_ptr<IStreamManagerListener> streamListener)
{
    auto dataManager = std::make_shared<StreamManager>(streamListener);
    dataManager->SetStreamMsgManager(msgManager);

    return dataManager;
}

bool StreamManager::PrepareEnvironment(const std::string &pkgName)
{
    return VtpStreamSocket::InitVtpInstance(pkgName);
}

void StreamManager::DestroyEnvironment(const std::string &pkgName)
{
    VtpStreamSocket::DestroyVtpInstance(pkgName);
}

int StreamManager::CreateStreamClientChannel(IpAndPort &local, IpAndPort remote, Proto protocol,
    int streamType, std::pair<uint8_t*, uint32_t> sessionKey)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO,
        "Start to create client channel, local:%d, remote:%d, proto:%d", local.port, remote.port, protocol);

    std::shared_ptr<IStreamSocket> streamSocket = nullptr;
    if (protocol == VTP) {
        streamSocket = std::make_shared<VtpStreamSocket>();
    } else {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "do not support %d protocol", protocol);
        return -1;
    }

    curProtocol_ = protocol;
    if (streamSocket->CreateClient(local, remote, streamType, sessionKey)) {
        socketMap_.insert(std::pair<Proto, std::shared_ptr<IStreamSocket>>(curProtocol_, streamSocket));
        SetStreamRecvListener(streamListener_);
        int scene = SOFTBUS_SCENE;
        if (!streamSocket->SetOption(SCENE, StreamAttr(scene))) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "set stream scene failed");
            return -1;
        }
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "streamSocket CreateClient success, port:%d", local.port);
        return local.port;
    }

    return 0;
}

int StreamManager::CreateStreamServerChannel(IpAndPort &local, Proto protocol,
    int streamType, std::pair<uint8_t*, uint32_t> sessionKey)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO,
        "Start to create server channel, local:%d, proto:%d", local.port, protocol);

    std::shared_ptr<IStreamSocket> streamSocket = nullptr;
    if (protocol == VTP) {
        streamSocket = std::make_shared<VtpStreamSocket>();
    } else {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "do not support %d protocol", protocol);
        return -1;
    }

    curProtocol_ = protocol;
    if (!streamSocket->CreateServer(local, streamType, sessionKey)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "create %d server error", protocol);
        return -1;
    }

    socketMap_.insert(std::pair<Proto, std::shared_ptr<IStreamSocket>>(curProtocol_, streamSocket));
    SetStreamRecvListener(streamListener_);

    int scene = SOFTBUS_SCENE;
    if (!streamSocket->SetOption(SCENE, StreamAttr(scene))) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "set stream scene failed");
        return -1;
    }
    return local.port;
}

bool StreamManager::DestroyStreamDataChannel()
{
    auto it = socketMap_.find(curProtocol_);
    if (it != socketMap_.end()) {
        auto streamSocket = it->second;
        streamSocket->DestroyStreamSocket();
        socketMap_.erase(it);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "DestroyStreamDataChannel %d protocol success", curProtocol_);
        return true;
    }
    return false;
}

bool StreamManager::Send(std::unique_ptr<IStream> data)
{
    auto it = socketMap_.find(curProtocol_);
    if (it != socketMap_.end()) {
        auto streamSocket = it->second;
        return streamSocket->Send(std::move(data));
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "do not found curProtocol = %d", curProtocol_);
    return false;
}

bool StreamManager::SetOption(int type, const StreamAttr &value)
{
    auto it = socketMap_.find(curProtocol_);
    if (it != socketMap_.end()) {
        auto streamSocket = it->second;
        streamSocket->SetOption(type, value);
        return true;
    }
    return false;
}

StreamAttr StreamManager::GetOption(int type) const
{
    auto it = socketMap_.find(curProtocol_);
    if (it != socketMap_.end()) {
        auto streamSocket = it->second;
        return streamSocket->GetOption(type);
    }
    return std::move(StreamAttr());
}

void StreamManager::SetStreamRecvListener(std::shared_ptr<IStreamManagerListener> recvListener)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "SetStreamRecvListener in");
    streamListener_ = recvListener;
    if (socketListener_ != nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_WARN, "Socket listener has existed");
        return;
    }

    socketListener_ = std::make_shared<StreamSocketListener>(recvListener);
    auto it = socketMap_.find(curProtocol_);
    if (it != socketMap_.end()) {
        auto streamSocket = it->second;
        streamSocket->SetStreamListener(socketListener_);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "SetStreamRecvListener %d protocol success", curProtocol_);
    }
}
} // namespace SoftBus
} // namespace Communication
