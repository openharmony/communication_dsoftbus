/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "vtp_stream_socket.h"
#include "softbus_error_code.h"

#define INVALID_FD (-1)

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
    TRANS_LOGI(TRANS_STREAM,
        "Start to create client channel, localPort=%{public}d, remotePort=%{public}d, proto=%{public}d",
        local.port, remote.port, protocol);

    std::shared_ptr<IStreamSocket> streamSocket = nullptr;
    if (protocol == VTP) {
        streamSocket = std::make_shared<VtpStreamSocket>();
    } else {
        TRANS_LOGE(TRANS_STREAM, "do not support protocol=%{public}d", protocol);
        return INVALID_FD;
    }

    curProtocol_ = protocol;
    if (streamSocket->CreateClient(local, remote, streamType, sessionKey)) {
        socketMap_.insert(std::pair<Proto, std::shared_ptr<IStreamSocket>>(curProtocol_, streamSocket));
        SetStreamRecvListener(streamListener_);
        int scene = SOFTBUS_SCENE;
        if (!streamSocket->SetOption(SCENE, StreamAttr(scene))) {
            TRANS_LOGE(TRANS_STREAM, "set stream scene failed");
            return INVALID_FD;
        }
        TRANS_LOGI(TRANS_STREAM, "streamSocket CreateClient success, localPort=%{public}d", local.port);
        return local.port;
    }

    return SOFTBUS_OK;
}

int StreamManager::CreateStreamServerChannel(IpAndPort &local, Proto protocol,
    int streamType, std::pair<uint8_t*, uint32_t> sessionKey)
{
    TRANS_LOGI(TRANS_STREAM,
        "Start to create server channel, localPort=%{public}d, protocol=%{public}d", local.port, protocol);

    std::shared_ptr<IStreamSocket> streamSocket = nullptr;
    if (protocol == VTP) {
        streamSocket = std::make_shared<VtpStreamSocket>();
    } else {
        TRANS_LOGE(TRANS_STREAM, "do not support protocol=%{public}d", protocol);
        return INVALID_FD;
    }

    curProtocol_ = protocol;
    if (!streamSocket->CreateServer(local, streamType, sessionKey)) {
        TRANS_LOGE(TRANS_STREAM, "create server error. protocol=%{public}d", protocol);
        return INVALID_FD;
    }

    socketMap_.insert(std::pair<Proto, std::shared_ptr<IStreamSocket>>(curProtocol_, streamSocket));
    SetStreamRecvListener(streamListener_);

    int scene = SOFTBUS_SCENE;
    if (!streamSocket->SetOption(SCENE, StreamAttr(scene))) {
        TRANS_LOGE(TRANS_STREAM, "set stream scene failed");
        return INVALID_FD;
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
        TRANS_LOGI(TRANS_STREAM, "curProtocol=%{public}d  success", curProtocol_);
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
    TRANS_LOGE(TRANS_STREAM, "do not found curProtocol=%{public}d", curProtocol_);
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

int32_t StreamManager::SetMultiLayer(const void *para)
{
    auto it = socketMap_.find(curProtocol_);
    if (it != socketMap_.end()) {
        auto streamSocket = it->second;
        return streamSocket->SetMultiLayer(para);
    }
    TRANS_LOGE(TRANS_STREAM, "do not found curProtocol=%{public}d", curProtocol_);
    return SOFTBUS_TRANS_SESSION_SET_CHANNEL_FAILED;
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
    TRANS_LOGD(TRANS_STREAM, "enter.");
    streamListener_ = recvListener;
    if (socketListener_ != nullptr) {
        TRANS_LOGW(TRANS_STREAM, "Socket listener has existed");
        return;
    }

    socketListener_ = std::make_shared<StreamSocketListener>(recvListener);
    auto it = socketMap_.find(curProtocol_);
    if (it != socketMap_.end()) {
        auto streamSocket = it->second;
        streamSocket->SetStreamListener(socketListener_);
        TRANS_LOGD(TRANS_STREAM, "success curProtocol=%{public}d", curProtocol_);
    }
}
} // namespace SoftBus
} // namespace Communication
