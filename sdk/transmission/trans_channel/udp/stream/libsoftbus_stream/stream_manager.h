/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#ifndef STREAM_MANAGER_H
#define STREAM_MANAGER_H

#include "i_stream_manager.h"
#include "i_stream_socket.h"

namespace Communication {
namespace SoftBus {
class StreamManager : public std::enable_shared_from_this<StreamManager>, public IStreamManager {
public:
    class StreamSocketListener : public IStreamSocketListener {
    public:
        explicit StreamSocketListener(std::shared_ptr<IStreamManagerListener> streamListener)
            : listener_(streamListener) {}
        StreamSocketListener() = delete;
        ~StreamSocketListener() override = default;
        void OnStreamReceived(std::unique_ptr<IStream> stream) override
        {
            listener_->OnStreamReceived(std::move(stream));
        }
        void OnStreamStatus(int32_t status) override
        {
            listener_->OnStreamStatus(status);
        }

        int32_t OnStreamHdrReceived(std::unique_ptr<char[]> header, int32_t size) override
        {
            static_cast<void>(header);
            static_cast<void>(size);
            return 0;
        }

        void OnQosEvent(int32_t eventId, int32_t tvCount, const QosTv *tvList) const override
        {
            listener_->OnQosEvent(eventId, tvCount, tvList);
        }

        void OnFrameStats(const StreamSendStats *data) override
        {
            listener_->OnFrameStats(data);
        }

        void OnRippleStats(const TrafficStats *data) override
        {
            listener_->OnRippleStats(data);
        }

    private:
        std::shared_ptr<IStreamManagerListener> listener_ = nullptr;
    };

    explicit StreamManager(std::shared_ptr<IStreamManagerListener> streamListener) : streamListener_(streamListener) {}
    StreamManager() = delete;
    virtual ~StreamManager() = default;

    int32_t CreateStreamClientChannel(IpAndPort &local, IpAndPort remote, Proto protocol,
        int32_t streamType, std::pair<uint8_t*, uint32_t> sessionKey) override;

    int32_t CreateStreamServerChannel(IpAndPort &local, Proto protocol, int32_t streamType,
        std::pair<uint8_t*, uint32_t> sessionKey) override;

    bool DestroyStreamDataChannel() override;

    bool Send(std::unique_ptr<IStream> data) override;

    bool SetOption(int32_t type, const StreamAttr &value) override;
    int32_t SetMultiLayer(const void *para) override;
    StreamAttr GetOption(int32_t type) const override;

    void SetStreamRecvListener(std::shared_ptr<IStreamManagerListener> recvListener) override;
    bool PrepareEnvironment(const std::string &pkgName) override;
    void DestroyEnvironment(const std::string &pkgName) override;

    void SetStreamMsgManager(std::shared_ptr<IStreamMsgManager> manager)
    {
        msgManager_ = manager;
    }
    std::shared_ptr<IStreamMsgManager> GetStreamMsgManager()
    {
        return msgManager_;
    }

private:
    StreamManager(const StreamManager &) = delete;
    StreamManager(StreamManager &&) = delete;
    StreamManager &operator=(const StreamManager &) = delete;
    StreamManager &operator=(StreamManager &&) = delete;

    std::map<Proto, std::shared_ptr<IStreamSocket>> socketMap_;
    Proto curProtocol_ = VTP;
    std::shared_ptr<IStreamSocketListener> socketListener_ = nullptr;
    std::shared_ptr<IStreamMsgManager> msgManager_ = nullptr;
    std::shared_ptr<IStreamManagerListener> streamListener_ = nullptr;
};
} // namespace SoftBus
} // namespace Communication

#endif
