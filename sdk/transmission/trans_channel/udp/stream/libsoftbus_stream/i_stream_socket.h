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

#ifndef STREAM_SOCKET_H
#define STREAM_SOCKET_H

#include <condition_variable>
#include <map>
#include <mutex>
#include <queue>
#include <securec.h>
#include <utility>

#include "client_trans_stream.h"
#include "i_stream.h"
#include "session.h"
#include "stream_common.h"

namespace Communication {
namespace SoftBus {
class IStreamSocketListener {
public:
    IStreamSocketListener() = default;
    virtual ~IStreamSocketListener() = default;

    virtual void OnStreamReceived(std::unique_ptr<IStream> stream) = 0;
    virtual void OnStreamStatus(int status) = 0;
    virtual int OnStreamHdrReceived(std::unique_ptr<char[]> header, int size) = 0;
    virtual void OnQosEvent(int32_t eventId, int32_t tvCount, const QosTv *tvList) const = 0;
    virtual void OnFrameStats(const StreamSendStats *data) = 0;
    virtual void OnRippleStats(const TrafficStats *data) = 0;
};

class IStreamSocket {
public:
    IStreamSocket()
    {
        listenFd_ = -1;
        streamFd_ = -1;
        epollFd_ = -1;
        isStreamRecv_ = false;
        streamType_ = INVALID;
        isBlocked_ = false;
    }
    virtual ~IStreamSocket()
    {
        if (sessionKey_.first != nullptr) {
            (void)memset_s(sessionKey_.first, sessionKey_.second, 0, sessionKey_.second);
            delete [] sessionKey_.first;
        }
        sessionKey_.first = nullptr;
    }

    virtual bool CreateClient(IpAndPort &local, int streamType,
        std::pair<uint8_t*, uint32_t> sessionKey) = 0; // socket + bind
    virtual bool CreateClient(IpAndPort &local, const IpAndPort &remote, int streamType,
        std::pair<uint8_t*, uint32_t> sessionKey) = 0;
    virtual bool CreateServer(IpAndPort &local, int streamType, std::pair<uint8_t*, uint32_t> sessionKey) = 0;

    virtual void DestroyStreamSocket() = 0;

    virtual bool Connect(const IpAndPort &remote) = 0;
    virtual bool Send(std::unique_ptr<IStream> stream) = 0;

    virtual bool SetOption(int type, const StreamAttr &value) = 0;
    virtual int32_t SetMultiLayer(const void *para) = 0;
    virtual StreamAttr GetOption(int type) const = 0;

    virtual bool SetStreamListener(std::shared_ptr<IStreamSocketListener> receiver) = 0;

protected:
    static constexpr int MAX_EPOLL_NUM = 100;
    static constexpr int MAX_CONNECTION_VALUE = 100;
    static constexpr int FRAME_HEADER_LEN = 4;
    static constexpr int BYTE_TO_BIT = 8;
    static constexpr int INT_TO_BYTE = 0xff;
    static constexpr int IPTOS_LOWDELAY = 0XBC;
    static constexpr int DEFAULT_UDP_BUFFER_SIZE = 512 * 1024;
    static constexpr int DEFAULT_UDP_BUFFER_RCV_SIZE = 1024 * 1024;
    static constexpr int STREAM_BUFFER_THRESHOLD = 5;

    virtual int CreateAndBindSocket(IpAndPort &local, bool isServer) = 0;
    virtual bool Accept() = 0;

    virtual int EpollTimeout(int fd, int timeout) = 0;
    virtual int SetSocketEpollMode(int fd) = 0;
    virtual std::unique_ptr<char[]> RecvStream(int dataLength) = 0;
    virtual std::unique_ptr<IStream> TakeStream()
    {
        std::unique_lock<std::mutex> lock(streamReceiveLock_);
        while (isStreamRecv_) {
            if (!streamReceiveBuffer_.empty()) {
                auto item = std::move(streamReceiveBuffer_.front());
                streamReceiveBuffer_.pop();
                return item;
            }
            streamReceiveCv_.wait(lock);
        }
        return nullptr;
    }

    virtual void PutStream(std::unique_ptr<IStream> stream)
    {
        std::lock_guard<std::mutex> lock(streamReceiveLock_);
        if (isStreamRecv_) {
            streamReceiveBuffer_.push(std::move(stream));
            streamReceiveCv_.notify_all();
        }
    }

    virtual int GetStreamNum()
    {
        std::lock_guard<std::mutex> lock(streamReceiveLock_);
        return streamReceiveBuffer_.size();
    }

    virtual void QuitStreamBuffer()
    {
        std::lock_guard<std::mutex> lock(streamReceiveLock_);
        isStreamRecv_ = false;
        streamReceiveCv_.notify_all();
    }

    int listenFd_;
    int streamFd_;
    int epollFd_;
    IpAndPort localIpPort_ {};
    IpAndPort remoteIpPort_ {};
    bool isStreamRecv_;
    std::shared_ptr<IStreamSocketListener> streamReceiver_ = nullptr;
    std::queue<std::unique_ptr<IStream>> streamReceiveBuffer_;
    std::mutex streamReceiveLock_;
    std::condition_variable streamReceiveCv_;
    int streamType_ = INVALID;
    bool isBlocked_;
    std::pair<uint8_t*, uint32_t> sessionKey_ = std::make_pair(nullptr, 0);
};
} // namespace SoftBus
} // namespace Communication

#endif //STREAM_SOCKET_H