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

#ifndef IDB_MANAGER_H
#define IDB_MANAGER_H

#include <memory>

#include "i_stream.h"
#include "i_stream_msg_manager.h"
#include "session.h"
#include "softbus_trans_def.h"
#include "stream_common.h"

namespace Communication {
namespace SoftBus {
class IStreamManagerListener {
public:
    IStreamManagerListener() = default;
    virtual ~IStreamManagerListener() = default;
    virtual void OnStreamReceived(std::unique_ptr<IStream> stream) = 0;
    virtual void OnStreamStatus(int status) = 0;
    virtual void OnQosEvent(int32_t eventId, int32_t tvCount, const QosTv *tvList) = 0;
    virtual void OnFrameStats(const StreamSendStats *data) = 0;
    virtual void OnRippleStats(const TrafficStats *data) = 0;
};

class IStreamManager {
public:
    IStreamManager() = default;
    virtual ~IStreamManager() = default;

    virtual bool PrepareEnvironment(const std::string &pkgName)
    {
        static_cast<void>(pkgName);
        return true;
    }
    virtual void DestroyEnvironment(const std::string &pkgName)
    {
        static_cast<void>(pkgName);
    }

    static std::shared_ptr<IStreamManager> GetInstance(std::shared_ptr<IStreamMsgManager> msgManager,
        std::shared_ptr<IStreamManagerListener> streamListener);

    virtual int CreateStreamClientChannel(IpAndPort &local, IpAndPort remote, Proto protocol,
        int streamType, std::pair<uint8_t*, uint32_t> sessionKey) = 0; // block
    virtual int CreateStreamServerChannel(IpAndPort &local, Proto protocol,
        int streamType, std::pair<uint8_t*, uint32_t> sessionKey) = 0; // Non-block
    virtual bool DestroyStreamDataChannel() = 0;

    virtual bool Send(std::unique_ptr<IStream>) = 0;

    virtual bool SetOption(int type, const StreamAttr &value) = 0;
    virtual int32_t SetMultiLayer(const void *para) = 0;
    virtual StreamAttr GetOption(int type) const = 0;

    virtual void SetStreamRecvListener(std::shared_ptr<IStreamManagerListener> recvListener) = 0;

protected:
    // virtual bool SendAck() = 0; // ACK形式待定
};
} // namespace SoftBus
} // namespace Communication

#endif
