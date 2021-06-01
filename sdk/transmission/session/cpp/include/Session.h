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

#ifndef SESSION_H
#define SESSION_H

#include <cstdint>
#include <string>
#include <unistd.h>
#include "CommDefs.h"

namespace Communication {
namespace SoftBus {
class COMM_EXPORT Session {
public:
    enum {
        TYPE_MESSAGE = 0x01,
        TYPE_BYTES = 0x02,
        TYPE_FILE = 0x04,
        TYPE_STREAM = 0x08,
    };

    enum RouteType {
        WIFI_STA = 1,
        WIFI_P2P = 2,
        BT_BR = 3,
        BT_BLE = 4,
        LOOPBACK = 5,
    };

    enum SessionStatus {
        INIT,
        OPENING,
        OPENED,
        CONNECTING,
        CONNECTED,
        CLOSING,
        CLOSED,
    };

    Session() = default;
    virtual ~Session() = default;

    virtual const std::string &GetMySessionName() const = 0;

    virtual const std::string &GetPeerSessionName() const = 0;

    virtual const std::string &GetDeviceId() const = 0;

    virtual const std::string &GetPeerDeviceId() const = 0;

    virtual int64_t GetChannelId() const = 0;

    virtual uid_t GetPeerUid() const = 0;

    virtual pid_t GetPeerPid() const = 0;

    virtual bool IsServerSide() const = 0;

    virtual int SendBytes(const void *buf, ssize_t len) const = 0;

    virtual int GetSessionId() const = 0;

    virtual void SetSessionId(int sessionId) = 0;

    virtual void SetMySessionName(const std::string &name) = 0;

    virtual void SetPeerSessionName(const std::string &name) = 0;

    virtual void SetPeerDeviceId(const std::string &name) = 0;

    virtual void SetDeviceId(const std::string &name) = 0;

    virtual void SetIsServer(bool isServer) = 0;

    virtual void SetPeerUid(uid_t peerUid) = 0;

    virtual void SetPeerPid(pid_t peerPid) = 0;

private:
    NO_COPY_AND_ASSIGN(Session)
};
} // namespace SoftBus
} // namespace Communication

#endif // SESSION_H
