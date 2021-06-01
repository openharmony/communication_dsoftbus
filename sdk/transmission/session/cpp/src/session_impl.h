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

#ifndef SESSION_IMPL_H
#define SESSION_IMPL_H

#include <cstdint>
#include <list>
#include <memory>
#include <string>
#include <unistd.h>
#include "CommDefs.h"
#include "ISessionListener.h"

namespace Communication {
namespace SoftBus {
class SessionImpl : public std::enable_shared_from_this<SessionImpl>, public Session {
public:
    static constexpr int TYPE_MSG = 1;

    static constexpr int TYPE_BYTES = 2;

    static constexpr int TYPE_FILE = 4;

    SessionImpl();

    ~SessionImpl() override = default;

    int GetSessionId() const override;

    void SetSessionId(int sessionId) override;

    void SetMySessionName(const std::string &name) override;

    const std::string &GetMySessionName() const override;

    void SetPeerSessionName(const std::string &name) override;

    const std::string &GetPeerSessionName() const override;

    void SetPeerDeviceId(const std::string &name) override;

    const std::string &GetPeerDeviceId() const override;

    const std::string &GetDeviceId() const override;

    void SetDeviceId(const std::string &name) override;

    void SetIsServer(bool isServer) override;

    void SetPeerUid(uid_t peerUid) override;

    void SetPeerPid(pid_t peerPid) override;

    int64_t GetChannelId() const override;

    uid_t GetPeerUid() const override;

    pid_t GetPeerPid() const override;

    bool IsServerSide() const override;

    int SendBytes(const void *buf, ssize_t len) const override;

private:
    NO_COPY_AND_ASSIGN(SessionImpl)

    const int MAX_BYTES_LENGTH = 128 * 1024 * 1024;
    const std::string nullString_ = "";
    const std::string noSession_ = "[Session]null";

    int sessionId_;
    std::string sessionName_;
    std::string peerSessionName_;
    std::string deviceId_;
    std::string peerDeviceId_;
    bool isServer_;
    uid_t peerUid_;
    pid_t peerPid_;
};
} // namespace SoftBus
} // namespace Communication

#endif // SESSION_IMPL_H
