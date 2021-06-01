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

#ifndef SESSION_SERVICE_IMPL_H
#define SESSION_SERVICE_IMPL_H

#include "Session.h"

#include <map>
#include <memory>
#include <string>
#include "ISessionListener.h"
#include "ISessionService.h"

namespace Communication {
namespace SoftBus {
class SessionServiceImpl : public ISessionService, public std::enable_shared_from_this<SessionServiceImpl> {
public:
    SessionServiceImpl() = default;

    ~SessionServiceImpl() override = default;

    int CreateSessionServer(const std::string &pkgName, const std::string &sessionName,
        std::shared_ptr<ISessionListener> listener) override;

    int RemoveSessionServer(const std::string &pkgName, const std::string &sessionName) override;

    std::shared_ptr<Session> OpenSession(const std::string &mySessionName, const std::string &peerSessionName,
        const std::string &peerDeviceId, const std::string &groupId, int flags) override;

    int CloseSession(std::shared_ptr<Session> session) override;

    int GrantPermission(int uid, int pid, const std::string &busName) override;

    int OpenSessionCallback(int sessionId);

    void CloseSessionCallback(int sessionId);

    void BytesReceivedCallback(int sessionId, const void *data, unsigned int len);

    void MessageReceivedCallback(int sessionId, const void *data, unsigned int len);

private:
    static std::mutex listenerMutex_;
    static std::map<std::string, std::shared_ptr<ISessionListener>> listenerMap_;

    static std::mutex sessionMutex_;
    static std::map<int, std::shared_ptr<Session>> sessionMap_;

    int GetSessionListener(int sessionId, std::shared_ptr<ISessionListener> &listener,
        std::shared_ptr<Session> &session);
    int CreatNewSession(int sessionId);
};
} // namespace SoftBus
} // namespace Communication

#endif // SESSION_SERVICE_IMPL_H
