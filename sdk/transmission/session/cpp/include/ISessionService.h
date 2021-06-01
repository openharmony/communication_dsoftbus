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

#ifndef ISESSION_SERVICE_H
#define ISESSION_SERVICE_H

#include <shared_mutex>
#include "CommDefs.h"
#include "ISessionListener.h"
#include "Session.h"

namespace Communication {
namespace SoftBus {
class COMM_EXPORT ISessionService {
public:
    static std::shared_ptr<ISessionService> GetInstance();

    ISessionService() = default;
    virtual ~ISessionService() = default;

    virtual int CreateSessionServer(const std::string &pkgName, const std::string &sessionName,
        std::shared_ptr<ISessionListener> listener) = 0;

    virtual int RemoveSessionServer(const std::string &pkgName, const std::string &sessionName) = 0;

    virtual std::shared_ptr<Session> OpenSession(const std::string &mySessionName, const std::string &peerSessionName,
        const std::string &peerDeviceId, const std::string &groupId, int flags) = 0;

    virtual int CloseSession(std::shared_ptr<Session> session) = 0;

    virtual int GrantPermission(int uid, int pid, const std::string &busName) = 0;

private:
    NO_COPY_AND_ASSIGN(ISessionService)
    static std::shared_ptr<ISessionService> instance_;
    static std::shared_mutex instanceMutex_;
};
} // namespace SoftBus
} // namespace Communication

#endif // ISESSION_SERVICE_H
