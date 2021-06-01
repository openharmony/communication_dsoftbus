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

#include "session_impl.h"

#include "session.h"
#include "session_mock.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

namespace Communication {
namespace SoftBus {
SessionImpl::SessionImpl() : sessionId_(-1), isServer_(false), peerUid_(-1), peerPid_(-1) {}

int64_t SessionImpl::GetChannelId() const
{
    return sessionId_;
}

void SessionImpl::SetSessionId(int sessionId)
{
    sessionId_ = sessionId;
}

int SessionImpl::GetSessionId() const
{
    return sessionId_;
}

void SessionImpl::SetMySessionName(const std::string &name)
{
    sessionName_ = name;
}

const std::string &SessionImpl::GetMySessionName() const
{
    return sessionName_;
}

void SessionImpl::SetPeerSessionName(const std::string &name)
{
    peerSessionName_ = name;
}

const std::string &SessionImpl::GetPeerSessionName() const
{
    return peerSessionName_;
}

void SessionImpl::SetPeerDeviceId(const std::string &name)
{
    peerDeviceId_ = name;
}

const std::string &SessionImpl::GetPeerDeviceId() const
{
    return peerDeviceId_;
}


void SessionImpl::SetDeviceId(const std::string &name)
{
    deviceId_ = name;
}

void SessionImpl::SetIsServer(bool isServer)
{
    isServer_ = isServer;
}

void SessionImpl::SetPeerUid(uid_t peerUid)
{
    peerUid_ = peerUid;
}

void SessionImpl::SetPeerPid(pid_t peerPid)
{
    peerPid_ = peerPid;
}

const std::string &SessionImpl::GetDeviceId() const
{
    return deviceId_;
}

uid_t SessionImpl::GetPeerUid() const
{
    return peerUid_;
}

pid_t SessionImpl::GetPeerPid() const
{
    return peerPid_;
}

bool SessionImpl::IsServerSide() const
{
    return isServer_;
}

int SessionImpl::SendBytes(const void *buf, ssize_t len) const
{
    if (buf == nullptr || len <= 0 || len > MAX_BYTES_LENGTH) {
        LOG_ERR("Invalid params");
        return SOFTBUS_ERR;
    }
    return SendBytesInner(sessionId_, buf, len);
}
} // namespace SoftBus
} // namespace Communication
