/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "sessionimpl_fuzzer.h"

#include "session_impl.h"

namespace OHOS {
void SessionTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int))) {
        return;
    }
    Communication::SoftBus::SessionImpl session;

    int sessionId = *(reinterpret_cast<const int*>(data));
    session.SetSessionId(sessionId);
    session.GetSessionId();

    std::string sessionName(data, data + size);
    session.SetMySessionName(sessionName);
    session.SetPeerSessionName(sessionName);
}

void SetOpeTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(pid_t)) || (size < sizeof(uid_t))) {
        return;
    }
    Communication::SoftBus::SessionImpl session;
    std::string deviceId(data, data + size);
    session.SetPeerDeviceId(deviceId);
    session.SetDeviceId(deviceId);
    session.SetIsServer(true);

    uid_t peerUid = *reinterpret_cast<const uid_t *>(data);
    pid_t peerPid = *reinterpret_cast<const pid_t *>(data);
    session.SetPeerUid(peerUid);
    session.SetPeerPid(peerPid);

    session.GetChannelId();
}

void SendBytesTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    Communication::SoftBus::SessionImpl session;
    session.SendBytes(data, size);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::SessionTest(data, size);
    OHOS::SetOpeTest(data, size);
    OHOS::SendBytesTest(data, size);
    return 0;
}
