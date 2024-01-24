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

#include "sessionserviceimpl_fuzzer.h"

#include "session.h"
#include "session_service_impl.h"

namespace OHOS {
void SessionTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int))) {
        return;
    }
    Communication::SoftBus::SessionServiceImpl sessionService;

    int flags = *(reinterpret_cast<const int*>(data));
    std::string sessionName(data, data + size);
    std::string peersessionName(data, data + size);
    std::string peerNetworkId(data, data + size);
    std::string groupId(data, data + size);

    std::shared_ptr<Communication::SoftBus::Session> session =
        sessionService.OpenSession(sessionName, peersessionName, peerNetworkId, groupId, flags);
    sessionService.CloseSession(session);

    int sessionId = *(reinterpret_cast<const int*>(data));
    sessionService.OpenSessionCallback(sessionId);
    sessionService.CloseSessionCallback(sessionId);
}

void RemovePermissionTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    Communication::SoftBus::SessionServiceImpl sessionService;
    std::string busName(data, data + size);
    sessionService.RemovePermission(busName);
}

void ReceivedCallbackTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int))) {
        return;
    }
    Communication::SoftBus::SessionServiceImpl sessionService;
    int len = *(reinterpret_cast<const int*>(data));
    sessionService.BytesReceivedCallback(size,  data, len);
    sessionService.MessageReceivedCallback(size,  data, len);
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::SessionTest(data, size);
    OHOS::RemovePermissionTest(data, size);
    OHOS::ReceivedCallbackTest(data, size);
    return 0;
}
