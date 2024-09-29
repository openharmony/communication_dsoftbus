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

#include "remote_object_mock.h"
#include <cstring>
#include "disc_log.h"
#include "if_softbus_client.h"
#include "securec.h"
#include "softbus_server_ipc_interface_code.h"

using testing::_;
namespace OHOS {
RemoteObjectMock::RemoteObjectMock() : IRemoteObject(std::u16string())
{
    DISC_LOGI(DISC_TEST, "construct");
}

RemoteObjectMock::~RemoteObjectMock()
{
    DISC_LOGI(DISC_TEST, "destroy");
    instance_ = nullptr;
}

void RemoteObjectMock::SetSelf(const sptr<RemoteObjectMock> &self)
{
    instance_ = self;
}

void RemoteObjectMock::Destroy()
{
    instance_ = nullptr;
}

void RemoteObjectMock::SetupStub(const sptr<RemoteObjectMock> &self)
{
    SetSelf(self);
}

sptr<RemoteObjectMock> RemoteObjectMock::Get()
{
    return instance_;
}

bool RemoteObjectMock::GetResult(uint32_t code, const DeviceInfo *deviceInfo, int32_t publishId, int32_t subscribeId,
                                 int32_t reason)
{
    if (descriptor_ != ISoftBusClient::GetDescriptor()) {
        DISC_LOGE(DISC_TEST, "descriptor mismatch");
        return false;
    }
    if (deviceInfo != nullptr) {
        if (memcmp(deviceInfo, &deviceInfo_, sizeof(DeviceInfo)) != 0) {
            DISC_LOGE(DISC_TEST, "device info mismatch");
            return false;
        }
    }
    if (code != code_) {
        DISC_LOGE(DISC_TEST, "code mismatch");
        return false;
    }
    if (publishId != publishId_) {
        DISC_LOGE(DISC_TEST, "publish id mismatch");
        return false;
    }
    if (subscribeId != subscribeId_) {
        DISC_LOGE(DISC_TEST, "subscribe id mismatch");
        return false;
    }
    if (reason != reason_) {
        DISC_LOGE(DISC_TEST, "reason mismatch");
        return false;
    }
    return true;
}