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
#include "if_softbus_client.h"
#include "softbus_log.h"
#include "softbus_ipc_def.h"
#include "securec.h"

using testing::_;
namespace OHOS {
RemoteObjectMock::RemoteObjectMock()
    : IRemoteObject(std::u16string())
{
    DLOGI("construct");
}

RemoteObjectMock::~RemoteObjectMock()
{
    DLOGI("destroy");
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
    EXPECT_CALL(*self, SendRequest(CLIENT_DISCOVERY_DEVICE_FOUND, _, _, _))
        .WillRepeatedly(ActionOfSendRequestForOnDeviceFound);
    EXPECT_CALL(*self, SendRequest(CLIENT_DISCOVERY_SUCC, _, _, _))
        .WillRepeatedly(ActionOfSendRequestForOnDiscoverySuccess);
    EXPECT_CALL(*self, SendRequest(CLIENT_DISCOVERY_FAIL, _, _, _))
        .WillRepeatedly(ActionOfSendRequestForOnDiscoveryFailed);
    EXPECT_CALL(*self, SendRequest(CLIENT_PUBLISH_SUCC, _, _, _))
        .WillRepeatedly(ActionOfSendRequestForOnPublishSuccess);
    EXPECT_CALL(*self, SendRequest(CLIENT_PUBLISH_FAIL, _, _, _))
        .WillRepeatedly(ActionOfSendRequestForOnPublishFail);
}

sptr<RemoteObjectMock> RemoteObjectMock::Get()
{
    return instance_;
}

bool RemoteObjectMock::GetResult(uint32_t code, const DeviceInfo *deviceInfo, int publishId, int subscribeId,
                                 int reason)
{
    if (descriptor_ != ISoftBusClient::GetDescriptor()) {
        DLOGE("descriptor mismatch");
        return false;
    }
    if (deviceInfo != nullptr) {
        if (memcmp(deviceInfo, &deviceInfo_, sizeof(DeviceInfo)) != 0) {
            DLOGE("device info mismatch");
            return false;
        }
    }
    if (code != code_) {
        DLOGE("code mismatch");
        return false;
    }
    if (publishId != publishId_) {
        DLOGE("publish id mismatch");
        return false;
    }
    if (subscribeId != subscribeId_) {
        DLOGE("subscribe id mismatch");
        return false;
    }
    if (reason != reason_) {
        DLOGE("reason mismatch");
        return false;
    }
    return true;
}

int RemoteObjectMock::ActionOfSendRequestForOnDeviceFound(uint32_t code, MessageParcel &data, MessageParcel &reply,
                                                          MessageOption &option)
{
    DLOGI("code=%u", code);
    Get()->code_ = code;
    Get()->descriptor_ = data.ReadInterfaceToken();
    return memcpy_s(&Get()->deviceInfo_, sizeof(DeviceInfo), data.ReadBuffer(sizeof(DeviceInfo)), sizeof(DeviceInfo));
}

int RemoteObjectMock::ActionOfSendRequestForOnDiscoveryFailed(uint32_t code, MessageParcel &data, MessageParcel &reply,
                                                              MessageOption &option)
{
    DLOGI("code=%u", code);
    Get()->code_ = code;
    Get()->descriptor_ = data.ReadInterfaceToken();
    Get()->subscribeId_ = data.ReadInt32();
    Get()->reason_ = data.ReadInt32();
    return 0;
}

int RemoteObjectMock::ActionOfSendRequestForOnDiscoverySuccess(uint32_t code, MessageParcel &data, MessageParcel &reply,
                                                               MessageOption &option)
{
    DLOGI("code=%u", code);
    Get()->code_ = code;
    Get()->descriptor_ = data.ReadInterfaceToken();
    Get()->subscribeId_ = data.ReadInt32();
    return 0;
}

int RemoteObjectMock::ActionOfSendRequestForOnPublishSuccess(uint32_t code, MessageParcel &data, MessageParcel &reply,
                                                             MessageOption &option)
{
    DLOGI("code=%u", code);
    Get()->code_ = code;
    Get()->descriptor_ = data.ReadInterfaceToken();
    Get()->publishId_ = data.ReadInt32();
    return 0;
}

int RemoteObjectMock::ActionOfSendRequestForOnPublishFail(uint32_t code, MessageParcel &data, MessageParcel &reply,
                                                          MessageOption &option)
{
    DLOGI("code=%u", code);
    Get()->code_ = code;
    Get()->descriptor_ = data.ReadInterfaceToken();
    Get()->publishId_ = data.ReadInt32();
    Get()->reason_ = data.ReadInt32();
    return 0;
}
}