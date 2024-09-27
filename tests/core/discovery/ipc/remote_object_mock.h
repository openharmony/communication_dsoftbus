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
#ifndef REMOTE_OBJECT_MOCK_H
#define REMOTE_OBJECT_MOCK_H

#include "gmock/gmock.h"
#include "iremote_object.h"
#include "softbus_common.h"

namespace OHOS {
class RemoteObjectMock : public IRemoteObject {
public:
    static sptr<RemoteObjectMock> Get();

    RemoteObjectMock();
    ~RemoteObjectMock() override;

    int32_t GetObjectRefCount() override
    {
        return 0;
    }

    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return true;
    }

    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return true;
    }

    int32_t Dump(int32_t fd, const std::vector<std::u16string> &args) override
    {
        return 0;
    }

    static void SetSelf(const sptr<RemoteObjectMock>& self);
    static void Destroy();
    static void SetupStub(const sptr<RemoteObjectMock>& self);

    MOCK_METHOD(int32_t, SendRequest, (uint32_t, MessageParcel&, MessageParcel&, MessageOption &), (override));

    bool GetResult(uint32_t code, const DeviceInfo *deviceInfo = nullptr,
                   int32_t publishId = 0, int32_t subscribeId = 0,
                   int32_t reason = 0);

private:
    std::u16string descriptor_;
    uint32_t code_ {};
    DeviceInfo deviceInfo_ {};
    int32_t publishId_ {};
    int32_t subscribeId_ {};
    int32_t reason_ {};

    static inline sptr<RemoteObjectMock> instance_;
};
}
#endif
