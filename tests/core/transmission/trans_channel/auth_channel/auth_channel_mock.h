/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef AUTH_CHANNEL_MOCK_H
#define AUTH_CHANNEL_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "lnn_settingdata_event_monitor.h"

namespace OHOS {
class AuthChannelInterface {
public:
    AuthChannelInterface() {};
    virtual ~AuthChannelInterface() {};
    virtual int32_t LnnInitGetDeviceName(LnnDeviceNameHandler handler) = 0;
    virtual int32_t LnnGetSettingDeviceName(char *deviceName, uint32_t len) = 0;
};

class AuthChannelInterfaceMock : public AuthChannelInterface {
public:
    AuthChannelInterfaceMock();
    ~AuthChannelInterfaceMock() override;
    MOCK_METHOD1(LnnInitGetDeviceName, int32_t (LnnDeviceNameHandler));
    MOCK_METHOD2(LnnGetSettingDeviceName, int32_t (char *, uint32_t));
    static int32_t ActionOfLnnInitGetDeviceName(LnnDeviceNameHandler handler);
    static inline LnnDeviceNameHandler g_deviceNameHandler;
};
} // namespace OHOS
#endif // AUTH_CHANNEL_MOCK_H