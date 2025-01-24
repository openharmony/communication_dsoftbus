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
#include "lnn_net_builder.h"

namespace OHOS {
class AuthChannelInterface {
public:
    AuthChannelInterface() {};
    virtual ~AuthChannelInterface() {};
    virtual int32_t LnnServerJoinExt(ConnectionAddr *addr, LnnServerJoinExtCallBack *callback) = 0;
};

class AuthChannelInterfaceMock : public AuthChannelInterface {
public:
    AuthChannelInterfaceMock();
    ~AuthChannelInterfaceMock() override;
    MOCK_METHOD2(LnnServerJoinExt, int32_t (ConnectionAddr *, LnnServerJoinExtCallBack *));
};
} // namespace OHOS
#endif // AUTH_CHANNEL_MOCK_H