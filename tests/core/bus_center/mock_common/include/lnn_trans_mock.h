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

#ifndef LNN_TRANS_MOCK_H
#define LNN_TRANS_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "softbus_transmission_interface.h"

namespace OHOS {
class LnnTransInterface {
public:
    LnnTransInterface() {};
    virtual ~LnnTransInterface() {};

    virtual int32_t TransRegisterNetworkingChannelListener(const INetworkingListener *listener) = 0;
    virtual int32_t TransOpenNetWorkingChannel(const char *sessionName, const char *peerNetworkId) = 0;
    virtual int32_t TransSendNetworkingMessage(
        int32_t channelId, const char *data, uint32_t dataLen, int32_t priority) = 0;
    virtual int32_t TransCloseNetWorkingChannel(int32_t channelId) = 0;
};

class LnnTransInterfaceMock : public LnnTransInterface {
public:
    LnnTransInterfaceMock();
    ~LnnTransInterfaceMock() override;
    MOCK_METHOD1(TransRegisterNetworkingChannelListener, int(const INetworkingListener *));
    MOCK_METHOD2(TransOpenNetWorkingChannel, int32_t(const char *, const char *));
    MOCK_METHOD4(TransSendNetworkingMessage, int32_t(int32_t, const char *, uint32_t, int32_t));
    MOCK_METHOD1(TransCloseNetWorkingChannel, int32_t(int32_t));
    static int32_t ActionOfTransRegister(const INetworkingListener *listener);
    static inline const INetworkingListener *g_networkListener;
};
} // namespace OHOS
#endif // AUTH_TRANS_MOCK_H