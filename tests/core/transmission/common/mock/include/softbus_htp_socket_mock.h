/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef TRANS_AUTH_MOCK_H
#define TRANS_AUTH_MOCK_H

#include <gmock/gmock.h>
#include "softbus_htp_socket.h"

namespace OHOS {
class SoftbusHtpSocket {
public:
    SoftbusHtpSocket() {};
    virtual ~SoftbusHtpSocket() {};

    virtual int32_t SoftBusSocketGetLocalName(int32_t socketFd, SoftBusSockAddr *addr) = 0;
    virtual int32_t SoftBusSocketAccept(int32_t socketFd, SoftBusSockAddr *addr, int32_t *acceptFd) = 0;
};

class SoftbusHtpSocketMock : public SoftbusHtpSocket {
public:
    SoftbusHtpSocketMock();
    ~SoftbusHtpSocketMock() override;

    MOCK_METHOD2(SoftBusSocketGetLocalName, int32_t (int32_t socketFd, SoftBusSockAddr *addr));
    MOCK_METHOD3(SoftBusSocketAccept, int32_t (int32_t socketFd, SoftBusSockAddr *addr, int32_t *acceptFd));
};
} // namespace OHOS
#endif // TRANS_AUTH_MOCK_H
