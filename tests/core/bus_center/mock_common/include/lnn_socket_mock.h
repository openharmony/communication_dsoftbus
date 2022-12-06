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

#ifndef DSOFTBUS_LNN_SOCKET_MOCK_H
#define DSOFTBUS_LNN_SOCKET_MOCK_H

#include "softbus_socket.h"
#include <gmock/gmock.h>

namespace OHOS {
class LnnSocketInterface {
public:
    LnnSocketInterface() {};
    virtual ~LnnSocketInterface() {};
    virtual int32_t ConnOpenClientSocket(const ConnectOption *option, const char *bindAddr, bool isNonBlock) = 0;
};

class LnnSocketInterfaceMock : public LnnSocketInterface {
public:
    LnnSocketInterfaceMock();
    ~LnnSocketInterfaceMock() override;

    MOCK_METHOD3(ConnOpenClientSocket, int32_t(const ConnectOption *, const char *, bool));
};
} // namespace OHOS
#endif // DSOFTBUS_LNN_SOCKET_MOCK_H