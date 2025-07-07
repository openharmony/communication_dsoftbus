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

#ifndef TRANS_SERVICE_MOCK_H
#define TRANS_SERVICE_MOCK_H

#include <gmock/gmock.h>

#include "socket.h"
#include "softbus_error_code.h"
#include "trans_type.h"

namespace OHOS {
class TransServiceInterface {
public:
    TransServiceInterface() {};
    virtual ~TransServiceInterface() {};

    virtual int32_t GetDefaultConfigType(int32_t channelType, int32_t businessType) = 0;
    virtual int32_t ClientBind(
        int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener, bool isAsync) = 0;
};

class TransServiceInterfaceMock : public TransServiceInterface {
public:
    TransServiceInterfaceMock();
    ~TransServiceInterfaceMock() override;

    MOCK_METHOD2(GetDefaultConfigType, int32_t(int32_t channelType, int32_t businessType));
    MOCK_METHOD5(ClientBind, int32_t(
        int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener, bool isAsync));
};

} // namespace OHOS
#endif // TRANS_SERVICE_MOCK_H
