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

#include "trans_service_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

void *g_serviceInterface = nullptr;

TransServiceInterfaceMock::TransServiceInterfaceMock()
{
    g_serviceInterface = reinterpret_cast<void *>(this);
}

TransServiceInterfaceMock::~TransServiceInterfaceMock()
{
    g_serviceInterface = nullptr;
}

static TransServiceInterface *GetServiceInterface()
{
    return reinterpret_cast<TransServiceInterface *>(g_serviceInterface);
}

#ifdef __cplusplus
extern "C" {
#endif

int32_t GetDefaultConfigType(int32_t channelType, int32_t businessType)
{
    return GetServiceInterface()->GetDefaultConfigType(channelType, businessType);
}

int32_t ClientBind(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener, bool isAsync)
{
    return GetServiceInterface()->ClientBind(socket, qos, qosCount, listener, isAsync);
}
#ifdef __cplusplus
}
#endif
}
