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

#include "trans_udp_nego_test_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_transUdpNegoInterface;
TransUdpNegoInterfaceMock::TransUdpNegoInterfaceMock()
{
    g_transUdpNegoInterface = reinterpret_cast<void *>(this);
}

TransUdpNegoInterfaceMock::~TransUdpNegoInterfaceMock()
{
    g_transUdpNegoInterface = nullptr;
}

static TransUdpNegoInterface *GetTransUdpNegoInterface()
{
    return reinterpret_cast<TransUdpNegoInterface *>(g_transUdpNegoInterface);
}

extern "C" {
int32_t AuthMetaPostTransData(int64_t authId, const AuthTransData *dataInfo)
{
    return GetTransUdpNegoInterface()->AuthMetaPostTransData(authId, dataInfo);
}
}
}
