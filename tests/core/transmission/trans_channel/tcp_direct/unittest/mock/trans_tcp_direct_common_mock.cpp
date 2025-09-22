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

#include "trans_tcp_direct_common_mock.h"

#include "auth_interface_struct.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_transTcpDirectCommonInterface;
TransTcpDirectCommonInterfaceMock::TransTcpDirectCommonInterfaceMock()
{
    g_transTcpDirectCommonInterface = reinterpret_cast<void *>(this);
}

TransTcpDirectCommonInterfaceMock::~TransTcpDirectCommonInterfaceMock()
{
    g_transTcpDirectCommonInterface = nullptr;
}

static TransTcpDirectCommonInterface *GetTransServerTcpDirectInterface()
{
    return reinterpret_cast<TransTcpDirectCommonInterface *>(g_transTcpDirectCommonInterface);
}

extern "C" {
int32_t AuthMetaPostTransData(int64_t authId, const AuthTransData *dataInfo)
{
    return GetTransServerTcpDirectInterface()->AuthMetaPostTransData(authId, dataInfo);
}
int32_t AuthMetaGetServerSide(int64_t authId, bool *isServer)
{
    return GetTransServerTcpDirectInterface()->AuthMetaGetServerSide(authId, isServer);
}

int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size)
{
    return GetTransServerTcpDirectInterface()->AuthGetDeviceUuid(authId, uuid, size);
}
 
int32_t LnnGetOsTypeByNetworkId(const char *networkId, int32_t *osType)
{
    return GetTransServerTcpDirectInterface()->LnnGetOsTypeByNetworkId(networkId, osType);
}
 
int32_t AuthMetaGetLocalIpByMetaNodeIdPacked(const char *metaNodeId, char *localIp, int32_t len)
{
    return GetTransServerTcpDirectInterface()->AuthMetaGetLocalIpByMetaNodeIdPacked(metaNodeId, localIp, len);
}
}
}
