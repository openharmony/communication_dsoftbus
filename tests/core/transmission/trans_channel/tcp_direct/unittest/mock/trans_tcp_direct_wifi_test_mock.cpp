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

#include "trans_tcp_direct_wifi_test_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_transTcpDirectWifiInterface;
TransTcpDirectWifiInterfaceMock::TransTcpDirectWifiInterfaceMock()
{
    g_transTcpDirectWifiInterface = reinterpret_cast<void *>(this);
}

TransTcpDirectWifiInterfaceMock::~TransTcpDirectWifiInterfaceMock()
{
    g_transTcpDirectWifiInterface = nullptr;
}

static TransTcpDirectWifiInterface *GetTransTcpDirectWifiInterface()
{
    return reinterpret_cast<TransTcpDirectWifiInterface *>(g_transTcpDirectWifiInterface);
}

extern "C" {
SessionConn *CreateNewSessinConn(ListenerModule module, bool isServerSid)
{
    return GetTransTcpDirectWifiInterface()->CreateNewSessinConn(module, isServerSid);
}

ListenerModule LnnGetProtocolListenerModule(ProtocolType protocol, ListenerMode mode)
{
    return GetTransTcpDirectWifiInterface()->LnnGetProtocolListenerModule(protocol, mode);
}

void AuthGetLatestIdByUuid(const char *uuid, AuthLinkType type, bool isMeta, AuthHandle *authHandle)
{
    return GetTransTcpDirectWifiInterface()->AuthGetLatestIdByUuid(uuid, type, isMeta, authHandle);
}

ListenerModule GetModuleByHmlIp(const char *ip)
{
    return GetTransTcpDirectWifiInterface()->GetModuleByHmlIp(ip);
}

int32_t TransSrvAddDataBufNode(int32_t channelId, int32_t fd)
{
    return GetTransTcpDirectWifiInterface()->TransSrvAddDataBufNode(channelId, fd);
}

int32_t TransTdcAddSessionConn(SessionConn *conn)
{
    return GetTransTcpDirectWifiInterface()->TransTdcAddSessionConn(conn);
}

int32_t ConnOpenClientSocket(const ConnectOption *option, const char *bindAddr, bool isNonBlock)
{
    return GetTransTcpDirectWifiInterface()->ConnOpenClientSocket(option, bindAddr, isNonBlock);
}

int32_t AddTrigger(ListenerModule module, int32_t fd, TriggerType trigger)
{
    return GetTransTcpDirectWifiInterface()->AddTrigger(module, fd, trigger);
}
}
}
