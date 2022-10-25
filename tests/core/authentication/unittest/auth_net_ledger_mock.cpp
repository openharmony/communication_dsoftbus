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

#include "auth_net_ledger_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_netLedgerinterface;
AuthNetLedgertInterfaceMock::AuthNetLedgertInterfaceMock()
{
    g_netLedgerinterface = reinterpret_cast<void *>(this);
}

AuthNetLedgertInterfaceMock::~AuthNetLedgertInterfaceMock()
{
    g_netLedgerinterface = nullptr;
}

static AuthNetLedgerInterface *GetNetLedgerInterface()
{
    return reinterpret_cast<AuthNetLedgertInterfaceMock *>(g_netLedgerinterface);
}

extern "C" {
int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return GetNetLedgerInterface()->LnnGetLocalStrInfo(key, info, len);
}

int32_t LnnDeleteSpecificTrustedDevInfo(const char *udid)
{
    return GetNetLedgerInterface()->LnnDeleteSpecificTrustedDevInfo(udid);
}

const NodeInfo *LnnGetLocalNodeInfo(void)
{
    return GetNetLedgerInterface()->LnnGetLocalNodeInfo();
}

int32_t LnnGetAuthPort(const NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnGetAuthPort(info);
}

int32_t LnnGetSessionPort(const NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnGetSessionPort(info);
}

int32_t LnnGetProxyPort(const NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnGetProxyPort(info);
}

const char *LnnGetBtMac(const NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnGetBtMac(info);
}

const char *LnnGetDeviceName(const DeviceBasicInfo *info)
{
    return GetNetLedgerInterface()->LnnGetDeviceName(info);
}

char *LnnConvertIdToDeviceType(uint16_t typeId)
{
    return GetNetLedgerInterface()->LnnConvertIdToDeviceType(typeId);
}

const char *LnnGetDeviceUdid(const NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnGetDeviceUdid(info);
}

int32_t LnnGetP2pRole(const NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnGetP2pRole(info);
}

const char *LnnGetP2pMac(const NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnGetP2pMac(info);
}

uint64_t LnnGetSupportedProtocols(const NodeInfo *info)
{
    return GetNetLedgerInterface()->LnnGetSupportedProtocols(info);
}

int32_t LnnConvertDeviceTypeToId(const char *deviceType, uint16_t *typeId)
{
    return GetNetLedgerInterface()->LnnConvertDeviceTypeToId(deviceType, typeId);
}

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    return GetNetLedgerInterface()->LnnGetLocalNumInfo(key, info);
}
}
}