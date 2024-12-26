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

#include "softbus_server_stub_test_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

static void *g_softbusServerStubInterface = nullptr;
SoftbusServerStubTestInterfaceMock::SoftbusServerStubTestInterfaceMock()
{
    g_softbusServerStubInterface = reinterpret_cast<void *>(this);
}

SoftbusServerStubTestInterfaceMock::~SoftbusServerStubTestInterfaceMock()
{
    g_softbusServerStubInterface = nullptr;
}

static SoftbusServerStubTestInterface *GetSoftbusServerStubTestInterface()
{
    return reinterpret_cast<SoftbusServerStubTestInterface *>(g_softbusServerStubInterface);
}

extern "C" {
int32_t CheckTransPermission(pid_t callingUid, pid_t callingPid, const char *pkgName,
    const char *sessionName, uint32_t actions)
{
    return GetSoftbusServerStubTestInterface()->CheckTransPermission(callingUid, callingPid, pkgName,
        sessionName, actions);
}
int32_t CheckTransSecLevel(const char *mySessionName, const char *peerSessionName)
{
    return GetSoftbusServerStubTestInterface()->CheckTransSecLevel(mySessionName, peerSessionName);
}
int32_t TransGetNameByChanId(const TransInfo *info, char *pkgName, char *sessionName,
    uint16_t pkgLen, uint16_t sessionNameLen)
{
    return GetSoftbusServerStubTestInterface()->TransGetNameByChanId(info, pkgName, sessionName,
        pkgLen, sessionNameLen);
}
int32_t TransGetAppInfoByChanId(int32_t channelId, int32_t channelType, AppInfo *appInfo)
{
    return GetSoftbusServerStubTestInterface()->TransGetAppInfoByChanId(channelId, channelType, appInfo);
}
int32_t TransGetAndComparePid(pid_t pid, int32_t channelId, int32_t channelType)
{
    return GetSoftbusServerStubTestInterface()->TransGetAndComparePid(pid, channelId, channelType);
}
int32_t TransGetAndComparePidBySession(pid_t pid, const char *sessionName, int32_t sessionlId)
{
    return GetSoftbusServerStubTestInterface()->TransGetAndComparePidBySession(pid, sessionName, sessionlId);
}
int32_t LnnIpcGetAllOnlineNodeInfo(const char *pkgName, void **info, uint32_t infoTypeLen, int32_t *infoNum)
{
    return GetSoftbusServerStubTestInterface()->LnnIpcGetAllOnlineNodeInfo(pkgName, info, infoTypeLen, infoNum);
}
int32_t LnnIpcGetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen)
{
    return GetSoftbusServerStubTestInterface()->LnnIpcGetLocalDeviceInfo(pkgName, info, infoTypeLen);
}
int32_t LnnIpcGetNodeKeyInfo(const char *pkgName, const char *networkId, int32_t key,
    unsigned char *buf, uint32_t len)
{
    return GetSoftbusServerStubTestInterface()->LnnIpcGetNodeKeyInfo(pkgName, networkId, key, buf, len);
}
int32_t SoftBusCheckDynamicPermission(uint64_t tokenId)
{
    return GetSoftbusServerStubTestInterface()->SoftBusCheckDynamicPermission(tokenId);
}
int32_t LnnIpcActiveMetaNode(const MetaNodeConfigInfo *info, char *metaNodeId)
{
    return GetSoftbusServerStubTestInterface()->LnnIpcActiveMetaNode(info, metaNodeId);
}
int32_t LnnIpcDeactiveMetaNode(const char *metaNodeId)
{
    return GetSoftbusServerStubTestInterface()->LnnIpcDeactiveMetaNode(metaNodeId);
}
int32_t LnnIpcGetAllMetaNodeInfo(MetaNodeInfo *infos, int32_t *infoNum)
{
    return GetSoftbusServerStubTestInterface()->LnnIpcGetAllMetaNodeInfo(infos, infoNum);
}
int32_t TransReleaseUdpResources(int32_t channelId)
{
    return GetSoftbusServerStubTestInterface()->TransReleaseUdpResources(channelId);
}
bool CheckUidAndPid(const char *sessionName, pid_t callingUid, pid_t callingPid)
{
    return GetSoftbusServerStubTestInterface()->CheckUidAndPid(sessionName, callingUid, callingPid);
}
int32_t SoftBusCheckDmsServerPermission(uint64_t tokenId)
{
    return GetSoftbusServerStubTestInterface()->SoftBusCheckDmsServerPermission(tokenId);
}
}
}