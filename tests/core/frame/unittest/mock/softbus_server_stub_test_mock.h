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

#ifndef SOFTBUS_SERVER_STUB_TEST_MOCK_H
#define SOFTBUS_SERVER_STUB_TEST_MOCK_H

#include <gmock/gmock.h>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "ipc_object_stub.h"
#include "lnn_bus_center_ipc.h"
#include "message_option.h"
#include "message_parcel.h"
#include "softbus_access_token_adapter.h"
#include "softbus_app_info.h"
#include "softbus_permission.h"
#include "softbus_trans_def.h"
#include "trans_channel_manager.h"

namespace OHOS {
class SoftbusServerStubTestInterface {
public:
    SoftbusServerStubTestInterface() {};
    virtual ~SoftbusServerStubTestInterface() {};
    virtual int32_t CheckTransPermission(pid_t callingUid, pid_t callingPid, const char *pkgName,
        const char *sessionName, uint32_t actions) = 0;
    virtual int32_t CheckTransSecLevel(const char *mySessionName, const char *peerSessionName) = 0;
    virtual int32_t TransGetNameByChanId(const TransInfo *info, char *pkgName, char *sessionName,
        uint16_t pkgLen, uint16_t sessionNameLen) = 0;
    virtual int32_t TransGetAppInfoByChanId(int32_t channelId, int32_t channelType, AppInfo *appInfo) = 0;
    virtual int32_t TransGetAndComparePid(pid_t pid, int32_t channelId, int32_t channelType) = 0;
    virtual int32_t TransGetAndComparePidBySession(pid_t pid, const char *sessionName, int32_t sessionlId) = 0;
    virtual int32_t LnnIpcGetAllOnlineNodeInfo(const char *pkgName, void **info,
        uint32_t infoTypeLen, int32_t *infoNum) = 0;
    virtual int32_t LnnIpcGetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen) = 0;
    virtual int32_t LnnIpcGetNodeKeyInfo(const char *pkgName, const char *networkId, int32_t key,
        unsigned char *buf, uint32_t len) = 0;
    virtual int32_t SoftBusCheckDynamicPermission(uint64_t tokenId) = 0;
    virtual int32_t LnnIpcActiveMetaNode(const MetaNodeConfigInfo *info, char *metaNodeId) = 0;
    virtual int32_t LnnIpcDeactiveMetaNode(const char *metaNodeId) = 0;
    virtual int32_t LnnIpcGetAllMetaNodeInfo(MetaNodeInfo *infos, int32_t *infoNum) = 0;
    virtual int32_t TransReleaseUdpResources(int32_t channelId) = 0;
    virtual bool CheckUidAndPid(const char *sessionName, pid_t callingUid, pid_t callingPid) = 0;
    virtual int32_t SoftBusCheckDmsServerPermission(uint64_t tokenId) = 0;
};
class SoftbusServerStubTestInterfaceMock : public SoftbusServerStubTestInterface {
public:
    SoftbusServerStubTestInterfaceMock();
    ~SoftbusServerStubTestInterfaceMock() override;
    MOCK_METHOD5(CheckTransPermission, int32_t (pid_t callingUid, pid_t callingPid, const char *pkgName,
        const char *sessionName, uint32_t actions));
    MOCK_METHOD2(CheckTransSecLevel, int32_t (const char *mySessionName, const char *peerSessionName));
    MOCK_METHOD5(TransGetNameByChanId, int32_t (const TransInfo *info, char *pkgName, char *sessionName,
        uint16_t pkgLen, uint16_t sessionNameLen));
    MOCK_METHOD3(TransGetAppInfoByChanId, int32_t (int32_t channelId, int32_t channelType, AppInfo *appInfo));
    MOCK_METHOD3(TransGetAndComparePid, int32_t (pid_t pid, int32_t channelId, int32_t channelType));
    MOCK_METHOD3(TransGetAndComparePidBySession, int32_t (pid_t pid, const char *sessionName, int32_t sessionlId));
    MOCK_METHOD4(LnnIpcGetAllOnlineNodeInfo, int32_t (const char *pkgName, void **info,
        uint32_t infoTypeLen, int32_t *infoNum));
    MOCK_METHOD3(LnnIpcGetLocalDeviceInfo, int32_t (const char *pkgName, void *info, uint32_t infoTypeLen));
    MOCK_METHOD5(LnnIpcGetNodeKeyInfo, int32_t (const char *pkgName, const char *networkId, int32_t key,
        unsigned char *buf, uint32_t len));
    MOCK_METHOD1(SoftBusCheckDynamicPermission, int32_t (uint64_t tokenId));
    MOCK_METHOD2(LnnIpcActiveMetaNode, int32_t (const MetaNodeConfigInfo *info, char *metaNodeId));
    MOCK_METHOD1(LnnIpcDeactiveMetaNode, int32_t (const char *metaNodeId));
    MOCK_METHOD2(LnnIpcGetAllMetaNodeInfo, int32_t (MetaNodeInfo *infos, int32_t *infoNum));
    MOCK_METHOD1(TransReleaseUdpResources, int32_t (int32_t channelId));
    MOCK_METHOD3(CheckUidAndPid, bool (const char *sessionName, pid_t callingUid, pid_t callingPid));
    MOCK_METHOD1(SoftBusCheckDmsServerPermission, int32_t (uint64_t tokenId));
};
}

#endif