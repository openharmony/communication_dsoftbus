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

#ifndef TRANS_MANAGER_MOCK_H
#define TRANS_MANAGER_MOCK_H

#include <gmock/gmock.h>
#include "auth_interface.h"
#include "bus_center_info_key.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_lane_interface.h"
#include "lnn_node_info.h"
#include "softbus_app_info.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_trans_def.h"

namespace OHOS {
class TransManagerInterface {
public:
    TransManagerInterface() {};
    virtual ~TransManagerInterface() {};
    virtual int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info) = 0;
    virtual int32_t AuthCheckSessionKeyValidByConnInfo(const char *networkId, const AuthConnInfo *connInfo) = 0;
    virtual int32_t ConnGetConnectionInfo(uint32_t connectionId, ConnectionInfo *info) = 0;
    virtual uint64_t TransACLGetFirstTokenID() = 0;
    virtual int32_t TransCommonGetAppInfo(const SessionParam *param, AppInfo *appInfo) = 0;
    virtual int32_t TransAsyncGetLaneInfo(
        const SessionParam *param, uint32_t *laneHandle, uint32_t callingTokenId, int64_t timeStart) = 0;
    virtual int32_t TransGetLaneInfo(const SessionParam *param, LaneConnInfo *connInfo, uint32_t *laneHandle) = 0;
    virtual int32_t TransGetConnectOptByConnInfo(const LaneConnInfo *info, ConnectOption *connOpt) = 0;
    virtual int32_t TransOpenChannelProc(
        ChannelType type, AppInfo *appInfo, const ConnectOption *connOpt, int32_t *channelId) = 0;
    virtual int32_t TransProxyGetConnOptionByChanId(int32_t channelId, ConnectOption *connOpt) = 0;
    virtual int32_t TransGetUidAndPid(const char *sessionName, int32_t *uid, int32_t *pid) = 0;
    virtual int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t TransGetPkgNameBySessionName(const char *sessionName, char *pkgName, uint16_t len) = 0;
    virtual int32_t TransCommonGetLocalConfig(int32_t channelType, int32_t businessType, uint32_t *len) = 0;
};
class TransManagerInterfaceMock : public TransManagerInterface {
public:
    TransManagerInterfaceMock();
    ~TransManagerInterfaceMock() override;
    MOCK_METHOD3(LnnGetRemoteNodeInfoById, int32_t (const char *, IdCategory, NodeInfo *));
    MOCK_METHOD2(AuthCheckSessionKeyValidByConnInfo, int32_t (const char *, const AuthConnInfo *));
    MOCK_METHOD2(ConnGetConnectionInfo, int32_t (uint32_t, ConnectionInfo *));
    MOCK_METHOD0(TransACLGetFirstTokenID, uint64_t ());
    MOCK_METHOD2(TransCommonGetAppInfo, int32_t (const SessionParam *, AppInfo *));
    MOCK_METHOD4(TransAsyncGetLaneInfo, int32_t (const SessionParam *, uint32_t *, uint32_t, int64_t));
    MOCK_METHOD3(TransGetLaneInfo, int32_t (const SessionParam *, LaneConnInfo *, uint32_t *));
    MOCK_METHOD2(TransGetConnectOptByConnInfo, int32_t (const LaneConnInfo *, ConnectOption *));
    MOCK_METHOD4(TransOpenChannelProc, int32_t (ChannelType, AppInfo *, const ConnectOption *, int32_t *));
    MOCK_METHOD2(TransProxyGetConnOptionByChanId, int32_t (int32_t, ConnectOption *));
    MOCK_METHOD3(TransGetUidAndPid, int32_t (const char *, int32_t *, int32_t *));
    MOCK_METHOD3(LnnGetLocalStrInfo, int32_t (InfoKey, char *, uint32_t));
    MOCK_METHOD3(TransGetPkgNameBySessionName, int32_t (const char *, char *, uint16_t));
    MOCK_METHOD3(TransCommonGetLocalConfig, int32_t (int32_t, int32_t, uint32_t *));
};
} // namespace OHOS
#endif // TRANS_MANAGER_MOCK_H
