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

#ifndef TRANS_LANE_COMMON_TEST_MOCK_H
#define TRANS_LANE_COMMON_TEST_MOCK_H

#include <gmock/gmock.h>

#include "bus_center_info_key.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_distributed_net_ledger_common.h"
#include "lnn_network_manager.h"
#include "softbus_app_info.h"
#include "softbus_config_type.h"
#include "softbus_def.h"

namespace OHOS {
class TransLaneCommonTestInterface {
public:
    TransLaneCommonTestInterface() {};
    virtual ~TransLaneCommonTestInterface() {};
    virtual int SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len) = 0;
    virtual struct WifiDirectManager *GetWifiDirectManager() = 0;
    virtual int32_t LnnGetOsTypeByNetworkId(const char *networkId, int32_t *osType) = 0;
    virtual int32_t LnnGetRemoteStrInfo(const char *networkId, InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info) = 0;
    virtual int32_t TransGetUidAndPid(const char *sessionName, int32_t *uid, int32_t *pid) = 0;
    virtual int32_t TransGetPkgNameBySessionName(const char *sessionName, char *pkgName, uint16_t len) = 0;
    virtual int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len) = 0;
    virtual ListenerModule LnnGetProtocolListenerModule(ProtocolType protocol, ListenerMode mode) = 0;
    virtual int32_t TransOpenUdpChannel(AppInfo *appInfo, const ConnectOption *connOpt, int32_t *channelId) = 0;
    virtual int32_t TransProxyOpenProxyChannel(AppInfo *appInfo,
        const ConnectOption *connInfo, int32_t *channelId) = 0;
    virtual int32_t TransOpenDirectChannel(AppInfo *appInfo, const ConnectOption *connInfo, int32_t *channelId) = 0;
};

class TransLaneCommonTestInterfaceMock : public TransLaneCommonTestInterface {
public:
    TransLaneCommonTestInterfaceMock();
    ~TransLaneCommonTestInterfaceMock() override;
    MOCK_METHOD3(SoftbusGetConfig, int (ConfigType type, unsigned char *val, uint32_t len));
    MOCK_METHOD0(GetWifiDirectManager, struct WifiDirectManager *());
    MOCK_METHOD2(LnnGetOsTypeByNetworkId, int32_t (const char *networkId, int32_t *osType));
    MOCK_METHOD4(LnnGetRemoteStrInfo, int32_t (const char *networkId, InfoKey key, char *info, uint32_t len));
    MOCK_METHOD3(LnnGetRemoteNodeInfoById, int32_t (const char *id, IdCategory type, NodeInfo *info));
    MOCK_METHOD3(TransGetUidAndPid, int32_t (const char *sessionName, int32_t *uid, int32_t *pid));
    MOCK_METHOD3(TransGetPkgNameBySessionName, int32_t (const char *sessionName, char *pkgName, uint16_t len));
    MOCK_METHOD3(LnnGetLocalStrInfo, int32_t (InfoKey key, char *info, uint32_t len));
    MOCK_METHOD2(LnnGetProtocolListenerModule, ListenerModule (ProtocolType protocol, ListenerMode mode));
    MOCK_METHOD3(TransOpenUdpChannel, int32_t (AppInfo *appInfo, const ConnectOption *connOpt, int32_t *channelId));
    MOCK_METHOD3(TransProxyOpenProxyChannel, int32_t (AppInfo *appInfo,
        const ConnectOption *connInfo, int32_t *channelId));
    MOCK_METHOD3(TransOpenDirectChannel, int32_t (AppInfo *appInfo, const ConnectOption *connInfo, int32_t *channelId));
};
} // namespace OHOS
#endif // TRANS_LANE_COMMON_TEST_MOCK_H
