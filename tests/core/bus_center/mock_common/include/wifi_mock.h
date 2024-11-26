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

#ifndef DISTRIBUTE_NET_LEDGER_MOCK_H
#define DISTRIBUTE_NET_LEDGER_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "kits/c/wifi_device.h"
#include "kits/c/wifi_error_code.h"
#include "kits/c/wifi_hid2d.h"
#include "kits/c/wifi_p2p.h"
#include "kits/c/wifi_scan_info.h"

namespace OHOS {
class WifiInterface {
public:
    WifiInterface() {};
    virtual ~WifiInterface() {};

    virtual WifiErrorCode GetDeviceConfigs(WifiDeviceConfig *result, unsigned int *size) = 0;
    virtual WifiErrorCode ConnectToDevice(const WifiDeviceConfig *config) = 0;
    virtual WifiErrorCode Scan(void) = 0;
    virtual WifiErrorCode RegisterWifiEvent(WifiEvent *event) = 0;
    virtual WifiErrorCode GetScanInfoList(WifiScanInfo *result, unsigned int *size) = 0;
    virtual WifiErrorCode UnRegisterWifiEvent(WifiEvent *event) = 0;
    virtual WifiErrorCode Hid2dGetChannelListFor5G(int32_t *chanList, int32_t len) = 0;
    virtual WifiErrorCode GetLinkedInfo(WifiLinkedInfo *info) = 0;
    virtual WifiErrorCode GetCurrentGroup(WifiP2pGroupInfo *groupInfo) = 0;
    virtual int32_t IsWifiActive(void) = 0;
    virtual WifiErrorCode GetWifiDetailState(WifiDetailState *state) = 0;
    virtual WifiErrorCode GetP2pEnableStatus(P2pState *state) = 0;
};
class WifiInterfaceMock : public WifiInterface {
public:
    WifiInterfaceMock();
    ~WifiInterfaceMock() override;

    MOCK_METHOD2(GetDeviceConfigs, WifiErrorCode(WifiDeviceConfig *, unsigned int *));
    MOCK_METHOD1(ConnectToDevice, WifiErrorCode(const WifiDeviceConfig *));
    MOCK_METHOD0(Scan, WifiErrorCode(void));
    MOCK_METHOD1(RegisterWifiEvent, WifiErrorCode(WifiEvent *));
    MOCK_METHOD2(GetScanInfoList, WifiErrorCode(WifiScanInfo *, unsigned int *));
    MOCK_METHOD1(UnRegisterWifiEvent, WifiErrorCode(WifiEvent *));
    MOCK_METHOD2(Hid2dGetChannelListFor5G, WifiErrorCode(int32_t *, int));
    MOCK_METHOD1(GetLinkedInfo, WifiErrorCode(WifiLinkedInfo *));
    MOCK_METHOD1(GetCurrentGroup, WifiErrorCode(WifiP2pGroupInfo *));
    MOCK_METHOD0(IsWifiActive, int(void));
    MOCK_METHOD1(GetWifiDetailState, WifiErrorCode(WifiDetailState *));
    MOCK_METHOD1(GetP2pEnableStatus, WifiErrorCode(P2pState *));
};
} // namespace OHOS
#endif // AUTH_CONNECTION_MOCK_H