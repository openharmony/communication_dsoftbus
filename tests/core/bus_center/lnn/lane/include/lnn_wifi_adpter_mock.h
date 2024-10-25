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

#ifndef LNN_WIFI_ADPTER_MOCK_H
#define LNN_WIFI_ADPTER_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "lnn_lane_link.h"
#include "softbus_adapter_wlan_extend.h"
#include "softbus_wifi_api_adapter.h"

namespace OHOS {
class LnnWifiAdpterInterface {
public:
    LnnWifiAdpterInterface() {};
    virtual ~LnnWifiAdpterInterface() {};
    virtual int32_t SoftBusGetLinkedInfo(SoftBusWifiLinkedInfo *info) = 0;
    virtual SoftBusBand SoftBusGetLinkBand(void) = 0;
    virtual int32_t LnnDisconnectP2p(const char *networkId, uint32_t laneReqId) = 0;
    virtual void LnnDestroyP2p(void) = 0;
    virtual int32_t LnnConnectP2p(const LinkRequest *request, uint32_t laneReqId, const LaneLinkCb *callback) = 0;
    virtual int32_t UpdateP2pLinkedInfo(uint32_t laneReqId, uint64_t laneId) = 0;
    virtual void LnnCancelWifiDirect(uint32_t laneReqId) = 0;
    virtual void LnnDisconnectP2pWithoutLnn(uint32_t laneReqId) = 0;
    virtual SoftBusWifiDetailState SoftBusGetWifiState(void) = 0;
    virtual int32_t SoftBusRegWlanChannelInfoCb(WlanChannelInfoCb *cb) = 0;
    virtual int32_t SoftBusRegisterWifiEvent(ISoftBusScanResult *cb) = 0;
    virtual int32_t SoftBusUnRegisterWifiEvent(ISoftBusScanResult *cb) = 0;
    virtual int32_t SoftBusRequestWlanChannelInfo(int32_t *channelId, uint32_t num) = 0;
    virtual int32_t SoftBusGetChannelListFor5G(int32_t *channelList, int32_t num) = 0;
    virtual int32_t RemoveAuthSessionServer(const char *peerIp) = 0;
    virtual bool SoftBusIsWifiActive(void) = 0;
};

class LnnWifiAdpterInterfaceMock : public LnnWifiAdpterInterface {
public:
    LnnWifiAdpterInterfaceMock();
    ~LnnWifiAdpterInterfaceMock() override;
    MOCK_METHOD1(SoftBusGetLinkedInfo, int32_t (SoftBusWifiLinkedInfo*));
    MOCK_METHOD0(SoftBusGetLinkBand, SoftBusBand ());
    MOCK_METHOD2(LnnDisconnectP2p, int32_t (const char *, uint32_t));
    MOCK_METHOD0(LnnDestroyP2p, void (void));
    MOCK_METHOD3(LnnConnectP2p, int32_t (const LinkRequest *, uint32_t, const LaneLinkCb *));
    MOCK_METHOD2(UpdateP2pLinkedInfo, int32_t (uint32_t laneReqId, uint64_t laneId));
    MOCK_METHOD1(LnnCancelWifiDirect, void (uint32_t laneReqId));
    MOCK_METHOD1(LnnDisconnectP2pWithoutLnn, void (uint32_t laneReqId));
    MOCK_METHOD0(SoftBusGetWifiState, SoftBusWifiDetailState (void));
    MOCK_METHOD1(SoftBusRegWlanChannelInfoCb, int32_t (WlanChannelInfoCb *cb));
    MOCK_METHOD1(SoftBusRegisterWifiEvent, int32_t (ISoftBusScanResult *cb));
    MOCK_METHOD1(SoftBusUnRegisterWifiEvent, int32_t (ISoftBusScanResult *cb));
    MOCK_METHOD2(SoftBusRequestWlanChannelInfo, int32_t (int32_t *channelId, uint32_t num));
    MOCK_METHOD2(SoftBusGetChannelListFor5G, int32_t (int32_t *channelList, int32_t num));
    MOCK_METHOD0(SoftBusIsWifiActive, bool ());
    MOCK_METHOD1(RemoveAuthSessionServer, int32_t (const char *peerIp));
    void SetDefaultResult(void);
    static int32_t ActionOfLnnConnectP2p(const LinkRequest *request, uint32_t laneReqId, const LaneLinkCb *callback);
    static int32_t ActionOfOnConnectP2pFail(const LinkRequest *request, uint32_t laneReqId, const LaneLinkCb *callback);
    static bool delayNotifyLinkSuccess;
};

} // namespace OHOS
#endif // LNN_WIFI_ADPTER_MOCK_H