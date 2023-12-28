/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef WIFI_DIRECT_P2P_MOCK_H
#define WIFI_DIRECT_P2P_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "data/resource_manager.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "utils/wifi_direct_anonymous.h"
#include "utils/wifi_direct_network_utils.h"
#include "wifi_device.h"
#include "wifi_direct_defines.h"
#include "wifi_direct_p2p_adapter.h"
#include "wifi_direct_work_queue.h"
#include "wifi_errcode.h"
#include "wifi_hid2d.h"
#include "wifi_p2p.h"
#include "wifi_scan.h"

namespace OHOS {
class WifiDirectP2PAdapterInterface {
public:
    WifiDirectP2PAdapterInterface() {};
    virtual ~WifiDirectP2PAdapterInterface() {};

    virtual WifiErrorCode Hid2dGetChannelListFor5G(int *chanList, int len) = 0;
    virtual WifiErrorCode GetLinkedInfo(WifiLinkedInfo *info) = 0;
    virtual WifiErrorCode Hid2dGetRecommendChannel(const RecommendChannelRequest *request,
        RecommendChannelResponse *response) = 0;
    virtual WifiErrorCode Hid2dGetSelfWifiCfgInfo(SelfCfgType cfgType, char cfgData[CFG_DATA_MAX_BYTES],
        int* getDatValidLen) = 0;
    virtual int32_t SoftBusBase64Decode(unsigned char *dst, size_t dlen, size_t *olen,
        const unsigned char *src, size_t slen) = 0;
    virtual WifiErrorCode Hid2dSetPeerWifiCfgInfo(PeerCfgType cfgType, char cfgData[CFG_DATA_MAX_BYTES],
        int setDataValidLen) = 0;
    virtual WifiErrorCode GetCurrentGroup(WifiP2pGroupInfo* groupInfo) = 0;
    virtual WifiErrorCode Hid2dRequestGcIp(const unsigned char gcMac[MAC_LEN],
        unsigned int ipAddr[IPV4_ARRAY_LEN]) = 0;
    virtual WifiErrorCode Hid2dConfigIPAddr(const char ifName[IF_NAME_LEN], const IpAddrInfo *ipInfo) = 0;
    virtual WifiErrorCode Hid2dCreateGroup(const int frequency, FreqType type) = 0;
    virtual WifiErrorCode Hid2dConnect(const Hid2dConnectConfig *config) = 0;
    virtual WifiErrorCode Hid2dSharedlinkIncrease(void) = 0;
    virtual WifiErrorCode Hid2dSharedlinkDecrease(void) = 0;
    virtual int32_t CallMethodAsync(WorkFunction function, void *data, int64_t delayTimeMs) = 0;
    virtual WifiErrorCode RegisterP2pStateChangedCallback(const P2pStateChangedCallback callback) = 0;
    virtual WifiErrorCode RegisterP2pConnectionChangedCallback(const P2pConnectionChangedCallback callback) = 0;
};
class WifiDirectP2PAdapterInterfaceMock : public WifiDirectP2PAdapterInterface {
public:
    WifiDirectP2PAdapterInterfaceMock();
    ~WifiDirectP2PAdapterInterfaceMock() override;

    MOCK_METHOD2(Hid2dGetChannelListFor5G, WifiErrorCode(int *, int));
    MOCK_METHOD1(GetLinkedInfo, WifiErrorCode(WifiLinkedInfo *));
    MOCK_METHOD2(Hid2dGetRecommendChannel, WifiErrorCode(const RecommendChannelRequest *, RecommendChannelResponse *));
    MOCK_METHOD3(Hid2dGetSelfWifiCfgInfo, WifiErrorCode(SelfCfgType, char *, int*));
    MOCK_METHOD5(SoftBusBase64Decode, int32_t(unsigned char *, size_t, size_t*, const unsigned char *, size_t));
    MOCK_METHOD3(Hid2dSetPeerWifiCfgInfo, WifiErrorCode(PeerCfgType, char *, int));
    MOCK_METHOD1(GetCurrentGroup, WifiErrorCode(WifiP2pGroupInfo*));
    MOCK_METHOD2(Hid2dRequestGcIp, WifiErrorCode(const unsigned char*, unsigned int*));
    MOCK_METHOD2(Hid2dConfigIPAddr, WifiErrorCode(const char*, const IpAddrInfo *));
    MOCK_METHOD2(Hid2dCreateGroup, WifiErrorCode(const int, FreqType));
    MOCK_METHOD1(Hid2dConnect, WifiErrorCode(const Hid2dConnectConfig *));
    MOCK_METHOD0(Hid2dSharedlinkIncrease, WifiErrorCode(void));
    MOCK_METHOD0(Hid2dSharedlinkDecrease, WifiErrorCode(void));
    MOCK_METHOD3(CallMethodAsync, int32_t(WorkFunction, void *, int64_t));
    MOCK_METHOD1(RegisterP2pStateChangedCallback, WifiErrorCode(const P2pStateChangedCallback));
    MOCK_METHOD1(RegisterP2pConnectionChangedCallback, WifiErrorCode(const P2pConnectionChangedCallback));
};
} // namespace OHOS
#endif
