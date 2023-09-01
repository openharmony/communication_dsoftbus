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

#include "softbus_error_code.h"
#include "wifi_direct_p2p_adapter_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_wifiDirectP2PAdapterInterface;

WifiDirectP2PAdapterInterfaceMock::WifiDirectP2PAdapterInterfaceMock()
{
    g_wifiDirectP2PAdapterInterface = reinterpret_cast<void *>(this);
}

WifiDirectP2PAdapterInterfaceMock::~WifiDirectP2PAdapterInterfaceMock()
{
    g_wifiDirectP2PAdapterInterface = nullptr;
}

static WifiDirectP2PAdapterInterface *GetWifiDirectP2PAdapterInterface()
{
    return reinterpret_cast<WifiDirectP2PAdapterInterfaceMock *>(g_wifiDirectP2PAdapterInterface);
}

extern "C" {
WifiErrorCode Hid2dGetChannelListFor5G(int *chanList, int len)
{
    return GetWifiDirectP2PAdapterInterface()->Hid2dGetChannelListFor5G(chanList, len);
}
WifiErrorCode GetLinkedInfo(WifiLinkedInfo *info)
{
    return GetWifiDirectP2PAdapterInterface()->GetLinkedInfo(info);
}
WifiErrorCode Hid2dGetRecommendChannel(const RecommendChannelRequest *request, RecommendChannelResponse *response)
{
    return GetWifiDirectP2PAdapterInterface()->Hid2dGetRecommendChannel(request, response);
}
WifiErrorCode Hid2dGetSelfWifiCfgInfo(SelfCfgType cfgType, char cfgData[CFG_DATA_MAX_BYTES], int* getDatValidLen)
{
    return GetWifiDirectP2PAdapterInterface()->Hid2dGetSelfWifiCfgInfo(cfgType, cfgData, getDatValidLen);
}
int32_t SoftBusBase64Decode(unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen)
{
    return GetWifiDirectP2PAdapterInterface()->SoftBusBase64Decode(dst, dlen, olen, src, slen);
}
WifiErrorCode Hid2dSetPeerWifiCfgInfo(PeerCfgType cfgType, char cfgData[CFG_DATA_MAX_BYTES], int setDataValidLen)
{
    return GetWifiDirectP2PAdapterInterface()->Hid2dSetPeerWifiCfgInfo(cfgType, cfgData, setDataValidLen);
}
WifiErrorCode GetCurrentGroup(WifiP2pGroupInfo* groupInfo)
{
    return GetWifiDirectP2PAdapterInterface()->GetCurrentGroup(groupInfo);
}
WifiErrorCode Hid2dRequestGcIp(const unsigned char gcMac[MAC_LEN], unsigned int ipAddr[IPV4_ARRAY_LEN])
{
    return GetWifiDirectP2PAdapterInterface()->Hid2dRequestGcIp(gcMac, ipAddr);
}
WifiErrorCode Hid2dConfigIPAddr(const char ifName[IF_NAME_LEN], const IpAddrInfo *ipInfo)
{
    return GetWifiDirectP2PAdapterInterface()->Hid2dConfigIPAddr(ifName, ipInfo);
}
WifiErrorCode Hid2dCreateGroup(const int frequency, FreqType type)
{
    return GetWifiDirectP2PAdapterInterface()->Hid2dCreateGroup(frequency, type);
}
WifiErrorCode Hid2dConnect(const Hid2dConnectConfig *config)
{
    return GetWifiDirectP2PAdapterInterface()->Hid2dConnect(config);
}
WifiErrorCode Hid2dSharedlinkIncrease(void)
{
    return GetWifiDirectP2PAdapterInterface()->Hid2dSharedlinkIncrease();
}
WifiErrorCode Hid2dSharedlinkDecrease(void)
{
    return GetWifiDirectP2PAdapterInterface()->Hid2dSharedlinkDecrease();
}
int32_t CallMethodAsync(WorkFunction function, void *data, int64_t delayTimeMs)
{
    return GetWifiDirectP2PAdapterInterface()->CallMethodAsync(function, data, delayTimeMs);
}
WifiErrorCode RegisterP2pStateChangedCallback(const P2pStateChangedCallback callback)
{
    return GetWifiDirectP2PAdapterInterface()->RegisterP2pStateChangedCallback(callback);
}
WifiErrorCode RegisterP2pConnectionChangedCallback(const P2pConnectionChangedCallback callback)
{
    return GetWifiDirectP2PAdapterInterface()->RegisterP2pConnectionChangedCallback(callback);
}
}
} // namespace OHOS
