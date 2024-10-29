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
#ifndef WIFI_DIRECT_UTILS_H
#define WIFI_DIRECT_UTILS_H

#include <cinttypes>
#include <condition_variable>
#include <vector>
#include <string>

#include "data/ipv4_info.h"
#include "wifi_direct_types.h"
#include "data/link_info.h"
#include "data/inner_link.h"

namespace OHOS::SoftBus {
static constexpr int FREQUENCY_2G_FIRST = 2412;
static constexpr int FREQUENCY_2G_LAST = 2472;
static constexpr int FREQUENCY_5G_FIRST = 5170;
static constexpr int FREQUENCY_5G_LAST = 5825;
static constexpr int CHANNEL_2G_FIRST = 1;
static constexpr int CHANNEL_2G_LAST = 13;
static constexpr int CHANNEL_5G_FIRST = 34;
static constexpr int CHANNEL_5G_LAST = 165;
static constexpr int FREQUENCY_STEP = 5;
static constexpr int CHANNEL_INVALID = -1;
static constexpr int FREQUENCY_INVALID = -1;

class WifiDirectUtils {
public:
    static std::vector<std::string> SplitString(const std::string &s, const std::string &delimiter);

    static uint32_t BytesToInt(const std::vector<uint8_t> &data);
    static uint32_t BytesToInt(const uint8_t *data, uint32_t size);
    static void IntToBytes(uint32_t data, uint32_t len, std::vector<uint8_t> &out);
    static std::string ToString(const std::vector<uint8_t> &input);
    static std::vector<uint8_t> ToBinary(const std::string &input);

    static bool Is2GBand(int frequency);
    static bool Is5GBand(int frequency);
    static int ChannelToFrequency(int channel);
    static int FrequencyToChannel(int frequency);

    static std::string NetworkIdToUuid(const std::string &networkId);
    static std::string UuidToNetworkId(const std::string &uuid);
    static std::string GetLocalNetworkId();
    static std::string GetLocalUuid();
    static int32_t GetLocalConnSubFeature(uint64_t &feature);
    static std::vector<uint8_t> GetLocalPtk(const std::string &remoteNetworkId);
    static std::vector<uint8_t> GetRemotePtk(const std::string &remoteNetworkId);
    static bool IsRemoteSupportTlv(const std::string &remoteDeviceId);
    static bool IsLocalSupportTlv();
    static void SetLocalWifiDirectMac(const std::string &mac);
    static bool IsDeviceOnline(const std::string &remoteNetworkId);

    static std::vector<uint8_t> MacStringToArray(const std::string &macString);
    static std::string MacArrayToString(const std::vector<uint8_t> &macArray);
    static std::string MacArrayToString(const uint8_t *mac, int size);
    static std::vector<uint8_t> GetInterfaceMacAddr(const std::string &interface);
    static std::string GetInterfaceIpv6Addr(const std::string &name);

    static std::vector<Ipv4Info> GetLocalIpv4Infos();

    static int CompareIgnoreCase(const std::string &left, const std::string &right);

    static bool SupportHml();
    static bool SupportHmlTwo();
    static int32_t GetInterfaceIpString(const std::string &interface, std::string &ip);
    static bool IsInChannelList(int32_t channel, const std::vector<int> &channelArray);
    static int32_t IpStringToIntArray(const char *addrString, uint32_t *addrArray, size_t addrArraySize);

    static std::string ChannelListToString(const std::vector<int> &channels);
    static std::vector<int> StringToChannelList(std::string channels);

    static WifiDirectRole ToWifiDirectRole(LinkInfo::LinkMode mode);
    static void ShowLinkInfoList(const std::string &banana, const std::vector<LinkInfo> &inkList);

    static constexpr int BAND_WIDTH_80M_NUMBER = 80 << 20;
    static constexpr int BAND_WIDTH_160M_NUMBER = 160 << 20;
    static WifiDirectBandWidth BandWidthNumberToEnum(int bandWidth);
    static int BandWidthEnumToNumber(WifiDirectBandWidth bandWidth);
    static int GetRecommendChannelFromLnn(const std::string &networkId);

    static void SerialFlowEnter();
    static void SerialFlowExit();
    static void ParallelFlowEnter();
    static void ParallelFlowExit();
    static uint32_t CalculateStringLength(const char *str, uint32_t size);
    static void SyncLnnInfoForP2p(WifiDirectRole role, const std::string &localMac, const std::string &goMac);
    static bool IsDfsChannel(const int &frequency);
    static bool CheckLinkAtDfsChannelConflict(const std::string &remoteDeviceId, InnerLink::LinkType type);
    static int32_t GetOsType(const char *networkId);
    static int32_t GetDeviceType(const char *networkId);
    static int32_t GetDeviceType();
    static int32_t GetRemoteConnSubFeature(const std::string &remoteNetworkId, uint64_t &feature);
    static std::string GetRemoteOsVersion(const char *remoteNetworkId);
    static int32_t GetRemoteScreenStatus(const char *remoteNetworkId);

private:
    static inline std::mutex serialParallelLock_;
    static inline std::condition_variable serialParallelCv_;
    static inline int serialCount_ = 0;
    static inline int parallelCount_ = 0;
};
}

#endif
