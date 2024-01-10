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

#include <gtest/gtest.h>
#include <securec.h>

#include "broadcast_receiver.h"
#include "channel/default_negotiate_channel.h"
#include "data/resource_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "wifi_direct_p2p_adapter.h"
#include "wifi_direct_p2p_adapter.c"
#include "wifi_direct_p2p_adapter_mock.h"
#include "wifi_p2p.h"
#include "wifi_p2p_config.h"

#define GROUP_CONFIG_STRING     8
#define WIFI_DIRECT_API_ROLE_GO 4
#define WIFI_DIRECT_API_ROLE_AP 2

namespace OHOS {
using namespace testing::ext;
using namespace testing;

class WifiDirectP2PAdapterTest : public testing::Test {
public:
    WifiDirectP2PAdapterTest()
    {}
    ~WifiDirectP2PAdapterTest()
    {}
    void SetUp();
    void TearDown();
};

void WifiDirectP2PAdapterTest::SetUp(void) {}
void WifiDirectP2PAdapterTest::TearDown(void) {}

bool Is2GBand(int32_t frequency)
{
    (void)frequency;
    static int32_t temp = 0;
    return static_cast<bool>(temp++);
}

bool Is5GBand(int32_t frequency)
{
    (void)frequency;
    static int32_t temp = 0;
    return static_cast<bool>(temp++);
}

int32_t FrequencyToChannel(int32_t frequency)
{
    (void)frequency;
    return 0;
}

bool IsInChannelList(int32_t channel, const int32_t *channelArray, size_t channelNum)
{
    (void)channel;
    (void)channelArray;
    (void)channelNum;
    return true;
}

int32_t GetInterfaceMacAddr(const char *ifName, uint8_t *macAddrArray, size_t *macAddrArraySize)
{
    (void)ifName;
    (void)macAddrArray;
    (void)macAddrArraySize;
    static int32_t temp = 0;
    return temp++;
}

int32_t MacArrayToString(const uint8_t *array, size_t arraySize, char *macString, size_t macStringSize)
{
    (void)array;
    (void)arraySize;
    (void)macString;
    (void)macStringSize;
    static int32_t temp = 0;
    return temp++;
}

int32_t GetInterfaceAddr(const char *ifName, uint8_t *macAddrArray, size_t *macAddrArraySize)
{
    (void)ifName;
    (void)macAddrArray;
    (void)macAddrArraySize;
    static int32_t temp = 0;
    return temp++;
}

int32_t ArrayToString(const uint8_t *array, size_t arraySize, char *macString, size_t macStringSize)
{
    (void)array;
    (void)arraySize;
    (void)macString;
    (void)macStringSize;
    static int32_t temp = 0;
    return temp++;
}

int32_t MacStringToArray(const char *macString, uint8_t *array, size_t *arraySize)
{
    (void)macString;
    (void)array;
    (void)arraySize;
    static int32_t temp = 0;
    return temp++;
}

int32_t StringToArray(const char *macString, uint8_t *array, size_t *arraySize)
{
    (void)macString;
    (void)array;
    (void)arraySize;
    static int32_t temp = 0;
    return temp++;
}

int32_t GetInterfaceIpString(const char *interface, char *ipString, int32_t ipStringSize)
{
    (void)interface;
    (void)ipString;
    (void)ipStringSize;
    static int32_t temp = 0;
    return temp++;
}

int32_t IpStringToIntArray(const char *addrString, uint32_t *addrArray, size_t addrArraySize)
{
    (void)addrString;
    (void)addrArray;
    (void)addrArraySize;
    return 0;
}

int32_t SplitString(char *input, char *splitter, char **outputArray, size_t *outputArraySize)
{
    (void)input;
    (void)splitter;
    (void)outputArray;
    (void)outputArraySize;
    static int32_t temp = 0;
    return temp++;
}

int32_t GetInt(struct InterfaceInfo *self, size_t key, int32_t defaultValue)
{
    (void)self;
    (void)key;
    (void)defaultValue;
    static int32_t temp = WIFI_DIRECT_API_ROLE_GO;
    return temp * WIFI_DIRECT_API_ROLE_AP;
}

struct InterfaceInfo* GetInterfaceInfo(const char *interface)
{
    (void)interface;
    struct InterfaceInfo *info = nullptr;
    info = static_cast<struct InterfaceInfo *>(SoftBusMalloc(sizeof(InterfaceInfo)));
    EXPECT_TRUE(info != nullptr);
    info->getInt = GetInt;
    return info;
}

HWTEST_F(WifiDirectP2PAdapterTest, P2PAdapterTest001, TestSize.Level1)
{
    int32_t array[5];
    size_t size = 0;
    NiceMock<WifiDirectP2PAdapterInterfaceMock> wifiDirectP2PAdapterInterfaceMock;
    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock,
        Hid2dGetChannelListFor5G).WillRepeatedly(Return(ERROR_WIFI_INVALID_ARGS));
    int32_t ret = GetChannel5GListIntArray(array, &size);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock, Hid2dGetChannelListFor5G).WillRepeatedly(Return(WIFI_SUCCESS));
    ret = GetChannel5GListIntArray(array, &size);
    EXPECT_TRUE(ret == SOFTBUS_OK);
};

HWTEST_F(WifiDirectP2PAdapterTest, P2PAdapterTest002, TestSize.Level1)
{
    NiceMock<WifiDirectP2PAdapterInterfaceMock> wifiDirectP2PAdapterInterfaceMock;
    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock, GetLinkedInfo).WillRepeatedly(Return(ERROR_WIFI_INVALID_ARGS));
    int32_t ret = GetStationFrequency();
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock, GetLinkedInfo).WillRepeatedly(Return(WIFI_SUCCESS));
    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock, Hid2dGetChannelListFor5G).WillRepeatedly(Return(WIFI_SUCCESS));
    GetWifiDirectNetWorkUtils()->is2GBand = Is2GBand;
    GetWifiDirectNetWorkUtils()->is5GBand = Is5GBand;
    ret = GetStationFrequency();
    EXPECT_TRUE(ret == FREQUENCY_INVALID);

    GetWifiDirectNetWorkUtils()->is5GBand = Is5GBand;
    GetWifiDirectNetWorkUtils()->is5GBand = Is5GBand;
    GetWifiDirectNetWorkUtils()->frequencyToChannel = FrequencyToChannel;
    GetWifiDirectNetWorkUtils()->isInChannelList = IsInChannelList;
    ret = GetStationFrequency();
    EXPECT_TRUE(ret == SOFTBUS_OK);

    GetWifiDirectNetWorkUtils()->is2GBand = Is2GBand;
    ret = GetStationFrequency();
    EXPECT_TRUE(ret == SOFTBUS_OK);
};

HWTEST_F(WifiDirectP2PAdapterTest, P2PAdapterTest003, TestSize.Level1)
{
    NiceMock<WifiDirectP2PAdapterInterfaceMock> wifiDirectP2PAdapterInterfaceMock;
    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock,
        Hid2dGetRecommendChannel).WillRepeatedly(Return(ERROR_WIFI_INVALID_ARGS));
    int32_t ret = GetRecommendChannel();
    EXPECT_TRUE(ret == CHANNEL_INVALID);

    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock, Hid2dGetRecommendChannel).WillRepeatedly(Return(WIFI_SUCCESS));
    ret = GetRecommendChannel();
    EXPECT_TRUE(ret == CHANNEL_INVALID);
};

HWTEST_F(WifiDirectP2PAdapterTest, P2PAdapterTest004, TestSize.Level1)
{
    uint8_t config = 0;
    size_t configSize = 0;
    NiceMock<WifiDirectP2PAdapterInterfaceMock> wifiDirectP2PAdapterInterfaceMock;
    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock,
        Hid2dGetSelfWifiCfgInfo).WillRepeatedly(Return(ERROR_WIFI_INVALID_ARGS));
    int32_t ret = GetSelfWifiConfigInfo(&config, &configSize);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock,
        Hid2dGetSelfWifiCfgInfo).WillRepeatedly(Return(WIFI_SUCCESS));
    ret = GetSelfWifiConfigInfo(&config, &configSize);
    EXPECT_TRUE(ret == SOFTBUS_OK);
};

HWTEST_F(WifiDirectP2PAdapterTest, P2PAdapterTest005, TestSize.Level1)
{
    const char *config = "softBus";
    int32_t ret = SetPeerWifiConfigInfo(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    NiceMock<WifiDirectP2PAdapterInterfaceMock> wifiDirectP2PAdapterInterfaceMock;
    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock, SoftBusBase64Decode).WillRepeatedly(Return(SOFTBUS_ERR));
    ret = SetPeerWifiConfigInfo(config);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock, SoftBusBase64Decode).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock,
        Hid2dSetPeerWifiCfgInfo).WillRepeatedly(Return(ERROR_WIFI_INVALID_ARGS));
    ret = SetPeerWifiConfigInfo(config);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock, Hid2dSetPeerWifiCfgInfo).WillRepeatedly(Return(WIFI_SUCCESS));
    ret = SetPeerWifiConfigInfo(config);
    EXPECT_TRUE(ret == SOFTBUS_OK);
};

HWTEST_F(WifiDirectP2PAdapterTest, P2PAdapterTest006, TestSize.Level1)
{
    uint8_t cfg = 0;
    size_t size = 0;
    int32_t ret = SetPeerWifiConfigInfoV2(&cfg, size);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
};

HWTEST_F(WifiDirectP2PAdapterTest, P2PAdapterTest007, TestSize.Level1)
{
    char *groupConfigString = nullptr;
    size_t groupConfigStringSize = 0;
    NiceMock<WifiDirectP2PAdapterInterfaceMock> wifiDirectP2PAdapterInterfaceMock;
    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock, GetCurrentGroup).WillRepeatedly(Return(ERROR_WIFI_INVALID_ARGS));
    int32_t ret = GetGroupConfig(groupConfigString, &groupConfigStringSize);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock, GetCurrentGroup).WillRepeatedly(Return(WIFI_SUCCESS));
    GetWifiDirectNetWorkUtils()->getInterfaceMacAddr = GetInterfaceMacAddr;
    GetWifiDirectNetWorkUtils()->macArrayToString = MacArrayToString;
    ret = GetGroupConfig(groupConfigString, &groupConfigStringSize);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    GetWifiDirectNetWorkUtils()->macArrayToString = MacArrayToString;
    ret = GetGroupConfig(groupConfigString, &groupConfigStringSize);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    GetWifiDirectNetWorkUtils()->getInterfaceMacAddr = GetInterfaceMacAddr;
    ret = GetGroupConfig(groupConfigString, &groupConfigStringSize);
    EXPECT_TRUE(ret != SOFTBUS_OK);
};

HWTEST_F(WifiDirectP2PAdapterTest, P2PAdapterTest008, TestSize.Level1)
{
    struct WifiDirectP2pGroupInfo **groupInfoOut =
        reinterpret_cast<struct WifiDirectP2pGroupInfo **>(SoftBusMalloc(5 * sizeof(WifiDirectP2pGroupInfo)));
    EXPECT_TRUE(groupInfoOut != nullptr);
    NiceMock<WifiDirectP2PAdapterInterfaceMock> wifiDirectP2PAdapterInterfaceMock;
    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock, GetCurrentGroup).WillRepeatedly(Return(ERROR_WIFI_INVALID_ARGS));
    int32_t ret = GetGroupInfo(groupInfoOut);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock, GetCurrentGroup).WillRepeatedly(Return(WIFI_SUCCESS));
    ret = GetGroupInfo(groupInfoOut);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    SoftBusFree(groupInfoOut);
};

HWTEST_F(WifiDirectP2PAdapterTest, P2PAdapterTest009, TestSize.Level1)
{
    char *ipString = nullptr;
    int32_t ipStringSize = 0;
    NiceMock<WifiDirectP2PAdapterInterfaceMock> wifiDirectP2PAdapterInterfaceMock;
    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock, GetCurrentGroup).WillRepeatedly(Return(ERROR_WIFI_INVALID_ARGS));
    int32_t ret = GetIpAddress(ipString, ipStringSize);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock, GetCurrentGroup).WillRepeatedly(Return(WIFI_SUCCESS));
    GetWifiDirectNetWorkUtils()->getInterfaceIpString = GetInterfaceIpString;
    ret = GetIpAddress(ipString, ipStringSize);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    GetWifiDirectNetWorkUtils()->getInterfaceIpString = GetInterfaceIpString;
    ret = GetIpAddress(ipString, ipStringSize);
    EXPECT_TRUE(ret != SOFTBUS_OK);
};

HWTEST_F(WifiDirectP2PAdapterTest, P2PAdapterTest010, TestSize.Level1)
{
    char *macString = nullptr;
    size_t macStringSize = 0;
    NiceMock<WifiDirectP2PAdapterInterfaceMock> wifiDirectP2PAdapterInterfaceMock;
    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock, GetCurrentGroup).WillRepeatedly(Return(ERROR_WIFI_INVALID_ARGS));
    int32_t ret = GetDynamicMacAddress(macString, macStringSize);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock, GetCurrentGroup).WillRepeatedly(Return(WIFI_SUCCESS));
    GetWifiDirectNetWorkUtils()->getInterfaceMacAddr = GetInterfaceAddr;
    GetWifiDirectNetWorkUtils()->macArrayToString = ArrayToString;
    ret = GetDynamicMacAddress(macString, macStringSize);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    GetWifiDirectNetWorkUtils()->macArrayToString = ArrayToString;
    ret = GetDynamicMacAddress(macString, macStringSize);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    GetWifiDirectNetWorkUtils()->getInterfaceMacAddr = GetInterfaceAddr;
    ret = GetDynamicMacAddress(macString, macStringSize);
    EXPECT_TRUE(ret != SOFTBUS_OK);
};

HWTEST_F(WifiDirectP2PAdapterTest, P2PAdapterTest011, TestSize.Level1)
{
    const char *macString = "softBus";
    char *ipString = nullptr;
    size_t ipStringSize = 0;
    GetWifiDirectNetWorkUtils()->macStringToArray = MacStringToArray;
    NiceMock<WifiDirectP2PAdapterInterfaceMock> wifiDirectP2PAdapterInterfaceMock;
    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock, Hid2dRequestGcIp).WillRepeatedly(Return(WIFI_SUCCESS));
    int32_t ret = RequestGcIp(macString, ipString, ipStringSize);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock, Hid2dRequestGcIp).WillRepeatedly(Return(ERROR_WIFI_INVALID_ARGS));
    ret = RequestGcIp(macString, ipString, ipStringSize);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    GetWifiDirectNetWorkUtils()->macStringToArray = MacStringToArray;
    ret = RequestGcIp(macString, ipString, ipStringSize);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
};

HWTEST_F(WifiDirectP2PAdapterTest, P2PAdapterTest012, TestSize.Level1)
{
    const char *interface = "softBus";
    const char *ip = "softBus";
    int32_t ret = P2pConfigGcIp(nullptr, ip);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = P2pConfigGcIp(interface, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    GetWifiDirectNetWorkUtils()->ipStringToIntArray = IpStringToIntArray;
    NiceMock<WifiDirectP2PAdapterInterfaceMock> wifiDirectP2PAdapterInterfaceMock;
    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock, Hid2dConfigIPAddr).WillRepeatedly(Return(ERROR_WIFI_INVALID_ARGS));
    ret = P2pConfigGcIp(interface, ip);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock, Hid2dConfigIPAddr).WillRepeatedly(Return(WIFI_SUCCESS));
    ret = P2pConfigGcIp(interface, ip);
    EXPECT_TRUE(ret == SOFTBUS_OK);
};

HWTEST_F(WifiDirectP2PAdapterTest, P2PAdapterTest013, TestSize.Level1)
{
    int32_t frequency = 0;
    bool wideBandSupported = false;
    NiceMock<WifiDirectP2PAdapterInterfaceMock> wifiDirectP2PAdapterInterfaceMock;
    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock, Hid2dCreateGroup).WillRepeatedly(Return(ERROR_WIFI_INVALID_ARGS));
    int32_t ret = P2pCreateGroup(frequency, wideBandSupported);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock, Hid2dCreateGroup).WillRepeatedly(Return(WIFI_SUCCESS));
    ret = P2pCreateGroup(frequency, wideBandSupported);
    EXPECT_TRUE(ret == SOFTBUS_OK);
};

HWTEST_F(WifiDirectP2PAdapterTest, P2PAdapterTest014, TestSize.Level1)
{
    char groupConfigString[GROUP_CONFIG_STRING] = "softBus";
    GetWifiDirectNetWorkUtils()->splitString = SplitString;
    GetWifiDirectNetWorkUtils()->macStringToArray = StringToArray;
    NiceMock<WifiDirectP2PAdapterInterfaceMock> wifiDirectP2PAdapterInterfaceMock;
    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock, Hid2dConnect).WillRepeatedly(Return(ERROR_WIFI_INVALID_ARGS));
    int32_t ret = P2pConnectGroup(groupConfigString);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock, Hid2dConnect).WillRepeatedly(Return(WIFI_SUCCESS));
    ret = P2pConnectGroup(groupConfigString);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    GetWifiDirectNetWorkUtils()->splitString = SplitString;
    ret = P2pConnectGroup(groupConfigString);
    EXPECT_TRUE(ret != SOFTBUS_OK);
};

HWTEST_F(WifiDirectP2PAdapterTest, P2PAdapterTest015, TestSize.Level1)
{
    NiceMock<WifiDirectP2PAdapterInterfaceMock> wifiDirectP2PAdapterInterfaceMock;
    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock,
        Hid2dSharedlinkIncrease).WillRepeatedly(Return(ERROR_WIFI_INVALID_ARGS));
    int32_t ret = P2pShareLinkReuse();
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock, Hid2dSharedlinkIncrease).WillRepeatedly(Return(WIFI_SUCCESS));
    ret = P2pShareLinkReuse();
    EXPECT_TRUE(ret == SOFTBUS_OK);
};

HWTEST_F(WifiDirectP2PAdapterTest, P2PAdapterTest016, TestSize.Level1)
{
    const char *interface = "softBus";
    NiceMock<WifiDirectP2PAdapterInterfaceMock> wifiDirectP2PAdapterInterfaceMock;
    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock,
        Hid2dSharedlinkDecrease).WillRepeatedly(Return(ERROR_WIFI_INVALID_ARGS));
    int32_t ret = P2pShareLinkRemoveGroup(interface);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    EXPECT_CALL(wifiDirectP2PAdapterInterfaceMock, Hid2dSharedlinkDecrease).WillRepeatedly(Return(WIFI_SUCCESS));
    ret = P2pShareLinkRemoveGroup(interface);
    EXPECT_TRUE(ret == SOFTBUS_OK);
};

HWTEST_F(WifiDirectP2PAdapterTest, P2PAdapterTest017, TestSize.Level1)
{
    const char *interface = "softBus";
    GetResourceManager()->getInterfaceInfo = GetInterfaceInfo;
    int32_t ret = P2pRemoveGroup(interface);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    GetResourceManager()->getInterfaceInfo = GetInterfaceInfo;
    ret = P2pRemoveGroup(interface);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    GetResourceManager()->getInterfaceInfo = GetInterfaceInfo;
    ret = P2pRemoveGroup(interface);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
};
}
