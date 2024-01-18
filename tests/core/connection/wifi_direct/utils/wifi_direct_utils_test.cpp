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
#include <string>

#include "wifi_direct_defines.h"
#include "conn_log.h"
#include "wifi_direct_ipv4_info.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "wifi_direct_network_utils.h"
#include "wifi_direct_perf_recorder.h"
#include "wifi_direct_timer_list.h"
#include "wifi_direct_command_manager.h"
#include "wifi_direct_work_queue.h"
#include "wifi_direct_manager.h"
#include "wifi_direct_utils.h"
#include "wifi_direct_types.h"
#include "data/link_info.h"
#include "softbus_adapter_timer.h"
#include "wifi_direct_anonymous.h"
#include "wifi_direct_entity.h"
#include "message_handler.h"
#include "wifi_direct_statistic.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;
using namespace std;
constexpr int32_t PID = 2222;
constexpr int32_t CHANNEL_2G = 10;
constexpr int32_t CHANNEL_5G = 100;
constexpr int32_t CHANNEL_INCALID = 20;
constexpr int32_t FREQUENCY_2G = 2450;
constexpr int32_t FREQUENCY_5G = 5200;
constexpr int32_t FREQUENCY_INVALID_NUM = 3000;
constexpr uint32_t ARRARY_COUNT = 2;
constexpr uint32_t TEST_DATA1 = 123;
constexpr uint32_t TEST_DATA2 = 456;
constexpr uint32_t IN_SIZE = 3;
constexpr uint32_t MIN_NUM = 0;
constexpr uint32_t HTOLE_LEN = 4;
constexpr size_t IPV4_COUNT = 1;
constexpr size_t DATA_LEN = 10;
constexpr size_t INVALID_DATA_LEN = 2;
constexpr size_t IPV4_BYTE_LEN = 5;
constexpr size_t INVALID_BYTE_LEN = 6;
constexpr size_t HEX_SIZE = 16;
constexpr char HEX_DATA = '1';
constexpr char LOWER_CHAR = 'a';
constexpr char DIFF_CHAR = 'b';
constexpr char CAPITAL_CHAR = 'A';
constexpr char INVALID_CHAR = '0';

class WifiDirectUtilsTest : public testing::Test {
public:
    WifiDirectUtilsTest()
    {}
    ~WifiDirectUtilsTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void WifiDirectUtilsTest::SetUpTestCase(void) {}
void WifiDirectUtilsTest::TearDownTestCase(void) {}
void WifiDirectUtilsTest::SetUp(void) {}
void WifiDirectUtilsTest::TearDown(void) {}

/* wifi_direct_perf_recorder.c */
/*
* @tc.name: testDirectUtilsTest001
* @tc.desc: test WifiDirectPerfRecorder structMem
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectUtilsTest, testDirectUtilsTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "WifiDirectUtilsTest, testDirectUtilsTest001, Start");
    struct WifiDirectPerfRecorder* self = GetWifiDirectPerfRecorder();
    enum TimePointType type = TP_MAX;
    self->calculate();
    type = TP_P2P_CONNECT_END;
    self->record(type);
    self->calculate();
    type = TP_P2P_CONNECT_START;
    self->record(type);
    self->calculate();
    type = TP_P2P_CREATE_GROUP_END;
    self->record(type);
    self->calculate();
    type = TP_P2P_CONNECT_GROUP_START;
    self->record(type);
    self->calculate();
    type = TP_P2P_GET_WIFI_CONFIG_END;
    self->record(type);
    self->calculate();
    type = TP_P2P_GET_WIFI_CONFIG_START;
    self->record(type);
    self->calculate();
    self->clear();

    int32_t pid = PID;
    self->setPid(PID);
    EXPECT_EQ(self->getPid(), pid);
    CONN_LOGI(CONN_WIFI_DIRECT, "WifiDirectUtilsTest, testDirectUtilsTest001, End");
};

/* wifi_direct_utils.c */
/*
* @tc.name: testDirectUtilsTest002
* @tc.desc: test TransferModeToRole
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectUtilsTest, testDirectUtilsTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "WifiDirectUtilsTest, testDirectUtilsTest002, Start");
    struct WifiDirectUtils* self = GetWifiDirectUtils();

    char banana = INVALID_CHAR;
    uint8_t* data = static_cast<uint8_t *>(SoftBusCalloc(sizeof(*data)));
    *data = INVALID_CHAR;
    size_t size = MIN_NUM;
    self->hexDump(&banana, data, size);

    *data = HEX_DATA;
    size = HEX_SIZE;
    self->hexDump(&banana, data, size);

    enum WifiDirectRole ret;
    enum WifiDirectApiRole mode = WIFI_DIRECT_API_ROLE_NONE;
    ret = self->transferModeToRole(mode);
    EXPECT_EQ(ret, WIFI_DIRECT_ROLE_NONE);

    mode = WIFI_DIRECT_API_ROLE_GC;
    ret = self->transferModeToRole(mode);
    EXPECT_EQ(ret, WIFI_DIRECT_ROLE_GC);

    mode = WIFI_DIRECT_API_ROLE_GO;
    ret = self->transferModeToRole(mode);
    EXPECT_EQ(ret, WIFI_DIRECT_ROLE_GO);

    mode = WIFI_DIRECT_API_ROLE_HML;
    ret = self->transferModeToRole(mode);
    EXPECT_EQ(ret, WIFI_DIRECT_ROLE_HML);

    mode = WIFI_DIRECT_API_ROLE_AP;
    ret = self->transferModeToRole(mode);
    EXPECT_EQ(ret, WIFI_DIRECT_ROLE_INVALID);
    SoftBusFree(data);
    CONN_LOGI(CONN_WIFI_DIRECT, "WifiDirectUtilsTest, testDirectUtilsTest002, End");
};

/*
* @tc.name: testDirectUtilsTest003
* @tc.desc: test TransferRoleToPreferLinkMode
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectUtilsTest, testDirectUtilsTest003, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "WifiDirectUtilsTest, testDirectUtilsTest003, Start");
    struct WifiDirectUtils* self = GetWifiDirectUtils();

    uint32_t data = TEST_DATA1;
    uint32_t len = HTOLE_LEN;
    uint8_t out = MIN_NUM;
    uint32_t outSize = MIN_NUM;
    self->intToBytes(data, len, &out, outSize);
    len = HTOLE_LEN + 1;
    self->intToBytes(data, len, &out, outSize);

    enum WifiDirectApiRole ret;
    enum WifiDirectRole role = WIFI_DIRECT_ROLE_NONE;
    ret = self->transferRoleToPreferLinkMode(role);
    EXPECT_EQ(ret, WIFI_DIRECT_API_ROLE_NONE);

    role = WIFI_DIRECT_ROLE_GC;
    ret = self->transferRoleToPreferLinkMode(role);
    EXPECT_EQ(ret, WIFI_DIRECT_API_ROLE_GC | WIFI_DIRECT_API_ROLE_HML);

    role = WIFI_DIRECT_ROLE_GO;
    ret = self->transferRoleToPreferLinkMode(role);
    EXPECT_EQ(ret, WIFI_DIRECT_API_ROLE_GO | WIFI_DIRECT_API_ROLE_HML);

    role = WIFI_DIRECT_ROLE_HML;
    ret = self->transferRoleToPreferLinkMode(role);
    EXPECT_EQ(ret, WIFI_DIRECT_API_ROLE_HML);

    role = WIFI_DIRECT_ROLE_INVALID;
    ret = self->transferRoleToPreferLinkMode(role);
    EXPECT_EQ(ret, WIFI_DIRECT_API_ROLE_GC | WIFI_DIRECT_API_ROLE_GO | WIFI_DIRECT_API_ROLE_HML);
    CONN_LOGI(CONN_WIFI_DIRECT, "WifiDirectUtilsTest, testDirectUtilsTest003, End");
};

/*
* @tc.name: testDirectUtilsTest004
* @tc.desc: test StrCompareIgnoreCase
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectUtilsTest, testDirectUtilsTest004, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "WifiDirectUtilsTest, testDirectUtilsTest004, Start");
    struct WifiDirectUtils* self = GetWifiDirectUtils();
    char* string = static_cast<char *>(SoftBusCalloc(sizeof(*string)));
    self->printLargeString(string);
    *string = LOWER_CHAR;
    self->printLargeString(string);

    char *str1 = static_cast<char *>(SoftBusCalloc(sizeof(*str1)));
    *str1 = DIFF_CHAR;
    char *str2 = static_cast<char *>(SoftBusCalloc(sizeof(*str2)));
    *str2 = LOWER_CHAR;
    int32_t ret = self->strCompareIgnoreCase(str1, str2);
    EXPECT_TRUE(ret == 1);

    *str1 = CAPITAL_CHAR;
    *str2 = CAPITAL_CHAR;
    ret = self->strCompareIgnoreCase(str1, str2);
    EXPECT_TRUE(ret == 0);
    SoftBusFree(string);
    SoftBusFree(str1);
    SoftBusFree(str2);
    CONN_LOGI(CONN_WIFI_DIRECT, "WifiDirectUtilsTest, testDirectUtilsTest004, End");
};

/* wifi_direct_network_utils.c */
/*
* @tc.name: testDirectUtilsTest005
* @tc.desc: test ChannelToFrequency
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectUtilsTest, testDirectUtilsTest005, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "WifiDirectUtilsTest, testDirectUtilsTest005, Start");
    struct WifiDirectNetWorkUtils* self = GetWifiDirectNetWorkUtils();
    int32_t channel = CHANNEL_2G;
    int32_t ret = self->channelToFrequency(channel);
    EXPECT_TRUE(ret == ((channel - CHANNEL_2G_FIRST) * FREQUENCY_STEP + FREQUENCY_2G_FIRST));
    channel = CHANNEL_5G;
    ret = self->channelToFrequency(channel);
    EXPECT_TRUE(ret == ((channel - CHANNEL_5G_FIRST) * FREQUENCY_STEP + FREQUENCY_5G_FIRST));
    channel = CHANNEL_INCALID;
    ret = self->channelToFrequency(channel);
    EXPECT_TRUE(ret == FREQUENCY_INVALID);

    struct WifiDirectIpv4Info *ipv4 = static_cast<struct WifiDirectIpv4Info *>(SoftBusCalloc(sizeof(*ipv4)));
    size_t size = INVALID_DATA_LEN;

    ret = self->getLocalIpv4InfoArray(ipv4, &size);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(ipv4);
    CONN_LOGI(CONN_WIFI_DIRECT, "WifiDirectUtilsTest, testDirectUtilsTest005, End");
};

/*
* @tc.name: testDirectUtilsTest006
* @tc.desc: test ChannelListToString
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectUtilsTest, testDirectUtilsTest006, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "WifiDirectUtilsTest, testDirectUtilsTest006, Start");
    struct WifiDirectNetWorkUtils* self = GetWifiDirectNetWorkUtils();
    int32_t array[ARRARY_COUNT] = {TEST_DATA1, TEST_DATA2};
    size_t channelArraySize = ARRARY_COUNT;
    char *channelListString = static_cast<char *>(SoftBusCalloc(sizeof(*channelListString) * (IN_SIZE)));
    size_t inSize = IN_SIZE;
    int32_t ret = self->channelListToString(array, channelArraySize, channelListString, inSize);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    SoftBusFree(channelListString);
    CONN_LOGI(CONN_WIFI_DIRECT, "WifiDirectUtilsTest, testDirectUtilsTest006, End");
};

/*
* @tc.name: testDirectUtilsTest007
* @tc.desc: test frequencyToChannel
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectUtilsTest, testDirectUtilsTest007, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "WifiDirectUtilsTest, testDirectUtilsTest007, Start");
    struct WifiDirectNetWorkUtils* self = GetWifiDirectNetWorkUtils();
    int32_t frequency = FREQUENCY_2G;
    int32_t ret = self->frequencyToChannel(frequency);
    EXPECT_TRUE(ret == ((frequency - FREQUENCY_2G_FIRST) / FREQUENCY_STEP + CHANNEL_2G_FIRST));

    frequency = FREQUENCY_5G;
    ret = self->frequencyToChannel(frequency);
    EXPECT_TRUE(ret == ((frequency - FREQUENCY_5G_FIRST) / FREQUENCY_STEP + CHANNEL_5G_FIRST));

    frequency = FREQUENCY_INVALID_NUM;
    ret = self->frequencyToChannel(frequency);
    EXPECT_TRUE(ret == CHANNEL_INVALID);
    CONN_LOGI(CONN_WIFI_DIRECT, "WifiDirectUtilsTest, testDirectUtilsTest007, End");
};

/* wifi_direct_ipv4_info.c */
/*
* @tc.name: testDirectUtilsTest008
* @tc.desc: test WifiDirectIpv4InfoToBytes
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectUtilsTest, testDirectUtilsTest008, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "WifiDirectUtilsTest, testDirectUtilsTest008, Start");
    struct WifiDirectIpv4Info *ipv4 = static_cast<struct WifiDirectIpv4Info*>(SoftBusCalloc(sizeof(*ipv4)));
    ipv4->address = TEST_DATA1;
    ipv4->prefixLength = MIN_NUM;
    size_t ipv4Count = IPV4_COUNT;
    uint8_t data = MIN_NUM;
    size_t dataLen = INVALID_DATA_LEN;
    int32_t ret = WifiDirectIpv4InfoToBytes(ipv4, ipv4Count, &data, &dataLen);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    size_t ipv4BytesLen = INVALID_BYTE_LEN;
    ipv4Count = MIN_NUM;
    uint8_t ipv4Bytes = MIN_NUM;
    WifiDirectIpv4BytesToInfo(&ipv4Bytes, ipv4BytesLen, ipv4, &ipv4Count);
    SoftBusFree(ipv4);
    CONN_LOGI(CONN_WIFI_DIRECT, "WifiDirectUtilsTest, testDirectUtilsTest008, End");
};

/*
* @tc.name: testDirectUtilsTest009
* @tc.desc: test WifiDirectIpv4InfoToBytes
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectUtilsTest, testDirectUtilsTest009, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "WifiDirectUtilsTest, testDirectUtilsTest009, Start");
    struct WifiDirectIpv4Info *ipv4 = static_cast<struct WifiDirectIpv4Info*>(SoftBusCalloc(sizeof(*ipv4)));
    ipv4->address = TEST_DATA1;
    ipv4->prefixLength = MIN_NUM;
    size_t ipv4Count = IPV4_COUNT;
    uint8_t data = MIN_NUM;
    size_t dataLen = DATA_LEN;
    int32_t ret = WifiDirectIpv4InfoToBytes(ipv4, ipv4Count, &data, &dataLen);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    size_t ipv4BytesLen = IPV4_BYTE_LEN;
    uint8_t ipv4Bytes = MIN_NUM;
    WifiDirectIpv4BytesToInfo(&ipv4Bytes, ipv4BytesLen, ipv4, &ipv4Count);
    ipv4Count = MIN_NUM;
    WifiDirectIpv4BytesToInfo(&ipv4Bytes, ipv4BytesLen, ipv4, &ipv4Count);
    SoftBusFree(ipv4);
};

/*
* @tc.name: testDirectUtilsTest010
* @tc.desc: test WifiDirectIpStringToIpv4
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectUtilsTest, testDirectUtilsTest010, TestSize.Level1)
{
    struct WifiDirectIpv4Info *ipv4 = static_cast<struct WifiDirectIpv4Info*>(SoftBusCalloc(sizeof(*ipv4)));
    ipv4->address = TEST_DATA1;
    ipv4->prefixLength = MIN_NUM;

    int32_t ret = WifiDirectIpStringToIpv4(nullptr, ipv4);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    const char *ipString = "192.168.1.1";
    ret = WifiDirectIpStringToIpv4(ipString, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    const char *ipString1 = "19216811";
    ret = WifiDirectIpStringToIpv4(ipString1, ipv4);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    ret = WifiDirectIpStringToIpv4(ipString, ipv4);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(ipv4);
};

/*
* @tc.name: testDirectUtilsTest011
* @tc.desc: test WifiDirectIpv4ToString
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectUtilsTest, testDirectUtilsTest011, TestSize.Level1)
{
    struct WifiDirectIpv4Info *ipv4 = static_cast<struct WifiDirectIpv4Info*>(SoftBusCalloc(sizeof(*ipv4)));
    ipv4->address = TEST_DATA1;
    ipv4->prefixLength = MIN_NUM;
    char ipString[16] = {};
    size_t ipStringSize = sizeof(ipString) / sizeof(ipString[0]);

    int32_t ret = WifiDirectIpv4ToString(nullptr, ipString, ipStringSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    
    ret = WifiDirectIpv4ToString(ipv4, nullptr, ipStringSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    strcpy_s(ipString, ipStringSize, "192.168.0.1");
    size_t ipStringSize1 = 1;
    ret = WifiDirectIpv4ToString(ipv4, ipString, ipStringSize1);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    ipStringSize = sizeof(ipString) / sizeof(ipString[0]);
    ret = WifiDirectIpv4ToString(ipv4, ipString, ipStringSize);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(ipv4);
};

/*
* @tc.name: testDirectUtilsTest012
* @tc.desc: test WifiDirectIpv4InfoToBytes
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectUtilsTest, testDirectUtilsTest012, TestSize.Level1)
{
    struct WifiDirectIpv4Info *ipv4 = static_cast<struct WifiDirectIpv4Info*>(SoftBusCalloc(sizeof(*ipv4)));
    ipv4->address = TEST_DATA1;
    ipv4->prefixLength = MIN_NUM;
    size_t ipv4Count = 1;
    uint8_t data[16] = {};
    size_t dataLen = 4;

    int32_t ret = WifiDirectIpv4InfoToBytes
                (static_cast<const struct WifiDirectIpv4Info *>(ipv4), ipv4Count, data, &dataLen);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    size_t dataLen1 = sizeof(data) / sizeof(data[0]);
    ret = WifiDirectIpv4InfoToBytes(static_cast<const struct WifiDirectIpv4Info *>(ipv4), ipv4Count, data, &dataLen1);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(ipv4);
};

/* wifi_direct_anonymous.c */
/*
* @tc.name: DirectanonymousTest001
* @tc.desc: test WifiDirectAnonymizeMac
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectUtilsTest, DirectanonymousTest001, TestSize.Level1)
{
    const char *ret = WifiDirectAnonymizeMac(nullptr);
    EXPECT_EQ(ret, nullptr);

    const char *mac = "0A:1B:2C:3D:4E:5F:6G:7H:8I:9J:0K";
    const char *ret1 = WifiDirectAnonymizeMac(mac);
    EXPECT_EQ(ret1, nullptr);

    const char *mac1 = "0A:2B:3C:4D:5E6";
    const char *ret2 = WifiDirectAnonymizeMac(mac1);
    strcmp(ret2, "0A:2B:******5E6");
    EXPECT_TRUE(ret2 = "0A:2B:******5E6");
};

/*
* @tc.name: DirectanonymousTest002
* @tc.desc: test WifiDirectAnonymizeMac
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectUtilsTest, DirectanonymousTest002, TestSize.Level1)
{
    const char *ret = WifiDirectAnonymizeIp(nullptr);
    EXPECT_EQ(ret, nullptr);

    const char *ip = "192.168.123.1111";
    const char *ret1 = WifiDirectAnonymizeIp(ip);
    EXPECT_EQ(ret1, nullptr);

    const char *ip1 = "19216811";
    const char *ret2 = WifiDirectAnonymizeIp(ip1);
    EXPECT_EQ(ret2, nullptr);

    const char *ip2 = "192.168.1.1";
    const char *ret3 = WifiDirectAnonymizeIp(ip2);
    EXPECT_TRUE(ret3 = "192.*.*.1");

};

/* wifi_direct_network_utils.c */
/*
* @tc.name: DirectNetworkUtilsTest001
* @tc.desc: test channelToFrequency frequencyToChannel
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectUtilsTest, DirectNetworkUtilsTest001, TestSize.Level1)
{
    int32_t ret = GetWifiDirectNetWorkUtils()->channelToFrequency(CHANNEL_2G_FIRST);
    EXPECT_EQ(ret, FREQUENCY_2G_FIRST);
    ret = GetWifiDirectNetWorkUtils()->channelToFrequency(CHANNEL_5G_FIRST);
    EXPECT_EQ(ret, FREQUENCY_5G_FIRST);
    ret = GetWifiDirectNetWorkUtils()->channelToFrequency(0);
    EXPECT_EQ(ret, CHANNEL_INVALID);

    ret = GetWifiDirectNetWorkUtils()->frequencyToChannel(FREQUENCY_2G_FIRST);
    EXPECT_EQ(ret, CHANNEL_2G_FIRST);
    ret = GetWifiDirectNetWorkUtils()->frequencyToChannel(FREQUENCY_5G_FIRST);

    EXPECT_EQ(ret, CHANNEL_5G_FIRST);
    ret = GetWifiDirectNetWorkUtils()->frequencyToChannel(0);
    EXPECT_EQ(ret, FREQUENCY_INVALID);
};

/*
* @tc.name: DirectNetworkUtilsTest002
* @tc.desc: test isInChannelList stringToChannelList
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectUtilsTest, DirectNetworkUtilsTest002, TestSize.Level1)
{
    int32_t channel = 1;
    const int32_t channelArray[] = {CHANNEL_2G_FIRST, CHANNEL_2G_LAST, CHANNEL_5G_FIRST, CHANNEL_5G_LAST};
    size_t channelNum = sizeof(channelArray)/sizeof(channelArray[0]);

    bool ret = GetWifiDirectNetWorkUtils()->isInChannelList(channel, channelArray, channelNum);
    EXPECT_EQ(ret, true);

    channel = 2;
    ret = GetWifiDirectNetWorkUtils()->isInChannelList(channel, channelArray, channelNum);
    EXPECT_EQ(ret, false);

    char channelListString[16] = {'a', 'b', 'c', 'a', 'b', 'c', 'a', 'b', 'c', 'a', 'b', 'c', 'a', 'b', 'c'};
    int32_t channelArray1[] = {CHANNEL_2G_FIRST, CHANNEL_2G_LAST, CHANNEL_5G_FIRST, CHANNEL_5G_LAST};
    channelNum = static_cast<size_t>(257);
    int32_t ret1 = GetWifiDirectNetWorkUtils()->stringToChannelList(channelListString, channelArray1, &channelNum);
    EXPECT_EQ(ret1, SOFTBUS_INVALID_PARAM);

    channelNum = static_cast<size_t>(256);
    ret1 = GetWifiDirectNetWorkUtils()->stringToChannelList(nullptr, channelArray1, &channelNum);
    EXPECT_EQ(ret1, SOFTBUS_OK);
    
    int32_t channelArray2[] = {CHANNEL_2G_FIRST, CHANNEL_2G_LAST, CHANNEL_5G_FIRST, CHANNEL_5G_LAST, -1};
    channelNum = sizeof(channelArray2)/sizeof(channelArray2[0]);
    ret1 = GetWifiDirectNetWorkUtils()->stringToChannelList(channelListString, channelArray2, &channelNum);
    EXPECT_EQ(ret1, SOFTBUS_OK);

    ret1 = GetWifiDirectNetWorkUtils()->stringToChannelList(channelListString, channelArray1, &channelNum);
    EXPECT_EQ(ret1, SOFTBUS_OK);
};

/*
* @tc.name: DirectNetworkUtilsTest003
* @tc.desc: test ipAddrToString ipStringToAddr ipStringToIntArray
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectUtilsTest, DirectNetworkUtilsTest003, TestSize.Level1)
{
    struct WifiDirectIpv4Info ipv4;
    (void)memset_s(&ipv4, sizeof(ipv4), 0, sizeof(ipv4));
    char ipString[IP_ADDR_STR_LEN + 1];

    char ipString1[2];
    int32_t ret = GetWifiDirectNetWorkUtils()->ipAddrToString(ipv4.address, ipString1, 1);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    ret = GetWifiDirectNetWorkUtils()->ipAddrToString(ipv4.address, ipString, IP_ADDR_STR_LEN + 1);
    EXPECT_EQ(ret, SOFTBUS_OK);

    const char *addrString = "192.168.1.1";
    ret = GetWifiDirectNetWorkUtils()->ipStringToAddr(addrString, &ipv4.address);
    EXPECT_EQ(ret, SOFTBUS_OK);

    const char *addrString1 = "19216811";
    ret = GetWifiDirectNetWorkUtils()->ipStringToAddr(addrString1, &ipv4.address);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    uint32_t addrArray[IPV4_ADDR_ARRAY_LEN];
    ret = GetWifiDirectNetWorkUtils()->ipStringToIntArray(nullptr, addrArray, IPV4_ADDR_ARRAY_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = GetWifiDirectNetWorkUtils()->ipStringToIntArray(addrString, addrArray, IPV4_ADDR_ARRAY_LEN - 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = GetWifiDirectNetWorkUtils()->ipStringToIntArray(addrString, addrArray, IPV4_ADDR_ARRAY_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
};

/*
* @tc.name: DirectNetworkUtilsTest004
* @tc.desc: test splitString
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectUtilsTest, DirectNetworkUtilsTest004, TestSize.Level1)
{
    struct WifiDirectConnectParams params;
    (void)memset_s(&params, sizeof(WifiDirectConnectParams), 0, sizeof(WifiDirectConnectParams));
    const char strConfig[] = "00:2A:3B:4C:5D:67";
    strcpy_s(params.groupConfig, sizeof(params.groupConfig), strConfig);
    char *configs[P2P_GROUP_CONFIG_INDEX_MAX];
    size_t configsSize = P2P_GROUP_CONFIG_INDEX_MAX;
    int32_t ret = GetWifiDirectNetWorkUtils()->splitString(params.groupConfig, (char *)"\n", configs, &configsSize);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = GetWifiDirectNetWorkUtils()->splitString(params.groupConfig, nullptr, configs, &configsSize);
    EXPECT_EQ(ret, SOFTBUS_ERR);
};

/*
* @tc.name: DirectNetworkUtilsTest005
* @tc.desc: test macStringToArray macArrayToString getInterfaceMacAddr
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectUtilsTest, DirectNetworkUtilsTest005, TestSize.Level1)
{
    char macString1[18];
    const char *macString = "AA:BB:CC:DD:EE";
    const char *ifName = "1.txt";
    uint8_t array[6];
    const uint8_t array1[6] = {};
    size_t arraySize = 5;
    int32_t ret = GetWifiDirectNetWorkUtils()->macStringToArray(macString, array, &arraySize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = GetWifiDirectNetWorkUtils()->macArrayToString(array1, arraySize, macString1, arraySize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = GetWifiDirectNetWorkUtils()->getInterfaceMacAddr(ifName, array, &arraySize);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    arraySize = 6;
    const char *macString2 = "AABBCCDDEEFF";
    ret = GetWifiDirectNetWorkUtils()->macStringToArray(macString2, array, &arraySize);
    EXPECT_EQ(ret, SOFTBUS_OK);
    
    ret = GetWifiDirectNetWorkUtils()->macArrayToString(array1, 16, macString1, arraySize);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = GetWifiDirectNetWorkUtils()->getInterfaceMacAddr(nullptr, array, &arraySize);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    ret = GetWifiDirectNetWorkUtils()->getInterfaceMacAddr(ifName, array, &arraySize);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    ret = GetWifiDirectNetWorkUtils()->getInterfaceMacAddr(ifName, array, &arraySize);
    EXPECT_EQ(ret, SOFTBUS_ERR);
};

/*
* @tc.name: DirectNetworkUtilsTest006
* @tc.desc: test getInterfaceIpString
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectUtilsTest, DirectNetworkUtilsTest006, TestSize.Level1)
{
    const char *interface = "interface";
    char ipString[IP_ADDR_STR_LEN] = {'1', '9', '2', '.', '1', '6', '8', '.', '1', '.', '1'};;
    int32_t ret1 = GetWifiDirectNetWorkUtils()->getInterfaceIpString(nullptr, ipString, IP_ADDR_STR_LEN);
    EXPECT_EQ(ret1, SOFTBUS_INVALID_PARAM);

    ret1 = GetWifiDirectNetWorkUtils()->getInterfaceIpString(interface, nullptr, IP_ADDR_STR_LEN);
    EXPECT_EQ(ret1, SOFTBUS_INVALID_PARAM);

    const char *interface1 = "aabbccddeeffgghhiijjkkllmm";
    ret1 = GetWifiDirectNetWorkUtils()->getInterfaceIpString(interface1, ipString, IP_ADDR_STR_LEN);
    EXPECT_EQ(ret1, SOFTBUS_ERR);

    char ipString1[2];
    ret1 = GetWifiDirectNetWorkUtils()->getInterfaceIpString(interface, ipString1, 1);
    EXPECT_EQ(ret1, SOFTBUS_ERR);

    ret1 = GetWifiDirectNetWorkUtils()->getInterfaceIpString(interface, ipString, IP_ADDR_STR_LEN);
    EXPECT_EQ(ret1, SOFTBUS_ERR);
};

/*wifi_direct_perf_recorder.c*/
/*
* @tc.name: DirectPerfRecorderTest001
* @tc.desc: test WifiDirectPerfRecorder structMem
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectUtilsTest, DirectPerfRecorderTest001, TestSize.Level1)
{
    struct WifiDirectPerfRecorder *recorder = GetWifiDirectPerfRecorder();
    TimePointType pointType = TP_P2P_CONNECT_START;
    TimeCostType costType = TC_TOTAL;
    recorder->setPid(0);
    int32_t ret = recorder->getPid();
    EXPECT_EQ(ret, 0);
    recorder->setConnectType(WIFI_DIRECT_LINK_TYPE_INVALID);
    enum WifiDirectLinkType type = recorder->getConnectType();
    recorder->record(pointType);
    recorder->calculate();
    recorder->getTime(costType);
    recorder->clear();
    EXPECT_EQ(type, WIFI_DIRECT_LINK_TYPE_INVALID);
};

/*wifi_direct_timer_list.c*/
/*
* @tc.name: DirectTimerListTest001
* @tc.desc: test stopTimer
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectUtilsTest, DirectTimerListTest001, TestSize.Level1)
{
    struct WifiDirectTimerList *list = GetWifiDirectTimerList();
    EXPECT_NE(list, nullptr);
    int32_t ret = WifiDirectTimerListInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    TimeoutHandler handler;
    (void)memset_s(&handler, sizeof(TimeoutHandler), 0, sizeof(TimeoutHandler));
    void *ret1 = list->stopTimer(list->timerId);
    EXPECT_EQ(ret1, nullptr);
};

/*wifi_direct_work_queue.c*/
/*
* @tc.name: DirectWorkQueueTest001
* @tc.desc: test GetWifiDirectWorkQueue ObtainWifiDirectWork
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectUtilsTest, DirectWorkQueueTest001, TestSize.Level1)
{
    int32_t ret = WifiDirectWorkQueueInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    WorkFunction data;
    (void)memset_s(&data, sizeof(WorkFunction), 0, sizeof(WorkFunction));
    WifiDirectWork *work = ObtainWifiDirectWork(data, nullptr);
    EXPECT_NE(work, nullptr);
    SoftBusFree(work);
};

/*
* @tc.name: DirectWorkQueueTest002
* @tc.desc: test CallMethodAsync WifiDirectWorkQueueInit
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectUtilsTest, DirectWorkQueueTest002, TestSize.Level1)
{
    WorkFunction data;
    (void)memset_s(&data, sizeof(WorkFunction), 0, sizeof(WorkFunction));
    int64_t delayTimeMs = 1000;
    int32_t ret = CallMethodAsync(data, nullptr, delayTimeMs);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CONN_LOGI(CONN_WIFI_DIRECT, "WifiDirectUtilsTest, testDirectUtilsTest009, End");
};

/*
* @tc.name: SetWifiDirectStatisticLinkType001
* @tc.desc: test SetWifiDirectStatisticLinkType
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectUtilsTest, SetWifiDirectStatisticLinkType001, TestSize.Level1)
{
    (void)InitStatisticMutexLock();
    enum StatisticLinkType linkType = StatisticLinkType::STATISTIC_P2P;
    SetWifiDirectStatisticLinkType(1, linkType);
    enum StatisticLinkType resultLinkType;
    GetWifiDirectStatisticLinkType(1, &resultLinkType);
    EXPECT_EQ(resultLinkType, linkType);
    DestroyWifiDirectStatisticElement(1);
};

/*
* @tc.name: SetWifiDirectStatisticBootLinkType001
* @tc.desc: test SetWifiDirectStatisticBootLinkType
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectUtilsTest, SetWifiDirectStatisticBootLinkType001, TestSize.Level1)
{
    (void)InitStatisticMutexLock();
    enum StatisticBootLinkType linkType = StatisticBootLinkType::STATISTIC_NONE;
    SetWifiDirectStatisticBootLinkType(1, linkType);
    int32_t resultLinkType;
    GetWifiDirectStatisticBootLinkType(1, &resultLinkType);
    EXPECT_EQ(resultLinkType, 0);
    DestroyWifiDirectStatisticElement(1);
};

/*
* @tc.name: SetWifiDirectStatisticRenegotiate001
* @tc.desc: test SetWifiDirectStatisticRenegotiate
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectUtilsTest, SetWifiDirectStatisticRenegotiate001, TestSize.Level1)
{
    (void)InitStatisticMutexLock();
    SetWifiDirectStatisticRenegotiate(1);
    int32_t isRenegotiate;
    GetWifiDirectStatisticRenegotiate(1, &isRenegotiate);
    EXPECT_EQ(isRenegotiate, 1);
    DestroyWifiDirectStatisticElement(1);
};

/*
* @tc.name: SetWifiDirectStatisticReuse001
* @tc.desc: test SetWifiDirectStatisticReuse
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectUtilsTest, SetWifiDirectStatisticReuse001, TestSize.Level1)
{
    (void)InitStatisticMutexLock();
    SetWifiDirectStatisticReuse(1);
    int32_t isReuse;
    GetWifiDirectStatisticReuse(1, &isReuse);
    EXPECT_EQ(isReuse, 1);
    DestroyWifiDirectStatisticElement(1);
};

/*
* @tc.name: SetWifiDirectStatisticLinkTime001
* @tc.desc: test SetWifiDirectStatisticLinkTime
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectUtilsTest, SetWifiDirectStatisticLinkTime001, TestSize.Level1)
{
    (void)InitStatisticMutexLock();
    SetWifiDirectStatisticLinkStartTime(1);
    SetWifiDirectStatisticLinkEndTime(1);
    uint64_t linkTime = -1;
    GetWifiDirectStatisticLinkTime(1, &linkTime);
    EXPECT_NE(linkTime, -1);
    DestroyWifiDirectStatisticElement(1);
};

/*
* @tc.name: SetWifiDirectStatisticNegotiateTime001
* @tc.desc: test SetWifiDirectStatisticNegotiateTime
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectUtilsTest, SetWifiDirectStatisticLinkTime001, TestSize.Level1)
{
    (void)InitStatisticMutexLock();
    SetWifiDirectStatisticNegotiateStartTime(1);
    SetWifiDirectStatisticNegotiateEndTime(1);
    uint64_t negotiateTime = -1;
    GetWifiDirectStatisticNegotiateTime(1, &negotiateTime);
    EXPECT_NE(negotiateTime, -1);
    DestroyWifiDirectStatisticElement(1);
};
} //namespace OHOS
