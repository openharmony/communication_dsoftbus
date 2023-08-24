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

#include "wifi_direct_ipv4_info.h"
#include "softbus_log.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "wifi_direct_defines.h"
#include "wifi_direct_network_utils.h"
#include "wifi_direct_perf_recorder.h"
#include "wifi_direct_timer_list.h"
#include "wifi_direct_command_manager.h"
#include "wifi_direct_network_utils.h"
#include "wifi_direct_work_queue.h"
#include "wifi_direct_manager.h"
#include "wifi_direct_defines.h"
#include "wifi_direct_utils.h"
#include "wifi_direct_types.h"
#include "data/link_info.h"
#include "softbus_adapter_timer.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

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
* @tc.desc: test WifiDirectIpv4InfoToBytes
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectUtilsTest, testDirectUtilsTest001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "WifiDirectUtilsTest, testDirectUtilsTest001, Start");
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
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "WifiDirectUtilsTest, testDirectUtilsTest001, End");
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
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "WifiDirectUtilsTest, testDirectUtilsTest002, Start");
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
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "WifiDirectUtilsTest, testDirectUtilsTest002, End");
};

/*
* @tc.name: testDirectUtilsTest003
* @tc.desc: test TransferRoleToPreferLinkMode
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectUtilsTest, testDirectUtilsTest003, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "WifiDirectUtilsTest, testDirectUtilsTest003, Start");
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
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "WifiDirectUtilsTest, testDirectUtilsTest003, End");
};

/*
* @tc.name: testDirectUtilsTest004
* @tc.desc: test StrCompareIgnoreCase
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectUtilsTest, testDirectUtilsTest004, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "WifiDirectUtilsTest, testDirectUtilsTest004, Start");
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
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "WifiDirectUtilsTest, testDirectUtilsTest004, End");
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
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "WifiDirectUtilsTest, testDirectUtilsTest005, Start");
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
    EXPECT_TRUE(ret == SOFTBUS_OK);
    SoftBusFree(ipv4);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "WifiDirectUtilsTest, testDirectUtilsTest005, End");
};

/*
* @tc.name: testDirectUtilsTest006
* @tc.desc: test ChannelListToString
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectUtilsTest, testDirectUtilsTest006, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "WifiDirectUtilsTest, testDirectUtilsTest006, Start");
    struct WifiDirectNetWorkUtils* self = GetWifiDirectNetWorkUtils();
    int32_t array[ARRARY_COUNT] = {TEST_DATA1, TEST_DATA2};
    int32_t *channelArray = array;
    size_t channelArraySize = ARRARY_COUNT;
    char *channelListString = static_cast<char *>(SoftBusCalloc(sizeof(*channelListString) * (IN_SIZE)));
    size_t inSize = IN_SIZE;
    int32_t ret = self->channelListToString(channelArray, channelArraySize, channelListString, inSize);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    SoftBusFree(channelListString);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "WifiDirectUtilsTest, testDirectUtilsTest006, End");
};

/*
* @tc.name: testDirectUtilsTest007
* @tc.desc: test frequencyToChannel
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectUtilsTest, testDirectUtilsTest007, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "WifiDirectUtilsTest, testDirectUtilsTest007, Start");
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
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "WifiDirectUtilsTest, testDirectUtilsTest007, End");
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
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "WifiDirectUtilsTest, testDirectUtilsTest008, Start");
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
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "WifiDirectUtilsTest, testDirectUtilsTest008, End");
};

/*
* @tc.name: testDirectUtilsTest009
* @tc.desc: test WifiDirectIpv4InfoToBytes
* @tc.type: FUNC
* @tc.require: AR000I9Q40
*/
HWTEST_F(WifiDirectUtilsTest, testDirectUtilsTest009, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "WifiDirectUtilsTest, testDirectUtilsTest009, Start");
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
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "WifiDirectUtilsTest, testDirectUtilsTest009, End");
};
} //namespace OHOS
