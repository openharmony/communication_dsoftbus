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

#include "conn_log.h"
#include "cJSON.h"
#include "json_protocol.h"
#include "softbus_adapter_mem.h"
#include "wifi_direct_protocol_factory.h"
#include "wifi_direct_protocol.h"
#include "json_mock.h"
#include "softbus_json_utils.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr size_t DEFAULT_LEN = 0;
constexpr uint32_t MIN_SIZE = 0;
constexpr uint32_t DEFAULT_SIZE = 1;

class WifiDirectProtocolTest : public testing::Test {
public:
    WifiDirectProtocolTest()
    {}
    ~WifiDirectProtocolTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void WifiDirectProtocolTest::SetUpTestCase(void) {}
void WifiDirectProtocolTest::TearDownTestCase(void) {}
void WifiDirectProtocolTest::SetUp(void) {}
void WifiDirectProtocolTest::TearDown(void) {}

static bool TrueMarShalling(InfoContainer *container, WifiDirectProtocol *base)
{
    return true;
}

/* json_protocol.c */
/*
* @tc.name: testWifiProtocol001
* @tc.desc: test writeData
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectProtocolTest, testWifiProtocol001, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "WifiDirectProtocolTest, testWifiProtocol001, Start");
    WifiDirectMock wifiDirectMock;
    struct WifiDirectProtocolFactory* factory = GetWifiDirectProtocolFactory();
    struct WifiDirectProtocol *base = static_cast<struct WifiDirectProtocol*>(SoftBusCalloc(sizeof(*base)));
    struct InfoContainerKeyProperty *keyProperty = static_cast<struct InfoContainerKeyProperty*>
                                                    (SoftBusCalloc(sizeof(*keyProperty)));
    uint8_t *data = static_cast<uint8_t *>(SoftBusCalloc(sizeof(*data)));
    size_t size = DEFAULT_LEN;
    struct WifiDirectProtocol* protocol = factory->createProtocol(WIFI_DIRECT_PROTOCOL_JSON);

    keyProperty->type = STRING;
    EXPECT_CALL(wifiDirectMock, AddStringToJsonObject(_, _, _)).WillRepeatedly(Return(true));
    bool ret = protocol->writeData(base, keyProperty, data, size);
    EXPECT_TRUE(ret);
    EXPECT_CALL(wifiDirectMock, AddStringToJsonObject(_, _, _)).WillRepeatedly(Return(false));
    ret = protocol->writeData(base, keyProperty, data, size);
    EXPECT_TRUE(ret == false);
    keyProperty->type = INT;
    EXPECT_CALL(wifiDirectMock, AddNumberToJsonObject(_, _, _)).WillRepeatedly(Return(true));
    ret = protocol->writeData(base, keyProperty, data, size);
    EXPECT_TRUE(ret);
    EXPECT_CALL(wifiDirectMock, AddNumberToJsonObject(_, _, _)).WillRepeatedly(Return(false));
    ret = protocol->writeData(base, keyProperty, data, size);
    EXPECT_TRUE(ret == false);
    keyProperty->type = BOOLEAN;
    EXPECT_CALL(wifiDirectMock, AddBoolToJsonObject(_, _, _)).WillRepeatedly(Return(true));
    ret = protocol->writeData(base, keyProperty, data, size);
    EXPECT_TRUE(ret);
    EXPECT_CALL(wifiDirectMock, AddBoolToJsonObject(_, _, _)).WillRepeatedly(Return(false));
    ret = protocol->writeData(base, keyProperty, data, size);
    EXPECT_TRUE(ret == false);
    keyProperty->type = BYTE;
    EXPECT_TRUE(ret == false);

    SoftBusFree(base);
    SoftBusFree(keyProperty);
    SoftBusFree(data);
    factory->destroyProtocol(protocol);
    CONN_LOGI(CONN_WIFI_DIRECT, "WifiDirectProtocolTest, testWifiProtocol001, End");
};

/* tlv_protocol.c */
/*
* @tc.name: testWifiProtocol002
* @tc.desc: test setDataSource
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectProtocolTest, testWifiProtocol002, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "WifiDirectProtocolTest, testWifiProtocol002, Start");
    struct WifiDirectProtocolFactory* factory = GetWifiDirectProtocolFactory();
    struct WifiDirectProtocol *base = static_cast<struct WifiDirectProtocol*>(SoftBusCalloc(sizeof(*base)));
    struct InfoContainer *container = static_cast<struct InfoContainer*>(SoftBusCalloc(sizeof(*container)));
    uint8_t *outBuffer = static_cast<uint8_t *>(SoftBusCalloc(sizeof(*outBuffer)));
    size_t size = DEFAULT_LEN;
    struct WifiDirectProtocol* protocol = factory->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    container->marshalling = TrueMarShalling;

    bool ret = protocol->pack(base, container, &outBuffer, &size);
    EXPECT_TRUE(ret);
    ret = protocol->setDataSource(base, outBuffer, size);
    EXPECT_EQ(ret, false);

    factory->destroyProtocol(protocol);
    SoftBusFree(base);
    SoftBusFree(container);
    SoftBusFree(outBuffer);
    CONN_LOGI(CONN_WIFI_DIRECT, "WifiDirectProtocolTest, testWifiProtocol002, End");
};

/*
* @tc.name: testWifiProtocol003
* @tc.desc: test readData and writeData
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectProtocolTest, testWifiProtocol003, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "WifiDirectProtocolTest, testWifiProtocol003, Start");
    struct WifiDirectProtocol *base = static_cast<struct WifiDirectProtocol*>(SoftBusCalloc(sizeof(*base)));
    struct InfoContainerKeyProperty *keyProperty = static_cast<struct InfoContainerKeyProperty*>
                                                    (SoftBusCalloc(sizeof(*keyProperty)));
    uint8_t *data = static_cast<uint8_t *>(SoftBusCalloc(sizeof(*data)));
    size_t size = DEFAULT_LEN;
    struct WifiDirectProtocolFactory* factory = GetWifiDirectProtocolFactory();
    struct WifiDirectProtocol* protocol = factory->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);

    bool ret = protocol->readData(base, keyProperty, &data, &size);
    EXPECT_EQ(ret, false);
    size_t length = DEFAULT_LEN;
    ret = protocol->writeData(base, keyProperty, data, length);
    EXPECT_EQ(ret, false);
    base->format.tagSize = DEFAULT_SIZE;
    ret = protocol->readData(base, keyProperty, &data, &size);
    EXPECT_EQ(ret, false);
    base->format.tagSize = MIN_SIZE;
    base->format.lengthSize = DEFAULT_SIZE;
    ret = protocol->readData(base, keyProperty, &data, &size);
    EXPECT_EQ(ret, false);
    
    factory->destroyProtocol(protocol);
    SoftBusFree(base);
    SoftBusFree(keyProperty);
    SoftBusFree(data);
    CONN_LOGI(CONN_WIFI_DIRECT, "WifiDirectProtocolTest, testWifiProtocol003, End");
};
} // namespace OHOS
