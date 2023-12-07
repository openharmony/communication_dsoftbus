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
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"
#include "wifi_direct_negotiator.h"
#include "wifi_direct_processor_factory.h"
#include "processing_state.h"
#include "negotiate_message.h"
#include "available_state.h"
#include "waiting_connect_request_state.h"
#include "waiting_connect_response_state.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

class NegotiateStateTest : public testing::Test {
public:
    NegotiateStateTest()
    {}
    ~NegotiateStateTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void NegotiateStateTest::SetUpTestCase(void) {}
void NegotiateStateTest::TearDownTestCase(void) {}
void NegotiateStateTest::SetUp(void) {}
void NegotiateStateTest::TearDown(void) {}

/* processing_state.c */
/*
* @tc.name: NegotiateStateTest001
* @tc.desc: test HandleNegotiateMessageFromRemote
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(NegotiateStateTest, NegotiateStateTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "NegotiateStateTest, NegotiateStateTest001, Start");
    struct WifiDirectNegotiator* negotiator = GetWifiDirectNegotiator();
    struct ProcessingState* self = GetProcessingState(negotiator);
    struct WifiDirectProcessor *processor =
        GetWifiDirectProcessorFactory()->createProcessor(WIFI_DIRECT_PROCESSOR_TYPE_P2P_V1);
    struct NegotiateMessage* msg = NegotiateMessageNew();

    self->onTimeout(NEGO_TIMEOUT_EVENT_WAITING_PROCESSING);
    self->onTimeout(NEGO_TIMEOUT_EVENT_INVALID);
    int32_t ret = self->handleNegotiateMessageFromRemote(processor, CMD_DISCONNECT_V1_REQ, msg);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = self->handleNegotiateMessageFromRemote(processor, CMD_PC_GET_INTERFACE_INFO_REQ, msg);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    ret = self->handleNegotiateMessageFromRemote(processor, CMD_CTRL_CHL_HANDSHAKE, msg);
    EXPECT_NE(ret, SOFTBUS_OK);
    CONN_LOGI(CONN_WIFI_DIRECT, "NegotiateStateTest, NegotiateStateTest001, End");
};

/* waiting_connect_request_state.c */
/*
* @tc.name: NegotiateStateTest002
* @tc.desc: test HandleNegotiateMessageFromRemote
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(NegotiateStateTest, NegotiateStateTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "NegotiateStateTest, NegotiateStateTest002, Start");
    struct WifiDirectNegotiator* negotiator = GetWifiDirectNegotiator();
    struct WaitingConnectRequestState* self = GetWaitingConnectRequestState(negotiator);
    struct WifiDirectProcessor *processor =
        GetWifiDirectProcessorFactory()->createProcessor(WIFI_DIRECT_PROCESSOR_TYPE_P2P_V1);
    struct NegotiateMessage* msg = NegotiateMessageNew();

    self->onTimeout(NEGO_TIMEOUT_EVENT_WAITING_CONNECT_REQUEST);
    self->onTimeout(NEGO_TIMEOUT_EVENT_INVALID);
    int32_t ret = self->handleNegotiateMessageFromRemote(processor, CMD_CTRL_CHL_HANDSHAKE, msg);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = self->handleNegotiateMessageFromRemote(processor, CMD_INVALID, msg);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CONN_LOGI(CONN_WIFI_DIRECT, "NegotiateStateTest, NegotiateStateTest002, End");
};

/* waiting_connect_response_state.c */
/*
* @tc.name: NegotiateStateTest003
* @tc.desc: test HandleNegotiateMessageFromRemote
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(NegotiateStateTest, NegotiateStateTest003, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "NegotiateStateTest, NegotiateStateTest003, Start");
    struct WifiDirectNegotiator* negotiator = GetWifiDirectNegotiator();
    struct WaitingConnectResponseState* self = GetWaitingConnectResponseState(negotiator);
    struct WifiDirectProcessor *processor =
        GetWifiDirectProcessorFactory()->createProcessor(WIFI_DIRECT_PROCESSOR_TYPE_P2P_V1);
    struct NegotiateMessage* msg = NegotiateMessageNew();

    self->onTimeout(NEGO_TIMEOUT_EVENT_WAITING_CONNECT_RESPONSE);
    self->onTimeout(NEGO_TIMEOUT_EVENT_INVALID);
    int32_t ret = self->handleNegotiateMessageFromRemote(processor, CMD_CTRL_CHL_HANDSHAKE, msg);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = self->handleNegotiateMessageFromRemote(processor, CMD_INVALID, msg);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CONN_LOGI(CONN_WIFI_DIRECT, "NegotiateStateTest, NegotiateStateTest003, End");
};

/* available_state.c */
/*
* @tc.name: NegotiateStateTest004
* @tc.desc: test HandleNegotiateMessageFromRemote
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(NegotiateStateTest, NegotiateStateTest004, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "NegotiateStateTest, NegotiateStateTest004, Start");
    struct WifiDirectNegotiator* negotiator = GetWifiDirectNegotiator();
    struct AvailableState* self = GetAvailableState(negotiator);
    struct WifiDirectProcessor *processor =
        GetWifiDirectProcessorFactory()->createProcessor(WIFI_DIRECT_PROCESSOR_TYPE_P2P_V1);
    struct NegotiateMessage* msg = NegotiateMessageNew();

    int32_t ret = self->handleNegotiateMessageFromRemote(processor, CMD_CONN_V1_REQ, msg);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = self->handleNegotiateMessageFromRemote(processor, CMD_INVALID, msg);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CONN_LOGI(CONN_WIFI_DIRECT, "NegotiateStateTest, NegotiateStateTest004, End");
};
} // namespace OHOS
