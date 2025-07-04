/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <securec.h>

#include "auth_interface.h"
#include "client_trans_message_service.c"
#include "softbus_app_info.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_conn_interface.h"
#include "softbus_config_type.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"
#include "softbus_server_frame.h"
#include "softbus_trans_def.h"
#include "trans_log.h"
#include "trans_common_mock.h"
#include "trans_manager_mock.h"
#include "trans_service_mock.h"

#define TRANS_TEST_BEYOND_MAX_BYTES_LEN (6 * 1024 * 1024)
#define TRANS_TEST_INVALID_SEND_LEN (1024 * 1024)
#define TRANS_TEST_SEND_LEN 123

using namespace std;
using namespace testing;
using namespace testing::ext;
using testing::NiceMock;

namespace OHOS {

class TransClientMsgServiceExTest : public testing::Test {
public:
    TransClientMsgServiceExTest()
    {}
    ~TransClientMsgServiceExTest()
    {}
    static void SetUpTestCase(void)
    {}
    static void TearDownTestCase(void)
    {}
    void SetUp() override
    {}
    void TearDown() override
    {}
};

/**
 * @tc.name: CheckSendLenForBoosterTest01
 * @tc.desc: CheckSendLenForBooster with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientMsgServiceExTest, CheckSendLenForBoosterTest01, TestSize.Level1)
{
    NiceMock<TransCommInterfaceMock> transCommInterfaceMock;
    EXPECT_CALL(transCommInterfaceMock, SoftbusGetConfig).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(TransCommInterfaceMock::ActionOfSoftbusGetConfig);

    int32_t ret = CheckSendLenForBooster(TRANS_TEST_INVALID_SEND_LEN);
    EXPECT_EQ(ret, SOFTBUS_GET_CONFIG_VAL_ERR);

    ret = CheckSendLenForBooster(TRANS_TEST_BEYOND_MAX_BYTES_LEN);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SEND_LEN_BEYOND_LIMIT);

    ret = CheckSendLenForBooster(0);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransClientMsgServiceTest01
 * @tc.desc: Transmission sdk message service check send length with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientMsgServiceExTest, TransClientMsgServiceTest01, TestSize.Level1)
{
    NiceMock<TransMgrInterfaceMock> transMgrInterfaceMock;
    EXPECT_CALL(transMgrInterfaceMock, ClientGetDataConfigByChannelId).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillOnce(TransMgrInterfaceMock::ActionOfClientGetDataConfigByChannelId).WillRepeatedly(Return(SOFTBUS_OK));
    
    int32_t ret = CheckSendLen(CHANNEL_TYPE_AUTH, BUSINESS_TYPE_MESSAGE, TRANS_TEST_SEND_LEN, BUSINESS_TYPE_MESSAGE);
    EXPECT_EQ(ret, SOFTBUS_GET_CONFIG_VAL_ERR);

    ret = CheckSendLen(CHANNEL_TYPE_AUTH, BUSINESS_TYPE_MESSAGE, TRANS_TEST_SEND_LEN, BUSINESS_TYPE_MESSAGE);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SEND_LEN_BEYOND_LIMIT);

    NiceMock<TransServiceInterfaceMock> transServiceInterfaceMock;
    EXPECT_CALL(transServiceInterfaceMock, GetDefaultConfigType).WillOnce(Return(SOFTBUS_CONFIG_TYPE_MAX))
        .WillRepeatedly(Return(SOFTBUS_INT_STATIC_NET_CAPABILITY));
    
    ret = CheckSendLen(CHANNEL_TYPE_AUTH, BUSINESS_TYPE_MESSAGE, TRANS_TEST_SEND_LEN, BUSINESS_TYPE_MESSAGE);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    NiceMock<TransCommInterfaceMock> transCommInterfaceMock;
    EXPECT_CALL(transCommInterfaceMock, SoftbusGetConfig).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(TransCommInterfaceMock::ActionOfSoftbusGetConfig);
    
    ret = CheckSendLen(CHANNEL_TYPE_AUTH, BUSINESS_TYPE_MESSAGE, TRANS_TEST_SEND_LEN, BUSINESS_TYPE_MESSAGE);
    EXPECT_EQ(ret, SOFTBUS_GET_CONFIG_VAL_ERR);

    ret = CheckSendLen(CHANNEL_TYPE_AUTH, BUSINESS_TYPE_MESSAGE, INVALID_DATA_CONFIG, BUSINESS_TYPE_MESSAGE);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
}
