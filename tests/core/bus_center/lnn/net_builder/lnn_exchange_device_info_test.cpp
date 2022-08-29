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

#include <gtest/gtest.h>
#include <securec.h>

#include "lnn_exchange_device_info.h"
#include "lnn_node_info.h"
#include "softbus_conn_interface.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"

namespace OHOS {
using namespace testing::ext;

constexpr int32_t SEQ = 1;

class LnnExchangeDeviceInfoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LnnExchangeDeviceInfoTest::SetUpTestCase()
{
}

void LnnExchangeDeviceInfoTest::TearDownTestCase()
{
}

void LnnExchangeDeviceInfoTest::SetUp()
{
}

void LnnExchangeDeviceInfoTest::TearDown()
{
}

/*
* @tc.name: LNN_PARSE_PEER_NODE_INFO_TEST_001
* @tc.desc: test LnnParsePeerNodeInfo return failure
* @tc.type: FUNC
* @tc.require: I5OMIK
*/
HWTEST_F(LnnExchangeDeviceInfoTest, LNN_PARSE_PEER_NODE_INFO_TEST_001, TestSize.Level0)
{
    ConnectOption option;
    NodeInfo info;
    ParseBuf bufInfo;
    uint8_t buf;
    bufInfo.buf = nullptr;
    const ParseBuf *pBufInfo = &bufInfo;
    int32_t ret = LnnParsePeerNodeInfo(&option, AUTH_MAX, &info, pBufInfo, SERVER_SIDE_FLAG, SOFT_BUS_NEW_V1);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    bufInfo.buf = &buf;
    bufInfo.len = 1;
    ret = LnnParsePeerNodeInfo(&option, AUTH_MAX, &info, pBufInfo, SERVER_SIDE_FLAG, SOFT_BUS_NEW_V1);
    EXPECT_TRUE(ret == SOFTBUS_MALLOC_ERR);
    bufInfo.len = 33;
    ret = LnnParsePeerNodeInfo(&option, AUTH_MAX, &info, pBufInfo, SERVER_SIDE_FLAG, SOFT_BUS_NEW_V1);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: LNN_GET_EXCHANGE_NODE_INFO_TEST_001
* @tc.desc: test LnnCompareNodeWeight return failure
* @tc.type: FUNC
* @tc.require: I5OMIK
*/
HWTEST_F(LnnExchangeDeviceInfoTest, LNN_GET_EXCHANGE_NODE_INFO_TEST_001, TestSize.Level0)
{
    uint32_t *outSize = nullptr;
    int32_t *side = nullptr;
    uint32_t size;
    int32_t side2;
    uint8_t *ret = LnnGetExchangeNodeInfo(SEQ, AUTH_MAX, SOFT_BUS_NEW_V1, outSize, side);
    EXPECT_TRUE(ret == nullptr);
    ret = LnnGetExchangeNodeInfo(SEQ, AUTH_MAX, SOFT_BUS_NEW_V1, &size, &side2);
    EXPECT_TRUE(ret == nullptr);
}
} // namespace OHOS
