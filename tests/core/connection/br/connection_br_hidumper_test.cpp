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

#include <gtest/gtest.h>

#include "softbus_conn_br_connection.h"
#include "softbus_conn_br_snapshot.h"
#include "softbus_conn_br_trans.h"
#include "softbus_conn_interface.h"
#include "softbus_feature_config.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

class SoftbusConnBrHiDumperTest : public testing::Test {
public:
    SoftbusConnBrHiDumperTest() { }
    ~SoftbusConnBrHiDumperTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void SoftbusConnBrHiDumperTest::SetUpTestCase(void)
{
    LooperInit();
    SoftbusConfigInit();
    ConnServerInit();
}

void SoftbusConnBrHiDumperTest::TearDownTestCase(void)
{
    LooperDeinit();
}

void SoftbusConnBrHiDumperTest::SetUp(void) { }

void SoftbusConnBrHiDumperTest::TearDown(void) { }

int32_t GetBrConnStateByConnectionId(uint32_t connectId)
{
    (void)connectId;
    return BR_CONNECTION_STATE_CLOSED;
}

/*
 * @tc.name: BrHiDumperTest
 * @tc.desc: test dump method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusConnBrHiDumperTest, BrHiDumperTest, TestSize.Level1)
{
    const char *addr1 = "11:22:33:44:55:66";
    const char *addr2 = "22:33:44:55:66:77";
    ConnBrConnection *connection1 = ConnBrCreateConnection(addr1, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ConnBrSaveConnection(connection1);
    ConnBrConnection *connection2 = ConnBrCreateConnection(addr2, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ConnBrSaveConnection(connection2);
    int fd = 1;
    auto ret = BrHiDumper(fd);
    ASSERT_EQ(SOFTBUS_OK, ret);
}
} // namespace OHOS