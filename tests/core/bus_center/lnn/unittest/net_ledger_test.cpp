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
#include "lnn_decision_db.h"
#include "lnn_decision_db.c"

namespace OHOS {
using namespace testing::ext;
constexpr uint32_t TEST_DATA_LEN = 10;

class NetLedgerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void NetLedgerTest::SetUpTestCase()
{
}

void NetLedgerTest::TearDownTestCase()
{
}

void NetLedgerTest::SetUp()
{
    LOG_INFO("NetLedgerTest start.");
}

void NetLedgerTest::TearDown()
{
}

/*
* @tc.name: BUILD_TRUSTED_DEV_INFO_RECORD_Test_001
* @tc.desc: build trusted dev info record test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(NetLedgerTest, BUILD_TRUSTED_DEV_INFO_RECORD_Test_001, TestSize.Level1)
{
    const char *udid = "testdata";
    TrustedDevInfoRecord record;
    int32_t ret;

    (void)memset_s(&record, sizeof(TrustedDevInfoRecord), 0, sizeof(TrustedDevInfoRecord));
    ret = BuildTrustedDevInfoRecord(udid, &record);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LNN_GET_TRUSTED_DEV_INFO_FROM_DB_Test_001
* @tc.desc: lnn get trusted dev info from db test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(NetLedgerTest, LNN_GET_TRUSTED_DEV_INFO_FROM_DB_Test_001, TestSize.Level1)
{
    uint32_t num = 0;
    int32_t ret;

    char *udidArray = (char *)SoftBusMalloc(TEST_DATA_LEN);
    ret = LnnGetTrustedDevInfoFromDb(&udidArray, &num);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    SoftBusFree(udidArray);
}
} // namespace OHOS
