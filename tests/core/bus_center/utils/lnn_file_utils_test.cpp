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

#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>

#include "lnn_decision_db_deps_mock.h"
#include "lnn_file_utils.h"
#include "softbus_adapter_file.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

class LNNFileUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNFileUtilsTest::SetUpTestCase() { }

void LNNFileUtilsTest::TearDownTestCase() { }

void LNNFileUtilsTest::SetUp() { }

void LNNFileUtilsTest::TearDown() { }

/*
 * @tc.name: LNN_REMOVE_STORAGE_CONFIG_PATH_TEST_001
 * @tc.desc: LnnRemoveStorageConfigPathTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNFileUtilsTest, LNN_REMOVE_STORAGE_CONFIG_PATH_TEST_001, TestSize.Level1)
{
    DecisionDbDepsInterfaceMock decisionDbMock;
    EXPECT_CALL(decisionDbMock, LnnGetFullStoragePath(_, _, _))
        .WillOnce(Return(SOFTBUS_FILE_ERR)).WillRepeatedly(Return(SOFTBUS_OK));

    int32_t ret = LnnRemoveStorageConfigPath(LNN_FILE_ID_UUID);
    EXPECT_TRUE(ret == SOFTBUS_FILE_ERR);
    ret = LnnRemoveStorageConfigPath(LNN_FILE_ID_IRK_KEY);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}
} // namespace OHOS