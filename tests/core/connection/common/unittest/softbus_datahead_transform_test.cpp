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

#include "gtest/gtest.h"
#include <securec.h>

#include "softbus_datahead_transform.h"

using namespace testing::ext;

namespace OHOS {
#define TEST_CHANNEL_ID 1124

class DataheadTransformTest : public testing::Test {
public:
    DataheadTransformTest()
    {}
    ~DataheadTransformTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void DataheadTransformTest::SetUpTestCase(void) {}

void DataheadTransformTest::TearDownTestCase(void) {}

/**
 * @tc.name: DataheadTransformTest001
 * @tc.desc: PackProxyMessageShortHead
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DataheadTransformTest, DataheadTransformTest001, TestSize.Level1)
{
    ProxyMessageShortHead msgHead = { 0 };
    EXPECT_NO_FATAL_FAILURE(PackProxyMessageShortHead(nullptr));
    EXPECT_NO_FATAL_FAILURE(PackProxyMessageShortHead(&msgHead));
}
}
