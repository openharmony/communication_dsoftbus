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

#include "securec.h"
#include "softbus_bitmap.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

#define BITNUM   32
#define TEST_POS 1
#define TEST_BIT 2

using namespace std;
using namespace testing::ext;

namespace OHOS {
class CommonCoreBitMapTest : public testing::Test {
public:
    CommonCoreBitMapTest() { }
    ~CommonCoreBitMapTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void CommonCoreBitMapTest::SetUpTestCase(void) { }
void CommonCoreBitMapTest::TearDownTestCase(void) { }

/**
 * @tc.name: CommonBitMapTest001
 * @tc.desc: core common bit map test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CommonCoreBitMapTest, CommonBitMapTest001, TestSize.Level0)
{
    uint8_t pos = BITNUM + 1;
    uint32_t bitmap = 0;

    SoftbusBitmapSet(nullptr, pos);
    EXPECT_EQ(SOFTBUS_OK, bitmap);

    SoftbusBitmapClr(nullptr, pos);
    EXPECT_EQ(SOFTBUS_OK, bitmap);

    bool result = SoftbusIsBitmapSet(nullptr, pos);
    EXPECT_EQ(false, result);

    bitmap = OSD_CAPABILITY_BITMAP;
    SoftbusBitmapSet(&bitmap, pos);
    EXPECT_EQ(OSD_CAPABILITY_BITMAP, bitmap);

    bitmap = OSD_CAPABILITY_BITMAP;
    SoftbusBitmapClr(&bitmap, pos);
    EXPECT_EQ(OSD_CAPABILITY_BITMAP, bitmap);

    bitmap = OSD_CAPABILITY_BITMAP;
    result = SoftbusIsBitmapSet(&bitmap, pos);
    EXPECT_EQ(false, result);

    pos = TEST_POS;
    bitmap = OSD_CAPABILITY_BITMAP;
    SoftbusBitmapSet(&bitmap, pos);
    EXPECT_EQ(OSD_CAPABILITY_BITMAP, bitmap);

    bitmap = OSD_CAPABILITY_BITMAP;
    SoftbusBitmapSet(&bitmap, pos);
    EXPECT_EQ(OSD_CAPABILITY_BITMAP, bitmap);
}
} // namespace OHOS