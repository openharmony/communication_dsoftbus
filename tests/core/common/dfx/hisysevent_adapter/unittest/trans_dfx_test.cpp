/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string>
#include <gtest/gtest.h>

#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "softbus_log.h"
#include "softbus_common.h"
#include "softbus_hisysevt_transreporter.h"
#include "securec.h"
#include "softbus_adapter_hisysevent.h"
#include "softbus_hisysevt_common.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
class TransDfxTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void TransDfxTest::SetUpTestCase(void) {}

void TransDfxTest::TearDownTestCase(void) {}

void TransDfxTest::SetUp(void) {}

void TransDfxTest::TearDown(void) {}

/**
 * @tc.name: CreateTransFaultEvtTest001
 * @tc.desc: Verify SoftbusReportTransErrorEvt function, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require: I5NJEO
 */
HWTEST_F(TransDfxTest, CreateTransFaultEvtTest001, TestSize.Level0)
{
    int32_t errorCode = SOFTBUS_ACCESS_TOKEN_DENIED;
    SoftbusReportTransErrorEvt(errorCode);
}
}; // namespace OHOS

