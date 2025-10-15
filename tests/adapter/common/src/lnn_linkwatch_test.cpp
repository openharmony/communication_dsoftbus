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
#include <securec.h>
#include <ctime>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "gtest/gtest.h"
#include "lnn_linkwatch.h"
#include "lnn_log.h"
#include "softbus_adapter_errcode.h"
#include "softbus_adapter_socket.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
class LnnLinkWatchTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LnnLinkWatchTest::SetUpTestCase() { }

void LnnLinkWatchTest::TearDownTestCase() { }

void LnnLinkWatchTest::SetUp() { }

void LnnLinkWatchTest::TearDown() { }

/*
 * @tc.name: Add_Attr_001
 * @tc.desc: Verify the LnnIsLinkReady function return value equal false
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LnnLinkWatchTest, LnnIsLinkReady_001, TestSize.Level1)
{
    char *iface = nullptr;
    bool ret = LnnIsLinkReady(iface);
    EXPECT_EQ(ret, false);
}
} // namespace OHOS