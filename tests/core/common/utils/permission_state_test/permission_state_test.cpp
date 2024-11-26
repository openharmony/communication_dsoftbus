/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include <string>

#include "softbus_common.h"
#include "softbus_error_code.h"
#include "trans_client_proxy.h"

#define PID     520
#define TOKENID 7758
#define STATE   1

using namespace testing::ext;

namespace OHOS {
static std::string g_pkgName = "com.huawei.plrdtest.dsoftbus";
static std::string g_permName = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;

class PermissionStateTest : public testing::Test {
public:
    PermissionStateTest() { }
    ~PermissionStateTest() { }
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() { }
    void TearDown() { }
};

void PermissionStateTest::SetUpTestCase() { }

void PermissionStateTest::TearDownTestCase() { }

} // namespace OHOS