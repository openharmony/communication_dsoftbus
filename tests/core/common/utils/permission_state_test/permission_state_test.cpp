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
#include "trans_client_proxy.h"
#include "permission_status_change_cb.h"
#include "softbus_common.h"
#include "softbus_errcode.h"
#include <string>

#define TOKENID 7758
#define STATE 1

using namespace testing::ext;

namespace OHOS {
static std::string g_pkgName = "com.huawei.plrdtest.dsoftbus";
static std::string g_permName = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
static uint32_t g_callingTokenId = TOKENID;

class PermissionStateTest : public testing::Test {
public:
    PermissionStateTest()
    {}
    ~PermissionStateTest()
    {}
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp()
    {}
    void TearDown()
    {}
};

void PermissionStateTest::SetUpTestCase()
{
}

void PermissionStateTest::TearDownTestCase()
{
}

/**
 * @tc.name: PermissionStateTest001
 * @tc.desc: PermissionStateAPI.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionStateTest, PermissionStateTest001, TestSize.Level0)
{
    Security::AccessToken::PermStateChangeScope scopeInfo;
    scopeInfo.permList = {g_permName};
    scopeInfo.tokenIDs = {g_callingTokenId};
    std::shared_ptr<PermissionStatusChangeCb> callbackPtr_ =
        std::make_shared<PermissionStatusChangeCb>(scopeInfo, g_pkgName);
    struct PermStateChangeInfo result{STATE, g_callingTokenId, g_permName};
    callbackPtr_->PermStateChangeCallback(result);
}
} // namespace OHOS