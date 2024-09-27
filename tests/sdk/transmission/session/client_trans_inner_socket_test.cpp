/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "inner_socket.h"
#include "nativetoken_kit.h"
#include "softbus_error_code.h"
#include "token_setproc.h"

using namespace testing::ext;
namespace OHOS {
namespace {
void CounterfeitProcess(const char *processName)
{
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 0,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = nullptr,
        .acls = nullptr,
        .processName = processName,
        .aplStr = "system_core",
    };
    uint64_t tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
}
} // namespace

class ClientTransSocketTest : public testing::Test { };

/*
 * @tc.name: DBinderGrantPermissionTest001
 * @tc.desc: Grant permission to DBinder test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransSocketTest, DBinderGrantPermissionTest001, TestSize.Level1)
{
    CounterfeitProcess("samgr");
    int32_t uid = getuid();
    ASSERT_GE(uid, 0);
    int32_t pid = getpid();
    ASSERT_GT(pid, 0);
    std::string socketName = "DBinder" + std::to_string(uid) + std::string("_") + std::to_string(pid);
    auto ret = DBinderGrantPermission(uid, pid, socketName.c_str());
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = DBinderRemovePermission(socketName.c_str());
    ASSERT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: DBinderGrantPermissionTest002
 * @tc.desc: Other percess call DBinderGrantPermission test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransSocketTest, DBinderGrantPermissionTest002, TestSize.Level1)
{
    CounterfeitProcess("msdp");
    int32_t uid = getuid();
    ASSERT_GE(uid, 0);
    int32_t pid = getpid();
    ASSERT_GT(pid, 0);
    std::string socketName = "DBinder" + std::to_string(uid) + std::string("_") + std::to_string(pid);
    auto ret = DBinderGrantPermission(uid, pid, socketName.c_str());
    ASSERT_EQ(ret, SOFTBUS_TRANS_PROXY_SEND_REQUEST_FAILED);
}

/*
 * @tc.name: DBinderRemovePermissionTest001
 * @tc.desc: Other percess call DBinderRemovePermission test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransSocketTest, DBinderRemovePermissionTest001, TestSize.Level1)
{
    CounterfeitProcess("samgr");
    int32_t uid = getuid();
    ASSERT_GE(uid, 0);
    int32_t pid = getpid();
    ASSERT_GT(pid, 0);
    std::string socketName = "DBinder" + std::to_string(uid) + std::string("_") + std::to_string(pid);
    auto ret = DBinderGrantPermission(uid, pid, socketName.c_str());
    ASSERT_EQ(ret, SOFTBUS_OK);
    CounterfeitProcess("msdp");
    ret = DBinderRemovePermission(socketName.c_str());
    ASSERT_EQ(ret, SOFTBUS_TRANS_PROXY_SEND_REQUEST_FAILED);
}
} // namespace OHOS
