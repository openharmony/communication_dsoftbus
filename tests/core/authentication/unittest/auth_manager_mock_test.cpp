/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <cinttypes>
#include <gtest/gtest.h>
#include <securec.h>
#include <sys/time.h>

#include "anonymizer.h"
#include "auth_manager.c"
#include "auth_manager.h"
#include "auth_manager_deps_mock.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;

constexpr char UDID_TEST[UDID_BUF_LEN] = "testId123";
constexpr char UUID_TEST[UUID_BUF_LEN] = "testId123";
constexpr int64_t AUTH_SEQ = 1;

class AuthManagerMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthManagerMockTest::SetUpTestCase() { }

void AuthManagerMockTest::TearDownTestCase() { }

void AuthManagerMockTest::SetUp() { }

void AuthManagerMockTest::TearDown() { }

/*
 * @tc.name: RAW_LINK_NEED_UPDATE_AUTH_MANAGER_TEST_001
 * @tc.desc: RawLinkNeedUpdateAuthManager test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, RAW_LINK_NEED_UPDATE_AUTH_MANAGER_TEST_001, TestSize.Level1)
{
    AuthManagerInterfaceMock authManagerMock;
    EXPECT_CALL(authManagerMock, RequireAuthLock).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, ReleaseAuthLock).WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, CheckAuthConnInfoType).WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, InitSessionKeyList).WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, GetAuthSideStr).WillRepeatedly(Return("server"));
    EXPECT_CALL(authManagerMock, AuthNotifyDeviceVerifyPassed).WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, CancelUpdateSessionKey).WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, DestroySessionKeyList).WillRepeatedly(Return());
    bool ret = RawLinkNeedUpdateAuthManager(nullptr, true);
    EXPECT_FALSE(ret);
    ret = RawLinkNeedUpdateAuthManager(UUID_TEST, true);
    EXPECT_FALSE(ret);
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    EXPECT_EQ(strcpy_s(info.udid, UDID_BUF_LEN, UDID_TEST), EOK);
    EXPECT_EQ(strcpy_s(info.uuid, UUID_BUF_LEN, UUID_TEST), EOK);
    info.isServer = true;
    AuthManager *auth = NewAuthManager(AUTH_SEQ, &info);
    EXPECT_NE(auth, nullptr);
    ret = RawLinkNeedUpdateAuthManager(UUID_TEST, true);
    EXPECT_FALSE(ret);
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    info.isSavedSessionKey = true;
    AuthHandle handle;
    info.isConnectServer = true;
    NotifyAuthResult(handle, &info);
    DelAuthManager(auth, AUTH_LINK_TYPE_MAX);
}
} // namespace OHOS