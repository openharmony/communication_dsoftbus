/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <pthread.h>
#include <securec.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "wifi_direct_role_negotiator.h"
#include <string.h>
#include "softbus_error_code.h"
#include "utils/wifi_direct_utils.h"
#include "utils/wifi_direct_anonymous.h"

using namespace testing::ext;
namespace OHOS {

class WifiDirectRoleNegoTest : public testing::Test {
public:
    WifiDirectRoleNegoTest()
    {}
    ~WifiDirectRoleNegoTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void WifiDirectRoleNegoTest::SetUpTestCase(void)
{}

void WifiDirectRoleNegoTest::TearDownTestCase(void)
{}

void WifiDirectRoleNegoTest::SetUp(void)
{}

void WifiDirectRoleNegoTest::TearDown(void)
{}

/*
* @tc.name: WifiDirectRoleNegoTest001
* @tc.desc: test getExpectedRole with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectRoleNegoTest, WifiDirectRoleNegotiator001, TestSize.Level1)
{
    struct WifiDirectRoleNegotiator *self = GetRoleNegotiator();
    enum WifiDirectRole myRole = WIFI_DIRECT_ROLE_AUTO;
    enum WifiDirectRole peerRole = WIFI_DIRECT_ROLE_AUTO;
    enum WifiDirectRole expectedRole = WIFI_DIRECT_ROLE_AUTO;
    const char *localGoMac = "00-0A-95-9D-68-EE";
    const char *remoteGoMac = "B4-6D-83-F2-21-AB";
    int32_t ret = self->getFinalRoleWithPeerExpectedRole(myRole, peerRole, expectedRole, localGoMac, remoteGoMac);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
};

/*
* @tc.name: WifiDirectRoleNegoTest002
* @tc.desc: test getExpectedRole with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectRoleNegoTest, WifiDirectRoleNegotiator002, TestSize.Level1)
{
    struct WifiDirectRoleNegotiator *self = GetRoleNegotiator();
    enum WifiDirectRole myRole = WIFI_DIRECT_ROLE_GO;
    enum WifiDirectRole peerRole = WIFI_DIRECT_ROLE_AUTO;
    enum WifiDirectRole expectedRole = WIFI_DIRECT_ROLE_AUTO;
    const char *localGoMac = "00-0A-95-9D-68-EE";
    const char *remoteGoMac = "B4-6D-83-F2-21-AB";
    int32_t ret = self->getFinalRoleWithPeerExpectedRole(myRole, peerRole, expectedRole, localGoMac, remoteGoMac);
    EXPECT_EQ(ret, ERROR_INVALID_INPUT_PARAMETERS);
};


/*
* @tc.name: WifiDirectRoleNegoTest003
* @tc.desc: test getExpectedRole with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectRoleNegoTest, WifiDirectRoleNegotiator003, TestSize.Level1)
{
    struct WifiDirectRoleNegotiator *self = GetRoleNegotiator();
    enum WifiDirectRole myRole = WIFI_DIRECT_ROLE_GO;
    enum WifiDirectRole peerRole = WIFI_DIRECT_ROLE_GO;
    enum WifiDirectRole expectedRole = WIFI_DIRECT_ROLE_AUTO;
    const char *localGoMac = "00-0A-95-9D-68-EE";
    const char *remoteGoMac = "B4-6D-83-F2-21-AB";
    int32_t ret = self->getFinalRoleWithPeerExpectedRole(myRole, peerRole, expectedRole, localGoMac, remoteGoMac);
    EXPECT_EQ(ret, ERROR_P2P_BOTH_GO);
};

/*
* @tc.name: WifiDirectRoleNegoTest004
* @tc.desc: test getExpectedRole with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectRoleNegoTest, WifiDirectRoleNegotiator004, TestSize.Level1)
{
    struct WifiDirectRoleNegotiator *self = GetRoleNegotiator();
    enum WifiDirectRole myRole = WIFI_DIRECT_ROLE_GO;
    enum WifiDirectRole peerRole = WIFI_DIRECT_ROLE_GC;
    enum WifiDirectRole expectedRole = WIFI_DIRECT_ROLE_AUTO;
    const char *localGoMac = "00-0A-95-9D-68-EE";
    const char *remoteGoMac = "B4-6D-83-F2-21-AB";
    int32_t ret = self->getFinalRoleWithPeerExpectedRole(myRole, peerRole, expectedRole, localGoMac, remoteGoMac);
    EXPECT_EQ(ret, ERROR_P2P_PEER_GC_CONNECTED_TO_ANOTHER_DEVICE);
};

/*
* @tc.name: WifiDirectRoleNegoTest005
* @tc.desc: test getExpectedRole with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectRoleNegoTest, WifiDirectRoleNegotiator005, TestSize.Level1)
{
    struct WifiDirectRoleNegotiator *self = GetRoleNegotiator();
    enum WifiDirectRole myRole = WIFI_DIRECT_ROLE_GO;
    enum WifiDirectRole peerRole = WIFI_DIRECT_ROLE_GC;
    enum WifiDirectRole expectedRole = WIFI_DIRECT_ROLE_AUTO;
    const char *localGoMac = "00-0A-95-9D-68-EE";
    const char *remoteGoMac = nullptr;
    int32_t ret = self->getFinalRoleWithPeerExpectedRole(myRole, peerRole, expectedRole, localGoMac, remoteGoMac);
    EXPECT_EQ(ret, ERROR_P2P_PEER_GC_CONNECTED_TO_ANOTHER_DEVICE);
};

/*
* @tc.name: WifiDirectRoleNegoTest006
* @tc.desc: test getExpectedRole with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectRoleNegoTest, WifiDirectRoleNegotiator006, TestSize.Level1)
{
    struct WifiDirectRoleNegotiator *self = GetRoleNegotiator();
    enum WifiDirectRole myRole = WIFI_DIRECT_ROLE_GO;
    enum WifiDirectRole peerRole = WIFI_DIRECT_ROLE_GC;
    enum WifiDirectRole expectedRole = WIFI_DIRECT_ROLE_GO;
    const char *localGoMac = "00-0A-95-9D-68-EE";
    const char *remoteGoMac = "B4-6D-83-F2-21-AB";
    int32_t ret = self->getFinalRoleWithPeerExpectedRole(myRole, peerRole, expectedRole, localGoMac, remoteGoMac);
    EXPECT_EQ(ret, ERROR_P2P_PEER_GC_CONNECTED_TO_ANOTHER_DEVICE);
};

/*
* @tc.name: WifiDirectRoleNegoTest007
* @tc.desc: test getExpectedRole with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectRoleNegoTest, WifiDirectRoleNegotiator007, TestSize.Level1)
{
    struct WifiDirectRoleNegotiator *self = GetRoleNegotiator();
    enum WifiDirectRole myRole = WIFI_DIRECT_ROLE_GO;
    enum WifiDirectRole peerRole = WIFI_DIRECT_ROLE_NONE;
    enum WifiDirectRole expectedRole = WIFI_DIRECT_ROLE_AUTO;
    const char *localGoMac = "00-0A-95-9D-68-EE";
    const char *remoteGoMac = "B4-6D-83-F2-21-AB";
    int32_t ret = self->getFinalRoleWithPeerExpectedRole(myRole, peerRole, expectedRole, localGoMac, remoteGoMac);
    EXPECT_EQ(ret, WIFI_DIRECT_ROLE_GO);
};

/*
* @tc.name: WifiDirectRoleNegoTest008
* @tc.desc: test getExpectedRole with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectRoleNegoTest, WifiDirectRoleNegotiator008, TestSize.Level1)
{
    struct WifiDirectRoleNegotiator *self = GetRoleNegotiator();
    enum WifiDirectRole myRole = WIFI_DIRECT_ROLE_GO;
    enum WifiDirectRole peerRole = WIFI_DIRECT_ROLE_NONE;
    enum WifiDirectRole expectedRole = WIFI_DIRECT_ROLE_GO;
    const char *localGoMac = "00-0A-95-9D-68-EE";
    const char *remoteGoMac = "B4-6D-83-F2-21-AB";
    int32_t ret = self->getFinalRoleWithPeerExpectedRole(myRole, peerRole, expectedRole, localGoMac, remoteGoMac);
    EXPECT_EQ(ret, ERROR_P2P_GC_AVAILABLE_WITH_MISMATCHED_ROLE);
};

/*
* @tc.name: WifiDirectRoleNegoTest009
* @tc.desc: test getExpectedRole with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectRoleNegoTest, WifiDirectRoleNegotiator009, TestSize.Level1)
{
    struct WifiDirectRoleNegotiator *self = GetRoleNegotiator();
    enum WifiDirectRole myRole = WIFI_DIRECT_ROLE_GC;
    enum WifiDirectRole peerRole = WIFI_DIRECT_ROLE_AUTO;
    enum WifiDirectRole expectedRole = WIFI_DIRECT_ROLE_AUTO;
    const char *localGoMac = "00-0A-95-9D-68-EE";
    const char *remoteGoMac = "B4-6D-83-F2-21-AB";
    int32_t ret = self->getFinalRoleWithPeerExpectedRole(myRole, peerRole, expectedRole, localGoMac, remoteGoMac);
    EXPECT_EQ(ret, ERROR_P2P_GC_CONNECTED_TO_ANOTHER_DEVICE);
};

/*
* @tc.name: WifiDirectRoleNegoTest010
* @tc.desc: test getExpectedRole with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectRoleNegoTest, WifiDirectRoleNegotiator010, TestSize.Level1)
{
    struct WifiDirectRoleNegotiator *self = GetRoleNegotiator();
    enum WifiDirectRole myRole = WIFI_DIRECT_ROLE_GC;
    enum WifiDirectRole peerRole = WIFI_DIRECT_ROLE_GO;
    enum WifiDirectRole expectedRole = WIFI_DIRECT_ROLE_AUTO;
    const char *localGoMac = "00-0A-95-9D-68-EE";
    const char *remoteGoMac = "B4-6D-83-F2-21-AB";
    int32_t ret = self->getFinalRoleWithPeerExpectedRole(myRole, peerRole, expectedRole, localGoMac, remoteGoMac);
    EXPECT_EQ(ret, ERROR_P2P_GC_CONNECTED_TO_ANOTHER_DEVICE);
};

/*
* @tc.name: WifiDirectRoleNegoTest011
* @tc.desc: test getExpectedRole with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectRoleNegoTest, WifiDirectRoleNegotiator011, TestSize.Level1)
{
    struct WifiDirectRoleNegotiator *self = GetRoleNegotiator();
    enum WifiDirectRole myRole = WIFI_DIRECT_ROLE_GC;
    enum WifiDirectRole peerRole = WIFI_DIRECT_ROLE_GO;
    enum WifiDirectRole expectedRole = WIFI_DIRECT_ROLE_AUTO;
    const char *localGoMac = nullptr;
    const char *remoteGoMac = "B4-6D-83-F2-21-AB";
    int32_t ret = self->getFinalRoleWithPeerExpectedRole(myRole, peerRole, expectedRole, localGoMac, remoteGoMac);
    EXPECT_EQ(ret, ERROR_P2P_GC_CONNECTED_TO_ANOTHER_DEVICE);
};

/*
* @tc.name: WifiDirectRoleNegoTest012
* @tc.desc: test getExpectedRole with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectRoleNegoTest, WifiDirectRoleNegotiator012, TestSize.Level1)
{
    struct WifiDirectRoleNegotiator *self = GetRoleNegotiator();
    enum WifiDirectRole myRole = WIFI_DIRECT_ROLE_GC;
    enum WifiDirectRole peerRole = WIFI_DIRECT_ROLE_NONE;
    enum WifiDirectRole expectedRole = WIFI_DIRECT_ROLE_AUTO;
    const char *localGoMac = "00-0A-95-9D-68-EE";
    const char *remoteGoMac = "B4-6D-83-F2-21-AB";
    int32_t ret = self->getFinalRoleWithPeerExpectedRole(myRole, peerRole, expectedRole, localGoMac, remoteGoMac);
    EXPECT_EQ(ret, ERROR_WIFI_DIRECT_NO_AVAILABLE_INTERFACE);
};

/*
* @tc.name: WifiDirectRoleNegoTest013
* @tc.desc: test getExpectedRole with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectRoleNegoTest, WifiDirectRoleNegotiator013, TestSize.Level1)
{
    struct WifiDirectRoleNegotiator *self = GetRoleNegotiator();
    enum WifiDirectRole myRole = WIFI_DIRECT_ROLE_NONE;
    enum WifiDirectRole peerRole = WIFI_DIRECT_ROLE_AUTO;
    enum WifiDirectRole expectedRole = WIFI_DIRECT_ROLE_AUTO;
    const char *localGoMac = "00-0A-95-9D-68-EE";
    const char *remoteGoMac = "B4-6D-83-F2-21-AB";
    int32_t ret = self->getFinalRoleWithPeerExpectedRole(myRole, peerRole, expectedRole, localGoMac, remoteGoMac);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
};

/*
* @tc.name: WifiDirectRoleNegoTest014
* @tc.desc: test getExpectedRole with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectRoleNegoTest, WifiDirectRoleNegotiator014, TestSize.Level1)
{
    struct WifiDirectRoleNegotiator *self = GetRoleNegotiator();
    enum WifiDirectRole myRole = WIFI_DIRECT_ROLE_NONE;
    enum WifiDirectRole peerRole = WIFI_DIRECT_ROLE_GO;
    enum WifiDirectRole expectedRole = WIFI_DIRECT_ROLE_AUTO;
    const char *localGoMac = "00-0A-95-9D-68-EE";
    const char *remoteGoMac = "B4-6D-83-F2-21-AB";
    int32_t ret = self->getFinalRoleWithPeerExpectedRole(myRole, peerRole, expectedRole, localGoMac, remoteGoMac);
    EXPECT_EQ(ret, WIFI_DIRECT_ROLE_GC);
};

/*
* @tc.name: WifiDirectRoleNegoTest015
* @tc.desc: test getExpectedRole with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectRoleNegoTest, WifiDirectRoleNegotiator015, TestSize.Level1)
{
    struct WifiDirectRoleNegotiator *self = GetRoleNegotiator();
    enum WifiDirectRole myRole = WIFI_DIRECT_ROLE_NONE;
    enum WifiDirectRole peerRole = WIFI_DIRECT_ROLE_GO;
    enum WifiDirectRole expectedRole = WIFI_DIRECT_ROLE_GC;
    const char *localGoMac = "00-0A-95-9D-68-EE";
    const char *remoteGoMac = "B4-6D-83-F2-21-AB";
    int32_t ret = self->getFinalRoleWithPeerExpectedRole(myRole, peerRole, expectedRole, localGoMac, remoteGoMac);
    EXPECT_EQ(ret, ERROR_P2P_GC_AVAILABLE_WITH_MISMATCHED_ROLE);
};

/*
* @tc.name: WifiDirectRoleNegoTest016
* @tc.desc: test getExpectedRole with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectRoleNegoTest, WifiDirectRoleNegotiator016, TestSize.Level1)
{
    struct WifiDirectRoleNegotiator *self = GetRoleNegotiator();
    enum WifiDirectRole myRole = WIFI_DIRECT_ROLE_NONE;
    enum WifiDirectRole peerRole = WIFI_DIRECT_ROLE_GC;
    enum WifiDirectRole expectedRole = WIFI_DIRECT_ROLE_AUTO;
    const char *localGoMac = "00-0A-95-9D-68-EE";
    const char *remoteGoMac = "B4-6D-83-F2-21-AB";
    int32_t ret = self->getFinalRoleWithPeerExpectedRole(myRole, peerRole, expectedRole, localGoMac, remoteGoMac);
    EXPECT_EQ(ret, ERROR_P2P_GC_CONNECTED_TO_ANOTHER_DEVICE);
};

/*
* @tc.name: WifiDirectRoleNegoTest017
* @tc.desc: test getExpectedRole with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectRoleNegoTest, WifiDirectRoleNegotiator017, TestSize.Level1)
{
    struct WifiDirectRoleNegotiator *self = GetRoleNegotiator();
    enum WifiDirectRole myRole = WIFI_DIRECT_ROLE_NONE;
    enum WifiDirectRole peerRole = WIFI_DIRECT_ROLE_GC;
    enum WifiDirectRole expectedRole = WIFI_DIRECT_ROLE_GO;
    const char *localGoMac = "00-0A-95-9D-68-EE";
    const char *remoteGoMac = "B4-6D-83-F2-21-AB";
    int32_t ret = self->getFinalRoleWithPeerExpectedRole(myRole, peerRole, expectedRole, localGoMac, remoteGoMac);
    EXPECT_EQ(ret, ERROR_P2P_GC_AVAILABLE_WITH_MISMATCHED_ROLE);
};

/*
* @tc.name: WifiDirectRoleNegoTest018
* @tc.desc: test getExpectedRole with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectRoleNegoTest, WifiDirectRoleNegotiator018, TestSize.Level1)
{
    struct WifiDirectRoleNegotiator *self = GetRoleNegotiator();
    enum WifiDirectRole myRole = WIFI_DIRECT_ROLE_NONE;
    enum WifiDirectRole peerRole = WIFI_DIRECT_ROLE_NONE;
    enum WifiDirectRole expectedRole = WIFI_DIRECT_ROLE_AUTO;
    const char *localGoMac = "00-0A-95-9D-68-EE";
    const char *remoteGoMac = "B4-6D-83-F2-21-AB";
    int32_t ret = self->getFinalRoleWithPeerExpectedRole(myRole, peerRole, expectedRole, localGoMac, remoteGoMac);
    EXPECT_EQ(ret, WIFI_DIRECT_ROLE_GC);
};

/*
* @tc.name: WifiDirectRoleNegoTest019
* @tc.desc: test getExpectedRole with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectRoleNegoTest, WifiDirectRoleNegotiator019, TestSize.Level1)
{
    struct WifiDirectRoleNegotiator *self = GetRoleNegotiator();
    enum WifiDirectRole myRole = WIFI_DIRECT_ROLE_NONE;
    enum WifiDirectRole peerRole = WIFI_DIRECT_ROLE_NONE;
    enum WifiDirectRole expectedRole = WIFI_DIRECT_ROLE_GC;
    const char *localGoMac = "00-0A-95-9D-68-EE";
    const char *remoteGoMac = "B4-6D-83-F2-21-AB";
    int32_t ret = self->getFinalRoleWithPeerExpectedRole(myRole, peerRole, expectedRole, localGoMac, remoteGoMac);
    EXPECT_EQ(ret, WIFI_DIRECT_ROLE_GO);
};
}
