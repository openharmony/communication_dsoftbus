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

#include "accesstoken_kit.h"
#include "br_proxy.c"
#include "br_proxy_common.h"
#include "br_proxy_ext_test_mock.h"
#include "br_proxy_server_manager_mock.h"
#include "br_proxy_server_manager.c"
#include "message_handler.h"
#include "nativetoken_kit.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "token_setproc.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
#define CHANNEL_ID 5
#define CHANNEL_ID_ERR 0
#define SESSION_ID 2
#define REQUEST_ID 6
#define PID_TEST 1111
#define UID_TEST 2222
#define TOKENID_TEST 3333
const char *TEST_UUID = "0000FEEA-0000-1000-8000-00805F9B34FB";
const char *VALID_BR_MAC = "F0:FA:C7:13:56:BC";
const char *INVALID_BR_MAC = "F0:FA:C7:13:56:AB";

class BrProxyServerManagerTest : public testing::Test {
public:
    BrProxyServerManagerTest()
    {}
    ~BrProxyServerManagerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void BrProxyServerManagerTest::SetUpTestCase(void)
{
}

void BrProxyServerManagerTest::TearDownTestCase(void)
{
}

/**
 * @tc.name: BrProxyServerManagerTest000
 * @tc.desc: BrProxyServerManagerTest000, use the Normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest000, TestSize.Level1)
{
    int32_t ret = GetServerListCount(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    g_serverList = NULL;
    int32_t count = 0;
    ret = GetServerListCount(&count);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
    ret = BrProxyServerInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    ret = GetServerListCount(&count);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: BrProxyServerManagerTest001
 * @tc.desc: BrProxyServerManagerTest001, use the Normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest001, TestSize.Level1)
{
    BrProxyChannelInfo info = {
        .peerBRMacAddr = "FF:AA:CC:AA:BB:CC",
        .peerBRUuid = "AAAAAAAA-0000-0000-8888-BBBBBBBBBBBB",
    };
    NiceMock<BrProxyServerManagerInterfaceMock> brProxyServerManagerMock;
    EXPECT_CALL(brProxyServerManagerMock, GetCallerPid).WillRepeatedly(Return(PID_TEST));
    EXPECT_CALL(brProxyServerManagerMock, GetCallerUid).WillRepeatedly(Return(UID_TEST));
    EXPECT_CALL(brProxyServerManagerMock, GetCallerTokenId).WillRepeatedly(Return(TOKENID_TEST));
    int32_t ret = ServerAddChannelToList(info.peerBRMacAddr, info.peerBRUuid, CHANNEL_ID, REQUEST_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: BrProxyServerManagerTest002
 * @tc.desc: BrProxyServerManagerTest002, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest002, TestSize.Level1)
{
    int32_t channelId = 0;
    int32_t ret = GetChannelIdFromServerList(&channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = GetNewChannelId(&channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CloseAllConnect();
    LnnEventBasicInfo info;
    info.event = LNN_EVENT_USER_SWITCHED;
    UserSwitchedHandler(&info);
}

/**
 * @tc.name: BrProxyServerManagerTest003
 * @tc.desc: BrProxyServerManagerTest003
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest003, TestSize.Level1)
{
    const char *bundleName = "com.example.test";
    g_proxyList = NULL;
    bool ret = IsBrProxy(bundleName);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.name: BrProxyServerManagerTest004
 * @tc.desc: BrProxyServerManagerTest004
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest004, TestSize.Level1)
{
    int32_t ret = GetChannelIdFromServerList(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    g_serverList = NULL;
    int32_t channelId = 0;
    ret = GetChannelIdFromServerList(&channelId);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
}

/**
 * @tc.name: BrProxyServerManagerTest005
 * @tc.desc: BrProxyServerManagerTest005
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest005, TestSize.Level1)
{
    g_serverList = NULL;
    int32_t ret = CloseAllBrProxy();
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
}

/**
 * @tc.name: BrProxyServerManagerTest006
 * @tc.desc: BrProxyServerManagerTest006
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest006, TestSize.Level1)
{
    bool result = PermissionCheckPass(nullptr);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: BrProxyServerManagerTest007
 * @tc.desc: BrProxyServerManagerTest007
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest007, TestSize.Level1)
{
    int32_t ret = GetNewChannelId(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: BrProxyServerManagerTest008
 * @tc.desc: BrProxyServerManagerTest008
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest008, TestSize.Level1)
{
    uint32_t dataLen = 8;
    int32_t ret = ServerAddDataToList(nullptr, nullptr, dataLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ProxyBaseInfo *baseInfo = NULL;
    const uint8_t *data = reinterpret_cast<const uint8_t *>("Test data");
    ret = ServerAddDataToList(nullptr, data, dataLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ServerAddDataToList(baseInfo, nullptr, dataLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: BrProxyServerManagerTest009
 * @tc.desc: BrProxyServerManagerTest009
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest009, TestSize.Level1)
{
    int32_t ret = UpdateConnectState(nullptr, TEST_UUID, IS_CONNECTED);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    g_proxyList = NULL;
    ret = UpdateConnectState(VALID_BR_MAC, TEST_UUID, IS_CONNECTED);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: BrProxyServerManagerTest010
 * @tc.desc: BrProxyServerManagerTest010
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest010, TestSize.Level1)
{
    bool ret = IsBrProxyExist(nullptr, TEST_UUID);
    EXPECT_FALSE(ret);
    ret = IsBrProxyExist(VALID_BR_MAC, nullptr);
    EXPECT_FALSE(ret);
    g_proxyList = NULL;
    ret = IsBrProxyExist(VALID_BR_MAC, TEST_UUID);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: BrProxyServerManagerTest011
 * @tc.desc: BrProxyServerManagerTest011
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest011, TestSize.Level1)
{
    int32_t ret = GetCallerInfoAndVerifyPermission(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: BrProxyServerManagerTest012
 * @tc.desc: BrProxyServerManagerTest012
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest012, TestSize.Level1)
{
    int32_t ret = ServerAddProxyToList(nullptr, TEST_UUID);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ServerAddProxyToList(VALID_BR_MAC, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    g_proxyList = NULL;
    ret = ServerAddProxyToList(VALID_BR_MAC, TEST_UUID);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: BrProxyServerManagerTest013
 * @tc.desc: BrProxyServerManagerTest013
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest013, TestSize.Level1)
{
    g_proxyList = NULL;
    int32_t ret = ServerDeleteProxyFromList(VALID_BR_MAC, TEST_UUID);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
}

/**
 * @tc.name: BrProxyServerManagerTest014
 * @tc.desc: BrProxyServerManagerTest014
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest014, TestSize.Level1)
{
    bool ret;
    ret = IsSessionExist(nullptr, TEST_UUID);
    EXPECT_FALSE(ret);
    ret = IsSessionExist(VALID_BR_MAC, nullptr);
    EXPECT_FALSE(ret);
    g_proxyList = NULL;
    ret = IsSessionExist(VALID_BR_MAC, TEST_UUID);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: BrProxyServerManagerTest015
 * @tc.desc: BrProxyServerManagerTest015
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest015, TestSize.Level1)
{
    g_serverList = NULL;
    int32_t ret = ServerDeleteChannelFromList(CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
}

/**
 * @tc.name: BrProxyServerManagerTest016
 * @tc.desc: BrProxyServerManagerTest016
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest016, TestSize.Level1)
{
    struct ProxyChannel channel;
    g_serverList = NULL;
    int32_t ret = UpdateProxyChannel(VALID_BR_MAC, TEST_UUID, &channel);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
}

/**
 * @tc.name: BrProxyServerManagerTest017
 * @tc.desc: BrProxyServerManagerTest017
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest017, TestSize.Level1)
{
    pid_t uid = 1;
    bool ret = TransIsProxyChannelEnabled(uid);
    EXPECT_EQ(ret, true);
    ret = TransIsProxyChannelEnabled(uid);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: BrProxyServerManagerTest018
 * @tc.desc: BrProxyServerManagerTest018
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest018, TestSize.Level1)
{
    pid_t uid = 1;
    int32_t ret = RetryListInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t result = AddToRetryList(uid);
    EXPECT_EQ(result, SOFTBUS_OK);
    ClearCountInRetryList(uid);
    g_retryList = NULL;
}

/**
 * @tc.name: BrProxyServerManagerTest019
 * @tc.desc: BrProxyServerManagerTest019
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest019, TestSize.Level1)
{
    pid_t uid = 1;
    uint32_t cnt = 0;
    int32_t ret = GetCountFromRetryList(uid, &cnt);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = RetryListInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetCountFromRetryList(uid, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AddToRetryList(uid);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetCountFromRetryList(uid, &cnt);
    EXPECT_EQ(ret, SOFTBUS_OK);
    g_retryList = NULL;
}

/**
 * @tc.name: BrProxyServerManagerTest020
 * @tc.desc: BrProxyServerManagerTest020
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest020, TestSize.Level1)
{
    pid_t uid = 1;
    int32_t ret = AddToRetryList(uid);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = RetryListInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddToRetryList(uid);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddToRetryList(uid);
    EXPECT_EQ(ret, SOFTBUS_OK);
    g_retryList = NULL;
}

/**
 * @tc.name: BrProxyServerManagerTest021
 * @tc.desc: BrProxyServerManagerTest021
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest021, TestSize.Level1)
{
    pid_t uid = 1;
    bool ret = IsUidExist(uid);
    EXPECT_EQ(ret, false);
    int32_t result = RetryListInit();
    EXPECT_EQ(result, SOFTBUS_OK);
    ret = IsUidExist(uid);
    EXPECT_EQ(ret, false);
    result = AddToRetryList(uid);
    EXPECT_EQ(result, SOFTBUS_OK);
    ret = IsUidExist(uid);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: BrProxyServerManagerTest022
 * @tc.desc: BrProxyServerManagerTest022
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest022, TestSize.Level1)
{
    int32_t ret = RetryListInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = RetryListInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: BrProxyServerManagerTest023
 * @tc.desc: BrProxyServerManagerTest023
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest023, TestSize.Level1)
{
    const char *brMac = "";
    const char *uuid = "";
    int32_t channelId = 1;
    uint32_t requestId = 1;
    ServerBrProxyChannelInfo info = { 0 };
    int32_t ret = GetChannelInfo(brMac, uuid, channelId, requestId, &info);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
    ret = BrProxyServerInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = GetChannelInfo(brMac, uuid, channelId, requestId, &info);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_CHANNEL_ID);
    channelId = -1;
    ret = GetChannelInfo(brMac, uuid, channelId, requestId, &info);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/**
 * @tc.name: BrProxyServerManagerTest024
 * @tc.desc: BrProxyServerManagerTest024
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest024, TestSize.Level1)
{
    const char *mac = "11:33:44:22:33:56";
    const char *uuid = "testuuid";
    int32_t channelId = 1;
    int32_t arr = GetChannelId(NULL, uuid, &channelId);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = GetChannelId(mac, NULL, &channelId);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    g_proxyList = NULL;
    arr = GetChannelId(mac, uuid, &channelId);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    int32_t ret = BrProxyServerInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    arr = GetChannelId(mac, uuid, NULL);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = GetChannelId(NULL, NULL, &channelId);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = GetChannelId(NULL, NULL, &channelId);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = GetChannelId(NULL, NULL, &channelId);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = GetChannelId(NULL, NULL, NULL);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: BrProxyServerManagerTest025
 * @tc.desc: BrProxyServerManagerTest025
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest025, TestSize.Level1)
{
    const char *mac = "11:33:44:22:33:56";
    const char *uuid = "testuuid";
    int32_t channelId = 1;
    int32_t arr = GetChannelId(NULL, uuid, &channelId);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = GetChannelId(mac, NULL, &channelId);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = GetChannelId(mac, uuid, NULL);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = GetChannelId(NULL, NULL, &channelId);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = GetChannelId(mac, NULL, NULL);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = GetChannelId(NULL, NULL, NULL);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = GetChannelId(NULL, uuid, NULL);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: BrProxyServerManagerTest026
 * @tc.desc: BrProxyServerManagerTest026
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest026, TestSize.Level1)
{
    const char *mac = "11:33:44:22:33:56";
    const char *uuid = "testuuid";
    int32_t arr = TransOpenBrProxy(NULL, uuid);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = TransOpenBrProxy(mac, NULL);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = TransOpenBrProxy(NULL, NULL);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: BrProxyServerManagerTest027
 * @tc.desc: BrProxyServerManagerTest027
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest027, TestSize.Level1)
{
    const char *mac = "11:33:44:22:33:56";
    const char *uid = "testuuid";
    int32_t channelId = 1;
    uint32_t requestId = 0;
    int32_t arr = ServerAddChannelToList(NULL, uid, channelId, requestId);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = ServerAddChannelToList(mac, NULL, channelId, requestId);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    g_serverList = NULL;
    arr = ServerAddChannelToList(mac, uid, channelId, requestId);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = ServerAddChannelToList(NULL, uid, channelId, requestId);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = ServerAddChannelToList(mac, NULL, channelId, requestId);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = ServerAddChannelToList(mac, NULL, channelId, requestId);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    int32_t ret = BrProxyServerInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    arr = ServerAddChannelToList(NULL, NULL, channelId, requestId);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: BrProxyServerManagerTest028
 * @tc.desc: BrProxyServerManagerTest028
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest028, TestSize.Level1)
{
    int32_t ret = BrProxyServerInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: BrProxyServerManagerTest029
 * @tc.desc: BrProxyServerManagerTest029
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest029, TestSize.Level1)
{
    BrProxyInfo info;
    int32_t ret = BrProxyServerInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = GetBrProxy(nullptr, TEST_UUID, &info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = GetBrProxy(VALID_BR_MAC, nullptr, &info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    g_proxyList = nullptr;
    ret = GetBrProxy(VALID_BR_MAC, TEST_UUID, &info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = BrProxyServerInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetBrProxy(VALID_BR_MAC, TEST_UUID, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: BrProxyServerManagerTest030
 * @tc.desc: BrProxyServerManagerTest030
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest030, TestSize.Level1)
{
    struct ProxyChannel channel;
    int32_t ret = BrProxyServerInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = UpdateBrProxy(nullptr, TEST_UUID, &channel, true, CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = UpdateBrProxy(VALID_BR_MAC, nullptr, &channel, true, CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    g_proxyList = nullptr;
    ret = UpdateBrProxy(VALID_BR_MAC, TEST_UUID, &channel, true, CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = BrProxyServerInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UpdateBrProxy(VALID_BR_MAC, TEST_UUID, nullptr, true, CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: BrProxyServerManagerTest031
 * @tc.desc: BrProxyServerManagerTest031
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest031, TestSize.Level1)
{
    pid_t uid = 12345;
    g_proxyList = NULL;
    bool ret = IsBrProxyEnable(uid);
    EXPECT_FALSE(ret);
}
}
