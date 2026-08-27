/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
#include <string>
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
#define APP_INDEX_TEST 1
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

/*
 * @tc.name: GetChannelIdFromServerListTest001
 * @tc.desc: will return SOFTBUS_NOT_FIND when g_serverList is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, GetChannelIdFromServerListTest001, TestSize.Level1)
{
    int32_t channelId = 0;
    int32_t ret = GetChannelIdFromServerList(&channelId);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = GetNewChannelId(&channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CloseAllConnect();
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
    int32_t ret = ServerAddChannelToList(info.peerBRMacAddr, info.peerBRUuid, CHANNEL_ID, REQUEST_ID, APP_INDEX_TEST);
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
    g_serverList = NULL;
    int32_t channelId = 0;
    int32_t ret = GetChannelIdFromServerList(&channelId);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
    ret = BrProxyServerInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    BrProxyChannelInfo info;
    (void) strcpy_s(info.peerBRMacAddr, sizeof(info.peerBRMacAddr), VALID_BR_MAC);
    (void) strcpy_s(info.peerBRUuid, sizeof(info.peerBRUuid), TEST_UUID);
    NiceMock<BrProxyServerManagerInterfaceMock> brProxyServerManagerMock;
    EXPECT_CALL(brProxyServerManagerMock, GetCallerPid).WillRepeatedly(Return(PID_TEST));
    EXPECT_CALL(brProxyServerManagerMock, GetCallerUid).WillRepeatedly(Return(UID_TEST));
    EXPECT_CALL(brProxyServerManagerMock, GetCallerTokenId).WillRepeatedly(Return(TOKENID_TEST));
    ret = ServerAddChannelToList(info.peerBRMacAddr, info.peerBRUuid, CHANNEL_ID, REQUEST_ID, APP_INDEX_TEST);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = GetChannelIdFromServerList(&channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = GetChannelIdFromServerList(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: BrProxyServerManagerTest005
 * @tc.desc: BrProxyServerManagerTest005
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest005, TestSize.Level1)
{
    g_proxyList = NULL;
    int32_t ret = CloseAllBrProxy();
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
    ret = BrProxyServerInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = CloseAllBrProxy();
    EXPECT_EQ(SOFTBUS_OK, ret);
    BrProxyChannelInfo info1;
    (void) strcpy_s(info1.peerBRMacAddr, sizeof(info1.peerBRMacAddr), VALID_BR_MAC);
    (void) strcpy_s(info1.peerBRUuid, sizeof(info1.peerBRUuid), TEST_UUID);
    NiceMock<BrProxyServerManagerInterfaceMock> brProxyServerManagerMock;
    EXPECT_CALL(brProxyServerManagerMock, GetCallerPid).WillRepeatedly(Return(PID_TEST));
    EXPECT_CALL(brProxyServerManagerMock, GetCallerUid).WillRepeatedly(Return(UID_TEST));
    EXPECT_CALL(brProxyServerManagerMock, GetCallerTokenId).WillRepeatedly(Return(TOKENID_TEST));
    ret = ServerAddChannelToList(info1.peerBRMacAddr, info1.peerBRUuid, CHANNEL_ID, REQUEST_ID, APP_INDEX_TEST);
    EXPECT_EQ(SOFTBUS_OK, ret);
    BrProxyChannelInfo info2;
    (void) strcpy_s(info2.peerBRMacAddr, sizeof(info2.peerBRMacAddr), "FF:AA:CC:AA:BB:DD");
    (void) strcpy_s(info2.peerBRUuid, sizeof(info2.peerBRUuid), "BBBBBBBB-0000-0000-8888-BBBBBBBBBBBB");
    ret = ServerAddChannelToList(info2.peerBRMacAddr, info2.peerBRUuid, CHANNEL_ID + 1, REQUEST_ID + 1, APP_INDEX_TEST);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = CloseAllBrProxy();
    EXPECT_EQ(SOFTBUS_OK, ret);
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
    int32_t channelId = 0;
    int32_t ret = GetNewChannelId(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = GetNewChannelId(&channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
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
    struct ProxyChannel channel = {0};
    int32_t ret = UpdateConnectState(nullptr, TEST_UUID, &channel, IS_CONNECTED);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    g_proxyList = NULL;
    ret = UpdateConnectState(VALID_BR_MAC, TEST_UUID, &channel, IS_CONNECTED);
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
    BrProxyInfo inInfo;
    (void)memset_s(&inInfo, sizeof(BrProxyInfo), 0, sizeof(BrProxyInfo));
    bool ret = TryToUpdateBrProxy(nullptr, TEST_UUID, &inInfo);
    EXPECT_FALSE(ret);
    ret = TryToUpdateBrProxy(VALID_BR_MAC, nullptr, &inInfo);
    EXPECT_FALSE(ret);
    g_proxyList = NULL;
    ret = TryToUpdateBrProxy(VALID_BR_MAC, TEST_UUID, &inInfo);
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
    BrProxyInfo inInfo;
    (void)memset_s(&inInfo, sizeof(BrProxyInfo), 0, sizeof(BrProxyInfo));
    int32_t ret = ServerAddProxyToList(nullptr, TEST_UUID, &inInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ServerAddProxyToList(VALID_BR_MAC, nullptr, &inInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ServerAddProxyToList(VALID_BR_MAC, TEST_UUID, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    g_proxyList = NULL;
    ret = ServerAddProxyToList(VALID_BR_MAC, TEST_UUID, &inInfo);
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
    int32_t ret = ServerDisableProxyFromList(0);
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
    int32_t ret = BrProxyServerInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    BrProxyChannelInfo info;
    (void) strcpy_s(info.peerBRMacAddr, sizeof(info.peerBRMacAddr), VALID_BR_MAC);
    (void) strcpy_s(info.peerBRUuid, sizeof(info.peerBRUuid), TEST_UUID);
    NiceMock<BrProxyServerManagerInterfaceMock> brProxyServerManagerMock;
    EXPECT_CALL(brProxyServerManagerMock, GetCallerPid).WillRepeatedly(Return(PID_TEST));
    ret = ServerAddChannelToList(info.peerBRMacAddr, info.peerBRUuid, CHANNEL_ID, REQUEST_ID, APP_INDEX_TEST);
    EXPECT_EQ(SOFTBUS_OK, ret);
    bool result = IsSessionExist(nullptr, TEST_UUID, 0, false);
    EXPECT_FALSE(result);
    result = IsSessionExist(VALID_BR_MAC, nullptr, 0, false);
    EXPECT_FALSE(result);
    SoftBusList* temp = g_serverList;
    g_serverList = NULL;
    result = IsSessionExist(VALID_BR_MAC, TEST_UUID, 0, false);
    EXPECT_FALSE(result);
    g_serverList = temp;
    result = IsSessionExist(VALID_BR_MAC, TEST_UUID, 0, false);
    EXPECT_TRUE(result);
    ret = ServerDeleteChannelFromList(CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
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
    EXPECT_EQ(ret, false);
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
 * @tc.desc: BrProxyServerManagerTest024 - Test RefreshChannel parameter validation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest024, TestSize.Level1)
{
    ProxyChannelParam param = { 0 };
    bool isRefresh = false;
    uint32_t requestId = 1;

    int32_t ret = RefreshChannel(NULL, &isRefresh, requestId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = RefreshChannel(&param, NULL, requestId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    g_proxyList = NULL;
    ret = RefreshChannel(&param, &isRefresh, requestId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    int32_t initRet = BrProxyServerInit();
    ASSERT_EQ(initRet, SOFTBUS_OK);

    ret = RefreshChannel(NULL, &isRefresh, requestId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = RefreshChannel(&param, NULL, requestId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: BrProxyServerManagerTest025
 * @tc.desc: BrProxyServerManagerTest025 - Test RefreshChannel with valid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest025, TestSize.Level1)
{
    int32_t ret = BrProxyServerInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ProxyChannelParam param = { 0 };
    bool isRefresh = false;
    uint32_t requestId = 1;

    (void)strcpy_s(param.brMac, sizeof(param.brMac), "11:33:44:22:33:56");
    (void)strcpy_s(param.uuid, sizeof(param.uuid), "testuuid");
    param.timeoutMs = BR_PROXY_MAX_WAIT_TIME_MS;

    ret = RefreshChannel(&param, &isRefresh, requestId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(isRefresh, false);
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
    int32_t arr = ServerAddChannelToList(NULL, uid, channelId, requestId, APP_INDEX_TEST);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = ServerAddChannelToList(mac, NULL, channelId, requestId, APP_INDEX_TEST);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    g_serverList = NULL;
    arr = ServerAddChannelToList(mac, uid, channelId, requestId, APP_INDEX_TEST);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = ServerAddChannelToList(NULL, uid, channelId, requestId, APP_INDEX_TEST);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = ServerAddChannelToList(mac, NULL, channelId, requestId, APP_INDEX_TEST);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = ServerAddChannelToList(mac, NULL, channelId, requestId, APP_INDEX_TEST);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    int32_t ret = BrProxyServerInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    arr = ServerAddChannelToList(NULL, NULL, channelId, requestId, APP_INDEX_TEST);
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
    int32_t requestId = 1;
    ret = GetBrProxy(nullptr, TEST_UUID, requestId, &info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = GetBrProxy(VALID_BR_MAC, nullptr, requestId, &info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    g_proxyList = nullptr;
    ret = GetBrProxy(VALID_BR_MAC, TEST_UUID, requestId, &info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = BrProxyServerInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetBrProxy(VALID_BR_MAC, TEST_UUID, requestId, nullptr);
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
    ProxyBaseInfo proxyInfo;
    int32_t ret = BrProxyServerInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = UpdateBrProxy(nullptr, APP_INDEX_TEST, &channel, true, CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = UpdateBrProxy(&proxyInfo, APP_INDEX_TEST, &channel, true, CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    g_proxyList = nullptr;
    ret = UpdateBrProxy(&proxyInfo, APP_INDEX_TEST, &channel, true, CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = BrProxyServerInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UpdateBrProxy(&proxyInfo, APP_INDEX_TEST, nullptr, true, CHANNEL_ID);
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
    const char *bundleName = "com.example.test";
    bool ret = IsBrProxy(bundleName);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.name: BrProxyServerManagerTest032
 * @tc.desc: BrProxyServerManagerTest032
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest032, TestSize.Level1)
{
    g_serverList = NULL;
    int32_t ret = BrProxyServerInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    BrProxyChannelInfo info = {
        .peerBRMacAddr = "FF:AA:CC:AA:BB:CC",
        .peerBRUuid = "AAAAAAAA-0000-0000-8888-BBBBBBBBBBBB",
    };
    NiceMock<BrProxyServerManagerInterfaceMock> brProxyServerManagerMock;
    EXPECT_CALL(brProxyServerManagerMock, GetCallerPid).WillRepeatedly(Return(PID_TEST));
    EXPECT_CALL(brProxyServerManagerMock, GetCallerUid).WillRepeatedly(Return(UID_TEST));
    EXPECT_CALL(brProxyServerManagerMock, GetCallerTokenId).WillRepeatedly(Return(TOKENID_TEST));
    ret = ServerAddChannelToList(info.peerBRMacAddr, info.peerBRUuid, CHANNEL_ID, REQUEST_ID, APP_INDEX_TEST);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ServerDeleteChannelFromList(CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: BrProxyServerManagerTest033
 * @tc.desc: BrProxyServerManagerTest033
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest033, TestSize.Level1)
{
    g_serverList = NULL;
    int32_t ret = BrProxyServerInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    BrProxyChannelInfo info = {
        .peerBRMacAddr = "FF:AA:CC:AA:BB:CC",
        .peerBRUuid = "AAAAAAAA-0000-0000-8888-BBBBBBBBBBBB",
    };
    NiceMock<BrProxyServerManagerInterfaceMock> brProxyServerManagerMock;
    EXPECT_CALL(brProxyServerManagerMock, GetCallerPid).WillRepeatedly(Return(PID_TEST));
    EXPECT_CALL(brProxyServerManagerMock, GetCallerUid).WillRepeatedly(Return(UID_TEST));
    EXPECT_CALL(brProxyServerManagerMock, GetCallerTokenId).WillRepeatedly(Return(TOKENID_TEST));
    ret = ServerAddChannelToList(info.peerBRMacAddr, info.peerBRUuid, CHANNEL_ID, REQUEST_ID, APP_INDEX_TEST);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ServerDeleteChannelByPid(PID_TEST);
    EXPECT_EQ(g_serverList->cnt, 0);
}

/**
 * @tc.name: BrProxyServerManagerTest034
 * @tc.desc: BrProxyServerManagerTest034
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest034, TestSize.Level1)
{
    g_proxyList = NULL;
    bool result = CheckSessionExistByUid(UID_TEST);
    EXPECT_EQ(false, result);
    int32_t ret = BrProxyServerInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    NiceMock<BrProxyServerManagerInterfaceMock> brProxyServerManagerMock;
    EXPECT_CALL(brProxyServerManagerMock, GetCallerUid).WillRepeatedly(Return(UID_TEST));
    BrProxyInfo inInfo;
    (void)memset_s(&inInfo, sizeof(BrProxyInfo), 0, sizeof(BrProxyInfo));
    ret = ServerAddProxyToList(VALID_BR_MAC, TEST_UUID, &inInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    result = CheckSessionExistByUid(UID_TEST);
    EXPECT_EQ(result, IS_DISCONNECTED);
}

/**
 * @tc.name: BrProxyServerManagerTest035
 * @tc.desc: BrProxyServerManagerTest035
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest035, TestSize.Level1)
{
    g_serverList = NULL;
    int32_t ret = TransSetListenerState(CHANNEL_ID, 0, false);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
    ret = BrProxyServerInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    BrProxyChannelInfo info = {
        .peerBRMacAddr = "FF:AA:CC:AA:BB:CC",
        .peerBRUuid = "AAAAAAAA-0000-0000-8888-BBBBBBBBBBBB",
    };
    NiceMock<BrProxyServerManagerInterfaceMock> brProxyServerManagerMock;
    EXPECT_CALL(brProxyServerManagerMock, GetCallerPid).WillRepeatedly(Return(PID_TEST));
    EXPECT_CALL(brProxyServerManagerMock, GetCallerUid).WillRepeatedly(Return(UID_TEST));
    EXPECT_CALL(brProxyServerManagerMock, GetCallerTokenId).WillRepeatedly(Return(TOKENID_TEST));
    ret = ServerAddChannelToList(info.peerBRMacAddr, info.peerBRUuid, CHANNEL_ID, REQUEST_ID, APP_INDEX_TEST);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransSetListenerState(CHANNEL_ID, 0, false);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: BrProxyServerManagerTest036
 * @tc.desc: BrProxyServerManagerTest036
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest036, TestSize.Level1)
{
    g_serverList = NULL;
    int32_t ret = BrProxyServerInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    BrProxyChannelInfo info = {
        .peerBRMacAddr = "FF:AA:CC:AA:BB:CC",
        .peerBRUuid = "AAAAAAAA-0000-0000-8888-BBBBBBBBBBBB",
    };
    NiceMock<BrProxyServerManagerInterfaceMock> brProxyServerManagerMock;
    EXPECT_CALL(brProxyServerManagerMock, GetCallerPid).WillRepeatedly(Return(PID_TEST));
    EXPECT_CALL(brProxyServerManagerMock, GetCallerUid).WillRepeatedly(Return(UID_TEST));
    EXPECT_CALL(brProxyServerManagerMock, GetCallerTokenId).WillRepeatedly(Return(TOKENID_TEST));
    ret = ServerAddChannelToList(info.peerBRMacAddr, info.peerBRUuid, CHANNEL_ID, REQUEST_ID, APP_INDEX_TEST);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SetListenerStateByChannelId(CHANNEL_ID, DATA_RECEIVE, true);
    EXPECT_EQ(SOFTBUS_OK, ret);
    pid_t result = PID_TEST;
    ProxyBaseInfo info2 = {
        .brMac = "FF:AA:CC:AA:BB:CC",
        .uuid = "AAAAAAAA-0000-0000-8888-BBBBBBBBBBBB",
    };
    int32_t channelId = CHANNEL_ID;
    ret = SelectClient(&info2, &result, &channelId, REQUEST_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: BrProxyServerManagerTest037
 * @tc.desc: BrProxyServerManagerTest037
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest037, TestSize.Level1)
{
    g_serverList = NULL;
    int32_t ret = BrProxyServerInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    BrProxyChannelInfo info = {
        .peerBRMacAddr = "FF:AA:CC:AA:BB:CC",
        .peerBRUuid = "AAAAAAAA-0000-0000-8888-BBBBBBBBBBBB",
    };
    NiceMock<BrProxyServerManagerInterfaceMock> brProxyServerManagerMock;
    EXPECT_CALL(brProxyServerManagerMock, GetCallerPid).WillRepeatedly(Return(PID_TEST));
    EXPECT_CALL(brProxyServerManagerMock, GetCallerUid).WillRepeatedly(Return(UID_TEST));
    EXPECT_CALL(brProxyServerManagerMock, GetCallerTokenId).WillRepeatedly(Return(TOKENID_TEST));
    ret = ServerAddChannelToList(info.peerBRMacAddr, info.peerBRUuid, CHANNEL_ID, REQUEST_ID, APP_INDEX_TEST);
    EXPECT_EQ(SOFTBUS_OK, ret);
    pid_t result = PID_TEST;
    ProxyBaseInfo info2 = {
        .brMac = "FF:AA:CC:AA:BB:CC",
        .uuid = "AAAAAAAA-0000-0000-8888-BBBBBBBBBBBB",
    };
    int32_t channelId = CHANNEL_ID;
    ret = SelectClient(&info2, &result, &channelId, 0);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}

/**
 * @tc.name: BrProxyServerManagerTest038
 * @tc.desc: BrProxyServerManagerTest038
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest038, TestSize.Level1)
{
    g_serverList = NULL;
    int32_t ret = BrProxyServerInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    BrProxyChannelInfo info = {
        .peerBRMacAddr = "FF:AA:CC:AA:BB:CC",
        .peerBRUuid = "AAAAAAAA-0000-0000-8888-BBBBBBBBBBBB",
    };
    NiceMock<BrProxyServerManagerInterfaceMock> brProxyServerManagerMock;
    EXPECT_CALL(brProxyServerManagerMock, GetCallerPid).WillRepeatedly(Return(PID_TEST));
    EXPECT_CALL(brProxyServerManagerMock, GetCallerUid).WillRepeatedly(Return(UID_TEST));
    EXPECT_CALL(brProxyServerManagerMock, GetCallerTokenId).WillRepeatedly(Return(TOKENID_TEST));
    ret = ServerAddChannelToList(info.peerBRMacAddr, info.peerBRUuid, CHANNEL_ID, REQUEST_ID, APP_INDEX_TEST);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SetListenerStateByChannelId(CHANNEL_ID, DATA_RECEIVE, true);
    EXPECT_EQ(SOFTBUS_OK, ret);
    pid_t result = PID_TEST;
    ProxyBaseInfo info2 = {
        .brMac = "a",
        .uuid = "AAAAAAAA-0000-0000-8888-BBBBBBBBBBBB",
    };
    int32_t channelId = CHANNEL_ID;
    ret = SelectClient(&info2, &result, &channelId, 0);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    info2 = {
        .brMac = "FF:AA:CC:AA:BB:CC",
        .uuid = "b",
    };
    ret = SelectClient(&info2, &result, &channelId, 0);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}

/**
 * @tc.name: BrProxyServerManagerTest039
 * @tc.desc: BrProxyServerManagerTest039
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest039, TestSize.Level1)
{
    bool isEnable = true;
    int32_t ret = BrProxyServerInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ListenerType type = LISTENER_TYPE_MAX;
    ret = SetListenerStateByChannelId(CHANNEL_ID, type, isEnable);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    g_serverList = NULL;
    ret = SetListenerStateByChannelId(CHANNEL_ID, type, isEnable);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
    ret = BrProxyServerInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    BrProxyChannelInfo info = {
        .peerBRMacAddr = "FF:AA:CC:AA:BB:CC",
        .peerBRUuid = "AAAAAAAA-0000-0000-8888-BBBBBBBBBBBB",
    };
    NiceMock<BrProxyServerManagerInterfaceMock> brProxyServerManagerMock;
    EXPECT_CALL(brProxyServerManagerMock, GetCallerPid).WillRepeatedly(Return(PID_TEST));
    EXPECT_CALL(brProxyServerManagerMock, GetCallerUid).WillRepeatedly(Return(UID_TEST));
    EXPECT_CALL(brProxyServerManagerMock, GetCallerTokenId).WillRepeatedly(Return(TOKENID_TEST));
    ret = ServerAddChannelToList(info.peerBRMacAddr, info.peerBRUuid, CHANNEL_ID, REQUEST_ID, APP_INDEX_TEST);
    EXPECT_EQ(SOFTBUS_OK, ret);
    type = DATA_RECEIVE;
    ret = SetListenerStateByChannelId(CHANNEL_ID, type, isEnable);
    EXPECT_EQ(SOFTBUS_OK, ret);
    type = CHANNEL_STATE;
    ret = SetListenerStateByChannelId(CHANNEL_ID, type, isEnable);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SetListenerStateByChannelId(CHANNEL_ID_ERR, type, isEnable);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}

/**
 * @tc.name: BrProxyServerManagerTest040
 * @tc.desc: BrProxyServerManagerTest040
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest040, TestSize.Level1)
{
    int32_t ret = BrProxyServerInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    ret = TransSendBrProxyData(CHANNEL_ID, nullptr, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: BrProxyServerManagerTest041
 * @tc.desc: BrProxyServerManagerTest041
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest041, TestSize.Level1)
{
    g_serverList = nullptr;
    ProxyBaseInfo baseInfo;
    (void) strcpy_s(baseInfo.brMac, sizeof(baseInfo.brMac), VALID_BR_MAC);
    (void) strcpy_s(baseInfo.uuid, sizeof(baseInfo.uuid), TEST_UUID);
    bool result = IsProcExist(&baseInfo, 0);
    EXPECT_FALSE(result);
    int32_t ret = BrProxyServerInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    result = IsProcExist(&baseInfo, 0);
    EXPECT_FALSE(result);
    BrProxyChannelInfo info;
    (void) strcpy_s(info.peerBRMacAddr, sizeof(info.peerBRMacAddr), VALID_BR_MAC);
    (void) strcpy_s(info.peerBRUuid, sizeof(info.peerBRUuid), TEST_UUID);
    NiceMock<BrProxyServerManagerInterfaceMock> brProxyServerManagerMock;
    EXPECT_CALL(brProxyServerManagerMock, GetCallerPid).WillRepeatedly(Return(PID_TEST));
    EXPECT_CALL(brProxyServerManagerMock, GetCallerUid).WillRepeatedly(Return(UID_TEST));
    EXPECT_CALL(brProxyServerManagerMock, GetCallerTokenId).WillRepeatedly(Return(TOKENID_TEST));
    ret = ServerAddChannelToList(info.peerBRMacAddr, info.peerBRUuid, CHANNEL_ID, REQUEST_ID, APP_INDEX_TEST);
    ASSERT_EQ(SOFTBUS_OK, ret);
    result = IsProcExist(&baseInfo, REQUEST_ID);
    EXPECT_FALSE(result);
    BrProxyChannelInfo infoMismatch;
    (void) strcpy_s(infoMismatch.peerBRMacAddr, sizeof(infoMismatch.peerBRMacAddr), "FF:AA:CC:AA:BB:DD");
    (void) strcpy_s(infoMismatch.peerBRUuid, sizeof(infoMismatch.peerBRUuid), "BBBBBBBB-0000-0000-8888-BBBBBBBBBBBB");
    ret = ServerAddChannelToList(
        infoMismatch.peerBRMacAddr, infoMismatch.peerBRUuid, CHANNEL_ID + 1, REQUEST_ID + 1, APP_INDEX_TEST);
    ASSERT_EQ(SOFTBUS_OK, ret);
    result = IsProcExist(&baseInfo, REQUEST_ID);
    EXPECT_FALSE(result);
    ret = ServerDeleteChannelFromList(CHANNEL_ID);
    ASSERT_EQ(SOFTBUS_OK, ret);
    ret = ServerDeleteChannelFromList(CHANNEL_ID + 1);
    ASSERT_EQ(SOFTBUS_OK, ret);
    result = IsProcExist(&baseInfo, 0);
    EXPECT_FALSE(result);
}

/*
 * @tc.name: BrProxyServerManagerTest042
 * @tc.desc: BrProxyServerManagerTest042
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest042, TestSize.Level1)
{
    int32_t ret = SetCurrentConnect(nullptr, nullptr, APP_INDEX_TEST, false);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    const char *brMac = "AA:AA:AA:AA:AA:AA";
    const char *uuid = "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA";
    ret = BrProxyServerInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    ret = SetCurrentConnect(brMac, uuid, APP_INDEX_TEST, false);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}

/*
 * @tc.name: BrProxyServerManagerTest043
 * @tc.desc: BrProxyServerManagerTest043
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest043, TestSize.Level1)
{
#define TMP_LEN 100
    const char *brMac = "AA:AA:AA:AA:AA:AA";
    const char *uuid = "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA";

    (void)PrintSession(nullptr, nullptr);
    (void)PrintSession(brMac, uuid);

    NiceMock<BrProxyServerManagerInterfaceMock> brProxyServerManagerMock;
    EXPECT_CALL(brProxyServerManagerMock, GetCallerPid).WillRepeatedly(Return(PID_TEST));
    EXPECT_CALL(brProxyServerManagerMock, GetCallerUid).WillRepeatedly(Return(UID_TEST));
    int32_t ret = TransOpenBrProxy(brMac, uuid);
    EXPECT_NE(SOFTBUS_OK, ret);
    ProxyBaseInfo info = {
        .brMac = "FF:FF:FF:FF:FF:FF",
        .uuid = "AAAAAAAA-AAAA-AAAA-AAAA-BBBBBBBBBBBB",
    };
    (void)CleanUpDataListWithSameMac(&info, 0, 0);
    ProxyChannel channel = {
        .channelId = 0,
        .brMac = "FF:FF:FF:FF:FF:FF",
        .requestId = 0,
        .uuid = "AAAAAAAA-AAAA-AAAA-AAAA-BBBBBBBBBBBB",
        .send = nullptr,
        .close = nullptr,
    };
    (void)OnDisconnected(&channel, 0);
    (void)OnReconnected(nullptr, nullptr);
    char data[TMP_LEN] = "testtesttesttesttest";
    (void)OnReconnected(data, &channel);
    (void)NotifyChannelState(brMac, uuid, 0, 0);

    ret = TransSendBrProxyData(0, data, TMP_LEN);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_ID, ret);
}

/**
 * @tc.name: BrProxyServerManagerTest044
 * @tc.desc: BrProxyServerManagerTest044
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest044, TestSize.Level1)
{
    const char *mac = "11:33:44:22:33:56";
    const char *uuid = "testuuid";
    int32_t channelId = 1;
    int32_t userId = 1;
    int32_t arr = GetChannelIdAndUserId(NULL, uuid, &channelId, &userId);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = GetChannelIdAndUserId(mac, NULL, &channelId, &userId);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = GetChannelIdAndUserId(mac, uuid, NULL, &userId);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = GetChannelIdAndUserId(mac, uuid, &channelId, NULL);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = GetChannelIdAndUserId(mac, uuid, &channelId, &userId);
    EXPECT_EQ(arr, SOFTBUS_NOT_FIND);
    arr = BrProxyServerInit();
    ASSERT_EQ(arr, SOFTBUS_OK);
    NiceMock<BrProxyServerManagerInterfaceMock> brProxyServerManagerMock;
    EXPECT_CALL(brProxyServerManagerMock, GetCallerUid).WillRepeatedly(Return(UID_TEST));
    BrProxyInfo info;
    (void)memset_s(&info, sizeof(BrProxyInfo), 0, sizeof(BrProxyInfo));
    info.appIndex = 1;
    arr = ServerAddProxyToList(VALID_BR_MAC, TEST_UUID, &info);
    EXPECT_EQ(SOFTBUS_OK, arr);
    const char *mac1 = "11:33:44:22:33:88";
    const char *uuid1 = "testuuid1";
    arr = GetChannelIdAndUserId(mac1, uuid, &channelId, &userId);
    EXPECT_EQ(arr, SOFTBUS_NOT_FIND);
    arr = GetChannelIdAndUserId(mac, uuid1, &channelId, &userId);
    EXPECT_EQ(arr, SOFTBUS_NOT_FIND);
    arr = GetChannelIdAndUserId(mac, uuid, &channelId, &userId);
    EXPECT_EQ(arr, SOFTBUS_NOT_FIND);
}

/**
 * @tc.name: BrProxyServerManagerTest045
 * @tc.desc: Test BtPermissionChange when valid and invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest045, TestSize.Level1)
{
    int32_t ret = BtPermissionChange(0, nullptr, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = BtPermissionChange(1, "TestPkgName", 0);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = BtPermissionChange(0, "BrProxyPkgName", 0);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = BtPermissionChange(1, "BrProxyPkgName", 0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: BrProxyServerManagerTest046
 * @tc.desc: Test CloseConnectByPid when g_serverList is NULL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest046, TestSize.Level1)
{
    g_serverList = NULL;
    int32_t ret = CloseConnectByPid(PID_TEST);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
}

/**
 * @tc.name: BrProxyServerManagerTest047
 * @tc.desc: Test CloseConnectByPid with multiple PIDs
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest047, TestSize.Level1)
{
    g_serverList = NULL;
    int32_t ret = BrProxyServerInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    
    BrProxyChannelInfo info1 = {
        .peerBRMacAddr = "FF:AA:CC:AA:BB:CC",
        .peerBRUuid = "AAAAAAAA-0000-0000-8888-BBBBBBBBBBBB",
    };
    NiceMock<BrProxyServerManagerInterfaceMock> brProxyServerManagerMock;
    EXPECT_CALL(brProxyServerManagerMock, GetCallerPid).WillRepeatedly(Return(PID_TEST));
    EXPECT_CALL(brProxyServerManagerMock, GetCallerUid).WillRepeatedly(Return(UID_TEST));
    EXPECT_CALL(brProxyServerManagerMock, GetCallerTokenId).WillRepeatedly(Return(TOKENID_TEST));
    ret = ServerAddChannelToList(info1.peerBRMacAddr, info1.peerBRUuid, CHANNEL_ID, REQUEST_ID, APP_INDEX_TEST);
    ASSERT_EQ(SOFTBUS_OK, ret);
    
    pid_t pid2 = 2222;
    BrProxyChannelInfo info2 = {
        .peerBRMacAddr = "FF:AA:CC:AA:BB:DD",
        .peerBRUuid = "BBBBBBBB-0000-0000-8888-BBBBBBBBBBBB",
    };
    EXPECT_CALL(brProxyServerManagerMock, GetCallerPid).WillRepeatedly(Return(pid2));
    ret = ServerAddChannelToList(info2.peerBRMacAddr, info2.peerBRUuid, CHANNEL_ID + 1, REQUEST_ID + 1, APP_INDEX_TEST);
    ASSERT_EQ(SOFTBUS_OK, ret);
    
    EXPECT_EQ(g_serverList->cnt, 2);
    
    CloseConnectByPid(PID_TEST);
    
    EXPECT_EQ(g_serverList->cnt, 1);
    
    ret = ServerDeleteChannelFromList(CHANNEL_ID + 1);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

static void DummyCloseChannel(struct ProxyChannel *channel, bool isClearReconnectEvent)
{
    (void)channel;
    (void)isClearReconnectEvent;
}

/**
 * @tc.name: BrProxyServerManagerTest048
 * @tc.desc: Test RefreshChannel with invalid g_proxyList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest048, TestSize.Level1)
{
    int32_t ret = BrProxyServerInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    g_proxyList = NULL;
    ProxyChannelParam param = { 0 };
    bool isRefresh = false;
    uint32_t requestId = 1;

    ret = RefreshChannel(&param, &isRefresh, requestId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: BrProxyServerManagerTest049
 * @tc.desc: Test RefreshChannel with non-existent brMac and uuid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest049, TestSize.Level1)
{
    int32_t ret = BrProxyServerInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ProxyChannelParam param = { 0 };
    bool isRefresh = false;
    uint32_t requestId = 1;

    (void)strcpy_s(param.brMac, sizeof(param.brMac), "FF:FF:FF:FF:FF:FF");
    (void)strcpy_s(param.uuid, sizeof(param.uuid), "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF");
    param.timeoutMs = BR_PROXY_MAX_WAIT_TIME_MS;

    ret = RefreshChannel(&param, &isRefresh, requestId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(isRefresh, false);
}

/**
 * @tc.name: CloseAllBrProxyTest001
 * @tc.desc: CloseAllBrProxy, node isEnable is true and close is set, close is called and node freed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, CloseAllBrProxyTest001, TestSize.Level1)
{
    ASSERT_EQ(BrProxyServerInit(), SOFTBUS_OK);
    CloseAllBrProxy();
    BrProxyInfo *info = reinterpret_cast<BrProxyInfo *>(SoftBusCalloc(sizeof(BrProxyInfo)));
    ASSERT_NE(info, nullptr);
    info->isEnable = true;
    info->channel.close = DummyCloseChannel;
    ListInit(&info->node);
    ListAdd(&g_proxyList->list, &info->node);
    g_proxyList->cnt = 1;
    EXPECT_EQ(CloseAllBrProxy(), SOFTBUS_OK);
    EXPECT_EQ(g_proxyList->cnt, 0);
}

/**
 * @tc.name: CloseAllBrProxyTest002
 * @tc.desc: CloseAllBrProxy, node isEnable is false, close is not called and node freed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, CloseAllBrProxyTest002, TestSize.Level1)
{
    ASSERT_EQ(BrProxyServerInit(), SOFTBUS_OK);
    CloseAllBrProxy();
    BrProxyInfo *info = reinterpret_cast<BrProxyInfo *>(SoftBusCalloc(sizeof(BrProxyInfo)));
    ASSERT_NE(info, nullptr);
    info->isEnable = false;
    info->channel.close = DummyCloseChannel;
    ListInit(&info->node);
    ListAdd(&g_proxyList->list, &info->node);
    g_proxyList->cnt = 1;
    EXPECT_EQ(CloseAllBrProxy(), SOFTBUS_OK);
    EXPECT_EQ(g_proxyList->cnt, 0);
}

/**
 * @tc.name: RecoveryConnectTest001
 * @tc.desc: RecoveryConnect, brMac is too long and strcpy_s fails returns SOFTBUS_MEM_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, RecoveryConnectTest001, TestSize.Level1)
{
    std::string longMac(BT_MAC_MAX_LEN + 8, 'x');
    int32_t ret = RecoveryConnect(longMac.c_str(), TEST_UUID, REQUEST_ID);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);
    std::string longUuid(UUID_STRING_LEN + 8, 'y');
    ret = RecoveryConnect(VALID_BR_MAC, longUuid.c_str(), REQUEST_ID);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);
}

/**
 * @tc.name: RecoveryCurrentUserTest001
 * @tc.desc: RecoveryCurrentUser, g_proxyList is null or no matched node returns early
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, RecoveryCurrentUserTest001, TestSize.Level1)
{
    g_proxyList = NULL;
    EXPECT_NO_FATAL_FAILURE(RecoveryCurrentUser(UID_TEST));
    ASSERT_EQ(BrProxyServerInit(), SOFTBUS_OK);
    CloseAllBrProxy();
    EXPECT_NO_FATAL_FAILURE(RecoveryCurrentUser(UID_TEST));
}

/**
 * @tc.name: RecoveryCurrentUserTest002
 * @tc.desc: RecoveryCurrentUser, matched last connect node triggers pull up and recovery connect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, RecoveryCurrentUserTest002, TestSize.Level1)
{
    ASSERT_EQ(BrProxyServerInit(), SOFTBUS_OK);
    CloseAllBrProxy();
    BrProxyInfo *node = reinterpret_cast<BrProxyInfo *>(SoftBusCalloc(sizeof(BrProxyInfo)));
    ASSERT_NE(node, nullptr);
    (void)memset_s(node->proxyInfo.brMac, sizeof(node->proxyInfo.brMac), 'x', sizeof(node->proxyInfo.brMac));
    (void)strcpy_s(node->proxyInfo.uuid, sizeof(node->proxyInfo.uuid), TEST_UUID);
    node->userId = UID_TEST;
    node->isLastConnect = true;
    node->requestId = REQUEST_ID;
    ListInit(&node->node);
    ListAdd(&g_proxyList->list, &node->node);
    g_proxyList->cnt = 1;
    NiceMock<BrProxyServerManagerInterfaceMock> mock;
    EXPECT_CALL(mock, PullUpHap).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(RecoveryCurrentUser(UID_TEST));
    CloseAllBrProxy();
}

/**
 * @tc.name: TryToPullUpHapWhenSwitchTest001
 * @tc.desc: TryToPullUpHapWhenSwitch, storage read fails and PullUpHap is not called
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, TryToPullUpHapWhenSwitchTest001, TestSize.Level1)
{
    TransBrProxyStorage *storage = TransBrProxyStorageGetInstance();
    ASSERT_NE(storage, nullptr);
    TransBrProxyStorageClear(storage);
    storage->loaded = false;
    NiceMock<BrProxyServerManagerInterfaceMock> mock;
    EXPECT_CALL(mock, PullUpHap).Times(0);
    TryToPullUpHapWhenSwitch(UID_TEST);
}

/**
 * @tc.name: TryToPullUpHapWhenSwitchTest002
 * @tc.desc: TryToPullUpHapWhenSwitch, storage userId mismatches caller and PullUpHap is not called
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, TryToPullUpHapWhenSwitchTest002, TestSize.Level1)
{
    TransBrProxyStorage *storage = TransBrProxyStorageGetInstance();
    ASSERT_NE(storage, nullptr);
    TransBrProxyStorageInfo info;
    (void)memset_s(&info, sizeof(TransBrProxyStorageInfo), 0, sizeof(TransBrProxyStorageInfo));
    info.userId = UID_TEST + 100;
    (void)strcpy_s(info.bundleName, sizeof(info.bundleName), "bundle");
    (void)strcpy_s(info.abilityName, sizeof(info.abilityName), "ability");
    info.appIndex = APP_INDEX_TEST;
    TransBrProxyStorageWrite(storage, &info);
    NiceMock<BrProxyServerManagerInterfaceMock> mock;
    EXPECT_CALL(mock, PullUpHap).Times(0);
    TryToPullUpHapWhenSwitch(UID_TEST);
}

/**
 * @tc.name: TryToPullUpHapWhenSwitchTest003
 * @tc.desc: TryToPullUpHapWhenSwitch, g_proxyList is null and PullUpHap is called
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, TryToPullUpHapWhenSwitchTest003, TestSize.Level1)
{
    TransBrProxyStorage *storage = TransBrProxyStorageGetInstance();
    ASSERT_NE(storage, nullptr);
    TransBrProxyStorageInfo info;
    (void)memset_s(&info, sizeof(TransBrProxyStorageInfo), 0, sizeof(TransBrProxyStorageInfo));
    info.userId = UID_TEST;
    (void)strcpy_s(info.bundleName, sizeof(info.bundleName), "bundle");
    (void)strcpy_s(info.abilityName, sizeof(info.abilityName), "ability");
    info.appIndex = APP_INDEX_TEST;
    TransBrProxyStorageWrite(storage, &info);
    SoftBusList *proxyListBak = g_proxyList;
    g_proxyList = NULL;
    NiceMock<BrProxyServerManagerInterfaceMock> mock;
    EXPECT_CALL(mock, PullUpHap).WillOnce(Return(SOFTBUS_OK));
    TryToPullUpHapWhenSwitch(UID_TEST);
    g_proxyList = proxyListBak;
}

/**
 * @tc.name: TryToPullUpHapWhenSwitchTest004
 * @tc.desc: TryToPullUpHapWhenSwitch, matched node exists and PullUpHap is not called
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, TryToPullUpHapWhenSwitchTest004, TestSize.Level1)
{
    ASSERT_EQ(BrProxyServerInit(), SOFTBUS_OK);
    CloseAllBrProxy();
    BrProxyInfo *node = reinterpret_cast<BrProxyInfo *>(SoftBusCalloc(sizeof(BrProxyInfo)));
    ASSERT_NE(node, nullptr);
    (void)strcpy_s(node->bundleName, sizeof(node->bundleName), "bundle");
    (void)strcpy_s(node->abilityName, sizeof(node->abilityName), "ability");
    node->appIndex = APP_INDEX_TEST;
    node->userId = UID_TEST;
    ListInit(&node->node);
    ListAdd(&g_proxyList->list, &node->node);
    g_proxyList->cnt = 1;
    TransBrProxyStorage *storage = TransBrProxyStorageGetInstance();
    ASSERT_NE(storage, nullptr);
    TransBrProxyStorageInfo info;
    (void)memset_s(&info, sizeof(TransBrProxyStorageInfo), 0, sizeof(TransBrProxyStorageInfo));
    (void)strcpy_s(info.bundleName, sizeof(info.bundleName), "bundle");
    (void)strcpy_s(info.abilityName, sizeof(info.abilityName), "ability");
    info.appIndex = APP_INDEX_TEST;
    info.userId = UID_TEST;
    TransBrProxyStorageWrite(storage, &info);
    NiceMock<BrProxyServerManagerInterfaceMock> mock;
    EXPECT_CALL(mock, PullUpHap).Times(0);
    TryToPullUpHapWhenSwitch(UID_TEST);
    CloseAllBrProxy();
}

/**
 * @tc.name: TryToPullUpHapWhenSwitchTest005
 * @tc.desc: TryToPullUpHapWhenSwitch, no matched node in list and PullUpHap is called
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, TryToPullUpHapWhenSwitchTest005, TestSize.Level1)
{
    ASSERT_EQ(BrProxyServerInit(), SOFTBUS_OK);
    CloseAllBrProxy();
    TransBrProxyStorage *storage = TransBrProxyStorageGetInstance();
    ASSERT_NE(storage, nullptr);
    TransBrProxyStorageInfo info;
    (void)memset_s(&info, sizeof(TransBrProxyStorageInfo), 0, sizeof(TransBrProxyStorageInfo));
    (void)strcpy_s(info.bundleName, sizeof(info.bundleName), "bundle");
    (void)strcpy_s(info.abilityName, sizeof(info.abilityName), "ability");
    info.appIndex = APP_INDEX_TEST;
    info.userId = UID_TEST;
    TransBrProxyStorageWrite(storage, &info);
    NiceMock<BrProxyServerManagerInterfaceMock> mock;
    EXPECT_CALL(mock, PullUpHap).WillOnce(Return(SOFTBUS_OK));
    TryToPullUpHapWhenSwitch(UID_TEST);
}

/**
 * @tc.name: IsPidExistTest001
 * @tc.desc: IsPidExist, g_serverList is null returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, IsPidExistTest001, TestSize.Level1)
{
    g_serverList = NULL;
    ProxyBaseInfo baseInfo;
    (void)memset_s(&baseInfo, sizeof(ProxyBaseInfo), 0, sizeof(ProxyBaseInfo));
    bool ret = IsPidExist(&baseInfo, REQUEST_ID, PID_TEST);
    EXPECT_FALSE(ret);
    ret = IsPidExist(&baseInfo, 0, 0);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: IsPidExistTest002
 * @tc.desc: IsPidExist, matched channel exists returns true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, IsPidExistTest002, TestSize.Level1)
{
    g_serverList = NULL;
    ASSERT_EQ(BrProxyServerInit(), SOFTBUS_OK);
    ServerBrProxyChannelInfo *node =
        reinterpret_cast<ServerBrProxyChannelInfo *>(SoftBusCalloc(sizeof(ServerBrProxyChannelInfo)));
    ASSERT_NE(node, nullptr);
    (void)strcpy_s(node->proxyInfo.brMac, sizeof(node->proxyInfo.brMac), VALID_BR_MAC);
    (void)strcpy_s(node->proxyInfo.uuid, sizeof(node->proxyInfo.uuid), TEST_UUID);
    node->requestId = REQUEST_ID;
    node->callingPid = PID_TEST;
    ListInit(&node->node);
    ListAdd(&g_serverList->list, &node->node);
    g_serverList->cnt = 1;
    ProxyBaseInfo baseInfo;
    (void)memset_s(&baseInfo, sizeof(ProxyBaseInfo), 0, sizeof(ProxyBaseInfo));
    (void)strcpy_s(baseInfo.brMac, sizeof(baseInfo.brMac), VALID_BR_MAC);
    (void)strcpy_s(baseInfo.uuid, sizeof(baseInfo.uuid), TEST_UUID);
    bool ret = IsPidExist(&baseInfo, REQUEST_ID, PID_TEST);
    EXPECT_TRUE(ret);
    ListDelete(&node->node);
    SoftBusFree(node);
    g_serverList->cnt = 0;
}

/**
 * @tc.name: IsPidExistTest003
 * @tc.desc: IsPidExist, requestId mismatches and no matched channel returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, IsPidExistTest003, TestSize.Level1)
{
    g_serverList = NULL;
    ASSERT_EQ(BrProxyServerInit(), SOFTBUS_OK);
    ServerBrProxyChannelInfo *node =
        reinterpret_cast<ServerBrProxyChannelInfo *>(SoftBusCalloc(sizeof(ServerBrProxyChannelInfo)));
    ASSERT_NE(node, nullptr);
    (void)strcpy_s(node->proxyInfo.brMac, sizeof(node->proxyInfo.brMac), VALID_BR_MAC);
    (void)strcpy_s(node->proxyInfo.uuid, sizeof(node->proxyInfo.uuid), TEST_UUID);
    node->requestId = REQUEST_ID;
    node->callingPid = PID_TEST;
    ListInit(&node->node);
    ListAdd(&g_serverList->list, &node->node);
    g_serverList->cnt = 1;
    ProxyBaseInfo baseInfo;
    (void)memset_s(&baseInfo, sizeof(ProxyBaseInfo), 0, sizeof(ProxyBaseInfo));
    (void)strcpy_s(baseInfo.brMac, sizeof(baseInfo.brMac), VALID_BR_MAC);
    (void)strcpy_s(baseInfo.uuid, sizeof(baseInfo.uuid), TEST_UUID);
    bool ret = IsPidExist(&baseInfo, REQUEST_ID + 1, PID_TEST);
    EXPECT_FALSE(ret);
    ListDelete(&node->node);
    SoftBusFree(node);
    g_serverList->cnt = 0;
}

/**
 * @tc.name: MarkLastConnectTest001
 * @tc.desc: MarkLastConnect, brMac or uuid is null returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, MarkLastConnectTest001, TestSize.Level1)
{
    int32_t ret = MarkLastConnect(nullptr, TEST_UUID, REQUEST_ID);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = MarkLastConnect(VALID_BR_MAC, nullptr, REQUEST_ID);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = MarkLastConnect(nullptr, nullptr, REQUEST_ID);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: MarkLastConnectTest002
 * @tc.desc: MarkLastConnect, g_proxyList is null returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, MarkLastConnectTest002, TestSize.Level1)
{
    g_proxyList = NULL;
    int32_t ret = MarkLastConnect(VALID_BR_MAC, TEST_UUID, REQUEST_ID);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = MarkLastConnect(VALID_BR_MAC, TEST_UUID, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: MarkLastConnectTest003
 * @tc.desc: MarkLastConnect, matched node is found and returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, MarkLastConnectTest003, TestSize.Level1)
{
    ASSERT_EQ(BrProxyServerInit(), SOFTBUS_OK);
    CloseAllBrProxy();
    BrProxyInfo *node = reinterpret_cast<BrProxyInfo *>(SoftBusCalloc(sizeof(BrProxyInfo)));
    ASSERT_NE(node, nullptr);
    (void)strcpy_s(node->proxyInfo.brMac, sizeof(node->proxyInfo.brMac), VALID_BR_MAC);
    (void)strcpy_s(node->proxyInfo.uuid, sizeof(node->proxyInfo.uuid), TEST_UUID);
    node->requestId = REQUEST_ID;
    ListInit(&node->node);
    ListAdd(&g_proxyList->list, &node->node);
    g_proxyList->cnt = 1;
    int32_t ret = MarkLastConnect(VALID_BR_MAC, TEST_UUID, REQUEST_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CloseAllBrProxy();
}

/**
 * @tc.name: MarkLastConnectTest004
 * @tc.desc: MarkLastConnect, no matched node returns SOFTBUS_NOT_FIND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, MarkLastConnectTest004, TestSize.Level1)
{
    ASSERT_EQ(BrProxyServerInit(), SOFTBUS_OK);
    CloseAllBrProxy();
    int32_t ret = MarkLastConnect(VALID_BR_MAC, TEST_UUID, REQUEST_ID);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/**
 * @tc.name: StorageInfoTest001
 * @tc.desc: StorageInfo, valid proxyInfo writes storage without crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, StorageInfoTest001, TestSize.Level1)
{
    BrProxyInfo proxyInfo;
    (void)memset_s(&proxyInfo, sizeof(BrProxyInfo), 0, sizeof(BrProxyInfo));
    (void)strcpy_s(proxyInfo.bundleName, sizeof(proxyInfo.bundleName), "bundle");
    (void)strcpy_s(proxyInfo.abilityName, sizeof(proxyInfo.abilityName), "ability");
    proxyInfo.userId = UID_TEST;
    proxyInfo.appIndex = APP_INDEX_TEST;
    proxyInfo.uid = UID_TEST;
    EXPECT_NO_FATAL_FAILURE(StorageInfo(&proxyInfo));
    TransBrProxyStorageClear(TransBrProxyStorageGetInstance());
}

/**
 * @tc.name: GetRequestIdAndChanIdByEnableProxyTest001
 * @tc.desc: GetRequestIdAndChanIdByEnableProxy, g_proxyList is null returns SOFTBUS_TRANS_SESSION_SERVER_NOINIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, GetRequestIdAndChanIdByEnableProxyTest001, TestSize.Level1)
{
    g_proxyList = NULL;
    BrProxyInfo info;
    (void)memset_s(&info, sizeof(BrProxyInfo), 0, sizeof(BrProxyInfo));
    uint32_t requestId = 0;
    int32_t channelId = 0;
    int32_t ret = GetRequestIdAndChanIdByEnableProxy(&info, VALID_BR_MAC, TEST_UUID, &requestId, &channelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/**
 * @tc.name: GetRequestIdAndChanIdByEnableProxyTest002
 * @tc.desc: GetRequestIdAndChanIdByEnableProxy, info is null returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, GetRequestIdAndChanIdByEnableProxyTest002, TestSize.Level1)
{
    ASSERT_EQ(BrProxyServerInit(), SOFTBUS_OK);
    uint32_t requestId = 0;
    int32_t channelId = 0;
    int32_t ret = GetRequestIdAndChanIdByEnableProxy(nullptr, VALID_BR_MAC, TEST_UUID, &requestId, &channelId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetRequestIdAndChanIdByEnableProxy(nullptr, nullptr, nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: GetRequestIdAndChanIdByEnableProxyTest003
 * @tc.desc: GetRequestIdAndChanIdByEnableProxy, matched enabled node returns SOFTBUS_OK with existing ids
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, GetRequestIdAndChanIdByEnableProxyTest003, TestSize.Level1)
{
    ASSERT_EQ(BrProxyServerInit(), SOFTBUS_OK);
    CloseAllBrProxy();
    BrProxyInfo *node = reinterpret_cast<BrProxyInfo *>(SoftBusCalloc(sizeof(BrProxyInfo)));
    ASSERT_NE(node, nullptr);
    (void)strcpy_s(node->proxyInfo.brMac, sizeof(node->proxyInfo.brMac), VALID_BR_MAC);
    (void)strcpy_s(node->proxyInfo.uuid, sizeof(node->proxyInfo.uuid), TEST_UUID);
    node->appIndex = APP_INDEX_TEST;
    node->userId = UID_TEST;
    node->isEnable = true;
    node->requestId = REQUEST_ID;
    node->channelId = CHANNEL_ID;
    ListInit(&node->node);
    ListAdd(&g_proxyList->list, &node->node);
    g_proxyList->cnt = 1;
    BrProxyInfo query;
    (void)memset_s(&query, sizeof(BrProxyInfo), 0, sizeof(BrProxyInfo));
    query.appIndex = APP_INDEX_TEST;
    query.userId = UID_TEST;
    uint32_t requestId = 0;
    int32_t channelId = 0;
    int32_t ret = GetRequestIdAndChanIdByEnableProxy(&query, VALID_BR_MAC, TEST_UUID, &requestId, &channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(requestId, static_cast<uint32_t>(REQUEST_ID));
    EXPECT_EQ(channelId, CHANNEL_ID);
    CloseAllBrProxy();
}

/**
 * @tc.name: GetRequestIdAndChanIdByEnableProxyTest004
 * @tc.desc: GetRequestIdAndChanIdByEnableProxy, no matched node returns SOFTBUS_NOT_FIND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, GetRequestIdAndChanIdByEnableProxyTest004, TestSize.Level1)
{
    ASSERT_EQ(BrProxyServerInit(), SOFTBUS_OK);
    CloseAllBrProxy();
    BrProxyInfo query;
    (void)memset_s(&query, sizeof(BrProxyInfo), 0, sizeof(BrProxyInfo));
    query.appIndex = APP_INDEX_TEST;
    query.userId = UID_TEST;
    uint32_t requestId = 0;
    int32_t channelId = 0;
    int32_t ret = GetRequestIdAndChanIdByEnableProxy(&query, VALID_BR_MAC, TEST_UUID, &requestId, &channelId);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/**
 * @tc.name: GetRequestIdAndChanIdByEnableProxyTest005
 * @tc.desc: GetRequestIdAndChanIdByEnableProxy, matched disabled node generates new ids and returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, GetRequestIdAndChanIdByEnableProxyTest005, TestSize.Level1)
{
    ASSERT_EQ(BrProxyServerInit(), SOFTBUS_OK);
    CloseAllBrProxy();
    BrProxyInfo *node = reinterpret_cast<BrProxyInfo *>(SoftBusCalloc(sizeof(BrProxyInfo)));
    ASSERT_NE(node, nullptr);
    (void)strcpy_s(node->proxyInfo.brMac, sizeof(node->proxyInfo.brMac), VALID_BR_MAC);
    (void)strcpy_s(node->proxyInfo.uuid, sizeof(node->proxyInfo.uuid), TEST_UUID);
    node->appIndex = APP_INDEX_TEST;
    node->userId = UID_TEST;
    node->isEnable = false;
    ListInit(&node->node);
    ListAdd(&g_proxyList->list, &node->node);
    g_proxyList->cnt = 1;
    BrProxyInfo query;
    (void)memset_s(&query, sizeof(BrProxyInfo), 0, sizeof(BrProxyInfo));
    query.appIndex = APP_INDEX_TEST;
    query.userId = UID_TEST;
    uint32_t requestId = 0;
    int32_t channelId = 0;
    int32_t ret = GetRequestIdAndChanIdByEnableProxy(&query, VALID_BR_MAC, TEST_UUID, &requestId, &channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CloseAllBrProxy();
}

/**
 * @tc.name: UpdateServerAndNotifyOpenedTest001
 * @tc.desc: UpdateServerAndNotifyOpened, brMac/uuid/proxyInfo is null returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, UpdateServerAndNotifyOpenedTest001, TestSize.Level1)
{
    BrProxyInfo info;
    (void)memset_s(&info, sizeof(BrProxyInfo), 0, sizeof(BrProxyInfo));
    int32_t ret = UpdateServerAndNotifyOpened(nullptr, TEST_UUID, &info);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = UpdateServerAndNotifyOpened(VALID_BR_MAC, nullptr, &info);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = UpdateServerAndNotifyOpened(VALID_BR_MAC, TEST_UUID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: UpdateServerAndNotifyOpenedTest002
 * @tc.desc: UpdateServerAndNotifyOpened, g_proxyList is null and GetRequestId fails returns NOINIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, UpdateServerAndNotifyOpenedTest002, TestSize.Level1)
{
    g_proxyList = NULL;
    BrProxyInfo info;
    (void)memset_s(&info, sizeof(BrProxyInfo), 0, sizeof(BrProxyInfo));
    int32_t ret = UpdateServerAndNotifyOpened(VALID_BR_MAC, TEST_UUID, &info);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
    ASSERT_EQ(BrProxyServerInit(), SOFTBUS_OK);
}

/**
 * @tc.name: PostBrProxyOpenedEventTest001
 * @tc.desc: PostBrProxyOpenedEvent, brMac or uuid is null returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, PostBrProxyOpenedEventTest001, TestSize.Level1)
{
    int32_t ret = PostBrProxyOpenedEvent(PID_TEST, CHANNEL_ID, nullptr, TEST_UUID);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = PostBrProxyOpenedEvent(PID_TEST, CHANNEL_ID, VALID_BR_MAC, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = PostBrProxyOpenedEvent(PID_TEST, CHANNEL_ID, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: PostBrProxyOpenedEventTest002
 * @tc.desc: PostBrProxyOpenedEvent, brMac or uuid is too long and strcpy_s fails returns SOFTBUS_STRCPY_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, PostBrProxyOpenedEventTest002, TestSize.Level1)
{
    std::string longMac(BR_MAC_LEN + 8, 'x');
    int32_t ret = PostBrProxyOpenedEvent(PID_TEST, CHANNEL_ID, longMac.c_str(), TEST_UUID);
    EXPECT_EQ(ret, SOFTBUS_STRCPY_ERR);
    std::string longUuid(UUID_LEN + 8, 'y');
    ret = PostBrProxyOpenedEvent(PID_TEST, CHANNEL_ID, VALID_BR_MAC, longUuid.c_str());
    EXPECT_EQ(ret, SOFTBUS_STRCPY_ERR);
}

/**
 * @tc.name: TransOnBrProxyOpenedTest001
 * @tc.desc: TransOnBrProxyOpened, brMac or uuid is null returns early without crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, TransOnBrProxyOpenedTest001, TestSize.Level1)
{
    ASSERT_EQ(BrProxyServerInit(), SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(TransOnBrProxyOpened(PID_TEST, CHANNEL_ID, nullptr, TEST_UUID));
    EXPECT_NO_FATAL_FAILURE(TransOnBrProxyOpened(PID_TEST, CHANNEL_ID, VALID_BR_MAC, nullptr));
    EXPECT_NO_FATAL_FAILURE(TransOnBrProxyOpened(PID_TEST, CHANNEL_ID, nullptr, nullptr));
    EXPECT_NO_FATAL_FAILURE(TransOnBrProxyOpened(0, 0, nullptr, nullptr));
}

/**
 * @tc.name: TransBrProxyRemoveObjectTest001
 * @tc.desc: TransBrProxyRemoveObject, remove object with various pids without crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, TransBrProxyRemoveObjectTest001, TestSize.Level1)
{
    ASSERT_EQ(BrProxyServerInit(), SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(TransBrProxyRemoveObject(PID_TEST));
    EXPECT_NO_FATAL_FAILURE(TransBrProxyRemoveObject(0));
    EXPECT_NO_FATAL_FAILURE(TransBrProxyRemoveObject(-1));
    EXPECT_NO_FATAL_FAILURE(TransBrProxyRemoveObject(9999));
}
} // namespace OHOS