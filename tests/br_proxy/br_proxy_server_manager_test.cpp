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
 * @tc.desc: BrProxyServerManagerTest024
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest024, TestSize.Level1)
{
    const char *mac = "11:33:44:22:33:56";
    const char *uuid = "testuuid";
    int32_t channelId = 1;
    int32_t appIndex = 1;
    int32_t arr = GetChannelId(NULL, uuid, &channelId, appIndex);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = GetChannelId(mac, NULL, &channelId, appIndex);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    g_proxyList = NULL;
    arr = GetChannelId(mac, uuid, &channelId, appIndex);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    int32_t ret = BrProxyServerInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    arr = GetChannelId(mac, uuid, NULL, appIndex);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = GetChannelId(NULL, NULL, &channelId, appIndex);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = GetChannelId(NULL, NULL, &channelId, appIndex);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = GetChannelId(NULL, NULL, &channelId, appIndex);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = GetChannelId(NULL, NULL, NULL, appIndex);
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
    int32_t appIndex = 1;
    int32_t arr = GetChannelId(NULL, uuid, &channelId, appIndex);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = GetChannelId(mac, NULL, &channelId, appIndex);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = GetChannelId(mac, uuid, NULL, appIndex);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = GetChannelId(NULL, NULL, &channelId, appIndex);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = GetChannelId(mac, NULL, NULL, appIndex);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = GetChannelId(NULL, NULL, NULL, appIndex);
    EXPECT_EQ(arr, SOFTBUS_INVALID_PARAM);
    arr = GetChannelId(NULL, uuid, NULL, appIndex);
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
}