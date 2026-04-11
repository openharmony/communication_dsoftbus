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

#include "gmock/gmock.h"
#include <cinttypes>
#include <gtest/gtest.h>
#include <securec.h>
#include <sys/time.h>

#include "auth_request.c"

namespace OHOS {
using namespace testing;
using namespace testing::ext;
constexpr int32_t REQUEST_ID_VAL = 1000;
constexpr int32_t RESULT_VAL1 = 1;
constexpr int32_t RESULT_VAL2 = 2;
constexpr int32_t TEST_AUTH_ID = 12345;
constexpr int32_t TEST_AUTH_ID2 = 54321;
constexpr uint32_t TEST_REQUEST_ID1 = 100;
constexpr uint32_t TEST_REQUEST_ID2 = 200;
constexpr uint32_t TEST_REQUEST_ID3 = 300;
constexpr int64_t TEST_TRACE_ID = 9999;
constexpr uint16_t TEST_PORT = 12345;

/* Callback tracking variables */
static bool g_onVerifyPassedCalled = false;
static bool g_onVerifyFailedCalled = false;
static bool g_onConnOpenedCalled = false;
static bool g_onConnOpenFailedCalled = false;
static uint32_t g_callbackRequestId = 0;
static int32_t g_callbackResult = 0;
static int64_t g_callbackAuthId = 0;

static void OnVerifyPassed(uint32_t requestId, AuthHandle authHandle, const NodeInfo *info)
{
    g_onVerifyPassedCalled = true;
    g_callbackRequestId = requestId;
    g_callbackAuthId = authHandle.authId;
}

static void OnVerifyFailed(uint32_t requestId, int32_t reason)
{
    g_onVerifyFailedCalled = true;
    g_callbackRequestId = requestId;
    g_callbackResult = reason;
}

static void OnConnOpened(uint32_t requestId, AuthHandle authHandle)
{
    g_onConnOpenedCalled = true;
    g_callbackRequestId = requestId;
    g_callbackAuthId = authHandle.authId;
}

static void OnConnOpenFailed(uint32_t requestId, int32_t reason)
{
    g_onConnOpenFailedCalled = true;
    g_callbackRequestId = requestId;
    g_callbackResult = reason;
}

static void FreeWaitNotifyList(ListNode *list)
{
    if (list == nullptr) {
        return;
    }
    AuthRequest *item = nullptr;
    AuthRequest *next = nullptr;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, list, AuthRequest, node)
    {
        ListDelete(&item->node);
        SoftBusFree(item);
    }
}

class WaitNotifyListGuard {
public:
    explicit WaitNotifyListGuard(ListNode *list) : list_(list) {}
    ~WaitNotifyListGuard()
    {
        FreeWaitNotifyList(list_);
    }
    WaitNotifyListGuard(const WaitNotifyListGuard &) = delete;
    WaitNotifyListGuard &operator=(const WaitNotifyListGuard &) = delete;

private:
    ListNode *list_;
};

static void ResetCallbackFlags()
{
    g_onVerifyPassedCalled = false;
    g_onVerifyFailedCalled = false;
    g_onConnOpenedCalled = false;
    g_onConnOpenFailedCalled = false;
    g_callbackRequestId = 0;
    g_callbackResult = 0;
    g_callbackAuthId = 0;
}

static AuthVerifyCallback CreateVerifyCallback()
{
    AuthVerifyCallback cb;
    cb.onVerifyPassed = OnVerifyPassed;
    cb.onVerifyFailed = OnVerifyFailed;
    return cb;
}

static AuthConnCallback CreateConnCallback()
{
    AuthConnCallback cb;
    cb.onConnOpened = OnConnOpened;
    cb.onConnOpenFailed = OnConnOpenFailed;
    return cb;
}

static bool FillBleConnInfo(AuthConnInfo &info)
{
    (void)memset_s(&info, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    info.type = AUTH_LINK_TYPE_BLE;
    const char *bleMac = "11:22:33:44:55:66";
    return strcpy_s(info.info.bleInfo.bleMac, BT_MAC_LEN, bleMac) == EOK;
}

static bool FillBrConnInfo(AuthConnInfo &info)
{
    (void)memset_s(&info, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    info.type = AUTH_LINK_TYPE_BR;
    const char *brMac = "AA:BB:CC:DD:EE:FF";
    return strcpy_s(info.info.brInfo.brMac, BT_MAC_LEN, brMac) == EOK;
}

static bool FillWifiConnInfo(AuthConnInfo &info)
{
    (void)memset_s(&info, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    info.type = AUTH_LINK_TYPE_WIFI;
    const char *ip = "192.168.1.100";
    if (strcpy_s(info.info.ipInfo.ip, IP_LEN, ip) != EOK) {
        return false;
    }
    info.info.ipInfo.port = TEST_PORT;
    return true;
}

static AuthRequest *CreateAuthRequest(uint32_t requestId, RequestType type, AuthLinkType linkType)
{
    AuthRequest *request = static_cast<AuthRequest *>(SoftBusCalloc(sizeof(AuthRequest)));
    if (request == nullptr) {
        return nullptr;
    }
    request->requestId = requestId;
    request->type = type;
    request->authId = TEST_AUTH_ID;
    request->traceId = TEST_TRACE_ID;
    request->verifyCb = CreateVerifyCallback();
    request->connCb = CreateConnCallback();
    request->node.next = nullptr;
    request->node.prev = nullptr;
    request->addTime = 0;

    bool fillRet = false;
    if (linkType == AUTH_LINK_TYPE_BLE) {
        fillRet = FillBleConnInfo(request->connInfo);
    } else if (linkType == AUTH_LINK_TYPE_BR) {
        fillRet = FillBrConnInfo(request->connInfo);
    } else if (linkType == AUTH_LINK_TYPE_WIFI) {
        fillRet = FillWifiConnInfo(request->connInfo);
    }
    if (!fillRet) {
        SoftBusFree(request);
        return nullptr;
    }
    return request;
}

class AuthRequestTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthRequestTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "AuthRequestTest start";
    AuthCommonInit();
}

void AuthRequestTest::TearDownTestCase()
{
    AuthCommonDeinit();
    GTEST_LOG_(INFO) << "AuthRequestTest end";
}

void AuthRequestTest::SetUp()
{
    ResetCallbackFlags();
    ClearAuthRequest();
}

void AuthRequestTest::TearDown()
{
    ClearAuthRequest();
}

/*
 * @tc.name:GET_AUTH_REQUEST_TEST_001
 * @tc.desc: Verify that GetAuthRequestWaitNum correctly calculates the number of waiting
 *           authentication requests in the list.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, GET_AUTH_REQUEST_TEST_001, TestSize.Level1)
{
    AuthRequest *item = CreateAuthRequest(0, REQUEST_TYPE_RECONNECT, AUTH_LINK_TYPE_BLE);
    ASSERT_TRUE(item != nullptr);
    item->authId = 1234;
    item->addTime = 10;
    ListTailInsert(&g_authRequestList, &item->node);

    AuthRequest *request = CreateAuthRequest(1, REQUEST_TYPE_RECONNECT, AUTH_LINK_TYPE_BLE);
    ASSERT_TRUE(request != nullptr);
    request->authId = 123;
    request->addTime = 40000;
    ListTailInsert(&g_authRequestList, &request->node);

    uint32_t ret = GetAuthRequestWaitNum((const AuthRequest *)item, &g_authRequestList);
    EXPECT_NO_FATAL_FAILURE(ClearAuthRequest());
    EXPECT_EQ(ret, RESULT_VAL1);
}

/*
 * @tc.name:GET_AUTH_REQUEST_TEST_002
 * @tc.desc: Verify that GetAuthRequestWaitNum correctly calculates the number of waiting
 *           authentication requests in the list under different conditions.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, GET_AUTH_REQUEST_TEST_002, TestSize.Level1)
{
    AuthRequest *item = CreateAuthRequest(0, REQUEST_TYPE_RECONNECT, AUTH_LINK_TYPE_BLE);
    ASSERT_TRUE(item != nullptr);
    item->authId = REQUEST_ID_VAL;
    item->addTime = 10;
    ListTailInsert(&g_authRequestList, &item->node);

    AuthRequest *request = CreateAuthRequest(1, REQUEST_TYPE_RECONNECT, AUTH_LINK_TYPE_BLE);
    ASSERT_TRUE(request != nullptr);
    request->authId = REQUEST_ID_VAL;
    request->addTime = 3000;
    ListTailInsert(&g_authRequestList, &request->node);

    uint32_t ret = GetAuthRequestWaitNum((const AuthRequest *)request, &g_authRequestList);
    EXPECT_EQ(ret, RESULT_VAL2);
    EXPECT_NO_FATAL_FAILURE(ClearAuthRequest());
}

/*
 * @tc.name:CHECK_VERIFY_CALLBACK_TEST_001
 * @tc.desc: Verify CheckVerifyCallback returns false when callback is nullptr.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, CHECK_VERIFY_CALLBACK_TEST_001, TestSize.Level1)
{
    bool ret = CheckVerifyCallback(nullptr);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name:CHECK_VERIFY_CALLBACK_TEST_002
 * @tc.desc: Verify CheckVerifyCallback returns false when onVerifyPassed is nullptr.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, CHECK_VERIFY_CALLBACK_TEST_002, TestSize.Level1)
{
    AuthVerifyCallback cb;
    (void)memset_s(&cb, sizeof(AuthVerifyCallback), 0, sizeof(AuthVerifyCallback));
    cb.onVerifyPassed = nullptr;
    cb.onVerifyFailed = OnVerifyFailed;
    bool ret = CheckVerifyCallback(&cb);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name:CHECK_VERIFY_CALLBACK_TEST_003
 * @tc.desc: Verify CheckVerifyCallback returns false when onVerifyFailed is nullptr.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, CHECK_VERIFY_CALLBACK_TEST_003, TestSize.Level1)
{
    AuthVerifyCallback cb;
    (void)memset_s(&cb, sizeof(AuthVerifyCallback), 0, sizeof(AuthVerifyCallback));
    cb.onVerifyPassed = OnVerifyPassed;
    cb.onVerifyFailed = nullptr;
    bool ret = CheckVerifyCallback(&cb);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name:CHECK_VERIFY_CALLBACK_TEST_004
 * @tc.desc: Verify CheckVerifyCallback returns true when both callbacks are valid.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, CHECK_VERIFY_CALLBACK_TEST_004, TestSize.Level1)
{
    AuthVerifyCallback cb = CreateVerifyCallback();
    bool ret = CheckVerifyCallback(&cb);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name:CHECK_CONN_CALLBACK_TEST_001
 * @tc.desc: Verify CheckAuthConnCallback returns false when callback is nullptr.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, CHECK_CONN_CALLBACK_TEST_001, TestSize.Level1)
{
    bool ret = CheckAuthConnCallback(nullptr);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name:CHECK_CONN_CALLBACK_TEST_002
 * @tc.desc: Verify CheckAuthConnCallback returns false when onConnOpened is nullptr.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, CHECK_CONN_CALLBACK_TEST_002, TestSize.Level1)
{
    AuthConnCallback cb;
    (void)memset_s(&cb, sizeof(AuthConnCallback), 0, sizeof(AuthConnCallback));
    cb.onConnOpened = nullptr;
    cb.onConnOpenFailed = OnConnOpenFailed;
    bool ret = CheckAuthConnCallback(&cb);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name:CHECK_CONN_CALLBACK_TEST_003
 * @tc.desc: Verify CheckAuthConnCallback returns false when onConnOpenFailed is nullptr.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, CHECK_CONN_CALLBACK_TEST_003, TestSize.Level1)
{
    AuthConnCallback cb;
    (void)memset_s(&cb, sizeof(AuthConnCallback), 0, sizeof(AuthConnCallback));
    cb.onConnOpened = OnConnOpened;
    cb.onConnOpenFailed = nullptr;
    bool ret = CheckAuthConnCallback(&cb);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name:CHECK_CONN_CALLBACK_TEST_004
 * @tc.desc: Verify CheckAuthConnCallback returns true when both callbacks are valid.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, CHECK_CONN_CALLBACK_TEST_004, TestSize.Level1)
{
    AuthConnCallback cb = CreateConnCallback();
    bool ret = CheckAuthConnCallback(&cb);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name:ADD_AUTH_REQUEST_TEST_001
 * @tc.desc: Verify AddAuthRequest returns 0 when request is nullptr.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, ADD_AUTH_REQUEST_TEST_001, TestSize.Level1)
{
    uint32_t ret = AddAuthRequest(nullptr);
    EXPECT_EQ(ret, 0);
}

/*
 * @tc.name:ADD_AUTH_REQUEST_TEST_002
 * @tc.desc: Verify AddAuthRequest successfully adds a request and returns waitNum.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, ADD_AUTH_REQUEST_TEST_002, TestSize.Level1)
{
    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    request.requestId = TEST_REQUEST_ID1;
    request.type = REQUEST_TYPE_VERIFY;
    request.authId = TEST_AUTH_ID;
    request.connCb = CreateConnCallback();
    request.verifyCb = CreateVerifyCallback();
    FillBleConnInfo(request.connInfo);

    uint32_t ret = AddAuthRequest(&request);
    EXPECT_GE(ret, 1);
}

/*
 * @tc.name:ADD_AUTH_REQUEST_TEST_003
 * @tc.desc: Verify AddAuthRequest adds multiple requests and calculates waitNum correctly.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, ADD_AUTH_REQUEST_TEST_003, TestSize.Level1)
{
    AuthRequest req1;
    (void)memset_s(&req1, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    req1.requestId = TEST_REQUEST_ID1;
    req1.type = REQUEST_TYPE_RECONNECT;
    req1.connCb = CreateConnCallback();
    req1.verifyCb = CreateVerifyCallback();
    FillBleConnInfo(req1.connInfo);
    uint32_t ret1 = AddAuthRequest(&req1);
    EXPECT_GE(ret1, 1);

    AuthRequest req2;
    (void)memset_s(&req2, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    req2.requestId = TEST_REQUEST_ID2;
    req2.type = REQUEST_TYPE_RECONNECT;
    req2.connCb = CreateConnCallback();
    req2.verifyCb = CreateVerifyCallback();
    FillBleConnInfo(req2.connInfo);
    uint32_t ret2 = AddAuthRequest(&req2);
    EXPECT_GE(ret2, ret1);
}

/*
 * @tc.name:ADD_AUTH_REQUEST_TEST_004
 * @tc.desc: Verify AddAuthRequest with BR link type.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, ADD_AUTH_REQUEST_TEST_004, TestSize.Level1)
{
    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    request.requestId = TEST_REQUEST_ID1;
    request.type = REQUEST_TYPE_CONNECT;
    request.connCb = CreateConnCallback();
    request.verifyCb = CreateVerifyCallback();
    FillBrConnInfo(request.connInfo);

    uint32_t ret = AddAuthRequest(&request);
    EXPECT_GE(ret, 1);
}

/*
 * @tc.name:ADD_AUTH_REQUEST_TEST_005
 * @tc.desc: Verify AddAuthRequest with WIFI link type.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, ADD_AUTH_REQUEST_TEST_005, TestSize.Level1)
{
    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    request.requestId = TEST_REQUEST_ID1;
    request.type = REQUEST_TYPE_VERIFY;
    request.connCb = CreateConnCallback();
    request.verifyCb = CreateVerifyCallback();
    FillWifiConnInfo(request.connInfo);

    uint32_t ret = AddAuthRequest(&request);
    EXPECT_GE(ret, 1);
}

/*
 * @tc.name:ADD_AUTH_REQUEST_TEST_006
 * @tc.desc: Verify AddAuthRequest with REQUEST_TYPE_VERIFY type.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, ADD_AUTH_REQUEST_TEST_006, TestSize.Level2)
{
    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    request.requestId = TEST_REQUEST_ID3;
    request.type = REQUEST_TYPE_VERIFY;
    request.connCb = CreateConnCallback();
    request.verifyCb = CreateVerifyCallback();
    FillBleConnInfo(request.connInfo);

    uint32_t ret = AddAuthRequest(&request);
    EXPECT_GE(ret, 1);
}

/*
 * @tc.name:GET_AUTH_REQUEST_API_TEST_001
 * @tc.desc: Verify GetAuthRequest returns SOFTBUS_INVALID_PARAM when request is nullptr.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, GET_AUTH_REQUEST_API_TEST_001, TestSize.Level1)
{
    int32_t ret = GetAuthRequest(TEST_REQUEST_ID1, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name:GET_AUTH_REQUEST_API_TEST_002
 * @tc.desc: Verify GetAuthRequest returns SOFTBUS_NOT_FIND when requestId not found.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, GET_AUTH_REQUEST_API_TEST_002, TestSize.Level1)
{
    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    int32_t ret = GetAuthRequest(99999, &request);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/*
 * @tc.name:GET_AUTH_REQUEST_API_TEST_003
 * @tc.desc: Verify GetAuthRequest successfully retrieves a previously added request.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, GET_AUTH_REQUEST_API_TEST_003, TestSize.Level1)
{
    AuthRequest addReq;
    (void)memset_s(&addReq, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    addReq.requestId = TEST_REQUEST_ID1;
    addReq.type = REQUEST_TYPE_RECONNECT;
    addReq.authId = TEST_AUTH_ID;
    addReq.connCb = CreateConnCallback();
    addReq.verifyCb = CreateVerifyCallback();
    FillBleConnInfo(addReq.connInfo);
    AddAuthRequest(&addReq);

    AuthRequest getRequest;
    (void)memset_s(&getRequest, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    int32_t ret = GetAuthRequest(TEST_REQUEST_ID1, &getRequest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(getRequest.requestId, TEST_REQUEST_ID1);
    EXPECT_EQ(getRequest.authId, TEST_AUTH_ID);
    EXPECT_EQ(getRequest.type, REQUEST_TYPE_RECONNECT);
}

/*
 * @tc.name:GET_AUTH_REQUEST_API_TEST_004
 * @tc.desc: Verify GetAuthRequest can retrieve request with different link types.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, GET_AUTH_REQUEST_API_TEST_004, TestSize.Level2)
{
    AuthRequest addReq;
    (void)memset_s(&addReq, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    addReq.requestId = TEST_REQUEST_ID2;
    addReq.type = REQUEST_TYPE_CONNECT;
    addReq.authId = TEST_AUTH_ID2;
    addReq.connCb = CreateConnCallback();
    addReq.verifyCb = CreateVerifyCallback();
    FillBrConnInfo(addReq.connInfo);
    AddAuthRequest(&addReq);

    AuthRequest getRequest;
    (void)memset_s(&getRequest, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    int32_t ret = GetAuthRequest(TEST_REQUEST_ID2, &getRequest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(getRequest.requestId, TEST_REQUEST_ID2);
    EXPECT_EQ(getRequest.authId, TEST_AUTH_ID2);
    EXPECT_EQ(getRequest.connInfo.type, AUTH_LINK_TYPE_BR);
}

/*
 * @tc.name:GET_AUTH_REQUEST_NO_LOCK_TEST_001
 * @tc.desc: Verify GetAuthRequestNoLock returns SOFTBUS_INVALID_PARAM when request is nullptr.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, GET_AUTH_REQUEST_NO_LOCK_TEST_001, TestSize.Level1)
{
    int32_t ret = GetAuthRequestNoLock(TEST_REQUEST_ID1, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name:GET_AUTH_REQUEST_NO_LOCK_TEST_002
 * @tc.desc: Verify GetAuthRequestNoLock returns SOFTBUS_NOT_FIND when requestId not found.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, GET_AUTH_REQUEST_NO_LOCK_TEST_002, TestSize.Level1)
{
    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    int32_t ret = GetAuthRequestNoLock(99999, &request);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/*
 * @tc.name:GET_AUTH_REQUEST_NO_LOCK_TEST_003
 * @tc.desc: Verify GetAuthRequestNoLock successfully retrieves a manually inserted request.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, GET_AUTH_REQUEST_NO_LOCK_TEST_003, TestSize.Level1)
{
    AuthRequest *item = CreateAuthRequest(TEST_REQUEST_ID1, REQUEST_TYPE_VERIFY, AUTH_LINK_TYPE_BLE);
    ASSERT_TRUE(item != nullptr);
    item->addTime = 50000;
    ListTailInsert(&g_authRequestList, &item->node);

    AuthRequest getRequest;
    (void)memset_s(&getRequest, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    int32_t ret = GetAuthRequestNoLock(TEST_REQUEST_ID1, &getRequest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(getRequest.requestId, TEST_REQUEST_ID1);
    EXPECT_EQ(getRequest.addTime, 50000);
}

/*
 * @tc.name:GET_AUTH_REQUEST_NO_LOCK_TEST_004
 * @tc.desc: Verify GetAuthRequestNoLock with multiple items in list finds correct one.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, GET_AUTH_REQUEST_NO_LOCK_TEST_004, TestSize.Level2)
{
    AuthRequest *item1 = CreateAuthRequest(TEST_REQUEST_ID1, REQUEST_TYPE_VERIFY, AUTH_LINK_TYPE_BLE);
    ASSERT_TRUE(item1 != nullptr);
    ListTailInsert(&g_authRequestList, &item1->node);
    AuthRequest *item2 = CreateAuthRequest(TEST_REQUEST_ID2, REQUEST_TYPE_RECONNECT, AUTH_LINK_TYPE_BR);
    ASSERT_TRUE(item2 != nullptr);
    ListTailInsert(&g_authRequestList, &item2->node);

    AuthRequest getRequest;
    (void)memset_s(&getRequest, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    int32_t ret = GetAuthRequestNoLock(TEST_REQUEST_ID2, &getRequest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(getRequest.requestId, TEST_REQUEST_ID2);
    EXPECT_EQ(getRequest.type, REQUEST_TYPE_RECONNECT);
}

/*
 * @tc.name:FIND_AUTH_REQUEST_BY_CONN_INFO_TEST_001
 * @tc.desc: Verify FindAuthRequestByConnInfo returns SOFTBUS_INVALID_PARAM when connInfo is nullptr.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, FIND_AUTH_REQUEST_BY_CONN_INFO_TEST_001, TestSize.Level1)
{
    AuthRequest request;
    int32_t ret = FindAuthRequestByConnInfo(nullptr, &request);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name:FIND_AUTH_REQUEST_BY_CONN_INFO_TEST_002
 * @tc.desc: Verify FindAuthRequestByConnInfo returns SOFTBUS_INVALID_PARAM when request is nullptr.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, FIND_AUTH_REQUEST_BY_CONN_INFO_TEST_002, TestSize.Level1)
{
    AuthConnInfo connInfo;
    FillBleConnInfo(connInfo);
    int32_t ret = FindAuthRequestByConnInfo(&connInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name:FIND_AUTH_REQUEST_BY_CONN_INFO_TEST_003
 * @tc.desc: Verify FindAuthRequestByConnInfo returns SOFTBUS_NOT_FIND when no match.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, FIND_AUTH_REQUEST_BY_CONN_INFO_TEST_003, TestSize.Level1)
{
    AuthConnInfo connInfo;
    FillBleConnInfo(connInfo);
    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    int32_t ret = FindAuthRequestByConnInfo(&connInfo, &request);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/*
 * @tc.name:FIND_AUTH_REQUEST_BY_CONN_INFO_TEST_004
 * @tc.desc: Verify FindAuthRequestByConnInfo finds a REQUEST_TYPE_VERIFY request with matching BLE conn info.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, FIND_AUTH_REQUEST_BY_CONN_INFO_TEST_004, TestSize.Level1)
{
    AuthRequest *item = CreateAuthRequest(TEST_REQUEST_ID1, REQUEST_TYPE_VERIFY, AUTH_LINK_TYPE_BLE);
    ASSERT_TRUE(item != nullptr);
    ListTailInsert(&g_authRequestList, &item->node);

    AuthConnInfo connInfo;
    FillBleConnInfo(connInfo);
    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    int32_t ret = FindAuthRequestByConnInfo(&connInfo, &request);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(request.requestId, TEST_REQUEST_ID1);
    EXPECT_EQ(request.type, REQUEST_TYPE_VERIFY);
}

/*
 * @tc.name:FIND_AUTH_REQUEST_BY_CONN_INFO_TEST_005
 * @tc.desc: Verify FindAuthRequestByConnInfo does not find non-VERIFY type requests.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, FIND_AUTH_REQUEST_BY_CONN_INFO_TEST_005, TestSize.Level2)
{
    AuthRequest *item = CreateAuthRequest(TEST_REQUEST_ID1, REQUEST_TYPE_RECONNECT, AUTH_LINK_TYPE_BLE);
    ASSERT_TRUE(item != nullptr);
    ListTailInsert(&g_authRequestList, &item->node);

    AuthConnInfo connInfo;
    FillBleConnInfo(connInfo);
    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    int32_t ret = FindAuthRequestByConnInfo(&connInfo, &request);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/*
 * @tc.name:FIND_AUTH_REQUEST_BY_CONN_INFO_TEST_006
 * @tc.desc: Verify FindAuthRequestByConnInfo finds request with BR conn info.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, FIND_AUTH_REQUEST_BY_CONN_INFO_TEST_006, TestSize.Level1)
{
    AuthRequest *item = CreateAuthRequest(TEST_REQUEST_ID1, REQUEST_TYPE_VERIFY, AUTH_LINK_TYPE_BR);
    ASSERT_TRUE(item != nullptr);
    ListTailInsert(&g_authRequestList, &item->node);

    AuthConnInfo connInfo;
    FillBrConnInfo(connInfo);
    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    int32_t ret = FindAuthRequestByConnInfo(&connInfo, &request);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(request.requestId, TEST_REQUEST_ID1);
}

/*
 * @tc.name:FIND_AND_DEL_AUTH_REQUEST_TEST_001
 * @tc.desc: Verify FindAndDelAuthRequestByConnInfo returns SOFTBUS_INVALID_PARAM when connInfo is nullptr.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, FIND_AND_DEL_AUTH_REQUEST_TEST_001, TestSize.Level1)
{
    int32_t ret = FindAndDelAuthRequestByConnInfo(TEST_REQUEST_ID1, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name:FIND_AND_DEL_AUTH_REQUEST_TEST_002
 * @tc.desc: Verify FindAndDelAuthRequestByConnInfo with no matching items returns SOFTBUS_NOT_FIND.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, FIND_AND_DEL_AUTH_REQUEST_TEST_002, TestSize.Level1)
{
    AuthConnInfo connInfo;
    FillBleConnInfo(connInfo);
    int32_t ret = FindAndDelAuthRequestByConnInfo(TEST_REQUEST_ID1, &connInfo);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/*
 * @tc.name:FIND_AND_DEL_AUTH_REQUEST_TEST_004
 * @tc.desc: Verify FindAndDelAuthRequestByConnInfo triggers connCb for non-matching requestId.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, FIND_AND_DEL_AUTH_REQUEST_TEST_004, TestSize.Level1)
{
    AuthRequest *item = CreateAuthRequest(TEST_REQUEST_ID2, REQUEST_TYPE_VERIFY, AUTH_LINK_TYPE_BLE);
    ASSERT_TRUE(item != nullptr);
    ListTailInsert(&g_authRequestList, &item->node);

    AuthConnInfo connInfo;
    FillBleConnInfo(connInfo);
    ResetCallbackFlags();
    int32_t ret = FindAndDelAuthRequestByConnInfo(TEST_REQUEST_ID1, &connInfo);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    EXPECT_TRUE(g_onConnOpenFailedCalled);
    EXPECT_EQ(g_callbackRequestId, TEST_REQUEST_ID2);
}

/*
 * @tc.name:FIND_AND_DEL_AUTH_REQUEST_TEST_005
 * @tc.desc: Verify FindAndDelAuthRequestByConnInfo triggers verifyCb when connCb is invalid.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, FIND_AND_DEL_AUTH_REQUEST_TEST_005, TestSize.Level2)
{
    AuthRequest *item = CreateAuthRequest(TEST_REQUEST_ID2, REQUEST_TYPE_VERIFY, AUTH_LINK_TYPE_BLE);
    ASSERT_TRUE(item != nullptr);
    /* Make connCb invalid so verifyCb is used instead */
    (void)memset_s(&item->connCb, sizeof(AuthConnCallback), 0, sizeof(AuthConnCallback));
    ListTailInsert(&g_authRequestList, &item->node);

    AuthConnInfo connInfo;
    FillBleConnInfo(connInfo);
    ResetCallbackFlags();
    int32_t ret = FindAndDelAuthRequestByConnInfo(TEST_REQUEST_ID1, &connInfo);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    EXPECT_TRUE(g_onVerifyFailedCalled);
    EXPECT_EQ(g_callbackRequestId, TEST_REQUEST_ID2);
}

/*
 * @tc.name:DEL_AUTH_REQUEST_TEST_001
 * @tc.desc: Verify DelAuthRequest works when list is empty (no crash).
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, DEL_AUTH_REQUEST_TEST_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(DelAuthRequest(TEST_REQUEST_ID1));
}

/*
 * @tc.name:DEL_AUTH_REQUEST_TEST_002
 * @tc.desc: Verify DelAuthRequest removes a request that exists.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, DEL_AUTH_REQUEST_TEST_002, TestSize.Level1)
{
    AuthRequest *item = CreateAuthRequest(TEST_REQUEST_ID1, REQUEST_TYPE_VERIFY, AUTH_LINK_TYPE_BLE);
    ASSERT_TRUE(item != nullptr);
    ListTailInsert(&g_authRequestList, &item->node);

    EXPECT_NO_FATAL_FAILURE(DelAuthRequest(TEST_REQUEST_ID1));

    AuthRequest getRequest;
    (void)memset_s(&getRequest, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    int32_t ret = GetAuthRequest(TEST_REQUEST_ID1, &getRequest);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/*
 * @tc.name:DEL_AUTH_REQUEST_TEST_003
 * @tc.desc: Verify DelAuthRequest only removes the target request, not others.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, DEL_AUTH_REQUEST_TEST_003, TestSize.Level1)
{
    AuthRequest *item1 = CreateAuthRequest(TEST_REQUEST_ID1, REQUEST_TYPE_VERIFY, AUTH_LINK_TYPE_BLE);
    ASSERT_TRUE(item1 != nullptr);
    ListTailInsert(&g_authRequestList, &item1->node);
    AuthRequest *item2 = CreateAuthRequest(TEST_REQUEST_ID2, REQUEST_TYPE_RECONNECT, AUTH_LINK_TYPE_BR);
    ASSERT_TRUE(item2 != nullptr);
    ListTailInsert(&g_authRequestList, &item2->node);

    EXPECT_NO_FATAL_FAILURE(DelAuthRequest(TEST_REQUEST_ID1));

    AuthRequest getRequest;
    (void)memset_s(&getRequest, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    int32_t ret = GetAuthRequest(TEST_REQUEST_ID2, &getRequest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(getRequest.requestId, TEST_REQUEST_ID2);
}

/*
 * @tc.name:DEL_AUTH_REQUEST_TEST_004
 * @tc.desc: Verify DelAuthRequest with non-existent requestId does not affect others.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, DEL_AUTH_REQUEST_TEST_004, TestSize.Level2)
{
    AuthRequest *item = CreateAuthRequest(TEST_REQUEST_ID1, REQUEST_TYPE_VERIFY, AUTH_LINK_TYPE_BLE);
    ASSERT_TRUE(item != nullptr);
    ListTailInsert(&g_authRequestList, &item->node);

    EXPECT_NO_FATAL_FAILURE(DelAuthRequest(99999));

    AuthRequest getRequest;
    (void)memset_s(&getRequest, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    int32_t ret = GetAuthRequest(TEST_REQUEST_ID1, &getRequest);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name:CLEAR_AUTH_REQUEST_TEST_001
 * @tc.desc: Verify ClearAuthRequest works on an empty list.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, CLEAR_AUTH_REQUEST_TEST_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(ClearAuthRequest());
}

/*
 * @tc.name:CLEAR_AUTH_REQUEST_TEST_002
 * @tc.desc: Verify ClearAuthRequest removes all requests from the list.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, CLEAR_AUTH_REQUEST_TEST_002, TestSize.Level1)
{
    AuthRequest *item1 = CreateAuthRequest(TEST_REQUEST_ID1, REQUEST_TYPE_VERIFY, AUTH_LINK_TYPE_BLE);
    ASSERT_TRUE(item1 != nullptr);
    ListTailInsert(&g_authRequestList, &item1->node);
    AuthRequest *item2 = CreateAuthRequest(TEST_REQUEST_ID2, REQUEST_TYPE_RECONNECT, AUTH_LINK_TYPE_BR);
    ASSERT_TRUE(item2 != nullptr);
    ListTailInsert(&g_authRequestList, &item2->node);
    AuthRequest *item3 = CreateAuthRequest(TEST_REQUEST_ID3, REQUEST_TYPE_CONNECT, AUTH_LINK_TYPE_WIFI);
    ASSERT_TRUE(item3 != nullptr);
    ListTailInsert(&g_authRequestList, &item3->node);

    EXPECT_NO_FATAL_FAILURE(ClearAuthRequest());

    AuthRequest getRequest;
    (void)memset_s(&getRequest, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    EXPECT_EQ(GetAuthRequest(TEST_REQUEST_ID1, &getRequest), SOFTBUS_NOT_FIND);
    EXPECT_EQ(GetAuthRequest(TEST_REQUEST_ID2, &getRequest), SOFTBUS_NOT_FIND);
    EXPECT_EQ(GetAuthRequest(TEST_REQUEST_ID3, &getRequest), SOFTBUS_NOT_FIND);
}

/*
 * @tc.name:CLEAR_AUTH_REQUEST_TEST_003
 * @tc.desc: Verify ClearAuthRequest can be called multiple times safely.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, CLEAR_AUTH_REQUEST_TEST_003, TestSize.Level2)
{
    AuthRequest *item = CreateAuthRequest(TEST_REQUEST_ID1, REQUEST_TYPE_VERIFY, AUTH_LINK_TYPE_BLE);
    ASSERT_TRUE(item != nullptr);
    ListTailInsert(&g_authRequestList, &item->node);

    EXPECT_NO_FATAL_FAILURE(ClearAuthRequest());
    AuthRequest getRequest;
    (void)memset_s(&getRequest, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    EXPECT_EQ(GetAuthRequest(TEST_REQUEST_ID1, &getRequest), SOFTBUS_NOT_FIND);
}

/*
 * @tc.name:PERFORM_VERIFY_CALLBACK_TEST_001
 * @tc.desc: Verify PerformVerifyCallback returns early with invalid authHandle type (below WIFI).
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, PERFORM_VERIFY_CALLBACK_TEST_001, TestSize.Level1)
{
    AuthHandle invalidHandle;
    invalidHandle.authId = TEST_AUTH_ID;
    invalidHandle.type = 0; /* below AUTH_LINK_TYPE_WIFI */

    EXPECT_NO_FATAL_FAILURE(PerformVerifyCallback(TEST_REQUEST_ID1, SOFTBUS_OK, invalidHandle, nullptr));
    EXPECT_FALSE(g_onVerifyPassedCalled);
    EXPECT_FALSE(g_onVerifyFailedCalled);
}

/*
 * @tc.name:PERFORM_VERIFY_CALLBACK_TEST_002
 * @tc.desc: Verify PerformVerifyCallback returns early with authHandle type >= MAX.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, PERFORM_VERIFY_CALLBACK_TEST_002, TestSize.Level1)
{
    AuthHandle invalidHandle;
    invalidHandle.authId = TEST_AUTH_ID;
    invalidHandle.type = AUTH_LINK_TYPE_MAX;

    EXPECT_NO_FATAL_FAILURE(PerformVerifyCallback(TEST_REQUEST_ID1, SOFTBUS_OK, invalidHandle, nullptr));
    EXPECT_FALSE(g_onVerifyPassedCalled);
    EXPECT_FALSE(g_onVerifyFailedCalled);
}

/*
 * @tc.name:PERFORM_VERIFY_CALLBACK_TEST_003
 * @tc.desc: Verify PerformVerifyCallback returns early when requestId not found.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, PERFORM_VERIFY_CALLBACK_TEST_003, TestSize.Level1)
{
    AuthHandle handle;
    handle.authId = TEST_AUTH_ID;
    handle.type = AUTH_LINK_TYPE_BLE;

    EXPECT_NO_FATAL_FAILURE(PerformVerifyCallback(99999, SOFTBUS_OK, handle, nullptr));
    EXPECT_FALSE(g_onVerifyPassedCalled);
    EXPECT_FALSE(g_onVerifyFailedCalled);
}

/*
 * @tc.name:PERFORM_VERIFY_CALLBACK_TEST_004
 * @tc.desc: Verify PerformVerifyCallback calls onVerifyPassed when result is SOFTBUS_OK.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, PERFORM_VERIFY_CALLBACK_TEST_004, TestSize.Level1)
{
    AuthRequest *item = CreateAuthRequest(TEST_REQUEST_ID1, REQUEST_TYPE_VERIFY, AUTH_LINK_TYPE_BLE);
    ASSERT_TRUE(item != nullptr);
    ListTailInsert(&g_authRequestList, &item->node);

    AuthHandle handle;
    handle.authId = TEST_AUTH_ID;
    handle.type = AUTH_LINK_TYPE_BLE;

    ResetCallbackFlags();
    EXPECT_NO_FATAL_FAILURE(PerformVerifyCallback(TEST_REQUEST_ID1, SOFTBUS_OK, handle, nullptr));
    EXPECT_TRUE(g_onVerifyPassedCalled);
    EXPECT_FALSE(g_onVerifyFailedCalled);
    EXPECT_EQ(g_callbackRequestId, TEST_REQUEST_ID1);
    EXPECT_EQ(g_callbackAuthId, TEST_AUTH_ID);
}

/*
 * @tc.name:PERFORM_VERIFY_CALLBACK_TEST_005
 * @tc.desc: Verify PerformVerifyCallback calls onVerifyFailed when result is not SOFTBUS_OK.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, PERFORM_VERIFY_CALLBACK_TEST_005, TestSize.Level1)
{
    AuthRequest *item = CreateAuthRequest(TEST_REQUEST_ID1, REQUEST_TYPE_VERIFY, AUTH_LINK_TYPE_BLE);
    ASSERT_TRUE(item != nullptr);
    ListTailInsert(&g_authRequestList, &item->node);

    AuthHandle handle;
    handle.authId = TEST_AUTH_ID;
    handle.type = AUTH_LINK_TYPE_BLE;

    ResetCallbackFlags();
    EXPECT_NO_FATAL_FAILURE(PerformVerifyCallback(TEST_REQUEST_ID1, SOFTBUS_AUTH_CONN_FAIL, handle, nullptr));
    EXPECT_FALSE(g_onVerifyPassedCalled);
    EXPECT_TRUE(g_onVerifyFailedCalled);
    EXPECT_EQ(g_callbackRequestId, TEST_REQUEST_ID1);
    EXPECT_EQ(g_callbackResult, SOFTBUS_AUTH_CONN_FAIL);
}

/*
 * @tc.name:PERFORM_VERIFY_CALLBACK_TEST_006
 * @tc.desc: Verify PerformVerifyCallback with WIFI link type.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, PERFORM_VERIFY_CALLBACK_TEST_006, TestSize.Level2)
{
    AuthRequest *item = CreateAuthRequest(TEST_REQUEST_ID2, REQUEST_TYPE_VERIFY, AUTH_LINK_TYPE_WIFI);
    ASSERT_TRUE(item != nullptr);
    ListTailInsert(&g_authRequestList, &item->node);

    AuthHandle handle;
    handle.authId = TEST_AUTH_ID2;
    handle.type = AUTH_LINK_TYPE_WIFI;

    ResetCallbackFlags();
    EXPECT_NO_FATAL_FAILURE(PerformVerifyCallback(TEST_REQUEST_ID2, SOFTBUS_OK, handle, nullptr));
    EXPECT_TRUE(g_onVerifyPassedCalled);
    EXPECT_EQ(g_callbackRequestId, TEST_REQUEST_ID2);
}

/*
 * @tc.name:PERFORM_VERIFY_CALLBACK_TEST_007
 * @tc.desc: Verify PerformVerifyCallback does nothing with invalid verifyCb.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, PERFORM_VERIFY_CALLBACK_TEST_007, TestSize.Level2)
{
    AuthRequest *item = CreateAuthRequest(TEST_REQUEST_ID1, REQUEST_TYPE_VERIFY, AUTH_LINK_TYPE_BLE);
    ASSERT_TRUE(item != nullptr);
    /* Invalidate verifyCb */
    (void)memset_s(&item->verifyCb, sizeof(AuthVerifyCallback), 0, sizeof(AuthVerifyCallback));
    ListTailInsert(&g_authRequestList, &item->node);

    AuthHandle handle;
    handle.authId = TEST_AUTH_ID;
    handle.type = AUTH_LINK_TYPE_BLE;

    ResetCallbackFlags();
    EXPECT_NO_FATAL_FAILURE(PerformVerifyCallback(TEST_REQUEST_ID1, SOFTBUS_OK, handle, nullptr));
    EXPECT_FALSE(g_onVerifyPassedCalled);
    EXPECT_FALSE(g_onVerifyFailedCalled);
}

/*
 * @tc.name:PERFORM_VERIFY_CALLBACK_TEST_008
 * @tc.desc: Verify PerformVerifyCallback with BR link type handle.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, PERFORM_VERIFY_CALLBACK_TEST_008, TestSize.Level2)
{
    AuthRequest *item = CreateAuthRequest(TEST_REQUEST_ID1, REQUEST_TYPE_VERIFY, AUTH_LINK_TYPE_BLE);
    ASSERT_TRUE(item != nullptr);
    ListTailInsert(&g_authRequestList, &item->node);

    AuthHandle handle;
    handle.authId = TEST_AUTH_ID;
    handle.type = AUTH_LINK_TYPE_BR;

    ResetCallbackFlags();
    EXPECT_NO_FATAL_FAILURE(PerformVerifyCallback(TEST_REQUEST_ID1, SOFTBUS_OK, handle, nullptr));
    EXPECT_TRUE(g_onVerifyPassedCalled);
    EXPECT_EQ(g_callbackRequestId, TEST_REQUEST_ID1);
}

/*
 * @tc.name:PERFORM_CONN_CALLBACK_TEST_001
 * @tc.desc: Verify PerformAuthConnCallback returns early when requestId not found.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, PERFORM_CONN_CALLBACK_TEST_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(PerformAuthConnCallback(99999, SOFTBUS_OK, TEST_AUTH_ID));
    EXPECT_FALSE(g_onConnOpenedCalled);
    EXPECT_FALSE(g_onConnOpenFailedCalled);
}

/*
 * @tc.name:PERFORM_CONN_CALLBACK_TEST_002
 * @tc.desc: Verify PerformAuthConnCallback calls onConnOpened when result is SOFTBUS_OK.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, PERFORM_CONN_CALLBACK_TEST_002, TestSize.Level1)
{
    AuthRequest *item = CreateAuthRequest(TEST_REQUEST_ID1, REQUEST_TYPE_CONNECT, AUTH_LINK_TYPE_BLE);
    ASSERT_TRUE(item != nullptr);
    ListTailInsert(&g_authRequestList, &item->node);

    ResetCallbackFlags();
    EXPECT_NO_FATAL_FAILURE(PerformAuthConnCallback(TEST_REQUEST_ID1, SOFTBUS_OK, TEST_AUTH_ID));
    EXPECT_TRUE(g_onConnOpenedCalled);
    EXPECT_FALSE(g_onConnOpenFailedCalled);
    EXPECT_EQ(g_callbackRequestId, TEST_REQUEST_ID1);
    EXPECT_EQ(g_callbackAuthId, TEST_AUTH_ID);
}

/*
 * @tc.name:PERFORM_CONN_CALLBACK_TEST_003
 * @tc.desc: Verify PerformAuthConnCallback calls onConnOpenFailed when result is not SOFTBUS_OK.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, PERFORM_CONN_CALLBACK_TEST_003, TestSize.Level1)
{
    AuthRequest *item = CreateAuthRequest(TEST_REQUEST_ID1, REQUEST_TYPE_CONNECT, AUTH_LINK_TYPE_BLE);
    ASSERT_TRUE(item != nullptr);
    ListTailInsert(&g_authRequestList, &item->node);

    ResetCallbackFlags();
    EXPECT_NO_FATAL_FAILURE(PerformAuthConnCallback(TEST_REQUEST_ID1, SOFTBUS_AUTH_CONN_FAIL, TEST_AUTH_ID));
    EXPECT_FALSE(g_onConnOpenedCalled);
    EXPECT_TRUE(g_onConnOpenFailedCalled);
    EXPECT_EQ(g_callbackRequestId, TEST_REQUEST_ID1);
    EXPECT_EQ(g_callbackResult, SOFTBUS_AUTH_CONN_FAIL);
}

/*
 * @tc.name:PERFORM_CONN_CALLBACK_TEST_004
 * @tc.desc: Verify PerformAuthConnCallback does nothing with invalid connCb.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, PERFORM_CONN_CALLBACK_TEST_004, TestSize.Level2)
{
    AuthRequest *item = CreateAuthRequest(TEST_REQUEST_ID1, REQUEST_TYPE_CONNECT, AUTH_LINK_TYPE_BLE);
    ASSERT_TRUE(item != nullptr);
    /* Invalidate connCb */
    (void)memset_s(&item->connCb, sizeof(AuthConnCallback), 0, sizeof(AuthConnCallback));
    ListTailInsert(&g_authRequestList, &item->node);

    ResetCallbackFlags();
    EXPECT_NO_FATAL_FAILURE(PerformAuthConnCallback(TEST_REQUEST_ID1, SOFTBUS_OK, TEST_AUTH_ID));
    EXPECT_FALSE(g_onConnOpenedCalled);
    EXPECT_FALSE(g_onConnOpenFailedCalled);
}

/*
 * @tc.name:PERFORM_CONN_CALLBACK_TEST_005
 * @tc.desc: Verify PerformAuthConnCallback with BR link type.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, PERFORM_CONN_CALLBACK_TEST_005, TestSize.Level2)
{
    AuthRequest *item = CreateAuthRequest(TEST_REQUEST_ID2, REQUEST_TYPE_RECONNECT, AUTH_LINK_TYPE_BR);
    ASSERT_TRUE(item != nullptr);
    ListTailInsert(&g_authRequestList, &item->node);

    ResetCallbackFlags();
    EXPECT_NO_FATAL_FAILURE(PerformAuthConnCallback(TEST_REQUEST_ID2, SOFTBUS_OK, TEST_AUTH_ID2));
    EXPECT_TRUE(g_onConnOpenedCalled);
    EXPECT_EQ(g_callbackRequestId, TEST_REQUEST_ID2);
    EXPECT_EQ(g_callbackAuthId, TEST_AUTH_ID2);
}

/*
 * @tc.name:PERFORM_CONN_CALLBACK_TEST_006
 * @tc.desc: Verify PerformAuthConnCallback with WIFI link type.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, PERFORM_CONN_CALLBACK_TEST_006, TestSize.Level2)
{
    AuthRequest *item = CreateAuthRequest(TEST_REQUEST_ID3, REQUEST_TYPE_CONNECT, AUTH_LINK_TYPE_WIFI);
    ASSERT_TRUE(item != nullptr);
    ListTailInsert(&g_authRequestList, &item->node);

    ResetCallbackFlags();
    EXPECT_NO_FATAL_FAILURE(PerformAuthConnCallback(TEST_REQUEST_ID3, SOFTBUS_AUTH_CONN_FAIL, TEST_AUTH_ID));
    EXPECT_TRUE(g_onConnOpenFailedCalled);
    EXPECT_EQ(g_callbackRequestId, TEST_REQUEST_ID3);
}

/*
 * @tc.name:FIND_BY_REQUEST_ID_TEST_001
 * @tc.desc: Verify FindAuthRequestByRequestId returns nullptr when list is empty.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, FIND_BY_REQUEST_ID_TEST_001, TestSize.Level1)
{
    AuthRequest *ret = FindAuthRequestByRequestId(TEST_REQUEST_ID1);
    EXPECT_EQ(ret, nullptr);
}

/*
 * @tc.name:FIND_BY_REQUEST_ID_TEST_002
 * @tc.desc: Verify FindAuthRequestByRequestId finds correct item.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, FIND_BY_REQUEST_ID_TEST_002, TestSize.Level1)
{
    AuthRequest *item = CreateAuthRequest(TEST_REQUEST_ID1, REQUEST_TYPE_VERIFY, AUTH_LINK_TYPE_BLE);
    ASSERT_TRUE(item != nullptr);
    ListTailInsert(&g_authRequestList, &item->node);

    AuthRequest *ret = FindAuthRequestByRequestId(TEST_REQUEST_ID1);
    EXPECT_NE(ret, nullptr);
    EXPECT_EQ(ret->requestId, TEST_REQUEST_ID1);
}

/*
 * @tc.name:FIND_BY_REQUEST_ID_TEST_003
 * @tc.desc: Verify FindAuthRequestByRequestId returns nullptr for non-existent requestId.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, FIND_BY_REQUEST_ID_TEST_003, TestSize.Level1)
{
    AuthRequest *item = CreateAuthRequest(TEST_REQUEST_ID1, REQUEST_TYPE_VERIFY, AUTH_LINK_TYPE_BLE);
    ASSERT_TRUE(item != nullptr);
    ListTailInsert(&g_authRequestList, &item->node);

    AuthRequest *ret = FindAuthRequestByRequestId(99999);
    EXPECT_EQ(ret, nullptr);
}

/*
 * @tc.name:FIND_BY_REQUEST_ID_TEST_004
 * @tc.desc: Verify FindAuthRequestByRequestId finds correct item among multiple items.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, FIND_BY_REQUEST_ID_TEST_004, TestSize.Level2)
{
    AuthRequest *item1 = CreateAuthRequest(TEST_REQUEST_ID1, REQUEST_TYPE_VERIFY, AUTH_LINK_TYPE_BLE);
    ASSERT_TRUE(item1 != nullptr);
    ListTailInsert(&g_authRequestList, &item1->node);
    AuthRequest *item2 = CreateAuthRequest(TEST_REQUEST_ID2, REQUEST_TYPE_RECONNECT, AUTH_LINK_TYPE_BR);
    ASSERT_TRUE(item2 != nullptr);
    ListTailInsert(&g_authRequestList, &item2->node);
    AuthRequest *item3 = CreateAuthRequest(TEST_REQUEST_ID3, REQUEST_TYPE_CONNECT, AUTH_LINK_TYPE_WIFI);
    ASSERT_TRUE(item3 != nullptr);
    ListTailInsert(&g_authRequestList, &item3->node);

    AuthRequest *ret = FindAuthRequestByRequestId(TEST_REQUEST_ID3);
    EXPECT_NE(ret, nullptr);
    EXPECT_EQ(ret->requestId, TEST_REQUEST_ID3);
    EXPECT_EQ(ret->type, REQUEST_TYPE_CONNECT);
}

/*
 * @tc.name:GET_AUTH_REQUEST_WAIT_NUM_TEST_001
 * @tc.desc: Verify GetAuthRequestWaitNum returns 0 when list is empty.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, GET_AUTH_REQUEST_WAIT_NUM_TEST_001, TestSize.Level1)
{
    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    request.requestId = TEST_REQUEST_ID1;
    request.type = REQUEST_TYPE_VERIFY;
    FillBleConnInfo(request.connInfo);

    ListNode waitList = { &waitList, &waitList };
    WaitNotifyListGuard guard(&waitList);
    uint32_t ret = GetAuthRequestWaitNum(&request, &waitList);
    EXPECT_EQ(ret, 0);
}

/*
 * @tc.name:GET_AUTH_REQUEST_WAIT_NUM_TEST_002
 * @tc.desc: Verify GetAuthRequestWaitNum returns 1 with single matching item.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, GET_AUTH_REQUEST_WAIT_NUM_TEST_002, TestSize.Level1)
{
    AuthRequest *item = CreateAuthRequest(TEST_REQUEST_ID1, REQUEST_TYPE_RECONNECT, AUTH_LINK_TYPE_BLE);
    ASSERT_TRUE(item != nullptr);
    item->addTime = 1000;
    ListTailInsert(&g_authRequestList, &item->node);

    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    request.requestId = TEST_REQUEST_ID1;
    request.type = REQUEST_TYPE_RECONNECT;
    request.addTime = 50000;
    FillBleConnInfo(request.connInfo);

    ListNode waitList = { &waitList, &waitList };
    WaitNotifyListGuard guard(&waitList);
    uint32_t ret = GetAuthRequestWaitNum(&request, &waitList);
    EXPECT_EQ(ret, 1);
}

/*
 * @tc.name:GET_AUTH_REQUEST_WAIT_NUM_TEST_003
 * @tc.desc: Verify GetAuthRequestWaitNum skips items with different type.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, GET_AUTH_REQUEST_WAIT_NUM_TEST_003, TestSize.Level2)
{
    AuthRequest *item = CreateAuthRequest(TEST_REQUEST_ID1, REQUEST_TYPE_VERIFY, AUTH_LINK_TYPE_BLE);
    ASSERT_TRUE(item != nullptr);
    item->addTime = 1000;
    ListTailInsert(&g_authRequestList, &item->node);

    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    request.requestId = TEST_REQUEST_ID2;
    request.type = REQUEST_TYPE_RECONNECT;
    request.addTime = 50000;
    FillBleConnInfo(request.connInfo);

    ListNode waitList = { &waitList, &waitList };
    WaitNotifyListGuard guard(&waitList);
    uint32_t ret = GetAuthRequestWaitNum(&request, &waitList);
    EXPECT_EQ(ret, 0);
}

/*
 * @tc.name:GET_AUTH_REQUEST_WAIT_NUM_TEST_004
 * @tc.desc: Verify GetAuthRequestWaitNum skips items with different connInfo.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, GET_AUTH_REQUEST_WAIT_NUM_TEST_004, TestSize.Level2)
{
    AuthRequest *item = CreateAuthRequest(TEST_REQUEST_ID1, REQUEST_TYPE_RECONNECT, AUTH_LINK_TYPE_BR);
    ASSERT_TRUE(item != nullptr);
    item->addTime = 1000;
    ListTailInsert(&g_authRequestList, &item->node);

    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    request.requestId = TEST_REQUEST_ID2;
    request.type = REQUEST_TYPE_RECONNECT;
    request.addTime = 50000;
    FillBleConnInfo(request.connInfo); /* Different link type from item */

    ListNode waitList = { &waitList, &waitList };
    WaitNotifyListGuard guard(&waitList);
    uint32_t ret = GetAuthRequestWaitNum(&request, &waitList);
    EXPECT_EQ(ret, 0);
}

/*
 * @tc.name:GET_AUTH_REQUEST_WAIT_NUM_TEST_005
 * @tc.desc: Verify GetAuthRequestWaitNum with time difference exceeding AUTH_REQUEST_TIMTOUR.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, GET_AUTH_REQUEST_WAIT_NUM_TEST_005, TestSize.Level2)
{
    AuthRequest *item = CreateAuthRequest(TEST_REQUEST_ID1, REQUEST_TYPE_RECONNECT, AUTH_LINK_TYPE_BLE);
    ASSERT_TRUE(item != nullptr);
    item->addTime = 1000;
    item->connCb = CreateConnCallback();
    ListTailInsert(&g_authRequestList, &item->node);

    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    request.requestId = TEST_REQUEST_ID2;
    request.type = REQUEST_TYPE_RECONNECT;
    request.addTime = 100000; /* time diff > AUTH_REQUEST_TIMTOUR(30000) */
    FillBleConnInfo(request.connInfo);

    ResetCallbackFlags();
    ListNode waitList = { &waitList, &waitList };
    WaitNotifyListGuard guard(&waitList);
    uint32_t ret = GetAuthRequestWaitNum(&request, &waitList);
    /* Old item should be moved to waitNotifyList and trigger callback */
    EXPECT_EQ(ret, 0);
    EXPECT_NO_FATAL_FAILURE(ClearAuthRequest());
}

/*
 * @tc.name:GET_AUTH_REQUEST_WAIT_NUM_TEST_006
 * @tc.desc: Verify GetAuthRequestWaitNum counts items within time threshold.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, GET_AUTH_REQUEST_WAIT_NUM_TEST_006, TestSize.Level2)
{
    AuthRequest *item = CreateAuthRequest(TEST_REQUEST_ID1, REQUEST_TYPE_RECONNECT, AUTH_LINK_TYPE_BLE);
    ASSERT_TRUE(item != nullptr);
    item->addTime = 45000;
    ListTailInsert(&g_authRequestList, &item->node);

    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    request.requestId = TEST_REQUEST_ID2;
    request.type = REQUEST_TYPE_RECONNECT;
    request.addTime = 50000; /* time diff = 5000 < AUTH_REQUEST_TIMTOUR(30000) */
    FillBleConnInfo(request.connInfo);

    ListNode waitList = { &waitList, &waitList };
    WaitNotifyListGuard guard(&waitList);
    uint32_t ret = GetAuthRequestWaitNum(&request, &waitList);
    EXPECT_EQ(ret, 1);
}

/*
 * @tc.name:INTEGRATION_TEST_001
 * @tc.desc: Verify full lifecycle: Add -> Get -> Del -> Get fails.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, INTEGRATION_TEST_001, TestSize.Level1)
{
    AuthRequest addReq;
    (void)memset_s(&addReq, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    addReq.requestId = TEST_REQUEST_ID1;
    addReq.type = REQUEST_TYPE_VERIFY;
    addReq.authId = TEST_AUTH_ID;
    addReq.connCb = CreateConnCallback();
    addReq.verifyCb = CreateVerifyCallback();
    FillBleConnInfo(addReq.connInfo);
    AddAuthRequest(&addReq);

    AuthRequest getReq;
    (void)memset_s(&getReq, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    EXPECT_EQ(GetAuthRequest(TEST_REQUEST_ID1, &getReq), SOFTBUS_OK);
    EXPECT_EQ(getReq.requestId, TEST_REQUEST_ID1);

    EXPECT_NO_FATAL_FAILURE(DelAuthRequest(TEST_REQUEST_ID1));

    EXPECT_EQ(GetAuthRequest(TEST_REQUEST_ID1, &getReq), SOFTBUS_NOT_FIND);
}

/*
 * @tc.name:INTEGRATION_TEST_002
 * @tc.desc: Verify full lifecycle: Add -> FindByConnInfo -> Clear -> FindByConnInfo fails.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, INTEGRATION_TEST_002, TestSize.Level1)
{
    AuthRequest addReq;
    (void)memset_s(&addReq, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    addReq.requestId = TEST_REQUEST_ID1;
    addReq.type = REQUEST_TYPE_VERIFY;
    addReq.connCb = CreateConnCallback();
    addReq.verifyCb = CreateVerifyCallback();
    FillBleConnInfo(addReq.connInfo);
    AddAuthRequest(&addReq);

    AuthConnInfo connInfo;
    FillBleConnInfo(connInfo);
    AuthRequest findReq;
    (void)memset_s(&findReq, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    EXPECT_EQ(FindAuthRequestByConnInfo(&connInfo, &findReq), SOFTBUS_OK);

    EXPECT_NO_FATAL_FAILURE(ClearAuthRequest());

    (void)memset_s(&findReq, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    EXPECT_EQ(FindAuthRequestByConnInfo(&connInfo, &findReq), SOFTBUS_NOT_FIND);
}

/*
 * @tc.name:INTEGRATION_TEST_003
 * @tc.desc: Verify Add -> Add -> FindAndDel -> Verify remaining.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, INTEGRATION_TEST_003, TestSize.Level1)
{
    AuthRequest req1;
    (void)memset_s(&req1, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    req1.requestId = TEST_REQUEST_ID1;
    req1.type = REQUEST_TYPE_RECONNECT;
    req1.connCb = CreateConnCallback();
    req1.verifyCb = CreateVerifyCallback();
    FillBleConnInfo(req1.connInfo);
    AddAuthRequest(&req1);

    AuthRequest req2;
    (void)memset_s(&req2, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    req2.requestId = TEST_REQUEST_ID2;
    req2.type = REQUEST_TYPE_RECONNECT;
    req2.connCb = CreateConnCallback();
    req2.verifyCb = CreateVerifyCallback();
    FillBrConnInfo(req2.connInfo);
    AddAuthRequest(&req2);

    AuthConnInfo connInfo;
    FillBleConnInfo(connInfo);
    FindAndDelAuthRequestByConnInfo(TEST_REQUEST_ID1, &connInfo);

    AuthRequest getReq;
    (void)memset_s(&getReq, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    EXPECT_EQ(GetAuthRequest(TEST_REQUEST_ID1, &getReq), SOFTBUS_NOT_FIND);
    EXPECT_EQ(GetAuthRequest(TEST_REQUEST_ID2, &getReq), SOFTBUS_OK);
}

/*
 * @tc.name:INTEGRATION_TEST_004
 * @tc.desc: Verify multiple AddAuthRequest with different conn types.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, INTEGRATION_TEST_004, TestSize.Level2)
{
    AuthRequest reqBle;
    (void)memset_s(&reqBle, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    reqBle.requestId = TEST_REQUEST_ID1;
    reqBle.type = REQUEST_TYPE_VERIFY;
    reqBle.connCb = CreateConnCallback();
    reqBle.verifyCb = CreateVerifyCallback();
    FillBleConnInfo(reqBle.connInfo);

    AuthRequest reqBr;
    (void)memset_s(&reqBr, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    reqBr.requestId = TEST_REQUEST_ID2;
    reqBr.type = REQUEST_TYPE_CONNECT;
    reqBr.connCb = CreateConnCallback();
    reqBr.verifyCb = CreateVerifyCallback();
    FillBrConnInfo(reqBr.connInfo);

    uint32_t ret1 = AddAuthRequest(&reqBle);
    uint32_t ret2 = AddAuthRequest(&reqBr);
    EXPECT_GE(ret1, 1);
    EXPECT_GE(ret2, 1);

    AuthRequest getReq;
    (void)memset_s(&getReq, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    EXPECT_EQ(GetAuthRequest(TEST_REQUEST_ID1, &getReq), SOFTBUS_OK);
    EXPECT_EQ(GetAuthRequest(TEST_REQUEST_ID2, &getReq), SOFTBUS_OK);
}

/*
 * @tc.name:INTEGRATION_TEST_005
 * @tc.desc: Verify PerformVerifyCallback after AddAuthRequest.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, INTEGRATION_TEST_005, TestSize.Level2)
{
    AuthRequest addReq;
    (void)memset_s(&addReq, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    addReq.requestId = TEST_REQUEST_ID1;
    addReq.type = REQUEST_TYPE_VERIFY;
    addReq.authId = TEST_AUTH_ID;
    addReq.connCb = CreateConnCallback();
    addReq.verifyCb = CreateVerifyCallback();
    FillBleConnInfo(addReq.connInfo);
    AddAuthRequest(&addReq);

    AuthHandle handle;
    handle.authId = TEST_AUTH_ID;
    handle.type = AUTH_LINK_TYPE_BLE;

    ResetCallbackFlags();
    EXPECT_NO_FATAL_FAILURE(PerformVerifyCallback(TEST_REQUEST_ID1, SOFTBUS_OK, handle, nullptr));
    EXPECT_TRUE(g_onVerifyPassedCalled);
    EXPECT_EQ(g_callbackRequestId, TEST_REQUEST_ID1);
}

/*
 * @tc.name:INTEGRATION_TEST_006
 * @tc.desc: Verify PerformAuthConnCallback after AddAuthRequest.
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(AuthRequestTest, INTEGRATION_TEST_006, TestSize.Level2)
{
    AuthRequest addReq;
    (void)memset_s(&addReq, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    addReq.requestId = TEST_REQUEST_ID1;
    addReq.type = REQUEST_TYPE_CONNECT;
    addReq.authId = TEST_AUTH_ID;
    addReq.connCb = CreateConnCallback();
    addReq.verifyCb = CreateVerifyCallback();
    FillBleConnInfo(addReq.connInfo);
    AddAuthRequest(&addReq);

    ResetCallbackFlags();
    EXPECT_NO_FATAL_FAILURE(PerformAuthConnCallback(TEST_REQUEST_ID1, SOFTBUS_OK, TEST_AUTH_ID));
    EXPECT_TRUE(g_onConnOpenedCalled);
    EXPECT_EQ(g_callbackRequestId, TEST_REQUEST_ID1);
    EXPECT_EQ(g_callbackAuthId, TEST_AUTH_ID);
}
} // namespace OHOS
