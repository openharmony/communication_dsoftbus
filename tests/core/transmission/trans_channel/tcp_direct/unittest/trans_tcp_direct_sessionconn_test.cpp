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
#include "trans_tcp_direct_sessionconn.h"

#include <cstring>
#include <unistd.h>
#include <securec.h>
#include <gtest/gtest.h>

#include "auth_interface_struct.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "trans_session_service.h"
#include "trans_tcp_direct_manager.h"
#include "trans_tcp_direct_sessionconn_mock.h"

using namespace testing::ext;

namespace OHOS {

#define PID 2024
#define PKG_NAME_SIZE_MAX_LEN 65
#define INVALID_VALUE 0
#define TEST_CHANNEL_ID 1

static const char *g_pkgName = "dms";
static const char *g_myIp = "192.168.8.1";
static const char *g_peerIp = "192.168.8.2";
static int32_t g_netWorkId = 100;
static TcpChannelInfo g_testTcpChannelInfoRes = {
    .channelId = TEST_CHANNEL_ID,
    .myIp = "192.168.8.1",
    .pkgName = "dms",
    .pid = PID,
    .peerIp = "192.168.8.2",
    .needFastWakeUp = false,
};
static TcpChannelInfo g_testNullTcpChannelInfo = {};

static TcpChannelInfo g_testTcpChannelInfo;
static char g_testUuid[UUID_BUF_LEN];
static bool g_testNeedFastWakeUp;

class TransTcpDirectSessionConnTest : public testing::Test {
public:
    TransTcpDirectSessionConnTest()
    {}
    ~TransTcpDirectSessionConnTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransTcpDirectSessionConnTest::SetUpTestCase(void)
{
}

void TransTcpDirectSessionConnTest::TearDownTestCase(void)
{
}

struct TransGetTdcChannelByIdTestParam {
    int32_t channelId;
    TcpChannelInfo *channel;
    bool listInited;
    TcpChannelInfo *testChannelInfo;
    int32_t res;
    TcpChannelInfo channelRes;
};

class TransGetTdcChannelByIdTest : public testing::TestWithParam<TransGetTdcChannelByIdTestParam> {
public:
    TransGetTdcChannelByIdTest() { };
    ~TransGetTdcChannelByIdTest() { };
    void SetUp() override
    {
        memset_s(&g_testTcpChannelInfo, sizeof(TcpChannelInfo), 0, sizeof(TcpChannelInfo));
    }
    void TearDown() override { }
};

struct TransTdcGetWakeUpInfoTestParam {
    int32_t channelId;
    char *uuid;
    int32_t uuidLen;
    bool *needFastWakeUp;
    int32_t transGetTdcChannelByIdMockRes;
    TcpChannelInfo *channelInfoMockRes;
    int32_t lnnGetRemoteStrInfoMockRes;
    int32_t res;
};

class TransTdcGetWakeUpInfoTest : public testing::TestWithParam<TransTdcGetWakeUpInfoTestParam> {
public:
    TransTdcGetWakeUpInfoTest() { };
    ~TransTdcGetWakeUpInfoTest() { };
    void SetUp() override
    {
        memset_s(&g_testUuid, UUID_BUF_LEN, 0, UUID_BUF_LEN);
        g_testNeedFastWakeUp = false;
    }
    void TearDown() override { }
};

struct TransTdcSetWakeUpInfoTestParam {
    int32_t channelId;
    bool needFastWakeUp;
    bool listInited;
    TcpChannelInfo *testChannelInfo;
    int32_t res;
};

class TransTdcSetWakeUpInfoTest : public testing::TestWithParam<TransTdcSetWakeUpInfoTestParam> {
public:
    TransTdcSetWakeUpInfoTest() { };
    ~TransTdcSetWakeUpInfoTest() { };
};

SessionConn *TestSetSessionConn()
{
    SessionConn *conn = (SessionConn*)SoftBusCalloc(sizeof(SessionConn));
    if (conn == nullptr) {
        return nullptr;
    }
    conn->serverSide = true;
    conn->channelId = 1;
    conn->status = TCP_DIRECT_CHANNEL_STATUS_INIT;
    conn->timeout = 0;
    conn->req = INVALID_VALUE;
    conn->authHandle.authId = 1;
    conn->requestId = 1;
    conn->listenMod = DIRECT_CHANNEL_SERVER_WIFI;
    conn->appInfo.myData.pid = 1;
    conn->appInfo.fd = g_netWorkId;
    (void)memcpy_s(conn->appInfo.myData.pkgName, PKG_NAME_SIZE_MAX_LEN, g_pkgName, (strlen(g_pkgName)+1));
    return conn;
}

AppInfo *TestSetAppInfo()
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    if (appInfo == nullptr) {
        return nullptr;
    }
    appInfo->businessType = BUSINESS_TYPE_BYTE;
    appInfo->appType = APP_TYPE_NORMAL;
    appInfo->myData.apiVersion = API_V2;
    appInfo->peerData.apiVersion = API_V2;
    appInfo->encrypt = APP_INFO_FILE_FEATURES_SUPPORT;
    appInfo->algorithm = APP_INFO_ALGORITHM_AES_GCM_256;
    appInfo->crc = APP_INFO_FILE_FEATURES_SUPPORT;
    return appInfo;
}

/**
 * @tc.name: GetTcpChannelInfoLock
 * @tc.desc: test GetTcpChannelInfoLock001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectSessionConnTest, GetTcpChannelInfoLock001, TestSize.Level1)
{
    int32_t ret = GetTcpChannelInfoLock();
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);

    ret = CreateTcpChannelInfoList();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = GetTcpChannelInfoLock();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ReleaseTcpChannelInfoLock();
}

/**
 * @tc.name: GetSessionConnByRequestId
 * @tc.desc: test GetSessionConnByRequestId001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectSessionConnTest, GetSessionConnByRequestId001, TestSize.Level1)
{
    uint32_t requestId = 1;
    SessionConn *conn = GetSessionConnByRequestId(requestId);
    EXPECT_EQ(conn, nullptr);
}

/**
 * @tc.name: GetSessionConnByReq
 * @tc.desc: test GetSessionConnByReq001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectSessionConnTest, GetSessionConnByReq001, TestSize.Level1)
{
    int64_t req = 1;
    SessionConn *conn = GetSessionConnByReq(req);
    EXPECT_EQ(conn, nullptr);
}

/**
 * @tc.name: SetAppInfoById
 * @tc.desc: test SetAppInfoById001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectSessionConnTest, SetAppInfoById001, TestSize.Level1)
{
    int32_t channelId = 1;
    AppInfo *info = TestSetAppInfo();
    int32_t ret = SetAppInfoById(channelId, info);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
    SoftBusFree(info);
}

/**
 * @tc.name: UpdateAccessInfoById
 * @tc.desc: test UpdateAccessInfoById001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectSessionConnTest, UpdateAccessInfoById001, TestSize.Level1)
{
    int32_t channelId = 1;
    AccessInfo *accessInfo = (AccessInfo *)SoftBusCalloc(sizeof(AccessInfo));
    ASSERT_TRUE(accessInfo != nullptr);
    int32_t ret = UpdateAccessInfoById(channelId, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    accessInfo->localTokenId = 0;
    ret = UpdateAccessInfoById(channelId, accessInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(accessInfo);
}

/**
 * @tc.name: GetAuthIdByChanId
 * @tc.desc: test GetAuthIdByChanId001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectSessionConnTest, GetAuthIdByChanId001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = GetAuthIdByChanId(channelId);
    EXPECT_EQ(ret, AUTH_INVALID_ID);

    ret = CreatSessionConnList();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = GetAuthIdByChanId(channelId);
    EXPECT_EQ(ret, AUTH_INVALID_ID);

    SessionConn *conn = TestSetSessionConn();
    ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = GetAuthIdByChanId(channelId);
    EXPECT_EQ(ret, conn->authHandle.authId);
    TransDelSessionConnById(channelId);
}

/**
 * @tc.name: GetAuthHandleByChanId
 * @tc.desc: test GetAuthHandleByChanId001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectSessionConnTest, GetAuthHandleByChanId001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = GetAuthHandleByChanId(channelId, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    AuthHandle authHandle = { .authId = 1, .type = 1 };
    ret = GetAuthHandleByChanId(channelId, &authHandle);
    EXPECT_EQ(ret, SOFTBUS_TRANS_GET_AUTH_HANDLE_FAILED);
}

/**
 * @tc.name: CreateTcpChannelInfo
 * @tc.desc: test CreateTcpChannelInfo001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectSessionConnTest, CreateTcpChannelInfo001, TestSize.Level1)
{
    TcpChannelInfo *info = CreateTcpChannelInfo(NULL);
    EXPECT_EQ(info, nullptr);

    ChannelInfo *channel = (ChannelInfo *)SoftBusCalloc(sizeof(ChannelInfo));
    channel->channelId = 1;
    channel->businessType = BUSINESS_TYPE_BYTE;
    channel->connectType = CONNECT_HML;
    channel->isServer = false;
    channel->channelType = 0;
    channel->timeStart = 12345;
    channel->linkType = 0;
    (void)memcpy_s(channel->myIp, IP_LEN, g_myIp, strlen(g_myIp));
    info = CreateTcpChannelInfo(channel);
    EXPECT_EQ(info, nullptr);
    (void)memcpy_s(channel->peerSessionName, PKG_NAME_SIZE_MAX_LEN, g_pkgName, strlen(g_pkgName)+1);
    EXPECT_EQ(info, nullptr);
    (void)memcpy_s(channel->peerDeviceId, PKG_NAME_SIZE_MAX_LEN, "123456", strlen("123456"));
    EXPECT_EQ(info, nullptr);
    (void)memcpy_s(channel->peerIp, IP_LEN, g_peerIp, strlen(g_peerIp));
    info = CreateTcpChannelInfo(channel);
    EXPECT_EQ(info, nullptr);
    SoftBusFree(channel);
}

/**
 * @tc.name: TransTdcGetIpAndConnectTypeById
 * @tc.desc: test TransTdcGetIpAndConnectTypeById001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectSessionConnTest, TransTdcGetIpAndConnectTypeById001, TestSize.Level1)
{
    int32_t channelId = 1;
    char localIp[IP_LEN] = { 0 };
    char remoteIp[IP_LEN] = { 0 };
    int32_t connectType = CONNECT_HML;
    int32_t ret = TransTdcGetIpAndConnectTypeById(channelId, NULL, remoteIp, IP_LEN, &connectType);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransTdcGetIpAndConnectTypeById(channelId, localIp, NULL, IP_LEN, &connectType);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransTdcGetIpAndConnectTypeById(channelId, localIp, remoteIp, IP_LEN - 1, &connectType);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransTdcGetIpAndConnectTypeById(channelId, localIp, remoteIp, IP_LEN, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: TransTdcGetIpAndConnectTypeById
 * @tc.desc: test TransTdcGetIpAndConnectTypeById002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectSessionConnTest, TransTdcGetIpAndConnectTypeById002, TestSize.Level1)
{
    int32_t channelId = 1;
    char localIp[IP_LEN] = { 0 };
    char remoteIp[IP_LEN] = { 0 };
    int32_t connectType = CONNECT_HML;
    (void)memcpy_s(localIp, IP_LEN, g_myIp, strlen(g_myIp));
    (void)memcpy_s(remoteIp, IP_LEN, g_peerIp, strlen(g_peerIp));
    int32_t ret = TransTdcGetIpAndConnectTypeById(channelId, localIp, remoteIp, IP_LEN, &connectType);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);

    ret = CreateTcpChannelInfoList();
    EXPECT_EQ(ret, SOFTBUS_OK);

    TcpChannelInfo *info = (TcpChannelInfo *)SoftBusCalloc(sizeof(TcpChannelInfo));
    ASSERT_TRUE(info != nullptr);
    info->channelId = 1;
    info->businessType = BUSINESS_TYPE_BYTE;
    info->connectType = CONNECT_HML;
    (void)memcpy_s(info->myIp, IP_LEN, g_myIp, strlen(g_myIp));
    (void)memcpy_s(info->peerIp, IP_LEN, g_peerIp, strlen(g_peerIp));
    ret = TransAddTcpChannelInfo(info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ASSERT_FALSE(IsTdcRecoveryTransLimit());
    ret = TransTdcGetIpAndConnectTypeById(channelId, localIp, remoteIp, IP_LEN, &connectType);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransDelTcpChannelInfoByChannelId(info->channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SetSessionConnStatusById
 * @tc.desc: test SetSessionConnStatusById001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectSessionConnTest, SetSessionConnStatusById001, TestSize.Level1)
{
    int32_t channelId = 1;
    uint32_t status = TCP_DIRECT_CHANNEL_STATUS_CONNECTED;
    int32_t ret = SetSessionConnStatusById(channelId, status);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);

    ret = CreatSessionConnList();
    EXPECT_EQ(ret, SOFTBUS_OK);

    SessionConn *conn = TestSetSessionConn();
    ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = SetSessionConnStatusById(channelId, status);
    EXPECT_EQ(ret, SOFTBUS_OK);

    channelId = 0;
    ret = SetSessionConnStatusById(channelId, status);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    TransDelSessionConnById(conn->channelId);
}

/**
 * @tc.name: IsTdcRecoveryTransLimit
 * @tc.desc: test IsTdcRecoveryTransLimit001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectSessionConnTest, IsTdcRecoveryTransLimit001, TestSize.Level1)
{
    bool res = IsTdcRecoveryTransLimit();
    EXPECT_EQ(res, true);

    int32_t ret = CreateTcpChannelInfoList();
    EXPECT_EQ(ret, SOFTBUS_OK);
    res = IsTdcRecoveryTransLimit();
    EXPECT_EQ(res, true);

    TcpChannelInfo *info = (TcpChannelInfo *)SoftBusCalloc(sizeof(TcpChannelInfo));
    ASSERT_TRUE(info != nullptr);
    info->channelId = 1;
    info->businessType = BUSINESS_TYPE_BYTE;
    ret = TransAddTcpChannelInfo(info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    res = IsTdcRecoveryTransLimit();
    EXPECT_EQ(res, false);
    ret = TransDelTcpChannelInfoByChannelId(info->channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: GetChannelIdsByAuthIdAndStatus
 * @tc.desc: test GetChannelIdsByAuthIdAndStatus001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectSessionConnTest, GetChannelIdsByAuthIdAndStatus001, TestSize.Level1)
{
    int32_t count = 0;
    AuthHandle authHandle = {
        .type = 1,
        .authId = 1,
    };
    int32_t *channelId = GetChannelIdsByAuthIdAndStatus(NULL, &authHandle, TCP_DIRECT_CHANNEL_STATUS_VERIFY_P2P);
    EXPECT_EQ(channelId, nullptr);

    channelId = GetChannelIdsByAuthIdAndStatus(&count, NULL, TCP_DIRECT_CHANNEL_STATUS_VERIFY_P2P);
    EXPECT_EQ(channelId, nullptr);

    int32_t ret = CreatSessionConnList();
    EXPECT_EQ(ret, SOFTBUS_OK);

    SessionConn *conn = TestSetSessionConn();
    conn->status = TCP_DIRECT_CHANNEL_STATUS_AUTH_CHANNEL;
    conn->authHandle.type = 1;
    ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);
    channelId = GetChannelIdsByAuthIdAndStatus(&count, &authHandle, TCP_DIRECT_CHANNEL_STATUS_AUTH_CHANNEL);
    EXPECT_NE(channelId, nullptr);
    TransDelSessionConnById(conn->channelId);
}

/**
 * @tc.name: TransGetPidByChanId
 * @tc.desc: test TransGetPidByChanId001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectSessionConnTest, TransGetPidByChanId001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t channelType = 0;
    int32_t pid = 0;
    int32_t ret = TransGetPidByChanId(channelId, channelType, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransGetPidByChanId(channelId, channelType, &pid);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_CHANNEL_ID);

    ret = CreateTcpChannelInfoList();
    EXPECT_EQ(ret, SOFTBUS_OK);
    TcpChannelInfo *info = (TcpChannelInfo *)SoftBusCalloc(sizeof(TcpChannelInfo));
    ASSERT_TRUE(info != nullptr);
    info->channelId = 1;
    info->businessType = BUSINESS_TYPE_BYTE;
    info->channelType = 0;
    info->pid = PID;
    ret = TransAddTcpChannelInfo(info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransGetPidByChanId(channelId, channelType, &pid);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransDelTcpChannelInfoByChannelId(info->channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransGetPidByChanId
 * @tc.desc: test TransGetPidByChanId002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectSessionConnTest, TransGetPidByChanId002, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t channelType = 0;
    int32_t pid = 0;
    int32_t ret = CreateTcpChannelInfoList();
    EXPECT_EQ(ret, SOFTBUS_OK);
    TcpChannelInfo *info = (TcpChannelInfo *)SoftBusCalloc(sizeof(TcpChannelInfo));
    ASSERT_TRUE(info != nullptr);
    info->channelId = 2;
    info->businessType = BUSINESS_TYPE_BYTE;
    info->channelType = 0;
    info->pid = PID;
    ret = TransAddTcpChannelInfo(info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransGetPidByChanId(channelId, channelType, &pid);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_CHANNEL_ID);
    ret = TransDelTcpChannelInfoByChannelId(info->channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransGetPidByChanId
 * @tc.desc: test TransGetPidByChanId003
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectSessionConnTest, TransGetPidByChanId003, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t channelType = 0;
    int32_t pid = 0;
    int32_t ret = CreateTcpChannelInfoList();
    EXPECT_EQ(ret, SOFTBUS_OK);
    TcpChannelInfo *info = (TcpChannelInfo *)SoftBusCalloc(sizeof(TcpChannelInfo));
    ASSERT_TRUE(info != nullptr);
    info->channelId = 1;
    info->businessType = BUSINESS_TYPE_BYTE;
    info->channelType = 1;
    info->pid = PID;
    ret = TransAddTcpChannelInfo(info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransGetPidByChanId(channelId, channelType, &pid);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_CHANNEL_ID);
    ret = TransDelTcpChannelInfoByChannelId(info->channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransGetPkgNameByChanId
 * @tc.desc: test TransGetPkgNameByChanId001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectSessionConnTest, TransGetPkgNameByChanId001, TestSize.Level1)
{
    int32_t channelId = 2;
    int32_t ret = TransGetPkgNameByChanId(channelId, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    char pkgName[PKG_NAME_SIZE_MAX_LEN] = { 0 };
    ret = CreateTcpChannelInfoList();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransGetPkgNameByChanId(channelId, pkgName);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);

    TcpChannelInfo *info = (TcpChannelInfo *)SoftBusCalloc(sizeof(TcpChannelInfo));
    ASSERT_TRUE(info != nullptr);
    info->channelId = 2;
    (void)memcpy_s(info->pkgName, PKG_NAME_SIZE_MAX_LEN, g_pkgName, (strlen(g_pkgName)+1));
    ret = TransAddTcpChannelInfo(info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransGetPkgNameByChanId(channelId, pkgName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransDelTcpChannelInfoByChannelId(info->channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}


/**
 * @tc.name: TransTdcUpdateReplyCnt
 * @tc.desc: test TransTdcUpdateReplyCnt001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectSessionConnTest, TransTdcUpdateReplyCnt001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = CreatSessionConnList();
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionConn *conn = TestSetSessionConn();
    conn->status = TCP_DIRECT_CHANNEL_STATUS_AUTH_CHANNEL;
    conn->authHandle.type = 1;
    ret = TransTdcUpdateReplyCnt(channelId);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/**
 * @tc.name: TransTdcUpdateReplyCnt
 * @tc.desc: test TransTdcUpdateReplyCnt002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectSessionConnTest, TransTdcUpdateReplyCnt002, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = CreatSessionConnList();
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionConn *conn = TestSetSessionConn();
    conn->status = TCP_DIRECT_CHANNEL_STATUS_AUTH_CHANNEL;
    conn->authHandle.type = 1;
    ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransTdcUpdateReplyCnt(channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransDelSessionConnById(conn->channelId);
}

/**
 * @tc.name: TransTdcResetReplyCnt
 * @tc.desc: test TransTdcResetReplyCnt001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectSessionConnTest, TransTdcResetReplyCnt001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = CreatSessionConnList();
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionConn *conn = TestSetSessionConn();
    conn->status = TCP_DIRECT_CHANNEL_STATUS_AUTH_CHANNEL;
    conn->authHandle.type = 1;
    ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransTdcResetReplyCnt(channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransDelSessionConnById(conn->channelId);
}

/**
 * @tc.name: TransTdcResetReplyCnt
 * @tc.desc: test TransTdcResetReplyCnt002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectSessionConnTest, TransTdcResetReplyCnt002, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = CreatSessionConnList();
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionConn *conn = TestSetSessionConn();
    conn->status = TCP_DIRECT_CHANNEL_STATUS_AUTH_CHANNEL;
    conn->authHandle.type = 1;
    ret = TransTdcResetReplyCnt(channelId);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/**
 * @tc.name: TransTcpGetPrivilegeCloseList
 * @tc.desc: test TransTcpGetPrivilegeCloseList001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectSessionConnTest, TransTcpGetPrivilegeCloseList001, TestSize.Level1)
{
    TcpChannelInfo *info = (TcpChannelInfo *)SoftBusCalloc(sizeof(TcpChannelInfo));
    ASSERT_TRUE(info != nullptr);
    info->channelId = 1;
    info->businessType = BUSINESS_TYPE_BYTE;
    info->pid = 1;
    info->callingTokenId = 1;
    int32_t ret = TransAddTcpChannelInfo(info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    uint64_t tokenId = 1;
    int32_t pid = 1;
    ListNode privilegeCloseList;
    ListInit(&privilegeCloseList);
    ret = TransTcpGetPrivilegeCloseList(&privilegeCloseList, tokenId, pid);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransDelTcpChannelInfoByChannelId(info->channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransTcpGetPrivilegeCloseList
 * @tc.desc: test TransTcpGetPrivilegeCloseList002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectSessionConnTest, TransTcpGetPrivilegeCloseList002, TestSize.Level1)
{
    uint64_t tokenId = 1;
    int32_t pid = 1;
    ListNode privilegeCloseList;
    ListInit(&privilegeCloseList);
    int32_t ret = TransTcpGetPrivilegeCloseList(&privilegeCloseList, tokenId, pid);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransGetTdcChannelByIdTest
 * @tc.desc: test TransGetTdcChannelById in different case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_P(TransGetTdcChannelByIdTest, TransGetTdcChannelByIdTest, TestSize.Level1)
{
    TransGetTdcChannelByIdTestParam testParam = GetParam();
    int32_t ret = SOFTBUS_OK;
    TcpChannelInfo *tcpInfoNode = NULL;
    if (!testParam.listInited) {
        goto PROCESS;
    }

    ret = CreateTcpChannelInfoList();
    EXPECT_EQ(SOFTBUS_OK, ret);

    if (testParam.testChannelInfo == nullptr) {
        goto PROCESS;
    }
    tcpInfoNode = new TcpChannelInfo(); // release in TransDelTcpChannelInfoByChannelId
    (void)memcpy_s(tcpInfoNode, sizeof(TcpChannelInfo), testParam.testChannelInfo, sizeof(TcpChannelInfo));
    ret = TransAddTcpChannelInfo(tcpInfoNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

PROCESS:
    ret = TransGetTdcChannelById(testParam.channelId, testParam.channel);
    EXPECT_EQ(testParam.res, ret);
    if (testParam.listInited) {
        if (testParam.channel != nullptr) {
            EXPECT_EQ(testParam.channel->pid, testParam.channelRes.pid);
        }
        if (tcpInfoNode != nullptr) {
            ret = TransDelTcpChannelInfoByChannelId(tcpInfoNode->channelId);
            EXPECT_EQ(SOFTBUS_OK, ret);
        }
    }
}

INSTANTIATE_TEST_SUITE_P(TransGetTdcChannelByIdTest, TransGetTdcChannelByIdTest, testing::Values(
    // @tc.desc: test TransGetTdcChannelByIdTest ok.
    TransGetTdcChannelByIdTestParam {TEST_CHANNEL_ID, &g_testTcpChannelInfo, true,
        &g_testTcpChannelInfoRes, SOFTBUS_OK, g_testTcpChannelInfoRes},
    // @tc.desc: test TransGetTdcChannelByIdTest invalid param.
    TransGetTdcChannelByIdTestParam {TEST_CHANNEL_ID, nullptr, true,
        &g_testTcpChannelInfoRes, SOFTBUS_INVALID_PARAM, g_testNullTcpChannelInfo},
    // @tc.desc: test TransGetTdcChannelByIdTest channelId not found.
    TransGetTdcChannelByIdTestParam {-1, &g_testTcpChannelInfo, true,
        &g_testTcpChannelInfoRes, SOFTBUS_NOT_FIND, g_testNullTcpChannelInfo},
    // @tc.desc: test TransGetTdcChannelByIdTest node not register.
    TransGetTdcChannelByIdTestParam {TEST_CHANNEL_ID, &g_testTcpChannelInfo, true,
        nullptr, SOFTBUS_NOT_FIND, g_testNullTcpChannelInfo}
));

/**
 * @tc.name: TransTdcGetWakeUpInfoTest
 * @tc.desc: test TransGetTdcChannelById in different case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_P(TransTdcGetWakeUpInfoTest, TransTdcGetWakeUpInfoTest, TestSize.Level1)
{
    TransTdcGetWakeUpInfoTestParam testParam = GetParam();
    int32_t ret = SOFTBUS_OK;
    TcpChannelInfo *tcpInfoNode = NULL;
    ret = CreateTcpChannelInfoList();
    EXPECT_EQ(SOFTBUS_OK, ret);
    tcpInfoNode = new TcpChannelInfo(); // release in TransDelTcpChannelInfoByChannelId
    (void)memcpy_s(tcpInfoNode, sizeof(TcpChannelInfo), testParam.channelInfoMockRes, sizeof(TcpChannelInfo));
    ret = TransAddTcpChannelInfo(tcpInfoNode);
    EXPECT_EQ(SOFTBUS_OK, ret);
    testing::NiceMock<TransTcpDirectSessionConnMock> sessionconnMock;
    if (testParam.uuid != nullptr && testParam.channelId == TEST_CHANNEL_ID) {
        EXPECT_CALL(sessionconnMock, LnnGetRemoteStrInfo(testing::_, testing::_, testParam.uuid, testParam.uuidLen))
            .WillOnce(testing::Return(testParam.lnnGetRemoteStrInfoMockRes));
    }

    ret = TransTdcGetWakeUpInfo(testParam.channelId, testParam.uuid, testParam.uuidLen, testParam.needFastWakeUp);
    EXPECT_EQ(testParam.res, ret);
    if (testParam.needFastWakeUp != nullptr) {
        EXPECT_EQ(tcpInfoNode->needFastWakeUp, *testParam.needFastWakeUp);
    }
    if (tcpInfoNode != nullptr) {
        ret = TransDelTcpChannelInfoByChannelId(tcpInfoNode->channelId);
        EXPECT_EQ(SOFTBUS_OK, ret);
    }
}

INSTANTIATE_TEST_SUITE_P(TransTdcGetWakeUpInfoTest, TransTdcGetWakeUpInfoTest, testing::Values(
    // @tc.desc: test TransTdcGetWakeUpInfoTest ok.
    TransTdcGetWakeUpInfoTestParam {TEST_CHANNEL_ID, g_testUuid, UUID_BUF_LEN, &g_testNeedFastWakeUp,
        SOFTBUS_OK, &g_testTcpChannelInfoRes, SOFTBUS_OK, SOFTBUS_OK},
    // @tc.desc: test TransTdcGetWakeUpInfoTest TransGetTdcChannelById fail.
    TransTdcGetWakeUpInfoTestParam {-1, g_testUuid, UUID_BUF_LEN, &g_testNeedFastWakeUp,
        SOFTBUS_NOT_FIND, &g_testTcpChannelInfoRes, SOFTBUS_OK, SOFTBUS_NOT_FIND},
    // @tc.desc: test TransTdcGetWakeUpInfoTest uuid is null.
    TransTdcGetWakeUpInfoTestParam {TEST_CHANNEL_ID, nullptr, UUID_BUF_LEN, &g_testNeedFastWakeUp,
        SOFTBUS_OK, &g_testTcpChannelInfoRes, SOFTBUS_OK, SOFTBUS_OK},
    // @tc.desc: test TransTdcGetWakeUpInfoTest LnnGetRemoteStrInfo fail.
    TransTdcGetWakeUpInfoTestParam {TEST_CHANNEL_ID, g_testUuid, UUID_BUF_LEN, &g_testNeedFastWakeUp,
        SOFTBUS_OK, &g_testTcpChannelInfoRes, SOFTBUS_INVALID_PARAM, SOFTBUS_INVALID_PARAM}
));

/**
 * @tc.name: TransTdcSetWakeUpInfoTest
 * @tc.desc: test TransSetTdcChannelById in different case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_P(TransTdcSetWakeUpInfoTest, TransTdcSetWakeUpInfoTest, TestSize.Level1)
{
    TransTdcSetWakeUpInfoTestParam testParam = GetParam();
    int32_t ret = SOFTBUS_OK;
    TcpChannelInfo *tcpInfoNode;
    if (!testParam.listInited) {
        goto PROCESS;
    }

    ret = CreateTcpChannelInfoList();
    EXPECT_EQ(SOFTBUS_OK, ret);

    if (testParam.testChannelInfo == nullptr) {
        goto PROCESS;
    }

    tcpInfoNode = new TcpChannelInfo();
    memcpy_s(tcpInfoNode, sizeof(TcpChannelInfo), testParam.testChannelInfo, sizeof(TcpChannelInfo));
    ret = TransAddTcpChannelInfo(tcpInfoNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

PROCESS:
    ret = TransTdcSetWakeUpInfo(testParam.channelId, testParam.needFastWakeUp);
    EXPECT_EQ(testParam.res, ret);
    if (testParam.listInited) {
        if (testParam.testChannelInfo != nullptr) {
            EXPECT_EQ(testParam.needFastWakeUp, tcpInfoNode->needFastWakeUp);
            ret = TransDelTcpChannelInfoByChannelId(testParam.testChannelInfo->channelId);
            EXPECT_EQ(SOFTBUS_OK, ret);
        }
    }
}

INSTANTIATE_TEST_SUITE_P(TransTdcSetWakeUpInfoTest, TransTdcSetWakeUpInfoTest, testing::Values(
    // @tc.desc: test TransTdcSetWakeUpInfoTest true ok.
    TransTdcSetWakeUpInfoTestParam {TEST_CHANNEL_ID, true, true, &g_testTcpChannelInfoRes, SOFTBUS_OK},
    // @tc.desc: test TransTdcSetWakeUpInfoTest false ok.
    TransTdcSetWakeUpInfoTestParam {TEST_CHANNEL_ID, false, true, &g_testTcpChannelInfoRes, SOFTBUS_OK},
    // @tc.desc: test TransTdcSetWakeUpInfoTest node not found.
    TransTdcSetWakeUpInfoTestParam {TEST_CHANNEL_ID, true, false, nullptr, SOFTBUS_TRANS_INVALID_CHANNEL_ID}
));
}