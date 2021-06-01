/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>

#include "common_list.h"
#include "softbus_conn_interface.h"
#include "softbus_conn_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

static const int CONN_HEAD_SIZE = 24;
static const int SHIFT_BITS = 16;

static ConnectCallback *g_mangerCb = 0;
static ConnectionInfo g_connInfo = {0};
static unsigned int g_connId = 0;

using namespace testing::ext;

namespace OHOS {
unsigned int ObjectGetConnectionId(unsigned int type)
{
    unsigned int ret = type << SHIFT_BITS;
    ret++;
    return ret;
}

int ObjectConnectDevice(const ConnectOption *option, unsigned int requestId, const ConnectResult *result)
{
    ConnectionInfo info = {0};
    if (option == 0 || result == 0) {
        return 1;
    }
    g_connInfo.isAvailable = 1;
    g_connInfo.type = option->type;
    result->OnConnectSuccessed(requestId, ObjectGetConnectionId(option->type), &info);
    return 0;
}

int ObjectPostBytes(unsigned int connectionId, const char *data, int len, int pid, int flag)
{
    int module;
    int bufLen = 15;
    const char *str = "reply wdf";
    ConnPktHead *head = nullptr;
    if (data == nullptr) {
        return 1;
    }
    head = (ConnPktHead *)data;
    module = head->module;

    char *buf = (char *)calloc(1, CONN_HEAD_SIZE + bufLen);
    if (buf == nullptr) {
        return -1;
    }
    (void)strcpy_s(buf + CONN_HEAD_SIZE, strlen(str), str);
    if (g_mangerCb) {
        g_mangerCb->OnDataReceived(connectionId, static_cast<ConnModule>(module),
            1, buf, CONN_HEAD_SIZE + bufLen);
    }
    free(buf);
    return 0;
}

int ObjectDisconnectDevice(unsigned int connectionId)
{
    (void)connectionId;
    return 0;
}

int ObjectGetConnectionInfo(unsigned int connectionId, ConnectionInfo *info)
{
    (void)connectionId;
    if (info == nullptr) {
        return -1;
    }
    (void)memcpy_s(info, sizeof(ConnectionInfo), &g_connInfo, sizeof(ConnectionInfo));
    return 0;
}

int ObjectStartLocalListening(const LocalListenerInfo *info)
{
    if (info == nullptr) {
        return 1;
    }
    if (g_mangerCb) {
        g_mangerCb->OnConnected(ObjectGetConnectionId(info->type), &g_connInfo);
    }
    return 0;
}

int ObjectStopLocalListening(const LocalListenerInfo *info)
{
    if (info == nullptr) {
        return 1;
    }
    if (g_mangerCb) {
        g_mangerCb->OnDisconnected(ObjectGetConnectionId(info->type), &g_connInfo);
    }
    return 0;
}

ConnectFuncInterface *ConnInitObject(const ConnectCallback *callback)
{
    if (callback == 0) {
        return nullptr;
    }
    ConnectFuncInterface *inter = (ConnectFuncInterface*)calloc(1, sizeof(ConnectFuncInterface));
    if (inter == nullptr) {
        return nullptr;
    }
    g_mangerCb = (ConnectCallback*)callback;

    inter->ConnectDevice = ObjectConnectDevice;
    inter->PostBytes = ObjectPostBytes;
    inter->DisconnectDevice = ObjectDisconnectDevice;
    inter->GetConnectionInfo = ObjectGetConnectionInfo;
    inter->StartLocalListening = ObjectStartLocalListening;
    inter->StopLocalListening = ObjectStopLocalListening;
    return inter;
}

extern "C" ConnectFuncInterface *ConnInitBr(const ConnectCallback *callback)
{
    return ConnInitObject(callback);
}

extern "C" ConnectFuncInterface *ConnInitTcp(const ConnectCallback *callback)
{
    return ConnInitObject(callback);
}

void ConnectedCB(unsigned int connectionId, const ConnectionInfo *info)
{
    printf("recv remote ConnectedCB %u\r\n", connectionId);
    g_connId = connectionId;
    return;
}

void DisConnectCB(unsigned int connectionId, const ConnectionInfo *info)
{
    printf("DconDisConnect %u\r\n", connectionId);
    return;
}

void DataReceivedCB(unsigned int connectionId, ConnModule moduleId, int64_t seq, char *data, int len)
{
    printf("DconDataReceived moduleId %d %s %d\r\n", moduleId, data, len);
    return;
}

void ConnectSuccessedCB(unsigned int requestId, unsigned int connectionId, const ConnectionInfo *info)
{
    printf("ConnectSuccessedCB %u\r\n", connectionId);
    g_connId = connectionId;
    return;
}

void ConnectFailedCB(unsigned int requestId, int reason)
{
    (void)requestId;
    (void)reason;
    printf("DconConnectFailed\r\n");
    return;
}

class SoftbusConnmangerFuncTest : public testing::Test {
public:
    SoftbusConnmangerFuncTest()
    {}
    ~SoftbusConnmangerFuncTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void SoftbusConnmangerFuncTest::SetUpTestCase(void)
{
    ConnServerInit();
}

void SoftbusConnmangerFuncTest::TearDownTestCase(void)
{}

void SoftbusConnmangerFuncTest::SetUp(void)
{}

void SoftbusConnmangerFuncTest::TearDown(void)
{}

/*
* @tc.name: testConnmanger001
* @tc.desc: test ConnTypeIsSupport
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusConnmangerFuncTest, testConnmanger001, TestSize.Level1)
{
    int ret;
    printf("testConnmanger001\r\n");

    ret = ConnTypeIsSupport(CONNECT_TCP);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ConnTypeIsSupport(CONNECT_BR);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ConnTypeIsSupport(CONNECT_BLE);
    EXPECT_EQ(SOFTBUS_ERR, ret);
};

/*
* @tc.name: testConnmanger002
* @tc.desc: test invalid param
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusConnmangerFuncTest, testConnmanger002, TestSize.Level1)
{
    printf("test begin testConnmanger002 \r\n");
    ConnSetConnectCallback(static_cast<ConnModule>(0), nullptr);
    ConnConnectDevice(nullptr, 0, nullptr);
    ConnPostBytes(0, nullptr);
    ConnStartLocalListening(nullptr);
    ConnStopLocalListening(nullptr);
    EXPECT_EQ(SOFTBUS_OK, SOFTBUS_OK);
};

/*
* @tc.name: testConnmanger003
* @tc.desc: test set unset callback and connect post disconnect
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusConnmangerFuncTest, testConnmanger003, TestSize.Level1)
{
    int ret;
    int reqId;
    ConnectCallback connCb;
    ConnectResult connRet;
    ConnPostData data;
    ConnectOption info;
    const char *str = "send msg local2\r\n";
    printf("test begin testConnmanger003 \r\n");

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ConnSetConnectCallback(MODULE_AUTH_SDK, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    info.type = CONNECT_BR;
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;
    reqId = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&info, reqId, &connRet);
    EXPECT_EQ(SOFTBUS_OK, ret);
    if (g_connId) {
        data.buf = (char *)calloc(1, CONN_HEAD_SIZE + 20);
        ASSERT_TRUE(data.buf != NULL);
        (void)strcpy_s(data.buf + 1, strlen(str), str);
        data.len = CONN_HEAD_SIZE + 20;
        data.module = MODULE_TRUST_ENGINE;
        data.pid = 0;
        ret = ConnPostBytes(g_connId, &data);
        EXPECT_EQ(SOFTBUS_OK, ret);
        if (data.buf != nullptr) {
            free(data.buf);
        }
    }
    ret = ConnDisconnectDevice(g_connId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
    ConnUnSetConnectCallback(MODULE_AUTH_SDK);
    g_connId = 0;
};

/*
* @tc.name: testConnmanger004
* @tc.desc: test set unset callback and post disconnect without connect
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusConnmangerFuncTest, testConnmanger004, TestSize.Level1)
{
    printf("test begin ConnManagerTest004 \r\n");
    int ret;
    ConnectCallback connCb;
    LocalListenerInfo info;
    ConnPostData data;
    const char *str = "send msg local2\r\n";

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.type = CONNECT_BR;
    ret = ConnStartLocalListening(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    if (g_connId) {
        data.buf = (char*)calloc(1, CONN_HEAD_SIZE + 20);
        (void)strcpy_s(data.buf + CONN_HEAD_SIZE, strlen(str), str);
        ASSERT_TRUE(data.buf != NULL);
        data.len = CONN_HEAD_SIZE + 20;
        data.module = MODULE_TRUST_ENGINE;
        data.pid = 0;
        ret = ConnPostBytes(g_connId, &data);
        EXPECT_EQ(SOFTBUS_OK, ret);
        ret = ConnDisconnectDevice(g_connId);
        EXPECT_EQ(SOFTBUS_OK, ret);
        if (data.buf != nullptr) {
            free(data.buf);
        }
    }

    ret = ConnStopLocalListening(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
    g_connId = 0;
};

/*
* @tc.name: testConnmanger005
* @tc.desc: test set unset callback multi times
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusConnmangerFuncTest, testConnmanger005, TestSize.Level1)
{
    int ret;
    ConnectCallback connCb;

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ConnSetConnectCallback(MODULE_AUTH_SDK, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ConnSetConnectCallback(MODULE_AUTH_SDK, &connCb);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
    ConnUnSetConnectCallback(MODULE_AUTH_SDK);
};

/*
* @tc.name: testConnmanger006
* @tc.desc: test set unset callback and connect post disconnect
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusConnmangerFuncTest, testConnmanger006, TestSize.Level1)
{
    int reqId = 1;
    int ret;
    ConnectCallback connCb;
    ConnectOption optionInfo;
    ConnectionInfo info;
    ConnectResult connRet;

    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectCB;
    connCb.OnDataReceived = DataReceivedCB;
    ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(SOFTBUS_OK, ret);

    optionInfo.type = CONNECT_BR;
    connRet.OnConnectFailed = ConnectFailedCB;
    connRet.OnConnectSuccessed = ConnectSuccessedCB;
    reqId = ConnGetNewRequestId(MODULE_TRUST_ENGINE);
    ret = ConnConnectDevice(&optionInfo, reqId, &connRet);
    EXPECT_EQ(SOFTBUS_OK, ret);
    if (g_connId) {
        ret = ConnGetConnectionInfo(g_connId, &info);
        EXPECT_EQ(SOFTBUS_OK, ret);
        ret = ConnDisconnectDevice(g_connId);
        g_connId = 0;
        EXPECT_EQ(SOFTBUS_OK, ret);
        printf("testConnmanger006 ConnDisconnectDevice\r\n");
    }
    printf("testConnmanger006 ConnUnSetConnectCallback\r\n");
    ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
    printf("testConnmanger006 ConnUnSetConnectCallback end 11\r\n");
};
}