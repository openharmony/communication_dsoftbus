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

#include <gtest/gtest.h>

#include "general_connection_mock.h"
#include "softbus_conn_general_connection.h"
#include "softbus_conn_ipc.h"
#include "softbus_feature_config.h"
#include "softbus_adapter_mem.h"

using namespace testing::ext;
using namespace testing;
using namespace std;

#define GENERAL_PKGNAME_MAX_COUNT          (10)

static ConnectCallback *g_ConnectCallback = nullptr;
static uint32_t g_handle = 0;
static uint32_t g_ConnectionId = 0;

static uint32_t  g_isServerGeneralId = 0;

static bool g_connectCallbackFlag = false;
static int32_t g_failCallbackFlag = false;
static bool g_isRecvNewConnection = false;
static bool g_recvDataFlag = false;

namespace OHOS {
class GeneralConnectionTest : public testing::Test {
public:
    GeneralConnectionTest() { }
    ~GeneralConnectionTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void GeneralConnectionTest::SetUpTestCase(void) { }

void GeneralConnectionTest::TearDownTestCase(void) { }

void GeneralConnectionTest::SetUp(void) { }

void GeneralConnectionTest::TearDown(void) { }

static OutData *PackReceiveData(const uint8_t *data, uint32_t dataLen, uint32_t localId, uint32_t peerId)
{
    uint32_t tmpLen = GENERAL_CONNECTION_HEADER_SIZE + dataLen;
    GeneralConnectionHead *dataTmp = (GeneralConnectionHead *)SoftBusCalloc(tmpLen);
    if (dataTmp == nullptr) {
        return nullptr;
    }
    dataTmp->headLen = GENERAL_CONNECTION_HEADER_SIZE;
    dataTmp->localId = localId;
    dataTmp->peerId = peerId;
    dataTmp->msgType = GENERAL_CONNECTION_MSG_TYPE_NORMAL;

    if (memcpy_s((uint8_t *)dataTmp + GENERAL_CONNECTION_HEADER_SIZE, dataLen, data, dataLen) != EOK) {
        SoftBusFree(dataTmp);
        return nullptr;
    }

    uint32_t connectHeadLen = ConnGetHeadSize();
    uint32_t totalLen = tmpLen + connectHeadLen;
    OutData *outData = (OutData *)SoftBusCalloc(sizeof(OutData));
    if (outData == nullptr) {
        SoftBusFree(dataTmp);
        return nullptr;
    }
    outData->dataLen = totalLen;
    outData->data = (uint8_t *)SoftBusCalloc(totalLen);
    if (outData->data == nullptr) {
        SoftBusFree(dataTmp);
        SoftBusFree(outData);
        return nullptr;
    }

    int32_t ret = memcpy_s(outData->data + connectHeadLen, tmpLen, dataTmp, tmpLen);
    if (ret != EOK) {
        FreeOutData(outData);
        SoftBusFree(dataTmp);
        return nullptr;
    }
    SoftBusFree(dataTmp);
    return outData;
}

static ConnPostData *PackInnerMsg(GeneralConnectionInfo *info, GeneralConnectionMsgType msgType, int32_t module)
{
    OutData *data = GeneralConnectionPackMsg(info, msgType);
    EXPECT_NE(data, nullptr);

    uint32_t size = ConnGetHeadSize();

    static ConnPostData buff = {0};
    buff.seq = 0;
    buff.flag = CONN_HIGH;
    buff.pid = 0;

    buff.len = data->dataLen + size;
    buff.buf = (char *)SoftBusCalloc(buff.len);
    buff.module = module;

    if (buff.buf == NULL || memcpy_s(buff.buf + size, data->dataLen, data->data, data->dataLen) != EOK) {
        SoftBusFree(buff.buf);
        FreeOutData(data);
        return nullptr;
    }
    FreeOutData(data);
    return &buff;
}

static bool GetConnectCallbackFlag()
{
    if (g_connectCallbackFlag == true) {
        g_connectCallbackFlag = false;
        return true;
    }
    return false;
}

static int32_t GetFailCallbackReason()
{
    if (g_failCallbackFlag < 0) {
        int32_t reason = g_failCallbackFlag;
        g_failCallbackFlag = SOFTBUS_OK;
        return reason;
    }
    return SOFTBUS_OK;
}

static bool GetRecvDataFlag()
{
    if (g_recvDataFlag == true) {
        g_recvDataFlag = false;
        return true;
    }
    return false;
}

static void ConnectSuccess(GeneralConnectionParam *info, uint32_t generalHandle)
{
    (void)info;
    (void)generalHandle;
    g_connectCallbackFlag = true;
}

static void ConnectFailed(GeneralConnectionParam *info, uint32_t generalHandle, int32_t reason)
{
    (void)info;
    (void)generalHandle;
    (void)reason;
    g_failCallbackFlag = reason;
}

static void AcceptConnect(GeneralConnectionParam *info, uint32_t generalHandle)
{
    (void)info;
    (void)generalHandle;
    g_isRecvNewConnection = true;
    g_isServerGeneralId = generalHandle;
}

static void DataReceived(GeneralConnectionParam *info, uint32_t generalHandle, const uint8_t *data, uint32_t dataLen)
{
    (void)info;
    (void)generalHandle;
    (void)data;
    (void)dataLen;
    g_recvDataFlag = true;
}

static void ConnectionDisconnected(GeneralConnectionParam *info, uint32_t generalHandle, int32_t reason)
{
    (void)info;
    (void)generalHandle;
    (void)reason;
}

const uint8_t *g_baseFuzzData = nullptr;
size_t g_baseFuzzSize = 0;
size_t g_baseFuzzPos;
template <class T>
T GetConnGeneralRandomData()
{
    T objetct {};
    size_t objetctSize = sizeof(objetct);
    if (g_baseFuzzData == nullptr || objetctSize > g_baseFuzzSize - g_baseFuzzPos) {
        COMM_LOGE(COMM_TEST, "data invalid");
        return objetct;
    }
    errno_t ret = memcpy_s(&objetct, objetctSize, g_baseFuzzData + g_baseFuzzPos, objetctSize);
    if (ret != EOK) {
        COMM_LOGE(COMM_TEST, "memory copy error");
        return {};
    }
    g_baseFuzzPos += objetctSize;
    return objetct;
}

/*
* @tc.name: TestInit
* @tc.desc: test init general connection
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(GeneralConnectionTest, TestInit, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test init start");
    const char *pkgName = "testName";
    ClearGeneralConnection(pkgName, 0);
    int32_t ret = InitGeneralConnection();
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);

    ret = InitGeneralConnection();
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ConnUnSetConnectCallback(MODULE_BLE_GENERAL);

    LooperInit();
    SoftbusConfigInit();
    ret = ConnServerInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ClearGeneralConnection(pkgName, 0);
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    EXPECT_NE(manager, nullptr);
    GeneralConnectionParam param = {0};
    manager->closeServer(&param);
    g_ConnectCallback = GeneralConnectionInterfaceMock::GetConnectCallbackMock();
    ASSERT_NE(g_ConnectCallback, nullptr);
    CONN_LOGI(CONN_BLE, "test init end");
}

/*
* @tc.name: TestRegisterListener
* @tc.desc: test register listener
* @tc.type: FUNC
* @tc.require:AR000GIRGE
*/
HWTEST_F(GeneralConnectionTest, TestRegisterListener, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test register listener start");

    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    EXPECT_NE(manager, nullptr);

    GeneralConnectionListener listener = {
        .onConnectSuccess = ConnectSuccess,
        .onConnectFailed = ConnectFailed,
        .onAcceptConnect = AcceptConnect,
        .onDataReceived = DataReceived,
        .onConnectionDisconnected = ConnectionDisconnected,
    };

    int32_t ret = manager->registerListener(&listener);
    EXPECT_EQ(ret, SOFTBUS_OK);

    CONN_LOGI(CONN_BLE, "test register listener end");
}

/*
* @tc.name: TestCreateServerMax
* @tc.desc: test create server include max count(10) and normal case
* @tc.type: FUNC
* @tc.require:AR000GIRGE
*/
HWTEST_F(GeneralConnectionTest, TestCreateServer, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test createServer start");
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    EXPECT_NE(manager, nullptr);
    GeneralConnectionParam param = {0};

    const char *name = "test";
    int32_t ret = strcpy_s(param.name, GENERAL_NAME_LEN, "test");
    EXPECT_EQ(ret, EOK);
    const char *pkgName = "testPkgName";
    ret = strcpy_s(param.pkgName, PKG_NAME_SIZE_MAX, pkgName);
    EXPECT_EQ(ret, EOK);

    ret = strcpy_s(param.bundleName, BUNDLE_NAME_MAX, "testBundleName");
    EXPECT_EQ(ret, EOK);

    ret = manager->createServer(&param);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = manager->createServer(&param);
    EXPECT_EQ(ret, SOFTBUS_CONN_GENERAL_DUPLICATE_SERVER);
    for (uint32_t i = 0; i < GENERAL_PKGNAME_MAX_COUNT; ++i) {
        string nameTemp = name + to_string(i);
        ret = strcpy_s(param.name, GENERAL_NAME_LEN, nameTemp.c_str());
        EXPECT_EQ(ret, EOK);
        ret = manager->createServer(&param);
        int32_t expectedRet = (i == GENERAL_PKGNAME_MAX_COUNT - 1) ?
            SOFTBUS_CONN_GENERAL_CREATE_SERVER_MAX : SOFTBUS_OK;
        EXPECT_EQ(ret, expectedRet);
    }

    manager->closeServer(&param);
    ret = strcpy_s(param.name, GENERAL_NAME_LEN, "test9");
    EXPECT_EQ(ret, EOK);
    manager->closeServer(&param);

    ret = strcpy_s(param.name, GENERAL_NAME_LEN, "test8");
    EXPECT_EQ(ret, EOK);
    ret = strcpy_s(param.bundleName, GENERAL_NAME_LEN, "testBundleName0");
    EXPECT_EQ(ret, EOK);
    manager->closeServer(&param);
    CONN_LOGI(CONN_BLE, "test createServer end");
}

/*
* @tc.name: TestConnect
* @tc.desc: test connect include to max count(10) and normal case
* @tc.type: FUNC
* @tc.require:AR000GIRGE
*/
HWTEST_F(GeneralConnectionTest, TestConnect, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test connect start");
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    EXPECT_NE(manager, nullptr);
    GeneralConnectionParam param = {0};

    const char *pkgName = "testPkgName";
    int32_t ret = strcpy_s(param.pkgName, PKG_NAME_SIZE_MAX, pkgName);
    EXPECT_EQ(ret, EOK);
    
    ret = strcpy_s(param.bundleName, BUNDLE_NAME_MAX, "testBundleName");
    EXPECT_EQ(ret, EOK);
    const char *name = "test";
    const char *addr = "11:22:33:44:55:66";
    param.pid = 0;
    GeneralConnectionInterfaceMock mock;
    EXPECT_CALL(mock, BleConnectDeviceMock).WillRepeatedly(Return(SOFTBUS_OK));
    for (uint32_t i = 0; i < GENERAL_PKGNAME_MAX_COUNT; ++i) {
        string nameTemp = name + to_string(i);
        ret = strcpy_s(param.name, GENERAL_NAME_LEN, nameTemp.c_str());
        EXPECT_EQ(ret, EOK);
        ret = manager->connect(&param, addr);
        EXPECT_EQ(ret > 0, true);
    }
    ret = strcpy_s(param.name, GENERAL_NAME_LEN, "test10");
    EXPECT_EQ(ret, EOK);
    ret = manager->connect(&param, addr);
    EXPECT_EQ(ret, SOFTBUS_CONN_GENERAL_CREATE_CLIENT_MAX);
    manager->cleanupGeneralConnection(param.pkgName, param.pid);

    ret = strcpy_s(param.name, GENERAL_NAME_LEN, "test9");
    EXPECT_EQ(ret, EOK);
    EXPECT_CALL(mock, BleConnectDeviceMock).WillRepeatedly(Return(SOFTBUS_STRCPY_ERR));
    ret = manager->connect(&param, addr);
    EXPECT_EQ(ret, SOFTBUS_CONN_GENERAL_CONNECT_FAILED);
    CONN_LOGI(CONN_BLE, "test connect end");
}

/*
* @tc.name: test send
* @tc.desc: test send
* @tc.type: FUNC
* @tc.require:AR000GIRGE
*/
HWTEST_F(GeneralConnectionTest, TestSend, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test send start");
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    ASSERT_NE(manager, nullptr);
    GeneralConnectionParam param = {
        .pkgName = "testPkgName1",
        .bundleName = "testBundleName",
        .name = "test",
    };
    const char *addr = "11:22:33:44:55:66";
    param.pid = 0;
    NiceMock<GeneralConnectionInterfaceMock> mock;
    EXPECT_CALL(mock, BleConnectDeviceMock).WillRepeatedly(Return(SOFTBUS_OK));
    g_handle = manager->connect(&param, addr); // to get handle
    EXPECT_EQ(g_handle > 0, true);
    uint8_t *data = (uint8_t *)SoftBusCalloc(sizeof(uint8_t));
    EXPECT_NE(data, nullptr);
    int32_t ret = manager->send(g_handle, data, 0, 0); // unexpect state
    EXPECT_EQ(ret, SOFTBUS_CONN_GENERAL_CONNECTION_NOT_READY);
    GeneralConnectionInfo info = {{0}};
    info.peerId = g_handle;
    OutData *dataRecv = GeneralConnectionPackMsg(&info, GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE_ACK);
    EXPECT_NE(dataRecv, nullptr);
    uint32_t size = ConnGetHeadSize();
    uint32_t dataLen = dataRecv->dataLen + size;
    char *buff = (char *)SoftBusCalloc(dataLen);
    EXPECT_NE(buff, nullptr);
    ret = memcpy_s(buff + size, dataRecv->dataLen, dataRecv->data, dataRecv->dataLen);
    EXPECT_EQ(ret, EOK);
    g_ConnectCallback->OnDataReceived(0, MODULE_BLE_GENERAL, 0, buff, dataRecv->dataLen);
    g_ConnectCallback->OnDataReceived(0, MODULE_BLE_GENERAL, 0, (char *)dataRecv->data, dataRecv->dataLen);
    g_ConnectionId = (CONNECT_BLE << CONNECT_TYPE_SHIFT);
    ConnectResult *connectResult = GeneralConnectionInterfaceMock::GetConnectResultMock();
    uint32_t requestId = 12;
    ConnectionInfo infos = {0};
    connectResult->OnConnectSuccessed(requestId, g_ConnectionId, &infos); // save connectionId
    g_ConnectCallback->OnDataReceived(g_ConnectionId, MODULE_BLE_GENERAL, 0, buff, dataLen); // state change to success
    EXPECT_EQ(true, GetConnectCallbackFlag());
    uint32_t ConnectionId = (CONNECT_BLE << CONNECT_TYPE_SHIFT) + 1;
    g_ConnectCallback->OnDataReceived(ConnectionId, MODULE_BLE_GENERAL, 0, buff, dataLen); // not target connId

    EXPECT_CALL(mock, ConnBlePostBytesMock).WillRepeatedly(Return(SOFTBUS_OK));
    ret = manager->send(g_handle, data, sizeof(uint8_t), 0);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = manager->send(g_handle, data, sizeof(uint8_t), 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(data);
    SoftBusFree(buff);
    CONN_LOGI(CONN_BLE, "test send end");
}

/*
* @tc.name: test recv
* @tc.desc: test recv normal message
* @tc.type: FUNC
* @tc.require:AR000GIRGE
*/
HWTEST_F(GeneralConnectionTest, TestRecv, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test recv start");
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    EXPECT_NE(manager, nullptr);
    uint8_t *data = (uint8_t *)malloc(sizeof(uint8_t));
    EXPECT_NE(data, nullptr);
    g_ConnectCallback->OnDataReceived(0, MODULE_BLE_CONN, 0, (char *)data, GENERAL_CONNECTION_HEADER_SIZE + 1);
    EXPECT_EQ(GetRecvDataFlag(), false);
    OutData *dataRecv = PackReceiveData(data, sizeof(uint8_t), 0, g_handle);
    EXPECT_NE(dataRecv, nullptr);
    g_ConnectCallback->OnDataReceived(g_ConnectionId, MODULE_BLE_GENERAL, 0, (char *)dataRecv->data, dataRecv->dataLen);
    EXPECT_EQ(GetRecvDataFlag(), true);
    // not target connId
    g_ConnectCallback->OnDataReceived(0, MODULE_BLE_GENERAL, 0, (char *)dataRecv->data, dataRecv->dataLen);
    SoftBusFree(data);
    FreeOutData(dataRecv);
    CONN_LOGI(CONN_BLE, "test recv end");
}

/*
* @tc.name: Test GetPeerDeviceId
* @tc.desc: test recv normal message
* @tc.type: FUNC
* @tc.require:AR000GIRGE
*/
HWTEST_F(GeneralConnectionTest, TestGetPeerDeviceId, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test get peer deviceId start");
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    ASSERT_NE(manager, nullptr);
    
    char addr[BT_MAC_LEN] = {0};
    int32_t ret = manager->getPeerDeviceId(g_handle, addr, BT_MAC_LEN - 1, 0, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = manager->getPeerDeviceId(g_handle, addr, BT_MAC_LEN, 0, 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = manager->getPeerDeviceId(g_handle, addr, BT_MAC_LEN, 0, 0);
    EXPECT_NE(ret, SOFTBUS_OK);
    CONN_LOGI(CONN_BLE, "test get peer deviceId end");
}

/*
* @tc.name: Test OnConnectDisconnected
* @tc.desc: test OnConnectDisconnected
* @tc.type: FUNC
* @tc.require:AR000GIRGE
*/
HWTEST_F(GeneralConnectionTest, TestOnConnectDisconnected, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test on connect disconnect start");
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    ASSERT_NE(manager, nullptr);

    GeneralConnectionParam param = {0};
    const char *pkgName = "testPkgName1";
    int32_t ret = strcpy_s(param.pkgName, PKG_NAME_SIZE_MAX, pkgName);
    EXPECT_EQ(ret, EOK);
    ret = strcpy_s(param.bundleName, BUNDLE_NAME_MAX, "testBundleName1");
    EXPECT_EQ(ret, EOK);
    ret = strcpy_s(param.name, GENERAL_NAME_LEN, "test1");
    EXPECT_EQ(ret, EOK);
    const char *addr = "11:22:33:44:55:66";
    param.pid = 0;
    NiceMock<GeneralConnectionInterfaceMock> mock;
    EXPECT_CALL(mock, BleConnectDeviceMock).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t handle = manager->connect(&param, addr);
    EXPECT_EQ(handle > 0, true);

    ConnectResult *connectResult = GeneralConnectionInterfaceMock::GetConnectResultMock();
    uint32_t requestId = 13;
    ConnectionInfo infos = {0};
    uint32_t connectionId = (CONNECT_BLE << CONNECT_TYPE_SHIFT) + 1;
    connectResult->OnConnectSuccessed(requestId, connectionId, &infos);

    GeneralConnectionInfo info = {
        .peerId = handle,
    };
    ConnPostData *data = PackInnerMsg(&info, GENERAL_CONNECTION_MSG_TYPE_RESET, MODULE_BLE_GENERAL);
    EXPECT_NE(data, nullptr);
    g_ConnectCallback->OnDataReceived(connectionId, MODULE_BLE_GENERAL, 0, data->buf, data->len);
    EXPECT_EQ(GetFailCallbackReason(), SOFTBUS_CONN_GENERAL_PEER_CONNECTION_CLOSE);

    // not target connId
    g_ConnectCallback->OnDataReceived(0, MODULE_BLE_GENERAL, 0, data->buf, data->len);
    EXPECT_EQ(GetFailCallbackReason(), SOFTBUS_OK);
    
    g_ConnectCallback->OnDisconnected(connectionId, &infos);
    SoftBusFree(data->buf);
    CONN_LOGI(CONN_BLE, "test on connect disconnect end");
}

/*
* @tc.name: TestRecvNewConnection
* @tc.desc: test recv GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE
* @tc.type: FUNC
* @tc.require:AR000GIRGE
*/
HWTEST_F(GeneralConnectionTest, TestRecvNewConnection, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test recv new connection start ");
    NiceMock<GeneralConnectionInterfaceMock> mock;
    EXPECT_CALL(mock, ConnBlePostBytesMock).WillRepeatedly(Return(SOFTBUS_OK));

    // test recv peer connect and not create server
    uint32_t handle = 199657;
    uint32_t connectionId = (CONNECT_BLE << CONNECT_TYPE_SHIFT) + 1;
    GeneralConnectionInfo info = {
        .peerId = handle,
        .name = "test",
        .bundleName = "testApp",
    };
    ConnPostData *data = PackInnerMsg(&info, GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE, MODULE_BLE_GENERAL);
    g_ConnectCallback->OnDataReceived(connectionId, MODULE_BLE_GENERAL, 0, data->buf, data->len);
    EXPECT_EQ(g_isRecvNewConnection, false);

    // test recv peer connect and notify upperLayer success
    GeneralConnectionParam param = {
        .name = "test",
        .bundleName = "testApp",
    };
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    EXPECT_NE(manager, nullptr);
    manager->createServer(&param);
    g_ConnectCallback->OnDataReceived(connectionId, MODULE_BLE_GENERAL, 0, data->buf, data->len);
    EXPECT_EQ(g_isRecvNewConnection, true);
    CONN_LOGI(CONN_BLE, "test recv new connection end");

    // test recv merge message
    GeneralConnectionInfo info1 = {
        .peerId = g_isServerGeneralId,
        .updateHandle = 222,
    };
    data = PackInnerMsg(&info1, GENERAL_CONNECTION_MSG_TYPE_MERGE, MODULE_BLE_GENERAL);
    g_ConnectCallback->OnDataReceived(connectionId, MODULE_BLE_GENERAL, 0, data->buf, data->len);
    SoftBusFree(data->buf);
}

/*
 * @tc.name: TestDataReceivedFuzzTest
 * @tc.desc: test the unpack data interface with fuzz, just for fuzz
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralConnectionTest, TestDataReceivedFuzzTest, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "TestDataReceivedFuzzTest start ");
    NiceMock<GeneralConnectionInterfaceMock> mock;
    EXPECT_CALL(mock, ConnBlePostBytesMock).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t handle = GetConnGeneralRandomData<uint32_t>();
    uint32_t connectionId = GetConnGeneralRandomData<uint32_t>();
    GeneralConnectionInfo info = {
        .peerId = handle,
        .name = "test",
        .bundleName = "testApp",
    };
    ConnPostData *data = PackInnerMsg(
        &info, GetConnGeneralRandomData<GeneralConnectionMsgType>(), GetConnGeneralRandomData<ConnModule>());
    g_ConnectCallback->OnDataReceived(connectionId, MODULE_BLE_GENERAL, 0, data->buf, data->len);
    SoftBusFree(data->buf);
}
}