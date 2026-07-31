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

namespace {
constexpr uint32_t GENERAL_PKGNAME_MAX_COUNT = 10;

ConnectCallback *g_ConnectCallback = nullptr;
uint32_t g_handle = 0;
uint32_t g_isServerGeneralId = 0;
bool g_connectCallbackFlag = false;
int32_t g_failCallbackFlag = 0;
bool g_isRecvNewConnection = false;
bool g_recvDataFlag = false;

const uint8_t *g_baseFuzzData = nullptr;
size_t g_baseFuzzSize = 0;
size_t g_baseFuzzPos = 0;

void ConnectSuccess(GeneralConnectionParam *info, uint32_t generalHandle)
{
    (void)info;
    (void)generalHandle;
    g_connectCallbackFlag = true;
}

void ConnectFailed(GeneralConnectionParam *info, uint32_t generalHandle, int32_t reason)
{
    (void)info;
    (void)generalHandle;
    (void)reason;
    g_failCallbackFlag = reason;
}

void AcceptConnect(GeneralConnectionParam *info, uint32_t generalHandle)
{
    (void)info;
    (void)generalHandle;
    g_isRecvNewConnection = true;
    g_isServerGeneralId = generalHandle;
}

void DataReceived(GeneralConnectionParam *info, uint32_t generalHandle, const uint8_t *data, uint32_t dataLen)
{
    (void)info;
    (void)generalHandle;
    (void)data;
    (void)dataLen;
    g_recvDataFlag = true;
}

void ConnectionDisconnected(GeneralConnectionParam *info, uint32_t generalHandle, int32_t reason)
{
    (void)info;
    (void)generalHandle;
    (void)reason;
}

void GeneralServerStopped(GeneralConnectionParam *info)
{
    (void)info;
}

int32_t GetFailCallbackReason()
{
    if (g_failCallbackFlag < 0) {
        int32_t reason = g_failCallbackFlag;
        g_failCallbackFlag = SOFTBUS_OK;
        return reason;
    }
    return SOFTBUS_OK;
}

bool GetRecvDataFlag()
{
    if (g_recvDataFlag) {
        g_recvDataFlag = false;
        return true;
    }
    return false;
}

OutData *PackReceiveData(const uint8_t *data, uint32_t dataLen, uint32_t localId, uint32_t peerId)
{
    uint32_t tmpLen = GENERAL_CONNECTION_HEADER_SIZE + dataLen;
    GeneralConnectionHead *dataTmp = static_cast<GeneralConnectionHead *>(SoftBusCalloc(tmpLen));
    if (dataTmp == nullptr) {
        return nullptr;
    }
    dataTmp->headLen = GENERAL_CONNECTION_HEADER_SIZE;
    dataTmp->localId = localId;
    dataTmp->peerId = peerId;
    dataTmp->msgType = GENERAL_CONNECTION_MSG_TYPE_NORMAL;

    if (memcpy_s(reinterpret_cast<uint8_t *>(dataTmp) + GENERAL_CONNECTION_HEADER_SIZE,
        dataLen, data, dataLen) != EOK) {
        SoftBusFree(dataTmp);
        return nullptr;
    }

    uint32_t connectHeadLen = ConnGetHeadSize();
    uint32_t totalLen = tmpLen + connectHeadLen;
    OutData *outData = static_cast<OutData *>(SoftBusCalloc(sizeof(OutData)));
    if (outData == nullptr) {
        SoftBusFree(dataTmp);
        return nullptr;
    }
    outData->dataLen = totalLen;
    outData->data = static_cast<uint8_t *>(SoftBusCalloc(totalLen));
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

void FreeConnPostData(ConnPostData *data)
{
    if (data != nullptr) {
        SoftBusFree(data->buf);
        SoftBusFree(data);
    }
}

ConnPostData *PackInnerMsg(GeneralConnectionInfo *info, GeneralConnectionMsgType msgType, int32_t module)
{
    OutData *data = GeneralConnectionPackMsg(info, msgType);
    EXPECT_NE(data, nullptr);
    if (data == nullptr) {
        return nullptr;
    }

    uint32_t size = ConnGetHeadSize();
    ConnPostData *buff = static_cast<ConnPostData *>(SoftBusCalloc(sizeof(ConnPostData)));
    if (buff == nullptr) {
        FreeOutData(data);
        return nullptr;
    }
    buff->seq = 0;
    buff->flag = CONN_HIGH;
    buff->pid = 0;
    buff->len = data->dataLen + size;
    buff->buf = static_cast<char *>(SoftBusCalloc(buff->len));
    buff->module = module;

    if (buff->buf == nullptr || memcpy_s(buff->buf + size, data->dataLen, data->data, data->dataLen) != EOK) {
        FreeOutData(data);
        FreeConnPostData(buff);
        return nullptr;
    }
    FreeOutData(data);
    return buff;
}

void FillGeneralConnectionParam(GeneralConnectionParam &param,
    const char *name, const char *pkgName, const char *bundleName)
{
    EXPECT_EQ(strcpy_s(param.name, GENERAL_NAME_LEN, name), EOK);
    EXPECT_EQ(strcpy_s(param.pkgName, PKG_NAME_SIZE_MAX, pkgName), EOK);
    EXPECT_EQ(strcpy_s(param.bundleName, BUNDLE_NAME_MAX, bundleName), EOK);
}

template <class T>
T GetConnGeneralRandomData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (g_baseFuzzData == nullptr || objectSize > g_baseFuzzSize - g_baseFuzzPos) {
        COMM_LOGE(COMM_TEST, "data invalid");
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, g_baseFuzzData + g_baseFuzzPos, objectSize);
    if (ret != EOK) {
        COMM_LOGE(COMM_TEST, "memory copy error");
        return {};
    }
    g_baseFuzzPos += objectSize;
    return object;
}
}

namespace OHOS {
class GeneralConnectionTest : public testing::Test {
public:
    GeneralConnectionTest() = default;
    ~GeneralConnectionTest() override = default;
    static void SetUpTestCase();
    static void TearDownTestCase();
};

void GeneralConnectionTest::SetUpTestCase()
{
    LooperInit();
    SoftbusConfigInit();
    auto ret = ConnServerInit();
    EXPECT_EQ(ret, SOFTBUS_OK);

    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    EXPECT_NE(manager, nullptr);

    GeneralConnectionListener listener = {
        .onConnectSuccess = ConnectSuccess,
        .onConnectFailed = ConnectFailed,
        .onAcceptConnect = AcceptConnect,
        .onDataReceived = DataReceived,
        .onConnectionDisconnected = ConnectionDisconnected,
        .onServerStopped = GeneralServerStopped,
    };

    ret = manager->registerListener(&listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

void GeneralConnectionTest::TearDownTestCase()
{
    ConnServerDeinit();
}

/*
 * @tc.name: TestInit
 * @tc.desc: test init general connection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralConnectionTest, TestInit, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test init in");
    const char *pkgName = "testName";
    ClearGeneralConnection(pkgName, 0);
    ClearGeneralConnection(pkgName, 0);
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    EXPECT_NE(manager, nullptr);
    GeneralConnectionParam param = {};
    manager->closeServer(&param);
    g_ConnectCallback = GeneralConnectionInterfaceMock::GetConnectCallbackMock();
    ASSERT_NE(g_ConnectCallback, nullptr);
    CONN_LOGI(CONN_BLE, "test init out");
}

/*
 * @tc.name: TestCreateServer
 * @tc.desc: test create server include max count(10) and normal case
 * @tc.type: FUNC
 * @tc.require:AR000GIRGE
 */
HWTEST_F(GeneralConnectionTest, TestCreateServer, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test createServer in");
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    EXPECT_NE(manager, nullptr);
    GeneralConnectionParam param = {};
    FillGeneralConnectionParam(param, "test", "testPkgName", "testBundleNameServer");

    GeneralConnectionInterfaceMock mock;
    EXPECT_CALL(mock, LnnIsOsAccountConstraint).WillRepeatedly(Return(false));

    int32_t ret = manager->createServer(&param);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = manager->createServer(&param);
    EXPECT_EQ(ret, SOFTBUS_CONN_GENERAL_DUPLICATE_SERVER);
    for (uint32_t i = 0; i < GENERAL_PKGNAME_MAX_COUNT; ++i) {
        std::string nameTemp = "test" + std::to_string(i);
        EXPECT_EQ(strcpy_s(param.name, GENERAL_NAME_LEN, nameTemp.c_str()), EOK);
        ret = manager->createServer(&param);
        int32_t expectedRet = (i == GENERAL_PKGNAME_MAX_COUNT - 1) ?
            SOFTBUS_CONN_GENERAL_CREATE_SERVER_MAX : SOFTBUS_OK;
        EXPECT_EQ(ret, expectedRet);
    }

    manager->closeServer(&param);
    EXPECT_EQ(strcpy_s(param.name, GENERAL_NAME_LEN, "test9"), EOK);
    manager->closeServer(&param);

    EXPECT_EQ(strcpy_s(param.name, GENERAL_NAME_LEN, "test8"), EOK);
    EXPECT_EQ(strcpy_s(param.bundleName, GENERAL_NAME_LEN, "testBundleName0"), EOK);
    manager->closeServer(&param);
    CONN_LOGI(CONN_BLE, "test createServer out");
}

/*
 * @tc.name: TestCreateServerConstraint
 * @tc.desc: test create server blocked by account constraint
 * @tc.type: FUNC
 * @tc.require:AR000GIRGE
 */
HWTEST_F(GeneralConnectionTest, TestCreateServerConstraint, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test createServer constraint in");
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    EXPECT_NE(manager, nullptr);
    GeneralConnectionParam param = {};
    FillGeneralConnectionParam(param, "testConstraint", "testConstraintPkg", "testBundleNameServer");

    GeneralConnectionInterfaceMock mock;
    EXPECT_CALL(mock, LnnIsOsAccountConstraint).WillRepeatedly(Return(true));

    int32_t ret = manager->createServer(&param);
    EXPECT_EQ(ret, SOFTBUS_ACCOUNT_CONSTRAINT_ENABLE);
    CONN_LOGI(CONN_BLE, "test createServer constraint out");
}

/*
 * @tc.name: TestConnect
 * @tc.desc: test connect include to max count(10) and normal case
 * @tc.type: FUNC
 * @tc.require:AR000GIRGE
 */
HWTEST_F(GeneralConnectionTest, TestConnect, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test connect in");
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    EXPECT_NE(manager, nullptr);
    GeneralConnectionParam param = {};
    FillGeneralConnectionParam(param, "test", "testPkgName", "testBundleNameConnect");
    const char *addr = "11:22:33:44:55:66";
    param.pid = 0;
    GeneralConnectionInterfaceMock mock;
    EXPECT_CALL(mock, LnnIsOsAccountConstraint).WillRepeatedly(Return(false));
    EXPECT_CALL(mock, BleConnectDeviceMock).WillRepeatedly(Return(SOFTBUS_OK));
    for (uint32_t i = 0; i < GENERAL_PKGNAME_MAX_COUNT; ++i) {
        std::string nameTemp = "test" + std::to_string(i);
        EXPECT_EQ(strcpy_s(param.name, GENERAL_NAME_LEN, nameTemp.c_str()), EOK);
        int32_t ret = manager->connect(&param, addr);
        EXPECT_GT(ret, 0);
    }
    EXPECT_EQ(strcpy_s(param.name, GENERAL_NAME_LEN, "test10"), EOK);
    int32_t ret = manager->connect(&param, addr);
    EXPECT_EQ(ret, SOFTBUS_CONN_GENERAL_CREATE_CLIENT_MAX);
    manager->cleanupGeneralConnection(param.pkgName, param.pid);

    EXPECT_EQ(strcpy_s(param.name, GENERAL_NAME_LEN, "test9"), EOK);
    EXPECT_CALL(mock, BleConnectDeviceMock).WillRepeatedly(Return(SOFTBUS_STRCPY_ERR));
    ret = manager->connect(&param, addr);
    EXPECT_EQ(ret, SOFTBUS_CONN_GENERAL_CONNECT_FAILED);
    manager->cleanupGeneralConnection(param.pkgName, param.pid);
    CONN_LOGI(CONN_BLE, "test connect out");
}

/*
 * @tc.name: TestConnectConstraint
 * @tc.desc: test connect blocked by account constraint
 * @tc.type: FUNC
 * @tc.require: AR000GIRGE
 */
HWTEST_F(GeneralConnectionTest, TestConnectConstraint, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test connect constraint in");
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    EXPECT_NE(manager, nullptr);
    GeneralConnectionParam param = {};
    FillGeneralConnectionParam(param, "testConstraint", "testConstraintPkg", "testBundleNameConnect");
    const char *addr = "11:22:33:44:55:66";
    param.pid = 0;

    GeneralConnectionInterfaceMock mock;
    EXPECT_CALL(mock, LnnIsOsAccountConstraint).WillRepeatedly(Return(true));

    int32_t ret = manager->connect(&param, addr);
    EXPECT_EQ(ret, SOFTBUS_ACCOUNT_CONSTRAINT_ENABLE);
    CONN_LOGI(CONN_BLE, "test connect constraint out");
}

/*
 * @tc.name: TestSendConstraint
 * @tc.desc: test send blocked by account constraint
 * @tc.type: FUNC
 * @tc.require: AR000GIRGE
 */
HWTEST_F(GeneralConnectionTest, TestSendConstraint, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test send constraint in");
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    ASSERT_NE(manager, nullptr);
    GeneralConnectionParam param = {
        .pkgName = "testPkgConstraint",
        .bundleName = "testBundleNameSend",
        .name = "testConstraint",
    };
    param.pid = 0;
    uint8_t *data = static_cast<uint8_t *>(SoftBusCalloc(sizeof(uint8_t)));
    EXPECT_NE(data, nullptr);
    NiceMock<GeneralConnectionInterfaceMock> mock;
    EXPECT_CALL(mock, LnnIsOsAccountConstraint).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, BleConnectDeviceMock).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = manager->send(g_handle, nullptr, sizeof(uint8_t), 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = manager->send(g_handle, data, sizeof(uint8_t), 0);
    EXPECT_EQ(ret, SOFTBUS_ACCOUNT_CONSTRAINT_ENABLE);
    SoftBusFree(data);
    CONN_LOGI(CONN_BLE, "test send constraint out");
}

/*
 * @tc.name: TestRecv
 * @tc.desc: test recv normal message
 * @tc.type: FUNC
 * @tc.require:AR000GIRGE
 */
HWTEST_F(GeneralConnectionTest, TestRecv, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test recv in");
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    EXPECT_NE(manager, nullptr);
    GeneralConnectionParam param = {
        .pkgName = "testPkgNameRecv",
        .bundleName = "testBundleNameRecv",
        .name = "testRecv",
    };
    const char *addr = "22:22:33:44:55:66";
    param.pid = 0;
    NiceMock<GeneralConnectionInterfaceMock> mock;
    EXPECT_CALL(mock, BleConnectDeviceMock).WillRepeatedly(Return(SOFTBUS_OK));
    auto handle = manager->connect(&param, addr);
    EXPECT_GT(handle, 0);

    auto connectionId = (CONNECT_BLE << CONNECT_TYPE_SHIFT) + 2;
    ConnectResult *connectResult = GeneralConnectionInterfaceMock::GetConnectResultMock();
    uint32_t requestId = 69;
    ConnectionInfo infos = {};
    connectResult->OnConnectSuccessed(requestId, connectionId, &infos);

    uint8_t *data = static_cast<uint8_t *>(SoftBusMalloc(sizeof(uint8_t)));
    EXPECT_NE(data, nullptr);
    g_ConnectCallback->OnDataReceived(0, MODULE_BLE_CONN, 0,
        reinterpret_cast<char *>(data), GENERAL_CONNECTION_HEADER_SIZE + 1);
    EXPECT_FALSE(GetRecvDataFlag());
    OutData *dataRecv = PackReceiveData(data, sizeof(uint8_t), 0, handle);
    EXPECT_NE(dataRecv, nullptr);
    connectionId = 0;
    g_ConnectCallback->OnDataReceived(connectionId, MODULE_BLE_GENERAL, 0,
        reinterpret_cast<char *>(dataRecv->data), dataRecv->dataLen);
    EXPECT_TRUE(GetRecvDataFlag());
    g_ConnectCallback->OnDataReceived(0, MODULE_BLE_GENERAL, 0,
        reinterpret_cast<char *>(dataRecv->data), dataRecv->dataLen);
    SoftBusFree(data);
    FreeOutData(dataRecv);
    CONN_LOGI(CONN_BLE, "test recv out");
}

/*
 * @tc.name: TestGetPeerDeviceId
 * @tc.desc: test get peer device id
 * @tc.type: FUNC
 * @tc.require:AR000GIRGE
 */
HWTEST_F(GeneralConnectionTest, TestGetPeerDeviceId, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test get peer deviceId in");
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    ASSERT_NE(manager, nullptr);

    char addr[BT_MAC_LEN] = {};
    int32_t ret = manager->getPeerDeviceId(g_handle, addr, BT_MAC_LEN - 1, 0, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = manager->getPeerDeviceId(g_handle, addr, BT_MAC_LEN, 0, 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = manager->getPeerDeviceId(g_handle, addr, BT_MAC_LEN, 0, 0);
    EXPECT_NE(ret, SOFTBUS_OK);
    CONN_LOGI(CONN_BLE, "test get peer deviceId out");
}

/*
 * @tc.name: TestOnConnectDisconnected
 * @tc.desc: test OnConnectDisconnected
 * @tc.type: FUNC
 * @tc.require:AR000GIRGE
 */
HWTEST_F(GeneralConnectionTest, TestOnConnectDisconnected, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test on connect disconnect in");
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    ASSERT_NE(manager, nullptr);

    GeneralConnectionParam param = {};
    FillGeneralConnectionParam(param, "test1", "testPkgName1", "testBundleNameDisconnected");
    const char *addr = "11:22:33:44:55:66";
    param.pid = 0;
    NiceMock<GeneralConnectionInterfaceMock> mock;
    uint32_t actualRequestId = 0;
    EXPECT_CALL(mock, BleConnectDeviceMock)
        .WillRepeatedly(DoAll(SaveArg<1>(&actualRequestId), Return(SOFTBUS_OK)));
    int32_t handle = manager->connect(&param, addr);
    EXPECT_GT(handle, 0);

    ConnectResult *connectResult = GeneralConnectionInterfaceMock::GetConnectResultMock();
    ConnectionInfo infos = {};
    uint32_t connectionId = (CONNECT_BLE << CONNECT_TYPE_SHIFT) + 1;
    connectResult->OnConnectSuccessed(actualRequestId, connectionId, &infos);

    GeneralConnectionInfo info = {
        .peerId = static_cast<uint32_t>(handle),
    };
    ConnPostData *data = PackInnerMsg(&info, GENERAL_CONNECTION_MSG_TYPE_RESET, MODULE_BLE_GENERAL);
    EXPECT_NE(data, nullptr);
    g_ConnectCallback->OnDataReceived(connectionId, MODULE_BLE_GENERAL, 0, data->buf, data->len);
    EXPECT_EQ(GetFailCallbackReason(), SOFTBUS_CONN_GENERAL_PEER_CONNECTION_CLOSE);

    g_ConnectCallback->OnDataReceived(0, MODULE_BLE_GENERAL, 0, data->buf, data->len);
    EXPECT_EQ(GetFailCallbackReason(), SOFTBUS_OK);

    g_ConnectCallback->OnDisconnected(connectionId, &infos);
    FreeConnPostData(data);
    CONN_LOGI(CONN_BLE, "test on connect disconnect out");
}

/*
 * @tc.name: TestRecvNewConnection
 * @tc.desc: test recv GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE
 * @tc.type: FUNC
 * @tc.require:AR000GIRGE
 */
HWTEST_F(GeneralConnectionTest, TestRecvNewConnection, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test recv new connection in ");
    NiceMock<GeneralConnectionInterfaceMock> mock;
    EXPECT_CALL(mock, ConnBlePostBytesMock).WillRepeatedly(Return(SOFTBUS_OK));

    uint32_t handle = 199657;
    uint32_t connectionId = (CONNECT_BLE << CONNECT_TYPE_SHIFT) + 1;
    GeneralConnectionInfo info = {
        .peerId = handle,
        .name = "test",
        .bundleName = "testApp",
    };
    ConnPostData *data = PackInnerMsg(&info, GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE, MODULE_BLE_GENERAL);
    g_ConnectCallback->OnDataReceived(connectionId, MODULE_BLE_GENERAL, 0, data->buf, data->len);
    EXPECT_FALSE(g_isRecvNewConnection);

    GeneralConnectionParam param = {
        .name = "test",
        .bundleName = "testApp",
    };
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    EXPECT_NE(manager, nullptr);
    manager->createServer(&param);
    g_ConnectCallback->OnDataReceived(connectionId, MODULE_BLE_GENERAL, 0, data->buf, data->len);
    EXPECT_TRUE(g_isRecvNewConnection);

    GeneralConnectionInfo info1 = {
        .peerId = g_isServerGeneralId,
        .updateHandle = 222,
    };
    FreeConnPostData(data);
    data = PackInnerMsg(&info1, GENERAL_CONNECTION_MSG_TYPE_MERGE, MODULE_BLE_GENERAL);
    g_ConnectCallback->OnDataReceived(connectionId, MODULE_BLE_GENERAL, 0, data->buf, data->len);
    FreeConnPostData(data);
    CONN_LOGI(CONN_BLE, "test recv new connection out");
}

/*
 * @tc.name: TestDataReceivedFuzzTest
 * @tc.desc: test the unpack data interface with fuzz, just for fuzz
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralConnectionTest, TestDataReceivedFuzzTest, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "TestDataReceivedFuzzTest in");
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
    FreeConnPostData(data);
}

/*
 * @tc.name: TestConnectParamNull
 * @tc.desc: test connect with null param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralConnectionTest, TestConnectParamNull, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test connect param null in");
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    ASSERT_NE(manager, nullptr);
    const char *addr = "11:22:33:44:55:66";
    int32_t ret = manager->connect(nullptr, addr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TestConnectAddrNull
 * @tc.desc: test connect with null addr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralConnectionTest, TestConnectAddrNull, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test connect addr null in");
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    ASSERT_NE(manager, nullptr);
    GeneralConnectionParam param = {};
    FillGeneralConnectionParam(param, "testAddrNull", "testPkgAddrNull", "testBundleAddrNull");
    int32_t ret = manager->connect(&param, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TestSendDataNull
 * @tc.desc: test send with null data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralConnectionTest, TestSendDataNull, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test send data null in");
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    ASSERT_NE(manager, nullptr);
    int32_t ret = manager->send(g_handle, nullptr, 0, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TestCreateServerParamNull
 * @tc.desc: test createServer with null param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralConnectionTest, TestCreateServerParamNull, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test createServer param null in");
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    ASSERT_NE(manager, nullptr);
    int32_t ret = manager->createServer(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TestGetPeerDeviceIdAddrNull
 * @tc.desc: test getPeerDeviceId with null addr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralConnectionTest, TestGetPeerDeviceIdAddrNull, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test getPeerDeviceId addr null in");
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    ASSERT_NE(manager, nullptr);
    int32_t ret = manager->getPeerDeviceId(g_handle, nullptr, BT_MAC_LEN, 0, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
}
