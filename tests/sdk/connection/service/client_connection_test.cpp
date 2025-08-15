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
#include <securec.h>

#include "accesstoken_kit.h"
#include "general_client_connection.h"
#include "general_connection_server_proxy.h"
#include "nativetoken_kit.h"
#include "softbus_connection.h"
#include "softbus_error_code.h"
#include "token_setproc.h"

using namespace testing::ext;
namespace OHOS {
namespace {
class ClientConnectionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AddPermission(void)
{
    const char *perms[2];
    perms[0] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    perms[1] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "dsoftbus_server",
        .aplStr = "system_core",
    };
    uint64_t tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

void ClientConnectionTest::SetUpTestCase()
{
    AddPermission();
}

void ClientConnectionTest::TearDownTestCase() { }

void ClientConnectionTest::SetUp() { }

void ClientConnectionTest::TearDown() { }

static int32_t OnAcceptConnect(const char *name, uint32_t handle)
{
    printf("OnAcceptConnect called, name: %s, handle: %d\n", name, handle);
    return 0;
}

static int32_t OnConnectionStateChange(uint32_t handle, int32_t state, int32_t reason)
{
    printf("OnConnectionStateChange called, handle: %d, state: %d, reason: %d\n", handle, state, reason);
    return 0;
}

static void OnDataRecevied(uint32_t handle, const uint8_t *data, uint32_t len)
{
    printf("OnDataRecevied called, handle: %d, data: %s, len: %d\n", handle, data, len);
}

static void OnServiceDied(void)
{
    printf("OnServiceDied called\n");
}

static IGeneralListener g_listener = {
    .OnAcceptConnect = OnAcceptConnect,
    .OnConnectionStateChange = OnConnectionStateChange,
    .OnDataReceived = OnDataRecevied,
    .OnServiceDied = OnServiceDied,
};

static int32_t OnAcceptConnectBad(const char *name, uint32_t handle)
{
    printf("OnAcceptConnect called, name: %s, handle: %d\n", name, handle);
    return -1;
}

static int32_t OnConnectionStateChangeBad(uint32_t handle, int32_t state, int32_t reason)
{
    printf("OnConnectionStateChange called, handle: %d, state: %d, reason: %d\n", handle, state, reason);
    return -1;
}

static void OnDataReceviedBad(uint32_t handle, const uint8_t *data, uint32_t len)
{
    printf("OnDataRecevied called, handle: %d, data: %s, len: %d\n", handle, data, len);
}

static IGeneralListener g_listenerBad = {
    .OnAcceptConnect = OnAcceptConnectBad,
    .OnConnectionStateChange = OnConnectionStateChangeBad,
    .OnDataReceived = OnDataReceviedBad,
    .OnServiceDied = OnServiceDied,
};

/*
 * @tc.name: RegisterListenerTest
 * @tc.desc: register listener test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientConnectionTest, RegisterListenerTest, TestSize.Level0)
{
    int32_t ret = GeneralRegisterListener(nullptr);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);

    IGeneralListener listener = {
        .OnAcceptConnect = nullptr,
        .OnConnectionStateChange = nullptr,
        .OnDataReceived = nullptr,
        .OnServiceDied = nullptr,
    };
    ret = GeneralRegisterListener(&listener);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);

    listener.OnAcceptConnect = OnAcceptConnect;
    ret = GeneralRegisterListener(&listener);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);

    listener.OnConnectionStateChange = OnConnectionStateChange;
    ret = GeneralRegisterListener(&listener);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);

    listener.OnDataReceived = OnDataRecevied;
    ret = GeneralRegisterListener(&listener);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);

    listener.OnServiceDied = OnServiceDied;
    ret = GeneralRegisterListener(&listener);
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = GeneralUnregisterListener();
    ASSERT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ClientConnectionTest
 * @tc.desc: register listener test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientConnectionTest, ClientConnectionTest, TestSize.Level0)
{
    int32_t ret = GeneralRegisterListener(&g_listener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    const char *pkgName = "ohos.distributedschedule.dms";
    const char *name = "hanglvzongheng";
    ret = GeneralCreateServer(pkgName, name);
    ASSERT_EQ(ret, SOFTBUS_TRANS_GET_BUNDLENAME_FAILED);
    ret = GeneralRemoveServer(pkgName, name);
    ASSERT_EQ(ret, SOFTBUS_TRANS_GET_BUNDLENAME_FAILED);
    Address address;
    address.addrType = CONNECTION_ADDR_BLE;
    char mac[BT_MAC_LEN] = "12:32:43:54:65:76";
    ret = memcpy_s(address.addr.ble.mac, BT_MAC_LEN, mac, BT_MAC_LEN);
    ASSERT_EQ(ret, EOK);
    ret = GeneralConnect(pkgName, name, &address);
    ASSERT_EQ(ret, SOFTBUS_TRANS_GET_BUNDLENAME_FAILED);
    GeneralDisconnect(0);
    const uint8_t *data = (const uint8_t *)"hello world";
    ret = GeneralSend(1, data, strlen((const char *)data));
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GeneralGetPeerDeviceId(0, nullptr, 0);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GeneralGetPeerDeviceId(1, nullptr, 0);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
    uint32_t invalidLen = 20;
    const uint32_t len = 10;
    char udid[len] = { 0 };
    ret = GeneralGetPeerDeviceId(1, udid, invalidLen);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GeneralGetPeerDeviceId(1, udid, 0);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GeneralGetPeerDeviceId(1, udid, len);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GeneralUnregisterListener();
    ASSERT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ConnectionStateChangeTest
 * @tc.desc: connection state change test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientConnectionTest, ConnectionStateChangeTest, TestSize.Level0)
{
    int32_t ret = ConnectionStateChange(0, 0, 0);
    ASSERT_EQ(ret, SOFTBUS_OK);

    IGeneralListener listener = {
        .OnAcceptConnect = OnAcceptConnect,
        .OnConnectionStateChange = OnConnectionStateChange,
        .OnDataReceived = OnDataRecevied,
        .OnServiceDied = OnServiceDied,
    };
    ret = GeneralRegisterListener(&listener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = ConnectionStateChange(0, 0, 0);
    ASSERT_EQ(ret, SOFTBUS_OK);

    listener.OnConnectionStateChange = nullptr;
    ret = ConnectionStateChange(0, 0, 0);
    ASSERT_EQ(ret, SOFTBUS_NO_INIT);
    ret = GeneralUnregisterListener();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = GeneralRegisterListener(&g_listenerBad);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = ConnectionStateChange(0, 0, 0);
    ASSERT_NE(ret, SOFTBUS_OK);
    ret = GeneralUnregisterListener();
}

/*
 * @tc.name: AcceptConnectTest
 * @tc.desc: accept connect test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientConnectionTest, AcceptConnectTest, TestSize.Level0)
{
    int32_t ret = AcceptConnect("test", 0);
    ASSERT_EQ(ret, SOFTBUS_OK);
    IGeneralListener listener = {
        .OnAcceptConnect = OnAcceptConnect,
        .OnConnectionStateChange = OnConnectionStateChange,
        .OnDataReceived = OnDataRecevied,
        .OnServiceDied = OnServiceDied,
    };
    ret = GeneralRegisterListener(&listener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = AcceptConnect("test", 0);
    ASSERT_EQ(ret, SOFTBUS_OK);

    listener.OnAcceptConnect = nullptr;
    ret = AcceptConnect("test", 0);
    ASSERT_EQ(ret, SOFTBUS_NO_INIT);

    ret = GeneralUnregisterListener();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = GeneralRegisterListener(&g_listenerBad);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = AcceptConnect("test", 0);
    ASSERT_NE(ret, SOFTBUS_OK);
    ret = GeneralUnregisterListener();
}

/*
 * @tc.name: DataReceivedTest
 * @tc.desc: data received test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientConnectionTest, DataReceivedTest, TestSize.Level0)
{
    const uint8_t *data = reinterpret_cast<const uint8_t *>("test");
    uint32_t len = strlen(reinterpret_cast<const char *>(data));
    DataReceived(0, data, len);
    IGeneralListener listener = {
        .OnAcceptConnect = OnAcceptConnect,
        .OnConnectionStateChange = OnConnectionStateChange,
        .OnDataReceived = OnDataRecevied,
        .OnServiceDied = OnServiceDied,
    };
    int32_t ret = GeneralRegisterListener(&listener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    DataReceived(0, data, len);
    listener.OnDataReceived = nullptr;
    DataReceived(0, data, len);
    ret = GeneralUnregisterListener();
    ASSERT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ConnectionDeathNotifyTest
 * @tc.desc: connection death notify test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientConnectionTest, ConnectionDeathNotifyTest, TestSize.Level0)
{
    ConnectionDeathNotify();
    IGeneralListener listener = {
        .OnAcceptConnect = OnAcceptConnect,
        .OnConnectionStateChange = OnConnectionStateChange,
        .OnDataReceived = OnDataRecevied,
        .OnServiceDied = OnServiceDied,
    };
    int32_t ret = GeneralRegisterListener(&listener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ConnectionDeathNotify();
    listener.OnServiceDied = nullptr;
    ConnectionDeathNotify();
    listener.OnConnectionStateChange = nullptr;
    ConnectionDeathNotify();
    ret = GeneralUnregisterListener();
    ASSERT_EQ(ret, SOFTBUS_OK);
}
} // namespace
} // namespace OHOS
