/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "ble_protocol_interface_factory.h"
#include "softbus_conn_ble_connection.h"
#include "softbus_error_code.h"

using namespace testing::ext;

namespace OHOS {

class BleProtocolInterfaceFactoryTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

/*
* @tc.name: CONN_BLE_GET_UNIFY_INTERFACE_001
* @tc.desc: Test ConnBleGetUnifyInterface returns non-NULL for BLE_GATT
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GET_UNIFY_INTERFACE_001, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(interface, nullptr);
}

/*
* @tc.name: CONN_BLE_GET_UNIFY_INTERFACE_002
* @tc.desc: Test ConnBleGetUnifyInterface returns NULL for invalid type
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GET_UNIFY_INTERFACE_002, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(static_cast<BleProtocolType>(-1));
    EXPECT_EQ(interface, nullptr);
}

/*
* @tc.name: CONN_BLE_GET_UNIFY_INTERFACE_003
* @tc.desc: Test ConnBleGetUnifyInterface returns NULL for BLE_PROTOCOL_MAX
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GET_UNIFY_INTERFACE_003, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_PROTOCOL_MAX);
    EXPECT_EQ(interface, nullptr);
}

/*
* @tc.name: CONN_BLE_GET_UNIFY_INTERFACE_004
* @tc.desc: Test ConnBleGetUnifyInterface returns NULL for out-of-range type
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GET_UNIFY_INTERFACE_004, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(static_cast<BleProtocolType>(100));
    EXPECT_EQ(interface, nullptr);
}

/*
* @tc.name: CONN_BLE_GET_UNIFY_INTERFACE_005
* @tc.desc: Test ConnBleGetUnifyInterface returns NULL for BLE_COC when COC not registered
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GET_UNIFY_INTERFACE_005, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_COC);
    EXPECT_EQ(interface, nullptr);
}

/*
* @tc.name: CONN_BLE_GATT_INTERFACE_001
* @tc.desc: Test BLE_GATT interface has bleClientConnect function
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GATT_INTERFACE_001, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(interface, nullptr);
    EXPECT_NE(interface->bleClientConnect, nullptr);
}

/*
* @tc.name: CONN_BLE_GATT_INTERFACE_002
* @tc.desc: Test BLE_GATT interface has bleClientDisconnect function
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GATT_INTERFACE_002, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(interface, nullptr);
    EXPECT_NE(interface->bleClientDisconnect, nullptr);
}

/*
* @tc.name: CONN_BLE_GATT_INTERFACE_003
* @tc.desc: Test BLE_GATT interface has bleClientSend function
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GATT_INTERFACE_003, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(interface, nullptr);
    EXPECT_NE(interface->bleClientSend, nullptr);
}

/*
* @tc.name: CONN_BLE_GATT_INTERFACE_004
* @tc.desc: Test BLE_GATT interface has bleClientUpdatePriority function
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GATT_INTERFACE_004, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(interface, nullptr);
    EXPECT_NE(interface->bleClientUpdatePriority, nullptr);
}

/*
* @tc.name: CONN_BLE_GATT_INTERFACE_005
* @tc.desc: Test BLE_GATT interface has bleServerStartService function
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GATT_INTERFACE_005, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(interface, nullptr);
    EXPECT_NE(interface->bleServerStartService, nullptr);
}

/*
* @tc.name: CONN_BLE_GATT_INTERFACE_006
* @tc.desc: Test BLE_GATT interface has bleServerStopService function
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GATT_INTERFACE_006, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(interface, nullptr);
    EXPECT_NE(interface->bleServerStopService, nullptr);
}

/*
* @tc.name: CONN_BLE_GATT_INTERFACE_007
* @tc.desc: Test BLE_GATT interface has bleServerSend function
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GATT_INTERFACE_007, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(interface, nullptr);
    EXPECT_NE(interface->bleServerSend, nullptr);
}

/*
* @tc.name: CONN_BLE_GATT_INTERFACE_008
* @tc.desc: Test BLE_GATT interface has bleServerDisconnect function
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GATT_INTERFACE_008, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(interface, nullptr);
    EXPECT_NE(interface->bleServerDisconnect, nullptr);
}

/*
* @tc.name: CONN_BLE_GATT_INTERFACE_009
* @tc.desc: Test BLE_GATT interface has bleServerConnect function
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GATT_INTERFACE_009, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(interface, nullptr);
    EXPECT_NE(interface->bleServerConnect, nullptr);
}

/*
* @tc.name: CONN_BLE_GATT_INTERFACE_010
* @tc.desc: Test BLE_GATT interface has bleClientInitModule function
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GATT_INTERFACE_010, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(interface, nullptr);
    EXPECT_NE(interface->bleClientInitModule, nullptr);
}

/*
* @tc.name: CONN_BLE_GATT_INTERFACE_011
* @tc.desc: Test BLE_GATT interface has bleServerInitModule function
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GATT_INTERFACE_011, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(interface, nullptr);
    EXPECT_NE(interface->bleServerInitModule, nullptr);
}

/*
* @tc.name: CONN_BLE_GATT_INTERFACE_012
* @tc.desc: Test BLE_GATT interface all 11 function pointers are non-NULL
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GATT_INTERFACE_012, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(interface, nullptr);
    EXPECT_NE(interface->bleClientConnect, nullptr);
    EXPECT_NE(interface->bleClientDisconnect, nullptr);
    EXPECT_NE(interface->bleClientSend, nullptr);
    EXPECT_NE(interface->bleClientUpdatePriority, nullptr);
    EXPECT_NE(interface->bleServerStartService, nullptr);
    EXPECT_NE(interface->bleServerStopService, nullptr);
    EXPECT_NE(interface->bleServerSend, nullptr);
    EXPECT_NE(interface->bleServerDisconnect, nullptr);
    EXPECT_NE(interface->bleServerConnect, nullptr);
    EXPECT_NE(interface->bleClientInitModule, nullptr);
    EXPECT_NE(interface->bleServerInitModule, nullptr);
}

/*
* @tc.name: CONN_BLE_GET_UNIFY_INTERFACE_006
* @tc.desc: Test ConnBleGetUnifyInterface returns same pointer for consecutive calls
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GET_UNIFY_INTERFACE_006, TestSize.Level1)
{
    const BleUnifyInterface *interface1 = ConnBleGetUnifyInterface(BLE_GATT);
    const BleUnifyInterface *interface2 = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(interface1, nullptr);
    ASSERT_NE(interface2, nullptr);
    EXPECT_EQ(interface1, interface2);
}

/*
* @tc.name: CONN_BLE_GET_UNIFY_INTERFACE_007
* @tc.desc: Test ConnBleGetUnifyInterface BLE_GATT returns consistent interface
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GET_UNIFY_INTERFACE_007, TestSize.Level1)
{
    const BleUnifyInterface *interface1 = ConnBleGetUnifyInterface(BLE_GATT);
    const BleUnifyInterface *interface2 = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(interface1, nullptr);
    ASSERT_NE(interface2, nullptr);
    EXPECT_EQ(interface1->bleClientConnect, interface2->bleClientConnect);
    EXPECT_EQ(interface1->bleClientDisconnect, interface2->bleClientDisconnect);
    EXPECT_EQ(interface1->bleClientSend, interface2->bleClientSend);
    EXPECT_EQ(interface1->bleServerStartService, interface2->bleServerStartService);
}

/*
* @tc.name: CONN_BLE_GET_UNIFY_INTERFACE_008
* @tc.desc: Test ConnBleGetUnifyInterface with type value 0 (BLE_GATT)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GET_UNIFY_INTERFACE_008, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(static_cast<BleProtocolType>(0));
    ASSERT_NE(interface, nullptr);
}

/*
* @tc.name: CONN_BLE_GET_UNIFY_INTERFACE_009
* @tc.desc: Test ConnBleGetUnifyInterface returns NULL for type value 2 (out of range)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GET_UNIFY_INTERFACE_009, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(static_cast<BleProtocolType>(2));
    EXPECT_EQ(interface, nullptr);
}

/*
* @tc.name: CONN_BLE_GATT_INTERFACE_013
* @tc.desc: Test GATT interface function pointers are distinct from each other
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GATT_INTERFACE_013, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(interface, nullptr);
    EXPECT_NE(reinterpret_cast<const void *>(interface->bleClientConnect),
              reinterpret_cast<const void *>(interface->bleClientDisconnect));
    EXPECT_NE(reinterpret_cast<const void *>(interface->bleClientConnect),
              reinterpret_cast<const void *>(interface->bleClientSend));
    EXPECT_NE(reinterpret_cast<const void *>(interface->bleServerStartService),
              reinterpret_cast<const void *>(interface->bleServerStopService));
}

/*
* @tc.name: CONN_BLE_GATT_INTERFACE_014
* @tc.desc: Test GATT interface client functions are distinct from server functions
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GATT_INTERFACE_014, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(interface, nullptr);
    EXPECT_NE(reinterpret_cast<const void *>(interface->bleClientConnect),
              reinterpret_cast<const void *>(interface->bleServerConnect));
    EXPECT_NE(reinterpret_cast<const void *>(interface->bleClientSend),
              reinterpret_cast<const void *>(interface->bleServerSend));
    EXPECT_NE(reinterpret_cast<const void *>(interface->bleClientDisconnect),
              reinterpret_cast<const void *>(interface->bleServerDisconnect));
    EXPECT_NE(reinterpret_cast<const void *>(interface->bleClientInitModule),
              reinterpret_cast<const void *>(interface->bleServerInitModule));
}

/*
* @tc.name: CONN_BLE_GET_UNIFY_INTERFACE_010
* @tc.desc: Test interleaved calls with different types
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GET_UNIFY_INTERFACE_010, TestSize.Level1)
{
    const BleUnifyInterface *gattInterface = ConnBleGetUnifyInterface(BLE_GATT);
    const BleUnifyInterface *invalidInterface = ConnBleGetUnifyInterface(static_cast<BleProtocolType>(-1));
    const BleUnifyInterface *gattInterface2 = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(gattInterface, nullptr);
    EXPECT_EQ(invalidInterface, nullptr);
    ASSERT_NE(gattInterface2, nullptr);
    EXPECT_EQ(gattInterface, gattInterface2);
}

/*
* @tc.name: CONN_BLE_GET_UNIFY_INTERFACE_011
* @tc.desc: Test ConnBleGetUnifyInterface with COC after GATT call
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GET_UNIFY_INTERFACE_011, TestSize.Level1)
{
    const BleUnifyInterface *gattInterface = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(gattInterface, nullptr);
    const BleUnifyInterface *cocInterface = ConnBleGetUnifyInterface(BLE_COC);
    EXPECT_EQ(cocInterface, nullptr);
}

/*
* @tc.name: CONN_BLE_GET_UNIFY_INTERFACE_012
* @tc.desc: Test multiple consecutive invalid type calls
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GET_UNIFY_INTERFACE_012, TestSize.Level1)
{
    for (int i = 2; i < 10; i++) {
        const BleUnifyInterface *interface = ConnBleGetUnifyInterface(static_cast<BleProtocolType>(i));
        EXPECT_EQ(interface, nullptr);
    }
}

/*
* @tc.name: CONN_BLE_GATT_INTERFACE_015
* @tc.desc: Test GATT interface bleClientConnect is callable (returns error with null conn)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GATT_INTERFACE_015, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(interface, nullptr);
    ASSERT_NE(interface->bleClientConnect, nullptr);
    int32_t ret = interface->bleClientConnect(nullptr);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: CONN_BLE_GATT_INTERFACE_016
* @tc.desc: Test GATT interface bleClientDisconnect is callable
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GATT_INTERFACE_016, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(interface, nullptr);
    ASSERT_NE(interface->bleClientDisconnect, nullptr);
    int32_t ret = interface->bleClientDisconnect(nullptr, false, false);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: CONN_BLE_GATT_INTERFACE_017
* @tc.desc: Test GATT interface bleClientSend is callable
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GATT_INTERFACE_017, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(interface, nullptr);
    ASSERT_NE(interface->bleClientSend, nullptr);
    int32_t ret = interface->bleClientSend(nullptr, nullptr, 0, 0);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: CONN_BLE_GATT_INTERFACE_018
* @tc.desc: Test GATT interface bleClientUpdatePriority is callable
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GATT_INTERFACE_018, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(interface, nullptr);
    ASSERT_NE(interface->bleClientUpdatePriority, nullptr);
    int32_t ret = interface->bleClientUpdatePriority(nullptr, CONN_BLE_PRIORITY_BALANCED);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: CONN_BLE_GATT_INTERFACE_019
* @tc.desc: Test GATT interface bleServerStartService is callable
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GATT_INTERFACE_019, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(interface, nullptr);
    ASSERT_NE(interface->bleServerStartService, nullptr);
    int32_t ret = interface->bleServerStartService();
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: CONN_BLE_GATT_INTERFACE_020
* @tc.desc: Test GATT interface bleServerStopService is callable
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GATT_INTERFACE_020, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(interface, nullptr);
    ASSERT_NE(interface->bleServerStopService, nullptr);
    int32_t ret = interface->bleServerStopService();
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: CONN_BLE_GATT_INTERFACE_021
* @tc.desc: Test GATT interface bleServerSend is callable
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GATT_INTERFACE_021, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(interface, nullptr);
    ASSERT_NE(interface->bleServerSend, nullptr);
    int32_t ret = interface->bleServerSend(nullptr, nullptr, 0, 0);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: CONN_BLE_GATT_INTERFACE_022
* @tc.desc: Test GATT interface bleServerDisconnect is callable
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GATT_INTERFACE_022, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(interface, nullptr);
    ASSERT_NE(interface->bleServerDisconnect, nullptr);
    int32_t ret = interface->bleServerDisconnect(nullptr);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: CONN_BLE_GATT_INTERFACE_023
* @tc.desc: Test GATT interface bleServerConnect is callable
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GATT_INTERFACE_023, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(interface, nullptr);
    ASSERT_NE(interface->bleServerConnect, nullptr);
    int32_t ret = interface->bleServerConnect(nullptr);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: CONN_BLE_GATT_INTERFACE_024
* @tc.desc: Test GATT interface bleClientInitModule is callable
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GATT_INTERFACE_024, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(interface, nullptr);
    ASSERT_NE(interface->bleClientInitModule, nullptr);
    int32_t ret = interface->bleClientInitModule(nullptr, nullptr);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: CONN_BLE_GATT_INTERFACE_025
* @tc.desc: Test GATT interface bleServerInitModule is callable
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GATT_INTERFACE_025, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(interface, nullptr);
    ASSERT_NE(interface->bleServerInitModule, nullptr);
    int32_t ret = interface->bleServerInitModule(nullptr, nullptr);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: CONN_BLE_GET_UNIFY_INTERFACE_013
* @tc.desc: Test ConnBleGetUnifyInterface GATT interface is stable across multiple calls
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GET_UNIFY_INTERFACE_013, TestSize.Level1)
{
    const BleUnifyInterface *interfaces[5];
    for (int i = 0; i < 5; i++) {
        interfaces[i] = ConnBleGetUnifyInterface(BLE_GATT);
        ASSERT_NE(interfaces[i], nullptr);
    }
    for (int i = 1; i < 5; i++) {
        EXPECT_EQ(interfaces[0], interfaces[i]);
    }
}

/*
* @tc.name: CONN_BLE_GET_UNIFY_INTERFACE_014
* @tc.desc: Test ConnBleGetUnifyInterface COC consistently returns NULL without registration
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GET_UNIFY_INTERFACE_014, TestSize.Level1)
{
    for (int i = 0; i < 3; i++) {
        const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_COC);
        EXPECT_EQ(interface, nullptr);
    }
}

/*
* @tc.name: CONN_BLE_GATT_INTERFACE_026
* @tc.desc: Test GATT interface bleClientConnect with null connection returns error
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GATT_INTERFACE_026, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(interface, nullptr);
    int32_t ret = interface->bleClientConnect(nullptr);
    EXPECT_NE(ret, SOFTBUS_OK);
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: CONN_BLE_GATT_INTERFACE_027
* @tc.desc: Test GATT interface bleServerStartService returns error without init
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BleProtocolInterfaceFactoryTest, CONN_BLE_GATT_INTERFACE_027, TestSize.Level1)
{
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_GATT);
    ASSERT_NE(interface, nullptr);
    int32_t ret = interface->bleServerStartService();
    EXPECT_NE(ret, SOFTBUS_OK);
    int32_t ret2 = interface->bleServerStopService();
    EXPECT_NE(ret2, SOFTBUS_OK);
}

} // namespace OHOS
