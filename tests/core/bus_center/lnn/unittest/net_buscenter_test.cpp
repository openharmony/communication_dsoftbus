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

#include <gtest/gtest.h>

#include <securec.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <net/if.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "auth_interface.h"
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_event_monitor.h"
#include "lnn_local_net_ledger.h"
#include "lnn_network_manager.h"
#include "lnn_node_info.h"
#include "lnn_sync_item_info.h"
#include "softbus_bus_center.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_adapter_errcode.h"

namespace OHOS {
using namespace testing::ext;

static int32_t InitServer()
{
    if (ConnServerInit() != SOFTBUS_OK) {
        printf("softbus conn server init failed.");
        return SOFTBUS_CONN_INTERNAL_ERR;
    }
    if (AuthInit() != SOFTBUS_OK) {
        printf("softbus auth init failed.");
        return SOFTBUS_AUTH_INIT_FAIL;
    }
    if (LnnInitLocalLedger() != SOFTBUS_OK) {
        printf("init local net ledger fail!");
        return SOFTBUS_NETWORK_LEDGER_INIT_FAILED;
    }
    if (LnnInitDistributedLedger() != SOFTBUS_OK) {
        printf("init distributed net ledger fail!");
        return SOFTBUS_NETWORK_LEDGER_INIT_FAILED;
    }
    if (LnnInitEventMonitor() != SOFTBUS_OK) {
        printf("init event monitor failed");
        return SOFTBUS_EVENT_MONITER_INIT_FAILED;
    }
    if (LnnInitNetworkManager() != SOFTBUS_OK) {
        printf("init lnn network manager fail!");
        return SOFTBUS_NETWORK_MANAGER_INIT_FAILED;
    }
    return SOFTBUS_OK;
}

class NetBusCenterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void NetBusCenterTest::SetUpTestCase()
{
    EXPECT_TRUE(InitServer() == SOFTBUS_OK);
    sleep(2);
}

void NetBusCenterTest::TearDownTestCase()
{
    ConnServerDeinit();
    AuthDeinit();
    LnnDeinitLocalLedger();
    LnnDeinitDistributedLedger();
    LnnDeinitEventMonitor();
    LnnDeinitNetworkManager();
}

void NetBusCenterTest::SetUp() { }

void NetBusCenterTest::TearDown() { }

static int32_t SetIpaddr(const std::string &ip)
{
    int32_t sockFd = -1;
    struct sockaddr_in addr;
    struct ifreq ifr;
    if (memset_s((void *)&addr, sizeof(addr), 0, sizeof(addr)) != EOK) {
        printf("memset_s 1 fail\n");
        return SOFTBUS_MEM_ERR;
    }
    if (memset_s((void *)&ifr, sizeof(ifr), 0, sizeof(ifr)) != EOK) {
        printf("memset_s 3 fail\n");
        return SOFTBUS_MEM_ERR;
    }

    sockFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockFd < 0) {
        printf("could not create IP socket\n");
        return SOFTBUS_NETWORK_CREATE_SOCKET_FAILED;
    }
    if (strncpy_s(ifr.ifr_name, sizeof(ifr.ifr_name), "eth0", strlen("eth0")) != EOK) {
        printf("strncpy_s fail\n");
        close(sockFd);
        return SOFTBUS_STRCPY_ERR;
    }

    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip.c_str(), &(addr.sin_addr)) <= 0) {
        printf("inet_pton fail for ip\n");
        close(sockFd);
        return SOFTBUS_CONN_INET_PTON_FAILED;
    }
    (void)memcpy_s(&ifr.ifr_addr, sizeof(addr), &addr, sizeof(addr));
    if (ioctl(sockFd, SIOCSIFADDR, &ifr) < 0) {
        printf("error to set interface address, error: %s\n", strerror(errno));
        close(sockFd);
        return SOFTBUS_ADAPTER_ERR;
    }

    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(sockFd, SIOCSIFFLAGS, &ifr) < 0) {
        printf("error to set eth0 up\n");
        close(sockFd);
        return SOFTBUS_ADAPTER_ERR;
    }
    close(sockFd);
    return SOFTBUS_OK;
}

static int32_t SetIpDown()
{
    int32_t sockFd = -1;
    struct ifreq ifr;
    if (memset_s((void *)&ifr, sizeof(ifr), 0, sizeof(ifr)) != EOK) {
        printf("memset_s 1 fail\n");
        return SOFTBUS_MEM_ERR;
    }

    sockFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockFd < 0) {
        printf("could not create IP socket\n");
        return SOFTBUS_NETWORK_CREATE_SOCKET_FAILED;
    }
    if (strncpy_s(ifr.ifr_name, sizeof(ifr.ifr_name), "eth0", strlen("eth0")) != EOK) {
        printf("strncpy_s fail\n");
        close(sockFd);
        return SOFTBUS_STRCPY_ERR;
    }

    if (ioctl(sockFd, SIOCGIFFLAGS, &ifr) < 0) {
        printf("error to get eth0 flags\n");
        close(sockFd);
        return SOFTBUS_ADAPTER_ERR;
    }

    ifr.ifr_flags &= ~(IFF_UP);
    if (ioctl(sockFd, SIOCSIFFLAGS, &ifr) < 0) {
        printf("error to set eth0 down\n");
        close(sockFd);
        return SOFTBUS_ADAPTER_ERR;
    }
    close(sockFd);
    return SOFTBUS_OK;
}

/*
 * @tc.name: NET_BusCenter_IP_Change_Monitor_Test_001
 * @tc.desc: Verify IP change monitor correctly updates local IP address
 *           when IP is set to 192.168.50.10
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: AR000FK6J3
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_IP_Change_Monitor_Test_001, TestSize.Level0)
{
    char ipAddr[IP_LEN] = { 0 };
    char ip[IP_LEN] = "192.168.50.10";

    EXPECT_TRUE(SetIpaddr(ip) == SOFTBUS_OK);
    sleep(2);
    EXPECT_TRUE(LnnGetLocalStrInfoByIfnameIdx(STRING_KEY_IP, ipAddr, IP_LEN, WLAN_IF) == SOFTBUS_OK);
    EXPECT_TRUE(strncmp(ipAddr, ip, IP_LEN) == 0);
}

/*
 * @tc.name: NET_BusCenter_IP_Change_Monitor_Test_002
 * @tc.desc: Verify IP change monitor correctly updates local IP address
 *           to 127.0.0.1 when IP is set to 0.0.0.0
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: AR000FK6J3
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_IP_Change_Monitor_Test_002, TestSize.Level0)
{
    char ipAddr[IP_LEN] = { 0 };
    char ip[IP_LEN] = "0.0.0.0";
    EXPECT_TRUE(SetIpaddr(ip) == SOFTBUS_OK);
    sleep(2);
    EXPECT_TRUE(LnnGetLocalStrInfoByIfnameIdx(STRING_KEY_IP, ipAddr, IP_LEN, WLAN_IF) == SOFTBUS_OK);
    EXPECT_TRUE(strncmp(ipAddr, "127.0.0.1", IP_LEN) == 0);
}

/*
 * @tc.name: NET_BusCenter_IP_Change_Monitor_Test_003
 * @tc.desc: Verify IP change monitor correctly updates local IP address
 *           to 127.0.0.1 when network interface is brought down
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: AR000FK6J3
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_IP_Change_Monitor_Test_003, TestSize.Level0)
{
    char ipAddr[IP_LEN] = { 0 };
    EXPECT_TRUE(SetIpDown() == SOFTBUS_OK);
    sleep(2);
    EXPECT_TRUE(LnnGetLocalStrInfoByIfnameIdx(STRING_KEY_IP, ipAddr, IP_LEN, WLAN_IF) == SOFTBUS_OK);
    EXPECT_TRUE(strncmp(ipAddr, "127.0.0.1", IP_LEN) == 0);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Device_Info_Test_001
 * @tc.desc: Verify LnnGetLocalDeviceInfo returns valid local device
 *           basic info with non-empty network ID
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Device_Info_Test_001, TestSize.Level1)
{
    NodeBasicInfo info;
    EXPECT_EQ(EOK, memset_s(&info, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo)));
    int32_t ret = LnnGetLocalDeviceInfo(&info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(strlen(info.networkId) > 0);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Str_Info_Test_001
 * @tc.desc: Verify LnnGetLocalStrInfo retrieves local string info
 *           for STRING_KEY_DEV_UDID and STRING_KEY_NETWORKID
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Str_Info_Test_001, TestSize.Level1)
{
    char udid[UDID_BUF_LEN] = { 0 };
    int32_t ret = LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, udid, UDID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(strlen(udid) > 0);

    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    ret = LnnGetLocalStrInfo(STRING_KEY_NETWORKID, networkId, NETWORK_ID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(strlen(networkId) > 0);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Str_Info_Test_002
 * @tc.desc: Verify LnnGetLocalStrInfo retrieves local string info
 *           for STRING_KEY_DEV_NAME and STRING_KEY_DEV_TYPE
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Str_Info_Test_002, TestSize.Level1)
{
    char devName[DEVICE_NAME_BUF_LEN] = { 0 };
    int32_t ret = LnnGetLocalStrInfo(STRING_KEY_DEV_NAME, devName, DEVICE_NAME_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);

    char devType[DEVICE_TYPE_BUF_LEN] = { 0 };
    ret = LnnGetLocalStrInfo(STRING_KEY_DEV_TYPE, devType, DEVICE_TYPE_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Num_Info_Test_001
 * @tc.desc: Verify LnnGetLocalNumInfo retrieves local numeric info
 *           for NUM_KEY_DEV_TYPE_ID
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Num_Info_Test_001, TestSize.Level1)
{
    int32_t devTypeId = 0;
    int32_t ret = LnnGetLocalNumInfo(NUM_KEY_DEV_TYPE_ID, &devTypeId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(devTypeId >= 0);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Num_Info_Test_002
 * @tc.desc: Verify LnnGetLocalNumInfo retrieves local numeric info
 *           for NUM_KEY_OS_TYPE
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Num_Info_Test_002, TestSize.Level1)
{
    int32_t osType = 0;
    int32_t ret = LnnGetLocalNumInfo(NUM_KEY_OS_TYPE, &osType);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Num_Info_By_Ifname_Test_001
 * @tc.desc: Verify LnnGetLocalNumInfoByIfnameIdx retrieves port info
 *           for WLAN interface with NUM_KEY_AUTH_PORT
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Num_Info_By_Ifname_Test_001, TestSize.Level1)
{
    int32_t authPort = 0;
    int32_t ret = LnnGetLocalNumInfoByIfnameIdx(NUM_KEY_AUTH_PORT, &authPort, WLAN_IF);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Node_Info_Test_001
 * @tc.desc: Verify LnnGetLocalNodeInfo returns non-null local
 *           node info pointer
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Node_Info_Test_001, TestSize.Level1)
{
    const NodeInfo *info = LnnGetLocalNodeInfo();
    EXPECT_NE(info, nullptr);
    EXPECT_TRUE(strlen(LnnGetDeviceUdid(info)) > 0);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Node_Info_Safe_Test_001
 * @tc.desc: Verify LnnGetLocalNodeInfoSafe copies local node info
 *           to provided buffer correctly
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Node_Info_Safe_Test_001, TestSize.Level1)
{
    NodeInfo info;
    EXPECT_EQ(EOK, memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo)));
    int32_t ret = LnnGetLocalNodeInfoSafe(&info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(strlen(info.networkId) > 0);
}

/*
 * @tc.name: NET_BusCenter_Get_All_Online_Node_Info_Test_001
 * @tc.desc: Verify LnnGetAllOnlineNodeInfo returns successfully
 *           with valid output parameters
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_All_Online_Node_Info_Test_001, TestSize.Level1)
{
    NodeBasicInfo *info = nullptr;
    int32_t infoNum = 0;
    int32_t ret = LnnGetAllOnlineNodeInfo(&info, &infoNum);
    EXPECT_EQ(ret, SOFTBUS_OK);
    if (info != nullptr && infoNum > 0) {
        EXPECT_TRUE(strlen(info[0].networkId) > 0);
    }
    SoftBusFree(info);
}

/*
 * @tc.name: NET_BusCenter_Get_All_Online_Node_Num_Test_001
 * @tc.desc: Verify LnnGetAllOnlineNodeNum returns successfully
 *           and node count is non-negative
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_All_Online_Node_Num_Test_001, TestSize.Level1)
{
    int32_t nodeNum = 0;
    int32_t ret = LnnGetAllOnlineNodeNum(&nodeNum);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(nodeNum >= 0);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Str_Info_Invalid_Param_Test_001
 * @tc.desc: Verify LnnGetLocalStrInfo returns error when called
 *           with null buffer
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Str_Info_Invalid_Param_Test_001, TestSize.Level2)
{
    int32_t ret = LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, nullptr, UDID_BUF_LEN);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Num_Info_Invalid_Param_Test_001
 * @tc.desc: Verify LnnGetLocalNumInfo returns error when called
 *           with null output pointer
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Num_Info_Invalid_Param_Test_001, TestSize.Level2)
{
    int32_t ret = LnnGetLocalNumInfo(NUM_KEY_DEV_TYPE_ID, nullptr);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Str_Info_By_Ifname_Test_001
 * @tc.desc: Verify LnnGetLocalStrInfoByIfnameIdx retrieves net
 *           interface name for WLAN interface
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Str_Info_By_Ifname_Test_001, TestSize.Level1)
{
    char netIfName[NET_IF_NAME_LEN] = { 0 };
    int32_t ret = LnnGetLocalStrInfoByIfnameIdx(STRING_KEY_NET_IF_NAME, netIfName, NET_IF_NAME_LEN, WLAN_IF);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Num64_Info_Test_001
 * @tc.desc: Verify LnnGetLocalNum64Info retrieves local int64
 *           numeric info for NUM_KEY_NETWORK_ID_TIMESTAMP
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Num64_Info_Test_001, TestSize.Level1)
{
    int64_t timestamp = 0;
    int32_t ret = LnnGetLocalNum64Info(NUM_KEY_NETWORK_ID_TIMESTAMP, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(timestamp >= 0);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_NumU64_Info_Test_001
 * @tc.desc: Verify LnnGetLocalNumU64Info retrieves local uint64
 *           numeric info for NUM_KEY_HUKS_TIME
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_NumU64_Info_Test_001, TestSize.Level1)
{
    uint64_t huksTime = 0;
    int32_t ret = LnnGetLocalNumU64Info(NUM_KEY_HUKS_TIME, &huksTime);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Num16_Info_Test_001
 * @tc.desc: Verify LnnGetLocalNum16Info retrieves local int16
 *           numeric info for NUM_KEY_DATA_CHANGE_FLAG
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Num16_Info_Test_001, TestSize.Level1)
{
    int16_t dataChangeFlag = 0;
    int32_t ret = LnnGetLocalNum16Info(NUM_KEY_DATA_CHANGE_FLAG, &dataChangeFlag);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(dataChangeFlag >= 0);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_NumU16_Info_Test_001
 * @tc.desc: Verify LnnGetLocalNumU16Info retrieves local uint16
 *           numeric info for NUM_KEY_DATA_DYNAMIC_LEVEL
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_NumU16_Info_Test_001, TestSize.Level1)
{
    uint16_t dataDynamicLevel = 0;
    int32_t ret = LnnGetLocalNumU16Info(NUM_KEY_DATA_DYNAMIC_LEVEL, &dataDynamicLevel);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_NumU32_Info_Test_001
 * @tc.desc: Verify LnnGetLocalNumU32Info retrieves local uint32
 *           numeric info for NUM_KEY_DATA_SWITCH_LEVEL
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_NumU32_Info_Test_001, TestSize.Level1)
{
    uint32_t dataSwitchLevel = 0;
    int32_t ret = LnnGetLocalNumU32Info(NUM_KEY_DATA_SWITCH_LEVEL, &dataSwitchLevel);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Bool_Info_Test_001
 * @tc.desc: Verify LnnGetLocalBoolInfo retrieves local boolean
 *           info for BOOL_KEY_TLV_NEGOTIATION
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Bool_Info_Test_001, TestSize.Level1)
{
    bool tlvNegotiation = false;
    int32_t ret = LnnGetLocalBoolInfo(BOOL_KEY_TLV_NEGOTIATION, &tlvNegotiation, sizeof(bool));
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Byte_Info_Test_001
 * @tc.desc: Verify LnnGetLocalByteInfo retrieves local byte info
 *           for BYTE_KEY_ACCOUNT_HASH
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Byte_Info_Test_001, TestSize.Level1)
{
    uint8_t accountHash[SHA_256_HASH_LEN] = { 0 };
    int32_t ret = LnnGetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, accountHash, SHA_256_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Node_Info_Helper_Test_001
 * @tc.desc: Verify node info helper functions return valid values
 *           from local node info for UUID and BT MAC
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Node_Info_Helper_Test_001, TestSize.Level1)
{
    const NodeInfo *info = LnnGetLocalNodeInfo();
    ASSERT_NE(info, nullptr);
    const char *uuid = LnnGetDeviceUuid(info);
    EXPECT_NE(uuid, nullptr);
    const char *btMac = LnnGetBtMac(info);
    EXPECT_NE(btMac, nullptr);
    const char *bleMac = LnnGetBleMac(info);
    EXPECT_NE(bleMac, nullptr);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Node_Info_Helper_Test_002
 * @tc.desc: Verify node info helper functions return valid WiFi
 *           IP and net interface name from local node info
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Node_Info_Helper_Test_002, TestSize.Level1)
{
    const NodeInfo *info = LnnGetLocalNodeInfo();
    ASSERT_NE(info, nullptr);
    const char *wifiIp = LnnGetWiFiIp(info, WLAN_IF);
    EXPECT_NE(wifiIp, nullptr);
    const char *netIfName = LnnGetNetIfName(info, WLAN_IF);
    EXPECT_NE(netIfName, nullptr);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Node_Info_Helper_Test_003
 * @tc.desc: Verify node info helper functions return valid port
 *           values from local node info for WLAN interface
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Node_Info_Helper_Test_003, TestSize.Level1)
{
    const NodeInfo *info = LnnGetLocalNodeInfo();
    ASSERT_NE(info, nullptr);
    int32_t authPort = LnnGetAuthPort(info, WLAN_IF);
    EXPECT_TRUE(authPort >= 0);
    int32_t sessionPort = LnnGetSessionPort(info, WLAN_IF);
    EXPECT_TRUE(sessionPort >= 0);
    int32_t proxyPort = LnnGetProxyPort(info, WLAN_IF);
    EXPECT_TRUE(proxyPort >= 0);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Node_Info_Helper_Test_004
 * @tc.desc: Verify node info helper functions return valid P2P
 *           info from local node info
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Node_Info_Helper_Test_004, TestSize.Level1)
{
    const NodeInfo *info = LnnGetLocalNodeInfo();
    ASSERT_NE(info, nullptr);
    int32_t p2pRole = LnnGetP2pRole(info);
    EXPECT_TRUE(p2pRole >= 0);
    const char *p2pMac = LnnGetP2pMac(info);
    EXPECT_NE(p2pMac, nullptr);
    const char *p2pGoMac = LnnGetP2pGoMac(info);
    EXPECT_NE(p2pGoMac, nullptr);
    const char *wifiDirectAddr = LnnGetWifiDirectAddr(info);
    EXPECT_NE(wifiDirectAddr, nullptr);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Node_Info_Helper_Test_005
 * @tc.desc: Verify node info helper functions return valid master
 *           UDID and online state from local node info
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Node_Info_Helper_Test_005, TestSize.Level1)
{
    const NodeInfo *info = LnnGetLocalNodeInfo();
    ASSERT_NE(info, nullptr);
    const char *masterUdid = LnnGetMasterUdid(info);
    EXPECT_NE(masterUdid, nullptr);
    EXPECT_TRUE(LnnIsNodeOnline(info));
}

/*
 * @tc.name: NET_BusCenter_Set_Local_Str_Info_Test_001
 * @tc.desc: Verify LnnSetLocalStrInfo sets and gets local string
 *           info for STRING_KEY_DEV_NAME consistently
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Set_Local_Str_Info_Test_001, TestSize.Level1)
{
    char devName[DEVICE_NAME_BUF_LEN] = { 0 };
    int32_t ret = LnnGetLocalStrInfo(STRING_KEY_DEV_NAME, devName, DEVICE_NAME_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnSetLocalStrInfo(STRING_KEY_DEV_NAME, devName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    char devNameAfter[DEVICE_NAME_BUF_LEN] = { 0 };
    ret = LnnGetLocalStrInfo(STRING_KEY_DEV_NAME, devNameAfter, DEVICE_NAME_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_STREQ(devName, devNameAfter);
}

/*
 * @tc.name: NET_BusCenter_Set_Local_Num_Info_Test_001
 * @tc.desc: Verify LnnSetLocalNumInfo sets and gets local numeric
 *           info for NUM_KEY_P2P_ROLE consistently
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Set_Local_Num_Info_Test_001, TestSize.Level1)
{
    int32_t p2pRole = 0;
    int32_t ret = LnnGetLocalNumInfo(NUM_KEY_P2P_ROLE, &p2pRole);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnSetLocalNumInfo(NUM_KEY_P2P_ROLE, p2pRole);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t p2pRoleAfter = 0;
    ret = LnnGetLocalNumInfo(NUM_KEY_P2P_ROLE, &p2pRoleAfter);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(p2pRole, p2pRoleAfter);
}

/*
 * @tc.name: NET_BusCenter_Set_Local_Num64_Info_Test_001
 * @tc.desc: Verify LnnSetLocalNum64Info sets and gets local int64
 *           info for NUM_KEY_NETWORK_ID_TIMESTAMP consistently
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Set_Local_Num64_Info_Test_001, TestSize.Level1)
{
    int64_t timestamp = 0;
    int32_t ret = LnnGetLocalNum64Info(NUM_KEY_NETWORK_ID_TIMESTAMP, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnSetLocalNum64Info(NUM_KEY_NETWORK_ID_TIMESTAMP, timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int64_t timestampAfter = 0;
    ret = LnnGetLocalNum64Info(NUM_KEY_NETWORK_ID_TIMESTAMP, &timestampAfter);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(timestamp, timestampAfter);
}

/*
 * @tc.name: NET_BusCenter_Set_Local_Num16_Info_Test_001
 * @tc.desc: Verify LnnSetLocalNum16Info sets and gets local int16
 *           info for NUM_KEY_DATA_CHANGE_FLAG consistently
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Set_Local_Num16_Info_Test_001, TestSize.Level1)
{
    int16_t dataChangeFlag = 0;
    int32_t ret = LnnGetLocalNum16Info(NUM_KEY_DATA_CHANGE_FLAG, &dataChangeFlag);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnSetLocalNum16Info(NUM_KEY_DATA_CHANGE_FLAG, dataChangeFlag);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int16_t dataChangeFlagAfter = 0;
    ret = LnnGetLocalNum16Info(NUM_KEY_DATA_CHANGE_FLAG, &dataChangeFlagAfter);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(dataChangeFlag, dataChangeFlagAfter);
}

/*
 * @tc.name: NET_BusCenter_Set_Local_NumU16_Info_Test_001
 * @tc.desc: Verify LnnSetLocalNumU16Info sets and gets local uint16
 *           info for NUM_KEY_DATA_DYNAMIC_LEVEL consistently
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Set_Local_NumU16_Info_Test_001, TestSize.Level1)
{
    uint16_t dataDynamicLevel = 0;
    int32_t ret = LnnGetLocalNumU16Info(NUM_KEY_DATA_DYNAMIC_LEVEL, &dataDynamicLevel);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnSetLocalNumU16Info(NUM_KEY_DATA_DYNAMIC_LEVEL, dataDynamicLevel);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint16_t dataDynamicLevelAfter = 0;
    ret = LnnGetLocalNumU16Info(NUM_KEY_DATA_DYNAMIC_LEVEL, &dataDynamicLevelAfter);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(dataDynamicLevel, dataDynamicLevelAfter);
}

/*
 * @tc.name: NET_BusCenter_Set_Local_NumU32_Info_Test_001
 * @tc.desc: Verify LnnSetLocalNumU32Info sets and gets local uint32
 *           info for NUM_KEY_DATA_SWITCH_LEVEL consistently
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Set_Local_NumU32_Info_Test_001, TestSize.Level1)
{
    uint32_t dataSwitchLevel = 0;
    int32_t ret = LnnGetLocalNumU32Info(NUM_KEY_DATA_SWITCH_LEVEL, &dataSwitchLevel);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnSetLocalNumU32Info(NUM_KEY_DATA_SWITCH_LEVEL, dataSwitchLevel);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint32_t dataSwitchLevelAfter = 0;
    ret = LnnGetLocalNumU32Info(NUM_KEY_DATA_SWITCH_LEVEL, &dataSwitchLevelAfter);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(dataSwitchLevel, dataSwitchLevelAfter);
}

/*
 * @tc.name: NET_BusCenter_Set_Local_Str_Info_Invalid_Param_Test_001
 * @tc.desc: Verify LnnSetLocalStrInfo returns error when called
 *           with null value
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Set_Local_Str_Info_Invalid_Param_Test_001, TestSize.Level2)
{
    int32_t ret = LnnSetLocalStrInfo(STRING_KEY_DEV_NAME, nullptr);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Str_Info_By_Ifname_Invalid_Test_001
 * @tc.desc: Verify LnnGetLocalStrInfoByIfnameIdx returns error when
 *           called with invalid interface index
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Str_Info_By_Ifname_Invalid_Test_001, TestSize.Level2)
{
    char ipAddr[IP_LEN] = { 0 };
    int32_t ret = LnnGetLocalStrInfoByIfnameIdx(STRING_KEY_IP, ipAddr, IP_LEN, -1);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Num_Info_By_Ifname_Invalid_Test_001
 * @tc.desc: Verify LnnGetLocalNumInfoByIfnameIdx returns error when
 *           called with invalid interface index
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Num_Info_By_Ifname_Invalid_Test_001, TestSize.Level2)
{
    int32_t authPort = 0;
    int32_t ret = LnnGetLocalNumInfoByIfnameIdx(NUM_KEY_AUTH_PORT, &authPort, -1);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NET_BusCenter_Is_Master_Node_Test_001
 * @tc.desc: Verify LnnIsMasterNode returns valid boolean result
 *           after bus center initialization
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Is_Master_Node_Test_001, TestSize.Level1)
{
    bool isMaster = LnnIsMasterNode();
    EXPECT_TRUE(isMaster == true || isMaster == false);
}

/*
 * @tc.name: NET_BusCenter_Get_All_Online_And_Meta_Node_Info_Test_001
 * @tc.desc: Verify LnnGetAllOnlineAndMetaNodeInfo returns successfully
 *           with valid output parameters
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_All_Online_And_Meta_Node_Info_Test_001, TestSize.Level1)
{
    NodeBasicInfo *info = nullptr;
    int32_t infoNum = 0;
    int32_t ret = LnnGetAllOnlineAndMetaNodeInfo(&info, &infoNum);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(infoNum >= 0);
    SoftBusFree(info);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Str_Info_Test_003
 * @tc.desc: Verify LnnGetLocalStrInfo retrieves local string info
 *           for STRING_KEY_BT_MAC and STRING_KEY_UUID
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Str_Info_Test_003, TestSize.Level1)
{
    char btMac[BT_MAC_LEN] = { 0 };
    int32_t ret = LnnGetLocalStrInfo(STRING_KEY_BT_MAC, btMac, BT_MAC_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);

    char uuid[UUID_BUF_LEN] = { 0 };
    ret = LnnGetLocalStrInfo(STRING_KEY_UUID, uuid, UUID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Str_Info_Test_004
 * @tc.desc: Verify LnnGetLocalStrInfo retrieves local string info
 *           for STRING_KEY_NET_IF_NAME and STRING_KEY_MASTER_NODE_UDID
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Str_Info_Test_004, TestSize.Level1)
{
    char netIfName[NET_IF_NAME_LEN] = { 0 };
    int32_t ret = LnnGetLocalStrInfo(STRING_KEY_NET_IF_NAME, netIfName, NET_IF_NAME_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);

    char masterUdid[UDID_BUF_LEN] = { 0 };
    ret = LnnGetLocalStrInfo(STRING_KEY_MASTER_NODE_UDID, masterUdid, UDID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Num_Info_Test_003
 * @tc.desc: Verify LnnGetLocalNumInfo retrieves local numeric info
 *           for NUM_KEY_SESSION_PORT, NUM_KEY_AUTH_PORT and NUM_KEY_PROXY_PORT
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Num_Info_Test_003, TestSize.Level1)
{
    int32_t sessionPort = 0;
    int32_t ret = LnnGetLocalNumInfo(NUM_KEY_SESSION_PORT, &sessionPort);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(sessionPort >= 0);

    int32_t authPort = 0;
    ret = LnnGetLocalNumInfo(NUM_KEY_AUTH_PORT, &authPort);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(authPort >= 0);

    int32_t proxyPort = 0;
    ret = LnnGetLocalNumInfo(NUM_KEY_PROXY_PORT, &proxyPort);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(proxyPort >= 0);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Num_Info_Test_004
 * @tc.desc: Verify LnnGetLocalNumInfo retrieves local numeric info
 *           for NUM_KEY_MASTER_NODE_WEIGHT and NUM_KEY_FEATURE_CAPA
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Num_Info_Test_004, TestSize.Level1)
{
    int32_t masterWeight = 0;
    int32_t ret = LnnGetLocalNumInfo(NUM_KEY_MASTER_NODE_WEIGHT, &masterWeight);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(masterWeight >= 0);

    int32_t featureCapa = 0;
    ret = LnnGetLocalNumInfo(NUM_KEY_FEATURE_CAPA, &featureCapa);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Num_Info_By_Ifname_Test_002
 * @tc.desc: Verify LnnGetLocalNumInfoByIfnameIdx retrieves port info
 *           for WLAN interface with NUM_KEY_SESSION_PORT and NUM_KEY_PROXY_PORT
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Num_Info_By_Ifname_Test_002, TestSize.Level1)
{
    int32_t sessionPort = 0;
    int32_t ret = LnnGetLocalNumInfoByIfnameIdx(NUM_KEY_SESSION_PORT, &sessionPort, WLAN_IF);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(sessionPort >= 0);

    int32_t proxyPort = 0;
    ret = LnnGetLocalNumInfoByIfnameIdx(NUM_KEY_PROXY_PORT, &proxyPort, WLAN_IF);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(proxyPort >= 0);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Str_Info_By_Ifname_Test_002
 * @tc.desc: Verify LnnGetLocalStrInfoByIfnameIdx retrieves IP address
 *           for WLAN interface
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Str_Info_By_Ifname_Test_002, TestSize.Level1)
{
    char ipAddr[IP_LEN] = { 0 };
    int32_t ret = LnnGetLocalStrInfoByIfnameIdx(STRING_KEY_IP, ipAddr, IP_LEN, WLAN_IF);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(strlen(ipAddr) > 0);
}

/*
 * @tc.name: NET_BusCenter_Set_Local_Str_Info_By_Ifname_Test_001
 * @tc.desc: Verify LnnSetLocalStrInfoByIfnameIdx sets and gets IP
 *           address for WLAN interface consistently
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Set_Local_Str_Info_By_Ifname_Test_001, TestSize.Level1)
{
    char ipAddr[IP_LEN] = { 0 };
    int32_t ret = LnnGetLocalStrInfoByIfnameIdx(STRING_KEY_IP, ipAddr, IP_LEN, WLAN_IF);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnSetLocalStrInfoByIfnameIdx(STRING_KEY_IP, ipAddr, WLAN_IF);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NET_BusCenter_Set_Local_Num_Info_By_Ifname_Test_001
 * @tc.desc: Verify LnnSetLocalNumInfoByIfnameIdx sets and gets port
 *           info for WLAN interface consistently
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Set_Local_Num_Info_By_Ifname_Test_001, TestSize.Level1)
{
    int32_t authPort = 0;
    int32_t ret = LnnGetLocalNumInfoByIfnameIdx(NUM_KEY_AUTH_PORT, &authPort, WLAN_IF);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnSetLocalNumInfoByIfnameIdx(NUM_KEY_AUTH_PORT, authPort, WLAN_IF);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t authPortAfter = 0;
    ret = LnnGetLocalNumInfoByIfnameIdx(NUM_KEY_AUTH_PORT, &authPortAfter, WLAN_IF);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(authPort, authPortAfter);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Str_Info_Invalid_Param_Test_002
 * @tc.desc: Verify LnnGetLocalStrInfo returns error when called
 *           with zero buffer length
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Str_Info_Invalid_Param_Test_002, TestSize.Level2)
{
    char buf[UDID_BUF_LEN] = { 0 };
    int32_t ret = LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, buf, 0);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NET_BusCenter_Set_Local_Byte_Info_Test_001
 * @tc.desc: Verify LnnSetLocalByteInfo sets and gets local byte info
 *           for BYTE_KEY_ACCOUNT_HASH consistently
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Set_Local_Byte_Info_Test_001, TestSize.Level1)
{
    uint8_t accountHash[SHA_256_HASH_LEN] = { 0 };
    int32_t ret = LnnGetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, accountHash, SHA_256_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnSetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, accountHash, SHA_256_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint8_t accountHashAfter[SHA_256_HASH_LEN] = { 0 };
    ret = LnnGetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, accountHashAfter, SHA_256_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(memcmp(accountHash, accountHashAfter, SHA_256_HASH_LEN), 0);
}

/*
 * @tc.name: NET_BusCenter_Get_Remote_Str_Info_Invalid_Test_001
 * @tc.desc: Verify LnnGetRemoteStrInfo returns error when called
 *           with null network ID
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Remote_Str_Info_Invalid_Test_001, TestSize.Level2)
{
    char buf[UDID_BUF_LEN] = { 0 };
    int32_t ret = LnnGetRemoteStrInfo(nullptr, STRING_KEY_DEV_UDID, buf, UDID_BUF_LEN);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NET_BusCenter_Get_Remote_Num_Info_Invalid_Test_001
 * @tc.desc: Verify LnnGetRemoteNumInfo returns error when called
 *           with null network ID
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Remote_Num_Info_Invalid_Test_001, TestSize.Level2)
{
    int32_t value = 0;
    int32_t ret = LnnGetRemoteNumInfo(nullptr, NUM_KEY_DEV_TYPE_ID, &value);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NET_BusCenter_Get_Remote_Bool_Info_Invalid_Test_001
 * @tc.desc: Verify LnnGetRemoteBoolInfo returns error when called
 *           with null network ID
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Remote_Bool_Info_Invalid_Test_001, TestSize.Level2)
{
    bool value = false;
    int32_t ret = LnnGetRemoteBoolInfo(nullptr, BOOL_KEY_TLV_NEGOTIATION, &value);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NET_BusCenter_Get_Remote_Byte_Info_Invalid_Test_001
 * @tc.desc: Verify LnnGetRemoteByteInfo returns error when called
 *           with null network ID
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Remote_Byte_Info_Invalid_Test_001, TestSize.Level2)
{
    uint8_t buf[SHA_256_HASH_LEN] = { 0 };
    int32_t ret = LnnGetRemoteByteInfo(nullptr, BYTE_KEY_ACCOUNT_HASH, buf, SHA_256_HASH_LEN);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NET_BusCenter_Get_Remote_NumU32_Info_Invalid_Test_001
 * @tc.desc: Verify LnnGetRemoteNumU32Info returns error when called
 *           with null network ID
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Remote_NumU32_Info_Invalid_Test_001, TestSize.Level2)
{
    uint32_t value = 0;
    int32_t ret = LnnGetRemoteNumU32Info(nullptr, NUM_KEY_DATA_SWITCH_LEVEL, &value);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NET_BusCenter_Get_Remote_NumU64_Info_Invalid_Test_001
 * @tc.desc: Verify LnnGetRemoteNumU64Info returns error when called
 *           with null network ID
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Remote_NumU64_Info_Invalid_Test_001, TestSize.Level2)
{
    uint64_t value = 0;
    int32_t ret = LnnGetRemoteNumU64Info(nullptr, NUM_KEY_HUKS_TIME, &value);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NET_BusCenter_Get_Remote_Num16_Info_Invalid_Test_001
 * @tc.desc: Verify LnnGetRemoteNum16Info returns error when called
 *           with null network ID
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Remote_Num16_Info_Invalid_Test_001, TestSize.Level2)
{
    int16_t value = 0;
    int32_t ret = LnnGetRemoteNum16Info(nullptr, NUM_KEY_DATA_CHANGE_FLAG, &value);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Node_Info_Helper_Test_006
 * @tc.desc: Verify node info helper functions return valid WiFi
 *           config, channel list and STA frequency from local node info
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Node_Info_Helper_Test_006, TestSize.Level1)
{
    const NodeInfo *info = LnnGetLocalNodeInfo();
    ASSERT_NE(info, nullptr);
    const char *wifiCfg = LnnGetWifiCfg(info);
    EXPECT_NE(wifiCfg, nullptr);
    const char *chanList5g = LnnGetChanList5g(info);
    EXPECT_NE(chanList5g, nullptr);
    int32_t staFrequency = LnnGetStaFrequency(info);
    EXPECT_TRUE(staFrequency >= 0);
}

/*
 * @tc.name: NET_BusCenter_Get_Remote_Str_Info_By_Ifname_Invalid_Test_001
 * @tc.desc: Verify LnnGetRemoteStrInfoByIfnameIdx returns error when
 *           called with null network ID
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Remote_Str_Info_By_Ifname_Invalid_Test_001, TestSize.Level2)
{
    char buf[IP_LEN] = { 0 };
    int32_t ret = LnnGetRemoteStrInfoByIfnameIdx(nullptr, STRING_KEY_IP, buf, IP_LEN, WLAN_IF);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NET_BusCenter_Get_Remote_Num_Info_By_Ifname_Invalid_Test_001
 * @tc.desc: Verify LnnGetRemoteNumInfoByIfnameIdx returns error when
 *           called with null network ID
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Remote_Num_Info_By_Ifname_Invalid_Test_001, TestSize.Level2)
{
    int32_t value = 0;
    int32_t ret = LnnGetRemoteNumInfoByIfnameIdx(nullptr, NUM_KEY_AUTH_PORT, &value, WLAN_IF);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NET_BusCenter_Get_Remote_Bool_Info_Ignore_Online_Invalid_Test_001
 * @tc.desc: Verify LnnGetRemoteBoolInfoIgnoreOnline returns error when
 *           called with null network ID
 * @tc.type: FUNC
 * @tc.level: Level2
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Remote_Bool_Info_Ignore_Online_Invalid_Test_001, TestSize.Level2)
{
    bool value = false;
    int32_t ret = LnnGetRemoteBoolInfoIgnoreOnline(nullptr, BOOL_KEY_TLV_NEGOTIATION, &value);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Str_Info_Test_005
 * @tc.desc: Verify LnnGetLocalStrInfo retrieves local string info
 *           for STRING_KEY_BLE_MAC and STRING_KEY_WIFIDIRECT_ADDR
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Str_Info_Test_005, TestSize.Level1)
{
    char bleMac[MAC_LEN] = { 0 };
    int32_t ret = LnnGetLocalStrInfo(STRING_KEY_BLE_MAC, bleMac, MAC_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);

    char wifiDirectAddr[MAC_LEN] = { 0 };
    ret = LnnGetLocalStrInfo(STRING_KEY_WIFIDIRECT_ADDR, wifiDirectAddr, MAC_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Num_Info_Test_005
 * @tc.desc: Verify LnnGetLocalNumInfo retrieves local numeric info
 *           for NUM_KEY_STA_FREQUENCY and NUM_KEY_P2P_ROLE
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Num_Info_Test_005, TestSize.Level1)
{
    int32_t staFrequency = 0;
    int32_t ret = LnnGetLocalNumInfo(NUM_KEY_STA_FREQUENCY, &staFrequency);
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t p2pRole = 0;
    ret = LnnGetLocalNumInfo(NUM_KEY_P2P_ROLE, &p2pRole);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NET_BusCenter_Get_Local_Num_Info_Test_006
 * @tc.desc: Verify LnnGetLocalNumInfo retrieves local numeric info
 *           for NUM_KEY_NET_CAP and NUM_KEY_DEVICE_SECURITY_LEVEL
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(NetBusCenterTest, NET_BusCenter_Get_Local_Num_Info_Test_006, TestSize.Level1)
{
    int32_t netCap = 0;
    int32_t ret = LnnGetLocalNumInfo(NUM_KEY_NET_CAP, &netCap);
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t securityLevel = 0;
    ret = LnnGetLocalNumInfo(NUM_KEY_DEVICE_SECURITY_LEVEL, &securityLevel);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
} // namespace OHOS
