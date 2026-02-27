/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <cstddef>
#include <cstring>

#include "comm_log.h"
#include "fuzz_data_generator.h"
#include "fuzz_environment.h"
#include "lnn_net_builder.h"
#include "securec.h"

using namespace std;
#define UDID_HASH_LEN 32

static const std::vector<ConnectionAddrType> CONNECTION_ADDR_TYPE_LIST = { CONNECTION_ADDR_WLAN, CONNECTION_ADDR_BR,
    CONNECTION_ADDR_BLE, CONNECTION_ADDR_ETH, CONNECTION_ADDR_SESSION, CONNECTION_ADDR_USB,
    CONNECTION_ADDR_SESSION_WITH_KEY, CONNECTION_ADDR_SLE, CONNECTION_ADDR_NCM };

#ifdef LNN_NET_BUILDER_FULL_TEST
static const std::vector<LnnSyncInfoType> LNN_SYNC_INFO_TYPE_LIST = {
    LNN_INFO_TYPE_CAPABILITY,
    LNN_INFO_TYPE_CONNECTION_INFO,
    LNN_INFO_TYPE_DEVICE_NAME,
    LNN_INFO_TYPE_BATTERY_INFO,
    LNN_INFO_TYPE_SCREEN_STATUS,
    LNN_INFO_TYPE_OFFLINE,
    LNN_INFO_TYPE_P2P_INFO,
    LNN_INFO_TYPE_CHANNEL_NOISE_INFO,
    LNN_INFO_TYPE_NOT_TRUSTED,
    LNN_INFO_TYPE_WIFI_DIRECT,
    LNN_INFO_TYPE_NICK_NAME,
    LNN_INFO_TYPE_MASTER_ELECT,
    LNN_INFO_TYPE_BSS_TRANS,
    LNN_INFO_TYPE_TOPO_UPDATE,
    LNN_INFO_TYPE_NODE_ADDR,
    LNN_INFO_TYPE_NODE_ADDR_DETECTION,
    LNN_INFO_TYPE_SYNC_CIPHERKEY,
    LNN_INFO_TYPE_ROUTE_LSU,
    LNN_INFO_TYPE_PTK,
    LNN_INFO_TYPE_USERID,
    LNN_INFO_TYPE_SYNC_BROADCASTLINKKEY,
    LNN_INFO_TYPE_SLE_MAC,
    LNN_INFO_TYPE_COUNT
};

static const std::vector<string> NETWORKID_TEST_LIST = {
    "qqwweerrttyyuuiiooppaassddffgghhjjkkllzzxxccvvbbnnTESTLNN111",
    "qqwweerrttyyuuiiooppaassddffgghhjjkkllzzxxccvvbbnnTESTLNN222",
    "qqwweerrttyyuuiiooppaassddffgghhjjkkllzzxxccvvbbnnTESTLNN333",
    "qqwweerrttyyuuiiooppaassddffgghhjjkkllzzxxccvvbbnnTESTLNN444",
    "qqwweerrttyyuuiiooppaassddffgghhjjkkllzzxxccvvbbnnTESTLNN555",
    "qqwweerrttyyuuiiooppaassddffgghhjjkkllzzxxccvvbbnnTESTLNN666",
    "qqwweerrttyyuuiiooppaassddffgghhjjkkllzzxxccvvbbnnTESTLNN777",
    "qqwweerrttyyuuiiooppaassddffgghhjjkkllzzxxccvvbbnnTESTLNN888",
    "qqwweerrttyyuuiiooppaassddffgghhjjkkllzzxxccvvbbnnTESTLNN999",
    "qqwweerrttyyuuiiooppaassddffgghhjjkkllzzxxccvvbbnnTESTLNN000",
};
#endif

static const std::vector<string> IP_ADDR_LIST = { "192.168.1.1", "192.168.1.2", "192.168.3.1", "192.168.1.12",
    "192.168.11.12", "192.168.111.11", "192.168.110.1", "192.168.75.3", "192.168.64.24", "192.168.55.1" };

static const std::vector<BleProtocolType> BLE_PROTOCOL_TYPE_LIST = { BLE_PROTOCOL_ANY, BLE_GATT,
    BLE_COC, BLE_PROTOCOL_MAX };

static const std::vector<BlePriority> BLE_PRIORITY_LIST = { BLE_PRIORITY_DEFAULT, BLE_PRIORITY_BALANCED,
    BLE_PRIORITY_HIGH, BLE_PRIORITY_LOW_POWER, BLE_PRIORITY_MAX };

static const std::vector<string> BT_MAC_LIST = {"11:22:33:44:55:66", "12:34:56:78:9A:BC", "12:34:56:78:AA:BB",
    "13:57:9B:24:68:CD", "24:68:AC:13:57:9B", "33:44:55:66:11:22" };

static int32_t FuzzEnvInit(const uint8_t* data, size_t size)
{
    int32_t ret = LnnInitNetBuilder();
    DataGenerator::Write(data, size);
    return ret;
}

static void FuzzDeinit()
{
    LnnDeinitNetBuilder();
    DataGenerator::Clear();
}

static void GenerateUint8Array(uint8_t *data, uint8_t len)
{
    for (uint8_t i = 0; i < len; i++) {
        GenerateUint8(data[i]);
    }
}

#ifdef LNN_NET_BUILDER_FULL_TEST
static void GenerateBoolArray(bool *data, uint8_t len)
{
    for (uint8_t i = 0; i < len; i++) {
        GenerateBool(data[i]);
    }
}
#endif

namespace OHOS {
static bool ProcessFuzzAddrCommInfo(ConnectionAddr *addr)
{
    string uid;
    GenerateString(uid);
    if (strcpy_s(addr->peerUid, MAX_ACCOUNT_HASH_LEN, uid.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s peer uid failed!");
        return false;
    }
    GenerateBool(addr->deviceKeyId.hasDeviceKeyId);
    GenerateInt32(addr->deviceKeyId.localDeviceKeyId);
    GenerateInt32(addr->deviceKeyId.remoteDeviceKeyId);
    return true;
}

static bool ProcessFuzzAddrInfo(ConnectionAddr *addr)
{
    string info;
    if (!ProcessFuzzAddrCommInfo(addr)) {
        COMM_LOGE(COMM_TEST, "process addr comm info failed!");
        return false;
    }
    switch (addr->type) {
        case CONNECTION_ADDR_WLAN:
        case CONNECTION_ADDR_ETH:
            GenerateFromList(info, IP_ADDR_LIST);
            if (strcpy_s(addr->info.ip.ip, IP_STR_MAX_LEN, info.c_str()) != EOK) {
                COMM_LOGE(COMM_TEST, "strcpy_s ip failed!");
                return false;
            }
            GenerateUint16(addr->info.ip.port);
            GenerateUint8Array(addr->info.ip.udidHash, UDID_HASH_LEN);
            return true;
        case CONNECTION_ADDR_BR:
            GenerateFromList(info, BT_MAC_LIST);
            if (strcpy_s(addr->info.br.brMac, BT_MAC_LEN, info.c_str()) != EOK) {
                COMM_LOGE(COMM_TEST, "strcpy_s brMac failed!");
                return false;
            }
            return true;
        case CONNECTION_ADDR_BLE:
            GenerateFromList(info, BT_MAC_LIST);
            if (strcpy_s(addr->info.ble.bleMac, BT_MAC_LEN, info.c_str()) != EOK) {
                COMM_LOGE(COMM_TEST, "strcpy_s bleMac failed!");
                return false;
            }
            GenerateFromList(addr->info.ble.protocol, BLE_PROTOCOL_TYPE_LIST);
            GenerateUint8Array(addr->info.ble.udidHash, UDID_HASH_LEN);
            GenerateUint32(addr->info.ble.psm);
            GenerateFromList(addr->info.ble.priority, BLE_PRIORITY_LIST);
            return true;
        case CONNECTION_ADDR_SESSION:
        case CONNECTION_ADDR_SESSION_WITH_KEY:
            GenerateInt32(addr->info.session.sessionId);
            GenerateInt32(addr->info.session.channelId);
            GenerateInt32(addr->info.session.type);
            return true;
        default:
            return false;
    }
}

#ifdef LNN_NET_BUILDER_FULL_TEST
static bool GenerateFuzzNetworkId(char *id, uint32_t len)
{
    string stringData;
    GenerateString(stringData);
    const uint8_t *data = reinterpret_cast<const uint8_t *>(stringData.data());
    size_t size = stringData.size();
    if (data == nullptr || size < NETWORK_ID_BUF_LEN) {
        COMM_LOGE(COMM_TEST, "data or size is valid");
        return false;
    }
    if (strcpy_s(id, NETWORK_ID_BUF_LEN, stringData.c_str())) {
        COMM_LOGE(COMM_TEST, "cp fail!");
        return false;
    }
    return true;
}

static bool GenerateFuzzNetworkIdByList(char *id, uint32_t len)
{
    string networkId;
    GenerateFromList(networkId, NETWORKID_TEST_LIST);
    const uint8_t *data = reinterpret_cast<const uint8_t *>(networkId.data());
    size_t size = networkId.size();
    if (data == nullptr || size < NETWORK_ID_BUF_LEN) {
        COMM_LOGE(COMM_TEST, "data or size is valid");
        return false;
    }
    if (strcpy_s(id, len, networkId.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s networkid from list failed!");
        return false;
    }
    return true;
}
#endif

bool LnnNotifyDiscoveryDeviceFuzzTest()
{
    ConnectionAddr addr;
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    GenerateFromList(addr.type, CONNECTION_ADDR_TYPE_LIST);
    if (!ProcessFuzzAddrInfo(&addr)) {
        COMM_LOGE(COMM_TEST, "process fuzz addr info failed!");
        return false;
    }
    LnnDfxDeviceInfoReport infoReport;
    (void)memset_s(&infoReport, sizeof(LnnDfxDeviceInfoReport), 0, sizeof(LnnDfxDeviceInfoReport));
    bool isNeedConnect;
    GenerateBool(isNeedConnect);
    LnnNotifyDiscoveryDevice(&addr, &infoReport, isNeedConnect);
    return true;
}

#ifdef LNN_NET_BUILDER_FULL_TEST
bool LnnRequestLeaveByAddrTypeFuzzTest1()
{
    bool type[CONNECTION_ADDR_MAX] = { 0 };
    GenerateBoolArray(type, sizeof(type));
    LnnRequestLeaveByAddrType((const bool *)type, CONNECTION_ADDR_MAX, false);
    (void)memset_s(type, sizeof(type), 0, sizeof(type));
    GenerateBoolArray(type, sizeof(type));
    LnnRequestLeaveByAddrType((const bool *)type, CONNECTION_ADDR_WLAN, false);
    (void)memset_s(type, sizeof(type), 0, sizeof(type));
    GenerateBoolArray(type, sizeof(type));
    LnnRequestLeaveByAddrType((const bool *)type, CONNECTION_ADDR_BR, false);
    (void)memset_s(type, sizeof(type), 0, sizeof(type));
    GenerateBoolArray(type, sizeof(type));
    LnnRequestLeaveByAddrType((const bool *)type, CONNECTION_ADDR_BLE, false);
    (void)memset_s(type, sizeof(type), 0, sizeof(type));
    GenerateBoolArray(type, sizeof(type));
    LnnRequestLeaveByAddrType((const bool *)type, CONNECTION_ADDR_ETH, false);
    (void)memset_s(type, sizeof(type), 0, sizeof(type));
    GenerateBoolArray(type, sizeof(type));
    LnnRequestLeaveByAddrType((const bool *)type, CONNECTION_ADDR_SESSION, false);
    (void)memset_s(type, sizeof(type), 0, sizeof(type));
    GenerateBoolArray(type, sizeof(type));
    LnnRequestLeaveByAddrType((const bool *)type, CONNECTION_ADDR_USB, false);
    (void)memset_s(type, sizeof(type), 0, sizeof(type));
    GenerateBoolArray(type, sizeof(type));
    LnnRequestLeaveByAddrType((const bool *)type, CONNECTION_ADDR_SESSION_WITH_KEY, false);
    (void)memset_s(type, sizeof(type), 0, sizeof(type));
    GenerateBoolArray(type, sizeof(type));
    LnnRequestLeaveByAddrType((const bool *)type, CONNECTION_ADDR_SLE, false);
    (void)memset_s(type, sizeof(type), 0, sizeof(type));
    GenerateBoolArray(type, sizeof(type));
    LnnRequestLeaveByAddrType((const bool *)type, CONNECTION_ADDR_NCM, false);
    return true;
}

bool LnnRequestLeaveByAddrTypeFuzzTest2()
{
    bool type[CONNECTION_ADDR_MAX] = { 0 };
    ConnectionAddrType addrType = CONNECTION_ADDR_MAX;
    GenerateFromList(addrType, CONNECTION_ADDR_TYPE_LIST);
    GenerateBoolArray(type, sizeof(type));
    LnnRequestLeaveByAddrType((const bool *)type, addrType, false);
    (void)memset_s(type, sizeof(type), 0, sizeof(type));
    GenerateBoolArray(type, sizeof(type));
    GenerateFromList(addrType, CONNECTION_ADDR_TYPE_LIST);
    LnnRequestLeaveByAddrType((const bool *)type, addrType, false);
    (void)memset_s(type, sizeof(type), 0, sizeof(type));
    GenerateBoolArray(type, sizeof(type));
    GenerateFromList(addrType, CONNECTION_ADDR_TYPE_LIST);
    LnnRequestLeaveByAddrType((const bool *)type, addrType, false);
    (void)memset_s(type, sizeof(type), 0, sizeof(type));
    GenerateBoolArray(type, sizeof(type));
    GenerateFromList(addrType, CONNECTION_ADDR_TYPE_LIST);
    LnnRequestLeaveByAddrType((const bool *)type, addrType, false);
    (void)memset_s(type, sizeof(type), 0, sizeof(type));
    GenerateBoolArray(type, sizeof(type));
    GenerateFromList(addrType, CONNECTION_ADDR_TYPE_LIST);
    LnnRequestLeaveByAddrType((const bool *)type, addrType, false);
    (void)memset_s(type, sizeof(type), 0, sizeof(type));
    GenerateBoolArray(type, sizeof(type));
    GenerateFromList(addrType, CONNECTION_ADDR_TYPE_LIST);
    LnnRequestLeaveByAddrType((const bool *)type, addrType, false);
    (void)memset_s(type, sizeof(type), 0, sizeof(type));
    GenerateBoolArray(type, sizeof(type));
    GenerateFromList(addrType, CONNECTION_ADDR_TYPE_LIST);
    LnnRequestLeaveByAddrType((const bool *)type, addrType, false);
    (void)memset_s(type, sizeof(type), 0, sizeof(type));
    GenerateBoolArray(type, sizeof(type));
    GenerateFromList(addrType, CONNECTION_ADDR_TYPE_LIST);
    LnnRequestLeaveByAddrType((const bool *)type, addrType, false);
    (void)memset_s(type, sizeof(type), 0, sizeof(type));
    GenerateBoolArray(type, sizeof(type));
    GenerateFromList(addrType, CONNECTION_ADDR_TYPE_LIST);
    LnnRequestLeaveByAddrType((const bool *)type, addrType, false);
    (void)memset_s(type, sizeof(type), 0, sizeof(type));
    GenerateBoolArray(type, sizeof(type));
    GenerateFromList(addrType, CONNECTION_ADDR_TYPE_LIST);
    LnnRequestLeaveByAddrType((const bool *)type, addrType, false);
    return true;
}

bool LnnRequestLeaveSpecificFuzzTest1()
{
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnRequestLeaveSpecific(networkId, CONNECTION_ADDR_WLAN);
    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnRequestLeaveSpecific(networkId, CONNECTION_ADDR_BR);
    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnRequestLeaveSpecific(networkId, CONNECTION_ADDR_BLE);
    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnRequestLeaveSpecific(networkId, CONNECTION_ADDR_ETH);
    return true;
}

bool LnnRequestLeaveSpecificFuzzTest3()
{
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    ConnectionAddrType addrType = CONNECTION_ADDR_MAX;
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    GenerateFromList(addrType, CONNECTION_ADDR_TYPE_LIST);
    LnnRequestLeaveSpecific(networkId, addrType);
    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    GenerateFromList(addrType, CONNECTION_ADDR_TYPE_LIST);
    LnnRequestLeaveSpecific(networkId, addrType);
    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    GenerateFromList(addrType, CONNECTION_ADDR_TYPE_LIST);
    LnnRequestLeaveSpecific(networkId, addrType);
    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    GenerateFromList(addrType, CONNECTION_ADDR_TYPE_LIST);
    LnnRequestLeaveSpecific(networkId, addrType);
    return true;
}

bool LnnRequestLeaveSpecificFuzzTest4()
{
    ConnectionAddrType addrType = CONNECTION_ADDR_MAX;
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    GenerateFromList(addrType, CONNECTION_ADDR_TYPE_LIST);
    LnnRequestLeaveSpecific(networkId, addrType);
    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    GenerateFromList(addrType, CONNECTION_ADDR_TYPE_LIST);
    LnnRequestLeaveSpecific(networkId, addrType);
    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    GenerateFromList(addrType, CONNECTION_ADDR_TYPE_LIST);
    LnnRequestLeaveSpecific(networkId, addrType);
    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    GenerateFromList(addrType, CONNECTION_ADDR_TYPE_LIST);
    LnnRequestLeaveSpecific(networkId, addrType);
    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    GenerateFromList(addrType, CONNECTION_ADDR_TYPE_LIST);
    LnnRequestLeaveSpecific(networkId, addrType);
    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    GenerateFromList(addrType, CONNECTION_ADDR_TYPE_LIST);
    LnnRequestLeaveSpecific(networkId, addrType);
    return true;
}

bool LnnRequestLeaveSpecificFuzzTest2()
{
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnRequestLeaveSpecific(networkId, CONNECTION_ADDR_SESSION);
    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnRequestLeaveSpecific(networkId, CONNECTION_ADDR_USB);
    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnRequestLeaveSpecific(networkId, CONNECTION_ADDR_SESSION_WITH_KEY);
    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnRequestLeaveSpecific(networkId, CONNECTION_ADDR_SLE);
    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnRequestLeaveSpecific(networkId, CONNECTION_ADDR_NCM);
    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnRequestLeaveSpecific(networkId, CONNECTION_ADDR_MAX);
    return true;
}

bool LnnSyncOfflineCompleteFuzzTest1()
{
    LnnSyncInfoType type = LNN_INFO_TYPE_CONNECTION_INFO;
    GenerateFromList(type, LNN_SYNC_INFO_TYPE_LIST);

    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    int32_t data = 0;
    GenerateInt32(data);
    LnnSyncOfflineComplete(type, networkId, (const uint8_t *)&data, sizeof(int32_t));
    return true;
}

bool LnnSyncOfflineCompleteFuzzTest2()
{
    int32_t data = 0;
    GenerateInt32(data);
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnSyncOfflineComplete(LNN_INFO_TYPE_CAPABILITY, networkId, (const uint8_t *)&data, sizeof(int32_t));

    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnSyncOfflineComplete(LNN_INFO_TYPE_CONNECTION_INFO, networkId, (const uint8_t *)&data, sizeof(int32_t));

    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnSyncOfflineComplete(LNN_INFO_TYPE_DEVICE_NAME, networkId, (const uint8_t *)&data, sizeof(int32_t));

    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnSyncOfflineComplete(LNN_INFO_TYPE_BATTERY_INFO, networkId, (const uint8_t *)&data, sizeof(int32_t));

    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnSyncOfflineComplete(LNN_INFO_TYPE_SCREEN_STATUS, networkId, (const uint8_t *)&data, sizeof(int32_t));

    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnSyncOfflineComplete(LNN_INFO_TYPE_OFFLINE, networkId, (const uint8_t *)&data, sizeof(int32_t));
    return true;
}

bool LnnSyncOfflineCompleteFuzzTest3()
{
    int32_t data = 0;
    GenerateInt32(data);
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnSyncOfflineComplete(LNN_INFO_TYPE_P2P_INFO, networkId, (const uint8_t *)&data, sizeof(int32_t));

    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnSyncOfflineComplete(LNN_INFO_TYPE_CHANNEL_NOISE_INFO, networkId, (const uint8_t *)&data, sizeof(int32_t));

    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnSyncOfflineComplete(LNN_INFO_TYPE_NOT_TRUSTED, networkId, (const uint8_t *)&data, sizeof(int32_t));

    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnSyncOfflineComplete(LNN_INFO_TYPE_WIFI_DIRECT, networkId, (const uint8_t *)&data, sizeof(int32_t));

    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnSyncOfflineComplete(LNN_INFO_TYPE_NICK_NAME, networkId, (const uint8_t *)&data, sizeof(int32_t));

    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnSyncOfflineComplete(LNN_INFO_TYPE_MASTER_ELECT, networkId, (const uint8_t *)&data, sizeof(int32_t));
    return true;
}

bool LnnSyncOfflineCompleteFuzzTest4()
{
    int32_t data = 0;
    GenerateInt32(data);
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnSyncOfflineComplete(LNN_INFO_TYPE_BSS_TRANS, networkId, (const uint8_t *)&data, sizeof(int32_t));

    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnSyncOfflineComplete(LNN_INFO_TYPE_TOPO_UPDATE, networkId, (const uint8_t *)&data, sizeof(int32_t));

    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnSyncOfflineComplete(LNN_INFO_TYPE_NODE_ADDR, networkId, (const uint8_t *)&data, sizeof(int32_t));

    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnSyncOfflineComplete(LNN_INFO_TYPE_NODE_ADDR_DETECTION, networkId, (const uint8_t *)&data, sizeof(int32_t));

    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnSyncOfflineComplete(LNN_INFO_TYPE_SYNC_CIPHERKEY, networkId, (const uint8_t *)&data, sizeof(int32_t));

    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnSyncOfflineComplete(LNN_INFO_TYPE_ROUTE_LSU, networkId, (const uint8_t *)&data, sizeof(int32_t));
    return true;
}

bool LnnSyncOfflineCompleteFuzzTest5()
{
    int32_t data = 0;
    GenerateInt32(data);
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnSyncOfflineComplete(LNN_INFO_TYPE_PTK, networkId, (const uint8_t *)&data, sizeof(int32_t));

    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnSyncOfflineComplete(LNN_INFO_TYPE_USERID, networkId, (const uint8_t *)&data, sizeof(int32_t));

    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnSyncOfflineComplete(LNN_INFO_TYPE_SYNC_BROADCASTLINKKEY, networkId, (const uint8_t *)&data, sizeof(int32_t));

    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnSyncOfflineComplete(LNN_INFO_TYPE_SLE_MAC, networkId, (const uint8_t *)&data, sizeof(int32_t));

    (void)memset_s(networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkId(networkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate network Id fail!");
        return false;
    }
    LnnSyncOfflineComplete(LNN_INFO_TYPE_COUNT, networkId, (const uint8_t *)&data, sizeof(int32_t));
    return true;
}

bool LnnRequestLeaveInvalidConnFuzzTest1()
{
    char oldNetworkId[NETWORK_ID_BUF_LEN] = { 0 };
    char newNetworkId[NETWORK_ID_BUF_LEN] = { 0 };
    ConnectionAddrType type = CONNECTION_ADDR_MAX;
    GenerateFromList(type, CONNECTION_ADDR_TYPE_LIST);
    if (!GenerateFuzzNetworkIdByList(oldNetworkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate old network Id fail!");
        return false;
    }
    if (!GenerateFuzzNetworkIdByList(newNetworkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate new network Id fail!");
        return false;
    }
    LnnRequestLeaveInvalidConn(oldNetworkId, type, newNetworkId);
    return true;
}

bool LnnRequestLeaveInvalidConnFuzzTest2()
{
    char oldNetworkId[NETWORK_ID_BUF_LEN] = { 0 };
    char newNetworkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (!GenerateFuzzNetworkIdByList(oldNetworkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate old network Id fail!");
        return false;
    }
    if (!GenerateFuzzNetworkIdByList(newNetworkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate new network Id fail!");
        return false;
    }
    LnnRequestLeaveInvalidConn(oldNetworkId, CONNECTION_ADDR_WLAN, newNetworkId);
    (void)memset_s(oldNetworkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    (void)memset_s(newNetworkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkIdByList(oldNetworkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate old network Id fail!");
        return false;
    }
    if (!GenerateFuzzNetworkIdByList(newNetworkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate new network Id fail!");
        return false;
    }
    LnnRequestLeaveInvalidConn(oldNetworkId, CONNECTION_ADDR_BR, newNetworkId);
    (void)memset_s(oldNetworkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    (void)memset_s(newNetworkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkIdByList(oldNetworkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate old network Id fail!");
        return false;
    }
    if (!GenerateFuzzNetworkIdByList(newNetworkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate new network Id fail!");
        return false;
    }
    LnnRequestLeaveInvalidConn(oldNetworkId, CONNECTION_ADDR_BLE, newNetworkId);
    (void)memset_s(oldNetworkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    (void)memset_s(newNetworkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkIdByList(oldNetworkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate old network Id fail!");
        return false;
    }
    if (!GenerateFuzzNetworkIdByList(newNetworkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate new network Id fail!");
        return false;
    }
    LnnRequestLeaveInvalidConn(oldNetworkId, CONNECTION_ADDR_ETH, newNetworkId);
    return true;
}

bool LnnRequestLeaveInvalidConnFuzzTest3()
{
    char oldNetworkId[NETWORK_ID_BUF_LEN] = { 0 };
    char newNetworkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (!GenerateFuzzNetworkIdByList(oldNetworkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate old network Id fail!");
        return false;
    }
    if (!GenerateFuzzNetworkIdByList(newNetworkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate new network Id fail!");
        return false;
    }
    LnnRequestLeaveInvalidConn(oldNetworkId, CONNECTION_ADDR_SESSION, newNetworkId);
    (void)memset_s(oldNetworkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    (void)memset_s(newNetworkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkIdByList(oldNetworkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate old network Id fail!");
        return false;
    }
    if (!GenerateFuzzNetworkIdByList(newNetworkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate new network Id fail!");
        return false;
    }
    LnnRequestLeaveInvalidConn(oldNetworkId, CONNECTION_ADDR_USB, newNetworkId);
    (void)memset_s(oldNetworkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    (void)memset_s(newNetworkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkIdByList(oldNetworkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate old network Id fail!");
        return false;
    }
    if (!GenerateFuzzNetworkIdByList(newNetworkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate new network Id fail!");
        return false;
    }
    LnnRequestLeaveInvalidConn(oldNetworkId, CONNECTION_ADDR_SESSION_WITH_KEY, newNetworkId);
    (void)memset_s(oldNetworkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    (void)memset_s(newNetworkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkIdByList(oldNetworkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate old network Id fail!");
        return false;
    }
    if (!GenerateFuzzNetworkIdByList(newNetworkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate new network Id fail!");
        return false;
    }
    LnnRequestLeaveInvalidConn(oldNetworkId, CONNECTION_ADDR_SLE, newNetworkId);
    return true;
}

bool LnnRequestLeaveInvalidConnFuzzTest4()
{
    char oldNetworkId[NETWORK_ID_BUF_LEN] = { 0 };
    char newNetworkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (!GenerateFuzzNetworkIdByList(oldNetworkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate old network Id fail!");
        return false;
    }
    if (!GenerateFuzzNetworkIdByList(newNetworkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate new network Id fail!");
        return false;
    }
    LnnRequestLeaveInvalidConn(oldNetworkId, CONNECTION_ADDR_NCM, newNetworkId);
    (void)memset_s(oldNetworkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    (void)memset_s(newNetworkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    if (!GenerateFuzzNetworkIdByList(oldNetworkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate old network Id fail!");
        return false;
    }
    if (!GenerateFuzzNetworkIdByList(newNetworkId, NETWORK_ID_BUF_LEN)) {
        COMM_LOGE(COMM_TEST, "generate new network Id fail!");
        return false;
    }
    LnnRequestLeaveInvalidConn(oldNetworkId, CONNECTION_ADDR_MAX, newNetworkId);
    return true;
}
#endif

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return 0;
    }
    /* Run your code on data */
    int32_t ret = FuzzEnvInit(data, size);
    if (ret != 0) {
        return ret;
    }
    OHOS::LnnNotifyDiscoveryDeviceFuzzTest();
#ifdef LNN_NET_BUILDER_FULL_TEST
    OHOS::LnnRequestLeaveByAddrTypeFuzzTest1();
    OHOS::LnnRequestLeaveByAddrTypeFuzzTest2();
    OHOS::LnnRequestLeaveSpecificFuzzTest1();
    OHOS::LnnRequestLeaveSpecificFuzzTest2();
    OHOS::LnnRequestLeaveSpecificFuzzTest3();
    OHOS::LnnRequestLeaveSpecificFuzzTest4();
    OHOS::LnnSyncOfflineCompleteFuzzTest1();
    OHOS::LnnSyncOfflineCompleteFuzzTest2();
    OHOS::LnnSyncOfflineCompleteFuzzTest3();
    OHOS::LnnSyncOfflineCompleteFuzzTest4();
    OHOS::LnnSyncOfflineCompleteFuzzTest5();
    OHOS::LnnRequestLeaveInvalidConnFuzzTest1();
    OHOS::LnnRequestLeaveInvalidConnFuzzTest2();
    OHOS::LnnRequestLeaveInvalidConnFuzzTest3();
    OHOS::LnnRequestLeaveInvalidConnFuzzTest4();
#endif
    FuzzDeinit();
    return 0;
}
} // namespace OHOS