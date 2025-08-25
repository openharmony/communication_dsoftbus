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
    FuzzDeinit();
    return 0;
}
} // namespace OHOS