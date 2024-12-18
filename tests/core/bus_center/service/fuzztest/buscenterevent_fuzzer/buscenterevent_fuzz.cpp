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

#include "bus_center_event.h"
#include "comm_log.h"
#include "fuzz_data_generator.h"
#include "securec.h"
#include "softbus_adapter_mem.h"

using namespace std;

namespace OHOS {
const uint8_t *g_baseFuzzData = nullptr;
size_t g_baseFuzzSize = 0;
size_t g_baseFuzzPos;

template <class T>
T GetData()
{
    T objetct {};
    size_t objetctSize = sizeof(objetct);
    if (g_baseFuzzData == nullptr || objetctSize > g_baseFuzzSize - g_baseFuzzPos) {
        return objetct;
    }
    errno_t ret = memcpy_s(&objetct, objetctSize, g_baseFuzzData + g_baseFuzzPos, objetctSize);
    if (ret != EOK) {
        return {};
    }
    g_baseFuzzPos += objetctSize;
    return objetct;
}

bool LnnNotifyOnlineStateFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < NETWORK_ID_BUF_LEN) {
        COMM_LOGE(COMM_TEST, "data or size is valid");
        return false;
    }
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    bool isOnline = GetData<bool>();
    NodeBasicInfo info;
    (void)memset_s(&info, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    string outData;
    GenerateString(outData);
    if (strcpy_s(info.networkId, NETWORK_ID_BUF_LEN, outData.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "networkId strcpy_s is failed");
        return false;
    }
    LnnNotifyOnlineState(isOnline, &info);
    LnnNotifyMigrate(isOnline, &info);
    return true;
}

bool LnnNotifyLnnRelationChangedFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        COMM_LOGE(COMM_TEST, "data is nullptr");
        return false;
    }
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    ConnectionAddrType type = static_cast<ConnectionAddrType>
    (GetData<int>() % (CONNECTION_ADDR_MAX - CONNECTION_ADDR_WLAN + 1));
    uint8_t relation = GetData<uint8_t>();
    int32_t weight = GetData<int32_t>();
    bool isJoin = GetData<bool>();
    bool isMaster = GetData<bool>();
    string udid1;
    GenerateString(udid1);
    LnnNotifyLnnRelationChanged(udid1.c_str(), type, relation, isJoin);
    string udid2;
    GenerateString(udid2);
    LnnNotifyMasterNodeChanged(isMaster, udid2.c_str(), weight);
    return true;
}

void LnnNotifyStateChangeEventFuzzTest()
{
    string outData1;
    GenerateString(outData1);
    char *state = (char *)SoftBusCalloc(sizeof(SoftBusDifferentAccountState));
    if (state == nullptr) {
        COMM_LOGE(COMM_TEST, "state is null, softBusCalloc is failed!");
        return;
    }
    if (strcpy_s(state, sizeof(SoftBusDifferentAccountState), outData1.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "state strcpy_s is failed");
        SoftBusFree(state);
        return;
    }
    LnnNotifyDifferentAccountChangeEvent(state);

    string outData2;
    GenerateString(outData2);
    char *btState = (char *)SoftBusCalloc(sizeof(SoftBusBtState));
    if (btState == nullptr) {
        COMM_LOGE(COMM_TEST, "btState is null, softBusCalloc is failed!");
        return;
    }
    if (strcpy_s(btState, sizeof(SoftBusBtState), outData2.c_str()) != EOK) {
        SoftBusFree(btState);
        COMM_LOGE(COMM_TEST, "btState strcpy_s is failed");
        return;
    }
    LnnNotifyBtStateChangeEvent(btState);
}

bool LnnNotifyBtAclStateChangeEventFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < NETWORK_ID_BUF_LEN || size < BT_MAC_LEN) {
        COMM_LOGE(COMM_TEST, "data or size is valid");
        return false;
    }
    string outData1;
    GenerateString(outData1);
    char btMac[BT_MAC_LEN] = { 0 };
    if (strcpy_s(btMac, BT_MAC_LEN, outData1.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s btMac is failed!");
        return false;
    }
    btMac[BT_MAC_LEN - 1] = '\0';

    string outData2;
    GenerateString(outData2);
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (strcpy_s(networkId, NETWORK_ID_BUF_LEN, outData2.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s networkId is failed!");
        return false;
    }
    networkId[NETWORK_ID_BUF_LEN - 1] = '\0';
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    bool isLocal = GetData<bool>();
    SoftBusBtAclState state =
        static_cast<SoftBusBtAclState>(GetData<int>() % (SOFTBUS_BR_ACL_DISCONNECTED - SOFTBUS_BR_ACL_CONNECTED + 1));

    LnnNotifyNetworkIdChangeEvent(networkId);
    LnnNotifyNodeAddressChanged(btMac, networkId, isLocal);
    LnnNotifyBtAclStateChangeEvent(btMac, state);
    LnnNotifyAddressChangedEvent(btMac);
    return true;
}

bool LnnNotifySingleOffLineEventFuzzTest()
{
    NodeBasicInfo basicInfo;
    (void)memset_s(&basicInfo, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    int32_t testData = 0;
    GenerateInt32(testData);
    string outData;
    GenerateString(outData);
    if (strcpy_s(basicInfo.networkId, NETWORK_ID_BUF_LEN, outData.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s networkId is failed!");
        return false;
    }
    basicInfo.networkId[NETWORK_ID_BUF_LEN - 1] = '\0';
    ConnectionAddrType type =
        static_cast<ConnectionAddrType>(testData % (CONNECTION_ADDR_MAX - CONNECTION_ADDR_WLAN + 1));
    ConnectionAddr addr = { .type = type };
    LnnNotifySingleOffLineEvent(&addr, &basicInfo);
    return true;
}

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return 0;
    }

    DataGenerator::Write(data, size);

    /* Run your code on data */
    OHOS::LnnNotifyOnlineStateFuzzTest(data, size);
    OHOS::LnnNotifyLnnRelationChangedFuzzTest(data, size);
    OHOS::LnnNotifyStateChangeEventFuzzTest();
    OHOS::LnnNotifyBtAclStateChangeEventFuzzTest(data, size);
    OHOS::LnnNotifySingleOffLineEventFuzzTest();

    DataGenerator::Clear();

    return 0;
}
} // namespace OHOS