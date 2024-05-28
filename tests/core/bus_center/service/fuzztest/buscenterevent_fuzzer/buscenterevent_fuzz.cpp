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

#include "comm_log.h"
#include "bus_center_event.h"
#include "softbus_adapter_mem.h"
#include <cstddef>
#include <cstring>
#include "securec.h"

namespace OHOS {
    const uint8_t *g_baseFuzzData = nullptr;
    size_t g_baseFuzzSize = 0;
    size_t g_baseFuzzPos;

template <class T> T GetData()
{
    T objetct{};
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


bool LnnNotifyOnlineStateFuzzTest(const uint8_t* data, size_t size)
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
    const char *outData = reinterpret_cast<const char*>(data);
    memcpy_s(info.networkId, NETWORK_ID_BUF_LEN, outData, NETWORK_ID_BUF_LEN);
    LnnNotifyOnlineState(isOnline, &info);
    LnnNotifyMigrate(isOnline, &info);
    return true;
}

bool LnnNotifyLnnRelationChangedFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        COMM_LOGE(COMM_TEST, "data is nullptr");
        return false;
    }
    const char *outData = reinterpret_cast<const char*>(data);
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    ConnectionAddrType type = static_cast<ConnectionAddrType>
    (GetData<int>() % (CONNECTION_ADDR_MAX - CONNECTION_ADDR_WLAN + 1));
    uint8_t relation = GetData<uint8_t>();
    int32_t weight = GetData<int32_t>();
    bool isJoin = GetData<bool>();
    bool isMaster = GetData<bool>();
    char *udid = reinterpret_cast<char *>(SoftBusCalloc(size));
    if (udid == nullptr) {
        COMM_LOGE(COMM_TEST, "udid is nullptr");
        return false;
    }
    if (memcpy_s(udid, size, outData, size) != EOK) {
        COMM_LOGE(COMM_TEST, "memcpy_s is failed!");
        SoftBusFree(udid);
        return false;
    }
    LnnNotifyLnnRelationChanged(udid, type, relation, isJoin);
    LnnNotifyMasterNodeChanged(isMaster, udid, weight);
    SoftBusFree(udid);
    return true;
}

void LnnNotifyStateChangeEventFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size > sizeof(SoftBusDifferentAccountState)) {
        COMM_LOGE(COMM_TEST, "data is nullptr");
        return;
    }
    const char *outData = reinterpret_cast<const char*>(data);
    char *state = (char *)SoftBusCalloc(sizeof(SoftBusDifferentAccountState));
    if (state == nullptr) {
        COMM_LOGE(COMM_TEST, "state is null, softBusCalloc is failed!");
        return;
    }
    if (memcpy_s(state, sizeof(SoftBusDifferentAccountState), outData, size) != EOK) {
        COMM_LOGE(COMM_TEST, "state memcpy_s is failed");
        SoftBusFree(state);
        return;
    }
    LnnNotifyDifferentAccountChangeEvent(state);

    if (size > sizeof(SoftBusBtState)) {
        COMM_LOGE(COMM_TEST, "size less than softBusBtState");
        return;
    }
    char *btState = (char *)SoftBusCalloc(sizeof(SoftBusBtState));
    if (btState == nullptr) {
        COMM_LOGE(COMM_TEST, "btState is null, softBusCalloc is failed!");
        return;
    }
    if (memcpy_s(btState, sizeof(SoftBusBtState), outData, size) != EOK) {
        SoftBusFree(btState);
        COMM_LOGE(COMM_TEST, "btState memcpy_s is failed");
        return;
    }
    LnnNotifyBtStateChangeEvent(btState);
}

bool LnnNotifyBtAclStateChangeEventFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < NETWORK_ID_BUF_LEN || size < BT_MAC_LEN) {
        COMM_LOGE(COMM_TEST, "data or size is valid");
        return false;
    }
    const char *outData = reinterpret_cast<const char*>(data);
    char btMac[BT_MAC_LEN] = { 0 };
    if (memcpy_s(btMac, BT_MAC_LEN, outData, BT_MAC_LEN) != EOK) {
        COMM_LOGE(COMM_TEST, "memcpy_s btMac is failed!");
        return false;
    }
    btMac[BT_MAC_LEN - 1] = '\0';
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (memcpy_s(networkId, NETWORK_ID_BUF_LEN, outData, NETWORK_ID_BUF_LEN) != EOK) {
        COMM_LOGE(COMM_TEST, "memcpy_s networkId is failed!");
        return false;
    }
    networkId[NETWORK_ID_BUF_LEN - 1] = '\0';
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    bool isLocal = GetData<bool>();
    SoftBusBtAclState state = static_cast<SoftBusBtAclState>
    (GetData<int>() % (SOFTBUS_BR_ACL_DISCONNECTED - SOFTBUS_BR_ACL_CONNECTED + 1));

    LnnNotifyNetworkIdChangeEvent(networkId);
    LnnNotifyNodeAddressChanged(btMac, networkId, isLocal);
    LnnNotifyBtAclStateChangeEvent(btMac, state);
    LnnNotifyAddressChangedEvent(btMac);
    return true;
}

bool LnnNotifySingleOffLineEventFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < NETWORK_ID_BUF_LEN) {
        COMM_LOGE(COMM_TEST, "data or size is valid");
        return false;
    }
    NodeBasicInfo basicInfo;
    const char *outData = reinterpret_cast<const char*>(data);
    memcpy_s(basicInfo.networkId, NETWORK_ID_BUF_LEN, outData, NETWORK_ID_BUF_LEN);
    ConnectionAddrType type = static_cast<ConnectionAddrType>
    (GetData<int>() % (CONNECTION_ADDR_MAX - CONNECTION_ADDR_WLAN + 1));
    ConnectionAddr addr = {.type = type};
    LnnNotifySingleOffLineEvent(&addr, &basicInfo);
    return true;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::LnnNotifyOnlineStateFuzzTest(data, size);
    OHOS::LnnNotifyLnnRelationChangedFuzzTest(data, size);
    OHOS::LnnNotifyStateChangeEventFuzzTest(data, size);
    OHOS::LnnNotifyBtAclStateChangeEventFuzzTest(data, size);
    OHOS::LnnNotifySingleOffLineEventFuzzTest(data, size);
    return 0;
}
}