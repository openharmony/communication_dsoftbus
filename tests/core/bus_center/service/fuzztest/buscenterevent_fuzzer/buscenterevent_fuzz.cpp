/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
    if (data == nullptr) {
        return false;
    }
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    bool isOnline = GetData<bool>();
    NodeBasicInfo info;
    info.networkId = reinterpret_cast<const char*>(data);
    
    LnnNotifyOnlineState(isOnline, &info);
    LnnNotifyMigrate(isOnline, &info);
}

bool LnnNotifyLnnRelationChangedFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
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
    char *udid = NULL;
    udid = (char *)SoftBusMalloc(UDID_BUF_LEN);
    if (udid == NULL) {
        return false;
    }
    if (strcpy_s(udid, UDID_BUF_LEN, outData) != EOK) {
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
    LnnNotifyBtStateChangeEvent(data);
    LnnNotifyDifferentAccountChangeEvent(data);
}

bool LnnNotifyBtAclStateChangeEventFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return false;
    }
    const char *outData = reinterpret_cast<const char*>(data);
    char *btMac = NULL;
    btMac = (char *)SoftBusMalloc(BT_MAC_LEN);
    if (btMac == NULL) {
        return false;
    }
    if (strcpy_s(btMac, BT_MAC_LEN, outData) != EOK) {
        SoftBusFree(btMac);
        return false;
    }
    char *networkId = NULL;
    networkId = (char *)SoftBusMalloc(NETWORK_ID_BUF_LEN);
    if (networkId == NULL) {
        return false;
    }
    if (strcpy_s(networkId, NETWORK_ID_BUF_LEN, outData) != EOK) {
        SoftBusFree(networkId);
        return false;
    }
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    bool isLocal = GetData<bool>();
    SoftBusBtAclState state = static_cast<SoftBusBtAclState>
    (GetData<int>() % (SOFTBUS_BR_ACL_CONNECTED - SOFTBUS_BR_ACL_DISCONNECTED + 1));

    LnnNotifyNetworkIdChangeEvent(networkId);
    LnnNotifyNodeAddressChanged(btMac, networkId, isLocal);
    LnnNotifyBtAclStateChangeEvent(btMac, state);
    LnnNotifyAddressChangedEvent(btMac);
    SoftBusFree(networkId);
    SoftBusFree(btMac);
    return true;
}

bool LnnNotifySingleOffLineEventFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return false;
    }
    NodeBasicInfo basicInfo;
    (void)memset_s(&basicInfo, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));

    ConnectionAddr *addr = (ConnectionAddr *)SoftBusMalloc(sizeof(ConnectionAddr));
    if (addr == NULL) {
        return false;
    }
    if (memset_s(addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr)) != EOK) {
        SoftBusFree(addr);
        return false;
    }
    LnnNotifySingleOffLineEvent(addr, &basicInfo);
    SoftBusFree(addr);
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