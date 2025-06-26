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

#include "lnnslecapability_fuzzer.h"

#include <cstddef>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>

#include "comm_log.h"
#include "cJSON.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_node_info.h"
#include "lnn_sle_capability.h"
#include "lnn_sle_capability.c"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_json_utils.h"

constexpr char NODE1_NETWORK_ID[] = "235689BNHFCF";
constexpr char NODE1_UUID[] = "235689BNHFCC";
constexpr char NODE1_BT_MAC[] = "56789TTU";
constexpr char NODE1_UDID[] = "123456ABCDEF";
constexpr int64_t AUTH_SEQ = 1;
constexpr uint64_t TIME_STAMP = 5000;

using namespace std;
namespace OHOS {
class TestEnv {
public:
    TestEnv()
    {
        isInited_ = false;
        LnnInitSleInfo();
        LnnInitDistributedLedger();
        NodeInfo info;
        (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
        info.discoveryType = DISCOVERY_TYPE_BR;
        (void)strncpy_s(info.uuid, UUID_BUF_LEN, NODE1_UUID, strlen(NODE1_UUID));
        (void)strncpy_s(info.deviceInfo.deviceUdid, UDID_BUF_LEN, NODE1_UDID, strlen(NODE1_UDID));
        (void)strncpy_s(info.networkId, NETWORK_ID_BUF_LEN, NODE1_NETWORK_ID, strlen(NODE1_NETWORK_ID));
        (void)strncpy_s(info.connectInfo.macAddr, MAC_LEN, NODE1_BT_MAC, strlen(NODE1_BT_MAC));
        info.authSeq[0] = AUTH_SEQ;
        info.heartbeatTimestamp = TIME_STAMP;
        info.deviceInfo.osType = HO_OS_TYPE;
        LnnAddOnlineNode(&info);
        SetSleRangeCapToLocalLedger();
        SetSleAddrToLocalLedger();
        LnnSendSleInfoForAllNode();
        isInited_ = true;
    }

    ~TestEnv()
    {
        isInited_ = false;
        LnnDeinitSleInfo();
        LnnDeinitDistributedLedger();
    }

    bool IsInited(void)
    {
        return isInited_;
    }
private:
    volatile bool isInited_;
};

bool LocalLedgerInitSleCapacityFuzzTest(FuzzedDataProvider &dataProvider)
{
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    int32_t state = dataProvider.ConsumeIntegral<int32_t>();
    SleStateChangeEventHandler(state);
    if (LocalLedgerInitSleCapacity(&nodeInfo) != SOFTBUS_OK) {
        COMM_LOGE(COMM_TEST, "local ledger init sle capacity failed");
        return false;
    }
    return true;
}

bool OnReceiveSleMacChangedMsgFuzzTest(FuzzedDataProvider &dataProvider)
{
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    string networkIdStr = dataProvider.ConsumeBytesAsString(NETWORK_ID_BUF_LEN - 1);
    if (strcpy_s(networkId, NETWORK_ID_BUF_LEN, networkIdStr.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s networkId failed!");
        return false;
    }
    int32_t testData = dataProvider.ConsumeIntegral<int32_t>();
    LnnSyncInfoType type = static_cast<LnnSyncInfoType>(testData % LNN_INFO_TYPE_COUNT);
    cJSON *json = cJSON_CreateObject();
    if (json == nullptr) {
        COMM_LOGE(COMM_TEST, "create json failed!");
        return false;
    }
    int32_t sleCap = dataProvider.ConsumeIntegral<int32_t>();
    char sleMac[MAC_LEN] = { 0 };
    string sleMacStr = dataProvider.ConsumeBytesAsString(MAC_LEN - 1);
    if (strcpy_s(sleMac, MAC_LEN, sleMacStr.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s sleMac failed!");
        cJSON_Delete(json);
        return false;
    }
    if (!AddNumberToJsonObject(json, JSON_KEY_SLE_CAP, sleCap) ||
        !AddStringToJsonObject(json, JSON_KEY_SLE_MAC, sleMac)) {
        COMM_LOGE(COMM_TEST, "add json object failed!");
        cJSON_Delete(json);
        return false;
    }
    char *msg = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (msg == nullptr) {
        COMM_LOGE(COMM_TEST, "json transform unformatted failed!");
        return false;
    }
    OnReceiveSleMacChangedMsg(type, networkId, reinterpret_cast<const uint8_t *>(msg),
        strlen(msg));
    cJSON_free(msg);
    return true;
}

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    static TestEnv env;
    if (!env.IsInited()) {
        COMM_LOGE(COMM_TEST, "TestEnv init fail");
        return 0;
    }
    FuzzedDataProvider dataProvider(data, size);
    OHOS::LocalLedgerInitSleCapacityFuzzTest(dataProvider);
    OHOS::OnReceiveSleMacChangedMsgFuzzTest(dataProvider);
    return 0;
}
} // namespace OHOS