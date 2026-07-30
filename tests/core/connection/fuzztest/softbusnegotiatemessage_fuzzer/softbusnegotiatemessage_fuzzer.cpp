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

#include <securec.h>
#include "softbusnegotiatemessage_fuzzer.h"
#include "comm_log.h"
#include "negotiate_message.h"
#include "protocol/wifi_direct_protocol.h"
#include "protocol/wifi_direct_protocol_factory.h"

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
        COMM_LOGE(COMM_TEST, "data Invalid");
        return objetct;
    }
    errno_t ret = memcpy_s(&objetct, objetctSize, g_baseFuzzData + g_baseFuzzPos, objetctSize);
    if (ret != EOK) {
        COMM_LOGE(COMM_TEST, "memcpy err");
        return {};
    }
    g_baseFuzzPos += objetctSize;
    return objetct;
}

void SoftBusNegotiateMessageUnmarshallingFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        COMM_LOGE(COMM_TEST, "Invalid param");
        return;
    }
    g_baseFuzzSize = size;
    g_baseFuzzData = data;
    g_baseFuzzPos = 0;
    SoftBus::NegotiateMessage msg;
    SoftBus::NegotiateMessage msg1;
    msg1.SetSessionId(GetData<uint32_t>());
    msg1.SetPreferLinkBandWidth(GetData<int>());
    msg1.SetIsModeStrict(GetData<bool>());
    msg1.SetMessageType(GetData<SoftBus::NegotiateMessageType>());
    msg1.SetIpv4InfoArray({ GetData<SoftBus::Ipv4Info>(), GetData<SoftBus::Ipv4Info>() });
    std::vector<uint8_t> configVec = {0x32};
    msg1.SetWifiConfigInfo(configVec);
    msg1.SetLegacyP2pGroupConfig("OHOS-1234\n00:01:02:03:04:05\n00001111\n5180");
    SoftBus::InterfaceInfo interfaceInfo;
    interfaceInfo.SetBandWidth(1);
    std::vector<SoftBus::InterfaceInfo> interfaceArray;
    interfaceArray.push_back(interfaceInfo);
    msg1.SetInterfaceInfoArray(interfaceArray);
    SoftBus::LinkInfo linkInfo1;
    linkInfo1.SetCenter20M(GetData<int>());
    msg1.SetLinkInfo(linkInfo1);

    auto protocol1 = SoftBus::WifiDirectProtocolFactory::CreateProtocol(SoftBus::ProtocolType::TLV);
    protocol1->SetFormat({ SoftBus::TlvProtocol::TLV_TAG_SIZE, SoftBus::TlvProtocol::TLV_LENGTH_SIZE2 });
    std::vector<uint8_t> output;
    msg.Marshalling(*protocol1, output);
    msg1.Marshalling(*protocol1, output);

    SoftBus::NegotiateMessage msg2;
    auto protocol2 = SoftBus::WifiDirectProtocolFactory::CreateProtocol(SoftBus::ProtocolType::TLV);
    protocol2->SetFormat({ SoftBus::TlvProtocol::TLV_TAG_SIZE, SoftBus::TlvProtocol::TLV_LENGTH_SIZE2 });
    msg2.Unmarshalling(*protocol2, output);
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::SoftBusNegotiateMessageUnmarshallingFuzzTest(data, size);
    return 0;
}