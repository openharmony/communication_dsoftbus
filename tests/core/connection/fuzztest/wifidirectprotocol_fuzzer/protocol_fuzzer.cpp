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

#include "protocol_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "conn_log.h"
#include "softbus_utils.h"

#include "data/negotiate_message.h"
#include "protocol/wifi_direct_protocol_factory.h"

namespace OHOS::SoftBus {
static void JsonProtocolParseFuzzTest(const uint8_t *data, size_t size)
{
    (void)data;
    (void)size;
    std::string raw[] = {
        R"({"KEY_BRIDGE_SUPPORTED":false,"KEY_COMMAND_TYPE":8,"KEY_CONTENT_TYPE":2,"KEY_EXPECTED_ROLE":1,"KEY_GC_CHANNEL_LIST":"36##40##44##48##149##153##157##161##165","KEY_GC_MAC":"42:dc:a5:f3:4c:14","KEY_GO_MAC":"","KEY_MAC":"42:dc:a5:f3:4c:14","KEY_ROLE":5,"KEY_SELF_WIFI_CONFIG":"","KEY_STATION_FREQUENCY":5180,"KEY_VERSION":2,"KEY_WIDE_BAND_SUPPORTED":false})",
        R"({"KEY_COMMAND_TYPE":9,"KEY_CONTENT_TYPE":2,"KEY_GC_CHANNEL_LIST":"36##40##44##48##149##153##157##161##165","KEY_GC_MAC":"a6:3b:0e:78:29:dd","KEY_GO_MAC":"42:dc:a5:f3:4c:14","KEY_IP":"","KEY_MAC":"a6:3b:0e:78:29:dd","KEY_SELF_WIFI_CONFIG":"","KEY_STATION_FREQUENCY":5180,"KEY_VERSION":2,"KEY_WIDE_BAND_SUPPORTED":false})",
        R"({"KEY_BRIDGE_SUPPORTED":false,"KEY_COMMAND_TYPE":8,"KEY_CONTENT_TYPE":1,"KEY_EXPECTED_ROLE":2,"KEY_GC_IP":"192.168.49.3","KEY_GC_MAC":"a6:3b:0e:78:29:dd","KEY_GO_IP":"192.168.49.1","KEY_GO_MAC":"42:dc:a5:f3:4c:14","KEY_GO_PORT":43267,"KEY_GROUP_CONFIG":"DIRECT-ja-OHOS_0u31\n4e:e8:d0:45:8f:10\nulKjGU9T\n5180","KEY_MAC":"42:dc:a5:f3:4c:14","KEY_ROLE":2,"KEY_SELF_WIFI_CONFIG":"","KEY_VERSION":2})",
        R"({"KEY_COMMAND_TYPE":9,"KEY_CONTENT_TYPE":3,"KEY_IP":"192.168.49.3","KEY_MAC":"a6:3b:0e:78:29:dd","KEY_RESULT":0,"KEY_VERSION":2})",
        R"({"KEY_COMMAND_TYPE":13,"KEY_IP":"192.168.49.3","KEY_MAC":"a6:3b:0e:78:29:dd"})",
        R"({"KEY_COMMAND_TYPE":5,"KEY_MAC":"42:dc:a5:f3:4c:14"})",
    };
    for (auto s : raw) {
        std::vector<uint8_t> input;
        input.insert(input.end(), s.begin(), s.end());
        auto protocol = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::JSON);
        NegotiateMessage msg;
        msg.Unmarshalling(*protocol, input);
    }
}

static void StringToBytes(const std::string &s, std::vector<uint8_t> output)
{
    auto size = UN_HEXIFY_LEN(s.length());
    uint8_t *buf = new uint8_t[size];
    auto ret = ConvertHexStringToBytes(buf, size, s.c_str(), s.size());
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_TEST, "convert hex to bytes failed, error=%{public}d", ret);
        delete[] buf;
        return;
    }
    CONN_LOGE(CONN_TEST, "success, '%{public}s'", s.c_str());
    output.insert(output.end(), buf, buf + size);
    delete[] buf;
}

static void TlvProtocolParseFuzzTest(const uint8_t *data, size_t size)
{
    (void)data;
    (void)size;
    std::string raw[] = {
        R"(000400320000000d48007b2242616e645769647468223a332c224343223a34373735332c224368616e6e656c4964223a3135372c22576966694d6163223a2236383a31313a30353a38653a62363a3066227d)",
        R"(00040037000000)",
        R"(0004001b0000000104000100000008320000050063686261300105006368626130020400100000000304001000000013110036383a31313a30353a38653a62363a3066)",
    };
    for (auto s : raw) {
        std::vector<uint8_t> input;
        StringToBytes(s, input);
        auto protocol = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::TLV);
        NegotiateMessage msg;
        msg.Unmarshalling(*protocol, input);
    }
}

} // namespace OHOS::SoftBus

extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::SoftBus::JsonProtocolParseFuzzTest(data, size);
    OHOS::SoftBus::TlvProtocolParseFuzzTest(data, size);
    return 0;
}
