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

#include <algorithm>
#include <array>
#include <fuzzer/FuzzedDataProvider.h>
#include <memory>
#include <string>
#include <vector>

#include "data/negotiate_message.h"
#include "protocol/json_protocol.h"
#include "protocol/wifi_direct_protocol_factory.h"
#include "softbus_error_code.h"

namespace OHOS::SoftBus {
// Maximum data size for fuzz testing
static constexpr size_t MAX_FUZZ_DATA_SIZE = 4096;
// Maximum number of write operations per test
static constexpr int MAX_WRITE_COUNT = 16;
// Maximum number of read operations per test
static constexpr int MAX_READ_COUNT = 32;
// Boundary values for length testing
static constexpr std::array<uint32_t, 16> BOUNDARY_VALUES = { 0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128,
    255 };

/**
 * @brief Initialize protocol factory and JSON protocol
 */
static std::shared_ptr<JsonProtocol> CreateJsonProtocol()
{
    auto protocol = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::JSON);
    auto jsonProtocol = std::dynamic_pointer_cast<JsonProtocol>(protocol);
    if (jsonProtocol == nullptr) {
        return nullptr;
    }
    auto format = ProtocolFormat { 0, 0 };
    jsonProtocol->SetFormat(format);
    return jsonProtocol;
}

/**
 * @brief Fuzz test for SetInput with various JSON data
 */
void JsonProtocolSetInputFuzzTest(const uint8_t *data, size_t size)
{
    auto provider = FuzzedDataProvider(data, size);
    auto protocol = CreateJsonProtocol();
    if (protocol == nullptr) {
        return;
    }

    const auto dataSize = std::min(provider.ConsumeIntegral<uint32_t>(), static_cast<uint32_t>(MAX_FUZZ_DATA_SIZE));
    auto dataBytes = provider.ConsumeBytes<uint8_t>(dataSize);

    protocol->SetInput(dataBytes);

    auto output = std::vector<uint8_t>();
    protocol->GetOutput(output);
}

/**
 * @brief Fuzz test for Read operation with valid JSON
 */
void JsonProtocolReadFuzzTest(const uint8_t *data, size_t size)
{
    auto provider = FuzzedDataProvider(data, size);
    auto protocol = CreateJsonProtocol();
    if (protocol == nullptr) {
        return;
    }

    if (provider.remaining_bytes() < sizeof(uint32_t)) {
        return;
    }

    const auto jsonSize = std::min(provider.ConsumeIntegral<uint32_t>(), static_cast<uint32_t>(MAX_FUZZ_DATA_SIZE));
    auto jsonBytes = provider.ConsumeBytes<uint8_t>(jsonSize);

    protocol->SetInput(jsonBytes);

    int maxReads = provider.ConsumeIntegralInRange<int>(0, MAX_READ_COUNT);
    for (int i = 0; i < maxReads; ++i) {
        int key = 0;
        uint8_t *value = nullptr;
        size_t valueSize = 0;
        if (!protocol->Read(key, value, valueSize)) {
            break; // Read failed, stop iteration
        }
    }
}

/**
 * @brief Fuzz test with malformed JSON (is_discarded branch)
 */
void JsonProtocolMalformedJsonFuzzTest(const uint8_t *data, size_t size)
{
    auto provider = FuzzedDataProvider(data, size);
    auto protocol = CreateJsonProtocol();
    if (protocol == nullptr) {
        return;
    }

    const auto malformedSize =
        std::min(provider.ConsumeIntegral<uint32_t>(), static_cast<uint32_t>(MAX_FUZZ_DATA_SIZE));
    auto malformedBytes = provider.ConsumeBytes<uint8_t>(malformedSize);

    protocol->SetInput(malformedBytes);

    int key = 0;
    uint8_t *value = nullptr;
    size_t valueSize = 0;
    protocol->Read(key, value, valueSize);
}

/**
 * @brief Fuzz test with boundary lengths
 */
void JsonProtocolBoundaryLengthFuzzTest(const uint8_t *data, size_t size)
{
    auto provider = FuzzedDataProvider(data, size);
    auto protocol = CreateJsonProtocol();
    if (protocol == nullptr) {
        return;
    }

    const auto len = provider.PickValueInArray(BOUNDARY_VALUES);
    // Use ConsumeBytes to get data with proper size, then pad/trim to target length
    const auto bytesToConsume = std::min(len, static_cast<uint32_t>(provider.remaining_bytes()));
    auto consumedBytes = provider.ConsumeBytes<uint8_t>(bytesToConsume);

    // Create test data with target length, fill with consumed bytes and pad with zeros
    auto testData = std::vector<uint8_t>(len, 0);
    if (!consumedBytes.empty()) {
        std::copy(consumedBytes.begin(), consumedBytes.end(), testData.begin());
    }

    protocol->SetInput(testData);

    int maxReads = provider.ConsumeIntegralInRange<int>(0, MAX_READ_COUNT / 4); // Use smaller limit for this test
    for (int i = 0; i < maxReads; ++i) {
        int key = 0;
        uint8_t *value = nullptr;
        size_t valueSize = 0;
        if (!protocol->Read(key, value, valueSize)) {
            break; // Read failed, stop iteration
        }
    }
}

/**
 * @brief Fuzz test for unknown key (recursive Read branch)
 *
 * Uses valid old p2p keys (200+ range) that exist in keyStringTable_
 */
void JsonProtocolUnknownKeyFuzzTest(const uint8_t *data, size_t size)
{
    auto provider = FuzzedDataProvider(data, size);
    auto protocol = CreateJsonProtocol();
    if (protocol == nullptr) {
        return;
    }

    // Use valid old p2p keys that exist in keyStringTable_
    int knownKey = static_cast<int>(NegotiateMessageKey::GC_CHANNEL_LIST); // = 200

    // Construct ASCII string to ensure valid UTF-8
    size_t strLen = provider.ConsumeIntegralInRange<size_t>(0, 64);
    std::string valueStr;
    valueStr.reserve(strLen);
    for (size_t j = 0; j < strLen && provider.remaining_bytes() > 0; ++j) {
        valueStr += static_cast<char>(0x20 + (provider.ConsumeIntegral<uint8_t>() % 0x5F));
    }
    protocol->Write(knownKey, Serializable::ValueType::STRING, reinterpret_cast<const uint8_t *>(valueStr.c_str()),
        valueStr.size());

    std::vector<uint8_t> output;
    protocol->GetOutput(output);
    protocol->SetInput(output);

    // Read all available items - will return false when reaching end
    int maxReads = provider.ConsumeIntegralInRange<int>(0, MAX_WRITE_COUNT);
    for (int i = 0; i < maxReads; ++i) {
        int key = 0;
        uint8_t *value = nullptr;
        size_t readValueSize = 0;
        if (!protocol->Read(key, value, readValueSize)) {
            break; // Read failed, stop iteration
        }
    }
}

/**
 * @brief Fuzz test for empty JSON object
 */
void JsonProtocolEmptyJsonFuzzTest(const uint8_t *data, size_t size)
{
    auto provider = FuzzedDataProvider(data, size);
    auto protocol = CreateJsonProtocol();
    if (protocol == nullptr) {
        return;
    }

    // Test with minimal/empty JSON-like data from fuzzer
    const auto jsonSize = std::min(provider.ConsumeIntegral<uint32_t>(), static_cast<uint32_t>(32));
    auto jsonBytes = provider.ConsumeBytes<uint8_t>(jsonSize);
    auto input = std::vector<uint8_t>(jsonBytes.begin(), jsonBytes.end());
    protocol->SetInput(input);

    int key = 0;
    uint8_t *value = nullptr;
    size_t valueSize = 0;

    int maxReads = provider.ConsumeIntegralInRange<int>(0, MAX_READ_COUNT / 3);
    for (int i = 0; i < maxReads; ++i) {
        // Read should return false when iterator reaches end
        if (!protocol->Read(key, value, valueSize)) {
            break; // Read failed, stop iteration
        }
    }
}
} // namespace OHOS::SoftBus

extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return SOFTBUS_INVALID_PARAM;
    }

    using FuzzFunc = void (*)(const uint8_t *, size_t);
    constexpr FuzzFunc fuzzFuncs[] = {
        OHOS::SoftBus::JsonProtocolSetInputFuzzTest,
        OHOS::SoftBus::JsonProtocolReadFuzzTest,
        OHOS::SoftBus::JsonProtocolMalformedJsonFuzzTest,
        OHOS::SoftBus::JsonProtocolBoundaryLengthFuzzTest,
        OHOS::SoftBus::JsonProtocolUnknownKeyFuzzTest,
        OHOS::SoftBus::JsonProtocolEmptyJsonFuzzTest,
    };
    static constexpr size_t fuzzFuncCount = std::size(fuzzFuncs);

    auto provider = FuzzedDataProvider(data, size);
    const auto testCase = provider.ConsumeIntegralInRange<int>(0, static_cast<int>(fuzzFuncCount) - 1);
    fuzzFuncs[testCase](data, size);

    return SOFTBUS_OK;
}
