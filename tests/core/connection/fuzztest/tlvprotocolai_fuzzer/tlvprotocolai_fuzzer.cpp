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
#include <vector>

#include "conn_log.h"
#include "protocol/tlv_protocol.h"
#include "protocol/wifi_direct_protocol_factory.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

namespace OHOS::SoftBus {
static constexpr size_t MAX_FUZZ_DATA_SIZE = 4096;
// Maximum number of write/read operations per test
static constexpr int MAX_WRITE_COUNT = 16;
static constexpr int MAX_READ_COUNT = 32;
static constexpr int MAX_ITEMS_COUNT = 10;
// Boundary values for length testing
static constexpr std::array<uint32_t, 16> BOUNDARY_VALUES = { 0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128,
    255 };
// Constants for length testing
static constexpr uint32_t LENGTH_THRESHOLD = 256;
static constexpr uint32_t LENGTH_VARIATION_RANGE = 1000;
// Extra iterations for testing overflow scenarios
static constexpr int EXTRA_READ_ITERATIONS = 5;
// Constants for 16-bit max value manipulation
static constexpr uint16_t UINT16_MAX_VALUE = 0xFFFF;
static constexpr int BITS_PER_BYTE = 8;
static constexpr uint8_t BYTE_MASK = 0xFF;
// Minimum bytes required for format parameter reading
static constexpr size_t MIN_FORMAT_PARAM_BYTES = 2;

/**
 * @brief Create TLV protocol with default format
 */
static std::shared_ptr<TlvProtocol> CreateTlvProtocol()
{
    auto protocol = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::TLV);
    auto tlvProtocol = std::dynamic_pointer_cast<TlvProtocol>(protocol);
    if (tlvProtocol == nullptr) {
        return nullptr;
    }
    auto format = ProtocolFormat { TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 };
    tlvProtocol->SetFormat(format);
    return tlvProtocol;
}

/**
 * @brief Fuzz test for SetInput with various data
 */
void TlvProtocolSetInputFuzzTest(const uint8_t *data, size_t size)
{
    auto provider = FuzzedDataProvider(data, size);
    auto protocol = CreateTlvProtocol();
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
 * @brief Fuzz test for Read operation
 */
void TlvProtocolReadFuzzTest(const uint8_t *data, size_t size)
{
    auto provider = FuzzedDataProvider(data, size);
    auto protocol = CreateTlvProtocol();
    if (protocol == nullptr) {
        return;
    }

    int writeCount = provider.ConsumeIntegralInRange<int>(0, MAX_WRITE_COUNT);
    for (int i = 0; i < writeCount; ++i) {
        if (provider.remaining_bytes() < sizeof(int) + sizeof(uint32_t)) {
            break;
        }

        int key = provider.ConsumeIntegral<int>();
        const auto valueSize =
            std::min(provider.ConsumeIntegral<uint32_t>(), static_cast<uint32_t>(MAX_FUZZ_DATA_SIZE));
        auto valueBytes = provider.ConsumeBytes<uint8_t>(valueSize);

        protocol->Write(key, Serializable::ValueType::STRING, valueBytes.data(), valueBytes.size());
    }

    std::vector<uint8_t> output;
    protocol->GetOutput(output);
    protocol->SetInput(output);

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
 * @brief Fuzz test with insufficient data for tag+length
 */
void TlvProtocolInsufficientHeaderFuzzTest(const uint8_t *data, size_t size)
{
    auto provider = FuzzedDataProvider(data, size);
    auto protocol = CreateTlvProtocol();
    if (protocol == nullptr) {
        return;
    }

    const auto dataSize = std::min(provider.ConsumeIntegral<uint32_t>(),
        static_cast<uint32_t>(TlvProtocol::TLV_TAG_SIZE + TlvProtocol::TLV_LENGTH_SIZE2 - 1));
    auto dataBytes = provider.ConsumeBytes<uint8_t>(dataSize);

    protocol->SetInput(dataBytes);

    int key = 0;
    uint8_t *value = nullptr;
    size_t valueSize = 0;

    // Read should return false due to insufficient header data
    protocol->Read(key, value, valueSize);
}

/**
 * @brief Fuzz test with length larger than remaining data
 */
void TlvProtocolLengthExceedsDataFuzzTest(const uint8_t *data, size_t size)
{
    auto provider = FuzzedDataProvider(data, size);
    auto protocol = CreateTlvProtocol();
    if (protocol == nullptr) {
        return;
    }

    // Construct TLV with valid header but length that exceeds remaining data
    auto malformedTlv = std::vector<uint8_t>();

    // Use random tag from fuzzer
    uint8_t tag = 0x01;
    if (provider.remaining_bytes() >= sizeof(uint8_t)) {
        tag = provider.ConsumeIntegral<uint8_t>();
    }
    malformedTlv.push_back(tag);

    // Use random length that's likely to exceed available data
    uint16_t largeLength = LENGTH_VARIATION_RANGE;
    if (provider.remaining_bytes() >= sizeof(uint16_t)) {
        largeLength = provider.ConsumeIntegral<uint16_t>();
        // Ensure length is large enough to trigger insufficient data condition
        if (largeLength < LENGTH_THRESHOLD) {
            largeLength =
                static_cast<uint16_t>(LENGTH_THRESHOLD + provider.ConsumeIntegral<uint16_t>() % LENGTH_VARIATION_RANGE);
        }
    }
    malformedTlv.push_back((largeLength >> BITS_PER_BYTE) & BYTE_MASK);
    malformedTlv.push_back(largeLength & BYTE_MASK);

    // Add a small amount of random data (not enough to satisfy length)
    uint8_t dataByte = 0x42;
    if (provider.remaining_bytes() >= sizeof(uint8_t)) {
        dataByte = provider.ConsumeIntegral<uint8_t>();
    }
    malformedTlv.push_back(dataByte);

    protocol->SetInput(malformedTlv);

    int key = 0;
    uint8_t *value = nullptr;
    size_t valueSize = 0;

    // Read should return false due to insufficient data
    protocol->Read(key, value, valueSize);
}

/**
 * @brief Fuzz test with boundary lengths
 */
void TlvProtocolBoundaryLengthFuzzTest(const uint8_t *data, size_t size)
{
    auto provider = FuzzedDataProvider(data, size);
    auto protocol = CreateTlvProtocol();
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

    if (provider.remaining_bytes() < sizeof(int)) {
        return;
    }

    int key = provider.ConsumeIntegral<int>();
    protocol->Write(key, Serializable::ValueType::STRING, testData.data(), testData.size());

    std::vector<uint8_t> output;
    protocol->GetOutput(output);
    protocol->SetInput(output);

    int maxReads = provider.ConsumeIntegralInRange<int>(0, MAX_READ_COUNT / 4);
    for (int i = 0; i < maxReads; ++i) {
        int readKey = 0;
        uint8_t *value = nullptr;
        size_t valueSize = 0;
        if (!protocol->Read(readKey, value, valueSize)) {
            break; // Read failed, stop iteration
        }
    }
}

/**
 * @brief Fuzz test with various format configurations
 */
void TlvProtocolVariousFormatsFuzzTest(const uint8_t *data, size_t size)
{
    auto provider = FuzzedDataProvider(data, size);
    auto protocol = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::TLV);
    if (protocol == nullptr) {
        return;
    }
    auto tlvProtocol = std::dynamic_pointer_cast<TlvProtocol>(protocol);
    if (tlvProtocol == nullptr) {
        return;
    }

    if (provider.remaining_bytes() < MIN_FORMAT_PARAM_BYTES) {
        return;
    }

    int tagSize = provider.ConsumeIntegralInRange<int>(1, 4);
    int lengthSize = provider.ConsumeIntegralInRange<int>(1, 2);

    auto format = ProtocolFormat { static_cast<uint32_t>(tagSize), static_cast<uint32_t>(lengthSize) };
    tlvProtocol->SetFormat(format);

    const auto valueSize = std::min(provider.ConsumeIntegral<uint32_t>(), static_cast<uint32_t>(MAX_FUZZ_DATA_SIZE));
    auto valueBytes = provider.ConsumeBytes<uint8_t>(valueSize);

    if (provider.remaining_bytes() < sizeof(int)) {
        return;
    }

    int key = provider.ConsumeIntegral<int>();
    tlvProtocol->Write(key, Serializable::ValueType::STRING, valueBytes.data(), valueBytes.size());

    std::vector<uint8_t> output;
    tlvProtocol->GetOutput(output);
    tlvProtocol->SetInput(output);

    int readKey = 0;
    uint8_t *value = nullptr;
    size_t readValueSize = 0;
    tlvProtocol->Read(readKey, value, readValueSize);
}

/**
 * @brief Fuzz test with empty data
 */
void TlvProtocolEmptyDataFuzzTest(const uint8_t *data, size_t size)
{
    auto provider = FuzzedDataProvider(data, size);
    auto protocol = CreateTlvProtocol();
    if (protocol == nullptr) {
        return;
    }

    auto emptyInput = std::vector<uint8_t>();
    protocol->SetInput(emptyInput);

    int key = 0;
    uint8_t *value = nullptr;
    size_t valueSize = 0;

    int maxReads = provider.ConsumeIntegralInRange<int>(0, MAX_READ_COUNT / 3);
    for (int i = 0; i < maxReads; ++i) {
        // Read should return false immediately
        if (!protocol->Read(key, value, valueSize)) {
            break; // Read failed, stop iteration
        }
    }
}

/**
 * @brief Fuzz test with multiple TLV items
 */
void TlvProtocolMultipleItemsFuzzTest(const uint8_t *data, size_t size)
{
    auto provider = FuzzedDataProvider(data, size);
    auto protocol = CreateTlvProtocol();
    if (protocol == nullptr) {
        return;
    }

    // Write multiple items
    int itemCount = provider.ConsumeIntegralInRange<int>(1, MAX_ITEMS_COUNT);
    for (int i = 0; i < itemCount; ++i) {
        if (provider.remaining_bytes() < sizeof(uint32_t)) {
            break;
        }

        const auto valueSize = std::min(provider.ConsumeIntegral<uint32_t>(), static_cast<uint32_t>(32));
        auto valueBytes = provider.ConsumeBytes<uint8_t>(valueSize);

        protocol->Write(i, Serializable::ValueType::STRING, valueBytes.data(), valueBytes.size());
    }

    std::vector<uint8_t> output;
    protocol->GetOutput(output);
    protocol->SetInput(output);

    // Read all items
    for (int i = 0; i < itemCount + EXTRA_READ_ITERATIONS; ++i) {
        int key = 0;
        uint8_t *value = nullptr;
        size_t valueSize = 0;
        if (!protocol->Read(key, value, valueSize)) {
            break; // Read failed, stop iteration
        }
    }
}

/**
 * @brief Fuzz test with maximum 16-bit length value
 */
void TlvProtocolMaxLengthFuzzTest(const uint8_t *data, size_t size)
{
    auto provider = FuzzedDataProvider(data, size);
    auto protocol = CreateTlvProtocol();
    if (protocol == nullptr) {
        return;
    }

    // Construct TLV with max 16-bit length (0xFFFF)
    auto tlvData = std::vector<uint8_t>();

    // Use random tag from fuzzer
    uint8_t tag = 0x01;
    if (provider.remaining_bytes() >= sizeof(uint8_t)) {
        tag = provider.ConsumeIntegral<uint8_t>();
    }
    tlvData.push_back(tag);

    uint16_t max16BitLength = UINT16_MAX_VALUE;
    tlvData.push_back((max16BitLength >> BITS_PER_BYTE) & BYTE_MASK);
    tlvData.push_back(max16BitLength & BYTE_MASK);

    // Add a small amount of random data (not enough to satisfy length)
    uint8_t dataByte = 0x42;
    if (provider.remaining_bytes() >= sizeof(uint8_t)) {
        dataByte = provider.ConsumeIntegral<uint8_t>();
    }
    tlvData.push_back(dataByte);

    protocol->SetInput(tlvData);

    int key = 0;
    uint8_t *value = nullptr;
    size_t valueSize = 0;

    // Read should detect insufficient data
    protocol->Read(key, value, valueSize);
}

} // namespace OHOS::SoftBus

extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return SOFTBUS_INVALID_PARAM;
    }

    using FuzzFunc = void (*)(const uint8_t *, size_t);
    constexpr FuzzFunc fuzzFuncs[] = {
        OHOS::SoftBus::TlvProtocolSetInputFuzzTest,
        OHOS::SoftBus::TlvProtocolReadFuzzTest,
        OHOS::SoftBus::TlvProtocolInsufficientHeaderFuzzTest,
        OHOS::SoftBus::TlvProtocolLengthExceedsDataFuzzTest,
        OHOS::SoftBus::TlvProtocolBoundaryLengthFuzzTest,
        OHOS::SoftBus::TlvProtocolVariousFormatsFuzzTest,
        OHOS::SoftBus::TlvProtocolEmptyDataFuzzTest,
        OHOS::SoftBus::TlvProtocolMultipleItemsFuzzTest,
        OHOS::SoftBus::TlvProtocolMaxLengthFuzzTest,
    };
    static constexpr size_t fuzzFuncCount = std::size(fuzzFuncs);

    auto provider = FuzzedDataProvider(data, size);
    const auto testCase = provider.ConsumeIntegralInRange<int>(0, static_cast<int>(fuzzFuncCount) - 1);
    fuzzFuncs[testCase](data, size);

    return SOFTBUS_OK;
}
