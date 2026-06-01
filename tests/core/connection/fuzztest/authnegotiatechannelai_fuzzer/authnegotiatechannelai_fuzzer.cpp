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
#include <gmock/gmock.h>
#include <vector>

#include "auth_negotiate_channel.h"
#include "softbus_common.h"
#include "softbus_conn_interface_struct.h"
#include "wifi_direct_mock.h"

using namespace testing;
using ::testing::_;

namespace OHOS {
// Maximum allowed authentication data length (128KB)
static constexpr int MAX_AUTH_DATA_LEN = 131072;
// Maximum data size for fuzz testing to prevent excessive memory allocation
static constexpr uint32_t MAX_FUZZ_DATA_SIZE = 4096;

// Global authentication listener - initialized once and reused
// Note: Fuzzer runs are single-threaded by default, so no synchronization needed
static AuthTransListener g_authListener = { };

/**
 * @brief Initialize mock objects and authentication listener
 *
 * This function sets up the necessary mocks and registers the authentication
 * listener. It is idempotent and safe to call multiple times.
 */
static void InitMockAndListener()
{
    static bool initialized = false;
    if (initialized) {
        return;
    }

    static OHOS::SoftBus::WifiDirectInterfaceMock mock;
    // Set up mock expectations for authentication listener registration
    EXPECT_CALL(mock, RegAuthTransListener(_, _)).WillRepeatedly([](int32_t module, const AuthTransListener *listener) {
        if (listener != nullptr) {
            // Safety note: AuthTransListener is a POD struct containing only primitive types
            // and function pointers. Shallow copy is safe as function pointers remain valid
            // throughout the fuzzer lifecycle.
            g_authListener = *const_cast<AuthTransListener *>(listener);
        }
        return SOFTBUS_OK;
    });
    // Set up mock expectations for feature capability checks
    EXPECT_CALL(mock, LnnGetFeatureCapabilty).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, IsFeatureSupport).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetRemoteBoolInfoIgnoreOnline).WillRepeatedly(Return(true));
    // Set up mock expectations for data transmission and device info
    EXPECT_CALL(mock, AuthPostTransData).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AuthGetDeviceUuid).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetOsTypeByNetworkId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetNetworkIdByUuid(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));

    OHOS::SoftBus::AuthNegotiateChannel::Init();
    initialized = true;
}

/**
 * @brief Standard fuzz test for authentication data reception
 *
 * Tests normal data reception with various data sizes and content.
 */
void OnAuthDataReceivedFuzzTest(const uint8_t *data, size_t size)
{
    auto provider = FuzzedDataProvider(data, size);
    AuthHandle handle = { 0 };

    // Check if provider has enough data before consuming handle fields
    if (provider.remaining_bytes() < sizeof(int64_t) + sizeof(uint32_t) + sizeof(uint32_t)) {
        return;
    }
    handle.authId = provider.ConsumeIntegral<int64_t>();
    handle.type = provider.ConsumeIntegral<uint32_t>();

    // Limit data size to prevent excessive memory allocation
    const auto dataSize = std::min(provider.ConsumeIntegral<uint32_t>(), MAX_FUZZ_DATA_SIZE);
    auto dataBytes = provider.ConsumeBytes<uint8_t>(dataSize);

    // Validate data bytes size matches requested size
    if (dataBytes.size() != dataSize && dataSize > 0) {
        // Provider couldn't provide enough bytes, skip this test
        return;
    }

    // Check if provider has enough data for remaining authData fields
    if (provider.remaining_bytes() < sizeof(int32_t) + sizeof(int32_t) + sizeof(int64_t)) {
        return;
    }
    AuthTransData authData = {
        .module = provider.ConsumeIntegral<int32_t>(),
        .flag = provider.ConsumeIntegral<int32_t>(),
        .seq = provider.ConsumeIntegral<int64_t>(),
        .len = static_cast<uint32_t>(dataBytes.size()),
        .data = dataBytes.empty() ? nullptr : dataBytes.data(),
    };
    // Validate authData fields before passing to callback
    if (authData.len == 0 && authData.data != nullptr) {
        authData.data = nullptr;
    }
    // Check if listener callback is valid before calling
    if (g_authListener.onDataReceived == nullptr) {
        return;
    }

    g_authListener.onDataReceived(handle, &authData);
}

/**
 * @brief Fuzz test with null AuthTransData pointer
 *
 * Tests handling of null data pointer to verify robustness.
 */
void OnAuthDataReceivedNullDataFuzzTest(const uint8_t *data, size_t size)
{
    auto provider = FuzzedDataProvider(data, size);
    AuthHandle handle = { 0 };

    // Check if provider has enough data before consuming
    if (provider.remaining_bytes() < sizeof(int64_t) + sizeof(uint32_t)) {
        return;
    }
    handle.authId = provider.ConsumeIntegral<int64_t>();
    handle.type = provider.ConsumeIntegral<uint32_t>();

    // Test null AuthTransData pointer handling
    // This should be safely handled by the implementation
    // Check if listener callback is valid before calling
    if (g_authListener.onDataReceived == nullptr) {
        return;
    }
    g_authListener.onDataReceived(handle, nullptr);
}

/**
 * @brief Fuzz test with oversized data length
 *
 * Tests handling of data that exceeds maximum allowed length.
 * Uses a reusable buffer with fresh data for each test to prevent
 * state leakage between test runs.
 */
void OnAuthDataReceivedOversizedDataFuzzTest(const uint8_t *data, size_t size)
{
    auto provider = FuzzedDataProvider(data, size);
    AuthHandle handle = { 0 };

    // Check if provider has enough data before consuming
    if (provider.remaining_bytes() < sizeof(int64_t) + sizeof(uint32_t) + sizeof(uint8_t)) {
        return;
    }
    handle.authId = provider.ConsumeIntegral<int64_t>();
    handle.type = provider.ConsumeIntegral<uint32_t>();

    // Use static buffer to avoid repeated large allocations
    // Fill with fresh pattern data for each test to prevent state leakage
    static std::vector<uint8_t> s_largeData(MAX_AUTH_DATA_LEN + 1);
    const auto fillValue = static_cast<uint8_t>(provider.ConsumeIntegral<uint8_t>() | 0x41);
    if (s_largeData.empty()) {
        return;
    }
    std::fill(s_largeData.begin(), s_largeData.end(), fillValue);

    // Validate buffer before use
    if (s_largeData.size() != static_cast<size_t>(MAX_AUTH_DATA_LEN + 1)) {
        return;
    }

    // Check if provider has enough data for remaining fields
    if (provider.remaining_bytes() < sizeof(int32_t) + sizeof(int32_t) + sizeof(int64_t)) {
        return;
    }
    AuthTransData authData = {
        .module = provider.ConsumeIntegral<int32_t>(),
        .flag = provider.ConsumeIntegral<int32_t>(),
        .seq = provider.ConsumeIntegral<int64_t>(),
        .len = MAX_AUTH_DATA_LEN + 1,
        .data = s_largeData.data(),
    };
    // Double-check data pointer validity
    if (authData.data == nullptr || authData.len == 0) {
        return;
    }
    // Check if listener callback is valid before calling
    if (g_authListener.onDataReceived == nullptr) {
        return;
    }
    g_authListener.onDataReceived(handle, &authData);
}

/**
 * @brief Fuzz test with null inner data pointer
 *
 * Tests scenario where AuthTransData struct is valid but data pointer is null.
 * This simulates a specific edge case in data reception.
 */
void OnAuthDataReceivedNullInnerDataFuzzTest(const uint8_t *data, size_t size)
{
    auto provider = FuzzedDataProvider(data, size);
    AuthHandle handle = { 0 };

    // Check if provider has enough data before consuming
    if (provider.remaining_bytes() <
        sizeof(int64_t) + sizeof(uint32_t) + sizeof(int32_t) + sizeof(int32_t) + sizeof(int64_t) + sizeof(uint32_t)) {
        return;
    }
    handle.authId = provider.ConsumeIntegral<int64_t>();
    handle.type = provider.ConsumeIntegral<uint32_t>();
    AuthTransData authData = {
        .module = provider.ConsumeIntegral<int32_t>(),
        .flag = provider.ConsumeIntegral<int32_t>(),
        .seq = provider.ConsumeIntegral<int64_t>(),
        .len = provider.ConsumeIntegral<uint32_t>(),
        .data = nullptr,
    };
    // Validate len field for null data case
    // If data is null, len should ideally be 0, but we test edge cases
    if (authData.len > MAX_AUTH_DATA_LEN) {
        // Cap the length to prevent potential issues
        authData.len = MAX_AUTH_DATA_LEN;
    }
    // Check if listener callback is valid before calling
    if (g_authListener.onDataReceived == nullptr) {
        return;
    }
    g_authListener.onDataReceived(handle, &authData);
}

/**
 * @brief Fuzz test with malformed/partially filled data
 *
 * Tests handling of malformed data patterns where the buffer contains
 * a mix of fuzz data and default values.
 */
void OnAuthDataReceivedMalformedDataFuzzTest(const uint8_t *data, size_t size)
{
    auto provider = FuzzedDataProvider(data, size);
    AuthHandle handle = { 0 };
    // Check if provider has enough data before consuming handle fields
    if (provider.remaining_bytes() <
        sizeof(int64_t) + sizeof(uint32_t) + sizeof(int32_t) + sizeof(int32_t) + sizeof(int64_t)) {
        return;
    }
    handle.authId = provider.ConsumeIntegral<int64_t>();
    handle.type = provider.ConsumeIntegral<uint32_t>();
    // First, consume the parameters we need
    const auto module = provider.ConsumeIntegral<int32_t>();
    const auto flag = provider.ConsumeIntegral<int32_t>();
    const auto seq = provider.ConsumeIntegral<int64_t>();
    // Then consume remaining bytes for malformed data
    constexpr auto malformedDataSize = size_t { 1024 };
    auto malformedData = std::vector<uint8_t>(malformedDataSize, 0);
    // Validate vector allocation succeeded
    if (malformedData.empty() && malformedDataSize > 0) {
        return;
    }
    if (provider.remaining_bytes() > 0) {
        auto fuzzBytes = provider.ConsumeRemainingBytes<uint8_t>();
        const auto copySize = std::min(fuzzBytes.size(), malformedData.size());
        if (copySize > 0) {
            // Validate iterator ranges before copy
            if (fuzzBytes.begin() + copySize <= fuzzBytes.end() &&
                malformedData.begin() + copySize <= malformedData.end()) {
                // Use std::copy for safer memory operations with validated ranges
                std::copy(fuzzBytes.begin(), fuzzBytes.begin() + copySize, malformedData.begin());
            }
        }
    }
    AuthTransData authData = {
        .module = module,
        .flag = flag,
        .seq = seq,
        .len = static_cast<uint32_t>(malformedData.size()),
        .data = malformedData.data(),
    };
    // Validate data pointer and length
    if (authData.data == nullptr && authData.len > 0) {
        return;
    }
    // Check if listener callback is valid before calling
    if (g_authListener.onDataReceived == nullptr) {
        return;
    }
    g_authListener.onDataReceived(handle, &authData);
}

/**
 * @brief Fuzz test for boundary length testing
 *
 * Tests data reception with specific boundary sizes (0-256 bytes).
 * Uses MODULE_P2P_LINK as the module type.
 */
void OnAuthDataReceivedBoundaryLengthFuzzTest(const uint8_t *data, size_t size)
{
    auto provider = FuzzedDataProvider(data, size);
    AuthHandle handle = { 0 };

    // Check if provider has enough data before consuming
    if (provider.remaining_bytes() < sizeof(int64_t) + sizeof(uint32_t) + sizeof(uint32_t)) {
        return;
    }
    handle.authId = provider.ConsumeIntegral<int64_t>();
    handle.type = provider.ConsumeIntegral<uint32_t>();

    // Test boundary sizes from 0 to 256 bytes
    constexpr auto macBoundarySize = uint32_t { 256 };
    const auto boundarySize = provider.ConsumeIntegralInRange<uint32_t>(0, macBoundarySize);

    // Only consume bytes if available
    auto boundaryData = std::vector<uint8_t>(boundarySize);

    // Validate vector allocation
    if (boundaryData.size() != static_cast<size_t>(boundarySize) && boundarySize > 0) {
        return;
    }

    const auto bytesToConsume = std::min(static_cast<size_t>(boundarySize), provider.remaining_bytes());
    // Safe loop with validated bounds - check provider has enough data before each consume
    for (size_t i = 0; i < bytesToConsume && i < boundaryData.size() && provider.remaining_bytes() >= sizeof(uint8_t);
        ++i) {
        boundaryData[i] = provider.ConsumeIntegral<uint8_t>();
    }
    // Remaining bytes stay as 0 (default initialized)

    // Check if provider has enough data for seq field
    if (provider.remaining_bytes() < sizeof(int64_t)) {
        return;
    }
    AuthTransData authData = {
        .module = MODULE_P2P_LINK,
        .flag = 0,
        .seq = provider.ConsumeIntegral<int64_t>(),
        .len = boundarySize,
        .data = boundaryData.empty() ? nullptr : boundaryData.data(),
    };
    // Final validation before callback
    if (authData.len > 0 && authData.data == nullptr) {
        return;
    }
    // Check if listener callback is valid before calling
    if (g_authListener.onDataReceived == nullptr) {
        return;
    }
    g_authListener.onDataReceived(handle, &authData);
}

/**
 * @brief Fuzz test for extreme boundary values
 *
 * Tests specific boundary values that are known to be problematic:
 * - Powers of 2 boundaries
 * - MAX_AUTH_DATA_LEN boundaries
 * - Edge cases around typical buffer sizes
 */
void OnAuthDataReceivedExtremeValuesFuzzTest(const uint8_t *data, size_t size)
{
    auto provider = FuzzedDataProvider(data, size);
    AuthHandle handle = { 0 };

    // Check if provider has enough data before consuming
    if (provider.remaining_bytes() < sizeof(int64_t) + sizeof(uint32_t)) {
        return;
    }
    handle.authId = provider.ConsumeIntegral<int64_t>();
    handle.type = provider.ConsumeIntegral<uint32_t>();

    // Test critical boundary values
    static constexpr std::array<uint32_t, 36> BOUNDARY_VALUES = { 0, 1, 2, 3, 4, 5, 7, 8, 15, 16, 31, 32, 63, 64, 127,
        128, 255, 256, 511, 512, 1023, 1024, 2047, 2048, 4095, 4096, 8191, 8192, 16383, 16384, 32767, 32768, 65535,
        65536, MAX_AUTH_DATA_LEN - 1, MAX_AUTH_DATA_LEN };
    const auto len = provider.PickValueInArray(BOUNDARY_VALUES);
    // Validate length is within reasonable bounds
    if (len > static_cast<uint32_t>(MAX_AUTH_DATA_LEN)) {
        return;
    }

    // Only allocate and fill if we have data
    auto testData = std::vector<uint8_t>(len);

    // Validate vector allocation succeeded
    if (testData.size() != static_cast<size_t>(len) && len > 0) {
        return;
    }

    const auto bytesToConsume = std::min(static_cast<size_t>(len), provider.remaining_bytes());
    // Safe loop with validated bounds - check provider has enough data before each consume
    for (size_t i = 0; i < bytesToConsume && i < testData.size() && provider.remaining_bytes() >= sizeof(uint8_t);
        ++i) {
        testData[i] = provider.ConsumeIntegral<uint8_t>();
    }
    // Check if provider has enough data for remaining fields
    if (provider.remaining_bytes() < sizeof(int32_t) + sizeof(int32_t) + sizeof(int64_t)) {
        return;
    }
    AuthTransData authData = {
        .module = provider.ConsumeIntegral<int32_t>(),
        .flag = provider.ConsumeIntegral<int32_t>(),
        .seq = provider.ConsumeIntegral<int64_t>(),
        .len = len,
        .data = testData.empty() ? nullptr : testData.data(),
    };
    if (authData.len > 0 && authData.data == nullptr) {
        return;
    }
    if (g_authListener.onDataReceived == nullptr) {
        return;
    }
    g_authListener.onDataReceived(handle, &authData);
}

/**
 * @brief Fuzz test with random module and data
 *
 * Tests with completely random data from the fuzzer input,
 * consuming all remaining bytes as test data.
 */
void OnAuthDataReceivedRandomModuleTest(const uint8_t *data, size_t size)
{
    auto provider = FuzzedDataProvider(data, size);
    AuthHandle handle = { 0 };
    // Check if provider has enough data before consuming handle fields
    if (provider.remaining_bytes() <
        sizeof(int64_t) + sizeof(uint32_t) + sizeof(int32_t) + sizeof(int32_t) + sizeof(int64_t)) {
        return;
    }
    handle.authId = provider.ConsumeIntegral<int64_t>();
    handle.type = provider.ConsumeIntegral<uint32_t>();
    // First, consume the parameters we need
    const auto module = provider.ConsumeIntegral<int32_t>();
    const auto flag = provider.ConsumeIntegral<int32_t>();
    const auto seq = provider.ConsumeIntegral<int64_t>();
    // Then consume remaining bytes for data content
    auto randomData = provider.ConsumeRemainingBytes<uint8_t>();
    // Validate randomData size doesn't exceed maximum
    if (randomData.size() > static_cast<size_t>(MAX_AUTH_DATA_LEN)) {
        return;
    }
    AuthTransData authData = {
        .module = module,
        .flag = flag,
        .seq = seq,
        .len = static_cast<uint32_t>(randomData.size()),
        .data = randomData.empty() ? nullptr : randomData.data(),
    };
    if (authData.len > 0 && authData.data == nullptr) {
        return;
    }
    if (authData.len == 0 && authData.data != nullptr) {
        authData.data = nullptr;
    }
    if (g_authListener.onDataReceived == nullptr) {
        return;
    }
    g_authListener.onDataReceived(handle, &authData);
}

} // namespace OHOS

/**
 * @brief Main fuzzer entry point
 *
 * This function is called by the fuzzer engine with each test input.
 * It validates the input, initializes mocks, and dispatches to one
 * of the fuzz test functions based on the input data.
 *
 * @param data Pointer to the fuzzer-generated input data
 * @param size Size of the input data in bytes
 * @return SOFTBUS_OK on success, SOFTBUS_INVALID_PARAM on invalid input
 */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Validate input parameters
    if (data == nullptr || size < sizeof(int32_t)) {
        return SOFTBUS_INVALID_PARAM;
    }

    OHOS::InitMockAndListener();

    // Array of all fuzz test functions - each targets a specific aspect
    // The size is automatically calculated to prevent index errors
    using FuzzFunc = void (*)(const uint8_t *, size_t);
    static const FuzzFunc fuzzFuncs[] = {
        OHOS::OnAuthDataReceivedFuzzTest,               // Standard test
        OHOS::OnAuthDataReceivedNullDataFuzzTest,       // Null pointer test
        OHOS::OnAuthDataReceivedOversizedDataFuzzTest,  // Oversized data test
        OHOS::OnAuthDataReceivedNullInnerDataFuzzTest,  // Null inner data test
        OHOS::OnAuthDataReceivedMalformedDataFuzzTest,  // Malformed data test
        OHOS::OnAuthDataReceivedBoundaryLengthFuzzTest, // Boundary length test
        OHOS::OnAuthDataReceivedExtremeValuesFuzzTest,  // Extreme values test
        OHOS::OnAuthDataReceivedRandomModuleTest,       // Random data test
    };
    static constexpr size_t fuzzFuncCount = sizeof(fuzzFuncs) / sizeof(fuzzFuncs[0]);

    auto provider = FuzzedDataProvider(data, size);
    // Array size is calculated at compile time - no magic numbers
    const auto testCase = provider.ConsumeIntegralInRange<int>(0, static_cast<int>(fuzzFuncCount) - 1);
    fuzzFuncs[testCase](data, size);

    return SOFTBUS_OK;
}
