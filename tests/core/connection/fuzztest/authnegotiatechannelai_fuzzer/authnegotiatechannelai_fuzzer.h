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
#ifndef AUTHNEGOTIATECHANNELAI_FUZZER_H
#define AUTHNEGOTIATECHANNELAI_FUZZER_H

#include <cstddef>
#include <cstdint>

namespace OHOS {

/**
 * @brief Standard fuzz test for authentication data reception
 * @param data Fuzzer-generated input data
 * @param size Size of input data in bytes
 */
void OnAuthDataReceivedFuzzTest(const uint8_t *data, size_t size);

/**
 * @brief Fuzz test with null AuthTransData pointer
 * @param data Fuzzer-generated input data
 * @param size Size of input data in bytes
 */
void OnAuthDataReceivedNullDataFuzzTest(const uint8_t *data, size_t size);

/**
 * @brief Fuzz test with oversized data length (exceeds MAX_AUTH_DATA_LEN)
 * @param data Fuzzer-generated input data
 * @param size Size of input data in bytes
 */
void OnAuthDataReceivedOversizedDataFuzzTest(const uint8_t *data, size_t size);

/**
 * @brief Fuzz test with null inner data pointer
 * @param data Fuzzer-generated input data
 * @param size Size of input data in bytes
 */
void OnAuthDataReceivedNullInnerDataFuzzTest(const uint8_t *data, size_t size);

/**
 * @brief Fuzz test with malformed/partially filled data
 * @param data Fuzzer-generated input data
 * @param size Size of input data in bytes
 */
void OnAuthDataReceivedMalformedDataFuzzTest(const uint8_t *data, size_t size);

/**
 * @brief Fuzz test for boundary length testing (0-256 bytes)
 * @param data Fuzzer-generated input data
 * @param size Size of input data in bytes
 */
void OnAuthDataReceivedBoundaryLengthFuzzTest(const uint8_t *data, size_t size);

/**
 * @brief Fuzz test for extreme boundary values
 * @param data Fuzzer-generated input data
 * @param size Size of input data in bytes
 */
void OnAuthDataReceivedExtremeValuesFuzzTest(const uint8_t *data, size_t size);

/**
 * @brief Fuzz test with random module and data
 * @param data Fuzzer-generated input data
 * @param size Size of input data in bytes
 */
void OnAuthDataReceivedRandomModuleTest(const uint8_t *data, size_t size);

} // namespace OHOS

#endif // AUTHNEGOTIATECHANNELAI_FUZZER_H
