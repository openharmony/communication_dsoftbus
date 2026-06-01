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

#ifndef TLVPROTOCOLAI_FUZZER_H
#define TLVPROTOCOLAI_FUZZER_H

#include <cstddef>
#include <cstdint>

namespace OHOS {
void TlvProtocolSetInputFuzzTest(const uint8_t *data, size_t size);
void TlvProtocolWriteFuzzTest(const uint8_t *data, size_t size);
void TlvProtocolReadFuzzTest(const uint8_t *data, size_t size);
void TlvProtocolNullValueFuzzTest(const uint8_t *data, size_t size);
void TlvProtocolWriteZeroSizeFuzzTest(const uint8_t *data, size_t size);
void TlvProtocolInsufficientHeaderFuzzTest(const uint8_t *data, size_t size);
void TlvProtocolLengthExceedsDataFuzzTest(const uint8_t *data, size_t size);
void TlvProtocolBoundaryLengthFuzzTest(const uint8_t *data, size_t size);
void TlvProtocolVariousFormatsFuzzTest(const uint8_t *data, size_t size);
void TlvProtocolEmptyDataFuzzTest(const uint8_t *data, size_t size);
void TlvProtocolMultipleItemsFuzzTest(const uint8_t *data, size_t size);
void TlvProtocolMaxLengthFuzzTest(const uint8_t *data, size_t size);
void TlvProtocolWriteReadConsistencyFuzzTest(const uint8_t *data, size_t size);
} // namespace OHOS

#endif // TLVPROTOCOLAI_FUZZER_H
