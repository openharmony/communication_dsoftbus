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

#ifndef JSONPROTOCOLAI_FUZZER_H
#define JSONPROTOCOLAI_FUZZER_H

#include <cstddef>
#include <cstdint>

namespace OHOS {
void JsonProtocolSetInputFuzzTest(const uint8_t *data, size_t size);
void JsonProtocolReadFuzzTest(const uint8_t *data, size_t size);
void JsonProtocolWriteFuzzTest(const uint8_t *data, size_t size);
void JsonProtocolMalformedJsonFuzzTest(const uint8_t *data, size_t size);
void JsonProtocolNullValueFuzzTest(const uint8_t *data, size_t size);
void JsonProtocolWriteZeroSizeFuzzTest(const uint8_t *data, size_t size);
void JsonProtocolOversizedStringFuzzTest(const uint8_t *data, size_t size);
void JsonProtocolBoundaryLengthFuzzTest(const uint8_t *data, size_t size);
void JsonProtocolUnknownKeyFuzzTest(const uint8_t *data, size_t size);
void JsonProtocolAllValueTypesFuzzTest(const uint8_t *data, size_t size);
void JsonProtocolNumberTypeFuzzTest(const uint8_t *data, size_t size);
void JsonProtocolEmptyJsonFuzzTest(const uint8_t *data, size_t size);
void JsonProtocolInvalidValueTypeFuzzTest(const uint8_t *data, size_t size);
} // namespace OHOS

#endif // JSONPROTOCOLAI_FUZZER_H
