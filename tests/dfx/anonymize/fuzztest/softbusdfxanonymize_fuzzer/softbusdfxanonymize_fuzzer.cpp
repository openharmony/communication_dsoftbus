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

#include "softbusdfxanonymize_fuzzer.h"

#include <string>
#include "anonymizer.h"

extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    std::string str(reinterpret_cast<const char *>(data), size);

    char *anonymized = nullptr;
    Anonymize(str.c_str(), &anonymized);
    AnonymizeWrapper(anonymized);
    AnonymizeFree(anonymized);

    AnonymizeDeviceName(str.c_str(), &anonymized);
    AnonymizeWrapper(anonymized);
    AnonymizeFree(anonymized);
    return 0;
}
