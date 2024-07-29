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

#ifndef FUZZ_DATA_GENERATOR_H
#define FUZZ_DATA_GENERATOR_H

#include <cstdint>
#include <string>
#include <vector>

#include "parcel.h"

class DataGenerator {
public:
    static void Write(const uint8_t *data, size_t size)
    {
        DataGenerator::parcel_.WriteBuffer(data, size);
        DataGenerator::parcel_.RewindRead(0);
    }

    static void Clear()
    {
        DataGenerator::parcel_.FlushBuffer();
    }

    static OHOS::Parcel &GetInstance()
    {
        return DataGenerator::parcel_;
    }

private:
    static inline OHOS::Parcel parcel_;
};

template <typename T>
inline bool GenerateFromList(T &value, const std::vector<T> &candidateValues)
{
    if (candidateValues.empty()) {
        return false;
    }
    uint8_t rawData = 0;
    if (!DataGenerator::GetInstance().ReadUint8(rawData)) {
        return false;
    }
    value = candidateValues[rawData % candidateValues.size()];
    return true;
}

inline bool GenerateBool(bool &value)
{
    return DataGenerator::GetInstance().ReadBool(value);
}

inline bool GenerateInt8(int8_t &value)
{
    return DataGenerator::GetInstance().ReadInt8(value);
}

inline bool GenerateInt16(int16_t &value)
{
    return DataGenerator::GetInstance().ReadInt16(value);
}

inline bool GenerateInt32(int32_t &value)
{
    return DataGenerator::GetInstance().ReadInt32(value);
}

inline bool GenerateInt64(int64_t &value)
{
    return DataGenerator::GetInstance().ReadInt64(value);
}

inline bool GenerateUint8(uint8_t &value)
{
    return DataGenerator::GetInstance().ReadUint8(value);
}

inline bool GenerateUint16(uint16_t &value)
{
    return DataGenerator::GetInstance().ReadUint16(value);
}

inline bool GenerateUint32(uint32_t &value)
{
    return DataGenerator::GetInstance().ReadUint32(value);
}

inline bool GenerateUint64(uint64_t &value)
{
    return DataGenerator::GetInstance().ReadUint64(value);
}

inline bool GenerateFloat(float &value)
{
    return DataGenerator::GetInstance().ReadFloat(value);
}

inline bool GenerateDouble(double &value)
{
    return DataGenerator::GetInstance().ReadDouble(value);
}

inline bool GenerateString(std::string &value)
{
    return DataGenerator::GetInstance().ReadString(value);
}

inline bool GeneratePayload(std::vector<uint8_t> &payload, const std::vector<uint8_t> &prefix = {})
{
    uint8_t len = 0;
    if (!DataGenerator::GetInstance().ReadUint8(len)) {
        return false;
    }
    size_t readableSize = DataGenerator::GetInstance().GetReadableBytes();
    len = (readableSize == 0) ? 0 : (len % readableSize);
    payload.push_back(len + prefix.size());
    payload.insert(payload.end(), prefix.begin(), prefix.end());
    for (uint8_t i = 0; i < len; ++i) {
        payload.push_back(DataGenerator::GetInstance().ReadUint8());
    }
    return true;
}

#endif // FUZZ_DATA_GENERATOR_H
