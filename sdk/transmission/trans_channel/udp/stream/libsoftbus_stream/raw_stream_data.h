/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef RAW_STREAM_DATA_H
#define RAW_STREAM_DATA_H

#include <cstdint>
#include <memory>
#include <sys/types.h>

#include "i_stream.h"

namespace Communication {
namespace SoftBus {
class RawStreamData : public IStream {
public:
    RawStreamData() = default;
    explicit RawStreamData(const StreamFrameInfo &frameInfo);
    ~RawStreamData() override = default;
    static constexpr int BYTE_TO_BIT = 8;
    static constexpr int INT_TO_BYTE = 0xff;
    static constexpr int FRAME_HEADER_LEN = 4;

    int InitStreamData(std::unique_ptr<char[]> buffer, ssize_t bufLen, std::unique_ptr<char[]> extBuffer,
        ssize_t extLen);

    std::unique_ptr<char[]> GetBuffer() override;
    ssize_t GetBufferLen() const override;

    static void InsertBufferLength(int num, int length, uint8_t *output);

private:
    void SetTimeStamp(uint32_t timestamp) override
    {
        static_cast<void>(timestamp);
    }
    uint32_t GetTimeStamp() const override
    {
        return 0;
    }

    std::unique_ptr<char[]> GetExtBuffer() override
    {
        return nullptr;
    }

    ssize_t GetExtBufferLen() const override
    {
        return 0;
    }

    int GetSeqNum() const override
    {
        return 0;
    }

    uint32_t GetStreamId() const override
    {
        return 0;
    }

    const StreamFrameInfo* GetStreamFrameInfo() const override
    {
        return &streamFrameInfo_;
    }

    std::unique_ptr<char[]> streamData_ = nullptr;
    ssize_t streamLen_ = 0;
    StreamFrameInfo streamFrameInfo_;
};
} // namespace SoftBus
} // namespace Communication
#endif