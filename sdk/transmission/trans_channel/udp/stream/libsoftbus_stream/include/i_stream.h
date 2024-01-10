/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef I_STREAM_DATA_H
#define I_STREAM_DATA_H

#include <cstdint>
#include <memory>
#include <sys/types.h>

#include "stream_common.h"

namespace Communication {
namespace SoftBus {
struct StreamData {
    std::unique_ptr<char[]> buffer = nullptr;
    ssize_t bufLen = 0;
    std::unique_ptr<char[]> extBuffer = nullptr;
    ssize_t extLen = 0;
};

// APP should update StreamFrameInfo each time.
struct StreamFrameInfo {
    uint32_t streamId = 0;
    uint32_t seqNum = 0;
    uint32_t level = 0;
    FrameType frameType = NONE;
    uint32_t seqSubNum = 0;
    uint32_t bitMap = 0;
    uint32_t timeStamp = 0;
    uint32_t bitrate = 0;
};

class IStream {
public:
    IStream() = default;
    virtual ~IStream() = default;

    static std::unique_ptr<IStream> MakeCommonStream(StreamData &data, const StreamFrameInfo &info);
    static std::unique_ptr<IStream> MakeSliceStream(StreamData &data, const StreamFrameInfo &info);
    static std::unique_ptr<IStream> MakeRawStream(StreamData &data, const StreamFrameInfo &info);
    static std::unique_ptr<IStream> MakeRawStream(const char *buf, ssize_t bufLen, const StreamFrameInfo &info,
        int scene);

    virtual void SetTimeStamp(uint32_t timestamp) = 0;
    virtual uint32_t GetTimeStamp() const = 0;

    virtual std::unique_ptr<char[]> GetBuffer() = 0;
    virtual ssize_t GetBufferLen() const = 0;
    virtual std::unique_ptr<char[]> GetExtBuffer() = 0;
    virtual ssize_t GetExtBufferLen() const = 0;

    virtual int GetSeqNum() const = 0;
    virtual uint32_t GetStreamId() const = 0;
    virtual const StreamFrameInfo* GetStreamFrameInfo() const = 0;
};
}; // namespace SoftBus
}; // namespace Communication

#endif //I_STREAM_DATA_H