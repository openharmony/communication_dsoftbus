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

#ifndef STREAM_PACKETIZER_H
#define STREAM_PACKETIZER_H

#include <memory>
#include <sys/types.h>
#include <utility>

#include "i_stream.h"

namespace Communication {
namespace SoftBus {
class StreamPacketizer {
public:
    StreamPacketizer(int streamType, std::unique_ptr<IStream> data)
    {
        originData_ = std::move(data);
        streamType_ = streamType;
    }
    virtual ~StreamPacketizer() = default;

    ssize_t CalculateHeaderSize() const;
    ssize_t CalculateExtSize(ssize_t extSize) const;

    std::unique_ptr<char[]> PacketizeStream();
    ssize_t GetPacketLen() const
    {
        return hdrSize_ + dataSize_ + extSize_;
    }

    ssize_t GetHeaderLen() const
    {
        return hdrSize_ + extSize_;
    }

private:
    ssize_t hdrSize_ = 0;
    ssize_t dataSize_ = 0;
    ssize_t extSize_ = 0;
    std::unique_ptr<IStream> originData_ = nullptr;
    int streamType_ = INVALID;
};
} // namespace SoftBus
} // namespace Communication

#endif
