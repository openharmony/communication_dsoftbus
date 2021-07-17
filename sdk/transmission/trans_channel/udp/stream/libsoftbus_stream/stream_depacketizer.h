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

#ifndef STREAM_DEPACKETTIZER_H
#define STREAM_DEPACKETTIZER_H

#include <memory>
#include <utility>

#include "stream_packet_header.h"

namespace Communication {
namespace SoftBus {
class StreamDepacketizer {
public:
    explicit StreamDepacketizer(int type) : streamType_(type) {}
    virtual ~StreamDepacketizer() = default;

    void DepacketizeHeader(const char *header);
    void DepacketizeBuffer(char *buffer);

    uint32_t GetHeaderDataLen() const
    {
        return header_.GetDataLen();
    }

    uint32_t GetStreamId() const
    {
        return header_.GetStreamId();
    }

    uint32_t GetSeqNum() const
    {
        return header_.GetSeqNum();
    }

    std::unique_ptr<char[]> GetUserExt()
    {
        return tlvs_.GetExtBuffer();
    }

    ssize_t GetUserExtSize() const
    {
        return tlvs_.GetExtLen();
    }

    std::unique_ptr<char[]> GetData()
    {
        return std::move(data_);
    }

    int GetDataLength() const
    {
        return dataLength_;
    }

private:
    int streamType_;
    StreamPacketHeader header_ {};
    TwoLevelsTlv tlvs_ {};
    std::unique_ptr<char[]> data_ = nullptr;
    int dataLength_ = 0;
};
} // namespace SoftBus
} // namespace Communication

#endif
