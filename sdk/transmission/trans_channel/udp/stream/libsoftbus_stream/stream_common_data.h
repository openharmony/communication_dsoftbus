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

#ifndef STREAM_COMMON_DATA_H
#define STREAM_COMMON_DATA_H

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <sys/types.h>

#include "i_stream.h"
#include "stream_common.h"

namespace Communication {
namespace SoftBus {
class StreamCommonData : public IStream {
public:
    StreamCommonData() = default;
    StreamCommonData(uint32_t streamId, uint16_t seq, const StreamFrameInfo& frameInfo);

    ~StreamCommonData() override = default;

    // 应用调用生成流数据。
    int InitStreamData(std::unique_ptr<char[]> inputBuf, ssize_t bufSize, std::unique_ptr<char[]> inputExt,
        ssize_t extSize);

    void SetTimeStamp(uint32_t timestamp) override
    {
        static_cast<void>(timestamp);
    }

    virtual uint32_t GetTimeStamp() const override
    {
        return 0;
    }

    std::unique_ptr<char[]> GetBuffer() override
    {
        return std::unique_ptr<char[]>(streamData_.release());
    }

    ssize_t GetBufferLen() const override
    {
        return streamLen_;
    }

    std::unique_ptr<char[]> GetExtBuffer() override
    {
        return std::unique_ptr<char[]>(extBuf_.release());
    }

    ssize_t GetExtBufferLen() const override
    {
        return extBufLen_;
    }

    int GetSeqNum() const override
    {
        return curSeqNum_;
    }

    uint32_t GetStreamId() const override
    {
        return curStreamId_;
    }

    const StreamFrameInfo* GetStreamFrameInfo() const override
    {
        return &streamFrameInfo_;
    }

protected:
    std::unique_ptr<char[]> streamData_ = nullptr;
    ssize_t streamLen_ = 0;

    /*
     * 额外buffer信息，随着帧一起传输到对端
     */
    std::unique_ptr<char[]> extBuf_ = nullptr;
    ssize_t extBufLen_ = 0;

    uint16_t curSeqNum_ = 0;
    uint32_t curStreamId_ = 0;

    StreamFrameInfo streamFrameInfo_;
};
} // namespace SoftBus
} // namespace Communication

#endif