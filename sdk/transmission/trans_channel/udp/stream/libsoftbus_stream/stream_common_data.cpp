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

#include "stream_common_data.h"

#include "common_inner.h"

namespace Communication {
namespace SoftBus {
std::unique_ptr<IStream> IStream::MakeCommonStream(StreamData &data, const StreamFrameInfo &info)
{
    auto stream = std::make_unique<StreamCommonData>(info.streamId, info.seqNum, info);
    stream->InitStreamData(std::move(data.buffer), data.bufLen, std::move(data.extBuffer), data.extLen);

    return stream;
}

StreamCommonData::StreamCommonData(uint32_t streamId, uint16_t seq, const StreamFrameInfo& frameInfo)
{
    curSeqNum_ = seq;
    curStreamId_ = streamId;
    streamFrameInfo_ = frameInfo;
}

int StreamCommonData::InitStreamData(std::unique_ptr<char[]> inputBuf, ssize_t bufSize,
    std::unique_ptr<char[]> inputExt, ssize_t extSize)
{
    if (inputBuf == nullptr) {
        TRANS_LOGE(TRANS_STREAM, "InitStreamData: Stream MUST not be null");
        return -1;
    }
    streamData_ = std::move(inputBuf);
    streamLen_ = bufSize;

    if (inputExt == nullptr) {
        extBuf_ = nullptr;
        extBufLen_ = 0;
    } else {
        extBuf_ = std::move(inputExt);
        extBufLen_ = extSize;
    }

    return 0;
}
} // namespace SoftBus
} // namespace Communication
