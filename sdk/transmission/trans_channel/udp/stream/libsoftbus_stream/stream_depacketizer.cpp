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

#include "stream_depacketizer.h"

#include "common_inner.h"
#include "i_stream.h"

namespace Communication {
namespace SoftBus {
void StreamDepacketizer::DepacketizeHeader(const char *header)
{
    if (streamType_ == COMMON_VIDEO_STREAM || streamType_ == COMMON_AUDIO_STREAM) {
        const char *ptr = header;
        header_.Depacketize(ptr);

        TRANS_LOGD(TRANS_STREAM,
            "streamPktHeader version=%{public}d, subVersion=%{public}d, extFlag=%{public}d, streamType=%{public}d, "
            "marker=%{public}d, flag=%{public}d, streamId=%{public}d(%{public}x), timestamp=%{public}u(%{public}x), "
            "dataLen=%{public}u(%{public}x), seqNum=%{public}d(%{public}x), subSeqNum=%{public}d(%{public}x)",
            header_.GetVersion(), header_.GetSubVersion(), header_.GetExtFlag(), header_.GetStreamType(),
            header_.GetMarker(), header_.GetFlag(), header_.GetStreamId(), header_.GetStreamId(),
            header_.GetTimestamp(), header_.GetTimestamp(), header_.GetDataLen(), header_.GetDataLen(),
            header_.GetSeqNum(), header_.GetSeqNum(), header_.GetSubSeqNum(), header_.GetSubSeqNum());
    }
}

void StreamDepacketizer::DepacketizeBuffer(char *buffer, uint32_t bufferSize)
{
    char *ptr = buffer;
    uint32_t tlvTotalLen = 0;
    if (header_.GetExtFlag() != 0) {
        tlvs_.Depacketize(ptr, bufferSize);
        TRANS_LOGD(TRANS_STREAM, "TLV version=%{public}d, num=%{public}d, extLen=%{public}zd, checksum=%{public}u",
            tlvs_.GetVersion(), tlvs_.GetTlvNums(), tlvs_.GetExtLen(), tlvs_.GetCheckSum());

        tlvTotalLen = tlvs_.GetCheckSum() + sizeof(tlvs_.GetCheckSum());
        ptr += tlvTotalLen;
    }

    dataLength_ = static_cast<int>(header_.GetDataLen() - tlvTotalLen);
    if (dataLength_ <= 0 || dataLength_ > MAX_STREAM_LEN) {
        TRANS_LOGE(
            TRANS_STREAM,
            "error. headerDataLen=%{public}u, tlvTotalLen=%{public}u", header_.GetDataLen(), tlvTotalLen);
        return;
    }

    int remain = static_cast<int>(bufferSize - (ptr - buffer));
    if (remain < dataLength_) {
        TRANS_LOGE(TRANS_STREAM, "Data out of bounds, remain=%{public}d, dataLen=%{public}d", remain, dataLength_);
        return;
    }

    data_ = std::make_unique<char[]>(dataLength_);
    auto ret = memcpy_s(data_.get(), dataLength_, ptr, dataLength_);
    if (ret != 0) {
        TRANS_LOGE(TRANS_STREAM, "Failed to memcpy data_, ret=%{public}d", ret);
        dataLength_ = -1;
    }
}
} // namespace SoftBus
} // namespace Communication
