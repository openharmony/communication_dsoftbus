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

#include "stream_packetizer.h"

#include "common_inner.h"
#include "securec.h"
#include "stream_packet_header.h"

namespace Communication {
namespace SoftBus {
ssize_t StreamPacketizer::CalculateHeaderSize() const
{
    auto total = StreamPacketHeader::STREAM_HEADER_SIZE;

    return total;
}

ssize_t StreamPacketizer::CalculateExtSize(ssize_t extSize) const
{
    auto total = 0;

    if (extSize > 0) {
        total += TwoLevelsTlv::HEADER_LEN + TwoLevelsTlv::NUMS_LEN;
        total += TwoLevelsTlv::HEADER_LEN + TwoLevelsTlv::NUMS_LEN;
        total += Align(extSize, SHIFT);
        total += TwoLevelsTlv::CHECK_SUM_LEN;
    }

    return total;
}

std::unique_ptr<char[]> StreamPacketizer::PacketizeStream()
{
    dataSize_ = originData_->GetBufferLen();
    hdrSize_ = CalculateHeaderSize();
    extSize_ = CalculateExtSize(originData_->GetExtBufferLen());
    auto data = std::make_unique<char[]>(hdrSize_ + extSize_ + dataSize_);

    auto streamPktHeader = StreamPacketHeader(streamType_, extSize_ > 0, extSize_ + dataSize_,
        originData_->GetStreamFrameInfo());
    streamPktHeader.Packetize(data.get(), hdrSize_, 0);

    TwoLevelsTlv tlv(originData_->GetExtBuffer(), originData_->GetExtBufferLen());
    if (tlv.Packetize(data.get(), extSize_, hdrSize_) != 0) {
        TRANS_LOGE(TRANS_STREAM, "packetize tlv failed");
        return nullptr;
    }

    TRANS_LOGD(TRANS_STREAM,
        "streamPktHeader version=%{public}d, subVersion=%{public}d, extFlag=%{public}d, streamType=%{public}d, "
        "marker=%{public}d, flag=%{public}d, streamId=%{public}d(%{public}x), timestamp=%{public}u(%{public}x), "
        "dataLen=%{public}u(%{public}x), seqNum=%{public}d(%{public}x), subSeqNum=%{public}d(%{public}x), "
        "dataSize=%{public}zd, extSize=%{public}zd",
        streamPktHeader.GetVersion(), streamPktHeader.GetSubVersion(), streamPktHeader.GetExtFlag(),
        streamPktHeader.GetStreamType(), streamPktHeader.GetMarker(), streamPktHeader.GetFlag(),
        streamPktHeader.GetStreamId(), streamPktHeader.GetStreamId(), streamPktHeader.GetTimestamp(),
        streamPktHeader.GetTimestamp(), streamPktHeader.GetDataLen(), streamPktHeader.GetDataLen(),
        streamPktHeader.GetSeqNum(), streamPktHeader.GetSeqNum(), streamPktHeader.GetSubSeqNum(),
        streamPktHeader.GetSubSeqNum(), dataSize_, extSize_);

    TRANS_LOGD(TRANS_STREAM,
        "TLV version=%{public}d, num=%{public}d, extSize=%{public}zd, extLen=%{public}zd, checksum=%{public}u",
        tlv.GetVersion(), tlv.GetTlvNums(), extSize_, tlv.GetExtLen(), tlv.GetCheckSum());

    auto ret = memcpy_s(data.get() + hdrSize_ + extSize_, dataSize_, originData_->GetBuffer().get(),
        originData_->GetBufferLen());
    if (ret != 0) {
        TRANS_LOGE(TRANS_STREAM, "Failed to memcpy data! ret=%{public}d", ret);
    }

    return data;
}
} // namespace SoftBus
} // namespace Communication
