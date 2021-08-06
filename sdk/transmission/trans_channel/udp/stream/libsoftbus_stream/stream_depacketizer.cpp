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

#define LOG_TAG "STREAM-DEPACKETTIZER"

namespace Communication {
namespace SoftBus {
void StreamDepacketizer::DepacketizeHeader(const char *header)
{
    if (streamType_ == COMMON_VIDEO_STREAM || streamType_ == COMMON_AUDIO_STREAM) {
        const char *ptr = header;
        header_.Depacketize(ptr);

        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_DBG,
            "streamPktHeader version = %d, subVersion = %d, extFlag = %d, streamType = %d, marker = %d, flag = %d"
            "streamId = %d (%x), timestamp = %u (%x), dataLen = %u (%x), seqNum = %d (%x), subSeqNum = %d (%x)",
            header_.GetVersion(), header_.GetSubVersion(), header_.GetExtFlag(), header_.GetStreamType(),
            header_.GetMarker(), header_.GetFlag(), header_.GetStreamId(), header_.GetStreamId(),
            header_.GetTimestamp(), header_.GetTimestamp(), header_.GetDataLen(), header_.GetDataLen(),
            header_.GetSeqNum(), header_.GetSeqNum(), header_.GetSubSeqNum(), header_.GetSubSeqNum());
    }
}

void StreamDepacketizer::DepacketizeBuffer(char *buffer)
{
    char *ptr = buffer;
    int tlvTotalLen = 0;
    if (header_.GetExtFlag() != 0) {
        tlvs_.Depacketize(ptr);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO,
            "TLV version: %d, num = %d, extLen = %zd, checksum = %u", tlvs_.GetVersion(), tlvs_.GetTlvNums(),
            tlvs_.GetExtLen(), tlvs_.GetCheckSum());

        tlvTotalLen = tlvs_.GetCheckSum() + sizeof(tlvs_.GetCheckSum());
        ptr += tlvTotalLen;
    }

    dataLength_ = header_.GetDataLen() - tlvTotalLen;
    if (dataLength_ <= 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
            "DepacketizeBuffer error, header_dataLen = %d, tlvTotalLen = %d", header_.GetDataLen(), tlvTotalLen);
        return;
    }
    data_ = std::make_unique<char[]>(dataLength_);
    auto ret = memcpy_s(data_.get(), dataLength_, ptr, dataLength_);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Failed to memcpy data_, ret:%d", ret);
        dataLength_ = -1;
    }
}
} // namespace SoftBus
} // namespace Communication
