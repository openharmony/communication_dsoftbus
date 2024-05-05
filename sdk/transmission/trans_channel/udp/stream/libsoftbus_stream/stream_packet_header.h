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

#ifndef STREAM_PACKET_HEADER_H
#define STREAM_PACKET_HEADER_H

#include <arpa/inet.h>
#include <chrono>
#include <cstdint>
#include <memory>
#include <sys/types.h>
#include <utility>
#include <vector>

#include "securec.h"
#include "stream_common.h"
#include "i_stream.h"

using ::std::chrono::duration_cast;
using ::std::chrono::milliseconds;
using ::std::chrono::system_clock;

namespace Communication {
namespace SoftBus {
static constexpr int SHIFT = 2;
// Align x up to the nearest integer multiple of 2*shift
inline static int Align(int x, int shift)
{
    auto tmpValue = static_cast<unsigned int>(x);
    auto tmpShift = static_cast<unsigned int>(shift);
    return static_cast<int>((tmpValue + ((1 << tmpShift) - 1)) & ~((1 << tmpShift) - 1));
}

inline static int AlignTo4Bytes(int x)
{
    return Align(x, SHIFT);
}

struct CommonHeader {
    uint8_t version : 2;
    uint8_t subVersion : 1;
    uint8_t extFlag : 1;
    uint8_t streamType : 4;
    uint8_t marker : 1;
    uint8_t flag : 1;
    uint8_t level : 4;
    uint8_t pad : 2;
    uint16_t streamId;
    uint32_t timestamp;
    uint32_t dataLen;
    uint16_t seqNum;
    uint16_t subSeqNum;
};

struct TypeLength {
    uint16_t type = 0;
    uint32_t length = 0;
};

class TwoLevelsTlv {
public:
    static constexpr int HEADER_LEN = 2;
    static constexpr int NUMS_LEN = 2;
    static constexpr int CHECK_SUM_LEN = 4;

    TwoLevelsTlv()
    {
        SetTlvVersion(0);
    }
    TwoLevelsTlv(std::unique_ptr<char[]> extBuf, ssize_t extSize)
    {
        SetTlvVersion(0);
        ext_ = std::move(extBuf);
        extLen_ = extSize;
    }

    virtual ~TwoLevelsTlv() = default;

    void SetTlvVersion(uint16_t version)
    {
        firstLevelHeader.type |= (static_cast<uint16_t>(version << TopOffset::VERSION_OFFSET) & TopMask::VERSION_MASK);
    }

    uint16_t GetVersion() const
    {
        return (firstLevelHeader.type & TopMask::VERSION_MASK) >> TopOffset::VERSION_OFFSET;
    }

    int Packetize(char *start, ssize_t size, ssize_t offset)
    {
        char *pos = new (start + offset) char[size];
        if (ext_ != nullptr) {
            auto extTlvAlignSize = HEADER_LEN + NUMS_LEN + AlignTo4Bytes(extLen_);
            if (AddFrameExtData(pos + HEADER_LEN + NUMS_LEN) != 0) {
                return -1;
            }
            checkSum_ += static_cast<uint32_t>(extTlvAlignSize);
        } else {
            return 0; // 目前假设只有ext，其他option后面添加
        }

        checkSum_ += HEADER_LEN + NUMS_LEN;

        auto tmp = reinterpret_cast<uint16_t *>(pos);
        *(tmp++) = htons(firstLevelHeader.type);
        *(tmp++) = htons(firstLevelHeader.length);

        // size is always bigger than CHECK_SUM_LEN
        auto checkSumTmp = reinterpret_cast<uint32_t *>(pos + (size - CHECK_SUM_LEN));
        *checkSumTmp = htonl(checkSum_);
        return 0;
    }

    void Depacketize(char *data, uint32_t size)
    {
        if (size < sizeof(uint16_t) + sizeof(uint16_t)) {
            return;
        }
        auto tmp = reinterpret_cast<uint16_t *>(data);
        firstLevelHeader.type = ntohs(*tmp++);
        firstLevelHeader.length = ntohs(*tmp++);

        if (firstLevelHeader.type & TopMask::EXT_BUF_MASK) {
            constexpr uint32_t extFiledNum = 4;
            if (size < sizeof(uint16_t) * extFiledNum) {
                return;
            }
            TypeLength tl;
            tl.type = ntohs(*tmp++);
            tl.length = ntohs(*tmp++);

            if (tl.length == 0 || sizeof(uint16_t) * extFiledNum + tl.length > size) {
                return;
            }
            ext_ = std::make_unique<char[]>(tl.length);
            int ret = memcpy_s(ext_.get(), tl.length, reinterpret_cast<void *>(tmp), tl.length);
            if (ret == 0) {
                extLen_ = static_cast<ssize_t>(tl.length);
            }
        }

        checkSum_ = ntohl(*reinterpret_cast<uint32_t *>((reinterpret_cast<char *>(tmp) + AlignTo4Bytes(extLen_))));
    }

    uint16_t GetTlvNums() const
    {
        return firstLevelHeader.length;
    }

    ssize_t GetExtLen() const
    {
        return extLen_;
    }

    uint32_t GetCheckSum() const
    {
        return checkSum_;
    }

    std::unique_ptr<char[]> GetExtBuffer()
    {
        return std::move(ext_);
    }

private:
    enum TopMask {
        VERSION_MASK = 0xC000,
        EXT_BUF_MASK = 0x0001,
        OPTION_MASK = 0x0002,
    };

    enum TopOffset {
        VERSION_OFFSET = 14,
        EXT_BUF_OFFSET = 0,
        OPTION_OFFSET = 1,
    };

    enum BottomMask {
        LEN_MASK = 0x8000,
        EXT_MASK = 0x0001,
    };

    enum BottomOffset {
        EXT_OFFSET = 0,
    };

    int AddFrameExtData(char *start)
    {
        firstLevelHeader.type |= ((1 << TopOffset::EXT_BUF_OFFSET) & TopMask::EXT_BUF_MASK);
        firstLevelHeader.length++;

        TypeLength extTlv {};
        extTlv.type = 0;
        extTlv.length = static_cast<uint16_t>(extLen_);

        auto pos = reinterpret_cast<uint16_t *>(start);
        *(pos++) = htons(extTlv.type);
        *(pos++) = htons(extTlv.length);

        char *extPos = reinterpret_cast<char *>(pos);
        int ret = memcpy_s(extPos, AlignTo4Bytes(extLen_), ext_.get(), extLen_);
        if (ret != 0) {
            return -1;
        }
        return 0;
    }

    uint32_t checkSum_ = 0;
    TypeLength firstLevelHeader {};
    std::vector<TypeLength> tlvList_ {};
    std::unique_ptr<char[]> ext_ = nullptr;
    ssize_t extLen_ = 0;
};

class StreamPacketHeader {
public:
    static constexpr int STREAM_HEADER_SIZE = 16;
    static constexpr int VERSION = 0;
    static constexpr int SUB_VERSION = 1;

    static constexpr uint32_t VERSION_OFFSET = 30;
    static constexpr uint32_t SUB_VERSION_OFFSET = 29;
    static constexpr uint32_t EXT_FLAG_OFFSET = 28;
    static constexpr uint32_t STREAM_TYPE_OFFSET = 24;
    static constexpr uint32_t MAKER_OFFSET = 23;
    static constexpr uint32_t FLAG_OFFSET = 22;
    static constexpr uint32_t LEVEL_OFFSET = 18;
    static constexpr uint32_t SEQ_NUM_OFFSET = 0;

    static constexpr uint32_t WORD_SIZE = 16;

    StreamPacketHeader() {}
    StreamPacketHeader(uint8_t streamType, bool extended, uint32_t dataLen,
        const Communication::SoftBus::StreamFrameInfo* streamFrameInfo)
    {
        uint32_t ts = 0;
        if (streamFrameInfo->timeStamp == 0) {
            const auto now = system_clock::now();
            const auto ms = duration_cast<milliseconds>(now.time_since_epoch()).count();
            ts = static_cast<uint32_t>(ms);
        } else {
            ts = streamFrameInfo->timeStamp;
        }

        SetVersion(VERSION, SUB_VERSION);
        commonHeader_.extFlag = extended ? 1 : 0;
        commonHeader_.streamType = streamType;
        commonHeader_.marker = 0;
        commonHeader_.flag = 0;
        commonHeader_.level = streamFrameInfo->level;
        commonHeader_.pad = 0;
        commonHeader_.streamId = streamFrameInfo->streamId;
        commonHeader_.timestamp = ts;
        commonHeader_.dataLen = dataLen;
        commonHeader_.seqNum = streamFrameInfo->seqNum;
        commonHeader_.subSeqNum = streamFrameInfo->seqSubNum;
    }

    virtual ~StreamPacketHeader() = default;

    void Packetize(char *pos, ssize_t size, ssize_t offset) const
    {
        auto start = reinterpret_cast<uint32_t *>(new (pos + offset) char[size]);

        uint32_t common = 0;
        common |= commonHeader_.version << VERSION_OFFSET;
        common |= commonHeader_.subVersion << SUB_VERSION_OFFSET;
        common |= commonHeader_.extFlag << EXT_FLAG_OFFSET;
        common |= commonHeader_.streamType << STREAM_TYPE_OFFSET;
        common |= commonHeader_.marker << MAKER_OFFSET;
        common |= commonHeader_.flag << FLAG_OFFSET;
        common |= commonHeader_.level << LEVEL_OFFSET;
        common |= static_cast<uint16_t>(commonHeader_.streamId << SEQ_NUM_OFFSET);

        *start++ = htonl(common);
        *start++ = htonl(commonHeader_.timestamp);
        *start++ = htonl(commonHeader_.dataLen);
        common = 0;
        common |= commonHeader_.seqNum << WORD_SIZE;
        common |= commonHeader_.subSeqNum;
        *start++ = htonl(common);
    }

    void Depacketize(const char *header)
    {
        auto start = reinterpret_cast<const uint32_t *>(header);
        uint32_t common = ntohl(*start++);
        commonHeader_.timestamp = ntohl(*start++);
        commonHeader_.dataLen = ntohl(*start++);
        uint32_t seq = ntohl(*start);
        commonHeader_.seqNum = seq >> WORD_SIZE;
        commonHeader_.subSeqNum = seq & 0xff;

        commonHeader_.version = common >> VERSION_OFFSET;
        commonHeader_.subVersion = common >> SUB_VERSION_OFFSET;
        commonHeader_.extFlag = common >> EXT_FLAG_OFFSET;
        commonHeader_.streamType = common >> STREAM_TYPE_OFFSET;
        commonHeader_.marker = common >> MAKER_OFFSET;
        commonHeader_.flag = common >> FLAG_OFFSET;
        commonHeader_.level = common >> LEVEL_OFFSET;
        commonHeader_.streamId = common >> SEQ_NUM_OFFSET;
    }

    void SetVersion(uint8_t version, uint8_t subVersion)
    {
        commonHeader_.version = version;
        commonHeader_.subVersion = subVersion;
    }
    uint8_t GetVersion() const
    {
        return commonHeader_.version;
    }

    uint8_t GetSubVersion() const
    {
        return commonHeader_.subVersion;
    }

    uint8_t GetExtFlag() const
    {
        return commonHeader_.extFlag;
    }

    uint8_t GetStreamType() const
    {
        return commonHeader_.streamType;
    }

    void SetMarker(uint8_t marker)
    {
        commonHeader_.marker = marker;
    }
    uint8_t GetMarker() const
    {
        return commonHeader_.marker;
    }

    uint8_t GetFlag() const
    {
        return commonHeader_.flag;
    }

    uint16_t GetSeqNum() const
    {
        return commonHeader_.seqNum;
    }

    uint32_t GetTimestamp() const
    {
        return commonHeader_.timestamp;
    }

    uint32_t GetDataLen() const
    {
        return commonHeader_.dataLen;
    }

    uint16_t GetStreamId() const
    {
        return commonHeader_.streamId;
    }
    uint16_t GetSubSeqNum() const
    {
        return commonHeader_.subSeqNum;
    }
    uint8_t GetLevel() const
    {
        return commonHeader_.level;
    }

private:
    CommonHeader commonHeader_ {};
};
} // namespace SoftBus
} // namespace Communication

#endif
