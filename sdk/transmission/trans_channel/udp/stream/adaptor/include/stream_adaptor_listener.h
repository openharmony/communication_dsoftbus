/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef CLIENT_TRANS_UDP_STREAM_ADAPTOR_LISTENER_H_
#define CLIENT_TRANS_UDP_STREAM_ADAPTOR_LISTENER_H_

#include "i_stream.h"
#include "i_stream_manager.h"
#include "softbus_def.h"
#include "trans_log.h"

using Communication::SoftBus::IStreamManagerListener;
using Communication::SoftBus::IStream;

namespace OHOS {
class StreamAdaptorListener : public IStreamManagerListener {
public:
    StreamAdaptorListener() = default;
    explicit StreamAdaptorListener(std::shared_ptr<StreamAdaptor> adaptor) : adaptor_(adaptor) {}
    virtual ~StreamAdaptorListener() override = default;
    void ConvertStreamFrameInfo(StreamFrameInfo *outFrameInfo,
        const Communication::SoftBus::StreamFrameInfo *inFrameInfo)
    {
        outFrameInfo->frameType = inFrameInfo->frameType;
        outFrameInfo->timeStamp = (int64_t)inFrameInfo->timeStamp;
        outFrameInfo->seqNum = (int)inFrameInfo->seqNum;
        outFrameInfo->seqSubNum = (int)inFrameInfo->seqSubNum;
        outFrameInfo->level = (int)inFrameInfo->level;
        outFrameInfo->bitMap = (int)inFrameInfo->bitMap;
        outFrameInfo->tvCount = 0;
        outFrameInfo->tvList = nullptr;
    }
    void OnStreamReceived(std::unique_ptr<IStream> stream) override
    {
        if (adaptor_ == nullptr || adaptor_->GetListenerCallback() == nullptr ||
            adaptor_->GetListenerCallback()->OnStreamReceived == nullptr) {
            return;
        }
        StreamFrameInfo tmpf = {0};
        auto uniptr = stream->GetBuffer();
        char *retbuf = uniptr.get();
        int32_t buflen = stream->GetBufferLen();
        auto extUniptr = stream->GetExtBuffer();
        char *extRetBuf = extUniptr.get();
        int32_t extRetBuflen = stream->GetExtBufferLen();
        StreamData retStreamData = {0};
        int32_t streamType = adaptor_->GetStreamType();
        std::unique_ptr<char[]> plainData = nullptr;
        if (streamType == StreamType::COMMON_VIDEO_STREAM || streamType == StreamType::COMMON_AUDIO_STREAM) {
            retStreamData.buf = retbuf;
            retStreamData.bufLen = buflen;
            ConvertStreamFrameInfo(&tmpf, stream->GetStreamFrameInfo());
        } else if (streamType == StreamType::RAW_STREAM) {
            int32_t ret = ConvertRawStreamData(retbuf, buflen, plainData, retStreamData);
            if (ret != SOFTBUS_OK) {
                TRANS_LOGE(TRANS_STREAM, "failed to convert raw stream data, ret=%{public}d", ret);
                return;
            }
        } else {
            TRANS_LOGE(TRANS_STREAM, "Do not support, streamType=%{public}d", streamType);
            return;
        }
        StreamData extStreamData = {
            extRetBuf,
            extRetBuflen,
        };
        adaptor_->GetListenerCallback()->OnStreamReceived(adaptor_->GetChannelId(),
            &retStreamData, &extStreamData, &tmpf);
    }

    void OnStreamStatus(int status) override
    {
        TRANS_LOGD(TRANS_STREAM, "status=%{public}d", status);

        if (adaptor_->GetListenerCallback() != nullptr && adaptor_->GetListenerCallback()->OnStatusChange != nullptr) {
            TRANS_LOGI(TRANS_STREAM, "OnStatusChange status=%{public}d", status);
            adaptor_->GetListenerCallback()->OnStatusChange(adaptor_->GetChannelId(), status);
        }
    }

    void OnQosEvent(int32_t eventId, int32_t tvCount, const QosTv *tvList) override
    {
        if (adaptor_->GetListenerCallback() != nullptr && adaptor_->GetListenerCallback()->OnQosEvent != nullptr) {
            TRANS_LOGD(TRANS_QOS, "channelId=%{public}" PRId64, adaptor_->GetChannelId());
            adaptor_->GetListenerCallback()->OnQosEvent(adaptor_->GetChannelId(), eventId, tvCount, tvList);
        } else {
            TRANS_LOGE(TRANS_QOS,
                "Get ListenerCallback by StreamAdaptor is failed, channelId=%{public}" PRId64,
                adaptor_->GetChannelId());
        }
    }

    void OnFrameStats(const StreamSendStats *data) override
    {
        if (adaptor_->GetListenerCallback() != nullptr && adaptor_->GetListenerCallback()->OnFrameStats != nullptr) {
            TRANS_LOGI(TRANS_STREAM, "channelId=%{public}" PRId64, adaptor_->GetChannelId());
            adaptor_->GetListenerCallback()->OnFrameStats(adaptor_->GetChannelId(), data);
        } else {
            TRANS_LOGE(TRANS_STREAM,
                "Get ListenerCallback by StreamAdaptor is failed, channelId=%{public}" PRId64,
                adaptor_->GetChannelId());
        }
    }

    void OnRippleStats(const TrafficStats *data) override
    {
        if (adaptor_->GetListenerCallback() != nullptr && adaptor_->GetListenerCallback()->OnRippleStats != nullptr) {
            TRANS_LOGI(TRANS_STREAM, "channelId=%{public}" PRId64, adaptor_->GetChannelId());
            adaptor_->GetListenerCallback()->OnRippleStats(adaptor_->GetChannelId(), data);
        } else {
            TRANS_LOGE(TRANS_STREAM,
                "Get ListenerCallback by StreamAdaptor is failed, channelId=%{public}" PRId64,
                adaptor_->GetChannelId());
        }
    }

private:
    int32_t ConvertRawStreamData(char *buf, int32_t bufLen, std::unique_ptr<char[]> &plainData,
        StreamData &retStreamData)
    {
        if (!adaptor_->IsEncryptedRawStream()) {
            retStreamData.buf = buf;
            retStreamData.bufLen = bufLen;
            return SOFTBUS_OK;
        }

        ssize_t encryptOverhead = adaptor_->GetEncryptOverhead();
        int32_t plainDataLength = bufLen - encryptOverhead;
        if (plainDataLength < 0) {
            TRANS_LOGE(TRANS_STREAM,
                "bufLen < GetEncryptOverhead. bufLen=%{public}d, GetEncryptOverhead=%{public}zd",
                bufLen, encryptOverhead);
            return SOFTBUS_TRANS_DECRYPT_ERR;
        }
        plainData = std::make_unique<char[]>(plainDataLength);
        ssize_t decLen = adaptor_->Decrypt(buf, bufLen, plainData.get(), plainDataLength,
            adaptor_->GetSessionKey());
        if (decLen != plainDataLength) {
            TRANS_LOGE(TRANS_STREAM,
                "Decrypt failed, dataLen=%{public}d, decLen=%{public}zd", plainDataLength, decLen);
            return SOFTBUS_TRANS_DECRYPT_ERR;
        }
        retStreamData.buf = plainData.get();
        retStreamData.bufLen = plainDataLength;
        return SOFTBUS_OK;
    }

    std::shared_ptr<StreamAdaptor> adaptor_ = nullptr;
};
} // namespace OHOS

#endif // !defined(CLIENT_TRANS_UDP_STREAM_ADAPTOR_LISTENER_H_)
