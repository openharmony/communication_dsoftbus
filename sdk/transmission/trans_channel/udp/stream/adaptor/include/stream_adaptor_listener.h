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
#include "softbus_log.h"

using Communication::SoftBus::IStreamManagerListener;
using Communication::SoftBus::IStream;

namespace OHOS {
class StreamAdaptorListener : public IStreamManagerListener {
public:
    StreamAdaptorListener() = default;
    explicit StreamAdaptorListener(std::shared_ptr<StreamAdaptor> adaptor) : adaptor_(adaptor) {}
    virtual ~StreamAdaptorListener() = default;
    void OnStreamReceived(std::unique_ptr<IStream> stream)
    {
        if (adaptor_ == nullptr || adaptor_->GetListenerCallback() == nullptr ||
            adaptor_->GetListenerCallback()->OnStreamReceived == nullptr) {
            return;
        }
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
        } else if (streamType == StreamType::RAW_STREAM) {
            int32_t plainDataLength = buflen - adaptor_->GetEncryptOverhead();
            if (plainDataLength < 0) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
                    "StreamAdaptorListener:OnStreamReceived:buflen:%d < GetEncryptOverhead:%zd",
                    buflen, adaptor_->GetEncryptOverhead());
                return;
            }
            plainData = std::make_unique<char[]>(plainDataLength);
            ssize_t decLen = adaptor_->Decrypt(retbuf, buflen, plainData.get(),
                plainDataLength, adaptor_->GetSessionKey());
            if (decLen != plainDataLength) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
                    "Decrypt failed, dataLength = %d, decryptedLen = %zd", plainDataLength, decLen);
                return;
            }
            retStreamData.buf = plainData.get();
            retStreamData.bufLen = plainDataLength;
        } else {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Do not support, streamType = %d", streamType);
            return;
        }
        StreamData extStreamData = {
            extRetBuf,
            extRetBuflen,
        };

        StreamFrameInfo tmpf = {0};
        adaptor_->GetListenerCallback()->OnStreamReceived(adaptor_->GetChannelId(),
            &retStreamData, &extStreamData, &tmpf);
    }

    void OnStreamStatus(int status)
    {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "StreamAdaptorListener: OnStreamStatus(%d) in.", status);

        if (adaptor_->GetListenerCallback() != nullptr && adaptor_->GetListenerCallback()->OnStatusChange != nullptr) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_DBG, "OnStreamStatus OnStatusChange :%d", status);
            adaptor_->GetListenerCallback()->OnStatusChange(adaptor_->GetChannelId(), status);
        }
    }

    void OnQosEvent(int32_t eventId, int32_t tvCount, const QosTv *tvList)
    {
        if (adaptor_->GetListenerCallback() != nullptr && adaptor_->GetListenerCallback()->OnQosEvent != nullptr) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "StreamAdaptorListener: OnQosEvent for channelId = %" PRId64,
                adaptor_->GetChannelId());
            adaptor_->GetListenerCallback()->OnQosEvent(adaptor_->GetChannelId(), eventId, tvCount, tvList);
        } else {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
                "Get ListenerCallback by StreamAdaptor is failed, channelId = %" PRId64, adaptor_->GetChannelId());
        }
    }

    void OnFrameStats(const StreamSendStats *data)
    {
        if (adaptor_->GetListenerCallback() != nullptr && adaptor_->GetListenerCallback()->OnFrameStats != nullptr) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO,
                "StreamAdaptorListener: OnFrameStats for channelId = %" PRId64, adaptor_->GetChannelId());
            adaptor_->GetListenerCallback()->OnFrameStats(adaptor_->GetChannelId(), data);
        } else {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
                "Get ListenerCallback by StreamAdaptor is failed, channelId = %" PRId64, adaptor_->GetChannelId());
        }
    }

    void OnRippleStats(const TrafficStats *data)
    {
        if (adaptor_->GetListenerCallback() != nullptr && adaptor_->GetListenerCallback()->OnRippleStats != nullptr) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO,
                "StreamAdaptorListener: OnRippleStats for channelId = %" PRId64, adaptor_->GetChannelId());
            adaptor_->GetListenerCallback()->OnRippleStats(adaptor_->GetChannelId(), data);
        } else {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
                "Get ListenerCallback by StreamAdaptor is failed, channelId = %" PRId64, adaptor_->GetChannelId());
        }
    }

private:
    std::shared_ptr<StreamAdaptor> adaptor_ = nullptr;
};
} // namespace OHOS

#endif // !defined(CLIENT_TRANS_UDP_STREAM_ADAPTOR_LISTENER_H_)
