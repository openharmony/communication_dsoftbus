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
        if (adaptor_->GetListenerCallback() != nullptr &&
            adaptor_->GetListenerCallback()->OnStreamReceived != nullptr) {
            auto uniptr = stream->GetBuffer();
            char *retbuf = uniptr.get();
            int buflen = stream->GetBufferLen();
            char *extRetBuf = stream->GetExtBuffer().get();
            int extRetBuflen = stream->GetExtBufferLen();

            int plainDataLength = buflen - adaptor_->GetEncryptOverhead();
            if (plainDataLength < 0) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
                    "StreamAdaptorListener:OnStreamReceived:buflen:%d < GetEncryptOverhead:%d",
                    buflen, adaptor_->GetEncryptOverhead());
                return;
            }
            std::unique_ptr<char[]> plainData = std::make_unique<char[]>(plainDataLength);
            ssize_t decLen = adaptor_->Decrypt(retbuf, buflen, plainData.get(),
                plainDataLength, adaptor_->GetSessionKey());
            if (decLen != plainDataLength) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
                    "Decrypt failed, dataLength = %d, decryptedLen = %zd", plainDataLength, decLen);
                return;
            }

            StreamData retStreamData = {
                plainData.get(),
                plainDataLength,
            };

            StreamData extStreamData = {
                extRetBuf,
                extRetBuflen,
            };

            FrameInfo tmpf = {};
            adaptor_->GetListenerCallback()->OnStreamReceived(adaptor_->GetChannelId(),
                &retStreamData, &extStreamData, &tmpf);
        }
    }

    void OnStreamStatus(int status)
    {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "StreamAdaptorListener: OnStreamStatus(%d) in.", status);

        if (adaptor_->GetListenerCallback() != nullptr && adaptor_->GetListenerCallback()->OnStatusChange != nullptr) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_DBG, "OnStreamStatus OnStatusChange :%d", status);
            adaptor_->GetListenerCallback()->OnStatusChange(adaptor_->GetChannelId(), status);
        }
    }

private:
    std::shared_ptr<StreamAdaptor> adaptor_ = nullptr;
};
}

#endif // !defined(CLIENT_TRANS_UDP_STREAM_ADAPTOR_LISTENER_H_)
