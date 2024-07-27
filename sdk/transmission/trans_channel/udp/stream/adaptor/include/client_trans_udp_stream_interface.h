/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef CLIENT_TRANS_UDP_STREAM_INTERFACE_H_
#define CLIENT_TRANS_UDP_STREAM_INTERFACE_H_

#include <stdint.h>
#include "session.h"
#include "softbus_trans_def.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef enum {
    VTP,
    TCP,
} Proto;

// keep same with the SessionStatus of softbus.
typedef enum {
    STREAM_INIT,
    STREAM_OPENING,
    STREAM_OPENED,
    STREAM_CONNECTING,
    STREAM_CONNECTED,
    STREAM_CLOSING,
    STREAM_CLOSED,
} StreamStatus;

typedef struct {
    void (*OnStatusChange)(int32_t channelId, int32_t newStatus);
    void (*OnStreamReceived)(int32_t channelId, const StreamData *data, const StreamData *ext,
        const StreamFrameInfo *param);
    void (*OnQosEvent)(int32_t channelId, int32_t eventId, int32_t tvCount, const QosTv *tvList);
    void (*OnFrameStats)(int32_t channelId, const StreamSendStats *data);
    void (*OnRippleStats)(int32_t channelId, const TrafficStats *data);
} IStreamListener;

typedef struct {
    const char *pkgName;
    char *myIp;
    char *peerIp;
    int32_t peerPort;
    StreamType type;
    uint8_t *sessionKey;
    uint32_t keyLen;
    bool isRawStreamEncrypt;
} VtpStreamOpenParam;

int32_t StartVtpStreamChannelServer(int32_t channelId, const VtpStreamOpenParam *param,
    const IStreamListener *callback);
int32_t StartVtpStreamChannelClient(int32_t channelId, const VtpStreamOpenParam *param,
    const IStreamListener *callback);
int32_t SendVtpStream(int32_t channelId, const StreamData *data, const StreamData *ext, const StreamFrameInfo *param);
int32_t CloseVtpStreamChannel(int32_t channelId, const char *pkgName);
int32_t SetVtpStreamMultiLayerOpt(int32_t channelId, const void *optValue);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif // !defined(CLIENT_TRANS_UDP_STREAM_INTERFACE_H_)
