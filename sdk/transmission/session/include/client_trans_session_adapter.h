/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef CLIENT_TRANS_SESSION_ADAPTER_H
#define CLIENT_TRANS_SESSION_ADAPTER_H

#include <stdint.h>
#include "trans_type.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *buf;     /**< Pointer to the buffer for storing the stream data */
    int bufLen;    /**< Length of the buffer */
} StreamDataAdapt; /* same as StreamData */

typedef enum {
    QOS_SATISFIED_ADAPT,     /**< Feedback on satisfied quality */
    QOS_NOT_SATISFIED_ADAPT, /**< Feedback on not satisfied quality */
} QoSEventAdapt;             /* same as QoSEvent */

typedef struct {
    void (*OnBind)(int32_t socket, PeerSocketInfo info);
    void (*OnShutdown)(int32_t socket, ShutdownReason reason);
    void (*OnBytes)(int32_t socket, const void *data, uint32_t dataLen);
    void (*OnMessage)(int32_t socket, const void *data, uint32_t dataLen);
    void (*OnStream)(int32_t socket, const StreamDataAdapt *data, const StreamDataAdapt *ext,
        const StreamFrameInfo *param);
    void (*OnFile)(int32_t socket, FileEvent *event);
    void (*OnQos)(int32_t socket, QoSEventAdapt eventId, const QosTV *qos, uint32_t qosCount);
} ISocketListenerAdapt; /* same as ISocketListener */

int32_t CreateSocket(const char *pkgName, const char *sessionName);
int32_t ClientAddSocket(const SocketInfo *info, int32_t *sessionId);
int32_t ClientListen(int32_t socket, const QosTV qos[], uint32_t len, const ISocketListenerAdapt *listener);
int32_t ClientBind(int32_t socket, const QosTV qos[], uint32_t len, const ISocketListenerAdapt *listener);
void ClientShutdown(int32_t socket);
#ifdef __cplusplus
}
#endif
#endif // CLIENT_TRANS_SESSION_ADAPTER_H