/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef G_REG_SDK_FUNC_H
#define G_REG_SDK_FUNC_H

#include "client_trans_session_manager_struct.h"
#include "client_trans_udp_manager_struct.h"
#include "g_enhance_sdk_func.h"
#include "stdint.h"
#include "softbus_server_proxy_frame_struct.h"
#include "softbus_trans_def.h"
#include "softbus_utils.h"
#include "trans_type.h"

#ifndef NULL
#define NULL 0
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t (*CheckPackageNameFunc)(const char *pkgName);
typedef int32_t (*InitSoftBusFunc)(const char *pkgName);
typedef int32_t (*RestartAuthParaCallbackRegisterFunc)(RestartEventCallback callback);
typedef int32_t (*ClientGetChannelBySessionIdFunc)(
    int32_t sessionId, int32_t *channelId, int32_t *type, SessionEnableStatus *enableStatus);
typedef int32_t (*TransGetUdpChannelFunc)(int32_t channelId, UdpChannel *channel);
typedef int32_t (*TransUdpChannelSetStreamMultiLayerFunc)(int32_t channelId, const void *optValue);
typedef int32_t (*TransSetUdpChannelTosFunc)(int32_t channelId);
typedef int32_t (*ClientGetChannelBusinessTypeBySessionIdFunc)(int32_t sessionId, int32_t *businessType);
typedef int32_t (*ClientAddAuthSessionFunc)(const char *sessionName, int32_t *sessionId);
typedef int32_t (*ClientSetActionIdBySessionIdFunc)(int32_t sessionId, uint32_t actionId);
typedef int32_t (*TransSetUdpChannelRenameHookFunc)(int32_t channelId, OnRenameFileCallback onRenameFile);
typedef int32_t (*ClientDeleteSessionFunc)(int32_t sessionId);
typedef int32_t (*ClientSetChannelBySessionIdFunc)(int32_t sessionId, TransInfo *transInfo);
typedef int32_t (*TransGetUdpChannelByFileIdFunc)(int32_t dfileId, UdpChannel *udpChannel);
typedef int32_t (*ClientGetSessionIdByChannelIdFunc)(int32_t channelId, int32_t channelType,
    int32_t *sessionId, bool isClosing);
typedef int (*GetMySessionNameFunc)(int sessionId, char *sessionName, unsigned int len);
typedef int32_t (*ClientRegEnhanceFunc)(ClientEnhanceFuncList *functionList);
typedef int32_t (*ClientSetLowLatencyBySocketFunc)(int32_t socket);
typedef int32_t (*CreatePagingSessionFunc)(const char *sessionName, int32_t businessType, int32_t socketId,
    const ISocketListener *socketListener, bool isPaging);
typedef int32_t (*ClientDeletePagingSessionFunc)(int32_t socketId);
typedef int32_t (*ClientGetChannelIdAndTypeBySocketIdFunc)(
    int32_t socketId, int32_t *type, int32_t *channelId, char *socketName);
typedef int32_t (*ClientForkSocketByIdFunc)(int32_t socketId, BusinessType type, int32_t *newSocketId);
typedef int32_t (*ClientTransSetChannelInfoFunc)(const char *sessionName, int32_t sessionId,
    int32_t channelId, int32_t channelType);
typedef int32_t (*ClientAddSocketServerFunc)(
    SoftBusSecType type, const char *pkgName, const char *sessionName, uint64_t *timestamp);
typedef int32_t (*GeneratePagingIdFunc)(void);
typedef void (*DestroyPagingIdFunc)(void);
typedef void (*SocketServerStateUpdateFunc)(const char *sessionName);
typedef int32_t (*RegisterTimeoutCallbackFunc)(int32_t timerFunId, TimerFunCallback callback);
typedef int32_t (*ClientGetSessionTypeBySocketFunc)(int32_t socket, int32_t *sessionType);
typedef int32_t (*ClientSetFLTosFunc)(int32_t socket, TransFlowInfo *flowInfo);

typedef struct TagClientOpenFuncList {
    CheckPackageNameFunc checkPackageName;
    InitSoftBusFunc initSoftBus;
    RestartAuthParaCallbackRegisterFunc restartAuthParaCallbackRegister;

    ClientGetChannelBySessionIdFunc clientGetChannelBySessionId;
    TransGetUdpChannelFunc transGetUdpChannel;
    TransUdpChannelSetStreamMultiLayerFunc transUdpChannelSetStreamMultiLayer;
    TransSetUdpChannelTosFunc transSetUdpChannelTos;
    ClientGetChannelBusinessTypeBySessionIdFunc clientGetChannelBusinessTypeBySessionId;
    ClientAddAuthSessionFunc clientAddAuthSession;
    ClientSetActionIdBySessionIdFunc clientSetActionIdBySessionId;
    TransSetUdpChannelRenameHookFunc transSetUdpChannelRenameHook;
    ClientDeleteSessionFunc clientDeleteSession;
    ClientSetChannelBySessionIdFunc clientSetChannelBySessionId;
    TransGetUdpChannelByFileIdFunc transGetUdpChannelByFileId;
    ClientGetSessionIdByChannelIdFunc clientGetSessionIdByChannelId;
    GetMySessionNameFunc getMySessionName;
    ClientSetLowLatencyBySocketFunc clientSetLowLatencyBySocket;
    CreatePagingSessionFunc createPagingSession;
    ClientDeletePagingSessionFunc clientDeletePagingSession;
    ClientGetChannelIdAndTypeBySocketIdFunc clientGetChannelIdAndTypeBySocketId;
    ClientForkSocketByIdFunc clientForkSocketById;
    ClientTransSetChannelInfoFunc clientTransSetChannelInfo;
    ClientAddSocketServerFunc clientAddSocketServer;
    GeneratePagingIdFunc generatePagingId;
    DestroyPagingIdFunc destroyPagingId;
    SocketServerStateUpdateFunc socketServerStateUpdate;
    RegisterTimeoutCallbackFunc registerTimeoutCallback;
    ClientGetSessionTypeBySocketFunc clientGetSessionTypeBySocket;
    ClientSetFLTosFunc clientSetFLTos;
} ClientOpenFuncList;

#ifdef __cplusplus
}
#endif

#endif