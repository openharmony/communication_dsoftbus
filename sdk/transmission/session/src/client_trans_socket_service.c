/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "string.h"
#include "anonymizer.h"
#include "client_trans_session_adapter.h"
#include "client_trans_session_manager.h"
#include "client_trans_socket_option.h"
#include "inner_socket.h"
#include "socket.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "trans_log.h"
#include "trans_server_proxy.h"

static int32_t CheckSocketInfoIsValid(const SocketInfo *info)
{
    if (!IsValidString(info->name, SESSION_NAME_SIZE_MAX - 1) ||
        !IsValidString(info->pkgName, PKG_NAME_SIZE_MAX - 1)) {
        TRANS_LOGE(TRANS_SDK, "invalid name or package name of socket");
        return SOFTBUS_INVALID_PARAM;
    }

    if (info->peerName != NULL && !IsValidString(info->peerName, SESSION_NAME_SIZE_MAX - 1)) {
        char *anonySessionName = NULL;
        Anonymize(info->peerName, &anonySessionName);
        TRANS_LOGI(TRANS_SDK, "strcpy peerName failed, peerName=%{public}s, peerNameLen=%{public}zu",
            anonySessionName, strlen(info->peerName));
        AnonymizeFree(anonySessionName);
        return SOFTBUS_INVALID_PARAM;
    }

    if (info->peerNetworkId != NULL && !IsValidString(info->peerNetworkId, DEVICE_ID_SIZE_MAX - 1)) {
        char *anonyNetworkId = NULL;
        Anonymize(info->peerNetworkId, &anonyNetworkId);
        TRANS_LOGI(TRANS_SDK, "strcpy peerNetworkId failed, peerNetworkId=%{public}s, peerNetworkIdLen=%{public}zu",
            anonyNetworkId, strlen(info->peerNetworkId));
        AnonymizeFree(anonyNetworkId);
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

static void PrintSocketInfo(const SocketInfo *info)
{
    char *tmpMyName = NULL;
    char *tmpPeerName = NULL;
    char *tmpPkgName = NULL;
    Anonymize(info->name, &tmpMyName);
    Anonymize(info->peerName, &tmpPeerName);
    Anonymize(info->pkgName, &tmpPkgName);
    TRANS_LOGI(TRANS_SDK,
        "Socket: mySessionName=%{public}s, peerSessionName=%{public}s, pkgName=%{public}s, dataType=%{public}d",
        tmpMyName, tmpPeerName, tmpPkgName, info->dataType);
    AnonymizeFree(tmpMyName);
    AnonymizeFree(tmpPeerName);
    AnonymizeFree(tmpPkgName);
}

int32_t Socket(SocketInfo info)
{
    int32_t ret = CheckSocketInfoIsValid(&info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGW(TRANS_SDK, "invalid SocketInfo");
        return ret;
    }

    PrintSocketInfo(&info);
    ret = CreateSocket(info.pkgName, info.name);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "CreateSocket failed, ret=%{public}d.", ret);
        return ret;
    }

    int32_t socketFd = INVALID_SESSION_ID;
    ret = ClientAddSocket(&info, &socketFd);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "add socket failed, ret=%{public}d.", ret);
        return ret;
    }

    TRANS_LOGD(TRANS_SDK, "create socket ok, socket=%{public}d", socketFd);
    return socketFd;
}

int32_t Listen(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener)
{
    TRANS_LOGD(TRANS_SDK, "Listen: socket=%{public}d", socket);
    return ClientListen(socket, qos, qosCount, listener);
}

static int32_t StartBindWaitTimer(int32_t socket, const QosTV qos[], uint32_t qosCount)
{
#define DEFAULT_MAX_WAIT_TIMEOUT 30000 // 30s
    int32_t maxWaitTime;
    int32_t ret = GetQosValue(qos, qosCount, QOS_TYPE_MAX_WAIT_TIMEOUT, &maxWaitTime, DEFAULT_MAX_WAIT_TIMEOUT);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get max wait timeout fail ret=%{public}d", ret);
        return ret;
    }

    if (maxWaitTime <= 0) {
        TRANS_LOGE(TRANS_SDK, "invalid max wait timeout. maxWaitTime=%{public}d", maxWaitTime);
        return SOFTBUS_INVALID_PARAM;
    }

    return ClientHandleBindWaitTimer(socket, (uint32_t)maxWaitTime, TIMER_ACTION_START);
}

int32_t Bind(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener)
{
    TRANS_LOGI(TRANS_SDK, "Bind: socket=%{public}d", socket);
    if (IsSessionExceedLimit()) {
        TRANS_LOGE(TRANS_SDK, "Bind failed, over session num limit");
        return SOFTBUS_TRANS_SESSION_CNT_EXCEEDS_LIMIT;
    }
    int32_t ret = StartBindWaitTimer(socket, qos, qosCount);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "Start timer failed, ret=%{public}d", ret);
        return ret;
    }

    ret = ClientBind(socket, qos, qosCount, listener, false);
    TRANS_LOGI(TRANS_SDK, "Bind end, stop timer, socket=%{public}d", socket);
    (void)ClientHandleBindWaitTimer(socket, 0, TIMER_ACTION_STOP);
    return ret;
}

int32_t BindAsync(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener)
{
    TRANS_LOGI(TRANS_SDK, "Bind async socket=%{public}d", socket);
    if (IsSessionExceedLimit()) {
        TRANS_LOGE(TRANS_SDK, "Bind async failed, over session num limit");
        return SOFTBUS_TRANS_SESSION_CNT_EXCEEDS_LIMIT;
    }

    int32_t ret = StartBindWaitTimer(socket, qos, qosCount);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "Start timer failed, ret=%{public}d, socket=%{public}d", ret, socket);
        return ret;
    }

    ret = ClientBind(socket, qos, qosCount, listener, true);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "BindAsync fail, stop timer, ret=%{public}d, socket=%{public}d", ret, socket);
        (void)ClientHandleBindWaitTimer(socket, 0, TIMER_ACTION_STOP);
    }
    return ret;
}

void Shutdown(int32_t socket)
{
    TRANS_LOGI(TRANS_SDK, "Shutdown: socket=%{public}d", socket);
    (void)ClientHandleBindWaitTimer(socket, 0, TIMER_ACTION_STOP);
    ClientShutdown(socket, SOFTBUS_TRANS_STOP_BIND_BY_CANCEL);
}

int32_t EvaluateQos(const char *peerNetworkId, TransDataType dataType, const QosTV *qos, uint32_t qosCount)
{
    if (!IsValidString(peerNetworkId, DEVICE_ID_SIZE_MAX) || dataType >= DATA_TYPE_BUTT ||
        (qos == NULL && qosCount != 0) || (qosCount > QOS_TYPE_BUTT)) {
        TRANS_LOGE(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    return ServerIpcEvaluateQos(peerNetworkId, dataType, qos, qosCount);
}

int32_t GetMtuSize(int32_t socket, uint32_t *mtuSize)
{
    TRANS_LOGI(TRANS_SDK, "GetMtuSize: socket=%{public}d", socket);
    return GetSocketMtuSize(socket, mtuSize);
}

int32_t DBinderGrantPermission(int32_t uid, int32_t pid, const char *socketName)
{
    return ClientGrantPermission(uid, pid, socketName);
}

int32_t DBinderRemovePermission(const char *socketName)
{
    return ClientRemovePermission(socketName);
}

int32_t DfsBind(int32_t socket, const ISocketListener *listener)
{
    return ClientDfsBind(socket, listener);
}

static int32_t CheckSocketOptParam(OptLevel level, OptType optType, void *optValue)
{
    if (level < 0 || level >= OPT_LEVEL_BUTT) {
        TRANS_LOGE(TRANS_SDK, "invalid level.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (optType < 0) {
        TRANS_LOGE(TRANS_SDK, "invalid optType.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (optValue == NULL) {
        TRANS_LOGE(TRANS_SDK, "invalid optValue.");
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

int32_t SetSocketOpt(int32_t socket, OptLevel level, OptType optType, void *optValue, int32_t optValueSize)
{
    int32_t ret = CheckSocketOptParam(level, optType, optValue);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (optValueSize <= 0) {
        TRANS_LOGE(TRANS_SDK, "invalid optValueSize.");
        return SOFTBUS_INVALID_PARAM;
    }
    switch (level) {
        case OPT_TYPE_MAX_BUFFER:
        case OPT_TYPE_FIRST_PACKAGE:
        case OPT_TYPE_MAX_IDLE_TIMEOUT:
            ret = SOFTBUS_NOT_IMPLEMENT;
            break;
        default:
            ret = SetExtSocketOpt(socket, level, optType, optValue, optValueSize);
            break;
    }
    return ret;
}

int32_t GetSocketOpt(int32_t socket, OptLevel level, OptType optType, void *optValue, int32_t *optValueSize)
{
    int32_t ret = CheckSocketOptParam(level, optType, optValue);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (optValueSize == NULL) {
        TRANS_LOGE(TRANS_SDK, "invalid optValueSize.");
        return SOFTBUS_INVALID_PARAM;
    }
    switch (level) {
        case OPT_TYPE_MAX_BUFFER:
        case OPT_TYPE_FIRST_PACKAGE:
        case OPT_TYPE_MAX_IDLE_TIMEOUT:
            ret = SOFTBUS_NOT_IMPLEMENT;
            break;
        default:
            ret = GetExtSocketOpt(socket, level, optType, optValue, optValueSize);
            break;
    }
    return ret;
}