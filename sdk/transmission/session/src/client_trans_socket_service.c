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

#include "string.h"
#include "anonymizer.h"
#include "client_trans_session_adapter.h"
#include "client_trans_session_manager.h"
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

    int32_t secoketFd = INVALID_SESSION_ID;
    ret = ClientAddSocket(&info, &secoketFd);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "add socket failed, ret=%{public}d.", ret);
        return ret;
    }

    TRANS_LOGI(TRANS_SDK, "create socket ok, socket=%{public}d", secoketFd);
    return secoketFd;
}

int32_t Listen(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener)
{
    TRANS_LOGI(TRANS_SDK, "Listen: socket=%{public}d", socket);
    return ClientListen(socket, qos, qosCount, listener);
}

int32_t Bind(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener)
{
    TRANS_LOGI(TRANS_SDK, "Bind: socket=%{public}d", socket);
    if (IsSessionExceedLimit()) {
        return SOFTBUS_TRANS_SESSION_CNT_EXCEEDS_LIMIT;
    }
    return ClientBind(socket, qos, qosCount, listener);
}

void Shutdown(int32_t socket)
{
    TRANS_LOGI(TRANS_SDK, "Shutdown: socket=%{public}d", socket);
    ClientShutdown(socket);
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