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

#include "anonymizer.h"
#include "client_trans_session_adapter.h"
#include "socket.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "trans_log.h"
#include "trans_server_proxy.h"

static int32_t CheckSocketInfoIsValid(const SocketInfo *info)
{
    if (!IsValidString(info->name, SESSION_NAME_SIZE_MAX) || !IsValidString(info->pkgName, PKG_NAME_SIZE_MAX)) {
        TRANS_LOGE(TRANS_SDK, "invalid name or package name of socket");
        return SOFTBUS_INVALID_PARAM;
    }

    if (info->peerName != NULL && !IsValidString(info->peerName, SESSION_NAME_SIZE_MAX)) {
        TRANS_LOGE(TRANS_SDK, "invalid peerName of socket");
        return SOFTBUS_INVALID_PARAM;
    }

    if (info->peerNetworkId != NULL && !IsValidString(info->peerNetworkId, DEVICE_ID_SIZE_MAX)) {
        TRANS_LOGE(TRANS_SDK, "invalid peerNetworkId of socket");
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
    TRANS_LOGI(TRANS_SDK, "Socket: mySessionName=%s, peerSessionName=%s, pkgName=%s, dataType=%d",
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
        TRANS_LOGE(TRANS_SDK, "CreateSocket failed, ret=%d.", ret);
        return ret;
    }

    int32_t secoketFd = INVALID_SESSION_ID;
    ret = ClientAddSocket(&info, &secoketFd);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "add socket failed, ret=%d.", ret);
        return ret;
    }

    TRANS_LOGI(TRANS_SDK, "create socket ok, socket=%d", secoketFd);
    return secoketFd;
}

int32_t Listen(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener)
{
    TRANS_LOGI(TRANS_SDK, "Listen: socket=%d", socket);
    return ClientListen(socket, qos, qosCount, listener);
}

int32_t Bind(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener)
{
    TRANS_LOGI(TRANS_SDK, "Bind: socket=%d", socket);
    return ClientBind(socket, qos, qosCount, listener);
}

void Shutdown(int32_t socket)
{
    TRANS_LOGI(TRANS_SDK, "Shutdown: socket=%d", socket);
    ClientShutdown(socket);
}

int32_t EvaluateQos(const char *peerNetworkId, TransDataType dataType, const QosTV *qos, uint32_t qosCount)
{
    if (!IsValidString(peerNetworkId, DEVICE_ID_SIZE_MAX) || dataType >= DATA_TYPE_BUTT ||
        (qos == NULL && qosCount != 0) || (qosCount >= QOS_TYPE_BUTT)) {
        TRANS_LOGE(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    return ServerIpcEvaluateQos(peerNetworkId, dataType, qos, qosCount);
}