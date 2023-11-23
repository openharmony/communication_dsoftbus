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

static int32_t CheckSocketInfoIsValid(const SocketInfo *info)
{
    if (!IsValidString(info->pkgName, PKG_NAME_SIZE_MAX - 1) || !IsValidString(info->name, SESSION_NAME_SIZE_MAX - 1) ||
        info->dataType >= DATA_TYPE_BUTT) {
        TRANS_LOGE(TRANS_SDK, "CheckSocketInfoIsValid invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    return SOFTBUS_OK;
}

static bool IsValidSocketListener(const ISocketListener *listener)
{
    if ((listener != NULL) && (listener->OnShutdown != NULL)) {
        return true;
    }
    TRANS_LOGE(TRANS_SDK, "invalid ISocketListener");
    return false;
}

int32_t Socket(SocketInfo info)
{
    int32_t ret = CheckSocketInfoIsValid(&info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "Socket invalid param, ret=%d.", ret);
        return SOFTBUS_INVALID_PARAM;
    }

    char *anonyOutMy = NULL;
    char *anonyOutPeer = NULL;
    Anonymize(info.name, &anonyOutMy);
    Anonymize(info.peerName, &anonyOutPeer);
    TRANS_LOGI(TRANS_SDK, "Socket: mySessionName=%s, peerSessionName=%s", anonyOutMy, anonyOutPeer);
    AnonymizeFree(anonyOutMy);
    AnonymizeFree(anonyOutPeer);

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

int32_t Listen(int32_t socket, const QosTV qos[], uint32_t len, const ISocketListener *listener)
{
    if (!IsValidSocketListener(listener) || qos == NULL || len > QOS_TYPE_BUTT) {
        TRANS_LOGE(TRANS_SDK, "invalid listener");
        return SOFTBUS_INVALID_PARAM;
    }
    return ClientListen(socket, qos, len, (const ISocketListenerAdapt *)listener);
}

int32_t Bind(int32_t socket, const QosTV qos[], uint32_t len, const ISocketListener *listener)
{
    if (!IsValidSocketListener(listener) || qos == NULL || len > QOS_TYPE_BUTT) {
        TRANS_LOGE(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    return ClientBind(socket, qos, len, (const ISocketListenerAdapt *)listener);
}

void Shutdown(int32_t socket)
{
    ClientShutdown(socket);
}