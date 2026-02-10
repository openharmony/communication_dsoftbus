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
#include <securec.h>
#include <unistd.h>

#include "anonymizer.h"
#include "client_trans_session_adapter.h"
#include "client_trans_session_manager.h"
#include "client_trans_session_service.h"
#include "client_trans_socket_manager.h"
#include "client_trans_socket_option.h"
#include "g_enhance_sdk_func.h"
#include "inner_socket.h"
#include "session_ipc_adapter.h"
#include "socket.h"
#include "softbus_access_token_adapter.h"
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
            AnonymizeWrapper(anonySessionName), strlen(info->peerName));
        AnonymizeFree(anonySessionName);
        return SOFTBUS_INVALID_PARAM;
    }

    if (info->peerNetworkId != NULL && !IsValidString(info->peerNetworkId, DEVICE_ID_SIZE_MAX - 1)) {
        char *anonyNetworkId = NULL;
        Anonymize(info->peerNetworkId, &anonyNetworkId);
        TRANS_LOGI(TRANS_SDK, "strcpy peerNetworkId failed, peerNetworkId=%{public}s, peerNetworkIdLen=%{public}zu",
            AnonymizeWrapper(anonyNetworkId), strlen(info->peerNetworkId));
        AnonymizeFree(anonyNetworkId);
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

static void PrintSocketInfo(const SocketInfo *info)
{
    char *tmpMyName = NULL;
    char *tmpPeerName = NULL;
    char *tmpPeerNetworkId = NULL;
    char *tmpPkgName = NULL;
    Anonymize(info->name, &tmpMyName);
    Anonymize(info->peerName, &tmpPeerName);
    Anonymize(info->peerNetworkId, &tmpPeerNetworkId);
    Anonymize(info->pkgName, &tmpPkgName);
    TRANS_LOGI(TRANS_SDK,
        "Socket: mySessionName=%{public}s, peerSessionName=%{public}s, peerNetworkId=%{public}s, "
        "pkgName=%{public}s, dataType=%{public}d", AnonymizeWrapper(tmpMyName), AnonymizeWrapper(tmpPeerName),
        AnonymizeWrapper(tmpPeerNetworkId), AnonymizeWrapper(tmpPkgName), info->dataType);
    AnonymizeFree(tmpMyName);
    AnonymizeFree(tmpPeerName);
    AnonymizeFree(tmpPeerNetworkId);
    AnonymizeFree(tmpPkgName);
}

static void PrintServiceSocketInfo(const ServiceSocketInfo *serviceInfo, const SocketInfo *info)
{
    if (serviceInfo == NULL || info == NULL) {
        return;
    }
    char *tmpMyName = NULL;
    char *tmpPeerName = NULL;
    char *tmpPeerNetworkId = NULL;
    Anonymize(info->name, &tmpMyName);
    Anonymize(info->peerName, &tmpPeerName);
    Anonymize(info->peerNetworkId, &tmpPeerNetworkId);
    TRANS_LOGI(TRANS_SDK,
        "Socket: myServiceId=%{public}" PRId64 ", peerServiceId=%{public}" PRId64 ", "
        "mySocketName=%{public}s, peerSocketName=%{public}s, peerNetworkId=%{public}s, pkgName=%{public}s, "
        "dataType=%{public}d",
        serviceInfo->serviceId, serviceInfo->peerServiceId, AnonymizeWrapper(tmpMyName), AnonymizeWrapper(tmpPeerName),
        AnonymizeWrapper(tmpPeerNetworkId), info->pkgName, info->dataType);
    AnonymizeFree(tmpMyName);
    AnonymizeFree(tmpPeerName);
    AnonymizeFree(tmpPeerNetworkId);
}

static bool SetNameByServiceId(char **dest, const char* name, uint32_t destLen)
{
    *dest = (char *)SoftBusCalloc(destLen * sizeof(char));
    if (*dest == NULL) {
        TRANS_LOGE(TRANS_SDK, "SoftBusCalloc failed");
        return false;
    }

    if (strcpy_s(*dest, destLen, name) != EOK) {
        SoftBusFree(*dest);
        *dest = NULL;
        TRANS_LOGE(TRANS_SDK, "strcpy_s failed");
        return false;
    }

    return true;
}

static bool GenerateNameByServiceId(SocketInfo *socketInfo, ServiceSocketInfo info)
{
    char pkgName[PKG_NAME_SIZE_MAX];
    int32_t ret = sprintf_s(pkgName, PKG_NAME_SIZE_MAX, "pkg_%d_%u", getpid(), getuid());
    if (ret < 0 || ret >= (int32_t)sizeof(pkgName)) {
        TRANS_LOGE(TRANS_SDK, "pkgName err");
        return false;
    }
    char name[PKG_NAME_SIZE_MAX];
    ret = sprintf_s(name, PKG_NAME_SIZE_MAX, "serviceId_%" PRId64, info.serviceId);
    if (ret < 0 || ret >= (int32_t)sizeof(name)) {
        TRANS_LOGE(TRANS_SDK, "name err");
        return false;
    }
    char peerName[PKG_NAME_SIZE_MAX];
    ret = sprintf_s(peerName, PKG_NAME_SIZE_MAX, "serviceId_%" PRId64, info.peerServiceId);
    if (ret < 0 || ret >= (int32_t)sizeof(peerName)) {
        TRANS_LOGE(TRANS_SDK, "peerName err");
        return false;
    }

    if (!SetNameByServiceId(&socketInfo->pkgName, pkgName, PKG_NAME_SIZE_MAX)) {
        return false;
    }

    if (!SetNameByServiceId(&socketInfo->name, name, PKG_NAME_SIZE_MAX)) {
        SoftBusFree(socketInfo->pkgName);
        socketInfo->pkgName = NULL;
        return false;
    }

    if (!SetNameByServiceId(&socketInfo->peerName, peerName, PKG_NAME_SIZE_MAX)) {
        SoftBusFree(socketInfo->name);
        socketInfo->name = NULL;
        SoftBusFree(socketInfo->pkgName);
        socketInfo->pkgName = NULL;
        return false;
    }

    return true;
}
 
int32_t ServiceSocket(ServiceSocketInfo info)
{
    if (info.peerNetworkId == NULL) {
        TRANS_LOGW(TRANS_SDK, "invalid SocketInfo");
        return SOFTBUS_INVALID_PARAM;
    }
    SocketInfo socket;
    (void)memset_s(&socket, sizeof(SocketInfo), 0, sizeof(SocketInfo));
    if (!GenerateNameByServiceId(&socket, info)) {
        return SOFTBUS_INVALID_PARAM;
    }
    socket.dataType = info.dataType;
    socket.peerNetworkId = info.peerNetworkId;
    PrintServiceSocketInfo(&info, &socket);
    int32_t ret = CreateSocket(socket.pkgName, socket.name);
    int32_t socketFd = INVALID_SESSION_ID;
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "CreateSocket failed, ret=%{public}d.", ret);
        goto FREE;
    }
    TRANS_LOGI(TRANS_SDK, "generate socketFd start");
    ret = ClientAddSocket(&socket, &socketFd);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "add socket failed, ret=%{public}d.", ret);
        goto FREE;
    }
    SocketServerStateUpdate(socket.name);
    TRANS_LOGD(TRANS_SDK, "create socket ok, socket=%{public}d", socketFd);
    ret = socketFd;

FREE:
    SoftBusFree(socket.peerName);
    SoftBusFree(socket.name);
    SoftBusFree(socket.pkgName);
    return ret;
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
    char newSessionName[SESSION_NAME_SIZE_MAX + 1] = {0};
    uint64_t callingFullTokenId = 0;
    ret = SoftBusGetCallingFullTokenId(&callingFullTokenId);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "get callingFullTokenId failed");

    if (SoftBusCheckIsNormalApp(callingFullTokenId, info.name)) {
        if (strncpy_s(newSessionName, SESSION_NAME_SIZE_MAX + 1, info.name, strlen(info.name)) != EOK) {
            TRANS_LOGE(TRANS_SDK, "copy session name failed");
            return SOFTBUS_STRCPY_ERR;
        }
        if (!RemoveAppIdFromSessionName(info.name, newSessionName, SESSION_NAME_SIZE_MAX + 1)) {
            TRANS_LOGE(TRANS_SDK, "invalid bundlename or appId and delete appId failed");
            return SOFTBUS_TRANS_NOT_FIND_APPID;
        }
        info.name = newSessionName;
    }
    ret = ClientAddSocket(&info, &socketFd);
    SocketServerStateUpdate(info.name);
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
    if (ret == SOFTBUS_ALREADY_TRIGGERED) {
        TRANS_LOGW(TRANS_SDK, "already success, socket=%{public}d", socket);
        return SOFTBUS_OK;
    } else if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "Start timer failed, ret=%{public}d", ret);
        return ret;
    }

    ret = ClientBind(socket, qos, qosCount, listener, false);
    TRANS_LOGI(TRANS_SDK, "Bind end, stop timer, socket=%{public}d", socket);
    (void)ClientHandleBindWaitTimer(socket, 0, TIMER_ACTION_STOP);
    if (ret != SOFTBUS_OK) {
        (void)ClientSetEnableStatusBySocket(socket, ENABLE_STATUS_INIT);
        (void)SetSessionStateBySessionId(socket, SESSION_STATE_INIT, 0);
    }
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
    if (ret == SOFTBUS_ALREADY_TRIGGERED) {
        TRANS_LOGW(TRANS_SDK, "already success, socket=%{public}d", socket);
        return SOFTBUS_OK;
    } else if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "Start timer failed, ret=%{public}d, socket=%{public}d", ret, socket);
        return ret;
    }

    ret = ClientBind(socket, qos, qosCount, listener, true);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "BindAsync fail, stop timer, ret=%{public}d, socket=%{public}d", ret, socket);
        (void)ClientHandleBindWaitTimer(socket, 0, TIMER_ACTION_STOP);
        (void)SetSessionStateBySessionId(socket, SESSION_STATE_INIT, 0);
    }
    return ret;
}

void Shutdown(int32_t socket)
{
    TRANS_LOGI(TRANS_SDK, "Shutdown: socket=%{public}d", socket);
    (void)ClientHandleBindWaitTimer(socket, 0, TIMER_ACTION_STOP);
    SessionInfoReport(socket);
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

static int32_t ClientCheckFuncPointer(void *func)
{
    if (func == NULL) {
        TRANS_LOGE(TRANS_SDK, "enhance func not register");
        return SOFTBUS_FUNC_NOT_REGISTER;
    }
    return SOFTBUS_OK;
}

static int32_t SetExtSocketOptPacked(
    int32_t socket, OptLevel level, OptType optType, void *optValue, uint32_t optValueSize)
{
    ClientEnhanceFuncList *pfnClientEnhanceFuncList = ClientEnhanceFuncListGet();
    if (ClientCheckFuncPointer((void *)pfnClientEnhanceFuncList->setExtSocketOpt) != SOFTBUS_OK) {
        return SOFTBUS_NOT_IMPLEMENT;
    }
    return pfnClientEnhanceFuncList->setExtSocketOpt(socket, level, optType, optValue, optValueSize);
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
    if (optType >= OPT_TYPE_BEGIN && optType < OPT_TYPE_END) {
        ret = SetCommonSocketOpt(socket, level, optType, optValue, optValueSize);
    } else {
        ret = SetExtSocketOptPacked(socket, level, optType, optValue, optValueSize);
    }
    return ret;
}

static int32_t GetExtSocketOptPacked(
    int32_t socket, OptLevel level, OptType optType, void *optValue, int32_t *optValueSize)
{
    ClientEnhanceFuncList *pfnClientEnhanceFuncList = ClientEnhanceFuncListGet();
    if (ClientCheckFuncPointer((void *)pfnClientEnhanceFuncList->getExtSocketOpt) != SOFTBUS_OK) {
        return SOFTBUS_NOT_IMPLEMENT;
    }
    return pfnClientEnhanceFuncList->getExtSocketOpt(socket, level, optType, optValue, optValueSize);
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
    if (optType >= OPT_TYPE_BEGIN && optType < OPT_TYPE_END) {
        ret = GetCommonSocketOpt(socket, level, optType, optValue, optValueSize);
    } else {
        ret = GetExtSocketOptPacked(socket, level, optType, optValue, optValueSize);
    }
    return ret;
}

int32_t PrivilegeShutdown(uint64_t tokenId, int32_t pid, const char *peerNetworkId)
{
    if (peerNetworkId == NULL || strlen(peerNetworkId) >= DEVICE_ID_SIZE_MAX) {
        TRANS_LOGE(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    char *tmpPeerNetworkId = NULL;
    Anonymize(peerNetworkId, &tmpPeerNetworkId);
    TRANS_LOGI(TRANS_SDK, "tokenId=%{private}" PRId64 ", pid=%{public}d, networkId=%{public}s", tokenId, pid,
        AnonymizeWrapper(tmpPeerNetworkId));
    AnonymizeFree(tmpPeerNetworkId);
    return ServerIpcPrivilegeCloseChannel(tokenId, pid, peerNetworkId);
}

int32_t RegisterRelationChecker(IFeatureAbilityRelationChecker *relationChecker)
{
    if (relationChecker == NULL) {
        TRANS_LOGE(TRANS_SDK, "invalid relationChecker.");
        return SOFTBUS_INVALID_PARAM;
    }
    return ClientRegisterRelationChecker(relationChecker);
}

static int32_t WriteAcessInfoToBuf(uint8_t *buf, uint32_t bufLen, char *sessionName, SocketAccessInfo *accessInfo)
{
    int32_t offSet = 0;
    int32_t ret = WriteInt32ToBuf(buf, bufLen, &offSet, accessInfo->userId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "write userId=%{public}d to buf failed! ret=%{public}d", accessInfo->userId, ret);
        return ret;
    }
    ret = WriteUint64ToBuf(buf, bufLen, &offSet, accessInfo->localTokenId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "write tokenId to buf failed! ret=%{public}d", ret);
        return ret;
    }
    ret = WriteStringToBuf(buf, bufLen, &offSet, sessionName, strlen(sessionName) + 1);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "write sessionName to buf failed! ret=%{public}d", ret);
        return ret;
    }
    ret = WriteStringToBuf(buf, bufLen, &offSet, accessInfo->extraAccessInfo, strlen(accessInfo->extraAccessInfo) + 1);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "write extraAccessInfo to buf failed! ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t SetAccessInfo(int32_t socket, SocketAccessInfo accessInfo)
{
#define WRITE_BUF_PARAM_NUM 5 // tokenId + userId + 2 * string info len
    TRANS_LOGI(TRANS_SDK, "SetAccessInfo: socket=%{public}d", socket);
    if (accessInfo.extraAccessInfo == NULL || accessInfo.userId < 0) {
        TRANS_LOGE(TRANS_SDK, "accessInfo param invalid, socket=%{public}d.", socket);
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t extraInfoLen = strnlen(accessInfo.extraAccessInfo, EXTRA_ACCESS_INFO_LEN_MAX) + 1;
    TRANS_CHECK_AND_RETURN_RET_LOGE(extraInfoLen <= EXTRA_ACCESS_INFO_LEN_MAX,
        SOFTBUS_INVALID_PARAM, TRANS_SDK, "extra info len over limit");
    char sessionName[SESSION_NAME_SIZE_MAX] = { 0 };
    int32_t ret = ClientGetSessionNameBySessionId(socket, sessionName);
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        ret == SOFTBUS_OK, ret, TRANS_SDK, "get sessionName by socket=%{public}d failed, ret=%{public}d", socket, ret);

    uint32_t bufLen = sizeof(int32_t) * WRITE_BUF_PARAM_NUM + extraInfoLen + strlen(sessionName) + 1;
    uint8_t *buf = (uint8_t *)SoftBusCalloc(bufLen);
    if (buf == NULL) {
        TRANS_LOGE(TRANS_SDK, "malloc buf failed, socket=%{public}d.", socket);
        return SOFTBUS_MALLOC_ERR;
    }
    ret = WriteAcessInfoToBuf(buf, bufLen, sessionName, &accessInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "Write accessinfo to buf failed! ret=%{public}d", ret);
        SoftBusFree(buf);
        return ret;
    }
    ret = ServerIpcProcessInnerEvent(EVENT_TYPE_SET_ACCESS_INFO, buf, bufLen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "ServerIpcProcessInnerEvent failed! ret=%{public}d", ret);
    }
    SoftBusFree(buf);
    return ret;
}
