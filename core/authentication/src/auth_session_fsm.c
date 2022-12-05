/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "auth_session_fsm.h"

#include <securec.h>

#include "auth_connection.h"
#include "auth_hichain.h"
#include "auth_manager.h"
#include "auth_session_message.h"
#include "softbus_adapter_mem.h"

#define AUTH_TIMEOUT_MS (10 * 1000)
#define TO_AUTH_FSM(ptr) CONTAINER_OF(ptr, AuthFsm, fsm)

typedef enum {
    STATE_SYNC_DEVICE_ID = 0,
    STATE_DEVICE_AUTH,
    STATE_SYNC_DEVICE_INFO,
    STATE_NUM_MAX
} AuthFsmStateIndex;

typedef enum {
    FSM_MSG_RECV_DEVICE_ID,
    FSM_MSG_RECV_AUTH_DATA,
    FSM_MSG_SAVE_SESSION_KEY,
    FSM_MSG_AUTH_RESULT,
    FSM_MSG_RECV_DEVICE_INFO,
    FSM_MSG_RECV_CLOSE_ACK,
    FSM_MSG_AUTH_TIMEOUT,
    FSM_MSG_DEVICE_NOT_TRUSTED,
    FSM_MSG_DEVICE_DISCONNECTED,
} StateMessageType;

typedef struct {
    uint32_t len;
    uint8_t data[0];
} MessagePara;

typedef struct {
    int64_t param1;
    bool param2;
    AuthFsm *(*getFunc)(int64_t param1, bool param2);
} AuthFsmGetFunc;

static ListNode g_authFsmList = { &g_authFsmList, &g_authFsmList };

static void SyncDevIdStateEnter(FsmStateMachine *fsm);
static bool SyncDevIdStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para);
static bool DeviceAuthStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para);
static bool SyncDevInfoStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para);
static void AuthFsmDeinitCallback(FsmStateMachine *fsm);

static FsmState g_states[STATE_NUM_MAX] = {
    [STATE_SYNC_DEVICE_ID] = {
        .enter = SyncDevIdStateEnter,
        .process = SyncDevIdStateProcess,
        .exit = NULL,
    },
    [STATE_DEVICE_AUTH] = {
        .enter = NULL,
        .process = DeviceAuthStateProcess,
        .exit = NULL,
    },
    [STATE_SYNC_DEVICE_INFO] = {
        .enter = NULL,
        .process = SyncDevInfoStateProcess,
        .exit = NULL,
    },
};

static AuthFsm *TranslateToAuthFsm(FsmStateMachine *fsm, int32_t msgType, MessagePara *para)
{
    if (fsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "fsm is null");
        return NULL;
    }
    AuthFsm *authFsm = TO_AUTH_FSM(fsm);
    if (authFsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "authFsm is null");
        return NULL;
    }
    if (authFsm->isDead) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth fsm[%"PRId64"] has dead", authFsm->authSeq);
        return NULL;
    }
    /* check para */
    if ((msgType != FSM_MSG_AUTH_TIMEOUT &&
        msgType != FSM_MSG_DEVICE_NOT_TRUSTED &&
        msgType != FSM_MSG_DEVICE_DISCONNECTED) && para == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid msgType: %d", msgType);
        return NULL;
    }
    return authFsm;
}

static uint32_t GetNextAuthFsmId(void)
{
    static uint32_t authFsmId = 0;
    return ++authFsmId;
}

static AuthFsm *CreateAuthFsm(int64_t authSeq, uint32_t requestId, uint64_t connId,
    const AuthConnInfo *connInfo, bool isServer)
{
    AuthFsm *authFsm = SoftBusCalloc(sizeof(AuthFsm));
    if (authFsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "malloc AuthFsm fail");
        return NULL;
    }
    authFsm->id = GetNextAuthFsmId();
    authFsm->authSeq = authSeq;
    authFsm->info.requestId = requestId;
    authFsm->info.isServer = isServer;
    authFsm->info.connId = connId;
    authFsm->info.connInfo = *connInfo;
    if (sprintf_s(authFsm->fsmName, sizeof(authFsm->fsmName), "AuthFsm-%u", authFsm->id) == -1) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "format auth fsm name fail");
        SoftBusFree(authFsm);
        return NULL;
    }
    if (LnnFsmInit(&authFsm->fsm, NULL, authFsm->fsmName, AuthFsmDeinitCallback) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "init fsm fail");
        SoftBusFree(authFsm);
        return NULL;
    }
    for (int32_t i = 0; i < STATE_NUM_MAX; ++i) {
        LnnFsmAddState(&authFsm->fsm, &g_states[i]);
    }
    ListNodeInsert(&g_authFsmList, &authFsm->node);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "create auth fsm[%"PRId64"], name[%s], side[%s], reqId[%u], "CONN_INFO,
        authFsm->authSeq, authFsm->fsmName, GetAuthSideStr(isServer), requestId, CONN_DATA(connId));
    return authFsm;
}

static void DestroyAuthFsm(AuthFsm *authFsm)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "destroy auth fsm[%"PRId64"], side[%s], reqId[%u]",
        authFsm->authSeq, GetAuthSideStr(authFsm->info.isServer), authFsm->info.requestId);
    ListDelete(&authFsm->node);
    if (authFsm->info.deviceInfoData != NULL) {
        SoftBusFree(authFsm->info.deviceInfoData);
        authFsm->info.deviceInfoData = NULL;
    }
    SoftBusFree(authFsm);
}

static void AuthFsmDeinitCallback(FsmStateMachine *fsm)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth fsm deinit callback enter");
    if (fsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "fsm is null");
        return;
    }
    if (!RequireAuthLock()) {
        return;
    }
    DestroyAuthFsm(TO_AUTH_FSM(fsm));
    ReleaseAuthLock();
}

static MessagePara *NewMessagePara(const uint8_t *data, uint32_t len)
{
    MessagePara *para = (MessagePara *)SoftBusCalloc(sizeof(MessagePara) + len);
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "malloc ExchangeDataPara fail");
        return NULL;
    }
    para->len = len;
    if (memcpy_s(para->data, len, data, len) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "copy data fail");
        SoftBusFree(para);
        return NULL;
    }
    return para;
}

static void FreeMessagePara(MessagePara *para)
{
    if (para != NULL) {
        SoftBusFree(para);
    }
}

static void CompleteAuthSession(AuthFsm *authFsm, int32_t result)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth fsm[%"PRId64"] complete: side=%s, result=%d",
        authFsm->authSeq, GetAuthSideStr(authFsm->info.isServer), result);
    LnnFsmRemoveMessage(&authFsm->fsm, FSM_MSG_AUTH_TIMEOUT);

    if (result == SOFTBUS_OK) {
        AuthManagerSetAuthPassed(authFsm->authSeq, &authFsm->info);
    } else {
        AuthManagerSetAuthFailed(authFsm->authSeq, &authFsm->info, result);
    }

    authFsm->isDead = true;
    LnnFsmStop(&authFsm->fsm);
    LnnFsmDeinit(&authFsm->fsm);
}

static void HandleCommonMsg(AuthFsm *authFsm, int32_t msgType, MessagePara *msgPara)
{
    (void)msgPara;
    switch (msgType) {
        case FSM_MSG_AUTH_TIMEOUT:
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth fsm[%"PRId64"] timeout", authFsm->authSeq);
            CompleteAuthSession(authFsm, SOFTBUS_AUTH_TIMEOUT);
            break;
        case FSM_MSG_DEVICE_NOT_TRUSTED:
            CompleteAuthSession(authFsm, SOFTBUS_AUTH_HICHAIN_NOT_TRUSTED);
            break;
        case FSM_MSG_DEVICE_DISCONNECTED:
            CompleteAuthSession(authFsm, SOFTBUS_AUTH_DEVICE_DISCONNECTED);
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
                "auth fsm[%"PRId64"] cannot handle msg: %d", authFsm->authSeq, msgType);
            break;
        }
}

static void SyncDevIdStateEnter(FsmStateMachine *fsm)
{
    if (fsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "fsm is null");
        return;
    }
    AuthFsm *authFsm = TO_AUTH_FSM(fsm);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "SyncDevIdState: auth fsm[%"PRId64"] enter", authFsm->authSeq);
    if (!authFsm->info.isServer) {
        if (PostDeviceIdMessage(authFsm->authSeq, &authFsm->info) != SOFTBUS_OK) {
            CompleteAuthSession(authFsm, SOFTBUS_AUTH_SYNC_DEVID_FAIL);
        }
    }
}

static void HandleMsgRecvDeviceId(AuthFsm *authFsm, MessagePara *para)
{
    int32_t ret;
    AuthSessionInfo *info = &authFsm->info;
    do {
        if (ProcessDeviceIdMessage(info, para->data, para->len) != SOFTBUS_OK) {
            ret = SOFTBUS_AUTH_SYNC_DEVID_FAIL;
            break;
        }
        if (info->isServer) {
            if (PostDeviceIdMessage(authFsm->authSeq, info) != SOFTBUS_OK) {
                ret = SOFTBUS_AUTH_SYNC_DEVID_FAIL;
                break;
            }
        } else {
            /* just client need start authDevice. */
            if (HichainStartAuth(authFsm->authSeq, info->udid, info->connInfo.peerUid) != SOFTBUS_OK) {
                ret = SOFTBUS_AUTH_HICHAIN_AUTH_FAIL;
                break;
            }
        }
        LnnFsmTransactState(&authFsm->fsm, g_states + STATE_DEVICE_AUTH);
        ret = SOFTBUS_OK;
    } while (false);

    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "handle devId msg fail, ret=%d", ret);
        CompleteAuthSession(authFsm, ret);
    }
}

static bool SyncDevIdStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    MessagePara *msgPara = (MessagePara *)para;
    AuthFsm *authFsm = TranslateToAuthFsm(fsm, msgType, msgPara);
    if (authFsm == NULL) {
        FreeMessagePara(msgPara);
        return false;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "SyncDevIdState: auth fsm[%"PRId64"] process message: %d", authFsm->authSeq, msgType);
    switch (msgType) {
        case FSM_MSG_RECV_DEVICE_ID:
            HandleMsgRecvDeviceId(authFsm, msgPara);
            break;
        default:
            HandleCommonMsg(authFsm, msgType, msgPara);
            break;
    }
    FreeMessagePara(msgPara);
    return true;
}

static void HandleMsgRecvAuthData(AuthFsm *authFsm, MessagePara *para)
{
    if (HichainProcessData(authFsm->authSeq, para->data, para->len) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "process hichain data fail.");
        CompleteAuthSession(authFsm, SOFTBUS_AUTH_HICHAIN_PROCESS_FAIL);
    }
}

static void HandleMsgSaveSessionKey(AuthFsm *authFsm, MessagePara *para)
{
    SessionKey sessionKey = {.len = para->len};
    if (memcpy_s(sessionKey.value, sizeof(sessionKey.value), para->data, para->len) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "copy session key fail.");
        (void)memset_s(&sessionKey, sizeof(sessionKey), 0, sizeof(sessionKey));
        return;
    }
    if (AuthManagerSetSessionKey(authFsm->authSeq, &authFsm->info, &sessionKey) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "auth fsm[%"PRId64"] save session key fail", authFsm->authSeq);
    }
    (void)memset_s(&sessionKey, sizeof(sessionKey), 0, sizeof(sessionKey));
}

static int32_t TrySyncDeviceInfo(int64_t authSeq, AuthSessionInfo *info)
{
    switch (info->connInfo.type) {
        case AUTH_LINK_TYPE_WIFI:
            /* WIFI: client firstly send device info, server just reponse it. */
            if (!info->isServer) {
                return PostDeviceInfoMessage(authSeq, info);
            }
            return SOFTBUS_OK;
        case AUTH_LINK_TYPE_BR:
        case AUTH_LINK_TYPE_BLE:
        case AUTH_LINK_TYPE_P2P:
            return PostDeviceInfoMessage(authSeq, info);
        default:
            break;
    }
    return SOFTBUS_ERR;
}

static void HandleMsgAuthResult(AuthFsm *authFsm, MessagePara *para)
{
    int32_t result = *((int32_t *)(para->data));
    if (result != SOFTBUS_OK) {
        CompleteAuthSession(authFsm, SOFTBUS_AUTH_HICHAIN_AUTH_ERROR);
        return;
    }
    if (TrySyncDeviceInfo(authFsm->authSeq, &authFsm->info) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "auth fsm[%"PRId64"] sync device info fail", authFsm->authSeq);
        CompleteAuthSession(authFsm, SOFTBUS_AUTH_SYNC_DEVINFO_FAIL);
        return;
    }
    if (authFsm->info.deviceInfoData != NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "auth fsm[%"PRId64"] dispatch device info to next state", authFsm->authSeq);
        (void)AuthSessionProcessDevInfoData(authFsm->authSeq,
            authFsm->info.deviceInfoData, authFsm->info.deviceInfoDataLen);
        SoftBusFree(authFsm->info.deviceInfoData);
        authFsm->info.deviceInfoData = NULL;
    }
    LnnFsmTransactState(&authFsm->fsm, g_states + STATE_SYNC_DEVICE_INFO);
}

static void HandleMsgRecvDevInfoEarly(AuthFsm *authFsm, MessagePara *para)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "auth fsm[%"PRId64"] recv device info early, save it", authFsm->authSeq);
    AuthSessionInfo *info = &authFsm->info;
    if (info->deviceInfoData != NULL) {
        SoftBusFree(info->deviceInfoData);
        info->deviceInfoData = NULL;
    }
    info->deviceInfoData = DupMemBuffer(para->data, para->len);
    if (info->deviceInfoData == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "dup device info fail.");
        return;
    }
    info->deviceInfoDataLen = para->len;
}

static bool DeviceAuthStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    MessagePara *msgPara = (MessagePara *)para;
    AuthFsm *authFsm = TranslateToAuthFsm(fsm, msgType, msgPara);
    if (authFsm == NULL) {
        FreeMessagePara(msgPara);
        return false;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "DeviceAuthState: auth fsm[%"PRId64"] process message: %d", authFsm->authSeq, msgType);
    switch (msgType) {
        case FSM_MSG_RECV_AUTH_DATA:
            HandleMsgRecvAuthData(authFsm, msgPara);
            break;
        case FSM_MSG_SAVE_SESSION_KEY:
            HandleMsgSaveSessionKey(authFsm, msgPara);
            break;
        case FSM_MSG_AUTH_RESULT:
            HandleMsgAuthResult(authFsm, msgPara);
            break;
        case FSM_MSG_RECV_DEVICE_INFO:
            HandleMsgRecvDevInfoEarly(authFsm, msgPara);
            break;
        default:
            HandleCommonMsg(authFsm, msgType, msgPara);
            break;
    }
    FreeMessagePara(msgPara);
    return true;
}

static void HandleMsgRecvDeviceInfo(AuthFsm *authFsm, MessagePara *para)
{
    AuthSessionInfo *info = &authFsm->info;
    if (ProcessDeviceInfoMessage(authFsm->authSeq, info, para->data, para->len) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "process device info msg fail.");
        CompleteAuthSession(authFsm, SOFTBUS_AUTH_UNPACK_DEVINFO_FAIL);
        return;
    }
    info->isNodeInfoReceived = true;

    if (info->connInfo.type == AUTH_LINK_TYPE_WIFI) {
        if (!info->isServer) {
            CompleteAuthSession(authFsm, SOFTBUS_OK);
            return;
        }
        /* WIFI: server should response device info */
        if (PostDeviceInfoMessage(authFsm->authSeq, info) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "server: response device info fail.");
            CompleteAuthSession(authFsm, SOFTBUS_AUTH_SYNC_DEVINFO_FAIL);
            return;
        }
        CompleteAuthSession(authFsm, SOFTBUS_OK);
        return;
    }

    if (PostCloseAckMessage(authFsm->authSeq, info) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "post close ack fail.");
        CompleteAuthSession(authFsm, SOFTBUS_AUTH_SEND_FAIL);
        return;
    }
    if (info->isCloseAckReceived) {
        CompleteAuthSession(authFsm, SOFTBUS_OK);
    }
}

static void HandleMsgRecvCloseAck(AuthFsm *authFsm, MessagePara *para)
{
    (void)para;
    AuthSessionInfo *info = &authFsm->info;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "auth fsm[%"PRId64"] recv close ack, isNodeInfoReceived=%d", authFsm->authSeq, info->isNodeInfoReceived);
    if (info->isNodeInfoReceived) {
        CompleteAuthSession(authFsm, SOFTBUS_OK);
    } else {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "close ack received before device info");
        info->isCloseAckReceived = true;
    }
}

static bool SyncDevInfoStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    MessagePara *msgPara = (MessagePara *)para;
    AuthFsm *authFsm = TranslateToAuthFsm(fsm, msgType, msgPara);
    if (authFsm == NULL) {
        FreeMessagePara(msgPara);
        return false;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "SyncDevInfoState: auth fsm[%"PRId64"] process message: %d", authFsm->authSeq, msgType);
    switch (msgType) {
        case FSM_MSG_RECV_DEVICE_INFO:
            HandleMsgRecvDeviceInfo(authFsm, msgPara);
            break;
        case FSM_MSG_RECV_CLOSE_ACK:
            HandleMsgRecvCloseAck(authFsm, msgPara);
            break;
        default:
            HandleCommonMsg(authFsm, msgType, msgPara);
            break;
    }
    FreeMessagePara(msgPara);
    return true;
}

static AuthFsm *GetAuthFsmByAuthSeq(int64_t authSeq)
{
    AuthFsm *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_authFsmList, AuthFsm, node) {
        if (item->authSeq != authSeq) {
            continue;
        }
        if (item->isDead) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
                "auth fsm[%"PRId64"] has dead.", item->authSeq);
            break;
        }
        return item;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth fsm[%"PRId64"] not found.", authSeq);
    return NULL;
}

static AuthFsm *GetAuthFsmByConnId(uint64_t connId, bool isServer)
{
    AuthFsm *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_authFsmList, AuthFsm, node) {
        if (item->info.connId != connId || item->info.isServer != isServer) {
            continue;
        }
        if (item->isDead) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
                "auth fsm[%"PRId64"] has dead.", item->authSeq);
            break;
        }
        return item;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
        "auth fsm not found by "CONN_INFO, CONN_DATA(connId));
    return NULL;
}

static int32_t GetSessionInfoFromAuthFsm(int64_t authSeq, AuthSessionInfo *info)
{
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    AuthFsm *authFsm = GetAuthFsmByAuthSeq(authSeq);
    if (authFsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth fsm[%"PRId64"] not found.", authSeq);
        ReleaseAuthLock();
        return SOFTBUS_ERR;
    }
    *info = authFsm->info;
    info->deviceInfoData = NULL;
    info->deviceInfoDataLen = 0;
    ReleaseAuthLock();
    return SOFTBUS_OK;
}

static int32_t PostMessageToAuthFsm(int32_t msgType, int64_t authSeq, const uint8_t *data, uint32_t len)
{
    MessagePara *para = NewMessagePara(data, len);
    if (para == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    if (!RequireAuthLock()) {
        SoftBusFree(para);
        return SOFTBUS_LOCK_ERR;
    }
    AuthFsm *authFsm = GetAuthFsmByAuthSeq(authSeq);
    if (authFsm == NULL) {
        ReleaseAuthLock();
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    LnnFsmPostMessage(&authFsm->fsm, msgType, para);
    ReleaseAuthLock();
    return SOFTBUS_OK;
}

static int32_t PostMessageToAuthFsmByConnId(int32_t msgType, uint64_t connId, bool isServer,
    const uint8_t *data, uint32_t len)
{
    MessagePara *para = NewMessagePara(data, len);
    if (para == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    if (!RequireAuthLock()) {
        SoftBusFree(para);
        return SOFTBUS_LOCK_ERR;
    }
    AuthFsm *authFsm = GetAuthFsmByConnId(connId, isServer);
    if (authFsm == NULL) {
        ReleaseAuthLock();
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    LnnFsmPostMessage(&authFsm->fsm, msgType, para);
    ReleaseAuthLock();
    return SOFTBUS_OK;
}

int32_t AuthSessionStartAuth(int64_t authSeq, uint32_t requestId,
    uint64_t connId, const AuthConnInfo *connInfo, bool isServer)
{
    CHECK_NULL_PTR_RETURN_VALUE(connInfo, SOFTBUS_INVALID_PARAM);
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    AuthFsm *authFsm = CreateAuthFsm(authSeq, requestId, connId, connInfo, isServer);
    if (authFsm == NULL) {
        ReleaseAuthLock();
        return SOFTBUS_MEM_ERR;
    }
    if (LnnFsmStart(&authFsm->fsm, g_states + STATE_SYNC_DEVICE_ID) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "start auth fsm[%"PRId64"]", authFsm->authSeq);
        DestroyAuthFsm(authFsm);
        ReleaseAuthLock();
        return SOFTBUS_ERR;
    }
    LnnFsmPostMessageDelay(&authFsm->fsm, FSM_MSG_AUTH_TIMEOUT, NULL, AUTH_TIMEOUT_MS);
    ReleaseAuthLock();
    return SOFTBUS_OK;
}

int32_t AuthSessionProcessDevIdData(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    if (data == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    return PostMessageToAuthFsm(FSM_MSG_RECV_DEVICE_ID, authSeq, data, len);
}

int32_t AuthSessionPostAuthData(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    AuthSessionInfo info;
    if (GetSessionInfoFromAuthFsm(authSeq, &info) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (PostHichainAuthMessage(authSeq, &info, data, len) != SOFTBUS_OK) {
        return SOFTBUS_AUTH_SYNC_DEVID_FAIL;
    }
    return SOFTBUS_OK;
}

int32_t AuthSessionProcessAuthData(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    if (data == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    return PostMessageToAuthFsm(FSM_MSG_RECV_AUTH_DATA, authSeq, data, len);
}

int32_t AuthSessionGetUdid(int64_t authSeq, char *udid, uint32_t size)
{
    if (udid == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    AuthSessionInfo info = {0};
    if (GetSessionInfoFromAuthFsm(authSeq, &info) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (memcpy_s(udid, size, info.udid, sizeof(info.udid)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "copy udid fail.");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t AuthSessionSaveSessionKey(int64_t authSeq, const uint8_t *key, uint32_t len)
{
    if (key == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    return PostMessageToAuthFsm(FSM_MSG_SAVE_SESSION_KEY, authSeq, key, len);
}

int32_t AuthSessionHandleAuthResult(int64_t authSeq, int32_t reason)
{
    return PostMessageToAuthFsm(FSM_MSG_AUTH_RESULT, authSeq, (uint8_t *)&reason, sizeof(reason));
}

int32_t AuthSessionProcessDevInfoData(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    if (data == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    return PostMessageToAuthFsm(FSM_MSG_RECV_DEVICE_INFO, authSeq, data, len);
}

int32_t AuthSessionProcessCloseAck(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    if (data == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    return PostMessageToAuthFsm(FSM_MSG_RECV_CLOSE_ACK, authSeq, data, len);
}

int32_t AuthSessionProcessDevInfoDataByConnId(uint64_t connId, bool isServer, const uint8_t *data, uint32_t len)
{
    if (data == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    return PostMessageToAuthFsmByConnId(FSM_MSG_RECV_DEVICE_INFO, connId, isServer, data, len);
}

int32_t AuthSessionProcessCloseAckByConnId(uint64_t connId, bool isServer, const uint8_t *data, uint32_t len)
{
    if (data == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    return PostMessageToAuthFsmByConnId(FSM_MSG_RECV_CLOSE_ACK, connId, isServer, data, len);
}

int32_t AuthSessionHandleDeviceNotTrusted(const char *udid)
{
    if (udid == NULL || udid[0] == '\0') {
        return SOFTBUS_INVALID_PARAM;
    }
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    AuthFsm *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_authFsmList, AuthFsm, node) {
        if (strcmp(item->info.udid, udid) != 0) {
            continue;
        }
        if (item->isDead) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
                "auth fsm[%"PRId64"] has dead.", item->authSeq);
            continue;
        }
        LnnFsmPostMessage(&item->fsm, FSM_MSG_DEVICE_NOT_TRUSTED, NULL);
    }
    ReleaseAuthLock();
    return SOFTBUS_OK;
}

int32_t AuthSessionHandleDeviceDisconnected(uint64_t connId)
{
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    AuthFsm *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_authFsmList, AuthFsm, node) {
        if (item->info.connId != connId) {
            continue;
        }
        if (item->isDead) {
            ALOGE("auth fsm[%"PRId64"] has dead.", item->authSeq);
            continue;
        }
        LnnFsmPostMessage(&item->fsm, FSM_MSG_DEVICE_DISCONNECTED, NULL);
    }
    ReleaseAuthLock();
    return SOFTBUS_OK;
}

void AuthSessionFsmExit(void)
{
    HichainDestroy();
    if (!RequireAuthLock()) {
        return;
    }
    AuthFsm *item = NULL;
    AuthFsm *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authFsmList, AuthFsm, node) {
        DestroyAuthFsm(item);
    }
    ListInit(&g_authFsmList);
    ReleaseAuthLock();
}
