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
#include "auth_device_common_key.h"
#include "auth_hichain.h"
#include "auth_manager.h"
#include "auth_session_message.h"
#include "softbus_adapter_hitrace.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"

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
    FSM_MSG_AUTH_ERROR,
    FSM_MSG_RECV_DEVICE_INFO,
    FSM_MSG_RECV_CLOSE_ACK,
    FSM_MSG_AUTH_FINISH,
    FSM_MSG_AUTH_TIMEOUT,
    FSM_MSG_DEVICE_NOT_TRUSTED,
    FSM_MSG_DEVICE_DISCONNECTED,
    FSM_MSG_UNKNOWN,
} StateMessageType;
typedef struct {
    StateMessageType type;
    char *msg;
} StateMsgMap;

static const StateMsgMap g_StateMsgMap[] = {
    {FSM_MSG_RECV_DEVICE_ID, (char *)"RECV_DEVICE_ID"},
    {FSM_MSG_RECV_AUTH_DATA, (char *)"RECV_AUTH_DATA"},
    {FSM_MSG_SAVE_SESSION_KEY, (char *)"SAVE_SESSION_KEY"},
    {FSM_MSG_AUTH_ERROR, (char *)"AUTH_ERROR"},
    {FSM_MSG_RECV_DEVICE_INFO, (char *)"RECV_DEVICE_INFO"},
    {FSM_MSG_RECV_CLOSE_ACK, (char *)"RECV_CLOSE_ACK"},
    {FSM_MSG_AUTH_FINISH, (char *)"AUTH_FINISH"},
    {FSM_MSG_AUTH_TIMEOUT, (char *)"AUTH_TIMEOUT"},
    {FSM_MSG_DEVICE_NOT_TRUSTED, (char *)"DEVICE_NOT_TRUSTED"},
    {FSM_MSG_DEVICE_DISCONNECTED, (char *)"DEVICE_DISCONNECTED"},
    {FSM_MSG_UNKNOWN, (char *)"UNKNOWN MSG!!"},
};

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

static char *FsmMsgTypeToStr(int32_t type)
{
    if (type < FSM_MSG_RECV_DEVICE_ID || type > FSM_MSG_DEVICE_DISCONNECTED) {
        return g_StateMsgMap[FSM_MSG_UNKNOWN].msg;
    }
    return g_StateMsgMap[type].msg;
}

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
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth fsm[%" PRId64 "] has dead", authFsm->authSeq);
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
    AuthFsm *authFsm = (AuthFsm *)SoftBusCalloc(sizeof(AuthFsm));
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
    authFsm->info.version = SOFTBUS_NEW_V2;
    authFsm->info.idType = EXCHANHE_UDID;
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
        "create auth fsm[%" PRId64 "], name[%s], side[%s], reqId[%u], " CONN_INFO,
        authFsm->authSeq, authFsm->fsmName, GetAuthSideStr(isServer), requestId, CONN_DATA(connId));
    return authFsm;
}

static void DestroyAuthFsm(AuthFsm *authFsm)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "destroy auth fsm[%" PRId64 "], side[%s], reqId[%u]",
        authFsm->authSeq, GetAuthSideStr(authFsm->info.isServer), authFsm->info.requestId);
    ListDelete(&authFsm->node);
    if (authFsm->info.deviceInfoData != NULL) {
        SoftBusFree(authFsm->info.deviceInfoData);
        authFsm->info.deviceInfoData = NULL;
    }
    SoftBusFree(authFsm);
}

NO_SANITIZE("cfi") static void AuthFsmDeinitCallback(FsmStateMachine *fsm)
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
    if (data != NULL && len > 0 && memcpy_s(para->data, len, data, len) != EOK) {
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

static SoftBusLinkType ConvertAuthLinkTypeToHisysEvtLinkType(AuthLinkType type)
{
    switch (type) {
        case AUTH_LINK_TYPE_WIFI:
            return SOFTBUS_HISYSEVT_LINK_TYPE_WLAN;
        case AUTH_LINK_TYPE_BR:
            return SOFTBUS_HISYSEVT_LINK_TYPE_BR;
        case AUTH_LINK_TYPE_BLE:
            return SOFTBUS_HISYSEVT_LINK_TYPE_BLE;
        case AUTH_LINK_TYPE_P2P:
            return SOFTBUS_HISYSEVT_LINK_TYPE_P2P;
        default:
            return SOFTBUS_HISYSEVT_LINK_TYPE_BUTT;
    }
}

static void ReportAuthResultEvt(AuthFsm *authFsm, int32_t result)
{
    ALOGI("report auth result evt enter");
    SoftBusLinkType linkType = ConvertAuthLinkTypeToHisysEvtLinkType(authFsm->info.connInfo.type);
    if (linkType == SOFTBUS_HISYSEVT_LINK_TYPE_BUTT) {
        return;
    }
    authFsm->statisticData.endAuthTime = LnnUpTimeMs();
    uint64_t costTime = authFsm->statisticData.endAuthTime - authFsm->statisticData.startAuthTime;
    AuthFailStage stage;
    switch (result) {
        case SOFTBUS_OK:
            if (SoftBusRecordAuthResult(linkType, SOFTBUS_OK, costTime, AUTH_STAGE_BUTT) != SOFTBUS_OK) {
                ALOGE("report static auth result fail");
            }
            return;
        case SOFTBUS_AUTH_SYNC_DEVID_FAIL:
        case SOFTBUS_AUTH_SYNC_DEVINFO_FAIL:
        case SOFTBUS_AUTH_UNPACK_DEVINFO_FAIL:
        case SOFTBUS_AUTH_SEND_FAIL:
            stage = AUTH_EXCHANGE_STAGE;
            break;
        case SOFTBUS_AUTH_DEVICE_DISCONNECTED:
            stage = AUTH_CONNECT_STAGE;
            break;
        case SOFTBUS_AUTH_HICHAIN_PROCESS_FAIL:
        case SOFTBUS_AUTH_HICHAIN_AUTH_ERROR:
        case SOFTBUS_AUTH_TIMEOUT:
        case SOFTBUS_AUTH_HICHAIN_NOT_TRUSTED:
            stage = AUTH_VERIFY_STAGE;
            break;
        default:
            ALOGE("unsupport reasn:%d.", result);
            return;
    }
    if (SoftBusRecordAuthResult(linkType, SOFTBUS_ERR, costTime, stage) != SOFTBUS_OK) {
        ALOGE("report static auth result fail");
    }
    SoftBusFaultEvtInfo info;
    (void)memset_s(&info, sizeof(SoftBusFaultEvtInfo), 0, sizeof(SoftBusFaultEvtInfo));
    info.moduleType = MODULE_TYPE_AUTH;
    info.linkType = linkType;
    info.errorCode = result;
    if (SoftBusReportBusCenterFaultEvt(&info) != SOFTBUS_OK) {
        ALOGE("report buscenter fault evt fail");
    }
}

static void SaveDeviceKey(AuthFsm *authFsm)
{
    AuthDeviceKeyInfo deviceKey;
    SessionKey sessionKey;
    (void)memset_s(&deviceKey, sizeof(AuthDeviceKeyInfo), 0, sizeof(AuthDeviceKeyInfo));
    (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
    if (AuthManagerGetSessionKey(authFsm->authSeq, &authFsm->info, &sessionKey) != SOFTBUS_OK) {
        ALOGE("get session key fail");
        return;
    }
    if (memcpy_s(deviceKey.deviceKey, sizeof(deviceKey.deviceKey),
        sessionKey.value, sizeof(sessionKey.value)) != EOK) {
        ALOGE("session key cpy fail");
        return;
    }
    deviceKey.keyLen = sessionKey.len;
    deviceKey.keyIndex = authFsm->authSeq;
    deviceKey.keyType = authFsm->info.connInfo.type;
    deviceKey.isServerSide = authFsm->info.isServer;
    if (AuthInsertDeviceKey(&authFsm->info.nodeInfo, &deviceKey) != SOFTBUS_OK) {
        ALOGE("insert deviceKey fail");
        return;
    }
}

static void CompleteAuthSession(AuthFsm *authFsm, int32_t result)
{
    SoftbusHitraceStart(SOFTBUS_HITRACE_ID_VALID, (uint64_t)authFsm->authSeq);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth fsm[%" PRId64 "] complete: side=%s, result=%d",
        authFsm->authSeq, GetAuthSideStr(authFsm->info.isServer), result);
    ReportAuthResultEvt(authFsm, result);
    if (result == SOFTBUS_OK) {
        AuthManagerSetAuthFinished(authFsm->authSeq, &authFsm->info);
        if ((!authFsm->info.isSupportFastAuth) && (authFsm->info.connInfo.type == AUTH_LINK_TYPE_BLE)) {
            ALOGI("only hichain verify, save the device key");
            SaveDeviceKey(authFsm);
        }
    } else {
        LnnFsmRemoveMessage(&authFsm->fsm, FSM_MSG_AUTH_TIMEOUT);
        AuthManagerSetAuthFailed(authFsm->authSeq, &authFsm->info, result);
    }

    authFsm->isDead = true;
    LnnFsmStop(&authFsm->fsm);
    LnnFsmDeinit(&authFsm->fsm);
    SoftbusHitraceStop();
}

static void HandleCommonMsg(AuthFsm *authFsm, int32_t msgType, MessagePara *msgPara)
{
    (void)msgPara;
    switch (msgType) {
        case FSM_MSG_AUTH_TIMEOUT:
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth fsm[%" PRId64 "] timeout", authFsm->authSeq);
            CompleteAuthSession(authFsm, SOFTBUS_AUTH_TIMEOUT);
            break;
        case FSM_MSG_DEVICE_NOT_TRUSTED:
            CompleteAuthSession(authFsm, SOFTBUS_AUTH_HICHAIN_NOT_TRUSTED);
            break;
        case FSM_MSG_DEVICE_DISCONNECTED:
            if (authFsm->info.isNodeInfoReceived && authFsm->info.isCloseAckReceived) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_WARN,
                    "auth fsm[%" PRId64 "] wait for the finish event, ignore this disconnect event", authFsm->authSeq);
                break;
            }
            CompleteAuthSession(authFsm, SOFTBUS_AUTH_DEVICE_DISCONNECTED);
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
                "auth fsm[%" PRId64 "] cannot handle msg: %d", authFsm->authSeq, msgType);
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
    if (authFsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "authFsm is null");
        return;
    }
    SoftbusHitraceStart(SOFTBUS_HITRACE_ID_VALID, (uint64_t)authFsm->authSeq);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "SyncDevIdState: auth fsm[%" PRId64 "] enter", authFsm->authSeq);
    if (!authFsm->info.isServer) {
        if (PostDeviceIdMessage(authFsm->authSeq, &authFsm->info) != SOFTBUS_OK) {
            CompleteAuthSession(authFsm, SOFTBUS_AUTH_SYNC_DEVID_FAIL);
        }
    }
    SoftbusHitraceStop();
}

static int32_t RecoveryDeviceKey(AuthFsm *authFsm)
{
#define UDID_SHORT_HASH_LEN_TEMP 8
#define UDID_SHORT_HASH_HEX_STRING 17
    AuthDeviceKeyInfo key = {0};
    uint8_t hash[SHA_256_HASH_LEN] = {0};
    int ret = SoftBusGenerateStrHash((uint8_t *)authFsm->info.udid, strlen(authFsm->info.udid), hash);
    if (ret != SOFTBUS_OK) {
        ALOGE("generate udidHash fail");
        return SOFTBUS_ERR;
    }
    char udidShortHash[UDID_SHORT_HASH_HEX_STRING] = {0};
    if (ConvertBytesToUpperCaseHexString(udidShortHash, UDID_SHORT_HASH_HEX_STRING,
        hash, UDID_SHORT_HASH_LEN_TEMP) != SOFTBUS_OK) {
        ALOGE("convert bytes to string fail");
        return SOFTBUS_ERR;
    }
    if (AuthFindDeviceKey(udidShortHash, authFsm->info.connInfo.type , &key) != SOFTBUS_OK) {
        ALOGE("find key fail, fastAuth error");
        return SOFTBUS_ERR;
    }
    authFsm->info.oldIndex = key.keyIndex;
    return AuthSessionSaveSessionKey(authFsm->authSeq, key.deviceKey, key.keyLen);
}

static int32_t ClientSetExchangeIdType(AuthFsm *authFsm)
{
    int32_t ret = SOFTBUS_OK;
    AuthSessionInfo *info = &authFsm->info;
    char udidHash[UDID_BUF_LEN] = {0};
    do {
        if (info->idType == EXCHANGE_NETWORKID) {
            if (GetPeerUdidHashByNetworkId(info->udid, udidHash) != SOFTBUS_OK) {
                ret = SOFTBUS_ERR;
                break;
            }
        }
        if (info->idType == EXCHANGE_FAIL) {
            ret = SOFTBUS_ERR;
            break;
        }
    } while (false);
    if (ret != SOFTBUS_OK) {
        info->idType = EXCHANHE_UDID;
        LnnFsmTransactState(&authFsm->fsm, g_states + STATE_SYNC_DEVICE_ID);
    }
    return ret;
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
        }
        LnnFsmTransactState(&authFsm->fsm, g_states + STATE_DEVICE_AUTH);
        if (info->isSupportFastAuth) {
            ALOGI("fast auth succ");
            if (RecoveryDeviceKey(authFsm) != SOFTBUS_OK) {
                ALOGE("fast auth recovery device key fail");
                ret = SOFTBUS_AUTH_SYNC_DEVID_FAIL;
                 break;
            }
        } else if (!info->isServer) {
            /* just client need start authDevice. */
            if (ClientSetExchangeIdType(authFsm) != SOFTBUS_OK) {
                ret = SOFTBUS_OK;
                break;
            }
            if (HichainStartAuth(authFsm->authSeq, info->udid, info->connInfo.peerUid) != SOFTBUS_OK) {
                ret = SOFTBUS_AUTH_HICHAIN_AUTH_FAIL;
                break;
            }
        }
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
    SoftbusHitraceStart(SOFTBUS_HITRACE_ID_VALID, (uint64_t)authFsm->authSeq);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "SyncDevIdState: auth fsm[%" PRId64"] process message: %s", authFsm->authSeq, FsmMsgTypeToStr(msgType));
    switch (msgType) {
        case FSM_MSG_RECV_DEVICE_ID:
            HandleMsgRecvDeviceId(authFsm, msgPara);
            break;
        default:
            HandleCommonMsg(authFsm, msgType, msgPara);
            break;
    }
    FreeMessagePara(msgPara);
    SoftbusHitraceStop();
    return true;
}

static void HandleMsgRecvAuthData(AuthFsm *authFsm, MessagePara *para)
{
    int32_t ret = HichainProcessData(authFsm->authSeq, para->data, para->len);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "process hichain data fail.");
        if (!authFsm->info.isAuthFinished) {
            CompleteAuthSession(authFsm, SOFTBUS_AUTH_HICHAIN_PROCESS_FAIL);
        } else {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_DBG, "auth has finished, ignore this processing failure.");
        }
    }
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

static void HandleMsgSaveSessionKey(AuthFsm *authFsm, MessagePara *para)
{
    SessionKey sessionKey = {.len = para->len};
    if (memcpy_s(sessionKey.value, sizeof(sessionKey.value), para->data, para->len) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "copy session key fail.");
        (void)memset_s(&sessionKey, sizeof(sessionKey), 0, sizeof(sessionKey));
        return;
    }
    if (AuthManagerSetSessionKey(authFsm->authSeq, &authFsm->info, &sessionKey, true) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "auth fsm[%" PRId64 "] save session key fail", authFsm->authSeq);
    }
    (void)memset_s(&sessionKey, sizeof(sessionKey), 0, sizeof(sessionKey));

    if (TrySyncDeviceInfo(authFsm->authSeq, &authFsm->info) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "auth fsm[%" PRId64"] sync device info fail", authFsm->authSeq);
        CompleteAuthSession(authFsm, SOFTBUS_AUTH_SYNC_DEVINFO_FAIL);
        return;
    }
    if (authFsm->info.deviceInfoData != NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "auth fsm[%" PRId64"] dispatch device info to next state", authFsm->authSeq);
        (void)AuthSessionProcessDevInfoData(authFsm->authSeq,
            authFsm->info.deviceInfoData, authFsm->info.deviceInfoDataLen);
        SoftBusFree(authFsm->info.deviceInfoData);
        authFsm->info.deviceInfoData = NULL;
    }
    LnnFsmTransactState(&authFsm->fsm, g_states + STATE_SYNC_DEVICE_INFO);
}

static void HandleMsgAuthError(AuthFsm *authFsm, MessagePara *para)
{
    int32_t result = *((int32_t *)(para->data));
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
        "auth fsm[%" PRId64"] handle hichain error, reason = %d", authFsm->authSeq, result);
    CompleteAuthSession(authFsm, SOFTBUS_AUTH_HICHAIN_AUTH_ERROR);
}

static void HandleMsgRecvDevInfoEarly(AuthFsm *authFsm, MessagePara *para)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "auth fsm[%" PRId64 "] recv device info early, save it", authFsm->authSeq);
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

static void TryFinishAuthSession(AuthFsm *authFsm)
{
    AuthSessionInfo *info = &authFsm->info;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "auth fsm[%" PRId64"] Try finish auth session, devInfo|closeAck|authFinish=%d|%d|%d",
        authFsm->authSeq, info->isNodeInfoReceived, info->isCloseAckReceived, info->isAuthFinished);
    if (info->isNodeInfoReceived && info->isCloseAckReceived && info->isAuthFinished) {
        CompleteAuthSession(authFsm, SOFTBUS_OK);
    }
}

static void HandleMsgAuthFinish(AuthFsm *authFsm, MessagePara *para)
{
    (void)para;
    AuthSessionInfo *info = &authFsm->info;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "auth fsm[%" PRId64"] hichain finished, devInfo|closeAck=%d|%d",
        authFsm->authSeq, info->isNodeInfoReceived, info->isCloseAckReceived);
    info->isAuthFinished = true;
    TryFinishAuthSession(authFsm);
}

static bool DeviceAuthStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    MessagePara *msgPara = (MessagePara *)para;
    AuthFsm *authFsm = TranslateToAuthFsm(fsm, msgType, msgPara);
    if (authFsm == NULL) {
        FreeMessagePara(msgPara);
        return false;
    }
    SoftbusHitraceStart(SOFTBUS_HITRACE_ID_VALID, (uint64_t)authFsm->authSeq);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "DeviceAuthState: auth fsm[%" PRId64"] process message: %s", authFsm->authSeq, FsmMsgTypeToStr(msgType));
    switch (msgType) {
        case FSM_MSG_RECV_DEVICE_ID:
            HandleMsgRecvDeviceId(authFsm, msgPara);
            break;
        case FSM_MSG_RECV_AUTH_DATA:
            HandleMsgRecvAuthData(authFsm, msgPara);
            break;
        case FSM_MSG_SAVE_SESSION_KEY:
            HandleMsgSaveSessionKey(authFsm, msgPara);
            break;
        case FSM_MSG_AUTH_ERROR:
            HandleMsgAuthError(authFsm, msgPara);
            break;
        case FSM_MSG_RECV_DEVICE_INFO:
            HandleMsgRecvDevInfoEarly(authFsm, msgPara);
            break;
        case FSM_MSG_AUTH_FINISH:
            HandleMsgAuthFinish(authFsm, msgPara);
            break;
        default:
            HandleCommonMsg(authFsm, msgType, msgPara);
            break;
    }
    FreeMessagePara(msgPara);
    SoftbusHitraceStop();
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
        info->isCloseAckReceived = true; /* WiFi auth no need close ack, set true directly */
        if (!info->isServer) {
            LnnFsmRemoveMessage(&authFsm->fsm, FSM_MSG_AUTH_TIMEOUT);
            AuthManagerSetAuthPassed(authFsm->authSeq, info);
            TryFinishAuthSession(authFsm);
            return;
        }
        /* WIFI: server should response device info */
        if (PostDeviceInfoMessage(authFsm->authSeq, info) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "server: response device info fail.");
            CompleteAuthSession(authFsm, SOFTBUS_AUTH_SYNC_DEVINFO_FAIL);
            return;
        }
        LnnFsmRemoveMessage(&authFsm->fsm, FSM_MSG_AUTH_TIMEOUT);
        AuthManagerSetAuthPassed(authFsm->authSeq, info);
        TryFinishAuthSession(authFsm);
        return;
    }

    if (PostCloseAckMessage(authFsm->authSeq, info) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "post close ack fail.");
        CompleteAuthSession(authFsm, SOFTBUS_AUTH_SEND_FAIL);
        return;
    }
    if (info->isCloseAckReceived) {
        LnnFsmRemoveMessage(&authFsm->fsm, FSM_MSG_AUTH_TIMEOUT);
        AuthManagerSetAuthPassed(authFsm->authSeq, info);
        TryFinishAuthSession(authFsm);
    }
}

static void HandleMsgRecvCloseAck(AuthFsm *authFsm, MessagePara *para)
{
    (void)para;
    AuthSessionInfo *info = &authFsm->info;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "auth fsm[%" PRId64 "] recv close ack, isNodeInfoReceived=%d", authFsm->authSeq, info->isNodeInfoReceived);
    info->isCloseAckReceived = true;
    if (info->isNodeInfoReceived) {
        LnnFsmRemoveMessage(&authFsm->fsm, FSM_MSG_AUTH_TIMEOUT);
        AuthManagerSetAuthPassed(authFsm->authSeq, info);
    } else {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "close ack received before device info");
    }
    TryFinishAuthSession(authFsm);
}

static bool SyncDevInfoStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    MessagePara *msgPara = (MessagePara *)para;
    AuthFsm *authFsm = TranslateToAuthFsm(fsm, msgType, msgPara);
    if (authFsm == NULL) {
        FreeMessagePara(msgPara);
        return false;
    }
    SoftbusHitraceStart(SOFTBUS_HITRACE_ID_VALID, (uint64_t)authFsm->authSeq);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "SyncDevInfoState: auth fsm[%" PRId64"] process message: %s", authFsm->authSeq, FsmMsgTypeToStr(msgType));
    switch (msgType) {
        case FSM_MSG_RECV_DEVICE_INFO:
            HandleMsgRecvDeviceInfo(authFsm, msgPara);
            break;
        case FSM_MSG_RECV_CLOSE_ACK:
            HandleMsgRecvCloseAck(authFsm, msgPara);
            break;
        case FSM_MSG_RECV_AUTH_DATA:
            HandleMsgRecvAuthData(authFsm, msgPara);
            break;
        case FSM_MSG_AUTH_FINISH:
            HandleMsgAuthFinish(authFsm, msgPara);
            break;
        default:
            HandleCommonMsg(authFsm, msgType, msgPara);
            break;
    }
    FreeMessagePara(msgPara);
    SoftbusHitraceStop();
    return true;
}

AuthFsm *GetAuthFsmByAuthSeq(int64_t authSeq)
{
    AuthFsm *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_authFsmList, AuthFsm, node) {
        if (item->authSeq != authSeq) {
            continue;
        }
        if (item->isDead) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
                "auth fsm[%" PRId64 "] has dead.", item->authSeq);
            break;
        }
        return item;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth fsm[%" PRId64 "] not found.", authSeq);
    return NULL;
}

AuthFsm *GetAuthFsmByConnId(uint64_t connId, bool isServer)
{
    AuthFsm *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_authFsmList, AuthFsm, node) {
        if (item->info.connId != connId || item->info.isServer != isServer) {
            continue;
        }
        if (item->isDead) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
                "auth fsm[%" PRId64 "] has dead.", item->authSeq);
            break;
        }
        return item;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
        "auth fsm not found by " CONN_INFO, CONN_DATA(connId));
    return NULL;
}

static int32_t GetSessionInfoFromAuthFsm(int64_t authSeq, AuthSessionInfo *info)
{
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    AuthFsm *authFsm = GetAuthFsmByAuthSeq(authSeq);
    if (authFsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth fsm[%" PRId64 "] not found.", authSeq);
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
    if (LnnFsmPostMessage(&authFsm->fsm, msgType, para) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "post message to auth fsm fail.");
        ReleaseAuthLock();
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
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
    if (LnnFsmPostMessage(&authFsm->fsm, msgType, para) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "post message to auth fsm by connId fail.");
        ReleaseAuthLock();
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    ReleaseAuthLock();
    return SOFTBUS_OK;
}

static void SetAuthStartTime(AuthFsm *authFsm)
{
    authFsm->statisticData.startAuthTime = LnnUpTimeMs();
}

NO_SANITIZE("cfi") int32_t AuthSessionStartAuth(int64_t authSeq, uint32_t requestId,
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
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "start auth fsm[%" PRId64 "]", authFsm->authSeq);
        DestroyAuthFsm(authFsm);
        ReleaseAuthLock();
        return SOFTBUS_ERR;
    }
    SetAuthStartTime(authFsm);
    LnnFsmPostMessageDelay(&authFsm->fsm, FSM_MSG_AUTH_TIMEOUT, NULL, AUTH_TIMEOUT_MS);
    ReleaseAuthLock();
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") int32_t AuthSessionProcessDevIdData(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    if (data == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    return PostMessageToAuthFsm(FSM_MSG_RECV_DEVICE_ID, authSeq, data, len);
}

NO_SANITIZE("cfi") int32_t AuthSessionPostAuthData(int64_t authSeq, const uint8_t *data, uint32_t len)
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

NO_SANITIZE("cfi") int32_t AuthSessionProcessAuthData(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    if (data == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    return PostMessageToAuthFsm(FSM_MSG_RECV_AUTH_DATA, authSeq, data, len);
}

NO_SANITIZE("cfi") int32_t AuthSessionGetUdid(int64_t authSeq, char *udid, uint32_t size)
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

NO_SANITIZE("cfi") int32_t AuthSessionSaveSessionKey(int64_t authSeq, const uint8_t *key, uint32_t len)
{
    if (key == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    return PostMessageToAuthFsm(FSM_MSG_SAVE_SESSION_KEY, authSeq, key, len);
}

NO_SANITIZE("cfi") int32_t AuthSessionHandleAuthFinish(int64_t authSeq)
{
    return PostMessageToAuthFsm(FSM_MSG_AUTH_FINISH, authSeq, NULL, 0);
}

NO_SANITIZE("cfi") int32_t AuthSessionHandleAuthError(int64_t authSeq, int32_t reason)
{
    return PostMessageToAuthFsm(FSM_MSG_AUTH_ERROR, authSeq, (uint8_t *)&reason, sizeof(reason));
}

NO_SANITIZE("cfi") int32_t AuthSessionProcessDevInfoData(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    if (data == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    return PostMessageToAuthFsm(FSM_MSG_RECV_DEVICE_INFO, authSeq, data, len);
}

NO_SANITIZE("cfi") int32_t AuthSessionProcessCloseAck(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    if (data == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    return PostMessageToAuthFsm(FSM_MSG_RECV_CLOSE_ACK, authSeq, data, len);
}

NO_SANITIZE("cfi") int32_t AuthSessionProcessDevInfoDataByConnId(uint64_t connId, bool isServer, const uint8_t *data,
    uint32_t len)
{
    if (data == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    return PostMessageToAuthFsmByConnId(FSM_MSG_RECV_DEVICE_INFO, connId, isServer, data, len);
}

NO_SANITIZE("cfi") int32_t AuthSessionProcessCloseAckByConnId(uint64_t connId, bool isServer, const uint8_t *data,
    uint32_t len)
{
    if (data == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    return PostMessageToAuthFsmByConnId(FSM_MSG_RECV_CLOSE_ACK, connId, isServer, data, len);
}

NO_SANITIZE("cfi") int32_t AuthSessionHandleDeviceNotTrusted(const char *udid)
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
                "auth fsm[%" PRId64 "] has dead.", item->authSeq);
            continue;
        }
        LnnFsmPostMessage(&item->fsm, FSM_MSG_DEVICE_NOT_TRUSTED, NULL);
    }
    ReleaseAuthLock();
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") int32_t AuthSessionHandleDeviceDisconnected(uint64_t connId)
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
            ALOGE("auth fsm[%" PRId64 "] has dead.", item->authSeq);
            continue;
        }
        LnnFsmPostMessage(&item->fsm, FSM_MSG_DEVICE_DISCONNECTED, NULL);
    }
    ReleaseAuthLock();
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") void AuthSessionFsmExit(void)
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
