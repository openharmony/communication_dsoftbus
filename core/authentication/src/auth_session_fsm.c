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

#include "anonymizer.h"
#include "auth_connection.h"
#include "auth_device_common_key.h"
#include "auth_hichain.h"
#include "auth_log.h"
#include "auth_manager.h"
#include "auth_request.h"
#include "auth_session_message.h"
#include "bus_center_manager.h"
#include "lnn_event.h"
#include "softbus_adapter_hitrace.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"

#define AUTH_TIMEOUT_MS (10 * 1000)
#define TO_AUTH_FSM(ptr) CONTAINER_OF(ptr, AuthFsm, fsm)
#define SHORT_UDID_HASH_LEN 8
#define SHORT_UDID_HASH_HEX_LEN 16

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
        AUTH_LOGE(AUTH_FSM, "fsm is null");
        return NULL;
    }
    AuthFsm *authFsm = TO_AUTH_FSM(fsm);
    if (authFsm == NULL) {
        AUTH_LOGE(AUTH_FSM, "authFsm is null");
        return NULL;
    }
    if (authFsm->isDead) {
        AUTH_LOGE(AUTH_FSM, "auth fsm has dead. authSeq=%{public}" PRId64 "", authFsm->authSeq);
        return NULL;
    }
    /* check para */
    if ((msgType != FSM_MSG_AUTH_TIMEOUT &&
        msgType != FSM_MSG_DEVICE_NOT_TRUSTED &&
        msgType != FSM_MSG_DEVICE_DISCONNECTED) && para == NULL) {
        AUTH_LOGE(AUTH_FSM, "invalid msgType. msgType=%{public}d", msgType);
        return NULL;
    }
    return authFsm;
}

static uint32_t GetNextAuthFsmId(void)
{
    static uint32_t authFsmId = 0;
    return ++authFsmId;
}

static bool IsNeedExchangeNetworkId(uint32_t feature, AuthCapability capaBit)
{
    return ((feature & (1 << (uint32_t)capaBit)) != 0);
}

static void AddUdidInfo(uint32_t requestId, bool isServer, AuthConnInfo *connInfo)
{
    if (isServer || connInfo->type != AUTH_LINK_TYPE_ENHANCED_P2P) {
        AUTH_LOGD(AUTH_FSM, "is not server or enhancedP2p");
        return;
    }
    AuthRequest request;
    (void)memset_s(&request, sizeof(request), 0, sizeof(request));
    if (GetAuthRequestNoLock(requestId, &request) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "get auth request fail");
        return;
    }
    if (strcpy_s(connInfo->info.ipInfo.udid, UDID_BUF_LEN,
        request.connInfo.info.ipInfo.udid) != EOK) {
        AUTH_LOGE(AUTH_FSM, "strcpy udid fail");
        return;
    }
}

static int32_t ProcAuthFsm(uint32_t requestId, bool isServer, AuthFsm *authFsm)
{
    AuthRequest request;
    NodeInfo nodeInfo;
    (void)memset_s(&request, sizeof(request), 0, sizeof(request));
    (void)memset_s(&nodeInfo, sizeof(nodeInfo), 0, sizeof(nodeInfo));
    AddUdidInfo(requestId, isServer, &authFsm->info.connInfo);
    if (authFsm->info.connInfo.type == AUTH_LINK_TYPE_BLE) {
        if (GetAuthRequestNoLock(requestId, &request) != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_FSM, "get auth request fail");
            return SOFTBUS_ERR;
        }
        char udidHash[SHORT_UDID_HASH_HEX_LEN + 1] = {0};
        int32_t ret = ConvertBytesToHexString(udidHash, SHORT_UDID_HASH_HEX_LEN + 1,
            (const unsigned char *)request.connInfo.info.bleInfo.deviceIdHash, SHORT_UDID_HASH_LEN);
        if (ret == SOFTBUS_OK && LnnRetrieveDeviceInfo((const char *)udidHash, &nodeInfo) == SOFTBUS_OK &&
            IsNeedExchangeNetworkId(nodeInfo.authCapacity, BIT_SUPPORT_EXCHANGE_NETWORKID)) {
            AUTH_LOGI(AUTH_FSM, "LnnRetrieveDeviceInfo success");
            authFsm->info.idType = EXCHANGE_NETWORKID;
        }
    }
    return SOFTBUS_OK;
}

static AuthFsm *CreateAuthFsm(int64_t authSeq, uint32_t requestId, uint64_t connId,
    const AuthConnInfo *connInfo, bool isServer)
{
    AuthFsm *authFsm = (AuthFsm *)SoftBusCalloc(sizeof(AuthFsm));
    if (authFsm == NULL) {
        AUTH_LOGE(AUTH_FSM, "malloc AuthFsm fail");
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
    if (!isServer) {
        if (ProcAuthFsm(requestId, isServer, authFsm) != SOFTBUS_OK) {
            SoftBusFree(authFsm);
            return NULL;
        }
    }
    if (sprintf_s(authFsm->fsmName, sizeof(authFsm->fsmName), "AuthFsm-%u", authFsm->id) == -1) {
        AUTH_LOGE(AUTH_FSM, "format auth fsm name fail");
        SoftBusFree(authFsm);
        return NULL;
    }
    if (LnnFsmInit(&authFsm->fsm, NULL, authFsm->fsmName, AuthFsmDeinitCallback) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "init fsm fail");
        SoftBusFree(authFsm);
        return NULL;
    }
    for (int32_t i = 0; i < STATE_NUM_MAX; ++i) {
        LnnFsmAddState(&authFsm->fsm, &g_states[i]);
    }
    ListNodeInsert(&g_authFsmList, &authFsm->node);
    AUTH_LOGI(AUTH_FSM,
        "create auth fsm. authSeq=%{public}" PRId64 ", name=%{public}s, side=%{public}s, reqId=%{public}u, " CONN_INFO,
        authFsm->authSeq, authFsm->fsmName, GetAuthSideStr(isServer), requestId, CONN_DATA(connId));
    return authFsm;
}

static void DestroyAuthFsm(AuthFsm *authFsm)
{
    AUTH_LOGI(AUTH_FSM, "destroy auth. authSeq=%{public}" PRId64 ", side=%{public}s, reqId=%{public}u",
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
    AUTH_LOGI(AUTH_FSM, "auth fsm deinit callback enter");
    if (fsm == NULL) {
        AUTH_LOGE(AUTH_FSM, "fsm is null");
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
        AUTH_LOGE(AUTH_FSM, "malloc ExchangeDataPara fail");
        return NULL;
    }
    para->len = len;
    if (data != NULL && len > 0 && memcpy_s(para->data, len, data, len) != EOK) {
        AUTH_LOGE(AUTH_FSM, "copy data fail");
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

static void DfxRecordLnnAuthEnd(AuthFsm *authFsm, uint64_t costTime, int32_t reason)
{
    LnnEventExtra extra = { 0 };
    LnnEventExtraInit(&extra);
    extra.errcode = reason;
    extra.authCostTime = (int32_t)costTime;
    extra.result = (reason == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED;

    if (authFsm != NULL) {
        extra.authLinkType = authFsm->info.connInfo.type;
        extra.authId = (int32_t)authFsm->authSeq;
    }
    LNN_EVENT(EVENT_SCENE_JOIN_LNN, EVENT_STAGE_AUTH, extra);
}

static void ReportAuthResultEvt(AuthFsm *authFsm, int32_t result)
{
    AUTH_LOGE(AUTH_FSM, "report auth result evt enter");
    SoftBusLinkType linkType = ConvertAuthLinkTypeToHisysEvtLinkType(authFsm->info.connInfo.type);
    if (linkType == SOFTBUS_HISYSEVT_LINK_TYPE_BUTT) {
        return;
    }
    authFsm->statisticData.endAuthTime = LnnUpTimeMs();
    uint64_t costTime = authFsm->statisticData.endAuthTime - authFsm->statisticData.startAuthTime;
    DfxRecordLnnAuthEnd(authFsm, costTime, result);
    AuthFailStage stage;
    switch (result) {
        case SOFTBUS_OK:
            if (SoftBusRecordAuthResult(linkType, SOFTBUS_OK, costTime, AUTH_STAGE_BUTT) != SOFTBUS_OK) {
                AUTH_LOGE(AUTH_FSM, "report static auth result fail");
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
            AUTH_LOGE(AUTH_FSM, "unsupport reasn=%{public}d.", result);
            return;
    }
    if (SoftBusRecordAuthResult(linkType, SOFTBUS_ERR, costTime, stage) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "report static auth result fail");
    }
    SoftBusFaultEvtInfo info;
    (void)memset_s(&info, sizeof(SoftBusFaultEvtInfo), 0, sizeof(SoftBusFaultEvtInfo));
    info.moduleType = MODULE_TYPE_AUTH;
    info.linkType = linkType;
    info.errorCode = result;
    if (SoftBusReportBusCenterFaultEvt(&info) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "report buscenter fault evt fail");
    }
}

static void SaveDeviceKey(AuthFsm *authFsm)
{
    AuthDeviceKeyInfo deviceKey;
    SessionKey sessionKey;
    (void)memset_s(&deviceKey, sizeof(AuthDeviceKeyInfo), 0, sizeof(AuthDeviceKeyInfo));
    (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
    if (AuthManagerGetSessionKey(authFsm->authSeq, &authFsm->info, &sessionKey) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "get session key fail");
        return;
    }
    if (memcpy_s(deviceKey.deviceKey, sizeof(deviceKey.deviceKey),
        sessionKey.value, sizeof(sessionKey.value)) != EOK) {
        AUTH_LOGE(AUTH_FSM, "session key cpy fail");
        return;
    }
    deviceKey.keyLen = sessionKey.len;
    deviceKey.keyIndex = authFsm->authSeq;
    deviceKey.keyType = authFsm->info.connInfo.type;
    deviceKey.isServerSide = authFsm->info.isServer;
    if (AuthInsertDeviceKey(&authFsm->info.nodeInfo, &deviceKey) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "insert deviceKey fail");
        return;
    }
}

static void CompleteAuthSession(AuthFsm *authFsm, int32_t result)
{
    SoftbusHitraceStart(SOFTBUS_HITRACE_ID_VALID, (uint64_t)authFsm->authSeq);
    AUTH_LOGI(AUTH_FSM, "auth fsm complete. authSeq=%{public}" PRId64 ", side=%{public}s, result=%{public}d",
        authFsm->authSeq, GetAuthSideStr(authFsm->info.isServer), result);
    ReportAuthResultEvt(authFsm, result);
    if (result == SOFTBUS_OK) {
        AuthManagerSetAuthFinished(authFsm->authSeq, &authFsm->info);
        if ((!authFsm->info.isSupportFastAuth) && (authFsm->info.connInfo.type == AUTH_LINK_TYPE_BLE)) {
            AUTH_LOGI(AUTH_FSM, "only hichain verify, save the device key");
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
            AUTH_LOGE(AUTH_FSM, "auth fsm timeout. authSeq=%{public}" PRId64 "", authFsm->authSeq);
            CompleteAuthSession(authFsm, SOFTBUS_AUTH_TIMEOUT);
            break;
        case FSM_MSG_DEVICE_NOT_TRUSTED:
            CompleteAuthSession(authFsm, SOFTBUS_AUTH_HICHAIN_NOT_TRUSTED);
            break;
        case FSM_MSG_DEVICE_DISCONNECTED:
            if (authFsm->info.isNodeInfoReceived && authFsm->info.isCloseAckReceived) {
                AUTH_LOGW(AUTH_FSM,
                    "auth fsm wait for the finish event, ignore this disconnect event. authSeq=%{public}" PRId64 "",
                    authFsm->authSeq);
                /*
                * Note: Local hichain NOT onFinish, but remote hichain already onFinish
                *      Regard this situation as auth finish
                */
                CompleteAuthSession(authFsm, SOFTBUS_OK);
                break;
            }
            CompleteAuthSession(authFsm, SOFTBUS_AUTH_DEVICE_DISCONNECTED);
            HichainCancelRequest(authFsm->authSeq);
            break;
        default:
            AUTH_LOGE(AUTH_FSM,
                "auth fsm cannot handle msgType. authSeq=%{public}" PRId64 ", msgType=%{public}d",
                authFsm->authSeq, msgType);
            break;
    }
}

static void SyncDevIdStateEnter(FsmStateMachine *fsm)
{
    if (fsm == NULL) {
        AUTH_LOGE(AUTH_FSM, "fsm is null");
        return;
    }
    AuthFsm *authFsm = TO_AUTH_FSM(fsm);
    if (authFsm == NULL) {
        AUTH_LOGE(AUTH_FSM, "authFsm is null");
        return;
    }
    SoftbusHitraceStart(SOFTBUS_HITRACE_ID_VALID, (uint64_t)authFsm->authSeq);
    AUTH_LOGI(AUTH_FSM, "SyncDevIdState: auth fsm enter. authSeq=%{public}" PRId64 "", authFsm->authSeq);
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
        AUTH_LOGE(AUTH_FSM, "generate udidHash fail");
        return ret;
    }
    char udidShortHash[UDID_SHORT_HASH_HEX_STRING] = {0};
    if (ConvertBytesToUpperCaseHexString(udidShortHash, UDID_SHORT_HASH_HEX_STRING,
        hash, UDID_SHORT_HASH_LEN_TEMP) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "convert bytes to string fail");
        return SOFTBUS_ERR;
    }
    AuthLinkType linkType = authFsm->info.connInfo.type;
    if (authFsm->info.connInfo.type == AUTH_LINK_TYPE_ENHANCED_P2P) {
        // enhanced p2p reuse ble authKey
        linkType = AUTH_LINK_TYPE_BLE;
    }
    if (AuthFindDeviceKey(udidShortHash, linkType, &key) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "find key fail, fastAuth error");
        return SOFTBUS_ERR;
    }
    AuthUpdateKeyIndex(udidShortHash, authFsm->info.connInfo.type, authFsm->authSeq, authFsm->info.isServer);
    authFsm->info.oldIndex = key.keyIndex;
    ret = AuthSessionSaveSessionKey(authFsm->authSeq, key.deviceKey, key.keyLen);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "post save sessionKey event");
        return ret;
    }
    return AuthSessionHandleAuthFinish(authFsm->authSeq);
}

static void AuditReportSetPeerDevInfo(LnnAuditExtra *lnnAuditExtra, AuthSessionInfo *info)
{
    if (lnnAuditExtra == NULL || info == NULL) {
        AUTH_LOGE(AUTH_FSM, "lnnAuditExtra or info is null");
        return;
    }
    switch (info->connInfo.type) {
        case AUTH_LINK_TYPE_BR:
            if (strcpy_s((char *)lnnAuditExtra->peerBrMac, BT_MAC_LEN, info->connInfo.info.brInfo.brMac) != EOK) {
                AUTH_LOGE(AUTH_FSM, "BR MAC COPY ERROR");
            }
            break;
        case AUTH_LINK_TYPE_BLE:
            if (strcpy_s((char *)lnnAuditExtra->peerBleMac, BT_MAC_LEN, info->connInfo.info.bleInfo.bleMac) != EOK) {
                AUTH_LOGE(AUTH_FSM, "BLE MAC COPY ERROR");
            }
            break;
        case AUTH_LINK_TYPE_WIFI:
        case AUTH_LINK_TYPE_P2P:
        case AUTH_LINK_TYPE_ENHANCED_P2P:
            if (strcpy_s((char *)lnnAuditExtra->peerIp, IP_STR_MAX_LEN, info->connInfo.info.ipInfo.ip) != EOK) {
                AUTH_LOGE(AUTH_FSM, "IP COPY ERROR");
            }
            lnnAuditExtra->peerAuthPort = info->connInfo.info.ipInfo.port;
            break;
        default:
            AUTH_LOGW(AUTH_FSM, "unknow param type!");
            break;
    }
}

static void AuditReportSetLocalDevInfo(LnnAuditExtra *lnnAuditExtra)
{
    if (lnnAuditExtra == NULL) {
        AUTH_LOGE(AUTH_FSM, "lnnAuditExtra is null");
        return;
    }
    (void)LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, (char *)lnnAuditExtra->localIp, IP_LEN);
    (void)LnnGetLocalStrInfo(STRING_KEY_BT_MAC, (char *)lnnAuditExtra->localBrMac, MAC_LEN);
    (void)LnnGetLocalStrInfo(STRING_KEY_BLE_MAC, (char *)lnnAuditExtra->localBleMac, MAC_LEN);
    (void)LnnGetLocalStrInfo(STRING_KEY_NETWORKID, (char *)lnnAuditExtra->localNetworkId, NETWORK_ID_BUF_LEN);
    (void)LnnGetLocalStrInfo(STRING_KEY_DEV_NAME, (char *)lnnAuditExtra->localDevName, DEVICE_NAME_BUF_LEN);
    (void)LnnGetLocalNumInfo(NUM_KEY_AUTH_PORT, &lnnAuditExtra->localAuthPort);
    (void)LnnGetLocalNumInfo(NUM_KEY_PROXY_PORT, &lnnAuditExtra->localProxyPort);
    (void)LnnGetLocalNumInfo(NUM_KEY_SESSION_PORT, &lnnAuditExtra->localSessionPort);
    (void)LnnGetLocalNumInfo(NUM_KEY_DEV_TYPE_ID, &lnnAuditExtra->localDevType);
    char udid[UDID_BUF_LEN] = {0};
    uint8_t udidHash[SHA_256_HASH_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, udid, UUID_BUF_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "get local udid fail");
        return;
    }
    int32_t ret = SoftBusGenerateStrHash((const unsigned char *)udid, strlen(udid), udidHash);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "generate udid hash fail");
        return;
    }
    if (ConvertBytesToUpperCaseHexString((char *)lnnAuditExtra->localUdid, SHA_256_HEX_HASH_LEN,
        udidHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "convert hash to upper hex str fail");
    }
}

static void BuildLnnAuditEvent(LnnAuditExtra *lnnAuditExtra, AuthSessionInfo *info, int32_t result,
    int32_t errCode, SoftbusAuditType auditType)
{
    if (lnnAuditExtra == NULL || info == NULL) {
        AUTH_LOGE(AUTH_FSM, "lnnAuditExtra or info is null");
        return;
    }
    (void)AuditReportSetPeerDevInfo(lnnAuditExtra, info);
    (void)AuditReportSetLocalDevInfo(lnnAuditExtra);
    lnnAuditExtra->result = result;
    lnnAuditExtra->errCode = errCode;
    lnnAuditExtra->auditType = auditType;
    lnnAuditExtra->connId = info->connId;
    lnnAuditExtra->authLinkType = info->connInfo.type;
    lnnAuditExtra->authRequestId = info->requestId;
    (void)LnnGetAllOnlineNodeNum(&(lnnAuditExtra->onlineNum));
}

static int32_t ClientSetExchangeIdType(AuthFsm *authFsm)
{
    AuthSessionInfo *info = &authFsm->info;
    if (info->idType == EXCHANGE_FAIL) {
        AUTH_LOGE(AUTH_FSM, "fsm switch to reauth due to not find networkId");
        info->idType = EXCHANHE_UDID;
        LnnFsmTransactState(&authFsm->fsm, g_states + STATE_SYNC_DEVICE_ID);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void HandleMsgRecvDeviceId(AuthFsm *authFsm, const MessagePara *para)
{
    int32_t ret;
    AuthSessionInfo *info = &authFsm->info;
    do {
        if (ProcessDeviceIdMessage(info, para->data, para->len) != SOFTBUS_OK) {
            ret = SOFTBUS_AUTH_SYNC_DEVID_FAIL;
            LnnAuditExtra lnnAuditExtra = {0};
            BuildLnnAuditEvent(&lnnAuditExtra, info, AUDIT_HANDLE_MSG_FAIL_END_AUTH,
                ret, AUDIT_EVENT_PACKETS_ERROR);
            LNN_AUDIT(AUDIT_SCENE_HANDLE_MSG_DEV_ID, lnnAuditExtra);
            break;
        }
        if (info->isServer) {
            if (info->connInfo.type == AUTH_LINK_TYPE_BLE && strlen(info->udid) != 0 &&
                authFsm->info.connInfo.info.bleInfo.deviceIdHash[0] == '\0') {
                (void)SoftBusGenerateStrHash((unsigned char *)info->udid, strlen(info->nodeInfo.deviceInfo.deviceUdid),
                    (unsigned char *)authFsm->info.connInfo.info.bleInfo.deviceIdHash);
            }
            if (PostDeviceIdMessage(authFsm->authSeq, info) != SOFTBUS_OK) {
                ret = SOFTBUS_AUTH_SYNC_DEVID_FAIL;
                break;
            }
        }
        LnnFsmTransactState(&authFsm->fsm, g_states + STATE_DEVICE_AUTH);
        if (info->isSupportFastAuth) {
            AUTH_LOGI(AUTH_FSM, "fast auth succ");
            if (RecoveryDeviceKey(authFsm) != SOFTBUS_OK) {
                AUTH_LOGE(AUTH_FSM, "fast auth recovery device key fail");
                ret = SOFTBUS_AUTH_SYNC_DEVID_FAIL;
                break;
            }
        } else if (!info->isServer) {
            /* just client need start authDevice. */
            if (ClientSetExchangeIdType(authFsm) != SOFTBUS_OK) {
                ret = SOFTBUS_OK;
                break;
            }
            char *anonyUdid = NULL;
            Anonymize(info->udid, &anonyUdid);
            AUTH_LOGI(AUTH_FSM, "start auth send udid=%{public}s", anonyUdid);
            AnonymizeFree(anonyUdid);
            if (HichainStartAuth(authFsm->authSeq, info->udid, info->connInfo.peerUid) != SOFTBUS_OK) {
                ret = SOFTBUS_AUTH_HICHAIN_AUTH_FAIL;
                break;
            }
        }
        ret = SOFTBUS_OK;
    } while (false);

    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "handle devId msg fail, ret=%{public}d", ret);
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
    AUTH_LOGI(AUTH_FSM, "auth fsm process. authSeq=%{public}" PRId64 ", message=%{public}s",
        authFsm->authSeq, FsmMsgTypeToStr(msgType));
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

static void HandleMsgRecvAuthData(AuthFsm *authFsm, const MessagePara *para)
{
    int32_t ret = HichainProcessData(authFsm->authSeq, para->data, para->len);
    if (ret != SOFTBUS_OK) {
        LnnAuditExtra lnnAuditExtra = {0};
        BuildLnnAuditEvent(&lnnAuditExtra, &authFsm->info, AUDIT_HANDLE_MSG_FAIL_END_AUTH,
            ret, AUDIT_EVENT_PACKETS_ERROR);
        LNN_AUDIT(AUDIT_SCENE_HANDLE_MSG_AUTH_DATA, lnnAuditExtra);
        AUTH_LOGE(AUTH_FSM, "process hichain data fail");
        if (!authFsm->info.isAuthFinished) {
            CompleteAuthSession(authFsm, SOFTBUS_AUTH_HICHAIN_PROCESS_FAIL);
        } else {
            AUTH_LOGD(AUTH_FSM, "auth has finished, ignore this processing failure");
        }
    }
}

static int32_t TrySyncDeviceInfo(int64_t authSeq, const AuthSessionInfo *info)
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
        case AUTH_LINK_TYPE_ENHANCED_P2P:
            return PostDeviceInfoMessage(authSeq, info);
        default:
            break;
    }
    return SOFTBUS_ERR;
}

static void HandleMsgSaveSessionKey(AuthFsm *authFsm, const MessagePara *para)
{
    SessionKey sessionKey = {.len = para->len};
    if (memcpy_s(sessionKey.value, sizeof(sessionKey.value), para->data, para->len) != EOK) {
        AUTH_LOGE(AUTH_FSM, "copy session key fail.");
        (void)memset_s(&sessionKey, sizeof(sessionKey), 0, sizeof(sessionKey));
        return;
    }
    if (AuthManagerSetSessionKey(authFsm->authSeq, &authFsm->info, &sessionKey, true) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "auth fsm save session key fail. authSeq=%{public}" PRId64 "", authFsm->authSeq);
    }
    (void)memset_s(&sessionKey, sizeof(sessionKey), 0, sizeof(sessionKey));
    if (LnnGenerateLocalPtk(authFsm->info.udid, authFsm->info.uuid) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "generate ptk fail");
    }
    if (TrySyncDeviceInfo(authFsm->authSeq, &authFsm->info) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "auth fsm sync device info fail. authSeq=%{public}" PRId64 "", authFsm->authSeq);
        CompleteAuthSession(authFsm, SOFTBUS_AUTH_SYNC_DEVINFO_FAIL);
        return;
    }
    if (authFsm->info.deviceInfoData != NULL) {
        AUTH_LOGE(AUTH_FSM, "auth fsm dispatch device info to next state. authSeq=%{public}" PRId64, authFsm->authSeq);
        (void)AuthSessionProcessDevInfoData(authFsm->authSeq,
            authFsm->info.deviceInfoData, authFsm->info.deviceInfoDataLen);
        SoftBusFree(authFsm->info.deviceInfoData);
        authFsm->info.deviceInfoData = NULL;
    }
    LnnFsmTransactState(&authFsm->fsm, g_states + STATE_SYNC_DEVICE_INFO);
}

static void HandleMsgAuthError(AuthFsm *authFsm, const MessagePara *para)
{
    int32_t result = *((int32_t *)(para->data));
    AUTH_LOGE(AUTH_FSM,
        "auth fsm handle hichain error, authSeq=%{public}" PRId64", reason=%{public}d", authFsm->authSeq, result);
    CompleteAuthSession(authFsm, SOFTBUS_AUTH_HICHAIN_AUTH_ERROR);
}

static void HandleMsgRecvDevInfoEarly(AuthFsm *authFsm, const MessagePara *para)
{
    AUTH_LOGI(AUTH_FSM, "auth fsm recv device info early, save it. authSeq=%{public}" PRId64 "", authFsm->authSeq);
    AuthSessionInfo *info = &authFsm->info;
    if (info->deviceInfoData != NULL) {
        SoftBusFree(info->deviceInfoData);
        info->deviceInfoData = NULL;
    }
    info->deviceInfoData = DupMemBuffer(para->data, para->len);
    if (info->deviceInfoData == NULL) {
        AUTH_LOGE(AUTH_FSM, "dup device info fail.");
        return;
    }
    info->deviceInfoDataLen = para->len;
}

static void TryFinishAuthSession(AuthFsm *authFsm)
{
    AuthSessionInfo *info = &authFsm->info;
    AUTH_LOGI(AUTH_FSM,
        "Try finish auth fsm session, authSeq=%{public}" PRId64", devInfo=%{public}d, closeAck=%{public}d, "
        "authFinish=%{public}d",
        authFsm->authSeq, info->isNodeInfoReceived, info->isCloseAckReceived, info->isAuthFinished);
    if (info->isNodeInfoReceived && info->isCloseAckReceived && info->isAuthFinished) {
        CompleteAuthSession(authFsm, SOFTBUS_OK);
    }
}

static void HandleMsgAuthFinish(AuthFsm *authFsm, MessagePara *para)
{
    (void)para;
    AuthSessionInfo *info = &authFsm->info;
    AUTH_LOGI(AUTH_FSM,
        "auth fsm hichain finished, authSeq=%{public}" PRId64", devInfo=%{public}d, closeAck=%{public}d",
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
    AUTH_LOGI(AUTH_FSM, "auth fsm process. authSeq=%{public}" PRId64", message=%{public}s",
        authFsm->authSeq, FsmMsgTypeToStr(msgType));
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

static void HandleMsgRecvDeviceInfo(AuthFsm *authFsm, const MessagePara *para)
{
    AuthSessionInfo *info = &authFsm->info;
    if (ProcessDeviceInfoMessage(authFsm->authSeq, info, para->data, para->len) != SOFTBUS_OK) {
        LnnAuditExtra lnnAuditExtra = {0};
        BuildLnnAuditEvent(&lnnAuditExtra, info, AUDIT_HANDLE_MSG_FAIL_END_AUTH,
            SOFTBUS_AUTH_UNPACK_DEVINFO_FAIL, AUDIT_EVENT_PACKETS_ERROR);
        LNN_AUDIT(AUDIT_SCENE_HANDLE_MSG_DEV_INFO, lnnAuditExtra);
        AUTH_LOGE(AUTH_FSM, "process device info msg fail");
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
            AUTH_LOGE(AUTH_FSM, "server: response device info fail");
            CompleteAuthSession(authFsm, SOFTBUS_AUTH_SYNC_DEVINFO_FAIL);
            return;
        }
        LnnFsmRemoveMessage(&authFsm->fsm, FSM_MSG_AUTH_TIMEOUT);
        AuthManagerSetAuthPassed(authFsm->authSeq, info);
        TryFinishAuthSession(authFsm);
        return;
    }
    if (info->connInfo.type == AUTH_LINK_TYPE_BLE &&
        strlen(info->nodeInfo.deviceInfo.deviceUdid) != 0) {
            (void)SoftBusGenerateStrHash((unsigned char *)info->nodeInfo.deviceInfo.deviceUdid,
                strlen(info->nodeInfo.deviceInfo.deviceUdid),
                (unsigned char *)authFsm->info.connInfo.info.bleInfo.deviceIdHash);
    }
    if (PostCloseAckMessage(authFsm->authSeq, info) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "post close ack fail");
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
    AUTH_LOGI(AUTH_FSM, "auth fsm recv close ack, fsm=%{public}" PRId64 ", isNodeInfoReceived=%{public}d",
        authFsm->authSeq, info->isNodeInfoReceived);
    info->isCloseAckReceived = true;
    if (info->isNodeInfoReceived) {
        LnnFsmRemoveMessage(&authFsm->fsm, FSM_MSG_AUTH_TIMEOUT);
        AuthManagerSetAuthPassed(authFsm->authSeq, info);
    } else {
        AUTH_LOGI(AUTH_FSM, "close ack received before device info");
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
    AUTH_LOGI(AUTH_FSM, "auth fsm process. authSeq=%{public}" PRId64", message=%{public}s",
        authFsm->authSeq, FsmMsgTypeToStr(msgType));
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

static AuthFsm *GetAuthFsmByAuthSeq(int64_t authSeq)
{
    AuthFsm *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_authFsmList, AuthFsm, node) {
        if (item->authSeq != authSeq) {
            continue;
        }
        if (item->isDead) {
            AUTH_LOGE(AUTH_FSM, "auth fsm has dead. authSeq=%{public}" PRId64 "", item->authSeq);
            break;
        }
        return item;
    }
    AUTH_LOGE(AUTH_FSM, "auth fsm not found. authSeq=%{public}" PRId64 "", authSeq);
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
            AUTH_LOGE(AUTH_FSM, "auth fsm has dead. authSeq=%{public}" PRId64 "", item->authSeq);
            break;
        }
        return item;
    }
    AUTH_LOGE(AUTH_FSM, "auth fsm not found. " CONN_INFO, CONN_DATA(connId));
    return NULL;
}

static int32_t GetSessionInfoFromAuthFsm(int64_t authSeq, AuthSessionInfo *info)
{
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    AuthFsm *authFsm = GetAuthFsmByAuthSeq(authSeq);
    if (authFsm == NULL) {
        AUTH_LOGE(AUTH_FSM, "auth fsm not found. authSeq=%{public}" PRId64 "", authSeq);
        ReleaseAuthLock();
        return SOFTBUS_AUTH_NOT_FOUND;
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
        return SOFTBUS_AUTH_GET_FSM_FAIL;
    }
    if (LnnFsmPostMessage(&authFsm->fsm, msgType, para) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "post message to auth fsm fail");
        ReleaseAuthLock();
        SoftBusFree(para);
        return SOFTBUS_AUTH_SEND_FAIL;
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
        return SOFTBUS_AUTH_GET_FSM_FAIL;
    }
    if (LnnFsmPostMessage(&authFsm->fsm, msgType, para) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "post message to auth fsm by connId fail");
        ReleaseAuthLock();
        SoftBusFree(para);
        return SOFTBUS_AUTH_SEND_FAIL;
    }
    ReleaseAuthLock();
    return SOFTBUS_OK;
}

static void SetAuthStartTime(AuthFsm *authFsm)
{
    authFsm->statisticData.startAuthTime = LnnUpTimeMs();
}

int32_t AuthSessionStartAuth(int64_t authSeq, uint32_t requestId,
    uint64_t connId, const AuthConnInfo *connInfo, bool isServer, bool isFastAuth)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(connInfo != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "connInfo is NULL");
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    AuthFsm *authFsm = CreateAuthFsm(authSeq, requestId, connId, connInfo, isServer);
    if (authFsm == NULL) {
        ReleaseAuthLock();
        return SOFTBUS_MEM_ERR;
    }
    authFsm->info.isNeedFastAuth = isFastAuth;
    if (LnnFsmStart(&authFsm->fsm, g_states + STATE_SYNC_DEVICE_ID) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "start auth fsm. authSeq=%{public}" PRId64 "", authFsm->authSeq);
        DestroyAuthFsm(authFsm);
        ReleaseAuthLock();
        return SOFTBUS_ERR;
    }
    SetAuthStartTime(authFsm);
    LnnFsmPostMessageDelay(&authFsm->fsm, FSM_MSG_AUTH_TIMEOUT, NULL, AUTH_TIMEOUT_MS);
    ReleaseAuthLock();
    return SOFTBUS_OK;
}

int32_t AuthSessionProcessDevIdData(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    if (data == NULL) {
        AUTH_LOGE(AUTH_FSM, "data is null");
        return SOFTBUS_INVALID_PARAM;
    }
    return PostMessageToAuthFsm(FSM_MSG_RECV_DEVICE_ID, authSeq, data, len);
}

int32_t AuthSessionPostAuthData(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    AuthSessionInfo info;
    if (GetSessionInfoFromAuthFsm(authSeq, &info) != SOFTBUS_OK) {
        return SOFTBUS_AUTH_GET_SESSION_INFO_FAIL;
    }
    if (PostHichainAuthMessage(authSeq, &info, data, len) != SOFTBUS_OK) {
        return SOFTBUS_AUTH_SYNC_DEVID_FAIL;
    }
    return SOFTBUS_OK;
}

int32_t AuthSessionProcessAuthData(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    if (data == NULL) {
        AUTH_LOGE(AUTH_FSM, "data is null");
        return SOFTBUS_INVALID_PARAM;
    }
    return PostMessageToAuthFsm(FSM_MSG_RECV_AUTH_DATA, authSeq, data, len);
}

int32_t AuthSessionGetUdid(int64_t authSeq, char *udid, uint32_t size)
{
    if (udid == NULL) {
        AUTH_LOGE(AUTH_FSM, "udid is null");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthSessionInfo info = {0};
    if (GetSessionInfoFromAuthFsm(authSeq, &info) != SOFTBUS_OK) {
        return SOFTBUS_AUTH_GET_SESSION_INFO_FAIL;
    }
    if (memcpy_s(udid, size, info.udid, sizeof(info.udid)) != EOK) {
        AUTH_LOGE(AUTH_FSM, "copy udid fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t AuthSessionSaveSessionKey(int64_t authSeq, const uint8_t *key, uint32_t len)
{
    if (key == NULL) {
        AUTH_LOGE(AUTH_FSM, "key is null");
        return SOFTBUS_INVALID_PARAM;
    }
    return PostMessageToAuthFsm(FSM_MSG_SAVE_SESSION_KEY, authSeq, key, len);
}

int32_t AuthSessionHandleAuthFinish(int64_t authSeq)
{
    return PostMessageToAuthFsm(FSM_MSG_AUTH_FINISH, authSeq, NULL, 0);
}

int32_t AuthSessionHandleAuthError(int64_t authSeq, int32_t reason)
{
    return PostMessageToAuthFsm(FSM_MSG_AUTH_ERROR, authSeq, (uint8_t *)&reason, sizeof(reason));
}

int32_t AuthSessionProcessDevInfoData(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    if (data == NULL) {
        AUTH_LOGE(AUTH_FSM, "data is null");
        return SOFTBUS_INVALID_PARAM;
    }
    return PostMessageToAuthFsm(FSM_MSG_RECV_DEVICE_INFO, authSeq, data, len);
}

int32_t AuthSessionProcessCloseAck(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    if (data == NULL) {
        AUTH_LOGE(AUTH_FSM, "data is null");
        return SOFTBUS_INVALID_PARAM;
    }
    return PostMessageToAuthFsm(FSM_MSG_RECV_CLOSE_ACK, authSeq, data, len);
}

int32_t AuthSessionProcessDevInfoDataByConnId(uint64_t connId, bool isServer, const uint8_t *data,
    uint32_t len)
{
    if (data == NULL) {
        AUTH_LOGE(AUTH_FSM, "data is null");
        return SOFTBUS_INVALID_PARAM;
    }
    return PostMessageToAuthFsmByConnId(FSM_MSG_RECV_DEVICE_INFO, connId, isServer, data, len);
}

int32_t AuthSessionProcessCloseAckByConnId(uint64_t connId, bool isServer, const uint8_t *data,
    uint32_t len)
{
    if (data == NULL) {
        AUTH_LOGE(AUTH_FSM, "data is null");
        return SOFTBUS_INVALID_PARAM;
    }
    return PostMessageToAuthFsmByConnId(FSM_MSG_RECV_CLOSE_ACK, connId, isServer, data, len);
}

int32_t AuthSessionHandleDeviceNotTrusted(const char *udid)
{
    if (udid == NULL || udid[0] == '\0') {
        AUTH_LOGE(AUTH_FSM, "invalid udid");
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
            AUTH_LOGE(AUTH_FSM, "auth fsm has dead. authSeq=%{public}" PRId64 "", item->authSeq);
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
            AUTH_LOGE(AUTH_FSM, "auth fsm has dead. authSeq=%{public}" PRId64 "", item->authSeq);
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
