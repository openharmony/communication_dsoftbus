/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "auth_attest_interface.h"
#include "auth_connection.h"
#include "auth_device_common_key.h"
#include "auth_hichain.h"
#include "auth_log.h"
#include "auth_manager.h"
#include "auth_normalize_request.h"
#include "auth_request.h"
#include "auth_session_json.h"
#include "auth_session_message.h"
#include "auth_tcp_connection.h"
#include "bus_center_manager.h"
#include "legacy/softbus_adapter_hitrace.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_event.h"
#include "lnn_feature_capability.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"

#define AUTH_TIMEOUT_MS            (10 * 1000)
#define TO_AUTH_FSM(ptr)           CONTAINER_OF(ptr, AuthFsm, fsm)
#define SHORT_UDID_HASH_LEN        8
#define HICHAIN_RETURN_NOT_TRUSTED (-425919748)

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
    FSM_MSG_DEVICE_POST_DEVICEID,
    FSM_MSG_STOP_AUTH_FSM,
    FSM_MSG_UNKNOWN,
} StateMessageType;
typedef struct {
    StateMessageType type;
    char *msg;
} StateMsgMap;

static const StateMsgMap g_StateMsgMap[] = {
    { FSM_MSG_RECV_DEVICE_ID,       (char *)"RECV_DEVICE_ID"       },
    { FSM_MSG_RECV_AUTH_DATA,       (char *)"RECV_AUTH_DATA"       },
    { FSM_MSG_SAVE_SESSION_KEY,     (char *)"SAVE_SESSION_KEY"     },
    { FSM_MSG_AUTH_ERROR,           (char *)"AUTH_ERROR"           },
    { FSM_MSG_RECV_DEVICE_INFO,     (char *)"RECV_DEVICE_INFO"     },
    { FSM_MSG_RECV_CLOSE_ACK,       (char *)"RECV_CLOSE_ACK"       },
    { FSM_MSG_AUTH_FINISH,          (char *)"AUTH_FINISH"          },
    { FSM_MSG_AUTH_TIMEOUT,         (char *)"AUTH_TIMEOUT"         },
    { FSM_MSG_DEVICE_NOT_TRUSTED,   (char *)"DEVICE_NOT_TRUSTED"   },
    { FSM_MSG_DEVICE_DISCONNECTED,  (char *)"DEVICE_DISCONNECTED"  },
    { FSM_MSG_DEVICE_POST_DEVICEID, (char *)"DEVICE_POST_DEVICEID" },
    { FSM_MSG_STOP_AUTH_FSM,        (char *)"STOP_AUTH_FSM"        },
    { FSM_MSG_UNKNOWN,              (char *)"UNKNOWN MSG!!"        },
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

typedef struct {
    char localIp[IP_LEN];
    char localBrMac[MAC_LEN];
    char localBleMac[MAC_LEN];
    char localUdid[UDID_BUF_LEN];
    char localNetworkId[NETWORK_ID_BUF_LEN];
    char localDevName[DEVICE_NAME_BUF_LEN];
} AuditReportDevInfo;

static ListNode g_authFsmList = { &g_authFsmList, &g_authFsmList };

static void SyncNegotiationEnter(FsmStateMachine *fsm);
static bool SyncNegotiationStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para);
static void SyncDevIdStateEnter(FsmStateMachine *fsm);
static bool SyncDevIdStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para);
static void DeviceAuthStateEnter(FsmStateMachine *fsm);
static bool DeviceAuthStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para);
static bool SyncDevInfoStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para);
static void AuthFsmDeinitCallback(FsmStateMachine *fsm);

static FsmState g_states[STATE_NUM_MAX] = {
    [STATE_SYNC_NEGOTIATION] = {
        .enter = SyncNegotiationEnter,
        .process = SyncNegotiationStateProcess,
        .exit = NULL,
    },
    [STATE_SYNC_DEVICE_ID] = {
        .enter = SyncDevIdStateEnter,
        .process = SyncDevIdStateProcess,
        .exit = NULL,
    },
    [STATE_DEVICE_AUTH] = {
        .enter = DeviceAuthStateEnter,
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
    if (type < FSM_MSG_RECV_DEVICE_ID || type >= FSM_MSG_UNKNOWN) {
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
    if ((msgType != FSM_MSG_AUTH_TIMEOUT && msgType != FSM_MSG_DEVICE_NOT_TRUSTED &&
            msgType != FSM_MSG_DEVICE_DISCONNECTED && msgType != FSM_MSG_STOP_AUTH_FSM) &&
        para == NULL) {
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
    if (isServer) {
        AUTH_LOGD(AUTH_FSM, "is not client");
        return;
    }
    AuthRequest request;
    (void)memset_s(&request, sizeof(request), 0, sizeof(request));
    if (GetAuthRequestNoLock(requestId, &request) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "get auth request fail");
        return;
    }
    switch (connInfo->type) {
        case AUTH_LINK_TYPE_BR:
        case AUTH_LINK_TYPE_SESSION:
            break;
        case AUTH_LINK_TYPE_WIFI:
            (void)memcpy_s(connInfo->info.ipInfo.deviceIdHash, UDID_HASH_LEN, request.connInfo.info.ipInfo.deviceIdHash,
                UDID_HASH_LEN);
            break;
        case AUTH_LINK_TYPE_BLE:
            (void)memcpy_s(connInfo->info.bleInfo.deviceIdHash, UDID_HASH_LEN,
                request.connInfo.info.bleInfo.deviceIdHash, UDID_HASH_LEN);
            break;
        case AUTH_LINK_TYPE_P2P:
        case AUTH_LINK_TYPE_ENHANCED_P2P:
            if (strcpy_s(connInfo->info.ipInfo.udid, UDID_BUF_LEN, request.connInfo.info.ipInfo.udid) != EOK) {
                AUTH_LOGE(AUTH_FSM, "strcpy udid fail");
                return;
            }
            break;
        default:
            AUTH_LOGE(AUTH_FSM, "error type");
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
            return SOFTBUS_AUTH_NOT_FOUND;
        }
        char udidHash[SHORT_UDID_HASH_HEX_LEN + 1] = { 0 };
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

static int32_t FillSessionInfoModule(uint32_t requestId, AuthSessionInfo *info)
{
    if (!info->isServer) {
        AuthRequest request;
        (void)memset_s(&request, sizeof(request), 0, sizeof(request));
        int32_t ret = GetAuthRequestNoLock(requestId, &request);
        if (ret != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_FSM, "get auth request fail");
            return ret;
        }
        info->module = request.module;
    }
    return SOFTBUS_OK;
}

static AuthFsm *CreateAuthFsm(
    int64_t authSeq, uint32_t requestId, uint64_t connId, const AuthConnInfo *connInfo, bool isServer)
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
    authFsm->info.isConnectServer = isServer;
    authFsm->info.connId = connId;
    authFsm->info.connInfo = *connInfo;
    authFsm->info.version = SOFTBUS_NEW_V2;
    authFsm->info.idType = EXCHANGE_UDID;
    if (FillSessionInfoModule(requestId, &authFsm->info) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "fill module fail");
        SoftBusFree(authFsm);
        return NULL;
    }
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
        "create auth fsm. authSeq=%{public}" PRId64 ", name=%{public}s, side=%{public}s, requestId=%{public}u, "
        "" CONN_INFO,
        authFsm->authSeq, authFsm->fsmName, GetAuthSideStr(isServer), requestId, CONN_DATA(connId));
    return authFsm;
}

static void DestroyAuthFsm(AuthFsm *authFsm)
{
    AUTH_LOGI(AUTH_FSM, "destroy auth. authSeq=%{public}" PRId64 ", side=%{public}s, requestId=%{public}u",
        authFsm->authSeq, GetAuthSideStr(authFsm->info.isServer), authFsm->info.requestId);
    ListDelete(&authFsm->node);
    if (authFsm->info.deviceInfoData != NULL) {
        SoftBusFree(authFsm->info.deviceInfoData);
        authFsm->info.deviceInfoData = NULL;
    }
    if (authFsm->info.normalizedKey != NULL) {
        SoftBusFree(authFsm->info.normalizedKey);
        authFsm->info.normalizedKey = NULL;
    }
    SoftBusFree(authFsm);
}

static void AuthFsmDeinitCallback(FsmStateMachine *fsm)
{
    static uint32_t callCount = 0;
    AUTH_LOGI(AUTH_FSM, "auth fsm deinit callback enter, callCount=%{public}u", callCount++);
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
        extra.authRequestId = (int32_t)authFsm->info.requestId;
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
    authFsm->statisticData.endAuthTime = (uint64_t)LnnUpTimeMs();
    uint64_t costTime = authFsm->statisticData.endAuthTime - authFsm->statisticData.startAuthTime;
    DfxRecordLnnAuthEnd(authFsm, costTime, result);
    AuthFailStage stage = AUTH_STAGE_BUTT;

    if (result == SOFTBUS_OK) {
        if (SoftBusRecordAuthResult(linkType, SOFTBUS_OK, costTime, AUTH_STAGE_BUTT) != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_FSM, "report static auth result fail");
        }
        return;
    } else if (result == SOFTBUS_AUTH_SYNC_DEVID_FAIL || result == SOFTBUS_AUTH_SYNC_DEVINFO_FAIL ||
        result == SOFTBUS_AUTH_UNPACK_DEVINFO_FAIL || result == SOFTBUS_AUTH_SEND_FAIL ||
        result == SOFTBUS_AUTH_NOT_SUPPORT_THREE_STATE) {
        stage = AUTH_EXCHANGE_STAGE;
    } else if (result == SOFTBUS_AUTH_DEVICE_DISCONNECTED) {
        stage = AUTH_CONNECT_STAGE;
    } else if (result == SOFTBUS_AUTH_HICHAIN_PROCESS_FAIL || result == SOFTBUS_AUTH_TIMEOUT ||
        result == SOFTBUS_AUTH_HICHAIN_NOT_TRUSTED) {
        stage = AUTH_VERIFY_STAGE;
    } else if (result >= SOFTBUS_HICHAIN_MIN && result <= SOFTBUS_HICHAIN_MAX) {
        stage = AUTH_VERIFY_STAGE;
    } else {
        AUTH_LOGE(AUTH_FSM, "unsupport result=%{public}d.", result);
        return;
    }

    if (SoftBusRecordAuthResult(linkType, result, costTime, stage) != SOFTBUS_OK) {
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

static void SaveDeviceKey(AuthFsm *authFsm, int32_t keyType, AuthLinkType type)
{
    AuthDeviceKeyInfo deviceKey;
    SessionKey sessionKey;
    (void)memset_s(&deviceKey, sizeof(AuthDeviceKeyInfo), 0, sizeof(AuthDeviceKeyInfo));
    (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
    if (AuthManagerGetSessionKey(authFsm->authSeq, &authFsm->info, &sessionKey) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "get session key fail");
        return;
    }
    if (memcpy_s(deviceKey.deviceKey, sizeof(deviceKey.deviceKey), sessionKey.value, sizeof(sessionKey.value)) != EOK) {
        AUTH_LOGE(AUTH_FSM, "session key cpy fail");
        (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
        return;
    }
    deviceKey.keyLen = sessionKey.len;
    deviceKey.keyIndex = authFsm->authSeq;
    deviceKey.keyType = keyType;
    deviceKey.isServerSide = authFsm->info.isServer;
    if (AuthInsertDeviceKey(&authFsm->info.nodeInfo, &deviceKey, type) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "insert deviceKey fail");
    }
    (void)memset_s(&deviceKey, sizeof(AuthDeviceKeyInfo), 0, sizeof(AuthDeviceKeyInfo));
    (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
}

static AuthFsm *GetAuthFsmByConnInfo(const AuthConnInfo *connInfo, bool isServer)
{
    AuthFsm *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_authFsmList, AuthFsm, node) {
        if (!CompareConnInfo(&item->info.connInfo, connInfo, true) || item->info.isConnectServer != isServer) {
            continue;
        }
        if (item->isDead) {
            AUTH_LOGE(AUTH_FSM, "auth fsm has dead. authSeq=%{public}" PRId64 "", item->authSeq);
            break;
        }
        return item;
    }
    return NULL;
}

static void ProcessTimeoutErrorCode(AuthFsm *authFsm, int32_t *result)
{
    AuthFsmStateIndex curState = authFsm->curState;
    if (curState == STATE_SYNC_NEGOTIATION || curState == STATE_SYNC_DEVICE_ID) {
        *result = SOFTBUS_AUTH_SYNC_DEVICEID_TIMEOUT;
    } else if (curState == STATE_DEVICE_AUTH) {
        *result = (authFsm->info.normalizedType == NORMALIZED_SUPPORT || authFsm->info.isSupportFastAuth) ?
            SOFTBUS_AUTH_SAVE_SESSIONKEY_TIMEOUT : SOFTBUS_AUTH_HICHAIN_TIMEOUT;
    } else if (curState == STATE_SYNC_DEVICE_INFO) {
        *result = SOFTBUS_AUTH_SYNC_DEVICEINFO_TIMEOUT;
    } else {
        AUTH_LOGE(AUTH_FSM, "authFsm state error, curState=%{public}d", curState);
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
        if (authFsm->info.normalizedType == NORMALIZED_KEY_ERROR) {
            AUTH_LOGI(AUTH_FSM, "only hichain verify, save the device key");
            SaveDeviceKey(authFsm, AUTH_LINK_TYPE_NORMALIZED, authFsm->info.connInfo.type);
        } else if ((authFsm->info.normalizedType == NORMALIZED_NOT_SUPPORT) &&
            (authFsm->info.connInfo.type == AUTH_LINK_TYPE_BLE) && !authFsm->info.isSupportFastAuth) {
            AUTH_LOGI(AUTH_FSM, "save device key for fast auth");
            SaveDeviceKey(authFsm, AUTH_LINK_TYPE_BLE, AUTH_LINK_TYPE_BLE);
        }
        if (!authFsm->info.isServer) {
            NotifyNormalizeRequestSuccess(authFsm->authSeq, true);
        }
        // Disconnect another request and notify auth success
        if (authFsm->info.isConnectServer && authFsm->info.peerState != AUTH_STATE_COMPATIBLE) {
            AuthFsm *stopFsm = GetAuthFsmByConnInfo(&authFsm->info.connInfo, !authFsm->info.isConnectServer);
            if (stopFsm != NULL) {
                AuthNotifyAuthPassed(stopFsm->authSeq, &stopFsm->info);
                LnnFsmPostMessage(&stopFsm->fsm, FSM_MSG_STOP_AUTH_FSM, NULL);
            }
        }
    } else {
        if (result == SOFTBUS_AUTH_TIMEOUT) {
            ProcessTimeoutErrorCode(authFsm, &result);
        }
        LnnFsmRemoveMessage(&authFsm->fsm, FSM_MSG_AUTH_TIMEOUT);
        if (!authFsm->info.isServer) {
            NotifyNormalizeRequestFail(authFsm->authSeq, result);
        }
        AuthManagerSetAuthFailed(authFsm->authSeq, &authFsm->info, result);
    }

    authFsm->isDead = true;
    LnnFsmStop(&authFsm->fsm);
    LnnFsmDeinit(&authFsm->fsm);
    SoftbusHitraceStop();
}

static void StopAuthFsm(AuthFsm *authFsm)
{
    authFsm->isDead = true;
    LnnFsmStop(&authFsm->fsm);
    LnnFsmDeinit(&authFsm->fsm);
}

static void HandleCommonMsg(AuthFsm *authFsm, int32_t msgType, MessagePara *msgPara)
{
    (void)msgPara;
    switch (msgType) {
        case FSM_MSG_AUTH_TIMEOUT:
            AUTH_LOGE(AUTH_FSM, "auth fsm timeout. authSeq=%{public}" PRId64 "", authFsm->authSeq);
            CompleteAuthSession(authFsm, SOFTBUS_AUTH_TIMEOUT);
            HichainCancelRequest(authFsm->authSeq);
            break;
        case FSM_MSG_DEVICE_NOT_TRUSTED:
            CompleteAuthSession(authFsm, SOFTBUS_AUTH_HICHAIN_NOT_TRUSTED);
            HichainCancelRequest(authFsm->authSeq);
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
        case FSM_MSG_STOP_AUTH_FSM:
            StopAuthFsm(authFsm);
            break;
        default:
            AUTH_LOGE(AUTH_FSM, "auth fsm cannot handle msgType. authSeq=%{public}" PRId64 ", msgType=%{public}d",
                authFsm->authSeq, msgType);
            break;
    }
}

static uint32_t AddConcurrentAuthRequest(AuthFsm *authFsm)
{
    uint32_t num = 0;
    if (strlen(authFsm->info.udidHash) == 0) {
        AUTH_LOGE(AUTH_FSM, "udidHash is null, authSeq=%{public}" PRId64, authFsm->authSeq);
        return num;
    }
    NormalizeRequest normalizeRequest = { .authSeq = authFsm->authSeq,
        .connInfo = authFsm->info.connInfo,
        .isConnectServer = authFsm->info.isConnectServer };
    if (strcpy_s(normalizeRequest.udidHash, sizeof(normalizeRequest.udidHash), authFsm->info.udidHash) != EOK) {
        AUTH_LOGE(AUTH_FSM, "strcpy udid hash fail. authSeq=%{public}" PRId64, authFsm->authSeq);
        return num;
    }
    num = AddNormalizeRequest(&normalizeRequest);
    char *anonyUdidHash = NULL;
    Anonymize(normalizeRequest.udidHash, &anonyUdidHash);
    AUTH_LOGI(AUTH_CONN, "add normalize queue, num=%{public}d, udidHash=%{public}s",
        num, AnonymizeWrapper(anonyUdidHash));
    AnonymizeFree(anonyUdidHash);
    return num;
}

static void SyncNegotiationEnter(FsmStateMachine *fsm)
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
    authFsm->curState = STATE_SYNC_NEGOTIATION;
    AUTH_LOGI(AUTH_FSM, "SyncNegotiationState: auth fsm enter. authSeq=%{public}" PRId64, authFsm->authSeq);
    if (!authFsm->info.isServer) {
        if (PostDeviceIdMessage(authFsm->authSeq, &authFsm->info) != SOFTBUS_OK) {
            CompleteAuthSession(authFsm, SOFTBUS_AUTH_SYNC_DEVID_FAIL);
        }
    }
}

static void HandleMsgPostDeviceId(AuthFsm *authFsm, const MessagePara *para)
{
    (void)para;
    AuthSessionInfo *info = &authFsm->info;
    if (PostDeviceIdMessage(authFsm->authSeq, info) != SOFTBUS_OK) {
        CompleteAuthSession(authFsm, SOFTBUS_AUTH_SYNC_DEVID_FAIL);
        return;
    }
    if (info->isServer) {
        LnnFsmTransactState(&authFsm->fsm, g_states + STATE_DEVICE_AUTH);
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
    authFsm->curState = STATE_SYNC_DEVICE_ID;
    SoftbusHitraceStart(SOFTBUS_HITRACE_ID_VALID, (uint64_t)authFsm->authSeq);
    AUTH_LOGI(AUTH_FSM, "SyncDevIdState: auth fsm enter. authSeq=%{public}" PRId64 "", authFsm->authSeq);
    if (!authFsm->info.isServer) {
        if (authFsm->info.localState == AUTH_STATE_START) {
            if (!AuthIsRepeatedAuthRequest(authFsm->authSeq) && AddConcurrentAuthRequest(authFsm) > 1) {
                AUTH_LOGI(AUTH_FSM, "wait another auth, authSeq=%{public}" PRId64 "", authFsm->authSeq);
                return;
            }
        }
        if (PostDeviceIdMessage(authFsm->authSeq, &authFsm->info) != SOFTBUS_OK) {
            CompleteAuthSession(authFsm, SOFTBUS_AUTH_SYNC_DEVID_FAIL);
        }
    }
    SoftbusHitraceStop();
}

static void SaveLastAuthSeq(const unsigned char *udidHash, int64_t authSeq)
{
    AUTH_LOGI(AUTH_FSM, "save auth seq.authSeq=%{public}" PRId64, authSeq);
    char hashStr[SHORT_UDID_HASH_HEX_LEN + 1] = { 0 };
    if (ConvertBytesToHexString(
        hashStr, SHORT_UDID_HASH_HEX_LEN + 1, udidHash, SHORT_UDID_HASH_HEX_LEN / HEXIFY_UNIT_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "convert udidhash to hexstr fail.");
        return;
    }
    NodeInfo deviceInfo;
    (void)memset_s(&deviceInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnRetrieveDeviceInfo(hashStr, &deviceInfo) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "no this device info.");
        return;
    }
    deviceInfo.lastAuthSeq = authSeq;
    if (LnnSaveRemoteDeviceInfo(&deviceInfo) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "save device info fail.");
    }
}

static int32_t RecoveryNormalizedDeviceKey(AuthFsm *authFsm)
{
    if (authFsm->info.normalizedKey == NULL) {
        AUTH_LOGE(AUTH_FSM, "normalizedKey is NULL, auth fail");
        return SOFTBUS_INVALID_PARAM;
    }
    uint8_t hash[SHA_256_HASH_LEN] = { 0 };
    int32_t ret = SoftBusGenerateStrHash((uint8_t *)authFsm->info.udid, strlen(authFsm->info.udid), hash);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "generate udidHash fail");
        return ret;
    }
    char udidShortHash[SHORT_UDID_HASH_HEX_LEN + 1] = { 0 };
    if (ConvertBytesToUpperCaseHexString(udidShortHash, SHORT_UDID_HASH_HEX_LEN + 1, hash, SHORT_UDID_HASH_LEN) !=
        SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "convert bytes to string fail");
        return SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR;
    }
    AuthUpdateNormalizeKeyIndex(udidShortHash, authFsm->info.normalizedIndex, authFsm->info.connInfo.type,
        authFsm->info.normalizedKey, authFsm->info.isServer);
    if (authFsm->info.connInfo.type == AUTH_LINK_TYPE_BLE) {
        SaveLastAuthSeq(hash, authFsm->authSeq);
    }
    ret = AuthSessionSaveSessionKey(
        authFsm->authSeq, authFsm->info.normalizedKey->value, authFsm->info.normalizedKey->len);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "post save sessionKey event fail");
        return ret;
    }
    return AuthSessionHandleAuthFinish(authFsm->authSeq);
}

static int32_t RecoveryFastAuthKey(AuthFsm *authFsm)
{
    AuthDeviceKeyInfo key = { 0 };
    uint8_t hash[SHA_256_HASH_LEN] = { 0 };
    int32_t ret = SoftBusGenerateStrHash((uint8_t *)authFsm->info.udid, strlen(authFsm->info.udid), hash);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "generate udidHash fail");
        return ret;
    }
    char udidShortHash[SHORT_UDID_HASH_HEX_LEN + 1] = { 0 };
    if (ConvertBytesToUpperCaseHexString(udidShortHash, SHORT_UDID_HASH_HEX_LEN + 1, hash, SHORT_UDID_HASH_LEN) !=
        SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "convert bytes to string fail");
        return SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR;
    }
    AuthLinkType linkType = authFsm->info.connInfo.type;
    if (authFsm->info.connInfo.type == AUTH_LINK_TYPE_ENHANCED_P2P) {
        // enhanced p2p reuse ble authKey
        linkType = AUTH_LINK_TYPE_BLE;
    }
    if (AuthFindDeviceKey(udidShortHash, linkType, &key) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "find key fail, fastAuth error");
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    AuthUpdateKeyIndex(udidShortHash, authFsm->info.connInfo.type, authFsm->authSeq, authFsm->info.isServer);
    authFsm->info.oldIndex = key.keyIndex;
    ret = AuthSessionSaveSessionKey(authFsm->authSeq, key.deviceKey, key.keyLen);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "post save sessionKey event");
        (void)memset_s(&key, sizeof(AuthDeviceKeyInfo), 0, sizeof(AuthDeviceKeyInfo));
        return ret;
    }
    (void)memset_s(&key, sizeof(AuthDeviceKeyInfo), 0, sizeof(AuthDeviceKeyInfo));
    return AuthSessionHandleAuthFinish(authFsm->authSeq);
}

static void AuditReportSetPeerDevInfo(LnnAuditExtra *lnnAuditExtra, AuthSessionInfo *info)
{
    if (lnnAuditExtra == NULL || info == NULL) {
        AUTH_LOGE(AUTH_FSM, "lnnAuditExtra or info is null");
        return;
    }
    char *anonyBrMac = NULL;
    char *anonyBleMac = NULL;
    char *anonyIp = NULL;
    switch (info->connInfo.type) {
        case AUTH_LINK_TYPE_BR:
            Anonymize(info->connInfo.info.brInfo.brMac, &anonyBrMac);
            if (strcpy_s((char *)lnnAuditExtra->peerBrMac, BT_MAC_LEN, AnonymizeWrapper(anonyBrMac)) != EOK) {
                AUTH_LOGE(AUTH_FSM, "BR MAC COPY ERROR");
            }
            AnonymizeFree(anonyBrMac);
            break;
        case AUTH_LINK_TYPE_BLE:
            Anonymize(info->connInfo.info.bleInfo.bleMac, &anonyBleMac);
            if (strcpy_s((char *)lnnAuditExtra->peerBleMac, BT_MAC_LEN, AnonymizeWrapper(anonyBleMac)) != EOK) {
                AUTH_LOGE(AUTH_FSM, "BLE MAC COPY ERROR");
            }
            AnonymizeFree(anonyBleMac);
            break;
        case AUTH_LINK_TYPE_WIFI:
        case AUTH_LINK_TYPE_P2P:
        case AUTH_LINK_TYPE_ENHANCED_P2P:
            Anonymize(info->connInfo.info.ipInfo.ip, &anonyIp);
            if (strcpy_s((char *)lnnAuditExtra->peerIp, IP_STR_MAX_LEN, AnonymizeWrapper(anonyIp)) != EOK) {
                AUTH_LOGE(AUTH_FSM, "IP COPY ERROR");
            }
            AnonymizeFree(anonyIp);
            lnnAuditExtra->peerAuthPort = info->connInfo.info.ipInfo.port;
            break;
        default:
            AUTH_LOGW(AUTH_FSM, "unknow param type!");
            break;
    }
}

static void GetLocalDevReportInfo(AuditReportDevInfo *reportInfo, LnnAuditExtra *lnnAuditExtra)
{
    (void)LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, reportInfo->localIp, IP_LEN);
    char *anonyLocalIp = NULL;
    Anonymize(reportInfo->localIp, &anonyLocalIp);
    if (strcpy_s((char *)lnnAuditExtra->localIp, IP_LEN, AnonymizeWrapper(anonyLocalIp)) != EOK) {
        AUTH_LOGE(AUTH_FSM, "LOCAL IP COPY ERROR");
    }
    AnonymizeFree(anonyLocalIp);

    (void)LnnGetLocalStrInfo(STRING_KEY_BT_MAC, reportInfo->localBrMac, MAC_LEN);
    char *anonyLocalBrMac = NULL;
    Anonymize(reportInfo->localBrMac, &anonyLocalBrMac);
    if (strcpy_s((char *)lnnAuditExtra->localBrMac, MAC_LEN, AnonymizeWrapper(anonyLocalBrMac)) != EOK) {
        AUTH_LOGE(AUTH_FSM, "LOCAL BR MAC COPY ERROR");
    }
    AnonymizeFree(anonyLocalBrMac);

    (void)LnnGetLocalStrInfo(STRING_KEY_BLE_MAC, reportInfo->localBleMac, MAC_LEN);
    char *anonyLocalBleMac = NULL;
    Anonymize(reportInfo->localBleMac, &anonyLocalBleMac);
    if (strcpy_s((char *)lnnAuditExtra->localBleMac, MAC_LEN, AnonymizeWrapper(anonyLocalBleMac)) != EOK) {
        AUTH_LOGE(AUTH_FSM, "LOCAL BLE MAC COPY ERROR");
    }
    AnonymizeFree(anonyLocalBleMac);

    (void)LnnGetLocalStrInfo(STRING_KEY_NETWORKID, reportInfo->localNetworkId, NETWORK_ID_BUF_LEN);
    char *anonyLocalNetworkId = NULL;
    Anonymize(reportInfo->localNetworkId, &anonyLocalNetworkId);
    if (strcpy_s((char *)lnnAuditExtra->localNetworkId, NETWORK_ID_BUF_LEN, AnonymizeWrapper(anonyLocalNetworkId)) !=
        EOK) {
        AUTH_LOGE(AUTH_FSM, "LOCAL NETWORKID COPY ERROR");
    }
    AnonymizeFree(anonyLocalNetworkId);

    (void)LnnGetLocalStrInfo(STRING_KEY_DEV_NAME, reportInfo->localDevName, DEVICE_NAME_BUF_LEN);
    char *anonyLocalDevName = NULL;
    Anonymize(reportInfo->localDevName, &anonyLocalDevName);
    if (strcpy_s((char *)lnnAuditExtra->localDevName, DEVICE_NAME_BUF_LEN, AnonymizeWrapper(anonyLocalDevName)) !=
        EOK) {
        AUTH_LOGE(AUTH_FSM, "LOCAL DEVICE NAME COPY ERROR");
    }
    AnonymizeFree(anonyLocalDevName);
}

static void AuditReportSetLocalDevInfo(LnnAuditExtra *lnnAuditExtra)
{
    if (lnnAuditExtra == NULL) {
        AUTH_LOGE(AUTH_FSM, "lnnAuditExtra is null");
        return;
    }
    AuditReportDevInfo reportInfo;
    (void)memset_s(&reportInfo, sizeof(AuditReportDevInfo), 0, sizeof(AuditReportDevInfo));
    GetLocalDevReportInfo(&reportInfo, lnnAuditExtra);
    (void)LnnGetLocalNumInfo(NUM_KEY_AUTH_PORT, &lnnAuditExtra->localAuthPort);
    (void)LnnGetLocalNumInfo(NUM_KEY_PROXY_PORT, &lnnAuditExtra->localProxyPort);
    (void)LnnGetLocalNumInfo(NUM_KEY_SESSION_PORT, &lnnAuditExtra->localSessionPort);
    (void)LnnGetLocalNumInfo(NUM_KEY_DEV_TYPE_ID, &lnnAuditExtra->localDevType);
    char udid[UDID_BUF_LEN] = { 0 };
    uint8_t udidHash[SHA_256_HASH_LEN] = { 0 };
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, udid, UUID_BUF_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "get local udid fail");
        return;
    }
    int32_t ret = SoftBusGenerateStrHash((const unsigned char *)udid, strlen(udid), udidHash);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "generate udid hash fail");
        return;
    }
    if (ConvertBytesToUpperCaseHexString(reportInfo.localUdid, SHA_256_HEX_HASH_LEN, udidHash, SHA_256_HASH_LEN) !=
        SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "convert hash to upper hex str fail");
    }
    char *anonyLocalUdid = NULL;
    Anonymize(reportInfo.localUdid, &anonyLocalUdid);
    if (strcpy_s((char *)lnnAuditExtra->localUdid, SHA_256_HEX_HASH_LEN, AnonymizeWrapper(anonyLocalUdid)) != EOK) {
        AUTH_LOGE(AUTH_FSM, "LOCAL UDID COPY ERROR");
    }
    AnonymizeFree(anonyLocalUdid);
}

static void BuildLnnAuditEvent(
    LnnAuditExtra *lnnAuditExtra, AuthSessionInfo *info, int32_t result, int32_t errCode, SoftbusAuditType auditType)
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
        info->idType = EXCHANGE_UDID;
        LnnFsmTransactState(&authFsm->fsm, g_states + STATE_SYNC_DEVICE_ID);
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    return SOFTBUS_OK;
}

static void UpdateUdidHashIfEmpty(AuthFsm *authFsm, AuthSessionInfo *info)
{
    if (info->connInfo.type == AUTH_LINK_TYPE_BLE && strlen(info->udid) != 0 &&
        authFsm->info.connInfo.info.bleInfo.deviceIdHash[0] == '\0') {
        char *anonyUdid = NULL;
        Anonymize(info->udid, &anonyUdid);
        AUTH_LOGW(AUTH_FSM, "udidhash is empty, udid=%{public}s", AnonymizeWrapper(anonyUdid));
        AnonymizeFree(anonyUdid);
        if (SoftBusGenerateStrHash((unsigned char *)info->udid, strlen(info->udid),
            (unsigned char *)authFsm->info.connInfo.info.bleInfo.deviceIdHash) != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_FSM, "generate udidhash fail");
        }
    }
}

static void HandleMsgRecvDeviceId(AuthFsm *authFsm, const MessagePara *para)
{
    int32_t ret = SOFTBUS_OK;
    AuthSessionInfo *info = &authFsm->info;
    do {
        if (ProcessDeviceIdMessage(info, para->data, para->len) != SOFTBUS_OK) {
            ret = SOFTBUS_AUTH_SYNC_DEVID_FAIL;
            LnnAuditExtra lnnAuditExtra = { 0 };
            BuildLnnAuditEvent(&lnnAuditExtra, info, AUDIT_HANDLE_MSG_FAIL_END_AUTH, ret, AUDIT_EVENT_PACKETS_ERROR);
            LNN_AUDIT(AUDIT_SCENE_HANDLE_MSG_DEV_ID, lnnAuditExtra);
            break;
        }
        UpdateUdidHashIfEmpty(authFsm, info);
        if (info->isServer) {
            if (PostDeviceIdMessage(authFsm->authSeq, info) != SOFTBUS_OK) {
                ret = SOFTBUS_AUTH_SYNC_DEVID_FAIL;
                break;
            }
        } else {
            if (info->normalizedType == NORMALIZED_NOT_SUPPORT || info->peerState == AUTH_STATE_COMPATIBLE) {
                NotifyNormalizeRequestSuccess(authFsm->authSeq, false);
            }
        }
        LnnFsmTransactState(&authFsm->fsm, g_states + STATE_DEVICE_AUTH);
    } while (false);

    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "handle devId msg fail, ret=%{public}d", ret);
        CompleteAuthSession(authFsm, ret);
    }
}

static void HandleMsgRecvDeviceIdNego(AuthFsm *authFsm, const MessagePara *para)
{
    int32_t ret = SOFTBUS_OK;
    AuthSessionInfo *info = &authFsm->info;
    do {
        if (ProcessDeviceIdMessage(info, para->data, para->len) != SOFTBUS_OK) {
            ret = SOFTBUS_AUTH_SYNC_DEVID_FAIL;
            LnnAuditExtra lnnAuditExtra = { 0 };
            BuildLnnAuditEvent(&lnnAuditExtra, info, AUDIT_HANDLE_MSG_FAIL_END_AUTH, ret, AUDIT_EVENT_PACKETS_ERROR);
            LNN_AUDIT(AUDIT_SCENE_HANDLE_MSG_DEV_ID, lnnAuditExtra);
            break;
        }
        UpdateUdidHashIfEmpty(authFsm, info);
        if (UpdateLocalAuthState(authFsm->authSeq, &authFsm->info) != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_FSM, "update auth state fail, authSeq=%{public}" PRId64, authFsm->authSeq);
            return;
        }
        if (info->peerState == AUTH_STATE_COMPATIBLE) {
            NotifyNormalizeRequestSuccess(authFsm->authSeq, false);
        }
        if (info->localState == AUTH_STATE_START) {
            info->isServer = false;
            LnnFsmTransactState(&authFsm->fsm, g_states + STATE_SYNC_DEVICE_ID);
        } else if (info->localState == AUTH_STATE_ACK) {
            info->isServer = true;
            ret = PostDeviceIdMessage(authFsm->authSeq, info);
            LnnFsmTransactState(&authFsm->fsm, g_states + STATE_DEVICE_AUTH);
        } else if (info->localState == AUTH_STATE_WAIT) {
            info->isServer = true;
            ret = PostDeviceIdMessage(authFsm->authSeq, info);
        } else if (info->localState == AUTH_STATE_COMPATIBLE) {
            if (info->isServer) {
                ret = PostDeviceIdMessage(authFsm->authSeq, info);
            }
            LnnFsmTransactState(&authFsm->fsm, g_states + STATE_DEVICE_AUTH);
        } else if (info->localState == AUTH_STATE_UNKNOW) {
            ret = PostDeviceIdMessage(authFsm->authSeq, info);
        } else {
            AUTH_LOGE(AUTH_FSM, "local auth state error");
            ret = SOFTBUS_AUTH_SYNC_DEVID_FAIL;
        }
    } while (false);

    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "handle devId msg fail, ret=%{public}d", ret);
        CompleteAuthSession(authFsm, ret);
    }
}

static bool SyncNegotiationStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    MessagePara *msgPara = (MessagePara *)para;
    AuthFsm *authFsm = TranslateToAuthFsm(fsm, msgType, msgPara);
    if (authFsm == NULL) {
        FreeMessagePara(msgPara);
        return false;
    }
    SoftbusHitraceStart(SOFTBUS_HITRACE_ID_VALID, (uint64_t)authFsm->authSeq);
    AUTH_LOGI(AUTH_FSM, "auth fsm process. authSeq=%{public}" PRId64 ", message=%{public}s", authFsm->authSeq,
        FsmMsgTypeToStr(msgType));
    switch (msgType) {
        case FSM_MSG_RECV_DEVICE_ID:
            HandleMsgRecvDeviceIdNego(authFsm, msgPara);
            break;
        case FSM_MSG_DEVICE_POST_DEVICEID:
            HandleMsgPostDeviceId(authFsm, msgPara);
            break;
        default:
            HandleCommonMsg(authFsm, msgType, msgPara);
            break;
    }
    FreeMessagePara(msgPara);
    SoftbusHitraceStop();
    return true;
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
    AUTH_LOGI(AUTH_FSM, "auth fsm process. authSeq=%{public}" PRId64 ", message=%{public}s", authFsm->authSeq,
        FsmMsgTypeToStr(msgType));
    switch (msgType) {
        case FSM_MSG_RECV_DEVICE_ID:
            HandleMsgRecvDeviceId(authFsm, msgPara);
            break;
        case FSM_MSG_DEVICE_POST_DEVICEID:
            HandleMsgPostDeviceId(authFsm, msgPara);
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
        LnnAuditExtra lnnAuditExtra = { 0 };
        BuildLnnAuditEvent(
            &lnnAuditExtra, &authFsm->info, AUDIT_HANDLE_MSG_FAIL_END_AUTH, ret, AUDIT_EVENT_PACKETS_ERROR);
        LNN_AUDIT(AUDIT_SCENE_HANDLE_MSG_AUTH_DATA, lnnAuditExtra);
        AUTH_LOGE(AUTH_FSM, "process hichain data fail");
        if (!authFsm->info.isAuthFinished) {
            CompleteAuthSession(authFsm, ret);
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
        case AUTH_LINK_TYPE_SESSION:
            return PostDeviceInfoMessage(authSeq, info);
        default:
            break;
    }
    return SOFTBUS_AUTH_CONN_TYPE_INVALID;
}

static void HandleMsgSaveSessionKey(AuthFsm *authFsm, const MessagePara *para)
{
    SessionKey sessionKey = { .len = para->len };
    if (memcpy_s(sessionKey.value, sizeof(sessionKey.value), para->data, para->len) != EOK) {
        AUTH_LOGE(AUTH_FSM, "copy session key fail.");
        (void)memset_s(&sessionKey, sizeof(sessionKey), 0, sizeof(sessionKey));
        return;
    }
    if (AuthManagerSetSessionKey(authFsm->authSeq, &authFsm->info, &sessionKey, true, false) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "auth fsm save session key fail. authSeq=%{public}" PRId64 "", authFsm->authSeq);
    }

    (void)CalcHKDF((uint8_t *)(&sessionKey.value), sessionKey.len, (uint8_t *)(&authFsm->info.sessionKeyRandomNum),
        sizeof(authFsm->info.sessionKeyRandomNum));
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
        (void)AuthSessionProcessDevInfoData(
            authFsm->authSeq, authFsm->info.deviceInfoData, authFsm->info.deviceInfoDataLen);
        SoftBusFree(authFsm->info.deviceInfoData);
        authFsm->info.deviceInfoData = NULL;
    }
    LnnFsmTransactState(&authFsm->fsm, g_states + STATE_SYNC_DEVICE_INFO);
    authFsm->curState = STATE_SYNC_DEVICE_INFO;
}

static void HandleMsgAuthError(AuthFsm *authFsm, const MessagePara *para)
{
    int32_t result = *((int32_t *)(para->data));
    AUTH_LOGE(AUTH_FSM, "auth fsm handle hichain error, authSeq=%{public}" PRId64 ", reason=%{public}d",
        authFsm->authSeq, result);
    if (result == HICHAIN_RETURN_NOT_TRUSTED) {
        AUTH_LOGE(AUTH_FSM, "device not has trust relation, begin to offline");
        AuthDeviceNotTrust(authFsm->info.udid);
    }
    CompleteAuthSession(authFsm, result);
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

static int32_t TryRecoveryKey(AuthFsm *authFsm)
{
    int32_t ret = SOFTBUS_OK;
    if (authFsm->info.normalizedType == NORMALIZED_SUPPORT) {
        AUTH_LOGI(AUTH_FSM, "normalized auth succ");
        if (RecoveryNormalizedDeviceKey(authFsm) != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_FSM, "normalized auth recovery device key fail");
            ret = SOFTBUS_AUTH_SYNC_DEVID_FAIL;
        }
        return ret;
    }
    if (authFsm->info.isSupportFastAuth) {
        AUTH_LOGI(AUTH_FSM, "fast auth succ");
        if (RecoveryFastAuthKey(authFsm) != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_FSM, "fast auth recovery device key fail");
            ret = SOFTBUS_AUTH_SYNC_DEVID_FAIL;
        }
    }
    return ret;
}

static int32_t ProcessClientAuthState(AuthFsm *authFsm)
{
    /* just client need start authDevice */
    if (ClientSetExchangeIdType(authFsm) != SOFTBUS_OK) {
        return SOFTBUS_OK;
    }
    char *anonyUdid = NULL;
    Anonymize(authFsm->info.udid, &anonyUdid);
    AUTH_LOGI(AUTH_FSM, "start auth send udid=%{public}s peerUserId=%{public}d", AnonymizeWrapper(anonyUdid),
        authFsm->info.userId);
    AnonymizeFree(anonyUdid);
    return HichainStartAuth(authFsm->authSeq, authFsm->info.udid, authFsm->info.connInfo.peerUid, authFsm->info.userId);
}

static void DeviceAuthStateEnter(FsmStateMachine *fsm)
{
    if (fsm == NULL) {
        AUTH_LOGE(AUTH_FSM, "fsm is null");
        return;
    }
    int32_t ret = SOFTBUS_OK;
    AuthFsm *authFsm = TO_AUTH_FSM(fsm);
    if (authFsm == NULL) {
        AUTH_LOGE(AUTH_FSM, "authFsm is null");
        return;
    }
    AUTH_LOGI(AUTH_FSM, "auth state enter, authSeq=%{public}" PRId64, authFsm->authSeq);
    authFsm->curState = STATE_DEVICE_AUTH;
    AuthSessionInfo *info = &authFsm->info;
    if (info->normalizedType == NORMALIZED_SUPPORT || info->isSupportFastAuth) {
        ret = TryRecoveryKey(authFsm);
        if (ret != SOFTBUS_OK) {
            goto ERR_EXIT;
        }
        return;
    }
    if (!info->isServer) {
        ret = ProcessClientAuthState(authFsm);
    }
    if (ret != SOFTBUS_OK) {
        goto ERR_EXIT;
    }
    return;
ERR_EXIT:
    AUTH_LOGE(AUTH_FSM, "auth state enter, fail ret=%{public}d", ret);
    CompleteAuthSession(authFsm, ret);
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
    AUTH_LOGI(AUTH_FSM, "auth fsm process. authSeq=%{public}" PRId64 ", message=%{public}s", authFsm->authSeq,
        FsmMsgTypeToStr(msgType));
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

static int32_t HandleCloseAckMessage(AuthFsm *authFsm, const AuthSessionInfo *info)
{
    if ((info->connInfo.type == AUTH_LINK_TYPE_BLE) && (SoftBusGetBrState() == BR_DISABLE) &&
        (info->nodeInfo.feature & 1 << BIT_SUPPORT_THREE_STATE) == 0) {
        AUTH_LOGE(AUTH_FSM, "peer not support three state");
        CompleteAuthSession(authFsm, SOFTBUS_AUTH_NOT_SUPPORT_THREE_STATE);
        return SOFTBUS_NETWORK_NOT_SUPPORT;
    }
    if (PostCloseAckMessage(authFsm->authSeq, info) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "post close ack fail");
        CompleteAuthSession(authFsm, SOFTBUS_AUTH_SEND_FAIL);
        return SOFTBUS_AUTH_SYNC_DEVINFO_ACK_FAIL;
    }
    return SOFTBUS_OK;
}

static void HandleMsgRecvDeviceInfo(AuthFsm *authFsm, const MessagePara *para)
{
    AuthSessionInfo *info = &authFsm->info;
    if (ProcessDeviceInfoMessage(authFsm->authSeq, info, para->data, para->len) != SOFTBUS_OK) {
        LnnAuditExtra lnnAuditExtra = { 0 };
        BuildLnnAuditEvent(&lnnAuditExtra, info, AUDIT_HANDLE_MSG_FAIL_END_AUTH, SOFTBUS_AUTH_UNPACK_DEVINFO_FAIL,
            AUDIT_EVENT_PACKETS_ERROR);
        LNN_AUDIT(AUDIT_SCENE_HANDLE_MSG_DEV_INFO, lnnAuditExtra);
        AUTH_LOGE(AUTH_FSM, "process device info msg fail");
        CompleteAuthSession(authFsm, SOFTBUS_AUTH_UNPACK_DEVINFO_FAIL);
        return;
    }
    info->isNodeInfoReceived = true;
    if (strcpy_s(info->nodeInfo.uuid, UUID_BUF_LEN, info->uuid) != EOK) {
        AUTH_LOGE(AUTH_FSM, "copy uuid fail.");
        return;
    }
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
    if (HandleCloseAckMessage(authFsm, info) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "handle close ack fail");
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

AuthFsm *GetAuthFsmByAuthSeq(int64_t authSeq)
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

AuthFsm *GetAuthFsmByConnId(uint64_t connId, bool isServer, bool isConnectSide)
{
    AuthFsm *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_authFsmList, AuthFsm, node) {
        if (isConnectSide && (item->info.connId != connId || item->info.isConnectServer != isServer)) {
            continue;
        }
        if (!isConnectSide && (item->info.connId != connId || item->info.isServer != isServer)) {
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

static int32_t PostMessageToAuthFsmByConnId(
    int32_t msgType, uint64_t connId, bool isServer, const uint8_t *data, uint32_t len)
{
    MessagePara *para = NewMessagePara(data, len);
    if (para == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    if (!RequireAuthLock()) {
        SoftBusFree(para);
        return SOFTBUS_LOCK_ERR;
    }
    AuthFsm *authFsm = GetAuthFsmByConnId(connId, isServer, false);
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
    authFsm->statisticData.startAuthTime = (uint64_t)LnnUpTimeMs();
}

static bool IsPeerSupportNegoAuth(AuthSessionInfo *info)
{
    char udidHash[SHORT_UDID_HASH_HEX_LEN + 1] = { 0 };
    if (!GetUdidShortHash(info, udidHash, SHORT_UDID_HASH_HEX_LEN + 1)) {
        return true;
    }
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(nodeInfo), 0, sizeof(nodeInfo));
    if (LnnRetrieveDeviceInfo((const char *)udidHash, &nodeInfo) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "retrive deviceInfo fail");
        return true;
    }
    if (IsSupportFeatureByCapaBit(nodeInfo.authCapacity, BIT_SUPPORT_NEGOTIATION_AUTH)) {
        return true;
    }
    return false;
}

static int32_t GetFirstFsmState(AuthSessionInfo *info, int64_t authSeq, AuthFsmStateIndex *state)
{
    CHECK_NULL_PTR_RETURN_VALUE(info, SOFTBUS_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(state, SOFTBUS_INVALID_PARAM);
    if (info->isConnectServer) {
        *state = STATE_SYNC_NEGOTIATION;
    } else {
        if (!IsPeerSupportNegoAuth(info)) {
            info->localState = AUTH_STATE_COMPATIBLE;
            AUTH_LOGI(AUTH_FSM, "peer not support nego, localState change, authSeq=%{public}" PRId64, authSeq);
        }
        if (info->localState == AUTH_STATE_START || info->localState == AUTH_STATE_COMPATIBLE) {
            *state = STATE_SYNC_DEVICE_ID;
        } else {
            *state = STATE_SYNC_NEGOTIATION;
        }
    }
    return SOFTBUS_OK;
}

int32_t AuthSessionStartAuth(const AuthParam *authParam, const AuthConnInfo *connInfo)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(connInfo != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "connInfo is NULL");
    AUTH_CHECK_AND_RETURN_RET_LOGE(authParam != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "authParam is NULL");
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    AuthFsm *authFsm =
        CreateAuthFsm(authParam->authSeq, authParam->requestId, authParam->connId, connInfo, authParam->isServer);
    if (authFsm == NULL) {
        ReleaseAuthLock();
        return SOFTBUS_MEM_ERR;
    }
    authFsm->info.isNeedFastAuth = authParam->isFastAuth;
    (void)UpdateLocalAuthState(authFsm->authSeq, &authFsm->info);
    AuthFsmStateIndex nextState = STATE_SYNC_DEVICE_ID;
    if (GetFirstFsmState(&authFsm->info, authFsm->authSeq, &nextState) != SOFTBUS_OK ||
        LnnFsmStart(&authFsm->fsm, g_states + nextState) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "start auth fsm fail. authSeq=%{public}" PRId64 "", authFsm->authSeq);
        DestroyAuthFsm(authFsm);
        ReleaseAuthLock();
        return SOFTBUS_AUTH_START_FSM_FAIL;
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
    AuthSessionInfo info = { 0 };
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

int32_t AuthSessionProcessDevInfoDataByConnId(uint64_t connId, bool isServer, const uint8_t *data, uint32_t len)
{
    if (data == NULL) {
        AUTH_LOGE(AUTH_FSM, "data is null");
        return SOFTBUS_INVALID_PARAM;
    }
    return PostMessageToAuthFsmByConnId(FSM_MSG_RECV_DEVICE_INFO, connId, isServer, data, len);
}

int32_t AuthSessionProcessCloseAckByConnId(uint64_t connId, bool isServer, const uint8_t *data, uint32_t len)
{
    if (data == NULL) {
        AUTH_LOGE(AUTH_FSM, "data is null");
        return SOFTBUS_INVALID_PARAM;
    }
    return PostMessageToAuthFsmByConnId(FSM_MSG_RECV_CLOSE_ACK, connId, isServer, data, len);
}

int32_t AuthSessionProcessCancelAuthByConnId(uint64_t connId, bool isConnectServer, const uint8_t *data, uint32_t len)
{
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    AuthFsm *authFsm = GetAuthFsmByConnId(connId, isConnectServer, true);
    if (authFsm == NULL) {
        ReleaseAuthLock();
        return SOFTBUS_AUTH_GET_FSM_FAIL;
    }
    if (LnnFsmPostMessage(&authFsm->fsm, FSM_MSG_DEVICE_DISCONNECTED, NULL) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "post message to auth fsm by connId fail");
        ReleaseAuthLock();
        return SOFTBUS_AUTH_SEND_FAIL;
    }
    ReleaseAuthLock();
    return SOFTBUS_OK;
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

int32_t AuthSessionHandleDeviceDisconnected(uint64_t connId, bool isNeedDisconnect)
{
    if (!RequireAuthLock()) {
        AUTH_LOGE(AUTH_FSM, "get auth lock fail");
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
        if ((GetConnType(item->info.connId) == AUTH_LINK_TYPE_WIFI ||
            GetConnType(item->info.connId) == AUTH_LINK_TYPE_P2P)) {
            if (isNeedDisconnect) {
                DisconnectAuthDevice(&item->info.connId);
            } else {
                UpdateFd(&item->info.connId, AUTH_INVALID_FD);
            }
        }
        LnnFsmPostMessage(&item->fsm, FSM_MSG_DEVICE_DISCONNECTED, NULL);
    }
    ReleaseAuthLock();
    return SOFTBUS_OK;
}

int32_t AuthNotifyRequestVerify(int64_t authSeq)
{
    return PostMessageToAuthFsm(FSM_MSG_DEVICE_POST_DEVICEID, authSeq, NULL, 0);
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
