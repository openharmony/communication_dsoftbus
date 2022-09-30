/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "p2plink_negotiation.h"

#include "p2plink_channel_freq.h"
#include "p2plink_common.h"
#include "p2plink_json_payload.h"
#include "p2plink_loop.h"
#include "p2plink_message.h"
#include "p2plink_state_machine.h"
#include "p2plink_type.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"
#include "auth_interface.h"

#define P2PLINK_VERSION 2
#define P2PLINK_NEG_TIMEOUT 5000
#define P2PLINK_NEG_REQUEST_TIMEOUT 8000
#define P2PLINK_DHCP_CONNECT_TIMEOUT 15000
#define MAX_CHANNEL_NUM 1
#define FREQ_STR_LEN 8

typedef struct {
    char peerMac[P2P_MAC_LEN];
    int64_t authId;
    int32_t requestId;
    bool hasCreatedGroup;
    bool hasConnectGroup;
} P2pLinkNegoInfo;

typedef struct {
    FsmStateMachine *fsm;
    P2pLinkNegoInfo linkInfo;
    P2pLinkNegoConnResult result;
} P2pLinkNegoFsm;

static P2pLinkNegoCb g_p2pLinkNegoCb;
static P2pLinkNegoFsm g_p2pLinkNegoFsm;

static void IdleStateEnter(void);
static void IdleStateProcess(P2pLoopMsg msgType, void *param);
static void IdleStateExit(void);

static void RoleNegoStateEnter(void);
static void RoleNegoStateProcess(P2pLoopMsg msgType, void *param);
static void RoleNegoStateExit(void);

static void GroupCreateStateEnter(void);
static void GroupCreateStateProcess(P2pLoopMsg msgType, void *param);
static void GroupCreateStateExit(void);

static void WaitConnectStateEnter(void);
static void WaitConnectStateProcess(P2pLoopMsg msgType, void *param);
static void WaitConnectStateExit(void);

static void ConnectingStateEnter(void);
static void ConnectingStateProcess(P2pLoopMsg msgType, void *param);
static void ConnectingStateExit(void);

static void DhcpStateEnter(void);
static void DhcpStateProcess(P2pLoopMsg msgType, void *param);
static void DhcpStateExit(void);

static int32_t PostConnResponse(int64_t authId, P2pContentType type, int32_t reason);
static void OnGroupConnectSuccess(bool isNeedDhcp);

static FsmState g_p2pLinkNegoState[P2PLINK_NEG_MAX_STATE] = {
    [P2PLINK_NEG_IDLE] = {
        .enter = IdleStateEnter,
        .process = IdleStateProcess,
        .exit = IdleStateExit,
    },
    [P2PLINK_NEG_ROLE_NEGOING] = {
        .enter = RoleNegoStateEnter,
        .process = RoleNegoStateProcess,
        .exit = RoleNegoStateExit,
    },
    [P2PLINK_NEG_GROUP_CREATING] = {
        .enter = GroupCreateStateEnter,
        .process = GroupCreateStateProcess,
        .exit = GroupCreateStateExit,
    },
    [P2PLINK_NEG_GROUP_WAIT_CONNECTING] = {
        .enter = WaitConnectStateEnter,
        .process = WaitConnectStateProcess,
        .exit = WaitConnectStateExit,
    },
    [P2PLINK_NEG_CONNECTING] = {
        .enter = ConnectingStateEnter,
        .process = ConnectingStateProcess,
        .exit = ConnectingStateExit,
    },
    [P2PLINK_NEG_DHCP_STATE] = {
        .enter = DhcpStateEnter,
        .process = DhcpStateProcess,
        .exit = DhcpStateExit,
    },
};

static void IdleStateExit(void)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "p2p link idle state exit.");
}

static void RoleNegoStateEnter(void)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "p2p link role negotiation state enter.");
}

static void RoleNegoStateExit(void)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "p2p link role negotiation state exit.");
}

static void GroupCreateStateEnter(void)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "p2p link group create state enter.");
}

static void GroupCreateStateExit(void)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "p2p link group create state exit.");
}

static void WaitConnectStateEnter(void)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "p2p link wait connect state enter.");
}

static void WaitConnectStateExit(void)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "p2p link wait connect state exit.");
}

static void ConnectingStateEnter(void)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "p2p link connecting state enter.");
}

static void ConnectingStateExit(void)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "p2p link connecting state exit.");
}

static void DhcpStateEnter(void)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "p2p link dhcp state enter.");
}

static void DhcpStateExit(void)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "p2p link dhcp state exit.");
}

static int32_t GetConnectTimeout(void)
{
    if (P2pLinkGetDhcpState()) {
        return P2PLINK_DHCP_CONNECT_TIMEOUT;
    }

    return P2PLINK_NEG_TIMEOUT;
}

static void PostBusyConnResponse(void)
{
    int32_t ret = PostConnResponse(g_p2pLinkNegoFsm.linkInfo.authId, CONTENT_TYPE_RESULT, ERROR_BUSY);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "fail to post busy connect response, ret = %d.", ret);
    }
}

static void OnConnectFailed(int32_t failedReason)
{
    if (g_p2pLinkNegoFsm.linkInfo.requestId != 0) {
        if (g_p2pLinkNegoCb.onConnectFailed != NULL) {
            g_p2pLinkNegoCb.onConnectFailed(g_p2pLinkNegoFsm.linkInfo.requestId, failedReason);
        }
    }
    P2pLinkFsmTransactState(g_p2pLinkNegoFsm.fsm, g_p2pLinkNegoState + P2PLINK_NEG_IDLE);
}

static void DhcpStateProcess(P2pLoopMsg msgType, void *param)
{
    (void)param;
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "dhcp state process, msg type = %d.", msgType);
    switch (msgType) {
        case MAGICLINK_ON_GROUP_CHANGED:
            P2pLinkFsmMsgProcDelayDel(DHCP_TIME_OUT);
            OnGroupConnectSuccess(true);
            break;
        case CONN_REQUEST:
            PostBusyConnResponse();
            break;
        case DHCP_TIME_OUT:
            P2pLinkRemoveGcGroup();
            OnConnectFailed(MAGICLINK_DHCP_TIME_OUT);
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "unsupport message type %d in dhcp state.", msgType);
            break;
    }
}

static void IdleStateEnter(void)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "p2p link negotiation idle state enter.");
    (void)memset_s(&(g_p2pLinkNegoFsm.linkInfo), sizeof(P2pLinkNegoInfo), 0, sizeof(P2pLinkNegoInfo));
    g_p2pLinkNegoFsm.linkInfo.hasCreatedGroup = false;
    g_p2pLinkNegoFsm.linkInfo.hasConnectGroup = false;
}

static int32_t PackAndSendMsg(int64_t authId, bool isRequestMsg, const void *msg)
{
    cJSON *obj = cJSON_CreateObject();
    if (obj == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "create cjson object failed.");
        return SOFTBUS_ERR;
    }

    if (isRequestMsg) {
        const P2pRequestMsg *request = (P2pRequestMsg *)msg;
        if (P2pLinkPackRequestMsg(request, request->contentType, obj) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "pack p2p connect request json msg failed.");
            cJSON_Delete(obj);
            return SOFTBUS_ERR;
        }
    } else {
        const P2pRespMsg *response = (P2pRespMsg *)msg;
        if (P2plinkPackRepsonseMsg(response, response->contentType, obj) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "pack p2p connect response json msg failed.");
            cJSON_Delete(obj);
            return SOFTBUS_ERR;
        }
    }
    char *msgStr = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);
    if (msgStr == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "cjson unformatted failed.");
        return SOFTBUS_ERR;
    }
    if (P2pLinkSendMessage(authId, msgStr, strlen(msgStr) + 1) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "P2p link negotiation send message failed.");
        cJSON_free(msgStr);
        return SOFTBUS_ERR;
    }
    cJSON_free(msgStr);
    return SOFTBUS_OK;
}

static int32_t FillGoInfo(GoInfo *go)
{
    go->goPort = P2pLinkGetGoPort();
    char *groupConfig = P2pLinkGetGroupConfigInfo();
    if (groupConfig == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "P2p link get group config failed.");
        return SOFTBUS_ERR;
    }
    P2pLinkRequestGcIp(g_p2pLinkNegoFsm.linkInfo.peerMac, go->gcIp, sizeof(go->gcIp));
    if (strcpy_s(go->goMac, sizeof(go->goMac), P2pLinkGetGoMac()) != EOK ||
        strcpy_s(go->goIp, sizeof(go->goIp), P2pLinkGetGoIp()) != EOK ||
        strcpy_s(go->gcMac, sizeof(go->gcMac), g_p2pLinkNegoFsm.linkInfo.peerMac) != EOK ||
        strcpy_s(go->groupConfig, sizeof(go->groupConfig), groupConfig) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy_s failed.");
        SoftBusFree(groupConfig);
        return SOFTBUS_MEM_ERR;
    }

    SoftBusFree(groupConfig);

    if (strcpy_s(g_p2pLinkNegoFsm.result.peerIp, sizeof(g_p2pLinkNegoFsm.result.peerIp), go->gcIp) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy_s gc ip failed.");
        return SOFTBUS_MEM_ERR;
    }

    return SOFTBUS_OK;
}

static int32_t FillGcInfo(GcInfo *gc)
{
    gc->isWideBandSupported = P2pLinkIsWideBandwidthSupported();
    P2pLink5GList *channelList = P2pLinkGetChannelListFor5G();
    if (channelList == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "channelList is null.");
    }
    gc->stationFrequency = P2pLinkUpateAndGetStationFreq(channelList);
    if (P2plinkChannelListToString(channelList, gc->channelList, sizeof(gc->channelList)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "transact channelList to string format failed.");
        SoftBusFree(channelList);
        return SOFTBUS_ERR;
    }
    SoftBusFree(channelList);
    // channelScore is nothing, so don't fill channelScore.
    if (strcpy_s(gc->goMac, sizeof(gc->goMac), P2pLinkGetGoMac()) != EOK ||
        strcpy_s(gc->gcMac, sizeof(gc->gcMac), P2pLinkGetMyMac()) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy_s failed.");
        return SOFTBUS_MEM_ERR;
    }

    return SOFTBUS_OK;
}

static int32_t FillResponseInfo(P2pRespMsg *response, int32_t result)
{
    response->cmdType = CMD_CONNECT_RESPONSE;
    response->version = P2PLINK_VERSION;

    if (strcpy_s(response->myMac, sizeof(response->myMac), P2pLinkGetMyMac()) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy_s failed.");
        return SOFTBUS_MEM_ERR;
    }

    if (strcpy_s(response->myIp, sizeof(response->myIp), P2pLinkGetMyIp()) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy_s failed.");
        return SOFTBUS_MEM_ERR;
    }

    if (P2pLinkGetSelfWifiCfgInfo(response->wifiCfg, sizeof(response->wifiCfg)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_WARN, "get self wifi config failed.");
    }

    if (response->contentType == CONTENT_TYPE_GO_INFO) {
        GoInfo *go = (GoInfo *)(response->data);
        if (FillGoInfo(go) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "fill response go info failed.");
            return SOFTBUS_ERR;
        }
    } else if (response->contentType == CONTENT_TYPE_GC_INFO) {
        GcInfo *gc = (GcInfo *)(response->data);
        if (FillGcInfo(gc) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "fill response gc info failed.");
            return SOFTBUS_ERR;
        }
    } else {
        response->result = result;
    }

    return SOFTBUS_OK;
}

static int32_t FillRequestInfo(P2pRequestMsg *request, int32_t myRole, int32_t expectedRole, bool isbridgeSupport)
{
    request->cmdType = CMD_CONNECT_REQUEST;
    request->role = myRole;
    request->expectedRole = expectedRole;
    request->isbridgeSupport = isbridgeSupport;
    request->version = P2PLINK_VERSION;

    if (strcpy_s(request->myMac, sizeof(request->myMac), P2pLinkGetMyMac()) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy_s failed.");
        return SOFTBUS_MEM_ERR;
    }

    if (P2pLinkGetSelfWifiCfgInfo(request->wifiCfg, sizeof(request->wifiCfg)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_WARN, "get self wifi config failed.");
    }

    if (request->contentType == CONTENT_TYPE_GO_INFO) {
        GoInfo *go = (GoInfo *)(request->data);
        if (FillGoInfo(go) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "fill request go info failed.");
            return SOFTBUS_ERR;
        }
    } else if (request->contentType == CONTENT_TYPE_GC_INFO) {
        GcInfo *gc = (GcInfo *)(request->data);
        if (FillGcInfo(gc) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "fill request gc info failed.");
            return SOFTBUS_ERR;
        }
    }

    return SOFTBUS_OK;
}

static int32_t PostConnRequest(int64_t authId, const char *peerMac, int32_t expectRole, int32_t myRole)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
        "post connect requset msg, myRole = %d, myExpected role = %d.", myRole, expectRole);
    P2pRequestMsg *request = NULL;
    if (myRole == ROLE_GO) {
        request = (P2pRequestMsg *)SoftBusCalloc(sizeof(P2pRequestMsg) + sizeof(GoInfo));
        if (request == NULL) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "calloc failed.");
            return SOFTBUS_MALLOC_ERR;
        }
        request->contentType = CONTENT_TYPE_GO_INFO;
    } else {
        request = (P2pRequestMsg *)SoftBusCalloc(sizeof(P2pRequestMsg) + sizeof(GcInfo));
        if (request == NULL) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "calloc failed.");
            return SOFTBUS_MALLOC_ERR;
        }
        request->contentType = CONTENT_TYPE_GC_INFO;
    }

    if (FillRequestInfo(request, myRole, expectRole, false) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "fill request msg failed.");
        SoftBusFree(request);
        return SOFTBUS_ERR;
    }
    int32_t ret = PackAndSendMsg(authId, true, (void *)request);
    SoftBusFree(request);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "pack and send p2p link negotiation msg failed.");
        return ret;
    }
    return SOFTBUS_OK;
}

static void IdleStateStartNeo(const P2pLinkNegoConnInfo *info)
{
    int32_t ret;
    do {
        int32_t myRole = P2pLinkGetRole();
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "local device current role is %d.", myRole);
        g_p2pLinkNegoFsm.linkInfo.authId = info->authId;
        g_p2pLinkNegoFsm.linkInfo.requestId = info->requestId;
        if (myRole == ROLE_GC) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "not support bridge, gc can not connect other devices.");
            ret = NOT_SUPPORT_BRIDGE;
            break;
        }
        if (strcpy_s(g_p2pLinkNegoFsm.linkInfo.peerMac, sizeof(g_p2pLinkNegoFsm.linkInfo.peerMac),
            info->peerMac) != EOK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy_s peer mac failed, errno = %d.", errno);
            ret = SOFTBUS_MEM_ERR;
            break;
        }
        ret = PostConnRequest(info->authId, info->peerMac, info->expectRole, myRole);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
                "start negotiation, post connect request failed, ret = %d.", ret);
            break;
        }
        if (myRole == ROLE_GO) {
            P2pLinkFsmTransactState(g_p2pLinkNegoFsm.fsm, g_p2pLinkNegoState + P2PLINK_NEG_GROUP_WAIT_CONNECTING);
        } else if (myRole == ROLE_NONE) {
            P2pLinkFsmTransactState(g_p2pLinkNegoFsm.fsm, g_p2pLinkNegoState + P2PLINK_NEG_ROLE_NEGOING);
        }
        P2pLinkFsmMsgProcDelay(g_p2pLinkNegoFsm.fsm, CONN_REQUEST_TIME_OUT, NULL, P2PLINK_NEG_REQUEST_TIMEOUT);
    } while (0);

    if (ret != SOFTBUS_OK) {
        OnConnectFailed(ret);
    }
}

static int32_t DecideMyRoleAsGO(int32_t peerRole, int32_t peeerExpectRole, const char *myGoMac,
    char *peerGoMac, int32_t isSupportBridge)
{
    (void)isSupportBridge;
    switch (peerRole) {
        case ROLE_GO:
            return ERROR_BOTH_GO;
        case ROLE_GC:
            if (myGoMac != NULL && peerGoMac != NULL && strcmp(myGoMac, peerGoMac)) {
                return ERROR_PEER_GC_CONNECTED_TO_ANOTHER_DEVICE;
            }
            if (peeerExpectRole == ROLE_GO) {
                return ERROR_AVAILABLE_WITH_MISMATCHED_ROLE;
            }
            return ROLE_GO;
        default:
            if (peeerExpectRole == ROLE_GO) {
                return ERROR_AVAILABLE_WITH_MISMATCHED_ROLE;
            }
            return ROLE_GO;
    }
}

static int32_t DecideMyRoleAsGC(int32_t peerRole, int32_t peeerExpectRole, const char *myGoMac,
    char *peerGoMac, int32_t isSupportBridge)
{
    switch (peerRole) {
        case ROLE_GO:
            if (myGoMac != NULL && peerGoMac != NULL && !strcmp(myGoMac, peerGoMac)) {
                return ROLE_GC;
            }
            return ERROR_GC_CONNECTED_TO_ANOTHER_DEVICE;
        case ROLE_GC:
            if (myGoMac != NULL && peerGoMac != NULL && strcmp(myGoMac, peerGoMac)) {
                return ERROR_PEER_GC_CONNECTED_TO_ANOTHER_DEVICE;
            }
            if (peeerExpectRole == ROLE_GO || !isSupportBridge) {
                return ERROR_AVAILABLE_WITH_MISMATCHED_ROLE;
            }
            return ROLE_BRIDGE_GC;
        default:
            if (peeerExpectRole != ROLE_GO && isSupportBridge) {
                return ROLE_BRIDGE_GC;
            }
            return ERROR_AVAILABLE_WITH_MISMATCHED_ROLE;
    }
}

static int32_t DecideMyRoleAsNone(int32_t peerRole, int32_t peerExpectRole, const char *myGoMac,
    char *peerGoMac, int32_t isSupportBridge)
{
    (void)myGoMac;
    (void)peerGoMac;
    switch (peerRole) {
        case ROLE_GO:
            if (peerExpectRole == ROLE_GC) {
                return ERROR_AVAILABLE_WITH_MISMATCHED_ROLE;
            }
            return ROLE_GC;
        case ROLE_GC:
            if (peerExpectRole == ROLE_GO || !isSupportBridge) {
                return ERROR_AVAILABLE_WITH_MISMATCHED_ROLE;
            }
            return ROLE_BRIDGE_GC;
        default:
            if (peerExpectRole == ROLE_GC) {
                return ROLE_GO;
            }
            return ROLE_GC;
    }
}

int32_t P2pLinkNegoGetFinalRole(int32_t peerRole, int32_t peerExpectRole, const char *peerGoMac, bool isSupportBridge)
{
    int32_t myRole = P2pLinkGetRole();
    char *myGoMac = P2pLinkGetGoMac();
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "current my role = %d, peer role = %d, \
        peer expected role = %d.", myRole, peerRole, peerExpectRole);

    switch (myRole) {
        case ROLE_GO:
            return DecideMyRoleAsGO(peerRole, peerExpectRole, peerGoMac, myGoMac, isSupportBridge);
        case ROLE_GC:
            return DecideMyRoleAsGC(peerRole, peerExpectRole, peerGoMac, myGoMac, isSupportBridge);
        default:
            return DecideMyRoleAsNone(peerRole, peerExpectRole, peerGoMac, myGoMac, isSupportBridge);
    }
}

static int32_t CreateGroup(const GcInfo *gc)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "p2plink negotiation create group.");
    int32_t ret;
    P2pLinkStopPeerDiscovery();
    P2pLink5GList *channelList = P2pLinkGetChannelListFor5G();
    if (channelList == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "local channel 5g list is null.");
    }
    int32_t finalFreq = P2plinkGetGroupGrequency(gc, channelList);
    SoftBusFree(channelList);
    bool isWideBandSupport = false;
    if (P2pLinkIsWideBandwidthSupported() && gc->isWideBandSupported) {
        isWideBandSupport = true;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "final freq string = %d, support wide band = %d.",
        finalFreq, isWideBandSupport);
    ret = P2pLinkCreateGroup(finalFreq, isWideBandSupport);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "create group failed, ret = %d.", ret);
        return ret;
    }

    P2pLinkFsmTransactState(g_p2pLinkNegoFsm.fsm, g_p2pLinkNegoState + P2PLINK_NEG_GROUP_CREATING);
    P2pLinkFsmMsgProcDelay(g_p2pLinkNegoFsm.fsm, MAGICLINK_CREATE_GROUP_TIME_OUT, NULL, P2PLINK_NEG_TIMEOUT);
    return SOFTBUS_OK;
}

static void HndConnRequestAsGo(const P2pRequestMsg *request)
{
    int32_t ret;
    if (request->contentType != CONTENT_TYPE_GC_INFO) {
        ret = PostConnResponse(g_p2pLinkNegoFsm.linkInfo.authId, CONTENT_TYPE_RESULT, ERROR_BOTH_GO);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "fail to post go connect response, ret = %d.", ret);
        }
        P2pLinkFsmTransactState(g_p2pLinkNegoFsm.fsm, g_p2pLinkNegoState + P2PLINK_NEG_IDLE);
        return;
    }

    GcInfo *gc = (GcInfo *)(request->data);
    int32_t myRole = P2pLinkGetRole();
    if (myRole == ROLE_GO) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "my role is already go, reponse go info.");
        ret = PostConnResponse(g_p2pLinkNegoFsm.linkInfo.authId, CONTENT_TYPE_GO_INFO, 0);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "fail to post go connect response, ret = %d.", ret);
            P2pLinkFsmTransactState(g_p2pLinkNegoFsm.fsm, g_p2pLinkNegoState + P2PLINK_NEG_IDLE);
        }

        P2pLinkFsmTransactState(g_p2pLinkNegoFsm.fsm, g_p2pLinkNegoState + P2PLINK_NEG_GROUP_WAIT_CONNECTING);
        P2pLinkFsmMsgProcDelay(g_p2pLinkNegoFsm.fsm, WAIT_CONN_TIME_OUT, NULL, P2PLINK_NEG_TIMEOUT);
        return;
    }
    ret = CreateGroup(gc);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "fail to create group, ret = %d.", ret);
    }
}

static bool IsNeedDhcp(const GoInfo *go)
{
    if (strlen(go->gcIp) != 0) {
        return false;
    }

    if (strlen(go->groupConfig) == 0) {
        return false;
    }

    char groupCfg[GROUP_CONFIG_LEN] = {0};
    if (strcpy_s(groupCfg, sizeof(groupCfg), go->groupConfig) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "dhcp, strcpy_s group failed.");
        return false;
    }

    char *parseList[MAX_GROUP_CONFIG_ITEM_NUM] = {0};
    int32_t outNum;
    P2pLinkParseItemDataByDelimit(groupCfg, "\n", parseList, MAX_GROUP_CONFIG_ITEM_NUM, &outNum);
    if (outNum <= GROUP_CONFIG_ITEM_NUM) {
        return false;
    }

    if (!strcmp(parseList[GROUP_CONFIG_ITEM_NUM], "1")) {
        return true;
    } else {
        return false;
    }
}

static int32_t ConnectGroup(const GoInfo *go)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "p2plink negotiation connect group.");
    int32_t ret;
    bool isDhcp = IsNeedDhcp(go);
    P2pLinkSetDhcpState(isDhcp);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "set dhcp state %d.", isDhcp);
    P2pLinkStopPeerDiscovery();
    ret = P2pLinkConnectGroup((char *)(go->groupConfig));
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "magic link connect invoke failed, ret = %d.", ret);
        return ret;
    }

    if (strcpy_s(g_p2pLinkNegoFsm.result.peerIp, sizeof(g_p2pLinkNegoFsm.result.peerIp), go->goIp) != EOK ||
        strcpy_s(g_p2pLinkNegoFsm.result.localIp, sizeof(g_p2pLinkNegoFsm.result.localIp), go->gcIp) != EOK ||
        strcpy_s(g_p2pLinkNegoFsm.result.peerMac, sizeof(g_p2pLinkNegoFsm.result.peerMac), go->goMac) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy_s failed, errno = %d.", errno);
        return SOFTBUS_MEM_ERR;
    }
    g_p2pLinkNegoFsm.result.authId = g_p2pLinkNegoFsm.linkInfo.authId;
    g_p2pLinkNegoFsm.result.goPort = go->goPort;
    if (strlen(go->gcIp) != 0) {
        P2pLinkSetMyIp(go->gcIp);
    }

    P2pLinkFsmTransactState(g_p2pLinkNegoFsm.fsm, g_p2pLinkNegoState + P2PLINK_NEG_CONNECTING);
    P2pLinkFsmMsgProcDelay(g_p2pLinkNegoFsm.fsm, MAGICLINK_CONN_GROUP_TIME_OUT, NULL, GetConnectTimeout());
    return SOFTBUS_OK;
}

static void HndConnRequestAsGc(const P2pRequestMsg *request)
{
    int32_t type = request->contentType;
    int32_t ret;
    if (type == CONTENT_TYPE_GC_INFO) {
        ret = PostConnResponse(g_p2pLinkNegoFsm.linkInfo.authId, CONTENT_TYPE_GC_INFO, 0);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "fail to post connect gc response, ret = %d.", ret);
            P2pLinkFsmTransactState(g_p2pLinkNegoFsm.fsm, g_p2pLinkNegoState + P2PLINK_NEG_IDLE);
        }
        P2pLinkFsmTransactState(g_p2pLinkNegoFsm.fsm, g_p2pLinkNegoState + P2PLINK_NEG_ROLE_NEGOING);
        P2pLinkFsmMsgProcDelay(g_p2pLinkNegoFsm.fsm, WAIT_ROLE_NEG_TIME_OUT, NULL, P2PLINK_NEG_TIMEOUT);
    } else if (type == CONTENT_TYPE_GO_INFO) {
        if (P2pLinkGetRole() == ROLE_GC) {
            // normal position will not reach this branch
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "my role alread is gc, peer device should connect by reuse.");
            ret = PostConnResponse(g_p2pLinkNegoFsm.linkInfo.authId, CONTENT_TYPE_RESULT, ERROR_BUSY);
            if (ret != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "fail to post connect result response, ret = %d.", ret);
            }
            P2pLinkFsmTransactState(g_p2pLinkNegoFsm.fsm, g_p2pLinkNegoState + P2PLINK_NEG_IDLE);
            return;
        }
        GoInfo *go = (GoInfo *)(request->data);
        ret = ConnectGroup(go);
        if (ret == SOFTBUS_OK) {
            return;
        }
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "connect group failed, ret = %d.", ret);
        ret = PostConnResponse(g_p2pLinkNegoFsm.linkInfo.authId, CONTENT_TYPE_RESULT, ret);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
                "connect group failed, fail to post connect result response, ret = %d.", ret);
        }
        P2pLinkFsmTransactState(g_p2pLinkNegoFsm.fsm, g_p2pLinkNegoState + P2PLINK_NEG_IDLE);
    }
}

static P2pRequestMsg *JsonToConnRequest(const cJSON *data)
{
    P2pRequestMsg *request = NULL;
    int32_t contentType;
    if (!GetJsonObjectNumberItem(data, KEY_CONTENT_TYPE, &contentType)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get content type from json failed.");
        return NULL;
    }
    if (contentType == CONTENT_TYPE_GO_INFO) {
        request = (P2pRequestMsg *)SoftBusCalloc(sizeof(P2pRequestMsg) + sizeof(GoInfo));
    } else {
        request = (P2pRequestMsg *)SoftBusCalloc(sizeof(P2pRequestMsg) + sizeof(GcInfo));
    }

    if (request == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "calloc failed.");
        return NULL;
    }

    if (P2pLinkUnpackRequestMsg(data, contentType, request) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "unpack p2p link negotiation request message failed.");
        SoftBusFree(request);
        return NULL;
    }
    return request;
}

static void OnConnectRequestRecv(const cJSON *data)
{
    P2pRequestMsg *request = JsonToConnRequest(data);
    if (request == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "json to connect request failed.");
        P2pLinkFsmTransactState(g_p2pLinkNegoFsm.fsm, g_p2pLinkNegoState + P2PLINK_NEG_IDLE);
        return;
    }
    int32_t ret = P2pLinkSetPeerWifiCfgInfo(request->wifiCfg);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "set peer wifi config failed, ret = %d.", ret);
    }
    int32_t peerRole = request->role;
    int32_t peerExpectRole = request->expectedRole;
    int32_t isSupportBridge = request->isbridgeSupport;
    char *peerGoMac = NULL;
    if (request->contentType == CONTENT_TYPE_GO_INFO) {
        GoInfo *go = (GoInfo *)(request->data);
        peerGoMac = go->goMac;
    } else if (request->contentType == CONTENT_TYPE_GC_INFO) {
        GcInfo *gc = (GcInfo *)(request->data);
        peerGoMac = gc->goMac;
    }
    int32_t myDecideRole = P2pLinkNegoGetFinalRole(peerRole, peerExpectRole, peerGoMac, isSupportBridge);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "get my final role = %d.", myDecideRole);
    switch (myDecideRole) {
        case ROLE_GO:
            HndConnRequestAsGo(request);
            break;
        case ROLE_GC:
            HndConnRequestAsGc(request);
            break;
        case ROLE_BRIDGE_GC:
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "unsupport bridge gc.");
            P2pLinkFsmTransactState(g_p2pLinkNegoFsm.fsm, g_p2pLinkNegoState + P2PLINK_NEG_IDLE);
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "decide my role failed, error failed: %d.", myDecideRole);
            ret = PostConnResponse(g_p2pLinkNegoFsm.linkInfo.authId, CONTENT_TYPE_RESULT, myDecideRole);
            if (ret != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "fail to post connect result response, ret = %d.", ret);
            }
            P2pLinkFsmTransactState(g_p2pLinkNegoFsm.fsm, g_p2pLinkNegoState + P2PLINK_NEG_IDLE);
            break;
    }
    SoftBusFree(request);
}

static void SetCurrentPeerMac(const cJSON *data)
{
    char peerMac[P2P_MAC_LEN] = {0};

    if (!GetJsonObjectStringItem(data, KEY_MAC, peerMac, sizeof(peerMac))) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get peer mac failed");
        goto EXIT;
    }

    if (strcpy_s(g_p2pLinkNegoFsm.linkInfo.peerMac, sizeof(g_p2pLinkNegoFsm.linkInfo.peerMac), peerMac) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy_s failed");
        goto EXIT;
    }

    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "recv conn request, set current peer mac");
    return;
EXIT:
    P2pLinkFsmTransactState(g_p2pLinkNegoFsm.fsm, g_p2pLinkNegoState + P2PLINK_NEG_IDLE);
}

static void IdleStateProcess(P2pLoopMsg msgType, void *param)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "idle state process, msg type = %d.", msgType);
    switch (msgType) {
        case START_NEGOTIATION:
            IdleStateStartNeo((P2pLinkNegoConnInfo *)param);
            break;
        case CONN_REQUEST:
            SetCurrentPeerMac((cJSON *)param);
            OnConnectRequestRecv((cJSON *)param);
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "unsupport message type %d in idle state.", msgType);
            break;
    }
}

static void OnConnectSuccess(const P2pLinkNegoConnResult *conneResult)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "connected success");
    int32_t ret = AuthSetP2pMac(conneResult->authId, conneResult->peerMac);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "AuthSetP2pMac fail ret: %d", ret);
    }

    if (g_p2pLinkNegoFsm.linkInfo.requestId != 0) {
        if (g_p2pLinkNegoCb.onConnected != NULL) {
            g_p2pLinkNegoCb.onConnected(g_p2pLinkNegoFsm.linkInfo.requestId, conneResult);
        }
    } else {
        if (g_p2pLinkNegoCb.onPeerConnected != NULL) {
            g_p2pLinkNegoCb.onPeerConnected(conneResult);
        }
    }

    P2pLinkFsmTransactState(g_p2pLinkNegoFsm.fsm, g_p2pLinkNegoState + P2PLINK_NEG_IDLE);
}

static int32_t FillConnResult(P2pLinkNegoConnResult *result, const char *peerIp, const char *peerMac)
{
    result->goPort = P2pLinkGetGoPort();
    result->authId = g_p2pLinkNegoFsm.linkInfo.authId;
    if (strcpy_s(result->localMac, sizeof(result->localMac), P2pLinkGetMyMac()) != EOK ||
        strcpy_s(result->localIp, sizeof(result->localIp), P2pLinkGetMyIp()) != EOK ||
        strcpy_s(result->peerMac, sizeof(result->peerMac), peerMac) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy_s failed, errno = %d.", errno);
        return SOFTBUS_MEM_ERR;
    }

    if (peerIp != NULL) {
        if (strcpy_s(result->peerIp, sizeof(result->peerIp), peerIp) != EOK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
                "connect reult, strcpy_s peer ip failed, errno = %d.", errno);
            return SOFTBUS_MEM_ERR;
        }
    }

    return SOFTBUS_OK;
}

static void WaitStateOnRepsonseRecv(const P2pRespMsg *response)
{
    // for go request message, will receive group change and reponse message.
    if ((response == NULL) || (response->contentType != CONTENT_TYPE_RESULT)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "unsupport content type in wait connecting state.");
        OnConnectFailed(UNEXPECTED_CONTENT_TYPE);
        return;
    }

    if (response->result != 0) {
        if (g_p2pLinkNegoFsm.linkInfo.hasCreatedGroup) {
            P2pLinkRemoveGroup();
        }
        OnConnectFailed(response->result);
        return;
    }

    int32_t ret = FillConnResult(&(g_p2pLinkNegoFsm.result), response->myIp, response->myMac);
    if (ret != SOFTBUS_OK) {
        if (g_p2pLinkNegoFsm.linkInfo.hasCreatedGroup) {
            P2pLinkRemoveGroup();
        }
        OnConnectFailed(ret);
        return;
    }

    OnConnectSuccess(&(g_p2pLinkNegoFsm.result));
}

static void TimeoutErrorProcess(int32_t localErrCode, int32_t peerErrCode)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "invoke timeout, errcode %d.", localErrCode);
    if (g_p2pLinkNegoFsm.linkInfo.requestId != 0) {
        if (g_p2pLinkNegoCb.onConnectFailed != NULL) {
            g_p2pLinkNegoCb.onConnectFailed(g_p2pLinkNegoFsm.linkInfo.requestId, localErrCode);
        }
    } else {
        int32_t ret = PostConnResponse(g_p2pLinkNegoFsm.linkInfo.authId, CONTENT_TYPE_RESULT, peerErrCode);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "fail to post connect ret = %d.", ret);
        }
    }

    P2pLinkFsmTransactState(g_p2pLinkNegoFsm.fsm, g_p2pLinkNegoState + P2PLINK_NEG_IDLE);
}

static void WaitStateOnRepsonseRecvTimeout(int32_t failReason)
{
    if (g_p2pLinkNegoFsm.linkInfo.hasCreatedGroup) {
        P2pLinkRemoveGroup();
    }
    TimeoutErrorProcess(failReason, failReason);
}

static void WaitStateOnConnectEventRecv(const P2pLinkGroup *group)
{
    if (g_p2pLinkNegoFsm.linkInfo.requestId != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "go request msg, don't process peer connect, wait reponse msg.");
        return;
    }

    P2pLinkFsmMsgProcDelayDel(WAIT_CONN_TIME_OUT);
    if (group->role != ROLE_GO) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG,
            "wait state receive group role is not go, role = %d.", group->role);
        return;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "gc connected, num = %d.", group->peerMacNum);
    P2pLinkPeerMacList *macItem = (P2pLinkPeerMacList *)group->peerMacs;
    for (int32_t i = 0; i < group->peerMacNum; i++) {
        macItem =  macItem + i;
        if (macItem == NULL) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "invalid p2p link group item, null.");
            break;
        }
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "gc item %d.", i);
        if (!strcmp(g_p2pLinkNegoFsm.linkInfo.peerMac, macItem->mac)) {
            int32_t ret = FillConnResult(&(g_p2pLinkNegoFsm.result), NULL, g_p2pLinkNegoFsm.linkInfo.peerMac);
            if (ret == SOFTBUS_OK) {
                OnConnectSuccess(&(g_p2pLinkNegoFsm.result));
            }
        }
    }
}

static void WaitConnectStateProcess(P2pLoopMsg msgType, void *param)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "wait connect process, msg type = %d.", msgType);
    switch (msgType) {
        case CONN_RESPONSE:
            P2pLinkFsmMsgProcDelayDel(CONN_REQUEST_TIME_OUT);
            WaitStateOnRepsonseRecv((P2pRespMsg *)param);
            break;
        case CONN_REQUEST_TIME_OUT:
            WaitStateOnRepsonseRecvTimeout(WAIT_RESPONSE_MSG_TIME_OUT);
            break;
        case MAGICLINK_ON_GROUP_CHANGED:
            WaitStateOnConnectEventRecv((P2pLinkGroup *)param);
            break;
        case CONN_REQUEST:
            PostBusyConnResponse();
            break;
        case WAIT_CONN_TIME_OUT:
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
                "timeout, no gc connected, need to clean and transact to idle state.");
            if (g_p2pLinkNegoFsm.linkInfo.hasCreatedGroup) {
                P2pLinkRemoveGroup();
            }
            P2pLinkFsmTransactState(g_p2pLinkNegoFsm.fsm, g_p2pLinkNegoState + P2PLINK_NEG_IDLE);
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "unsupport message type %d in idle state.", msgType);
            break;
    }
}

static int32_t PostConnResponse(int64_t authId, P2pContentType type, int32_t reason)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "post connect response msg, content type = %d.", type);
    P2pRespMsg *response = NULL;
    if (type == CONTENT_TYPE_GO_INFO) {
        response = (P2pRespMsg *)SoftBusCalloc(sizeof(P2pRespMsg) + sizeof(GoInfo));
        if (response == NULL) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "calloc failed.");
            return SOFTBUS_MALLOC_ERR;
        }
    } else if (type == CONTENT_TYPE_GC_INFO) {
        response = (P2pRespMsg *)SoftBusCalloc(sizeof(P2pRespMsg) + sizeof(GcInfo));
        if (response == NULL) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "calloc failed.");
            return SOFTBUS_MALLOC_ERR;
        }
    } else {
        response = (P2pRespMsg *)SoftBusCalloc(sizeof(P2pRespMsg));
        if (response == NULL) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "calloc failed.");
            return SOFTBUS_MALLOC_ERR;
        }
    }
    response->contentType = type;
    if (FillResponseInfo(response, reason) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "fill response msg failed.");
        SoftBusFree(response);
        return SOFTBUS_ERR;
    }
    int32_t ret = PackAndSendMsg(authId, false, (void *)response);
    SoftBusFree(response);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "pack and send p2p link negotiation msg failed.");
        return ret;
    }

    return SOFTBUS_OK;
}

static void OnGroupCreated(const P2pLinkGroup *group)
{
    (void)group;
    g_p2pLinkNegoFsm.linkInfo.hasCreatedGroup = true;
    int32_t ret;
    if (g_p2pLinkNegoFsm.linkInfo.requestId != 0) {
        ret = PostConnRequest(g_p2pLinkNegoFsm.linkInfo.authId, g_p2pLinkNegoFsm.linkInfo.peerMac, ROLE_GO, ROLE_GO);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
                "post conn request failed as go, need to clean group, ret = %d.", ret);
            P2pLinkFsmMsgProc(g_p2pLinkNegoFsm.fsm, CONN_REQUEST_FAILED, (void *)&ret);
            return;
        }
        P2pLinkFsmTransactState(g_p2pLinkNegoFsm.fsm, g_p2pLinkNegoState + P2PLINK_NEG_GROUP_WAIT_CONNECTING);
        P2pLinkFsmMsgProcDelay(g_p2pLinkNegoFsm.fsm, CONN_REQUEST_TIME_OUT, NULL, P2PLINK_NEG_REQUEST_TIMEOUT);
    } else {
        ret = PostConnResponse(g_p2pLinkNegoFsm.linkInfo.authId, CONTENT_TYPE_GO_INFO, 0);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
                "post conn reponse failed as go, need to clean group, ret = %d.", ret);
            P2pLinkFsmMsgProc(g_p2pLinkNegoFsm.fsm, CONN_RESPONSE_FAILED, (void *)&ret);
            return;
        }

        P2pLinkFsmTransactState(g_p2pLinkNegoFsm.fsm, g_p2pLinkNegoState + P2PLINK_NEG_GROUP_WAIT_CONNECTING);
        P2pLinkFsmMsgProcDelay(g_p2pLinkNegoFsm.fsm, WAIT_CONN_TIME_OUT, NULL, P2PLINK_NEG_TIMEOUT);
    }
}

static void PostMsgFailedAsGo(const int32_t *ret)
{
    P2pLinkRemoveGroup();
    OnConnectFailed(*ret);
}

static void GroupCreateStateProcess(P2pLoopMsg msgType, void *param)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "group create process, msg type = %d.", msgType);
    switch (msgType) {
        case MAGICLINK_CREATE_GROUP_TIME_OUT:
            TimeoutErrorProcess(ERROR_CREATE_GROUP_FAILED, ERROR_PEER_CREATE_GROUP_FAILED);
            break;
        case MAGICLINK_ON_GROUP_CHANGED:
            P2pLinkFsmMsgProcDelayDel(MAGICLINK_CREATE_GROUP_TIME_OUT);
            OnGroupCreated((P2pLinkGroup *)param);
            break;
        case CONN_REQUEST_FAILED:
        case CONN_RESPONSE_FAILED:
            PostMsgFailedAsGo((int32_t *)param);
            break;
        case MAGICLINK_ON_CONNECTED:
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "connect state %d in create group state.", *(int32_t *)param);
            break;
        case CONN_REQUEST:
            PostBusyConnResponse();
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "unsupport message type %d in idle state.", msgType);
            break;
    }
}

static void OnGroupConnectSuccess(bool isNeedDhcp)
{
    int32_t ret;
    if (!isNeedDhcp) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "not support dhcp, config gc ip by magiclink.");
        ret = P2pLinkConfigGcIp(g_p2pLinkNegoFsm.result.localIp);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
                "config ip for gc failed, need clean gc group, ret = %d.", ret);
            P2pLinkRemoveGcGroup();
            OnConnectFailed(MAGICLINK_CONFIGIP_FAILED);
            return;
        }
    }

    if (g_p2pLinkNegoFsm.linkInfo.requestId == 0) {
        ret = PostConnResponse(g_p2pLinkNegoFsm.linkInfo.authId, CONTENT_TYPE_RESULT, SOFTBUS_OK);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "fail to post connect success response, ret = %d.", ret);
            P2pLinkRemoveGcGroup();
            P2pLinkFsmTransactState(g_p2pLinkNegoFsm.fsm, g_p2pLinkNegoState + P2PLINK_NEG_IDLE);
            return;
        }
    }

    if (isNeedDhcp) {
        ret = strcpy_s(g_p2pLinkNegoFsm.result.localIp, sizeof(g_p2pLinkNegoFsm.result.localIp), P2pLinkGetMyIp());
        if (ret != EOK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy_s local ip failed.");
            P2pLinkRemoveGcGroup();
            OnConnectFailed(SOFTBUS_MEM_ERR);
            return;
        }
    }

    if (strcpy_s(g_p2pLinkNegoFsm.result.localMac, sizeof(g_p2pLinkNegoFsm.result.localMac),
        P2pLinkGetMyMac()) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy_s failed, errno = %d.", errno);
        P2pLinkRemoveGcGroup();
        OnConnectFailed(SOFTBUS_MEM_ERR);
        return;
    }

    g_p2pLinkNegoFsm.result.authId = g_p2pLinkNegoFsm.linkInfo.authId;
    OnConnectSuccess(&(g_p2pLinkNegoFsm.result));
}

static void ConnectingStateOnConnectStateChanged(const int32_t *state)
{
    int32_t connState = *state;
    switch (connState) {
        case P2PLINK_CONNECTING:
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "connect state : connecting.");
            break;
        case P2PLINK_CONNECTED:
            P2pLinkFsmMsgProcDelayDel(MAGICLINK_CONN_GROUP_TIME_OUT);
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "connect state : connected.");
            g_p2pLinkNegoFsm.linkInfo.hasConnectGroup = true;
            if (P2pLinkGetDhcpState()) {
                P2pLinkFsmTransactState(g_p2pLinkNegoFsm.fsm, g_p2pLinkNegoState + P2PLINK_NEG_DHCP_STATE);
                P2pLinkFsmMsgProcDelay(g_p2pLinkNegoFsm.fsm, DHCP_TIME_OUT, NULL, P2PLINK_NEG_TIMEOUT);
                return;
            }
            OnGroupConnectSuccess(false);
            break;
        case P2PLINK_CONNECT_FAILED:
            P2pLinkFsmMsgProcDelayDel(MAGICLINK_CONN_GROUP_TIME_OUT);
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "connect state : connect failed.");
            TimeoutErrorProcess(NEED_POST_DISCONNECT, ERROR_CONNECT_TIMEOUT);
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "unsupport connect state %d when connect state changed.",
                connState);
            break;
    }
}

static void ConnectingStateProcess(P2pLoopMsg msgType, void *param)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "connecting state process, msg type = %d.", msgType);
    switch (msgType) {
        case MAGICLINK_CONN_GROUP_TIME_OUT:
            P2pLinkRemoveGroup();
            TimeoutErrorProcess(ERROR_CONNECT_GROUP_FAILED, ERROR_PEER_CONNECT_GROUP_FAILED);
            break;
        case MAGICLINK_ON_CONNECTED:
            ConnectingStateOnConnectStateChanged((int32_t *)param);
            break;
        case MAGICLINK_ON_GROUP_CHANGED:
            TimeoutErrorProcess(NEED_POST_DISCONNECT, ERROR_CONNECT_TIMEOUT);
            break;
        case CONN_REQUEST:
            PostBusyConnResponse();
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "unsupport message type %d in connecting state.", msgType);
            break;
    }
}

static void RoleNegoStateOnResponseRecv(const P2pRespMsg *response)
{
    int32_t ret = P2pLinkSetPeerWifiCfgInfo(response->wifiCfg);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG,
            "set peer wifi config in role negotiation state failed ret = %d.", ret);
    }
    if (response->contentType == CONTENT_TYPE_GO_INFO) {
        GoInfo *go = (GoInfo *)(response->data);
        ret = ConnectGroup(go);
    } else if (response->contentType == CONTENT_TYPE_GC_INFO) {
        GcInfo *gc = (GcInfo *)(response->data);
        ret = CreateGroup(gc);
    } else if (response->contentType == CONTENT_TYPE_RESULT) {
        ret = response->result;
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "receive peer errcode %d in role negotiation state.", ret);
    }

    if (ret != SOFTBUS_OK) {
        OnConnectFailed(ret);
    }
}

static bool IsSamePeerDevice(cJSON *data)
{
    char peerMac[P2P_MAC_LEN] = {0};
    if (!GetJsonObjectStringItem(data, KEY_MAC, peerMac, sizeof(peerMac))) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get peer mac failed");
        return false;
    }

    if (!strcmp(peerMac, g_p2pLinkNegoFsm.linkInfo.peerMac)) {
        return true;
    }

    return false;
}

static void RoleNegoStateProcess(P2pLoopMsg msgType, void *param)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "role negotiation state process, msg type = %d.", msgType);
    switch (msgType) {
        case CONN_REQUEST_TIME_OUT:
            TimeoutErrorProcess(ROLE_NEG_TIME_OUT, ROLE_NEG_TIME_OUT);
            break;
        case CONN_RESPONSE:
            P2pLinkFsmMsgProcDelayDel(CONN_REQUEST_TIME_OUT);
            RoleNegoStateOnResponseRecv((P2pRespMsg *)param);
            break;
        case WAIT_ROLE_NEG_TIME_OUT:
            P2pLinkFsmTransactState(g_p2pLinkNegoFsm.fsm, g_p2pLinkNegoState + P2PLINK_NEG_IDLE);
            break;
        case CONN_REQUEST:
            if (IsSamePeerDevice((cJSON *)param)) {
                P2pLinkFsmMsgProcDelayDel(WAIT_ROLE_NEG_TIME_OUT);
                OnConnectRequestRecv((cJSON *)param);
            } else {
                PostBusyConnResponse();
            }
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "unsupport message type %d in nego state.", msgType);
            break;
    }
}

static void P2pLinkNeoConnResponseProc(int64_t authId, const cJSON *data)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "recv conn response.");
    P2pRespMsg *response = NULL;
    int32_t contentType;
    if (!GetJsonObjectNumberItem(data, KEY_CONTENT_TYPE, &contentType)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get content type from json failed.");
        return;
    }
    if (contentType == CONTENT_TYPE_GO_INFO) {
        response = (P2pRespMsg *)SoftBusCalloc(sizeof(P2pRespMsg) + sizeof(GoInfo));
    } else if (contentType == CONTENT_TYPE_GC_INFO) {
        response = (P2pRespMsg *)SoftBusCalloc(sizeof(P2pRespMsg) + sizeof(GcInfo));
    } else {
        response = (P2pRespMsg *)SoftBusCalloc(sizeof(P2pRespMsg));
    }

    if (response == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "calloc failed.");
        return;
    }

    if (P2plinkUnpackRepsonseMsg(data, contentType, response) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "unpack p2p link negotiation response message failed.");
        SoftBusFree(response);
        return;
    }

    if (strcmp(response->myMac, g_p2pLinkNegoFsm.linkInfo.peerMac) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "recv conn response, peerMac is not correct.");
        SoftBusFree(response);
        return;
    }

    P2pLinkFsmMsgProc(g_p2pLinkNegoFsm.fsm, CONN_RESPONSE, (void *)response);
    SoftBusFree(response);
}

static void P2pLinkNeoConnRequestProc(int64_t authId, const cJSON *data)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "recv conn request.");
    if (!P2pLinkIsEnable()) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "recv p2p link negotiation msg, p2p link is not enable.");
        return;
    }

    char peerMac[P2P_MAC_LEN] = {0};
    if (!GetJsonObjectStringItem(data, KEY_MAC, peerMac, sizeof(peerMac))) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get peer mac failed");
        return;
    }

    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "recv conn request, authId = %" PRId64 ".", authId);
    g_p2pLinkNegoFsm.linkInfo.authId = authId;

    if (P2pLinkIsDisconnectState() == true) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "local dev is disconnecting state, reponse busy msg to peer");
        PostBusyConnResponse();
        return;
    }
    P2pLinkFsmMsgProc(g_p2pLinkNegoFsm.fsm, CONN_REQUEST, (void *)data);
}

void P2pLinkNegoMsgProc(int64_t authId, int32_t cmdType, const cJSON *data)
{
    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "p2p link negotiation data is null.");
        return;
    }

    if (cmdType == CMD_CONNECT_RESPONSE) {
        P2pLinkNeoConnResponseProc(authId, data);
    } else if (cmdType == CMD_CONNECT_REQUEST) {
        P2pLinkNeoConnRequestProc(authId, data);
    }
}

void P2pLinkNegoOnGroupChanged(const P2pLinkGroup *group)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "p2p link negotiation recv group changed.");
    if (group == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "group is null.");
        return;
    }

    P2pLinkFsmMsgProc(g_p2pLinkNegoFsm.fsm, MAGICLINK_ON_GROUP_CHANGED, (void *)group);
}

void P2pLinkNegoOnConnectState(int32_t state)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "p2p link negotiation recv connect state changed.");
    P2pLinkFsmMsgProc(g_p2pLinkNegoFsm.fsm, MAGICLINK_ON_CONNECTED, (void *)&state);
}

P2pLinkNegoState GetP2pLinkNegoStatus(void)
{
    uint8_t state;
    for (state = 0; state < P2PLINK_NEG_MAX_STATE; state++) {
        if (g_p2pLinkNegoFsm.fsm->currentState == (g_p2pLinkNegoState + state)) {
            break;
        }
    }

    return state;
}

char *P2pLinkNegoGetCurrentPeerMac(void)
{
    return g_p2pLinkNegoFsm.linkInfo.peerMac;
}

void P2pLinkNegoStart(const P2pLinkNegoConnInfo *connInfo)
{
    P2pLinkFsmMsgProc(g_p2pLinkNegoFsm.fsm, START_NEGOTIATION, (void *)connInfo);
}

void P2pLinkNegoStop(void)
{
    P2pLinkFsmMsgProcDelayDel(CONN_REQUEST_TIME_OUT);
    P2pLinkFsmMsgProcDelayDel(MAGICLINK_CONN_GROUP_TIME_OUT);
    P2pLinkFsmMsgProcDelayDel(MAGICLINK_CREATE_GROUP_TIME_OUT);
    P2pLinkFsmMsgProcDelayDel(WAIT_CONN_TIME_OUT);
    P2pLinkFsmMsgProcDelayDel(WAIT_ROLE_NEG_TIME_OUT);
    P2pLinkFsmMsgProcDelayDel(DHCP_TIME_OUT);
    if (g_p2pLinkNegoFsm.linkInfo.hasConnectGroup) {
        P2pLinkRemoveGcGroup();
    }
    if (g_p2pLinkNegoFsm.linkInfo.hasCreatedGroup) {
        P2pLinkRemoveGroup();
    }
    P2pLinkFsmTransactState(g_p2pLinkNegoFsm.fsm, g_p2pLinkNegoState + P2PLINK_NEG_IDLE);
}

int32_t P2pLinkNegoInit(const P2pLinkNegoCb *callback)
{
    if (callback == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return SOFTBUS_ERR;
    }
    (void)memset_s(&g_p2pLinkNegoCb, sizeof(P2pLinkNegoCb), 0, sizeof(P2pLinkNegoCb));
    if (memcpy_s(&g_p2pLinkNegoCb, sizeof(P2pLinkNegoCb), callback, sizeof(P2pLinkNegoCb)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "memcpy_s negotiation callback failed.");
        return SOFTBUS_ERR;
    }

    (void)memset_s(&g_p2pLinkNegoFsm, sizeof(P2pLinkNegoFsm), 0, sizeof(P2pLinkNegoFsm));
    g_p2pLinkNegoFsm.fsm = (FsmStateMachine *)SoftBusCalloc(sizeof(FsmStateMachine));
    if (g_p2pLinkNegoFsm.fsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "calloc failed.");
        return SOFTBUS_MEM_ERR;
    }

    if (P2pLinkFsmInit(g_p2pLinkNegoFsm.fsm) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "p2p link fsm init failed.");
        SoftBusFree(g_p2pLinkNegoFsm.fsm);
        return SOFTBUS_ERR;
    }

    for (int32_t i = 0; i < P2PLINK_NEG_MAX_STATE; i++) {
        P2pLinkFsmAddState(g_p2pLinkNegoFsm.fsm, &g_p2pLinkNegoState[i]);
    }

    P2pLinkFsmStart(g_p2pLinkNegoFsm.fsm, g_p2pLinkNegoState + P2PLINK_NEG_IDLE);

    return SOFTBUS_OK;
}