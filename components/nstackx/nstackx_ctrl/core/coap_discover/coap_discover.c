/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#include "coap_discover.h"
#include <errno.h>
#include <stdatomic.h>
#include <string.h>
#include <securec.h>

#include "coap_app.h"
#include "coap_client.h"
#include "nstackx_dfinder_log.h"
#include "nstackx_dfinder_mgt_msg_log.h"
#include "nstackx_util.h"
#include "nstackx_timer.h"
#include "nstackx_error.h"
#include "nstackx_device.h"
#include "json_payload.h"
#include "nstackx_statistics.h"
#include "nstackx_device_local.h"
#include "nstackx_device_remote.h"

#define TAG "nStackXCoAP"

#define COAP_URI_BUFFER_LENGTH 64 /* the size of the buffer or variable used to save uri. */
#define COAP_MAX_NUM_SUBSCRIBE_MODULE_COUNT 32 /* the maximum count of subscribed module */

#define COAP_RECV_COUNT_INTERVAL 1000
#define COAP_DISVOCER_MAX_RATE 200
#define COAP_MSGID_SURVIVAL_SECONDS 100
#define COAP_MAX_MSGID_RESERVE_NUM 100

typedef struct {
    coap_mid_t msgId;
    struct timespec recvTime;
} MsgIdRecord;

typedef struct {
    MsgIdRecord msgIdRecord[COAP_MAX_MSGID_RESERVE_NUM];
    uint32_t startIdx;
    uint32_t endIdx;
} MsgIdList;

static int g_resourceFlags = COAP_RESOURCE_FLAGS_NOTIFY_CON;
static uint32_t g_coapMaxDiscoverCount = COAP_DEFAULT_DISCOVER_COUNT;
static uint32_t g_coapDiscoverType = COAP_BROADCAST_TYPE_DEFAULT;

static uint8_t g_userRequest;
static uint8_t g_forceUpdate;
static Timer *g_discoverTimer = NULL;
static uint32_t g_discoverCount;
static uint32_t g_coapUserMaxDiscoverCount;
static uint32_t g_coapUserDiscoverInterval;
static uint32_t *g_coapIntervalArr = NULL;
static uint32_t g_coapDiscoverTargetCount;
static Timer *g_recvRecountTimer = NULL;
static uint32_t g_recvDiscoverMsgNum;
static MsgIdList *g_msgIdList = NULL;
static atomic_uint_fast8_t g_subscribeCount;

static uint16_t *g_notificationIntervals = NULL;
static uint8_t g_notificationTargetCnt = 0;
static uint8_t g_notificationRunCnt = 0;
static Timer *g_notificationTimer = NULL;

#ifdef DFINDER_SUPPORT_SET_SCREEN_STATUS
static bool g_isScreenOn = true;

void SetScreenStatus(bool isScreenOn)
{
    g_isScreenOn = isScreenOn;
}
#endif

static int32_t CoapUriParse(const char *uriString, coap_uri_t *uriPtr)
{
    coap_uri_t localUri;

    (void)memset_s(&localUri, sizeof(localUri), 0, sizeof(localUri));
    if ((uriString == NULL) || (uriPtr == NULL)) {
        return NSTACKX_EFAILED;
    }

    if (coap_split_uri((unsigned char *)uriString, strlen(uriString), &localUri) < 0) {
        DFINDER_LOGE(TAG, "invalid CoAP URI");
        return NSTACKX_EFAILED;
    }
#ifdef DFINDER_SUPPORT_MULTI_COAP_SCHEME
    if (!coap_dtls_is_supported() && localUri.scheme == COAP_URI_SCHEME_COAPS) {
        DFINDER_LOGE(TAG, "coap uri sheme coaps with no dtls support");
        return NSTACKX_EFAILED;
    }
    if (((localUri.scheme == COAP_URI_SCHEME_COAPS_TCP) || (localUri.scheme == COAP_URI_SCHEME_COAPS)) &&
        !coap_tls_is_supported()) {
        DFINDER_LOGE(TAG, "coaps + tcp uri scheme not supported in this version of libcoap");
        return NSTACKX_EFAILED;
    }
#else
    if (localUri.scheme != COAP_URI_SCHEME_COAP) {
        DFINDER_LOGE(TAG, "coaps uri scheme not supported in this version of libcoap");
        return NSTACKX_EFAILED;
    }
#endif
    (void)memcpy_s(uriPtr, sizeof(coap_uri_t), &localUri, sizeof(coap_uri_t));
    return NSTACKX_EOK;
}

static coap_pdu_t *CoapPackToPdu(const CoapRequest *coapRequest, const coap_uri_t *uriPtr, coap_session_t *session)
{
    coap_pdu_t *pdu = NULL;
    if (coapRequest == NULL || coapRequest->remoteUrl == NULL || session == NULL) {
        return NULL;
    }
    pdu = coap_new_pdu(coapRequest->type, coapRequest->code, session);
    if (pdu == NULL) {
        return NULL;
    }
    if (coapRequest->tokenLength) {
        if (!coap_add_token(pdu, coapRequest->tokenLength, coapRequest->token)) {
            DFINDER_LOGW(TAG, "cannot add token to request");
        }
    }
    coap_add_option(pdu, COAP_OPTION_URI_HOST, uriPtr->host.length, uriPtr->host.s);
    coap_add_option(pdu, COAP_OPTION_URI_PATH, uriPtr->path.length, uriPtr->path.s);
    if (coapRequest->dataLength) {
        coap_add_data(pdu, coapRequest->dataLength, (uint8_t *)(coapRequest->data));
    }

    return pdu;
}

static void FillCoapRequest(CoapRequest *coapRequest, uint8_t coapType, const char *url, char *data, size_t dataLen)
{
    (void)memset_s(coapRequest, sizeof(CoapRequest), 0, sizeof(CoapRequest));
    coapRequest->type = coapType;
    coapRequest->code = COAP_REQUEST_POST;
    coapRequest->remoteUrl = url;
    coapRequest->data = data;
    coapRequest->dataLength = dataLen;
}

static int32_t CoapSendRequestEx(CoapCtxType *ctx, uint8_t coapType, const char *url, char *data, size_t dataLen)
{
    CoapRequest coapRequest;
    coap_session_t *session = NULL;
    coap_address_t dst = {0};
    coap_str_const_t remote;
    int32_t tid;
    int32_t res;
    coap_pdu_t *pdu = NULL;
    coap_uri_t coapUri;
    CoapServerParameter coapServerParameter = {0};

    FillCoapRequest(&coapRequest, coapType, url, data, dataLen);

    (void)memset_s(&remote, sizeof(remote), 0, sizeof(remote));
    (void)memset_s(&coapUri, sizeof(coapUri), 0, sizeof(coapUri));
    if (CoapUriParse(coapRequest.remoteUrl, &coapUri) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "fail to parse uri");
        return NSTACKX_EFAILED;
    }
    remote = coapUri.host;
    res = CoapResolveAddress(&remote, &dst.addr.sa);
    if (res < 0) {
        DFINDER_LOGE(TAG, "fail to resolve address");
        return NSTACKX_EFAILED;
    }

    dst.size = (uint32_t)res;
    dst.addr.sin.sin_port = htons(COAP_DEFAULT_PORT);
    coapServerParameter.proto = COAP_PROTO_UDP;
    coapServerParameter.dst = &dst;
    session = CoapGetSession(ctx->ctx, GetLocalIfaceIpStr(ctx->iface), COAP_SRV_DEFAULT_PORT, &coapServerParameter);
    if (session == NULL) {
        DFINDER_LOGE(TAG, "get client session failed");
        return NSTACKX_EFAILED;
    }
    pdu = CoapPackToPdu(&coapRequest, &coapUri, session);
    if (pdu == NULL) {
        DFINDER_LOGE(TAG, "pack to pdu failed");
        goto SESSION_RELEASE;
    }
    DFINDER_LOGD("MYCOAP", "send coap pdu mid: %d", coap_pdu_get_mid(pdu));
    DFINDER_MGT_REQ_LOG(&coapRequest);
    tid = coap_send(session, pdu);
    if (tid == COAP_INVALID_MID) {
        DFINDER_LOGE(TAG, "coap send failed");
        goto SESSION_RELEASE;
    }

    coap_session_release(session);
    return NSTACKX_EOK;

SESSION_RELEASE:
    coap_session_release(session);
    return NSTACKX_EFAILED;
}

static int32_t CoapSendRequest(CoapCtxType *ctx, uint8_t coapType, const char *url, char *data, size_t dataLen)
{
    int32_t ret = CoapSendRequestEx(ctx, coapType, url, data, dataLen);
    if (ret != NSTACKX_EOK) {
        IncStatistics(STATS_SEND_REQUEST_FAILED);
    }
    return ret;
}

static int32_t CoapResponseService(CoapCtxType *ctx, const char *remoteUrl, uint8_t businessType)
{
    char *data = PrepareServiceDiscover(GetLocalIfaceIpStr(ctx->iface), NSTACKX_FALSE, businessType);
    if (data == NULL) {
        DFINDER_LOGE(TAG, "prepare service failed");
        return NSTACKX_EFAILED;
    }

    // for internal auto-reply unicast, make its type to NON-confirmable
    // reliablity depends on the number of broadcast
    uint8_t coapMsgType = (ShouldAutoReplyUnicast(businessType) == NSTACKX_TRUE) ? COAP_MESSAGE_NON : COAP_MESSAGE_CON;
    int32_t ret = CoapSendRequest(ctx, coapMsgType, remoteUrl, data, strlen(data) + 1);

    cJSON_free(data);
    return ret;
}

static void IncreaseRecvDiscoverNum(void)
{
    if (g_recvDiscoverMsgNum < UINT32_MAX) {
        g_recvDiscoverMsgNum++;
    }
}

static int32_t HndPostServiceDiscoverInner(const coap_pdu_t *request, char **remoteUrl, DeviceInfo *deviceInfo)
{
    size_t size;
    const uint8_t *buf = NULL;
    IncreaseRecvDiscoverNum();
    if (g_recvDiscoverMsgNum > COAP_DISVOCER_MAX_RATE) {
        DFINDER_LOGD(TAG, "too many dicover messages received");
        return NSTACKX_EFAILED;
    }
    if (coap_get_data(request, &size, &buf) == 0 || size == 0 || size > COAP_RXBUFFER_SIZE) {
        DFINDER_LOGE(TAG, "coap_get_data failed, size: %zu", size);
        return NSTACKX_EFAILED;
    }
    if (GetServiceDiscoverInfo(buf, size, deviceInfo, remoteUrl) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }
    /* receive coap broadcast, set peer device's discovery type to passive,
     * to identify the local device is in passive discovery
     */
    deviceInfo->discoveryType = (*remoteUrl != NULL) ? NSTACKX_DISCOVERY_TYPE_PASSIVE : NSTACKX_DISCOVERY_TYPE_ACTIVE;
    if (deviceInfo->mode == PUBLISH_MODE_UPLINE || deviceInfo->mode == PUBLISH_MODE_OFFLINE) {
        DFINDER_LOGD(TAG, "peer is not DISCOVER_MODE");
        NSTACKX_DeviceInfo deviceList;
        (void)memset_s(&deviceList, sizeof(NSTACKX_DeviceInfo), 0, sizeof(NSTACKX_DeviceInfo));
        if (GetNotifyDeviceInfo(&deviceList, deviceInfo) == NSTACKX_EOK) {
            NotifyDeviceFound(&deviceList, 1);
        } else {
            DFINDER_LOGE(TAG, "GetNotifyDeviceInfo failed");
        }
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static void CoapResponseServiceDiscovery(const char *remoteUrl, const coap_context_t *currCtx,
    coap_pdu_t *response, uint8_t businessType)
{
    if (remoteUrl != NULL) {
        if (ShouldAutoReplyUnicast(businessType) == NSTACKX_TRUE) {
            CoapCtxType *ctx = CoapGetCoapCtxType(currCtx);
            if (ctx != NULL) {
                (void)CoapResponseService(ctx, remoteUrl, businessType);
            }
        }
    } else {
        coap_pdu_set_code(response, COAP_RESPONSE_CODE_CREATED);
    }
}

static int32_t HndPostServiceDiscoverEx(coap_session_t *session, const coap_pdu_t *request, coap_pdu_t *response)
{
    int32_t ret = NSTACKX_EFAILED;
    coap_context_t *currCtx = coap_session_get_context(session);
    if (currCtx == NULL) {
        DFINDER_LOGE(TAG, "coap_session_get_context return null");
        return ret;
    }
    char *remoteUrl = NULL;
    DeviceInfo *deviceInfo = calloc(1, sizeof(DeviceInfo));
    if (deviceInfo == NULL) {
        DFINDER_LOGE(TAG, "calloc for device info failed");
        return ret;
    }

    const CoapCtxType *coapCtx = CoapGetCoapCtxType(currCtx);
    if (coapCtx == NULL) {
        DFINDER_LOGE(TAG, "get coap ctx type failed");
        goto L_ERR;
    }

    if (strcpy_s(deviceInfo->networkName, sizeof(deviceInfo->networkName),
        GetLocalIfaceName(coapCtx->iface)) != EOK) {
        DFINDER_LOGE(TAG, "copy network name failed");
        goto L_ERR;
    }

    if (HndPostServiceDiscoverInner(request, &remoteUrl, deviceInfo) != NSTACKX_EOK) {
        goto L_ERR;
    }
    if (GetModeInfo() == PUBLISH_MODE_UPLINE || GetModeInfo() == PUBLISH_MODE_OFFLINE) {
        DFINDER_LOGD(TAG, "local is not DISCOVER_MODE");
        goto L_ERR;
    }

    uint8_t receiveBcast = (remoteUrl == NULL) ? NSTACKX_FALSE : NSTACKX_TRUE;
    if (ReportDiscoveredDevice(coapCtx, deviceInfo, g_forceUpdate, receiveBcast) != NSTACKX_EOK) {
        goto L_ERR;
    }

    g_forceUpdate = NSTACKX_FALSE;
    if (deviceInfo->mode == PUBLISH_MODE_PROACTIVE) {
        DFINDER_LOGD(TAG, "peer is PUBLISH_MODE_PROACTIVE");
        goto L_ERR;
    }
    CoapResponseServiceDiscovery(remoteUrl, currCtx, response, deviceInfo->businessType);

    ret = NSTACKX_EOK;
L_ERR:
    free(deviceInfo);
    free(remoteUrl);
    return ret;
}

static void HndPostServiceDiscover(coap_resource_t *resource, coap_session_t *session,
    const coap_pdu_t *request, const coap_string_t *query, coap_pdu_t *response)
{
    Coverity_Tainted_Set((void *)request);

    (void)resource;
    (void)query;
#ifdef DFINDER_SUPPORT_SET_SCREEN_STATUS
    if (request == NULL || response == NULL || !g_isScreenOn) {
#else
    if (request == NULL || response == NULL) {
#endif
        DFINDER_LOGD(TAG, "invalid params");
        return;
    }
    DFINDER_LOGD("MYCOAP", "recv coap pdu mid: %d", coap_pdu_get_mid(request));
    if (HndPostServiceDiscoverEx(session, request, response) != NSTACKX_EOK) {
        IncStatistics(STATS_HANDLE_DEVICE_DISCOVER_MSG_FAILED);
    }
}

static void DeleteOverTimeMsgIdRecord(MsgIdList *msgIdList, struct timespec *curTime)
{
    uint32_t i = msgIdList->startIdx;
    if (msgIdList->startIdx >= COAP_MAX_MSGID_RESERVE_NUM || msgIdList->endIdx >= COAP_MAX_MSGID_RESERVE_NUM) {
        return;
    }
    uint32_t cycleTimes = 0;
    while (NSTACKX_TRUE) {
        if (curTime->tv_sec - msgIdList->msgIdRecord[i].recvTime.tv_sec < COAP_MSGID_SURVIVAL_SECONDS) {
            return;
        }
        if (i == msgIdList->endIdx) {
            msgIdList->startIdx = COAP_MAX_MSGID_RESERVE_NUM;
            msgIdList->endIdx = COAP_MAX_MSGID_RESERVE_NUM;
            return;
        }
        msgIdList->startIdx = (msgIdList->startIdx + 1) % COAP_MAX_MSGID_RESERVE_NUM;
        i = msgIdList->startIdx;
        if (cycleTimes > COAP_MAX_MSGID_RESERVE_NUM) {
            IncStatistics(STATS_DROP_MSG_ID);
            DFINDER_LOGE(TAG, "cycle too many times, error must occurred and init msgList");
            msgIdList->startIdx = COAP_MAX_MSGID_RESERVE_NUM;
            msgIdList->endIdx = COAP_MAX_MSGID_RESERVE_NUM;
            break;
        }
        cycleTimes++;
    }
}

static void AddMsgIdRecord(MsgIdList *msgIdList, coap_mid_t msgId, struct timespec *curTime)
{
    int32_t ret;
    uint32_t idx;
    if (msgIdList->endIdx == COAP_MAX_MSGID_RESERVE_NUM) {
        msgIdList->endIdx = 0;
        msgIdList->startIdx = 0;
        idx = 0;
    } else {
        idx = (msgIdList->endIdx + 1) % COAP_MAX_MSGID_RESERVE_NUM;
        if (idx == msgIdList->startIdx) {
            msgIdList->startIdx = (msgIdList->startIdx + 1) % COAP_MAX_MSGID_RESERVE_NUM;
        }
    }
    msgIdList->msgIdRecord[idx].msgId = msgId;
    ret = memcpy_s(&msgIdList->msgIdRecord[idx].recvTime, sizeof(struct timespec), curTime, sizeof(struct timespec));
    if (ret != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "set msg id time error");
        return;
    }
    msgIdList->endIdx = idx;
}

static uint8_t RefreshMsgIdList(coap_mid_t msgId)
{
    struct timespec curTime;
    uint32_t i;
    if (g_msgIdList == NULL) {
        return NSTACKX_TRUE;
    }
    ClockGetTime(CLOCK_MONOTONIC, &curTime);
    DeleteOverTimeMsgIdRecord(g_msgIdList, &curTime);
    if (g_msgIdList->startIdx >= COAP_MAX_MSGID_RESERVE_NUM || g_msgIdList->endIdx >= COAP_MAX_MSGID_RESERVE_NUM) {
        AddMsgIdRecord(g_msgIdList, msgId, &curTime);
        return NSTACKX_TRUE;
    }
    i = g_msgIdList->startIdx;
    uint32_t cycleTimes = 0;
    while (NSTACKX_TRUE) {
        if (g_msgIdList->msgIdRecord[i].msgId == msgId) {
            (void)memcpy_s(&g_msgIdList->msgIdRecord[i].recvTime, sizeof(struct timespec), &curTime,
                           sizeof(struct timespec));
            return NSTACKX_FALSE;
        }
        if (i == g_msgIdList->endIdx) {
            break;
        }
        i = (i + 1) % COAP_MAX_MSGID_RESERVE_NUM;
        if (cycleTimes > COAP_MAX_MSGID_RESERVE_NUM) {
            IncStatistics(STATS_DROP_MSG_ID);
            DFINDER_LOGE(TAG, "cycle too many times, error must occurred and init msgList");
            g_msgIdList->startIdx = COAP_MAX_MSGID_RESERVE_NUM;
            g_msgIdList->endIdx = COAP_MAX_MSGID_RESERVE_NUM;
            break;
        }
        cycleTimes++;
    }
    AddMsgIdRecord(g_msgIdList, msgId, &curTime);
    return NSTACKX_TRUE;
}

static uint16_t GetServiceMsgFrameLen(const uint8_t *frame, uint16_t size)
{
    uint16_t frameLen, ret;
    if (size < sizeof(frameLen)) {
        DFINDER_LOGE(TAG, "input size %u is too small", size);
        return 0;
    }
    if (memcpy_s(&frameLen, sizeof(frameLen), frame, sizeof(frameLen)) != EOK) {
        DFINDER_LOGE(TAG, "memcpy frame len failed");
        return 0;
    }
    ret = ntohs(frameLen);
    if (size < ret) {
        DFINDER_LOGE(TAG, "input size %u is smaller than decoded frame len %u", size, ret);
        return 0;
    }
    return ret;
}

static uint16_t GetUnitInfo(const uint8_t *data, uint16_t dataLen, uint8_t *outBuf, uint32_t outLen, uint8_t unitType)
{
    if (dataLen < sizeof(CoapMsgUnit)) {
        DFINDER_LOGE(TAG, "dataLen %u is too small", dataLen);
        return 0;
    }
    CoapMsgUnit *unit = (CoapMsgUnit *)data;
    if (unit->type != unitType) {
        DFINDER_LOGE(TAG, "unit type %u does match target type %u", unit->type, unitType);
        return 0;
    }
    uint16_t valueLen = ntohs(unit->len);
    if (valueLen == 0 || valueLen > outLen || valueLen + sizeof(CoapMsgUnit) > dataLen) {
        DFINDER_LOGE(TAG, "valueLen %u is illegal", valueLen);
        return 0;
    }
    if (memcpy_s(outBuf, outLen, unit->value, valueLen) != EOK) {
        DFINDER_LOGE(TAG, "memcpy unit->value failed");
        return 0;
    }
    if (unitType == COAP_MODULE_NAME_TYPE || unitType == COAP_DEVICE_ID_TYPE) {
        if (outBuf[valueLen - 1] != '\0') {
            DFINDER_LOGE(TAG, "uint type is %u but value is not end with 0", unitType);
            return 0;
        }
    }
    return valueLen;
}

static uint16_t ParseServiceMsgFrame(const uint8_t *frame, size_t size, char *moduleName, char *deviceId,
                                     uint8_t **msg)
{
    if (frame == NULL || size == 0) {
        return 0;
    }
    uint16_t frameLen = GetServiceMsgFrameLen(frame, size);
    if (frameLen < sizeof(frameLen) + sizeof(CoapMsgUnit)) {
        return 0;
    }

    /* get modulename info */
    uint16_t len = sizeof(frameLen);
    uint16_t moduleNameLen = GetUnitInfo(frame + len, frameLen - len, (uint8_t *)moduleName,
                                         NSTACKX_MAX_MODULE_NAME_LEN, COAP_MODULE_NAME_TYPE);
    if (moduleNameLen == 0 || moduleNameLen + sizeof(CoapMsgUnit) >= frameLen - len) {
        return 0;
    }

    /* get deviceIdLen info */
    len += moduleNameLen + sizeof(CoapMsgUnit);
    uint16_t deviceIdLen = GetUnitInfo(frame + len, frameLen - len, (uint8_t *)deviceId,
                                       NSTACKX_MAX_DEVICE_ID_LEN, COAP_DEVICE_ID_TYPE);
    if (deviceIdLen == 0 || deviceIdLen + sizeof(CoapMsgUnit) >= frameLen - len) {
        return 0;
    }

    /* get msg info */
    len += deviceIdLen + sizeof(CoapMsgUnit);
    uint8_t *msgPtr = (uint8_t *)calloc(1U, frameLen - len);
    if (msgPtr == NULL) {
        return 0;
    }
    uint16_t msgLen = GetUnitInfo(frame + len, frameLen - len, msgPtr, frameLen - len, COAP_MSG_TYPE);
    if (msgLen == 0) {
        free(msgPtr);
        return 0;
    }
    *msg = msgPtr;
    return msgLen;
}

static int32_t HndPostServiceMsgEx(coap_resource_t *resource, coap_session_t *session,
    const coap_pdu_t *request, const coap_string_t *query, coap_pdu_t *response)
{
    Coverity_Tainted_Set((void *)request);

    (void)resource;
    (void)session;
    (void)query;
    if (request == NULL || response == NULL) {
        return NSTACKX_EFAILED;
    }
    char deviceId[NSTACKX_MAX_DEVICE_ID_LEN] = {0};
    char moduleName[NSTACKX_MAX_MODULE_NAME_LEN] = {0};
    uint8_t *msg = NULL;
    const uint8_t *buf = NULL;
    uint16_t msgLen;
    size_t size;

    if (coap_get_data(request, &size, &buf) == 0 || size == 0 || size > COAP_RXBUFFER_SIZE) {
        return NSTACKX_EFAILED;
    }

    if (!RefreshMsgIdList(coap_pdu_get_mid(request))) {
        DFINDER_LOGE(TAG, "repeated msg id");
        return NSTACKX_EFAILED;
    }

    DFINDER_LOGD(TAG, "handling post service msg request");
    msgLen = ParseServiceMsgFrame(buf, size, moduleName, deviceId, &msg);
    if (msgLen == 0) {
        DFINDER_LOGD(TAG, "parse service msg frame error");
        return NSTACKX_EFAILED;
    }
    const coap_address_t *addPtr = coap_session_get_addr_remote(session);
    if (addPtr == NULL) {
        DFINDER_LOGE(TAG, "coap session get remote addr failed");
        free(msg);
        return NSTACKX_EFAILED;
    }
    char srcIp[NSTACKX_MAX_IP_STRING_LEN] = {0};
    if (inet_ntop(AF_INET, &((addPtr->addr).sin.sin_addr), srcIp, sizeof(srcIp)) == NULL) {
        free(msg);
        return NSTACKX_EFAILED;
    }
    NotifyMsgReceived(moduleName, deviceId, msg, msgLen, srcIp);

    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CREATED);
    free(msg);
    return NSTACKX_EOK;
}

static void HndPostServiceMsg(coap_resource_t *resource, coap_session_t *session,
    const coap_pdu_t *request, const coap_string_t *query, coap_pdu_t *response)
{
    if (HndPostServiceMsgEx(resource, session, request, query, response) != NSTACKX_EOK) {
        IncStatistics(STATS_HANDLE_SERVICE_MSG_FAILED);
    }
}

static int32_t CoapPostServiceDiscoverEx(CoapCtxType *ctx)
{
    char broadcastIp[NSTACKX_MAX_IP_STRING_LEN] = {0};
    if (GetBroadcastIp(ctx->iface, broadcastIp, sizeof(broadcastIp)) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "get broadcast ip failed");
        return NSTACKX_EFAILED;
    }

    char discoverUri[COAP_URI_BUFFER_LENGTH] = {0};
    if (sprintf_s(discoverUri, sizeof(discoverUri), "coap://%s/%s", broadcastIp, COAP_DEVICE_DISCOVER_URI) < 0) {
        DFINDER_LOGE(TAG, "formate uri failed");
        return NSTACKX_EFAILED;
    }

    char *data = PrepareServiceDiscover(GetLocalIfaceIpStr(ctx->iface), NSTACKX_TRUE, GetLocalDeviceBusinessType());
    if (data == NULL) {
        DFINDER_LOGE(TAG, "prepare json failed");
        return NSTACKX_EFAILED;
    }

    int ret = CoapSendRequest(ctx, COAP_MESSAGE_NON, discoverUri, data, strlen(data) + 1);
    cJSON_free(data);
    return ret;
}

static int32_t CoapPostServiceDiscover(void)
{
    List *pos = NULL;
    List *head = GetCoapContextList();
    int successCnt = 0;
    LIST_FOR_EACH(pos, head) {
        int ret = CoapPostServiceDiscoverEx((CoapCtxType *)pos);
        if (ret == NSTACKX_EOK) {
            successCnt++;
        }
    }

    if (successCnt == 0) {
        DFINDER_LOGE(TAG, "no iface send request");
        IncStatistics(STATS_POST_SD_REQUEST_FAILED);
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

static uint32_t GetUserDefineInterval(uint32_t discoverCount)
{
    if (discoverCount >= (g_coapMaxDiscoverCount - 1)) {
        DFINDER_LOGD(TAG, "discover end");
        return 0;
    }
    return g_coapIntervalArr[discoverCount];
}

static uint32_t GetDiscoverInterval(uint32_t discoverCount)
{
    switch (g_coapDiscoverType) {
        case COAP_BROADCAST_TYPE_USER:
            return g_coapUserDiscoverInterval;
        case COAP_BROADCAST_TYPE_USER_DEFINE_INTERVAL:
            return GetUserDefineInterval(discoverCount);
        case COAP_BROADCAST_TYPE_DEFAULT:
            return GetDefaultDiscoverInterval(discoverCount);
        default:
            return GetDefaultDiscoverInterval(discoverCount);
    }
}

static void CoapServiceDiscoverStop(void)
{
    g_forceUpdate = NSTACKX_FALSE;
    g_discoverCount = 0;
    SetModeInfo(DISCOVER_MODE);
#ifdef DFINDER_SAVE_DEVICE_LIST
    ClearRemoteDeviceListBackup();
    DFINDER_LOGD(TAG, "clear device list backup");
#endif
    g_coapDiscoverType = COAP_BROADCAST_TYPE_DEFAULT;
    g_coapMaxDiscoverCount = COAP_DEFAULT_DISCOVER_COUNT;
    /* Can call PostDeviceFindWrapper() to notify user if needed. */
    g_userRequest = NSTACKX_FALSE;
    // release interval array
    if (g_coapIntervalArr != NULL) {
        free(g_coapIntervalArr);
        g_coapIntervalArr = NULL;
    }
}

static void CoapServiceDiscoverTimerHandle(void *argument)
{
    uint32_t discoverInterval;

    (void)argument;

    if (g_discoverCount >= g_coapDiscoverTargetCount || !IsCoapContextReady()) {
        IncStatistics(STATS_ABORT_SD);
        CoapServiceDiscoverStop();
        return;
    }

    if (CoapPostServiceDiscover() != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "failed when posting service discover request");
        goto L_ERR_DISCOVER;
    }

    /* Restart timer */
    discoverInterval = GetDiscoverInterval(g_discoverCount);

    ++g_discoverCount;
    if (TimerSetTimeout(g_discoverTimer, discoverInterval, NSTACKX_FALSE) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "failed to set timer for service discovery");
        goto L_ERR_DISCOVER;
    }
    return;

L_ERR_DISCOVER:
    IncStatistics(STATS_ABORT_SD);
    /* Abort service discover by not starting timer. */
    DFINDER_LOGE(TAG, "abort service discovery, have tried %u request", g_discoverCount);
    /* Reset g_discoverCount to allow new request from user. */
    g_discoverCount = 0;
    return;
}

void CoapInitSubscribeModuleInner(void)
{
    g_subscribeCount = 0;
    return;
}

void CoapSubscribeModuleInner(uint8_t isSubscribe)
{
    if (isSubscribe && (g_subscribeCount < COAP_MAX_NUM_SUBSCRIBE_MODULE_COUNT)) {
        g_subscribeCount++;
    }
    return;
}

void CoapUnsubscribeModuleInner(uint8_t isUnsubscribe)
{
    if (isUnsubscribe && (g_subscribeCount > 0)) {
        g_subscribeCount--;
    }
}

static void SetCoapMaxDiscoverCount(void)
{
    switch (g_coapDiscoverType) {
        case COAP_BROADCAST_TYPE_DEFAULT:
            g_coapMaxDiscoverCount = COAP_DEFAULT_DISCOVER_COUNT;
            break;
        case COAP_BROADCAST_TYPE_USER:
        case COAP_BROADCAST_TYPE_USER_DEFINE_INTERVAL:
            g_coapMaxDiscoverCount = g_coapUserMaxDiscoverCount;
            break;
        default:
            g_coapMaxDiscoverCount = COAP_DEFAULT_DISCOVER_COUNT;
            break;
    }
}

static void CoapServiceDiscoverFirstTime(void)
{
    SetCoapMaxDiscoverCount();
    g_coapDiscoverTargetCount = g_coapMaxDiscoverCount;
    if (CoapPostServiceDiscover() != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "failed to send service discover request");
        return;
    }

    uint32_t discoverInterval = GetDiscoverInterval(g_discoverCount);
    if (TimerSetTimeout(g_discoverTimer, discoverInterval, NSTACKX_FALSE) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "failed to set timer when doing service discover");
        return;
    }
    ++g_discoverCount;
    DFINDER_LOGI(TAG, "first time for device discover.");
}

void CoapServiceDiscoverInner(uint8_t userRequest)
{
    if (!IsCoapContextReady()) {
        IncStatistics(STATS_START_SD_FAILED);
        DFINDER_LOGI(TAG, "Network not connected when discovery inner");
        return;
    }

    if (userRequest) {
        g_userRequest = NSTACKX_TRUE;
        g_forceUpdate = NSTACKX_TRUE;
    }

    if (g_coapDiscoverTargetCount > 0 &&
        g_discoverCount >= g_coapDiscoverTargetCount) {
        g_discoverCount = 0;
        SetModeInfo(DISCOVER_MODE);
#ifdef DFINDER_SAVE_DEVICE_LIST
        ClearRemoteDeviceListBackup();
        DFINDER_LOGW(TAG, "clear device list backup");
#endif
        (void)TimerSetTimeout(g_discoverTimer, 0, NSTACKX_FALSE);
    }

    if (g_discoverCount) {
        /* Service discover is ongoing, return. */
        return;
    }
#ifdef DFINDER_SAVE_DEVICE_LIST
    /* First discover */
    BackupRemoteDeviceList();
    DFINDER_LOGW(TAG, "clear device list when discovery inner");
#endif /* END OF DFINDER_SAVE_DEVICE_LIST */
    SetModeInfo(DISCOVER_MODE);
    CoapServiceDiscoverFirstTime();
    return;
}

void CoapServiceDiscoverInnerAn(uint8_t userRequest)
{
    if (!IsCoapContextReady()) {
        IncStatistics(STATS_START_SD_FAILED);
        DFINDER_LOGI(TAG, "Network not connected when discovery inner AN");
        return;
    }

    if (userRequest) {
        g_userRequest = NSTACKX_TRUE;
    }

    if (g_discoverCount != 0) {
        g_discoverCount = 0;
        /* Service discover is ongoing, reset. */
        (void)TimerSetTimeout(g_discoverTimer, 0, NSTACKX_FALSE);
    }

    CoapServiceDiscoverFirstTime();
    return;
}

void CoapServiceDiscoverInnerConfigurable(uint8_t userRequest)
{
    if (!IsCoapContextReady()) {
        IncStatistics(STATS_START_SD_FAILED);
        DFINDER_LOGI(TAG, "Network not connected when discovery configurable");
        return;
    }

    if (userRequest) {
        g_userRequest = NSTACKX_TRUE;
        g_forceUpdate = NSTACKX_TRUE;
    }

    if (g_coapDiscoverTargetCount > 0 && g_discoverCount >= g_coapDiscoverTargetCount) {
        g_discoverCount = 0;
#ifdef DFINDER_SAVE_DEVICE_LIST
        ClearRemoteDeviceListBackup();
        DFINDER_LOGW(TAG, "clear device list backup when discovery configurable");
#endif
        (void)TimerSetTimeout(g_discoverTimer, 0, NSTACKX_FALSE);
    }

    if (g_discoverCount != 0) {
        g_discoverCount = 0;
        /* Service discover is ongoing, return. */
        (void)TimerSetTimeout(g_discoverTimer, 0, NSTACKX_FALSE);
    } else {
        /* First discover */
#ifdef DFINDER_SAVE_DEVICE_LIST
        BackupRemoteDeviceList();
        DFINDER_LOGW(TAG, "clear device list when discovery configurable");
#endif
    }
    CoapServiceDiscoverFirstTime();
    return;
}

void CoapServiceDiscoverStopInner(void)
{
    (void)TimerSetTimeout(g_discoverTimer, 0, NSTACKX_FALSE);
    CoapServiceDiscoverStop();
    DFINDER_LOGI(TAG, "device discover inner stopped");
}

uint8_t CoapDiscoverRequestOngoing(void)
{
    return ((g_discoverCount > 0 && g_userRequest) || (g_subscribeCount > 0));
}

static uint8_t *CreateServiceMsgFrame(const char *moduleName, const char *deviceId, const uint8_t *msg, uint32_t msgLen,
                                      uint16_t *dataLen)
{
    uint16_t frameLen, moduleNameUnitLen, deviceIdUnitLen, msgUnitLen, bufferLen;
    uint8_t *frame = NULL;
    uint16_t len = 0;
    CoapMsgUnit *unit = NULL;
    moduleNameUnitLen = sizeof(CoapMsgUnit) + strlen(moduleName) + 1;
    deviceIdUnitLen = sizeof(CoapMsgUnit) + strlen(deviceId) + 1;
    msgUnitLen = sizeof(CoapMsgUnit) + msgLen;
    bufferLen = sizeof(frameLen) + moduleNameUnitLen + deviceIdUnitLen + msgUnitLen;
    frameLen = htons(bufferLen);

    frame = (uint8_t *)calloc(1U, bufferLen);
    if (frame == NULL) {
        IncStatistics(STATS_CREATE_SERVICE_MSG_FAILED);
        return NULL;
    }
    if (memcpy_s(frame, bufferLen, &frameLen, sizeof(frameLen)) != EOK) {
        goto L_ERR_SEND_MSG;
    }
    len += sizeof(frameLen);

    unit = (CoapMsgUnit *)(frame + len);
    unit->type = COAP_MODULE_NAME_TYPE;
    unit->len = htons(moduleNameUnitLen - sizeof(CoapMsgUnit));
    if (memcpy_s(unit->value, bufferLen - len - sizeof(CoapMsgUnit), moduleName, strlen(moduleName) + 1) != EOK) {
        goto L_ERR_SEND_MSG;
    }
    len += moduleNameUnitLen;

    unit = (CoapMsgUnit *)(frame + len);
    unit->type = COAP_DEVICE_ID_TYPE;
    unit->len = htons(deviceIdUnitLen - sizeof(CoapMsgUnit));
    if (memcpy_s(unit->value, bufferLen - len - sizeof(CoapMsgUnit), deviceId, strlen(deviceId) + 1) != EOK) {
        goto L_ERR_SEND_MSG;
    }
    len += deviceIdUnitLen;

    unit = (CoapMsgUnit *)(frame + len);
    unit->type = COAP_MSG_TYPE;
    unit->len = htons(msgUnitLen - sizeof(CoapMsgUnit));
    if (memcpy_s(unit->value, bufferLen - len - sizeof(CoapMsgUnit), msg, msgLen) != EOK) {
        goto L_ERR_SEND_MSG;
    }
    *dataLen = bufferLen;
    return frame;
L_ERR_SEND_MSG:
    IncStatistics(STATS_CREATE_SERVICE_MSG_FAILED);
    free(frame);
    return NULL;
}

int32_t CoapSendServiceMsg(MsgCtx *msgCtx, const char *remoteIpStr, const struct in_addr *remoteIp)
{
    char uriBuffer[COAP_URI_BUFFER_LENGTH] = {0};
    uint16_t dataLen = 0;

    CoapCtxType *ctx = LocalIfaceGetCoapCtxByRemoteIp(remoteIp, msgCtx->type);
    if (ctx == NULL) {
        DFINDER_LOGE(TAG, "can not find the local iface");
        return NSTACKX_EFAILED;
    }

    if (sprintf_s(uriBuffer, sizeof(uriBuffer), "coap://%s/" COAP_SERVICE_MSG_URI, remoteIpStr) < 0) {
        DFINDER_LOGE(TAG, "sprintf_s for coap service msg uri failed");
        return NSTACKX_EFAILED;
    }

    char *data = (char *)CreateServiceMsgFrame(msgCtx->moduleName,
        GetLocalDeviceId(), msgCtx->data, msgCtx->len, &dataLen);
    if (data == NULL) {
        DFINDER_LOGE(TAG, "failed to prepare msg data");
        return NSTACKX_EFAILED;
    }

    int ret = CoapSendRequest(ctx, COAP_MESSAGE_CON, uriBuffer, data, dataLen);
    free(data);
    return ret;
}

static void CoapRecvRecountTimerHandle(void *argument)
{
    (void)argument;
    if (g_recvDiscoverMsgNum > COAP_DISVOCER_MAX_RATE) {
        DFINDER_LOGI(TAG, "received %u discover msg in this interval", g_recvDiscoverMsgNum);
    }
    g_recvDiscoverMsgNum = 0;
    return;
}

static int32_t CoapPostServiceNotificationEx(CoapCtxType *ctx)
{
    char broadcastIp[NSTACKX_MAX_IP_STRING_LEN] = {0};
    if (GetBroadcastIp(ctx->iface, broadcastIp, sizeof(broadcastIp)) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "get %s broadcast ip failed, please check nic status with ifconfig or reconnect to network",
            GetLocalIfaceName(ctx->iface));
        return NSTACKX_EFAILED;
    }
    char notificationUri[COAP_URI_BUFFER_LENGTH] = {0};
    if (sprintf_s(notificationUri, sizeof(notificationUri),
        "coap://%s/%s", broadcastIp, COAP_SERVICE_NOTIFICATION_URI) < 0) {
        DFINDER_LOGE(TAG, "format coap service notification uri failed");
        return NSTACKX_EFAILED;
    }
    char *data = PrepareServiceNotification();
    if (data == NULL) {
        DFINDER_LOGE(TAG, "prepare service notification data fail");
        return NSTACKX_EFAILED;
    }
    int32_t ret = CoapSendRequest(ctx, COAP_MESSAGE_NON, notificationUri, data, strlen(data) + 1);
    cJSON_free(data);
    return ret;
}

static int32_t CoapPostServiceNotification(void)
{
    List *pos = NULL;
    List *head = GetCoapContextList();
    int successCnt = 0;
    LIST_FOR_EACH(pos, head) {
        int32_t ret = CoapPostServiceNotificationEx((CoapCtxType *)pos);
        if (ret == NSTACKX_EOK) {
            successCnt++;
        }
    }
    if (successCnt == 0) {
        DFINDER_LOGE(TAG, "no iface to send request, coap context ready: %d", IsCoapContextReady());
        IncStatistics(STATS_POST_SD_REQUEST_FAILED);
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static inline uint16_t GetNextNotificationInterval(uint8_t runCnt)
{
    return (runCnt >= g_notificationTargetCnt) ? 0 : g_notificationIntervals[runCnt];
}

static void ResetNotificationConfig(void)
{
    g_notificationRunCnt = 0;
    g_notificationTargetCnt = 0;
    if (g_notificationIntervals != NULL) {
        free(g_notificationIntervals);
        g_notificationIntervals = NULL;
    }
}

void CoapServiceNotificationStop(void)
{
    (void)TimerSetTimeout(g_notificationTimer, 0, NSTACKX_FALSE);
    ResetNotificationConfig();
    DFINDER_LOGI(TAG, "caller stop send notifications, reset run cnt, target cnt all to 0");
}

static void CoapServiceNotificationTimerHandle(void *argument)
{
    (void)argument;
    if (!IsCoapContextReady()) {
        DFINDER_LOGE(TAG, "coap context not ready, check nic status");
        return;
    }
    if (CoapPostServiceNotification() != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "failed when post service notification");
        goto L_ERR_NOTIFICATION;
    }
    DFINDER_LOGI(TAG, "the %hhu time for sending notification", g_notificationRunCnt + 1);
    uint16_t nextInterval = GetNextNotificationInterval(++g_notificationRunCnt);
    if (TimerSetTimeout(g_notificationTimer, nextInterval, NSTACKX_FALSE) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "failed to set timer for service notification");
        goto L_ERR_NOTIFICATION;
    }
    return;
L_ERR_NOTIFICATION:
    DFINDER_LOGE(TAG, "abort notification, tried %hhu request, now reset notification cnt to 0", g_notificationRunCnt);
    g_notificationRunCnt = 0;
}

static int32_t HndPostServiceNotificationEx(const coap_pdu_t *request)
{
    size_t size = 0;
    const uint8_t *buf = NULL;
    if (coap_get_data(request, &size, &buf) == 0 || size == 0 || size > COAP_RXBUFFER_SIZE) {
        DFINDER_LOGE(TAG, "coap_get_data fail, size: %zu, coap rx buffer size: %d", size, COAP_RXBUFFER_SIZE);
        return NSTACKX_EFAILED;
    }
    NSTACKX_NotificationConfig *notification =
        (NSTACKX_NotificationConfig *)calloc(1, sizeof(NSTACKX_NotificationConfig));
    if (notification == NULL) {
        DFINDER_LOGE(TAG, "calloc for notification fail, size wanted: %zu", sizeof(NSTACKX_NotificationConfig));
        return NSTACKX_ENOMEM;
    }
    notification->msg = (char *)calloc(NSTACKX_MAX_NOTIFICATION_DATA_LEN, sizeof(char));
    if (notification->msg == NULL) {
        DFINDER_LOGE(TAG, "calloc for notification msg failed");
        free(notification);
        return NSTACKX_ENOMEM;
    }
    if (GetServiceNotificationInfo(buf, size, notification) != NSTACKX_EOK) {
        free(notification->msg);
        free(notification);
        return NSTACKX_EFAILED;
    }
    NotificationReceived(notification);
    free(notification->msg);
    free(notification);
    return NSTACKX_EOK;
}

static void HndPostServiceNotification(coap_resource_t *resource, coap_session_t *session,
    const coap_pdu_t *request, const coap_string_t *query, coap_pdu_t *response)
{
    (void)resource;
    (void)query;
    (void)session;
    (void)response;

    if (request == NULL) {
        DFINDER_LOGW(TAG, "request pdu is null, return");
        return;
    }
#ifdef DFINDER_SUPPORT_SET_SCREEN_STATUS
    if (!g_isScreenOn) {
        DFINDER_LOGD(TAG, "device screen is off, ignore pdu received");
        return;
    }
#endif
    DFINDER_LOGI(TAG, "recv coap notification pdu mid: %d", coap_pdu_get_mid(request));

    if (HndPostServiceNotificationEx(request) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, " hnd post service notificatioin failed for pdu mid: %d", coap_pdu_get_mid(request));
    }
}

int32_t CoapInitResources(coap_context_t *ctx)
{
    coap_resource_t *r =
        coap_resource_init(coap_make_str_const(COAP_DEVICE_DISCOVER_URI), g_resourceFlags);
    if (r == NULL) {
        DFINDER_LOGE(TAG, "coap resource init discover failed");
        return NSTACKX_ENOMEM;
    }
    coap_register_request_handler(r, COAP_REQUEST_POST, HndPostServiceDiscover);
    coap_resource_set_get_observable(r, NSTACKX_TRUE);
    coap_add_resource(ctx, r);

    coap_resource_t *msg =
        coap_resource_init(coap_make_str_const(COAP_SERVICE_MSG_URI), 0);
    if (msg == NULL) {
        DFINDER_LOGE(TAG, "coap resource init msg failed");
        (void)coap_delete_resource(ctx, r);
        return NSTACKX_ENOMEM;
    }
    coap_register_request_handler(msg, COAP_REQUEST_POST, HndPostServiceMsg);
    coap_add_resource(ctx, msg);

    coap_resource_t *notification = coap_resource_init(coap_make_str_const(COAP_SERVICE_NOTIFICATION_URI), 0);
    if (notification == NULL) {
        DFINDER_LOGE(TAG, "coap_resource_init for service notification failed");
        (void)coap_delete_resource(ctx, r);
        (void)coap_delete_resource(ctx, msg);
        return NSTACKX_ENOMEM;
    }
    coap_register_request_handler(notification, COAP_REQUEST_POST, HndPostServiceNotification);
    coap_add_resource(ctx, notification);

    return NSTACKX_EOK;
}

int32_t CoapDiscoverInit(EpollDesc epollfd)
{
    if (g_recvRecountTimer == NULL) {
        g_recvRecountTimer = TimerStart(epollfd, COAP_RECV_COUNT_INTERVAL, NSTACKX_TRUE,
                                        CoapRecvRecountTimerHandle, NULL);
    }
    if (g_recvRecountTimer == NULL) {
        DFINDER_LOGE(TAG, "failed to start timer for receive discover message recount");
        return NSTACKX_EFAILED;
    }

    if (g_discoverTimer == NULL) {
        g_discoverTimer = TimerStart(epollfd, 0, NSTACKX_FALSE, CoapServiceDiscoverTimerHandle, NULL);
    }
    if (g_discoverTimer == NULL) {
        DFINDER_LOGE(TAG, "failed to start timer for service discover");
        TimerDelete(g_recvRecountTimer);
        g_recvRecountTimer = NULL;
        return NSTACKX_EFAILED;
    }

    if (g_notificationTimer == NULL) {
        g_notificationTimer = TimerStart(epollfd, 0, NSTACKX_FALSE, CoapServiceNotificationTimerHandle, NULL);
    }
    if (g_notificationTimer == NULL) {
        DFINDER_LOGE(TAG, "failed to start timer for service notification");
        TimerDelete(g_recvRecountTimer);
        g_recvRecountTimer = NULL;
        TimerDelete(g_discoverTimer);
        g_discoverTimer = NULL;
        return NSTACKX_EFAILED;
    }

    g_msgIdList = (MsgIdList *)calloc(1U, sizeof(MsgIdList));
    if (g_msgIdList == NULL) {
        DFINDER_LOGE(TAG, "message Id record list calloc error");
        TimerDelete(g_discoverTimer);
        g_discoverTimer = NULL;
        TimerDelete(g_recvRecountTimer);
        g_recvRecountTimer = NULL;
        TimerDelete(g_notificationTimer);
        g_notificationTimer = NULL;
        return NSTACKX_EFAILED;
    }

    g_msgIdList->startIdx = COAP_MAX_MSGID_RESERVE_NUM;
    g_msgIdList->endIdx = COAP_MAX_MSGID_RESERVE_NUM;
    g_userRequest = NSTACKX_FALSE;
    g_forceUpdate = NSTACKX_FALSE;
    g_recvDiscoverMsgNum = 0;
    g_subscribeCount = 0;
    g_discoverCount = 0;
    g_notificationRunCnt = 0;
    return NSTACKX_EOK;
}

void CoapDiscoverDeinit(void)
{
    if (g_discoverTimer != NULL) {
        TimerDelete(g_discoverTimer);
        g_discoverTimer = NULL;
    }
    if (g_recvRecountTimer != NULL) {
        TimerDelete(g_recvRecountTimer);
        g_recvRecountTimer = NULL;
    }
    if (g_notificationTimer != NULL) {
        TimerDelete(g_notificationTimer);
        g_notificationTimer = NULL;
    }
    if (g_msgIdList != NULL) {
        free(g_msgIdList);
        g_msgIdList = NULL;
    }
    if (g_coapIntervalArr != NULL) {
        free(g_coapIntervalArr);
        g_coapIntervalArr = NULL;
    }
    ResetNotificationConfig();
}

void ResetCoapDiscoverTaskCount(uint8_t isBusy)
{
    if (g_discoverTimer != NULL) {
        if (isBusy) {
            DFINDER_LOGI(TAG, "in busy state: g_discoverTimer task count %llu", g_discoverTimer->task.count);
        }
        g_discoverTimer->task.count = 0;
    }
    if (g_recvRecountTimer != NULL) {
        if (isBusy) {
            DFINDER_LOGI(TAG, "in busy state: g_recvRecountTimer task count %llu",
                         g_recvRecountTimer->task.count);
        }
        g_recvRecountTimer->task.count = 0;
    }
}

void SetCoapDiscoverType(CoapBroadcastType type)
{
    g_coapDiscoverType = (uint32_t)type;
}

void SetCoapUserDiscoverInfo(uint32_t advCount, uint32_t advDuration)
{
    g_coapUserMaxDiscoverCount = advCount;
    if (advCount != 0) {
        g_coapUserDiscoverInterval = advDuration / advCount;
    }
    DFINDER_LOGD(TAG, "SetCoapUserDiscoverInfo advCount %u, interval %u",
        g_coapUserMaxDiscoverCount, g_coapUserDiscoverInterval);
}

int32_t SetCoapDiscConfig(const DFinderDiscConfig *discConfig)
{
    uint32_t *tmp = (uint32_t *)malloc(discConfig->intervalArrLen * sizeof(uint32_t));
    if (tmp != NULL) {
        if (g_coapIntervalArr != NULL) {
            free(g_coapIntervalArr);
        }
        g_coapIntervalArr = tmp;
        for (size_t i = 0; i < discConfig->intervalArrLen; ++i) {
            g_coapIntervalArr[i] = (discConfig->bcastInterval)[i];
        }
        // add 1: first broadcast starts immediately
        g_coapUserMaxDiscoverCount = discConfig->intervalArrLen + 1;
        return NSTACKX_EOK;
    }
    DFINDER_LOGE(TAG, "malloc for user define interval array failed");
    if (g_coapIntervalArr != NULL) {
        DFINDER_LOGD(TAG, "going to use last interval config");
        return NSTACKX_EOK;
    }
    DFINDER_LOGE(TAG, "failed to use last interval config");
    return NSTACKX_EFAILED;
}

static int32_t SendDiscoveryRspEx(CoapCtxType *ctx, const NSTACKX_ResponseSettings *responseSettings)
{
    char remoteUrl[NSTACKX_MAX_URI_BUFFER_LENGTH] = {0};
    char host[NSTACKX_MAX_IP_STRING_LEN] = {0};

    if (SetLocalDeviceBusinessData(responseSettings->businessData, NSTACKX_TRUE) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }
    DFINDER_LOGD(TAG, "response settings with business type: %hu", responseSettings->businessType);

    if (strncpy_s(host, sizeof(host), responseSettings->remoteIp, strlen(responseSettings->remoteIp)) != EOK) {
        DFINDER_LOGE(TAG, "discoveryRsp remoteIp copy error");
        return NSTACKX_EFAILED;
    }
    if (sprintf_s(remoteUrl, sizeof(remoteUrl), "coap://%s/" COAP_DEVICE_DISCOVER_URI, host) < 0) {
        DFINDER_LOGE(TAG, "failed to get discoveryRsp remoteUrl");
        return NSTACKX_EFAILED;
    }
    IncreaseSequenceNumber(NSTACKX_FALSE);
    return CoapResponseService(ctx, remoteUrl, responseSettings->businessType);
}

void SendDiscoveryRsp(const NSTACKX_ResponseSettings *responseSettings)
{
    CoapCtxType *ctx = LocalIfaceGetCoapCtx(responseSettings->localNetworkName);
    if (ctx == NULL) {
        DFINDER_LOGE(TAG, "local iface get coap context return null");
        IncStatistics(STATS_SEND_SD_RESPONSE_FAILED);
        return;
    }

    if (SendDiscoveryRspEx(ctx, responseSettings) != NSTACKX_EOK) {
        IncStatistics(STATS_SEND_SD_RESPONSE_FAILED);
    }
}

int32_t LocalizeNotificationInterval(const uint16_t *intervals, const uint8_t intervalLen)
{
    uint16_t *tmp = (uint16_t *)calloc(intervalLen, sizeof(uint16_t));
    if (tmp != NULL) {
        if (g_notificationIntervals != NULL) {
            free(g_notificationIntervals);
        }
        g_notificationIntervals = tmp;
        for (size_t i = 0; i < intervalLen; ++i) {
            g_notificationIntervals[i] = intervals[i];
        }
        g_notificationTargetCnt = intervalLen;
        return NSTACKX_EOK;
    }
    DFINDER_LOGW(TAG, "calloc for notification intervals fail, interval len %hhu", intervalLen);
    if (g_notificationIntervals != NULL) {
        DFINDER_LOGW(TAG, "going to use last success notification config");
        return NSTACKX_EOK;
    }
    DFINDER_LOGE(TAG, "set notification intervals fail and can not use last success config");
    return NSTACKX_EFAILED;
}

static void CoapServiceNotificationFirstTime(void)
{
    if (CoapPostServiceNotification() != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "failed to send service notification first time");
        return;
    }

    uint16_t nextInterval = GetNextNotificationInterval(++g_notificationRunCnt);
    if (TimerSetTimeout(g_notificationTimer, nextInterval, NSTACKX_FALSE) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "failed to set timer when doing service notification");
        return;
    }
    DFINDER_LOGI(TAG, "first time for service notification");
}

void CoapServiceNotification(void)
{
    if (!IsCoapContextReady()) {
        DFINDER_LOGW(TAG, "no coap ctx inited, please check nic info or reconnected");
        return;
    }
    if (g_notificationRunCnt != 0) {
        DFINDER_LOGI(TAG, "reset notification run cnt to 0, run cnt: %hhu, target cnt: %hhu",
            g_notificationRunCnt, g_notificationTargetCnt);
        g_notificationRunCnt = 0;
        (void)TimerSetTimeout(g_notificationTimer, 0, NSTACKX_FALSE);
    }
    CoapServiceNotificationFirstTime();
}
