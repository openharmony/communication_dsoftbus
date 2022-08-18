/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#define TAG "nStackXCoAP"

#define COAP_URI_BUFFER_LENGTH 64 /* the size of the buffer or variable used to save uri. */
#define COAP_MAX_NUM_SUBSCRIBE_MODULE_COUNT 32 /* the maximum count of subscribed module */

#define COAP_RECV_COUNT_INTERVAL 1000
#define COAP_DISVOCER_MAX_RATE 200
#define COAP_MSGID_SURVIVAL_SECONDS 100
#define COAP_MAX_MSGID_RESERVE_NUM 100

#ifdef DFINDER_SUPPORT_MULTI_NIF
typedef struct {
    coap_context_t *context;
    char networkName[NSTACKX_MAX_INTERFACE_NAME_LEN];
} DiscoverCtx;
static DiscoverCtx g_discoverCtxList[NSTACKX_MAX_LISTENED_NIF_NUM] = {{0}, {0}};
#else
static coap_context_t *g_context = NULL;
static coap_context_t *g_p2pContext = NULL;
static coap_context_t *g_usbContext = NULL;
#endif /* END OF DFINDER_SUPPORT_MULTI_NIF */

typedef struct {
    coap_mid_t msgId;
    struct timespec recvTime;
} MsgIdRecord;

typedef struct {
    MsgIdRecord msgIdRecord[COAP_MAX_MSGID_RESERVE_NUM];
    uint32_t startIdx;
    uint32_t endIdx;
} MsgIdList;

typedef struct {
    coap_context_t *context;
    char ipString[INET_ADDRSTRLEN];
} CoapContextWrapper;

typedef struct {
    coap_context_t *context;
    uint8_t serverType; // used when DFINDER_SUPPORT_MULTI_NIF is not defined
} CoapRequestPara;

static int g_resourceFlags = COAP_RESOURCE_FLAGS_NOTIFY_CON;
static Timer *g_discoverTimer = NULL;
static uint32_t g_discoverCount;
static uint32_t g_coapMaxDiscoverCount = COAP_DEFAULT_DISCOVER_COUNT;
static uint32_t g_coapDiscoverType = COAP_BROADCAST_TYPE_DEFAULT;
static uint32_t g_coapUserMaxDiscoverCount;
static uint32_t g_coapUserDiscoverInterval;
static uint32_t g_coapDiscoverTargetCount;
static uint8_t g_userRequest;
static uint8_t g_forceUpdate;
static Timer *g_recvRecountTimer = NULL;
static uint32_t g_recvDiscoverMsgNum;
static MsgIdList *g_msgIdList = NULL;
static uint8_t g_subscribeCount;

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
    if (localUri.scheme != COAP_URI_SCHEME_COAP) {
        DFINDER_LOGE(TAG, "coaps URI scheme not supported in this version of libcoap");
        return NSTACKX_EFAILED;
    }

    (void)memcpy_s(uriPtr, sizeof(coap_uri_t), &localUri, sizeof(coap_uri_t));
    return NSTACKX_EOK;
}

static coap_pdu_t *CoapPackToPdu(const CoapRequest *coapRequest, const coap_uri_t *uriPtr, coap_session_t *session)
{
    coap_pdu_t *pdu = NULL;
    if (coapRequest == NULL) {
        return NULL;
    }
    if (coapRequest->remoteUrl == NULL) {
        return NULL;
    }
    if (session == NULL) {
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

#ifndef DFINDER_SUPPORT_MULTI_NIF
static int32_t GetTargetIpString(uint8_t serverType, char *ipString, size_t length)
{
    if (ipString == NULL || length == 0) {
        return NSTACKX_EFAILED;
    }

    if (serverType == SERVER_TYPE_WLANORETH) {
        return GetLocalIpString(ipString, length);
    }

    if (serverType == SERVER_TYPE_P2P) {
        return GetP2pIpString(ipString, length);
    }

    if (serverType == SERVER_TYPE_USB) {
        return GetUsbIpString(ipString, length);
    }

    return NSTACKX_EFAILED;
}
#endif

#ifdef DFINDER_SUPPORT_MULTI_NIF
static int32_t GetTargetIpStringWithIdx(char *ipString, size_t length, uint8_t idx)
{
    if (ipString == NULL || length == 0) {
        return NSTACKX_EFAILED;
    }
    return GetLocalIpStringWithIdx(ipString, length, idx);
}

static uint32_t GetIndexFromContext(coap_context_t *context)
{
    uint32_t i;
    for (i = 0; i < NSTACKX_MAX_LISTENED_NIF_NUM; ++i) {
        if (g_discoverCtxList[i].context == NULL) {
            continue;
        }
        if (g_discoverCtxList[i].context == context) {
            break;
        }
    }
    if (i == NSTACKX_MAX_LISTENED_NIF_NUM) {
        DFINDER_LOGW(TAG, "can not find legal ctx");
    }
    return i;
}
#endif

static void FillCoapRequest(CoapRequest *coapRequest, uint8_t coapType, const char *url, char *data, size_t dataLen)
{
    (void)memset_s(coapRequest, sizeof(CoapRequest), 0, sizeof(CoapRequest));
    coapRequest->type = coapType;
    coapRequest->code = COAP_REQUEST_POST;
    coapRequest->remoteUrl = url;
    coapRequest->data = data;
    coapRequest->dataLength = dataLen;
}
static int32_t CoapSendRequestInner(uint8_t coapType, const char *url, char *data, size_t dataLen,
    const CoapContextWrapper *wrapper)
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
        goto DATA_FREE;
    }
    remote = coapUri.host;
    res = CoapResolveAddress(&remote, &dst.addr.sa);
    if (res < 0) {
        DFINDER_LOGE(TAG, "fail to resolve address");
        goto DATA_FREE;
    }

    dst.size = res;
    dst.addr.sin.sin_port = htons(COAP_DEFAULT_PORT);

    coapServerParameter.proto = COAP_PROTO_UDP;
    coapServerParameter.dst = &dst;
    session = CoapGetSession(wrapper->context, wrapper->ipString, COAP_SRV_DEFAULT_PORT, &coapServerParameter);
    if (session == NULL) {
        DFINDER_LOGE(TAG, "get client session failed");
        goto DATA_FREE;
    }
    pdu = CoapPackToPdu(&coapRequest, &coapUri, session);
    if (pdu == NULL) {
        goto SESSION_RELEASE;
    }
    DFINDER_MGT_REQ_LOG(&coapRequest);
    tid = coap_send(session, pdu);
    if (tid == COAP_INVALID_TID) {
        DFINDER_LOGE(TAG, "coap send failed");
        goto SESSION_RELEASE;
    }
    free(coapRequest.data);
    coap_session_release(session);
    return NSTACKX_EOK;
SESSION_RELEASE:
    coap_session_release(session);
DATA_FREE:
    free(coapRequest.data);
    return NSTACKX_EFAILED;
}

// Caller must make sure that reqeustPara, reqeustPara->serverType/context are all valid.
static int32_t CoapSendRequestEx(uint8_t coapType, const char *url, char *data, size_t dataLen,
    const CoapRequestPara *reqeustPara)
{
    CoapContextWrapper wrapper = {
        .context = reqeustPara->context,
        .ipString = {0},
    };
#ifdef DFINDER_SUPPORT_MULTI_NIF
    uint32_t index = GetIndexFromContext(reqeustPara->context);
    if (index == NSTACKX_MAX_LISTENED_NIF_NUM) {
        free(data);
        return NSTACKX_EFAILED;
    }
    if (GetTargetIpStringWithIdx(wrapper.ipString, sizeof(wrapper.ipString), index) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "can't get target IP with idx-%d", index);
        free(data);
        return NSTACKX_EFAILED;
    }
#else
    if (GetTargetIpString(reqeustPara->serverType, wrapper.ipString, sizeof(wrapper.ipString)) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "can't get target IP with type %u", SERVER_TYPE_WLANORETH);
        free(data);
        return NSTACKX_EFAILED;
    }
#endif
    return CoapSendRequestInner(coapType, url, data, dataLen, &wrapper);
}

static int32_t CoapSendRequest(uint8_t coapType, const char *url, char *data, size_t dataLen,
    const CoapRequestPara *reqeustPara)
{
    int32_t ret = CoapSendRequestEx(coapType, url, data, dataLen, reqeustPara);
    if (ret != NSTACKX_EOK) {
        IncStatistics(STATS_SEND_REQUEST_FAILED);
    }
    return ret;
}

static int32_t CoapResponseService(const char *remoteUrl, coap_context_t *context)
{
    CoapRequestPara para = {
        .context = context,
        .serverType = SERVER_TYPE_WLANORETH,
    };
#ifdef DFINDER_SUPPORT_MULTI_NIF
     uint32_t index = GetIndexFromContext(context);
    if (index == NSTACKX_MAX_LISTENED_NIF_NUM) {
        return NSTACKX_EFAILED;
    }
    char *data = PrepareServiceDiscoverWithIdx(NSTACKX_FALSE, index);
#else
    char *data = PrepareServiceDiscover(NSTACKX_FALSE);
#endif
    if (data == NULL) {
        DFINDER_LOGE(TAG, "failed to prepare coap data");
        return NSTACKX_EFAILED;
    }

    return CoapSendRequest(COAP_MESSAGE_CON, remoteUrl, data, strlen(data) + 1, &para);
}

static void IncreaseRecvDiscoverNum(void)
{
    if (g_recvDiscoverMsgNum < UINT32_MAX) {
        g_recvDiscoverMsgNum++;
    }
}

static int32_t CheckBusinessTypeCanNotify(const uint8_t businessType)
{
    uint8_t localBusinessType = GetLocalDeviceInfoPtr()->businessType;
    if (businessType == localBusinessType) {
        return NSTACKX_EOK;
    }
    if ((localBusinessType == (uint8_t)NSTACKX_BUSINESS_TYPE_NEARBY) ||
        (businessType == (uint8_t)NSTACKX_BUSINESS_TYPE_NEARBY)) {
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static int32_t HndPostServiceDiscoverInner(const coap_pdu_t *request, char **remoteUrl, DeviceInfo *deviceInfo)
{
    size_t size;
    const uint8_t *buf = NULL;
    IncreaseRecvDiscoverNum();
    if (g_recvDiscoverMsgNum > COAP_DISVOCER_MAX_RATE) {
        return NSTACKX_EFAILED;
    }
    if (coap_get_data(request, &size, &buf) == 0 || size == 0 || size > COAP_RXBUFFER_SIZE) {
        return NSTACKX_EFAILED;
    }
    (void)memset_s(deviceInfo, sizeof(*deviceInfo), 0, sizeof(*deviceInfo));
    if (GetServiceDiscoverInfo(buf, size, deviceInfo, remoteUrl) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }
    if (CheckBusinessTypeCanNotify(deviceInfo->businessType) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }
    /* receive coap broadcast, set peer device's discovery type to passive,
     * to identify the local device is in passive discovery
     */
    deviceInfo->discoveryType = (*remoteUrl != NULL) ? NSTACKX_DISCOVERY_TYPE_PASSIVE : NSTACKX_DISCOVERY_TYPE_ACTIVE;
    if (deviceInfo->mode == PUBLISH_MODE_UPLINE || deviceInfo->mode == PUBLISH_MODE_OFFLINE) {
        DFINDER_LOGD(TAG, "peer is not DISCOVER_MODE");
        NSTACKX_DeviceInfo deviceList[PUBLISH_DEVICE_NUM];
        (void)memset_s(deviceList, sizeof(deviceList), 0, sizeof(deviceList));
        PushPublishInfo(deviceInfo, deviceList, PUBLISH_DEVICE_NUM);
        NotifyDeviceFound(deviceList, PUBLISH_DEVICE_NUM);
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static int32_t HndPostServiceDiscoverEx(coap_session_t *session, const coap_pdu_t *request, coap_pdu_t *response)
{
    int32_t ret = NSTACKX_EFAILED;
    coap_context_t *currCtx = coap_session_get_context(session);
    if (currCtx == NULL) {
        return ret;
    }
    char *remoteUrl = NULL;
    DeviceInfo *deviceInfo = malloc(sizeof(DeviceInfo));
    if (deviceInfo == NULL) {
        return ret;
    }
    if (HndPostServiceDiscoverInner(request, &remoteUrl, deviceInfo) != NSTACKX_EOK) {
        goto L_ERR;
    }
    if (GetModeInfo() == PUBLISH_MODE_UPLINE || GetModeInfo() == PUBLISH_MODE_OFFLINE) {
        DFINDER_LOGD(TAG, "local is not DISCOVER_MODE");
        goto L_ERR;
    }
#ifdef DFINDER_SUPPORT_MULTI_NIF
    uint32_t idx = GetIndexFromContext(currCtx);
    if (idx == NSTACKX_MAX_LISTENED_NIF_NUM || UpdateDeviceDbWithIdx(deviceInfo, g_forceUpdate, idx) != NSTACKX_EOK) {
        goto L_ERR;
    }
#else
#ifdef DFINDER_SAVE_DEVICE_LIST
    if (UpdateDeviceDb(deviceInfo, g_forceUpdate) != NSTACKX_EOK) {
#else
    if (DeviceInfoNotify(deviceInfo, g_forceUpdate) != NSTACKX_EOK) {
#endif /* END OF DFINDER_SAVE_DEVICE_LIST */
        goto L_ERR;
    }
#endif /* END OF DFINDER_SUPPORT_MULTI_NIF */
    g_forceUpdate = NSTACKX_FALSE;
    if (deviceInfo->mode == PUBLISH_MODE_PROACTIVE) {
        DFINDER_LOGD(TAG, "peer is PUBLISH_MODE_PROACTIVE");
        goto L_ERR;
    }
    if (remoteUrl != NULL) {
        if (CheckBusinessTypeReplyUnicast(deviceInfo->businessType) == NSTACKX_EOK) {
            (void)CoapResponseService(remoteUrl, currCtx);
        }
    } else {
        coap_pdu_set_code(response, COAP_RESPONSE_CODE_CREATED);
    }
    ret = NSTACKX_EOK;
L_ERR:
    free(deviceInfo);
    free(remoteUrl);
    return ret;
}

static void HndPostServiceDiscover(coap_resource_t *resource, coap_session_t *session,
    const coap_pdu_t *request, const coap_string_t *query, coap_pdu_t *response)
{
    (void)resource;
    (void)query;
    if (request == NULL || response == NULL) {
        return;
    }

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

static uint16_t ParseServiceMsgFrame(const uint8_t *frame, uint16_t size, char *moduleName, char *deviceId,
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

    NotifyMsgReceived(moduleName, deviceId, msg, msgLen);

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

#ifdef DFINDER_SUPPORT_MULTI_NIF
static int32_t CoapPostServiceDiscoverEx(void)
{
    char ifName[NSTACKX_MAX_INTERFACE_NAME_LEN] = {0};
    char ipString[NSTACKX_MAX_IP_STRING_LEN] = {0};
    char discoverUri[COAP_URI_BUFFER_LENGTH] = {0};
    char *data = NULL;

    int32_t errCnt = 0;
    int32_t postResult = 0;

    for (uint32_t i = 0; i < NSTACKX_MAX_LISTENED_NIF_NUM; ++i) {
        if (g_discoverCtxList[i].context == NULL) {
            continue;
        }
        (void)memset_s(ifName, sizeof(ifName), 0, sizeof(ifName));
        (void)memset_s(ipString, sizeof(ipString), 0, sizeof(ipString));
        (void)memset_s(discoverUri, sizeof(discoverUri), 0, sizeof(discoverUri));
        data = NULL;

        if (GetLocalInterfaceNameWithIdx(ifName, sizeof(ifName), i) != NSTACKX_EOK) {
            DFINDER_LOGE(TAG, "get local interface name with idx-%d failed", i);
            continue;
        }

        if (GetIfBroadcastIp(ifName, ipString, sizeof(ipString)) != NSTACKX_EOK) {
            DFINDER_LOGE(TAG, "get local interface bcast ip with idx-%d failed", i);
            continue;
        }

        if (sprintf_s(discoverUri, sizeof(discoverUri), "coap://%s/%s", ipString, COAP_DEVICE_DISCOVER_URI) < 0) {
            DFINDER_LOGE(TAG, "set discoverUri failed with idx-%d", i);
            continue;
        }

        data = PrepareServiceDiscoverWithIdx(NSTACKX_TRUE, i);
        if (data == NULL) {
            DFINDER_LOGE(TAG, "service discover data is NULL with idx-%d", i);
            ++errCnt;
            continue;
        }
        CoapRequestPara para = {0};
        para.context = g_discoverCtxList[i].context;
        postResult = CoapSendRequest(COAP_MESSAGE_NON, discoverUri, data, strlen(data) + 1, &para);
        if (postResult != NSTACKX_EOK) {
            DFINDER_LOGE(TAG, "coap send request with idx-%d failed", i);
            ++errCnt;
        }
    }
    if (errCnt == NSTACKX_MAX_LISTENED_NIF_NUM) {
        DFINDER_LOGE(TAG, "coap post service discover on all nif failed");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}
#else
static int32_t CoapPostServiceDiscoverEx(void)
{
    char ipString[NSTACKX_MAX_IP_STRING_LEN] = {0};
    char discoverUri[COAP_URI_BUFFER_LENGTH] = {0};
    char *data = NULL;
    CoapRequestPara para = {0};
#ifndef _WIN32
    char ifName[NSTACKX_MAX_INTERFACE_NAME_LEN] = {0};

    if (GetLocalInterfaceName(ifName, sizeof(ifName)) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "GetLocalInterfaceName failed");
        return NSTACKX_EFAILED;
    }

    if (GetIfBroadcastIp(ifName, ipString, sizeof(ipString)) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "GetIfBroadcastIp failed");
        return NSTACKX_EFAILED;
    }
#else
    struct in_addr ipNow;
    GetLocalIp(&ipNow);
    if (ipNow.s_addr == 0) {
        DFINDER_LOGE(TAG, "GetLocalIp failed");
        return NSTACKX_EFAILED;
    }

    if (GetIfBroadcastAddr(&ipNow, ipString, NSTACKX_MAX_IP_STRING_LEN) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "GetIfBroadcastAddr failed");
        return NSTACKX_EFAILED;
    }
#endif

    if (sprintf_s(discoverUri, sizeof(discoverUri), "coap://%s/%s", ipString, COAP_DEVICE_DISCOVER_URI) < 0) {
        return NSTACKX_EFAILED;
    }
    para.serverType = SERVER_TYPE_WLANORETH;
    para.context = GetContext(SERVER_TYPE_WLANORETH);
    if (para.context == NULL) {
        DFINDER_LOGE(TAG, "Failed to get coap context");
        return NSTACKX_EFAILED;
    }
    data = PrepareServiceDiscover(NSTACKX_TRUE);
    if (data == NULL) {
        DFINDER_LOGE(TAG, "failed to prepare coap data");
        return NSTACKX_EFAILED;
    }

    return CoapSendRequest(COAP_MESSAGE_NON, discoverUri, data, strlen(data) + 1, &para);
}
#endif /* END OF DFINDER_SUPPORT_MULTI_NIF */

static int32_t CoapPostServiceDiscover(void)
{
    int32_t ret = CoapPostServiceDiscoverEx();
    if (ret != NSTACKX_EOK) {
        IncStatistics(STATS_POST_SD_REQUEST_FAILED);
    }
    return ret;
}

static uint32_t GetDiscoverInterval(uint32_t discoverCount)
{
    switch (g_coapDiscoverType) {
        case COAP_BROADCAST_TYPE_USER:
            return g_coapUserDiscoverInterval;
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
    ClearDevices(GetDeviceDBBackup());
    DFINDER_LOGW(TAG, "clear device list backup");
#endif
    g_coapDiscoverType = COAP_BROADCAST_TYPE_DEFAULT;
    g_coapMaxDiscoverCount = COAP_DEFAULT_DISCOVER_COUNT;
    /* Can call PostDeviceFindWrapper() to notify user if needed. */
    g_userRequest = NSTACKX_FALSE;
}

static void CoapServiceDiscoverTimerHandle(void *argument)
{
    uint32_t discoverInterval;

    (void)argument;

#ifdef DFINDER_SUPPORT_MULTI_NIF
    if (g_discoverCount >= g_coapDiscoverTargetCount || !IsApConnected()) {
        IncStatistics(STATS_ABORT_SD);
        CoapServiceDiscoverStop();
        return;
    }
#else
    if (g_discoverCount >= g_coapDiscoverTargetCount || !IsWifiApConnected()) {
        IncStatistics(STATS_ABORT_SD);
        /* Discover done, or wifi AP disconnected. */
        CoapServiceDiscoverStop();
        return;
    }
#endif /* END OF DFINDER_SUPPORT_MULTI_NIF */

    if (CoapPostServiceDiscover() != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "failed when posting service discover request");
        goto L_ERR_DISCOVER;
    }
    DFINDER_LOGI(TAG, "the %u time for device discovery.", g_discoverCount + 1);

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
            g_coapMaxDiscoverCount = g_coapUserMaxDiscoverCount;
            break;
        default:
            g_coapMaxDiscoverCount = COAP_DEFAULT_DISCOVER_COUNT;
            break;
    }
}

#ifdef DFINDER_SUPPORT_MULTI_NIF
static uint8_t CheckAllContextDown(void)
{
    for (uint32_t i = 0; i < NSTACKX_MAX_LISTENED_NIF_NUM; ++i) {
        if (g_discoverCtxList[i].context != NULL) {
            return NSTACKX_FALSE;
        }
    }
    return NSTACKX_TRUE;
}
#endif

static void CoapServiceDiscoverFirstTime(void)
{
    SetCoapMaxDiscoverCount();
    g_coapDiscoverTargetCount = g_coapMaxDiscoverCount;
    if (CoapPostServiceDiscover() != NSTACKX_EOK) {
        // update log to avoid duplicate code.
        DFINDER_LOGE(TAG, "failed to send service discover request");
        return;
    }

    uint32_t discoverInterval = GetDiscoverInterval(g_discoverCount);
    if (TimerSetTimeout(g_discoverTimer, discoverInterval, NSTACKX_FALSE) != NSTACKX_EOK) {
        // update log to avoid duplicate code.
        DFINDER_LOGE(TAG, "failed to set timer when doing service discover");
        return;
    }
    ++g_discoverCount;
    // update log to avoid duplicate code.
    DFINDER_LOGI(TAG, "first time for device discover.");
}

static uint8_t NetworkIsConnected()
{
#ifdef DFINDER_SUPPORT_MULTI_NIF
    if (!IsApConnected()) {
        DFINDER_LOGE(TAG, "all ap is not connected in coap service discover inner");
        return NSTACKX_FALSE;
    }
    if (CheckAllContextDown()) {
        DFINDER_LOGW(TAG, "all context down");
        return NSTACKX_FALSE;
    }
#else
    if (!IsWifiApConnected() || g_context == NULL) {
        return NSTACKX_FALSE;
    }
#endif
    return NSTACKX_TRUE;
}

void CoapServiceDiscoverInner(uint8_t userRequest)
{
    if (!NetworkIsConnected()) {
        IncStatistics(STATS_START_SD_FAILED);
        LOGI(TAG, "Network not connected when discovery inner");
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
        ClearDevices(GetDeviceDBBackup());
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
    if (BackupDeviceDB() != NSTACKX_EOK) {
        IncStatistics(STATS_START_SD_FAILED);
        DFINDER_LOGE(TAG, "backup device list fail when discovery inner");
        return;
    }
    ClearDevices(GetDeviceDB());
    DFINDER_LOGW(TAG, "clear device list when discovery inner");
#endif /* END OF DFINDER_SAVE_DEVICE_LIST */
    SetModeInfo(DISCOVER_MODE);
    CoapServiceDiscoverFirstTime();
    return;
}

void CoapServiceDiscoverInnerAn(uint8_t userRequest)
{
    if (!NetworkIsConnected()) {
        IncStatistics(STATS_START_SD_FAILED);
        LOGI(TAG, "Network not connected when discovery inner AN");
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
    if (!NetworkIsConnected()) {
        IncStatistics(STATS_START_SD_FAILED);
        LOGI(TAG, "Network not connected when discovery configurable");
        return;
    }

    if (userRequest) {
        g_userRequest = NSTACKX_TRUE;
        g_forceUpdate = NSTACKX_TRUE;
    }

    if (g_coapDiscoverTargetCount > 0 && g_discoverCount >= g_coapDiscoverTargetCount) {
        g_discoverCount = 0;
#ifdef DFINDER_SAVE_DEVICE_LIST
        ClearDevices(GetDeviceDBBackup());
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
        if (BackupDeviceDB() != NSTACKX_EOK) {
            IncStatistics(STATS_START_SD_FAILED);
            DFINDER_LOGE(TAG, "backup device list fail when discovery configurable");
            return;
        }
        ClearDevices(GetDeviceDB());
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

#ifndef DFINDER_SUPPORT_MULTI_NIF
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

int32_t CoapSendServiceMsg(MsgCtx *msgCtx, DeviceInfo *deviceInfo)
{
    return CoapSendServiceMsgWithDefiniteTargetIp(msgCtx, deviceInfo);
}

coap_context_t *GetContext(uint8_t serverType)
{
    if (serverType == SERVER_TYPE_WLANORETH) {
        if (g_context == NULL) {
            DFINDER_LOGE(TAG, "DefiniteTargetIp getContext: g_context for wlan or eth is null");
        }
        return g_context;
    } else if (serverType == SERVER_TYPE_P2P) {
        if (g_p2pContext == NULL) {
            DFINDER_LOGE(TAG, "DefiniteTargetIp getContext: g_p2pContext for p2p is null");
        }
        return g_p2pContext;
    } else if (serverType == SERVER_TYPE_USB) {
        if (g_usbContext == NULL) {
            DFINDER_LOGE(TAG, "DefiniteTargetIp getContext: g_usbContext for usb is null");
        }
        return g_usbContext;
    } else {
        DFINDER_LOGE(TAG, "CoapSendServiceMsgWithDefiniteTargetIp serverType is unknown");
        return NULL;
    }
}

int32_t CoapSendServiceMsgWithDefiniteTargetIp(MsgCtx *msgCtx, DeviceInfo *deviceInfo)
{
    char ipString[INET_ADDRSTRLEN] = {0};
    char uriBuffer[COAP_URI_BUFFER_LENGTH] = {0};
    uint16_t dataLen = 0;
    if (msgCtx == NULL) {
        return NSTACKX_EFAILED;
    }
    uint8_t autcualType = GetActualType(msgCtx->type, msgCtx->p2pAddr);
    char *data = NULL;
    DFINDER_LOGD(TAG, "autcualType is %hhu", autcualType);
    if (msgCtx->len == 0 || msgCtx->len > NSTACKX_MAX_SENDMSG_DATA_LEN) {
        return NSTACKX_EINVAL;
    }

    if (strlen(msgCtx->p2pAddr) == 0) {
        if (deviceInfo == NULL) {
            return NSTACKX_EFAILED;
        }
        if (inet_ntop(AF_INET, &deviceInfo->netChannelInfo.wifiApInfo.ip, ipString, sizeof(ipString)) == NULL) {
            DFINDER_LOGE(TAG, "inet_ntop failed: %d", errno);
            return NSTACKX_EFAILED;
        }
    } else {
        if (strcpy_s(ipString, sizeof(ipString), msgCtx->p2pAddr) != EOK) {
            DFINDER_LOGE(TAG, "failed to get ip");
            return NSTACKX_EFAILED;
        }
    }

    if (sprintf_s(uriBuffer, sizeof(uriBuffer), "coap://%s/" COAP_SERVICE_MSG_URI, ipString) < 0) {
        return NSTACKX_EFAILED;
    }

    CoapRequestPara para = {0};
    para.serverType = autcualType;
    para.context = GetContext(autcualType);
    if (para.context == NULL) {
        DFINDER_LOGE(TAG, "Failed to get coap context");
        return NSTACKX_EFAILED;
    }

    data = (char *)CreateServiceMsgFrame(msgCtx->moduleName,
        GetLocalDeviceInfoPtr()->deviceId, msgCtx->data, msgCtx->len, &dataLen);
    if (data == NULL) {
        DFINDER_LOGE(TAG, "failed to prepare msg data");
        return NSTACKX_EFAILED;
    }

    return CoapSendRequest(COAP_MESSAGE_CON, uriBuffer, data, dataLen, &para);
}
#endif /* END OF DFINDER_SUPPORT_MULTI_NIF */

uint8_t GetActualType(const uint8_t type, const char *dstIp)
{
    if (type != INVALID_TYPE) {
        return type;
    }
    struct sockaddr_in localAddr;
    localAddr.sin_addr.s_addr = inet_addr(dstIp);
#ifndef _WIN32
    struct ifreq localDev;
    (void)memset_s(&localDev, sizeof(struct ifreq), 0, sizeof(struct ifreq));
    if (GetTargetInterface(&localAddr, &localDev) != NSTACKX_EOK) {
        return INVALID_TYPE;
    }
    if (IsWlanIpAddr(localDev.ifr_ifrn.ifrn_name) == NSTACKX_TRUE) {
        return SERVER_TYPE_WLANORETH;
    }
    if (IsEthIpAddr(localDev.ifr_ifrn.ifrn_name) == NSTACKX_TRUE) {
        return SERVER_TYPE_WLANORETH;
    }
    if (IsP2pIpAddr(localDev.ifr_ifrn.ifrn_name) == NSTACKX_TRUE) {
        return SERVER_TYPE_P2P;
    }
    if (IsUsbIpAddr(localDev.ifr_ifrn.ifrn_name) == NSTACKX_TRUE) {
        return SERVER_TYPE_USB;
    }
#else
    InterfaceInfo localDev;
    (void)memset_s(&localDev, sizeof(InterfaceInfo), 0, sizeof(InterfaceInfo));
    if (GetTargetAdapter(&localAddr, &localDev) != NSTACKX_EOK) {
        return INVALID_TYPE;
    }
    struct in_addr *sa = (struct in_addr *)&(localDev.ipAddr);
    if (IsWlanIpAddr(sa) == NSTACKX_TRUE) {
        return SERVER_TYPE_WLANORETH;
    }
    if (IsEthIpAddr(sa) == NSTACKX_TRUE) {
        return SERVER_TYPE_WLANORETH;
    }
    if (IsP2pIpAddr(sa) == NSTACKX_TRUE) {
        return SERVER_TYPE_P2P;
    }
    if (IsUsbIpAddr(sa) == NSTACKX_TRUE) {
        return SERVER_TYPE_USB;
    }
#endif
    return type;
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

static void CoapInitResourcesInner(coap_context_t *ctx)
{
    coap_resource_t *r = NULL;

    r = coap_resource_init(coap_make_str_const(COAP_DEVICE_DISCOVER_URI), g_resourceFlags);
    if (r == NULL) {
        return;
    }
    coap_register_handler(r, COAP_REQUEST_POST, HndPostServiceDiscover);
    coap_resource_set_get_observable(r, NSTACKX_TRUE);
    coap_add_resource(ctx, r);

    r = coap_resource_init(coap_make_str_const(COAP_SERVICE_MSG_URI), 0);
    if (r == NULL) {
        return;
    }
    coap_register_handler(r, COAP_REQUEST_POST, HndPostServiceMsg);
    coap_add_resource(ctx, r);
}

#ifdef DFINDER_SUPPORT_MULTI_NIF
void CoapInitResourcesWithIdx(coap_context_t *ctx, uint32_t idx, const char *networkName)
{
    CoapInitResourcesInner(ctx);
    g_discoverCtxList[idx].context = ctx;
    if (networkName != NULL) {
        (void)memset_s(g_discoverCtxList[idx].networkName, sizeof(g_discoverCtxList[idx].networkName),
                        0, sizeof(g_discoverCtxList[idx].networkName));
        if (strcpy_s(g_discoverCtxList[idx].networkName,
            sizeof(g_discoverCtxList[idx].networkName), networkName) != EOK) {
            DFINDER_LOGE(TAG, "strcpy failed");
        }
    }
    DFINDER_LOGD(TAG, "coap init resources with idx-%u update", idx);
}

#else
void CoapInitResources(coap_context_t *ctx, uint8_t serverType)
{
    CoapInitResourcesInner(ctx);

    if (serverType == SERVER_TYPE_WLANORETH) {
        g_context = ctx;
        DFINDER_LOGD(TAG, "CoapInitResources g_wlanOrEthContext update");
    } else if (serverType == SERVER_TYPE_P2P) {
        g_p2pContext = ctx;
        DFINDER_LOGD(TAG, "CoapInitResources g_p2pContext update");
    } else if (serverType == SERVER_TYPE_USB) {
        g_usbContext = ctx;
        DFINDER_LOGD(TAG, "CoapInitResources g_usbContext update");
    } else {
        DFINDER_LOGE(TAG, "CoapInitResources serverType is unknown!");
    }
}
#endif /* END OF DFINDER_SUPPORT_MULTI_NIF */

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

    g_msgIdList = (MsgIdList *)calloc(1U, sizeof(MsgIdList));
    if (g_msgIdList == NULL) {
        DFINDER_LOGE(TAG, "message Id record list calloc error");
        TimerDelete(g_discoverTimer);
        g_discoverTimer = NULL;
        TimerDelete(g_recvRecountTimer);
        g_recvRecountTimer = NULL;
        return NSTACKX_EFAILED;
    }

    g_msgIdList->startIdx = COAP_MAX_MSGID_RESERVE_NUM;
    g_msgIdList->endIdx = COAP_MAX_MSGID_RESERVE_NUM;
    g_userRequest = NSTACKX_FALSE;
    g_forceUpdate = NSTACKX_FALSE;
    g_recvDiscoverMsgNum = 0;
    g_subscribeCount = 0;
    g_discoverCount = 0;
    return NSTACKX_EOK;
}

#ifdef DFINDER_SUPPORT_MULTI_NIF
void CoapDestroyCtxWithIdx(uint32_t ctxIdx)
{
    g_discoverCtxList[ctxIdx].context = NULL;
    (void)memset_s(g_discoverCtxList[ctxIdx].networkName, sizeof(g_discoverCtxList[ctxIdx].networkName),
        0, sizeof(g_discoverCtxList[ctxIdx].networkName));
    DFINDER_LOGD(TAG, "coap destroy ctx with idx-%u success", ctxIdx);
}
#else
void CoapDestroyCtx(uint8_t serverType)
{
    if (serverType == SERVER_TYPE_WLANORETH) {
        g_context = NULL;
        DFINDER_LOGD(TAG, "CoapDestroyCtx, g_context is set to NULL");
    } else if (serverType == SERVER_TYPE_P2P) {
        g_p2pContext = NULL;
        DFINDER_LOGD(TAG, "CoapDestroyCtx, g_p2pContext is set to NULL");
    } else if (serverType == SERVER_TYPE_USB) {
        g_usbContext = NULL;
        DFINDER_LOGD(TAG, "CoapDestroyCtx, g_usbContext is set to NULL");
    } else {
        DFINDER_LOGE(TAG, "CoapDestroyCtx, serverType is unknown");
    }
}
#endif /* END OF DFINDER_SUPPORT_MULTI_NIF */

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
    if (g_msgIdList != NULL) {
        free(g_msgIdList);
        g_msgIdList = NULL;
    }
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
}

static int32_t SendDiscoveryRspEx(const NSTACKX_ResponseSettings *responseSettings)
{
    char remoteUrl[NSTACKX_MAX_URI_BUFFER_LENGTH] = {0};
    char host[NSTACKX_MAX_IP_STRING_LEN] = {0};
    if (responseSettings == NULL) {
        return NSTACKX_EFAILED;
    }
    if (responseSettings->businessData == NULL) {
        DFINDER_LOGE(TAG, "businessData is null");
        return NSTACKX_EFAILED;
    }

    if (SetLocalDeviceBusinessDataUnicast(responseSettings->businessData, responseSettings->length) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }

    if (strncpy_s(host, sizeof(host), responseSettings->remoteIp, strlen(responseSettings->remoteIp)) != EOK) {
        DFINDER_LOGE(TAG, "discoveryRsp remoteIp copy error");
        return NSTACKX_EFAILED;
    }
    if (sprintf_s(remoteUrl, sizeof(remoteUrl), "coap://%s/" COAP_DEVICE_DISCOVER_URI, host) < 0) {
        DFINDER_LOGE(TAG, "failed to get discoveryRsp remoteUrl");
        return NSTACKX_EFAILED;
    }
#ifdef DFINDER_SUPPORT_MULTI_NIF
    uint32_t i;
    for (i = 0; i < NSTACKX_MAX_LISTENED_NIF_NUM; ++i) {
        if (g_discoverCtxList[i].context == NULL) {
            continue;
        }
        if (strcmp(responseSettings->localNetworkName, g_discoverCtxList[i].networkName) == 0) {
            DFINDER_LOGD(TAG, "find right discover context to call CoapResponseService with idx-%u", i);
            return CoapResponseService(remoteUrl, g_discoverCtxList[i].context);
        }
    }

    DFINDER_LOGE(TAG, "can not find right discover context to call CoapResponseService");
    return NSTACKX_EFAILED;
#else
    coap_context_t *context = GetContext(SERVER_TYPE_WLANORETH);
    if (context == NULL) {
        DFINDER_LOGE(TAG, "can not find right discover context to call CoapResponseService");
        return NSTACKX_EFAILED;
    }
    return CoapResponseService(remoteUrl, context);
#endif
}

void SendDiscoveryRsp(const NSTACKX_ResponseSettings *responseSettings)
{
    if (SendDiscoveryRspEx(responseSettings) != NSTACKX_EOK) {
        IncStatistics(STATS_SEND_SD_RESPONSE_FAILED);
    }
}