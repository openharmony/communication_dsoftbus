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

#include "coap.h"
#include "coap_app.h"
#include "coap_client.h"
#include "nstackx_log.h"
#include "nstackx_util.h"
#include "nstackx_timer.h"
#include "nstackx_error.h"
#include "nstackx_device.h"
#include "json_payload.h"

#define TAG "nStackXCoAP"

#define COAP_URI_BUFFER_LENGTH 64 /* the size of the buffer or variable used to save uri. */
#define COAP_MAX_NUM_SUBSCRIBE_MODULE_COUNT 32 /* the maximum count of subscribed module */

/*
 * 1st discover interval: 100ms
 * 2nd ~ 3rd discover interval: 200ms
 * Remaining discover interval (9 times): 500ms
 */
#define COAP_DEFAULT_DISCOVER_COUNT 12
#define COAP_FIRST_DISCOVER_COUNT_RANGE 1
#define COAP_SECOND_DISCOVER_COUNT_RANGE 3
#define COAP_FIRST_DISCOVER_INTERVAL 100
#define COAP_SECOND_DISCOVER_INTERVAL 200
#define COAP_LAST_DISCOVER_INTERVAL 500
#define COAP_RECV_COUNT_INTERVAL 1000
#define COAP_DISVOCER_MAX_RATE 200
#define COAP_MSGID_SURVIVAL_SECONDS 100
#define COAP_MAX_MSGID_RESERVE_NUM 100

static coap_context_t *g_context = NULL;
static coap_context_t *g_p2pContext = NULL;
static coap_context_t *g_usbContext = NULL;

typedef struct CoapRequest {
    uint8_t type;
    uint8_t code;
    const char *remoteUrl;
    uint8_t *token;
    size_t tokenLength;
    char *data;
    size_t dataLength;
} CoapRequest;

typedef struct {
    uint16_t msgId;
    struct timespec recvTime;
} MsgIdRecord;

typedef struct {
    MsgIdRecord msgIdRecord[COAP_MAX_MSGID_RESERVE_NUM];
    uint32_t startIdx;
    uint32_t endIdx;
} MsgIdList;

static int g_resourceFlags = COAP_RESOURCE_FLAGS_NOTIFY_CON;
static Timer *g_discoverTimer = NULL;
static uint32_t g_discoverCount;
static uint32_t g_coapMaxDiscoverCount = COAP_DEFAULT_DISCOVER_COUNT;
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
        LOGE(TAG, "invalid CoAP URI");
        return NSTACKX_EFAILED;
    }
    if (localUri.scheme != COAP_URI_SCHEME_COAP) {
        LOGE(TAG, "coaps URI scheme not supported in this version of libcoap");
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
    pdu = coap_new_pdu(session);
    if (pdu == NULL) {
        return NULL;
    }
    pdu->type = coapRequest->type;
    pdu->tid = coap_new_message_id(session);
    pdu->code = coapRequest->code;
    if (coapRequest->tokenLength) {
        if (!coap_add_token(pdu, coapRequest->tokenLength, coapRequest->token)) {
            LOGW(TAG, "can't add token to request");
        }
    }
    coap_add_option(pdu, COAP_OPTION_URI_HOST, uriPtr->host.length, uriPtr->host.s);
    coap_add_option(pdu, COAP_OPTION_URI_PATH, uriPtr->path.length, uriPtr->path.s);
    if (coapRequest->dataLength) {
        coap_add_data(pdu, coapRequest->dataLength, (uint8_t *)(coapRequest->data));
    }

    return pdu;
}

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

coap_session_t *CoapGetSessionOnTargetServer(uint8_t serverType, const CoapServerParameter *coapServerParameter)
{
    coap_context_t *context = GetContext(serverType);
    if (context == NULL) {
        LOGE(TAG, "can't get target context with type %hhu", serverType);
        return NULL;
    }
    char ipString[INET_ADDRSTRLEN] = {0};

    if (GetTargetIpString(serverType, ipString, sizeof(ipString)) != NSTACKX_EOK) {
        LOGE(TAG, "can't get target IP with type %hhu", serverType);
        return NULL;
    }
    return CoapGetSession(context, ipString, COAP_SRV_DEFAULT_PORT, coapServerParameter);
}

int32_t CoapSendRequest(const CoapRequest *coapRequest, coap_session_t **sessionPtr, uint8_t serverType)
{
    coap_session_t *session = NULL;
    coap_address_t dst = {0};
    coap_str_const_t remote;
    int32_t tid;
    int32_t res;
    coap_pdu_t *pdu = NULL;
    coap_uri_t coapUri;
    CoapServerParameter coapServerParameter = {0};

    (void)memset_s(&remote, sizeof(remote), 0, sizeof(remote));
    (void)memset_s(&coapUri, sizeof(coapUri), 0, sizeof(coapUri));

    if (coapRequest == NULL || coapRequest->remoteUrl == NULL || sessionPtr == NULL) {
        return NSTACKX_EFAILED;
    }
    if (CoapUriParse(coapRequest->remoteUrl, &coapUri) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }
    remote = coapUri.host;
    res = CoapResolveAddress(&remote, &dst.addr.sa);
    if (res < 0) {
        LOGE(TAG, "fail to resolve address");
        return NSTACKX_EFAILED;
    }

    dst.size = res;
    dst.addr.sin.sin_port = htons(COAP_DEFAULT_PORT);

    coapServerParameter.proto = COAP_PROTO_UDP;
    coapServerParameter.dst = &dst;

    if (*sessionPtr == NULL) {
        session = CoapGetSessionOnTargetServer(serverType, &coapServerParameter);
        if (session == NULL) {
            LOGE(TAG, "coap_get_client_session failed");
            return NSTACKX_EFAILED;
        }
        *sessionPtr = session;
    } else {
        session = *sessionPtr;
    }

    pdu = CoapPackToPdu(coapRequest, &coapUri, session);
    if (pdu == NULL) {
        return NSTACKX_EFAILED;
    }

    tid = coap_send(session, pdu);
    if (tid == COAP_INVALID_TID) {
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}


static int32_t CoapResponseService(const char *remoteUrl)
{
    int32_t ret;
    CoapRequest coapRequest;
    coap_session_t *session = NULL;

    (void)memset_s(&coapRequest, sizeof(coapRequest), 0, sizeof(coapRequest));

    coapRequest.type = COAP_MESSAGE_CON;
    coapRequest.code = COAP_REQUEST_POST;
    coapRequest.remoteUrl = remoteUrl;
    coapRequest.data = PrepareServiceDiscover(NSTACKX_FALSE);
    if (coapRequest.data == NULL) {
        LOGE(TAG, "failed to prepare coap data");
        return NSTACKX_EFAILED;
    } else {
        coapRequest.dataLength = strlen(coapRequest.data) + 1;
    }

    ret = CoapSendRequest(&coapRequest, &session, SERVER_TYPE_WLANORETH);
    if (ret != NSTACKX_EOK) {
        LOGE(TAG, "failed to send coap request");
    }
    free(coapRequest.data);
    coap_session_release(session);

    return ret;
}

static int32_t GetServiceDiscoverInfo(uint8_t *buf, size_t size, DeviceInfo *deviceInfo, char **remoteUrlPtr)
{
    uint8_t *newBuf = NULL;
    if (size <= 0) {
        return NSTACKX_EFAILED;
    }
    if (buf[size - 1] != '\0') {
        newBuf = (uint8_t *)calloc(size + 1, 1U);
        if (newBuf == NULL) {
            LOGE(TAG, "data is not end with 0 and new buf calloc error");
            return NSTACKX_ENOMEM;
        }
        if (memcpy_s(newBuf, size + 1, buf, size) != EOK) {
            LOGE(TAG, "data is not end with 0 and memcpy data error");
            goto L_COAP_ERR;
        }
        LOGI(TAG, "data is not end with 0");
        buf = newBuf;
    }
    if (ParseServiceDiscover(buf, deviceInfo, remoteUrlPtr) != NSTACKX_EOK) {
        LOGE(TAG, "parse service discover error");
        goto L_COAP_ERR;
    }

    if (newBuf != NULL) {
        free(newBuf);
    }

    return NSTACKX_EOK;
L_COAP_ERR:
    if (newBuf != NULL) {
        free(newBuf);
    }
    return NSTACKX_EFAILED;
}

static void IncreaseRecvDiscoverNum(void)
{
    if (g_recvDiscoverMsgNum < UINT32_MAX) {
        g_recvDiscoverMsgNum++;
    }
}

static int32_t HndPostServiceDiscoverInner(coap_pdu_t *request, char **remoteUrl, DeviceInfo *deviceInfo)
{
    size_t size;
    uint8_t *buf = NULL;
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
    if (deviceInfo->mode == PUBLISH_MODE_UPLINE || deviceInfo->mode == PUBLISH_MODE_OFFLINE) {
        LOGD(TAG, "peer is not DISCOVER_MODE");
        NSTACKX_DeviceInfo deviceList[PUBLISH_DEVICE_NUM];
        (void)memset_s(deviceList, sizeof(deviceList), 0, sizeof(deviceList));
        PushPublishInfo(deviceInfo, deviceList, PUBLISH_DEVICE_NUM);
        NotifyDeviceFound(deviceList, PUBLISH_DEVICE_NUM);
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static void HndPostServiceDiscover(coap_context_t *ctx, struct coap_resource_t *resource, coap_session_t *session,
    coap_pdu_t *request, coap_binary_t *token, coap_string_t *query, coap_pdu_t *response)
{
    (void)ctx;
    (void)resource;
    (void)session;
    (void)token;
    (void)query;
    if (request == NULL || response == NULL) {
        return;
    }
    char *remoteUrl = NULL;
    DeviceInfo deviceInfo;
    if (HndPostServiceDiscoverInner(request, &remoteUrl, &deviceInfo) != NSTACKX_EOK) {
        free(remoteUrl);
        return;
    }
    if (GetModeInfo() == PUBLISH_MODE_UPLINE || GetModeInfo() == PUBLISH_MODE_OFFLINE) {
        LOGD(TAG, "local is not DISCOVER_MODE");
        free(remoteUrl);
        return;
    }
    if (UpdateDeviceDb(&deviceInfo, g_forceUpdate) != NSTACKX_EOK) {
        free(remoteUrl);
        return;
    }
    if (g_forceUpdate) {
        g_forceUpdate = NSTACKX_FALSE;
    }
    if (deviceInfo.mode == PUBLISH_MODE_PROACTIVE) {
        LOGD(TAG, "peer is PUBLISH_MODE_PROACTIVE");
        free(remoteUrl);
        return;
    }
    if (remoteUrl != NULL) {
        CoapResponseService(remoteUrl);
        free(remoteUrl);
    } else {
        response->code = COAP_RESPONSE_CODE(COAP_RESPONSE_201);
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
        if (i == g_msgIdList->endIdx) {
            msgIdList->startIdx = COAP_MAX_MSGID_RESERVE_NUM;
            msgIdList->endIdx = COAP_MAX_MSGID_RESERVE_NUM;
            return;
        }
        msgIdList->startIdx = (msgIdList->startIdx + 1) % COAP_MAX_MSGID_RESERVE_NUM;
        i = msgIdList->startIdx;
        if (cycleTimes > COAP_MAX_MSGID_RESERVE_NUM) {
            LOGE(TAG, "cycle too many times, error must occurred and init msgList");
            g_msgIdList->startIdx = COAP_MAX_MSGID_RESERVE_NUM;
            g_msgIdList->endIdx = COAP_MAX_MSGID_RESERVE_NUM;
            break;
        }
        cycleTimes++;
    }
}

static void AddMsgIdRecord(MsgIdList *msgIdList, uint16_t msgId, struct timespec *curTime)
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
        LOGE(TAG, "set msg id time error");
        return;
    }
    msgIdList->endIdx = idx;
}

static uint8_t RefreshMsgIdList(uint16_t msgId)
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
            LOGE(TAG, "cycle too many times, error must occurred and init msgList");
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
        LOGE(TAG, "input size %u is too small", size);
        return 0;
    }
    if (memcpy_s(&frameLen, sizeof(frameLen), frame, sizeof(frameLen)) != EOK) {
        LOGE(TAG, "memcpy frame len failed");
        return 0;
    }
    ret = ntohs(frameLen);
    if (size < ret) {
        LOGE(TAG, "input size %u is smaller than decoded frame len %u", size, ret);
        return 0;
    }
    return ret;
}

static uint16_t GetUnitInfo(const uint8_t *data, uint16_t dataLen, uint8_t *outBuf, uint32_t outLen, uint8_t unitType)
{
    if (dataLen < sizeof(CoapMsgUnit)) {
        LOGE(TAG, "dataLen %u is too small", dataLen);
        return 0;
    }
    CoapMsgUnit *unit = (CoapMsgUnit *)data;
    if (unit->type != unitType) {
        LOGE(TAG, "unit type %u does match target type %u", unit->type, unitType);
        return 0;
    }
    uint16_t valueLen = ntohs(unit->len);
    if (valueLen == 0 || valueLen > outLen || valueLen + sizeof(CoapMsgUnit) > dataLen) {
        LOGE(TAG, "valueLen %u is illegal", valueLen);
        return 0;
    }
    if (memcpy_s(outBuf, outLen, unit->value, valueLen) != EOK) {
        LOGE(TAG, "memcpy unit->value failed");
        return 0;
    }
    if (unitType == COAP_MODULE_NAME_TYPE || unitType == COAP_DEVICE_ID_TYPE) {
        if (outBuf[valueLen - 1] != '\0') {
            LOGE(TAG, "uint type is %u but value is not end with 0", unitType);
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

static void HndPostServiceMsg(coap_context_t *ctx, struct coap_resource_t *resource, coap_session_t *session,
                              coap_pdu_t *request, coap_binary_t *token, coap_string_t *query, coap_pdu_t *response)
{
    (void)ctx;
    (void)resource;
    (void)session;
    (void)token;
    (void)query;
    if (request == NULL || response == NULL) {
        return;
    }
    char deviceId[NSTACKX_MAX_DEVICE_ID_LEN] = {0};
    char moduleName[NSTACKX_MAX_MODULE_NAME_LEN] = {0};
    uint8_t *msg = NULL;
    uint8_t *buf = NULL;
    uint16_t msgLen;
    size_t size;

    if (coap_get_data(request, &size, &buf) == 0 || size == 0 || size > COAP_RXBUFFER_SIZE) {
        return;
    }

    if (!RefreshMsgIdList(request->tid)) {
        LOGE(TAG, "repeated msg id");
        return;
    }

    LOGD(TAG, "handling post service msg request");
    msgLen = ParseServiceMsgFrame(buf, size, moduleName, deviceId, &msg);
    if (msgLen == 0) {
        LOGD(TAG, "parse service msg frame error");
        return;
    }

    NotifyMsgReceived(moduleName, deviceId, msg, msgLen);

    response->code = COAP_RESPONSE_CODE(COAP_RESPONSE_201);
    free(msg);
    return;
}

static int32_t CoapPostServiceDiscover(void)
{
    int32_t ret;
    coap_session_t *session = NULL;
    char ifName[NSTACKX_MAX_INTERFACE_NAME_LEN] = {0};
    char ipString[NSTACKX_MAX_IP_STRING_LEN] = {0};
    char discoverUri[COAP_URI_BUFFER_LENGTH] = {0};
    CoapRequest coapRequest = {0};
    (void)memset_s(&coapRequest, sizeof(coapRequest), 0, sizeof(coapRequest));

    if (GetLocalInterfaceName(ifName, sizeof(ifName)) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }

    if (GetIfBroadcastIp(ifName, ipString, sizeof(ipString)) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }

    if (sprintf_s(discoverUri, sizeof(discoverUri), "coap://%s/%s", ipString, COAP_DEVICE_DISCOVER_URI) < 0) {
        return NSTACKX_EFAILED;
    }
    coapRequest.type = COAP_MESSAGE_NON;
    coapRequest.code = COAP_REQUEST_POST;
    coapRequest.remoteUrl = discoverUri;
    coapRequest.data = PrepareServiceDiscover(NSTACKX_TRUE);
    if (coapRequest.data == NULL) {
        LOGE(TAG, "failed to prepare coap data");
        return NSTACKX_EFAILED;
    } else {
        coapRequest.dataLength = strlen(coapRequest.data) + 1;
    }

    ret = CoapSendRequest(&coapRequest, &session, SERVER_TYPE_WLANORETH);
    if (ret != NSTACKX_EOK) {
        LOGE(TAG, "failed to send coap request");
    }
    free(coapRequest.data);
    coap_session_release(session);

    return ret;
}

static uint32_t GetDiscoverInterval(uint32_t discoverCount)
{
    if (discoverCount < COAP_FIRST_DISCOVER_COUNT_RANGE) {
        return COAP_FIRST_DISCOVER_INTERVAL;
    } else if (discoverCount < COAP_SECOND_DISCOVER_COUNT_RANGE) {
        return COAP_SECOND_DISCOVER_INTERVAL;
    }
    return COAP_LAST_DISCOVER_INTERVAL;
}

static void CoapServiceDiscoverStop(void)
{
    g_discoverCount = 0;
    g_forceUpdate = NSTACKX_FALSE;
    SetModeInfo(DISCOVER_MODE);
    ClearDevices(GetDeviceDBBackup());
    LOGW(TAG, "clear device list backup");
    /* Can call PostDeviceFindWrapper() to notify user if needed. */
    g_userRequest = NSTACKX_FALSE;
}

static void CoapServiceDiscoverTimerHandle(void *argument)
{
    uint32_t discoverInterval;

    (void)argument;

    if (g_discoverCount >= g_coapDiscoverTargetCount || !IsWifiApConnected()) {
        /* Discover done, or wifi AP disconnected. */
        CoapServiceDiscoverStop();
        return;
    }

    if (CoapPostServiceDiscover() != NSTACKX_EOK) {
        LOGE(TAG, "failed to post service discover request");
        goto L_ERR_SERVICE_DISCOVER;
    }
    LOGI(TAG, "the %d times for device discover.", g_discoverCount + 1);

    /* Restart timer */
    discoverInterval = GetDiscoverInterval(g_discoverCount);

    ++g_discoverCount;
    if (TimerSetTimeout(g_discoverTimer, discoverInterval, NSTACKX_FALSE) != NSTACKX_EOK) {
        LOGE(TAG, "failed to set timer for service discover");
        goto L_ERR_SERVICE_DISCOVER;
    }
    return;

L_ERR_SERVICE_DISCOVER:
    /* Abort service discover by not starting timer. */
    LOGE(TAG, "abort service discover, have tried %u request", g_discoverCount);
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
    return;
}

void CoapServiceDiscoverInner(uint8_t userRequest)
{
    uint32_t discoverInterval;
    if (!IsWifiApConnected() || g_context == NULL) {
        return;
    }

    if (userRequest) {
        g_userRequest = NSTACKX_TRUE;
        g_forceUpdate = NSTACKX_TRUE;
    }

    if (g_coapDiscoverTargetCount > 0 && g_discoverCount >= g_coapDiscoverTargetCount) {
        g_discoverCount = 0;
        SetModeInfo(DISCOVER_MODE);
        ClearDevices(GetDeviceDBBackup());
        LOGW(TAG, "clear device list backup");
        TimerSetTimeout(g_discoverTimer, 0, NSTACKX_FALSE);
    }

    if (g_discoverCount) {
        /* Service discover is ongoing, return. */
        return;
    } else {
        /* First discover */
        if (BackupDeviceDB() != NSTACKX_EOK) {
            LOGE(TAG, "backup device list fail");
            return;
        }
        ClearDevices(GetDeviceDB());
        LOGW(TAG, "clear device list");
        g_coapDiscoverTargetCount = g_coapMaxDiscoverCount;
    }
    SetModeInfo(DISCOVER_MODE);
    if (CoapPostServiceDiscover() != NSTACKX_EOK) {
        LOGE(TAG, "failed to post service discover request");
        return;
    }

    discoverInterval = GetDiscoverInterval(g_discoverCount);
    if (TimerSetTimeout(g_discoverTimer, discoverInterval, NSTACKX_FALSE) != NSTACKX_EOK) {
        LOGE(TAG, "failed to set timer for service discover");
        return;
    }
    ++g_discoverCount;
    LOGI(TAG, "the first time for device discover.");

    return;
}

void CoapServiceDiscoverInnerAn(uint8_t userRequest)
{
    if (!IsWifiApConnected() || g_context == NULL) {
        return;
    }

    if (userRequest) {
        g_userRequest = NSTACKX_TRUE;
    }

    if (g_discoverCount) {
        g_discoverCount = 0;
        /* Service discover is ongoing, reset. */
        TimerSetTimeout(g_discoverTimer, 0, NSTACKX_FALSE);
    } else {
        g_coapDiscoverTargetCount = g_coapMaxDiscoverCount;
    }

    if (CoapPostServiceDiscover() != NSTACKX_EOK) {
        LOGE(TAG, "failed to post service discover request");
        return;
    }

    uint32_t discoverInterval = GetDiscoverInterval(g_discoverCount);
    if (TimerSetTimeout(g_discoverTimer, discoverInterval, NSTACKX_FALSE) != NSTACKX_EOK) {
        LOGE(TAG, "failed to set timer for service discover");
        return;
    }
    ++g_discoverCount;
    LOGI(TAG, "the first time for device discover.");

    return;
}

void CoapServiceDiscoverStopInner(void)
{
    TimerSetTimeout(g_discoverTimer, 0, NSTACKX_FALSE);
    CoapServiceDiscoverStop();
    LOGI(TAG, "device discover stopped");
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
            LOGE(TAG, "DefiniteTargetIp getContext: g_context for wlan or eth is null");
        }
        return g_context;
    } else if (serverType == SERVER_TYPE_P2P) {
        if (g_p2pContext == NULL) {
            LOGE(TAG, "DefiniteTargetIp getContext: g_p2pContext for p2p is null");
        }
        return g_p2pContext;
    } else if (serverType == SERVER_TYPE_USB) {
        if (g_usbContext == NULL) {
            LOGE(TAG, "DefiniteTargetIp getContext: g_usbContext for usb is null");
        }
        return g_usbContext;
    } else {
        LOGE(TAG, "Coap serverType is unknown");
        return NULL;
    }
}

int32_t CoapSendServiceMsgWithDefiniteTargetIp(MsgCtx *msgCtx, DeviceInfo *deviceInfo)
{
    char ipString[INET_ADDRSTRLEN] = {0};
    char uriBuffer[COAP_URI_BUFFER_LENGTH] = {0};
    int32_t ret;
    CoapRequest coapRequest;
    coap_session_t *session = NULL;
    uint16_t dataLen = 0;
    uint8_t actualType = GetActualType(msgCtx->type, msgCtx->p2pAddr);
    LOGD(TAG, "actualType is %hhu", actualType);
    if (msgCtx->len == 0 || msgCtx->len > NSTACKX_MAX_SENDMSG_DATA_LEN) {
        return NSTACKX_EINVAL;
    }

    (void)memset_s(&coapRequest, sizeof(coapRequest), 0, sizeof(coapRequest));

    coapRequest.type = COAP_MESSAGE_CON;
    coapRequest.code = COAP_REQUEST_POST;

    if (strlen(msgCtx->p2pAddr) == 0) {
        if (deviceInfo == NULL) {
            return NSTACKX_EFAILED;
        }
        if (inet_ntop(AF_INET, &deviceInfo->netChannelInfo.wifiApInfo.ip, ipString, sizeof(ipString)) == NULL) {
            LOGE(TAG, "inet_ntop failed: %d", errno);
            return NSTACKX_EFAILED;
        }
    } else {
        if (strcpy_s(ipString, sizeof(ipString), msgCtx->p2pAddr) != EOK) {
            LOGE(TAG, "failed to get ip");
            return NSTACKX_EFAILED;
        }
    }

    if (sprintf_s(uriBuffer, sizeof(uriBuffer), "coap://%s/" COAP_SERVICE_MSG_URI, ipString) < 0) {
        return NSTACKX_EFAILED;
    }
    coapRequest.remoteUrl = uriBuffer;
    coapRequest.data = (char *)CreateServiceMsgFrame(msgCtx->moduleName,
        GetLocalDeviceInfoPtr()->deviceId, msgCtx->data, msgCtx->len, &dataLen);
    if (coapRequest.data == NULL) {
        LOGE(TAG, "failed to prepare msg data");
        return NSTACKX_EFAILED;
    }
    coapRequest.dataLength = dataLen;

    ret = CoapSendRequest(&coapRequest, &session, actualType);
    if (ret != NSTACKX_EOK) {
        LOGE(TAG, "failed to send coap request");
    }
    free(coapRequest.data);
    coap_session_release(session);
    return ret;
}

uint8_t GetActualType(const uint8_t type, const char *dstIp)
{
    if (type != INVALID_TYPE) {
        return type;
    }
    struct sockaddr_in localAddr;
    localAddr.sin_addr.s_addr = inet_addr(dstIp);
    struct ifreq localDev;
    GetTargetInterface(&localAddr, &localDev);
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
    return type;
}

static void CoapRecvRecountTimerHandle(void *argument)
{
    (void)argument;
    if (g_recvDiscoverMsgNum > COAP_DISVOCER_MAX_RATE) {
        LOGI(TAG, "received %u discover msg in this interval", g_recvDiscoverMsgNum);
    }
    g_recvDiscoverMsgNum = 0;
    return;
}

void CoapInitResources(coap_context_t *ctx, uint8_t serverType)
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

    if (serverType == SERVER_TYPE_WLANORETH) {
        g_context = ctx;
        LOGD(TAG, "CoapInitResources g_wlanOrEthContext update");
    } else if (serverType == SERVER_TYPE_P2P) {
        g_p2pContext = ctx;
        LOGD(TAG, "CoapInitResources g_p2pContext update");
    } else if (serverType == SERVER_TYPE_USB) {
        g_usbContext = ctx;
        LOGD(TAG, "CoapInitResources g_usbContext update");
    } else {
        LOGE(TAG, "CoapInitResources serverType is unknown!");
    }
}

int32_t CoapDiscoverInit(EpollDesc epollfd)
{
    if (g_recvRecountTimer == NULL) {
        g_recvRecountTimer = TimerStart(epollfd, COAP_RECV_COUNT_INTERVAL, NSTACKX_TRUE,
                                        CoapRecvRecountTimerHandle, NULL);
    }
    if (g_recvRecountTimer == NULL) {
        LOGE(TAG, "failed to start timer for receive discover message recount");
        return NSTACKX_EFAILED;
    }

    if (g_discoverTimer == NULL) {
        g_discoverTimer = TimerStart(epollfd, 0, NSTACKX_FALSE, CoapServiceDiscoverTimerHandle, NULL);
    }
    if (g_discoverTimer == NULL) {
        LOGE(TAG, "failed to start timer for service discover");
        TimerDelete(g_recvRecountTimer);
        g_recvRecountTimer = NULL;
        return NSTACKX_EFAILED;
    }

    g_msgIdList = (MsgIdList *)calloc(1U, sizeof(MsgIdList));
    if (g_msgIdList == NULL) {
        LOGE(TAG, "message Id record list calloc error");
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

void CoapDestroyCtx(uint8_t serverType)
{
    if (serverType == SERVER_TYPE_WLANORETH) {
        g_context = NULL;
        LOGD(TAG, "CoapDestroyCtx, g_context is set to NULL");
    } else if (serverType == SERVER_TYPE_P2P) {
        g_p2pContext = NULL;
        LOGD(TAG, "CoapDestroyCtx, g_p2pContext is set to NULL");
    } else if (serverType == SERVER_TYPE_USB) {
        g_usbContext = NULL;
        LOGD(TAG, "CoapDestroyCtx, g_usbContext is set to NULL");
    } else {
        LOGE(TAG, "CoapDestroyCtx, serverType is unknown");
    }
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
    if (g_msgIdList != NULL) {
        free(g_msgIdList);
        g_msgIdList = NULL;
    }
}

void ResetCoapDiscoverTaskCount(uint8_t isBusy)
{
    if (g_discoverTimer != NULL) {
        if (isBusy) {
            LOGI(TAG, "in this busy interval: g_discoverTimer task count %llu", g_discoverTimer->task.count);
        }
        g_discoverTimer->task.count = 0;
    }
    if (g_recvRecountTimer != NULL) {
        if (isBusy) {
            LOGI(TAG, "in this busy interval: g_recvRecountTimer task count %llu", g_recvRecountTimer->task.count);
        }
        g_recvRecountTimer->task.count = 0;
    }
}
