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

#include "trans_tcp_direct_message.h"

#include <securec.h>
#include <string.h>

#include "auth_interface.h"
#include "bus_center_manager.h"
#include "cJSON.h"
#include "p2plink_interface.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_adapter_socket.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_message_open_channel.h"
#include "softbus_socket.h"
#include "trans_tcp_direct_callback.h"
#include "trans_tcp_direct_manager.h"
#include "trans_tcp_direct_sessionconn.h"

#define MAX_PACKET_SIZE (64 * 1024)

typedef struct {
    ListNode node;
    int32_t channelId;
    int32_t fd;
    uint32_t size;
    char *data;
    char *w;
} ServerDataBuf;

static SoftBusList *g_tcpSrvDataList = NULL;

static void PackTdcPacketHead(TdcPacketHead *data)
{
    data->magicNumber = SoftBusHtoLl(data->magicNumber);
    data->module = SoftBusHtoLl(data->module);
    data->seq = SoftBusHtoLll(data->seq);
    data->flags = SoftBusHtoLl(data->flags);
    data->dataLen = SoftBusHtoLl(data->dataLen);
}

static void UnpackTdcPacketHead(TdcPacketHead *data)
{
    data->magicNumber = SoftBusLtoHl(data->magicNumber);
    data->module = SoftBusLtoHl(data->module);
    data->seq = SoftBusLtoHll(data->seq);
    data->flags = SoftBusLtoHl(data->flags);
    data->dataLen = SoftBusLtoHl(data->dataLen);
}

int32_t TransSrvDataListInit(void)
{
    if (g_tcpSrvDataList != NULL) {
        return SOFTBUS_OK;
    }
    g_tcpSrvDataList = CreateSoftBusList();
    if (g_tcpSrvDataList == NULL) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void TransSrvDestroyDataBuf(void)
{
    if (g_tcpSrvDataList ==  NULL) {
        return;
    }

    ServerDataBuf *item = NULL;
    ServerDataBuf *next = NULL;
    SoftBusMutexLock(&g_tcpSrvDataList->lock);
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_tcpSrvDataList->list, ServerDataBuf, node) {
        ListDelete(&item->node);
        SoftBusFree(item->data);
        SoftBusFree(item);
        g_tcpSrvDataList->cnt--;
    }
    SoftBusMutexUnlock(&g_tcpSrvDataList->lock);

    return;
}

void TransSrvDataListDeinit(void)
{
    if (g_tcpSrvDataList == NULL) {
        return;
    }
    TransSrvDestroyDataBuf();
    DestroySoftBusList(g_tcpSrvDataList);
    g_tcpSrvDataList = NULL;
}

int32_t TransSrvAddDataBufNode(int32_t channelId, int32_t fd)
{
#define MAX_DATA_BUF 4096
    ServerDataBuf *node = (ServerDataBuf *)SoftBusCalloc(sizeof(ServerDataBuf));
    if (node == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "create server data buf node fail.");
        return SOFTBUS_MALLOC_ERR;
    }
    node->channelId = channelId;
    node->fd = fd;
    node->size = MAX_DATA_BUF;
    node->data = (char*)SoftBusCalloc(MAX_DATA_BUF);
    if (node->data == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "create server data buf fail.");
        SoftBusFree(node);
        return SOFTBUS_MALLOC_ERR;
    }
    node->w = node->data;

    SoftBusMutexLock(&(g_tcpSrvDataList->lock));
    ListInit(&node->node);
    ListTailInsert(&g_tcpSrvDataList->list, &node->node);
    g_tcpSrvDataList->cnt++;
    SoftBusMutexUnlock(&(g_tcpSrvDataList->lock));

    return SOFTBUS_OK;
}

void TransSrvDelDataBufNode(int channelId)
{
    if (g_tcpSrvDataList ==  NULL) {
        return;
    }

    ServerDataBuf *item = NULL;
    ServerDataBuf *next = NULL;
    SoftBusMutexLock(&g_tcpSrvDataList->lock);
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_tcpSrvDataList->list, ServerDataBuf, node) {
        if (item->channelId == channelId) {
            ListDelete(&item->node);
            SoftBusFree(item->data);
            SoftBusFree(item);
            g_tcpSrvDataList->cnt--;
            break;
        }
    }
    SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
}

static AuthLinkType SwitchCipherTypeToAuthLinkType(uint32_t cipherFlag)
{
    if (cipherFlag & FLAG_BR) {
        return AUTH_LINK_TYPE_BR;
    }

    if (cipherFlag & FLAG_BLE) {
        return AUTH_LINK_TYPE_BLE;
    }

    if (cipherFlag & FLAG_P2P) {
        return AUTH_LINK_TYPE_P2P;
    }
    return AUTH_LINK_TYPE_WIFI;
}

static int32_t PackBytes(int32_t channelId, const char *data, TdcPacketHead *packetHead,
    char *buffer, uint32_t bufLen)
{
    int64_t authId = GetAuthIdByChanId(channelId);
    if (authId == AUTH_INVALID_ID) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "PackBytes get auth id fail");
        return SOFTBUS_NOT_FIND;
    }

    uint8_t *encData = (uint8_t *)buffer + DC_MSG_PACKET_HEAD_SIZE;
    uint32_t encDataLen = bufLen - DC_MSG_PACKET_HEAD_SIZE;
    if (AuthEncrypt(authId, (const uint8_t *)data, packetHead->dataLen, encData, &encDataLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "PackBytes encrypt fail");
        return SOFTBUS_ENCRYPT_ERR;
    }
    packetHead->dataLen = encDataLen;

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "PackBytes: flag=0x%x, seq=%" PRIu64,
        packetHead->flags, packetHead->seq);

    PackTdcPacketHead(packetHead);
    if (memcpy_s(buffer, bufLen, packetHead, sizeof(TdcPacketHead)) != EOK) {
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransTdcPostBytes(int32_t channelId, TdcPacketHead *packetHead, const char *data)
{
    if (data == NULL || packetHead == NULL || packetHead->dataLen == 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid para.");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t bufferLen = AuthGetEncryptSize(packetHead->dataLen) + DC_MSG_PACKET_HEAD_SIZE;
    char *buffer = (char *)SoftBusMalloc(bufferLen);
    if (buffer == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "buffer malloc error.");
        return SOFTBUS_MALLOC_ERR;
    }
    AnonyPacketPrintout(SOFTBUS_LOG_TRAN, "TransTdcPostBytes, data: ", data, packetHead->dataLen);
    if (PackBytes(channelId, data, packetHead, buffer, bufferLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Pack Bytes error.");
        SoftBusFree(buffer);
        return SOFTBUS_ENCRYPT_ERR;
    }
    SessionConn *conn = SoftBusCalloc(sizeof(SessionConn));
    if (conn == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "malloc conn fail");
        SoftBusFree(buffer);
        return SOFTBUS_ERR;
    }

    if (GetSessionConnById(channelId, conn) == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Get SessionConn fail");
        SoftBusFree(buffer);
        SoftBusFree(conn);
        return SOFTBUS_ERR;
    }
    int fd = conn->appInfo.fd;
    SoftBusFree(conn);
    if (ConnSendSocketData(fd, buffer, bufferLen, 0) != (int)bufferLen) {
        SoftBusFree(buffer);
        return SOFTBUS_ERR;
    }
    SoftBusFree(buffer);
    return SOFTBUS_OK;
}

static int32_t NotifyChannelOpened(int32_t channelId)
{
    SessionConn conn;
    if (GetSessionConnById(channelId, &conn) == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "notify channel open failed, get tdcInfo is null");
        return SOFTBUS_ERR;
    }
    ChannelInfo info = {0};
    info.channelId = channelId;
    info.channelType = CHANNEL_TYPE_TCP_DIRECT;
    info.isServer = conn.serverSide;
    info.isEnabled = true;
    info.fd = conn.appInfo.fd;
    info.sessionKey = conn.appInfo.sessionKey;

    info.peerSessionName = conn.appInfo.peerData.sessionName;
    info.groupId = conn.appInfo.groupId;
    info.keyLen = SESSION_KEY_LENGTH;
    info.peerUid = conn.appInfo.peerData.uid;
    info.peerPid = conn.appInfo.peerData.pid;
    info.routeType = conn.appInfo.routeType;

    char buf[NETWORK_ID_BUF_LEN] = {0};
    int32_t ret = LnnGetNetworkIdByUuid(conn.appInfo.peerData.deviceId, buf, NETWORK_ID_BUF_LEN);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get info networkId fail.");
        return SOFTBUS_ERR;
    }
    info.peerDeviceId = buf;

    char pkgName[PKG_NAME_SIZE_MAX] = {0};
    if (TransTdcGetPkgName(conn.appInfo.myData.sessionName, pkgName, PKG_NAME_SIZE_MAX) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get pkg name fail.");
        return SOFTBUS_ERR;
    }

    ret = TransTdcOnChannelOpened(pkgName, conn.appInfo.myData.sessionName, &info);
    conn.status = TCP_DIRECT_CHANNEL_STATUS_CONNECTED;
    SetSessionConnStatusById(channelId, conn.status);
    return ret;
}

int32_t NotifyChannelOpenFailed(int32_t channelId)
{
    SessionConn conn;
    if (GetSessionConnById(channelId, &conn) == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "notify channel open failed, get tdcInfo is null");
        return SOFTBUS_ERR;
    }

    char pkgName[PKG_NAME_SIZE_MAX] = {0};
    if (TransTdcGetPkgName(conn.appInfo.myData.sessionName, pkgName, PKG_NAME_SIZE_MAX) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get pkg name fail.");
        return SOFTBUS_ERR;
    }

    if (conn.serverSide == false) {
        int ret = TransTdcOnChannelOpenFailed(pkgName, channelId);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO,
            "TCP direct channel failed, channelId = %d, ret = %d", channelId, ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t OpenDataBusReply(int32_t channelId, uint64_t seq, const cJSON *reply)
{
    (void)seq;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OpenDataBusReply: channelId=%d", channelId);
    SessionConn conn;
    if (GetSessionConnById(channelId, &conn) == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "notify channel open failed, get tdcInfo is null");
        return SOFTBUS_ERR;
    }
    if (UnpackReply(reply, &conn.appInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "UnpackReply failed");
        return SOFTBUS_ERR;
    }

    if (SetAppInfoById(channelId, &conn.appInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "set app info by id failed.");
        return SOFTBUS_ERR;
    }

    if (NotifyChannelOpened(channelId) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OpenDataBusReply ok");
    return SOFTBUS_OK;
}

static int32_t OpenDataBusRequestReply(const AppInfo *appInfo, int32_t channelId, uint64_t seq,
    int32_t errCode, uint32_t flags)
{
    char *reply = NULL;
    if (errCode != SOFTBUS_OK) {
        char *errDesc = "notifyChannelOpened";
        reply = PackError(errCode, errDesc);
    } else {
        reply = PackReply(appInfo);
    }
    if (reply == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenDataBusRequestReply get pack reply err");
        return SOFTBUS_ERR;
    }

    TdcPacketHead packetHead = {
        .magicNumber = MAGIC_NUMBER,
        .module = MODULE_SESSION,
        .seq = seq,
        .flags = (FLAG_REPLY | flags),
        .dataLen = strlen(reply),
    };
    int32_t ret = TransTdcPostBytes(channelId, &packetHead, reply);
    cJSON_free(reply);
    return ret;
}

static int32_t GetUuidByChanId(int32_t channelId, char *uuid, uint32_t len)
{
    int64_t authId = GetAuthIdByChanId(channelId);
    if (authId == AUTH_INVALID_ID) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GetUuidByChanId get authId fail");
        return SOFTBUS_ERR;
    }
    return AuthGetDeviceUuid(authId, uuid, len);
}

static void OpenDataBusRequestOutSessionName(const char *mySessionName, const char *peerSessionName)
{
    char *anonyOutMy = NULL;
    char *anonyOutPeer = NULL;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OpenDataBusRequest: mySessionName=%s, peerSessionName=%s",
        AnonyDevId(&anonyOutMy, mySessionName), AnonyDevId(&anonyOutPeer, peerSessionName));
    SoftBusFree(anonyOutMy);
    SoftBusFree(anonyOutPeer);
}

static int32_t OpenDataBusRequest(int32_t channelId, uint32_t flags, uint64_t seq, const cJSON *request)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OpenDataBusRequest channelId=%d", channelId);
    SessionConn *conn = SoftBusCalloc(sizeof(SessionConn));
    if (conn == NULL) {
        return SOFTBUS_ERR;
    }
    if (GetSessionConnById(channelId, conn) == NULL) {
        SoftBusFree(conn);
        return SOFTBUS_INVALID_PARAM;
    }
    if (UnpackRequest(request, &conn->appInfo) != SOFTBUS_OK) {
        SoftBusFree(conn);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "UnpackRequest error");
        return SOFTBUS_ERR;
    }

    if (TransTdcGetUidAndPid(conn->appInfo.myData.sessionName,
        &conn->appInfo.myData.uid, &conn->appInfo.myData.pid) != SOFTBUS_OK) {
        SoftBusFree(conn);
        return SOFTBUS_ERR;
    }

    if (GetUuidByChanId(channelId, conn->appInfo.peerData.deviceId, DEVICE_ID_SIZE_MAX) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Get Uuid By ChanId failed.");
        SoftBusFree(conn);
        return SOFTBUS_ERR;
    }

    if (SetAppInfoById(channelId, &conn->appInfo) != SOFTBUS_OK) {
        SoftBusFree(conn);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "set app info by id failed.");
        return SOFTBUS_ERR;
    }
    OpenDataBusRequestOutSessionName(conn->appInfo.myData.sessionName, conn->appInfo.peerData.sessionName);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OpenDataBusRequest: myPid=%d, peerPid=%d",
        conn->appInfo.myData.pid, conn->appInfo.peerData.pid);

    int32_t ret = NotifyChannelOpened(channelId);
    if (OpenDataBusRequestReply(&conn->appInfo, channelId, seq, ret, flags) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenDataBusRequest reply err");
        SoftBusFree(conn);
        return SOFTBUS_ERR;
    }
    SoftBusFree(conn);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenDataBusRequest notify app err");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OpenDataBusRequest ok");
    return SOFTBUS_OK;
}

static int32_t ProcessMessage(int32_t channelId, uint32_t flags, uint64_t seq, const char *msg)
{
    int32_t ret;
    cJSON *json = cJSON_Parse(msg);
    if (json == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "ProcessMessage: json parse failed.");
        return SOFTBUS_ERR;
    }
    if (flags & FLAG_REPLY) {
        ret = OpenDataBusReply(channelId, seq, json);
    } else {
        ret = OpenDataBusRequest(channelId, flags, seq, json);
    }
    cJSON_Delete(json);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ProcessMessage: ret = [%d]", ret);
    return ret;
}

static ServerDataBuf *TransSrvGetDataBufNodeById(int32_t channelId)
{
    if (g_tcpSrvDataList ==  NULL) {
        return NULL;
    }

    ServerDataBuf *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_tcpSrvDataList->list), ServerDataBuf, node) {
        if (item->channelId == channelId) {
            return item;
        }
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv tcp direct channel id not exist.");
    return NULL;
}

static int64_t GetAuthIdByChannelInfo(int32_t channelId, uint64_t seq, uint32_t cipherFlag)
{
    int64_t authId = GetAuthIdByChanId(channelId);
    if (authId != AUTH_INVALID_ID) {
        return authId;
    }

    AppInfo appInfo;
    if (GetAppInfoById(channelId, &appInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get appInfo fail");
        return AUTH_INVALID_ID;
    }

    bool fromAuthServer = ((seq & AUTH_CONN_SERVER_SIDE) != 0);
    char p2pMac[P2P_MAC_LEN] = {0};
    if (P2pLinkGetPeerMacByPeerIp(appInfo.peerData.addr, p2pMac, sizeof(p2pMac)) != SOFTBUS_OK) {
        AuthConnInfo connInfo;
        connInfo.type = AUTH_LINK_TYPE_WIFI;
        if (strcpy_s(connInfo.info.ipInfo.ip, IP_LEN, appInfo.peerData.addr) != EOK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "copy ip addr fail");
            return AUTH_INVALID_ID;
        }
        return AuthGetIdByConnInfo(&connInfo, !fromAuthServer);
    }

    AuthLinkType linkType = SwitchCipherTypeToAuthLinkType(cipherFlag);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "get auth linktype %d flag 0x%x", linkType, cipherFlag);
    return AuthGetIdByP2pMac(p2pMac, linkType, !fromAuthServer);
}

static int32_t DecryptMessage(int32_t channelId, const TdcPacketHead *pktHead, const uint8_t *pktData,
    uint8_t **outData, uint32_t *outDataLen)
{
    int64_t authId = GetAuthIdByChannelInfo(channelId, pktHead->seq, pktHead->flags);
    if (authId == AUTH_INVALID_ID) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv process recv data: get authId fail.");
        return SOFTBUS_NOT_FIND;
    }
    if (SetAuthIdByChanId(channelId, authId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv process recv data: set authId fail.");
        return SOFTBUS_ERR;
    }

    uint32_t decDataLen = AuthGetDecryptSize(pktHead->dataLen) + 1;
    uint8_t *decData = (uint8_t *)SoftBusCalloc(decDataLen);
    if (decData == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv process recv data: malloc fail.");
        return SOFTBUS_MALLOC_ERR;
    }
    if (AuthDecrypt(authId, pktData, pktHead->dataLen, decData, &decDataLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv process recv data: decrypt fail.");
        SoftBusFree(decData);
        return SOFTBUS_DECRYPT_ERR;
    }
    *outData = decData;
    *outDataLen = decDataLen;
    return SOFTBUS_OK;
}

static int32_t ProcessReceivedData(int32_t channelId)
{
    uint64_t seq;
    uint32_t flags;
    uint8_t *data = NULL;
    uint32_t dataLen = 0;

    SoftBusMutexLock(&g_tcpSrvDataList->lock);
    ServerDataBuf *node = TransSrvGetDataBufNodeById(channelId);
    if (node == NULL || node->data == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "node is null.");
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        return SOFTBUS_ERR;
    }
    TdcPacketHead *pktHead = (TdcPacketHead *)(node->data);
    uint8_t *pktData = (uint8_t *)(node->data + sizeof(TdcPacketHead));
    if (pktHead->module != MODULE_SESSION) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv process recv data: illegal module.");
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        return SOFTBUS_ERR;
    }
    seq = pktHead->seq;
    flags = pktHead->flags;

    if (DecryptMessage(channelId, pktHead, pktData, &data, &dataLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv process recv data: decrypt fail.");
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        return SOFTBUS_DECRYPT_ERR;
    }

    char *end = node->data + sizeof(TdcPacketHead) + pktHead->dataLen;
    if (memmove_s(node->data, node->size, end, node->w - end) != EOK) {
        SoftBusFree(data);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memmove fail.");
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        return SOFTBUS_MEM_ERR;
    }
    node->w = node->w - sizeof(TdcPacketHead) - pktHead->dataLen;
    SoftBusMutexUnlock(&g_tcpSrvDataList->lock);

    AnonyPacketPrintout(SOFTBUS_LOG_TRAN, "TdcProcessReceivedData, data: ", (char *)data, dataLen);
    int32_t ret = ProcessMessage(channelId, flags, seq, (char *)data);
    SoftBusFree(data);
    return ret;
}

static int32_t TransTdcSrvProcData(ListenerModule module, int32_t channelId)
{
    SoftBusMutexLock(&g_tcpSrvDataList->lock);
    ServerDataBuf *node = TransSrvGetDataBufNodeById(channelId);
    if (node == NULL) {
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv can not get buf node.");
        return SOFTBUS_ERR;
    }

    uint32_t bufLen = node->w - node->data;
    if (bufLen < DC_MSG_PACKET_HEAD_SIZE) {
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "srv head not enough, recv next time.");
        return SOFTBUS_DATA_NOT_ENOUGH;
    }

    TdcPacketHead *pktHead = (TdcPacketHead *)(node->data);
    UnpackTdcPacketHead(pktHead);
    if (pktHead->magicNumber != MAGIC_NUMBER) {
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv recv invalid packet head");
        return SOFTBUS_ERR;
    }

    uint32_t dataLen = pktHead->dataLen;
    if (dataLen > node->size - DC_MSG_PACKET_HEAD_SIZE) {
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv out of recv buf size[%d]", dataLen);
        return SOFTBUS_ERR;
    }

    if (bufLen < dataLen + DC_MSG_PACKET_HEAD_SIZE) {
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "srv data not enough, recv next time.[%d][%d][%d]",
            bufLen, dataLen, DC_MSG_PACKET_HEAD_SIZE);
        return SOFTBUS_DATA_NOT_ENOUGH;
    }
    DelTrigger(module, node->fd, READ_TRIGGER);
    SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
    return ProcessReceivedData(channelId);
}

int32_t TransTdcSrvRecvData(ListenerModule module, int32_t channelId)
{
    SoftBusMutexLock(&g_tcpSrvDataList->lock);
    ServerDataBuf *node = TransSrvGetDataBufNodeById(channelId);
    if (node == NULL) {
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv can not find data buf node.");
        return SOFTBUS_ERR;
    }
    int32_t ret = ConnRecvSocketData(node->fd, node->w, node->size - (node->w - node->data), 0);
    if (ret < 0) {
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "recv tcp data fail.");
        return SOFTBUS_ERR;
    }
    node->w += ret;
    SoftBusMutexUnlock(&g_tcpSrvDataList->lock);

    return TransTdcSrvProcData(module, channelId);
}
