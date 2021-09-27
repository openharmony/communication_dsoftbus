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
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_message_open_channel.h"
#include "softbus_tcp_socket.h"
#include "trans_tcp_direct_callback.h"
#include "trans_tcp_direct_manager.h"

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
    pthread_mutex_lock(&g_tcpSrvDataList->lock);
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_tcpSrvDataList->list, ServerDataBuf, node) {
        ListDelete(&item->node);
        SoftBusFree(item->data);
        SoftBusFree(item);
        g_tcpSrvDataList->cnt--;
    }
    pthread_mutex_unlock(&g_tcpSrvDataList->lock);

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

    pthread_mutex_lock(&(g_tcpSrvDataList->lock));
    ListInit(&node->node);
    ListTailInsert(&g_tcpSrvDataList->list, &node->node);
    g_tcpSrvDataList->cnt++;
    pthread_mutex_unlock(&(g_tcpSrvDataList->lock));

    return SOFTBUS_OK;
}

void TransSrvDelDataBufNode(int channelId)
{
    if (g_tcpSrvDataList ==  NULL) {
        return;
    }

    ServerDataBuf *item = NULL;
    ServerDataBuf *next = NULL;
    pthread_mutex_lock(&g_tcpSrvDataList->lock);
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_tcpSrvDataList->list, ServerDataBuf, node) {
        if (item->channelId == channelId) {
            ListDelete(&item->node);
            SoftBusFree(item->data);
            SoftBusFree(item);
            g_tcpSrvDataList->cnt--;
            break;
        }
    }
    pthread_mutex_unlock(&g_tcpSrvDataList->lock);
}

static int32_t PackBytes(int32_t channelId, const uint8_t *data, TdcPacketHead *packetHead, uint8_t *buffer,
    uint32_t bufLen)
{
#define AUTH_CONN_SERVER_SIDE 0x01
    ConnectOption option = {0};
    option.type = CONNECT_TCP;
    SessionConn *conn = SoftBusCalloc(sizeof(SessionConn));
    if (conn == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "malloc conn fail");
        return SOFTBUS_ERR;
    }

    if (GetSessionConnById(channelId, conn) == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Get SessionConn fail");
        SoftBusFree(conn);
        return SOFTBUS_ERR;
    }
    if (strcpy_s(option.info.ipOption.ip, IP_LEN, conn->appInfo.peerData.ip) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "strcpy_s peer ip err.");
        SoftBusFree(conn);
        return SOFTBUS_ERR;
    }
    option.info.ipOption.port = conn->appInfo.peerData.port;
    SoftBusFree(conn);
    AuthSideFlag side;
    uint32_t len = packetHead->dataLen - SESSION_KEY_INDEX_SIZE - OVERHEAD_LEN;
    OutBuf outbuf = {0};
    outbuf.buf = buffer + DC_MSG_PACKET_HEAD_SIZE;
    outbuf.bufLen = packetHead->dataLen;

    int32_t ret = AuthEncrypt(&option, &side, (uint8_t*)data, len, &outbuf);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "AuthDecrypt err.");
        return SOFTBUS_ERR;
    }
    if (packetHead->flags == FLAG_REQUEST && side == SERVER_SIDE_FLAG) {
        packetHead->seq = packetHead->seq | AUTH_CONN_SERVER_SIDE;
    }
    if (memcpy_s(buffer, bufLen, packetHead, sizeof(TdcPacketHead)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy packetHead error.");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "side=%d, flag=%d, seq=%llu",
        side, packetHead->flags, packetHead->seq);
    return SOFTBUS_OK;
}

int32_t TransTdcPostBytes(int32_t channelId, TdcPacketHead *packetHead, const char *data)
{
    if (data == NULL || packetHead == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid para.");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t bufferLen = packetHead->dataLen + DC_MSG_PACKET_HEAD_SIZE;
    if (bufferLen <= OVERHEAD_LEN + MESSAGE_INDEX_SIZE + DC_MSG_PACKET_HEAD_SIZE) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid bufferLen.");
        return SOFTBUS_INVALID_PARAM;
    }
    char *buffer = (char *)SoftBusMalloc(bufferLen);
    if (buffer == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "buffer malloc error.");
        return SOFTBUS_MALLOC_ERR;
    }
    if (PackBytes(channelId, (uint8_t*)data, packetHead, (uint8_t*)buffer, bufferLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Pack Bytes error.");
        SoftBusFree(buffer);
        return SOFTBUS_ENCRYPT_ERR;
    }
    SessionConn *conn = SoftBusCalloc(sizeof(SessionConn));
    if (conn == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "malloc conn fail");
        return SOFTBUS_ERR;
    }

    if (GetSessionConnById(channelId, conn) == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Get SessionConn fail");
        SoftBusFree(conn);
        return SOFTBUS_ERR;
    }
    int fd = conn->appInfo.fd;
    SoftBusFree(conn);
    if (SendTcpData(fd, buffer, bufferLen, 0) != (int)bufferLen) {
        SoftBusFree(buffer);
        return SOFTBUS_ERR;
    }
    SoftBusFree(buffer);
    return SOFTBUS_OK;
}

static int32_t DecryptMessage(int32_t channelId, const char *in, uint32_t inLen, char *out, uint32_t *outLen)
{
    SessionConn conn;
    if (GetSessionConnById(channelId, &conn) == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "channelId[%d] is not exist.", channelId);
        return SOFTBUS_ERR;
    }

    ConnectOption option = {0};
    option.type = CONNECT_TCP;
    if (strcpy_s(option.info.ipOption.ip, sizeof(option.info.ipOption.ip), conn.appInfo.peerData.ip) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "strcpy_s peer ip err.");
        return SOFTBUS_ERR;
    }
    option.info.ipOption.port = conn.appInfo.peerData.port;

    AuthSideFlag side = CLIENT_SIDE_FLAG;
    OutBuf outbuf = {0};
    outbuf.bufLen = inLen - SESSION_KEY_INDEX_SIZE - OVERHEAD_LEN + 1;
    outbuf.buf = (uint8_t *)out;
    int32_t ret = AuthDecrypt(&option, side, (uint8_t *)in, inLen, &outbuf);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "AuthDecrypt err.");
        return SOFTBUS_ERR;
    }
    *outLen = outbuf.outLen;
    return ret;
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
    int32_t errCode)
{
    TdcPacketHead packetHead = {
        .magicNumber = MAGIC_NUMBER,
        .module = MODULE_SESSION,
        .seq = seq,
        .flags = FLAG_REPLY,
        .dataLen = 0,
    };

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

    packetHead.dataLen = strlen(reply) + OVERHEAD_LEN + MESSAGE_INDEX_SIZE;
    int32_t ret = TransTdcPostBytes(channelId, &packetHead, reply);
    cJSON_free(reply);
    return ret;
}

static int32_t OpenDataBusRequest(int32_t channelId, uint64_t seq, const cJSON *request)
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

    if (SetAppInfoById(channelId, &conn->appInfo) != SOFTBUS_OK) {
        SoftBusFree(conn);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "set app info by id failed.");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OpenDataBusRequest: mySessionName=%s, peerSessionName=%s",
        conn->appInfo.myData.sessionName, conn->appInfo.peerData.sessionName);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OpenDataBusRequest: myPid=%d, peerPid=%d",
        conn->appInfo.myData.pid, conn->appInfo.peerData.pid);

    int32_t ret = NotifyChannelOpened(channelId);
    if (OpenDataBusRequestReply(&conn->appInfo, channelId, seq, ret) != SOFTBUS_OK) {
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

static int32_t ProcessMessage(int32_t channelId, uint32_t flags, uint64_t seq, const cJSON *packet)
{
    if (flags & FLAG_REPLY) {
        return OpenDataBusReply(channelId, seq, packet);
    }
    return OpenDataBusRequest(channelId, seq, packet);
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

static int GetPktHeadInfoByDatabuf(const ServerDataBuf *node, uint32_t *inLen, uint64_t *seq, uint32_t *flags)
{
    if (node == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "node is null.");
        return SOFTBUS_ERR;
    }

    TdcPacketHead *pktHead = (TdcPacketHead *)(node->data);
    if (pktHead->module != MODULE_SESSION) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv process recv data: illegal package head module.");
        return SOFTBUS_ERR;
    }
    *inLen = pktHead->dataLen;
    *seq = pktHead->seq;
    *flags = pktHead->flags;
    return SOFTBUS_OK;
}

static int32_t ProcessReceivedData(int32_t channelId)
{
    uint32_t inLen, flags, outLen;
    uint64_t seq;

    pthread_mutex_lock(&g_tcpSrvDataList->lock);
    ServerDataBuf *node = TransSrvGetDataBufNodeById(channelId);
    if (GetPktHeadInfoByDatabuf(node, &inLen, &seq, &flags) != SOFTBUS_OK) {
        pthread_mutex_unlock(&g_tcpSrvDataList->lock);
        return SOFTBUS_ERR;
    }

    char *in = node->data + sizeof(TdcPacketHead);
    char *out = (char *)SoftBusCalloc(inLen - SESSION_KEY_INDEX_SIZE - OVERHEAD_LEN + 1);
    if (out == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv process recv data: malloc fail.");
        pthread_mutex_unlock(&g_tcpSrvDataList->lock);
        return SOFTBUS_MALLOC_ERR;
    }

    if (DecryptMessage(channelId, in, inLen, out, &outLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv process recv data: decrypt message err.");
        SoftBusFree(out);
        pthread_mutex_unlock(&g_tcpSrvDataList->lock);
        return SOFTBUS_ERR;
    }
    char *end = node->data + sizeof(TdcPacketHead) + inLen;
    if (memmove_s(node->data, node->size, end, node->w - end) != EOK) {
        SoftBusFree(out);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memmove fail.");
        pthread_mutex_unlock(&g_tcpSrvDataList->lock);
        return SOFTBUS_MEM_ERR;
    }
    node->w = node->w - sizeof(TdcPacketHead) - inLen;
    pthread_mutex_unlock(&g_tcpSrvDataList->lock);
    out[outLen] = 0;
    cJSON *packet = cJSON_Parse(out);
    if (packet == NULL) {
        SoftBusFree(out);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv process recv data: json parse failed.");
        return SOFTBUS_ERR;
    }
    int32_t ret = ProcessMessage(channelId, flags, seq, packet);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv process message fail.[%d]", ret);
    }
    SoftBusFree(out);
    cJSON_Delete(packet);
    return ret;
}

static int32_t TransTdcSrvProcData(int32_t channelId)
{
    pthread_mutex_lock(&g_tcpSrvDataList->lock);
    ServerDataBuf *node = TransSrvGetDataBufNodeById(channelId);
    if (node == NULL) {
        pthread_mutex_unlock(&g_tcpSrvDataList->lock);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv can not get buf node.");
        return SOFTBUS_ERR;
    }

    uint32_t bufLen = node->w - node->data;
    if (bufLen < DC_MSG_PACKET_HEAD_SIZE) {
        pthread_mutex_unlock(&g_tcpSrvDataList->lock);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "srv head not enough, recv next time.");
        return SOFTBUS_DATA_NOT_ENOUGH;
    }

    TdcPacketHead *pktHead = (TdcPacketHead *)(node->data);
    if (pktHead->magicNumber != MAGIC_NUMBER) {
        pthread_mutex_unlock(&g_tcpSrvDataList->lock);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv recv invalid packet head");
        return SOFTBUS_ERR;
    }

    uint32_t dataLen = pktHead->dataLen;
    if (dataLen > node->size - DC_MSG_PACKET_HEAD_SIZE) {
        pthread_mutex_unlock(&g_tcpSrvDataList->lock);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv out of recv buf size[%d]", dataLen);
        return SOFTBUS_ERR;
    }

    if (bufLen < dataLen + DC_MSG_PACKET_HEAD_SIZE) {
        pthread_mutex_unlock(&g_tcpSrvDataList->lock);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "srv data not enough, recv next time.[%d][%d][%d]",
            bufLen, dataLen, DC_MSG_PACKET_HEAD_SIZE);
        return SOFTBUS_DATA_NOT_ENOUGH;
    }
    pthread_mutex_unlock(&g_tcpSrvDataList->lock);
    return ProcessReceivedData(channelId);
}

int32_t TransTdcSrvRecvData(int32_t channelId)
{
    pthread_mutex_lock(&g_tcpSrvDataList->lock);
    ServerDataBuf *node = TransSrvGetDataBufNodeById(channelId);
    if (node == NULL) {
        pthread_mutex_unlock(&g_tcpSrvDataList->lock);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv can not find data buf node.");
        return SOFTBUS_ERR;
    }
    int32_t ret = RecvTcpData(node->fd, node->w, node->size - (node->w - node->data), 0);
    if (ret <= 0) {
        pthread_mutex_unlock(&g_tcpSrvDataList->lock);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "recv tcp data fail.");
        return SOFTBUS_ERR;
    }
    node->w += ret;
    pthread_mutex_unlock(&g_tcpSrvDataList->lock);

    return TransTdcSrvProcData(channelId);
}
