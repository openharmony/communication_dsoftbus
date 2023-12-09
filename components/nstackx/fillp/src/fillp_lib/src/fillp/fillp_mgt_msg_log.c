/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "fillp_mgt_msg_log.h"
#include "net.h"
#include "nstackx_util.h"

#ifdef FILLP_MGT_MSG_LOG

#define FILLP_EXT_PARA_FORMAT_BUF_LEN 512
#define FILLP_IP_ADDR_FORMAT_BUF_LEN 64

#define FILLP_COOKIE_TAG_AND_LEN_SIZE (sizeof(FILLP_UINT16) + sizeof(FILLP_UINT16))

#define FILLP_DIRECTION_STR(_d) (((_d) == FILLP_DIRECTION_RX) ? "recv" : "send")

#define FILLP_MGT_MSG_PRINT(_sockIndex, _hdr, _direction, fmt, ...) do { \
        FILLP_LOGMGTMSG("sock %d %s management message, version: %u, msg type: %s(0x%X)," \
            " msg flag: reserved(0x%02X), msg length: %u, seq num: %u, pkt seq: %u. " fmt, \
            _sockIndex, FILLP_DIRECTION_STR(_direction), FILLP_PKT_GET_PROTCOL_VERSION((_hdr)->flag), \
            g_fillpTypeStr[FILLP_PKT_GET_TYPE((_hdr)->flag)], FILLP_PKT_GET_TYPE((_hdr)->flag), \
            FILLP_PKT_GET_FLAG((_hdr)->flag), (_hdr)->dataLen, (_hdr)->seqNum, (_hdr)->pktNum, ##__VA_ARGS__); \
    } while (0)

static FILLP_CONST FILLP_CHAR *g_fillpTypeStr[] = {
    "RESERVED",
    "DATA",
    "CONN_REQ",
    "NACK",
    "RESERVED",
    "PACK",
    "FIN",
    "RESERVED",
    "RESERVED",
    "RESERVED",
    "CONN_REQ_ACK",
    "CONN_CONFIRM",
    "CONN_CONFIRM_ACK",
    "HISTORY_ACK",
    "CTRL_MSG",
};

static void FillpHeaderNtoH(struct FillpPktHead *out, FILLP_CONST struct FillpPktHead *in, FILLP_INT direction)
{
    if (direction == FILLP_DIRECTION_RX) { /* already convert to host byte order in FillpDoInput */
        (void)memcpy_s(out, sizeof(struct FillpPktHead), in, sizeof(struct FillpPktHead));
    } else {
        out->flag = FILLP_NTOHS(in->flag);
        out->dataLen = FILLP_NTOHS(in->dataLen);
        out->pktNum = FILLP_NTOHL(in->pktNum);
        out->seqNum = FILLP_NTOHL(in->seqNum);
    }
}

void FillpPktSimpleLog(FILLP_INT sockIndex, FILLP_CONST struct FillpPktHead *hdrInput, FILLP_INT direction)
{
    struct FillpPktHead hdr = {0};
    FillpHeaderNtoH(&hdr, hdrInput, direction);
    FILLP_UINT16 type = FILLP_PKT_GET_TYPE(hdr.flag);
    if (type == FILLP_PKT_TYPE_CONN_REQ || type == FILLP_PKT_TYPE_CONN_REQ_ACK ||
        type == FILLP_PKT_TYPE_CONN_CONFIRM || type == FILLP_PKT_TYPE_CONN_CONFIRM_ACK ||
        type == FILLP_PKT_TYPE_FIN) {
        FILLP_MGT_MSG_PRINT(sockIndex, &hdr, direction, "");
    }
}

void FillpConnReqLog(FILLP_INT sockIndex, FILLP_CONST struct FillpPktConnReq *req, FILLP_INT direction)
{
    struct FillpPktHead hdr = {0};
    FillpHeaderNtoH(&hdr, (FILLP_CONST struct FillpPktHead *)req->head, direction);
    FILLP_MGT_MSG_PRINT(sockIndex, &hdr, direction,
        "cookie preserve time: %u, send cache: %u, recv cache: %u, timestamp: %llu",
        FILLP_NTOHL(req->cookiePreserveTime), FILLP_NTOHL(req->sendCache), FILLP_NTOHL(req->recvCache),
        FILLP_NTOHLL(req->timestamp));
}

static FILLP_INT FillpExtParaRttFormat(FILLP_CONST struct FtNetconn *conn, FILLP_CHAR *buf, size_t len)
{
    return snprintf_s(buf, len, len - 1, "    init rtt: %llu", conn->calcRttDuringConnect);
}

static FILLP_INT FillpExtParaPktSizeFormat(FILLP_CONST struct FtNetconn *conn, FILLP_CHAR *buf, size_t len)
{
    return snprintf_s(buf, len, len - 1, "    peer pkt size: %u", conn->peerPktSize);
}

static FILLP_INT FillpBitmapFormat(FILLP_CHAR *buf, size_t len, FILLP_UINT32 bitmap,
    FILLP_CONST FILLP_CHAR *bitmapStr[], size_t bitmapStrSize)
{
    size_t formatLen = 0;
    size_t i;
    for (i = 0; i < bitmapStrSize; i++) {
        if (!UTILS_FLAGS_CHECK(bitmap, 1u << i)) {
            continue;
        }

        FILLP_INT ret = snprintf_s(buf + formatLen, len - formatLen, (len - formatLen) - 1, " %s", bitmapStr[i]);
        if (ret < 0) {
            FILLP_LOGERR("snprintf_s failed");
            return ret;
        }
        formatLen += (FILLP_UINT32)ret;
    }

    return (FILLP_INT)formatLen;
}

static FILLP_INT FillpExtParaCharacterFormat(FILLP_CONST struct FtNetconn *conn, FILLP_CHAR *buf, size_t len)
{
    FILLP_INT ret = snprintf_s(buf, len, len - 1, "    characters: 0x%08X", conn->peerCharacters);
    if (ret < 0) {
        FILLP_LOGERR("snprintf_s failed");
        return ret;
    }
    size_t formatLen = (FILLP_UINT32)ret;

    FILLP_CONST FILLP_CHAR *characterStr[] = { "HRBB", "PKT_IVAR" };
    ret = FillpBitmapFormat(buf + formatLen, len - formatLen, conn->peerCharacters,
        characterStr, UTILS_ARRAY_LEN(characterStr));
    if (ret < 0) {
        FILLP_LOGERR("FillpBitmapFormat failed");
        return ret;
    }
    formatLen += (FILLP_UINT32)ret;

    return (FILLP_INT)formatLen;
}

static FILLP_INT FillpExtParaFcAlgFormat(FILLP_CONST struct FtNetconn *conn, FILLP_CHAR *buf, size_t len)
{
    FILLP_INT ret = snprintf_s(buf, len, len - 1, "    FC ALG: 0x%02X", conn->peerFcAlgs);
    if (ret < 0) {
        FILLP_LOGERR("snprintf_s failed");
        return ret;
    }
    size_t formatLen = (FILLP_UINT32)ret;

    FILLP_CONST FILLP_CHAR *fcAlgStr[] = { "ALG_1", "ALG_2", "ALG_3", "ALG_MSG" };
    ret = FillpBitmapFormat(buf + formatLen, len - formatLen, conn->peerFcAlgs,
        fcAlgStr, UTILS_ARRAY_LEN(fcAlgStr));
    if (ret < 0) {
        FILLP_LOGERR("FillpBitmapFormat failed");
        return ret;
    }
    formatLen += (FILLP_UINT32)ret;

    return (FILLP_INT)formatLen;
}

static FILLP_INT (*g_extParaFormatter[FILLP_PKT_EXT_BUTT])(
    FILLP_CONST struct FtNetconn *conn, FILLP_CHAR *buf, size_t len) = {
    FILLP_NULL_PTR,
    FillpExtParaRttFormat,
    FillpExtParaPktSizeFormat,
    FillpExtParaCharacterFormat,
    FillpExtParaFcAlgFormat,
};

static FILLP_INT FillpExtParaFormat(FILLP_CONST FILLP_UCHAR *extPara, FILLP_INT extParaLen, FILLP_CHAR *buf, size_t len)
{
    struct FtNetconn conn;
    (void)memset_s(&conn, sizeof(struct FtNetconn), 0, sizeof(struct FtNetconn));
    if (FillpDecodeExtPara(extPara, extParaLen, &conn) != ERR_OK) {
        FILLP_LOGERR("FillpDecodeExtPara failed");
        return -1;
    }

    size_t formatLen = 0;
    FILLP_INT i;
    for (i = 0; i < FILLP_PKT_EXT_BUTT; i++) {
        if (!conn.extParameterExisted[i] || g_extParaFormatter[i] == FILLP_NULL_PTR) {
            continue;
        }

        FILLP_INT ret = g_extParaFormatter[i](&conn, buf + formatLen, len - formatLen);
        if (ret < 0 || (FILLP_UINT32)ret > len - formatLen) {
            FILLP_LOGERR("g_extParaFormatter failed");
            return -1;
        }

        formatLen += ret;
    }

    return (FILLP_INT)formatLen;
}

void FillpConnReqAckRxLog(FILLP_INT sockIndex, FILLP_CONST struct FillpPktHead *hdr,
    FILLP_CONST struct FillpConnReqAckClient *ack, FILLP_CONST FILLP_UCHAR *extPara, FILLP_INT extParaLen)
{
    FILLP_CHAR tmpBuf[FILLP_EXT_PARA_FORMAT_BUF_LEN] = {0};
    if (FillpExtParaFormat(extPara, extParaLen, tmpBuf, sizeof(tmpBuf)) < 0) {
        return;
    }

    FILLP_MGT_MSG_PRINT(sockIndex, hdr, FILLP_DIRECTION_RX,
        "tag cookie: %hu, cookie len: %hu, cookie content: ****, timestamp: %llu, external parameter: %s",
        ack->tagCookie, ack->cookieLength, ack->timestamp, tmpBuf);
}

void FillpConnReqAckTxLog(FILLP_INT sockIndex, FILLP_CONST struct FillpPktConnReqAck *ack,
    FILLP_CONST FILLP_UCHAR *extPara, FILLP_INT extParaLen)
{
    FILLP_CHAR tmpBuf[FILLP_EXT_PARA_FORMAT_BUF_LEN] = {0};
    if (FillpExtParaFormat(extPara, extParaLen, tmpBuf, sizeof(tmpBuf)) < 0) {
        return;
    }

    struct FillpPktHead hdr = {0};
    FillpHeaderNtoH(&hdr, (FILLP_CONST struct FillpPktHead *)ack, FILLP_DIRECTION_TX);
    FILLP_MGT_MSG_PRINT(sockIndex, &hdr, FILLP_DIRECTION_TX,
        "tag cookie: %hu, cookie len: %hu, cookie content: ****, timestamp: %llu, external parameter: %s",
        FILLP_NTOHS(ack->tagCookie), FILLP_NTOHS(ack->cookieLength), FILLP_NTOHLL(ack->timestamp), tmpBuf);
}

void FillpConnConfirmRxLog(FILLP_INT sockIndex, FILLP_CONST struct FillpPktConnConfirm *confirm,
    FILLP_CONST FILLP_UCHAR *extPara, FILLP_INT extParaLen)
{
    FILLP_CHAR tmpBuf[FILLP_EXT_PARA_FORMAT_BUF_LEN] = {0};
    if (FillpExtParaFormat(extPara, extParaLen, tmpBuf, sizeof(tmpBuf)) < 0) {
        return;
    }

    FILLP_CHAR ipStr[FILLP_IP_ADDR_FORMAT_BUF_LEN] = {0};
    FILLP_INT ret = IpAddrAnonymousFormat(ipStr, sizeof(ipStr),
        (struct sockaddr *)&confirm->remoteAddr, sizeof(confirm->remoteAddr));
    if (ret < 0) {
        FILLP_LOGERR("ip addr format failed");
        return;
    }

    FILLP_MGT_MSG_PRINT(sockIndex, (FILLP_CONST struct FillpPktHead *)confirm->head, FILLP_DIRECTION_RX,
        "tag cookie: %hu, cookie len: %hu, cookie content: ****, "
        "remote address: [family: %s, port: %hu, IP: %s], external parameter: %s",
        FILLP_NTOHS(confirm->tagCookie), FILLP_NTOHS(confirm->cookieLength),
        (confirm->remoteAddr.sin6_family == AF_INET) ? "ipv4" : "ipv6",
        FILLP_NTOHS(confirm->remoteAddr.sin6_port), ipStr, tmpBuf);
}

void FillpConnConfirmTxLog(FILLP_INT sockIndex, FILLP_CONST FILLP_UCHAR *data, FILLP_INT dataLen,
    FILLP_INT extParaOffset)
{
    if (dataLen < extParaOffset || dataLen < (FILLP_INT)(FILLP_HLEN + FILLP_COOKIE_TAG_AND_LEN_SIZE)) {
        return;
    }

    FILLP_UINT16 tagCookie = *(FILLP_UINT16 *)(data + FILLP_HLEN);
    tagCookie = FILLP_NTOHS(tagCookie);
    FILLP_UINT16 cookieLen = *(FILLP_UINT16 *)(data + FILLP_HLEN + sizeof(FILLP_UINT16));
    cookieLen = FILLP_NTOHS(cookieLen);
    if (dataLen < (FILLP_INT)(FILLP_HLEN + FILLP_COOKIE_TAG_AND_LEN_SIZE + cookieLen + sizeof(struct sockaddr_in6))) {
        return;
    }

    struct sockaddr_in6 remoteAddr;
    (void)memcpy_s(&remoteAddr, sizeof(struct sockaddr_in6),
        data + FILLP_HLEN + FILLP_COOKIE_TAG_AND_LEN_SIZE + cookieLen, sizeof(struct sockaddr_in6));
    FILLP_CHAR ipStr[FILLP_IP_ADDR_FORMAT_BUF_LEN] = {0};
    FILLP_INT ret = IpAddrAnonymousFormat(ipStr, sizeof(ipStr), (struct sockaddr *)&remoteAddr, sizeof(remoteAddr));
    if (ret < 0) {
        FILLP_LOGERR("ip addr format failed");
        return;
    }

    FILLP_CHAR tmpBuf[FILLP_EXT_PARA_FORMAT_BUF_LEN] = {0};
    if (FillpExtParaFormat(data + extParaOffset, dataLen - extParaOffset, tmpBuf, sizeof(tmpBuf)) < 0) {
        return;
    }

    struct FillpPktHead hdr = {0};
    FillpHeaderNtoH(&hdr, (FILLP_CONST struct FillpPktHead *)data, FILLP_DIRECTION_TX);

    FILLP_MGT_MSG_PRINT(sockIndex, &hdr, FILLP_DIRECTION_TX,
        "tag cookie: %hu, cookie len: %hu, cookie content: ****, "
        "remote address: [family: %s, port: %hu, IP: %s], external parameter: %s",
        tagCookie, cookieLen,
        (remoteAddr.sin6_family == AF_INET) ? "ipv4" : "ipv6",
        FILLP_NTOHS(remoteAddr.sin6_port), ipStr, tmpBuf);
}

void FillpConnConfirmAckLog(FILLP_INT sockIndex,
    FILLP_CONST struct FillpPktConnConfirmAck *confirmAck, FILLP_INT direction)
{
    struct FillpPktHead hdr = {0};
    FillpHeaderNtoH(&hdr, (FILLP_CONST struct FillpPktHead *)confirmAck->head, direction);

    FILLP_CHAR ipStr[FILLP_IP_ADDR_FORMAT_BUF_LEN] = {0};
    FILLP_INT ret = IpAddrAnonymousFormat(ipStr, sizeof(ipStr),
        (struct sockaddr *)&confirmAck->remoteAddr, sizeof(confirmAck->remoteAddr));
    if (ret < 0) {
        FILLP_LOGERR("ip addr format failed");
        return;
    }

    FILLP_MGT_MSG_PRINT(sockIndex, &hdr, direction,
        "send cache: %u, recv cache: %u, packet size: %u, remote address: [family: %s, port: %hu, IP: %s]",
        FILLP_NTOHL(confirmAck->sendCache), FILLP_NTOHL(confirmAck->recvCache), FILLP_NTOHL(confirmAck->pktSize),
        (confirmAck->remoteAddr.sin6_family == AF_INET) ? "ipv4" : "ipv6",
        FILLP_NTOHS(confirmAck->remoteAddr.sin6_port), ipStr);
}

void FillpConnFinLog(FILLP_INT sockIndex, FILLP_CONST struct FillpPktFin *fin, FILLP_INT direction)
{
    FILLP_CHAR tmpBuf[FILLP_EXT_PARA_FORMAT_BUF_LEN] = {0};
    FILLP_CONST FILLP_CHAR *flagStr[] = { "WR", "RD", "ACK", "VERSION_MISMATCH" };
    FILLP_UINT32 flags = FILLP_NTOHS(fin->flag);
    if (FillpBitmapFormat(tmpBuf, sizeof(tmpBuf), flags, flagStr, UTILS_ARRAY_LEN(flagStr)) < 0) {
        FILLP_LOGERR("FillpBitmapFormat failed");
        return;
    }

    struct FillpPktHead hdr = {0};
    FillpHeaderNtoH(&hdr, (FILLP_CONST struct FillpPktHead *)fin->head, direction);

    FILLP_MGT_MSG_PRINT(sockIndex, &hdr, direction, "flags: %s", tmpBuf);
}
#endif
