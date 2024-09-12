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

#ifndef FILLP_H
#define FILLP_H

#include "fillpinc.h"
#include "fillp_os.h"
#include "hlist.h"
#include "lf_ring.h"
#include "queue.h"
#include "log.h"
#include "opt.h"
#include "skiplist.h"
#include "fillp_pcb.h"
#include "fillp_cookie.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FILLP_PROTOCOL_VERSION_NUMBER 0
#define FILLP_INITIAL_COOKIE_LIFETIME (10 * 1000 * 1000)
#define NACK_HISTORY_BY_TIME_INDEX 0

#define FILLP_LM_TRACE_SEND_MSG(traceFlag, traceObjType, traceHandle, len, sock, traceDesc, traceMsg) do { \
    if ((g_traceInfo.fillpTraceSend != FILLP_NULL_PTR) \
        && ((traceFlag) >= (traceObjType))) { \
        (traceDesc).traceDirection = FILLP_TRACE_DIRECT_SEND; \
        (*g_traceInfo.fillpTraceSend) (traceObjType, traceHandle, len, (FILLP_UINT32)(sock), \
            (FILLP_UINT8 *)(void *)&(traceDesc), traceMsg); \
    } \
} while (0)

/* Message indication */
#define FILLP_LM_FILLPMSGTRACE_OUTPUT(traceFlag, traceObjType, traceHandle, len, sock, pTracedesc, traceMsg) do { \
    if ((g_traceInfo.fillpTraceSend != FILLP_NULL_PTR) \
        && ((traceFlag) >= (traceObjType))) { \
        (*g_traceInfo.fillpTraceSend) (traceObjType, traceHandle, len, (FILLP_UINT32)(sock), \
            pTracedesc, traceMsg); \
    } \
} while (0)

#define FILLP_LM_FILLPMSGTRACE_OUTPUT_WITHOUT_FT_TRACE_ENABLE_FLAG(traceObjType, traceHandle, len, sock, \
    traceDesc, traceMsg) do { \
    if (g_traceInfo.fillpTraceSend != FILLP_NULL_PTR) { \
        (traceDesc).traceDirection = FILLP_TRACE_DIRECT_RECV; \
        (*g_traceInfo.fillpTraceSend) (traceObjType, traceHandle, len, (FILLP_UINT32)(sock), \
            (FILLP_UINT8 *)(void *)&(traceDesc), traceMsg); \
    } \
} while (0)

#define FILLP_ITEM_RESEND_TRIGGER_NACK 0X01 /* item resend triggered by nack */
#define FILLP_ITEM_RESEND_TRIGGER_PACK 0X02 /* item resend triggered by pack */
#define FILLP_ITEM_RESEND_TRIGGER_TP 0X03 /* item resend triggered by tail protect */
#define FILLP_ITEM_RESEND_TRIGGER_HNACK 0X04 /* item resend triggered by history nack */

/* these flags is also used in the bitMap of the data option */
#define FILLP_ITEM_FLAGS_FRAME_OPT_BITMAP_MASK 0xFFu
#define FILLP_ITEM_FLAGS_FRAME_FIRST_FRAG_START 0x00000001u /* mark the item is the 1st pkt
                                                               of the 1st fragment of the frame */
#define FILLP_ITEM_FLAGS_FRAME_LAST_FRAG_START 0x00000002u /* mark the item is the 1st pkt
                                                              of the last fragment of the frame */

#define FILLP_ITEM_FLAGS_APP_LIMITED 0x00000100
#define FILLP_ITEM_FLAGS_FIRST_PKT 0x00000200
#define FILLP_ITEM_FLAGS_LAST_PKT 0x00000400
#define FILLP_ITEM_FLAGS_APP_LARGE_DATA 0x00000800
#define FILLP_ITEM_FLAGS_REDUNDANT 0x00001000

#define FILLP_ITEM_FLAGS_FIRST_PKT_FOR_CAL_COST (FILLP_ITEM_FLAGS_APP_LARGE_DATA | FILLP_ITEM_FLAGS_FIRST_PKT)
#define FILLP_ITEM_FLAGS_LAST_PKT_FOR_CAL_COST (FILLP_ITEM_FLAGS_APP_LARGE_DATA | FILLP_ITEM_FLAGS_LAST_PKT)

struct FillpPcbItem {
    struct NetBuf buf; /* Data -- This has to be the first node in the structure. */
    struct HlistNode node;
    struct HlistNode unsendNode;
    struct HlistNode pktSeqMapNode;
    struct SkipListNode skipListNode;
    void *netconn;
    void *fpcb;
    FILLP_UINT32 seqNum;
    FILLP_UINT32 pktNum;
    FILLP_UINT16 dataLen;    /* Data Len */
    FILLP_UINT16 dataOptLen; /* Data option Len */
    FILLP_UINT32 dataOptFlag;
    FILLP_UINT8 sendCount;
    FILLP_UINT8 resendTrigger;
    FILLP_UINT32 flags;
    FILLP_UINT32 infCount; /* send success and flight in cap count */
    FILLP_LLONG firstSendTimestamp;
    FILLP_LLONG lastSendTimestamp;
    FILLP_LLONG appSendTimestamp;
    FILLP_UINT32 appSendSize;

    FILLP_LLONG rxTimeStamp;
    struct FillpFrameItem *frame;
};

static __inline struct FillpPcbItem *FillpPcbEntry(struct HlistNode *node)
{
    return (struct FillpPcbItem *)((char *)(node) - (uintptr_t)(&(((struct FillpPcbItem *)0)->node)));
}

static __inline struct FillpPcbItem *FillpPcbPktSeqMapNodeEntry(struct HlistNode *node)
{
    return (struct FillpPcbItem *)((char *)(node) - (uintptr_t)(&(((struct FillpPcbItem *)0)->pktSeqMapNode)));
}

static __inline struct FillpPcbItem *FillpPcbUnsendNodeEntry(struct HlistNode *node)
{
    return (struct FillpPcbItem *)((char *)(node) - (uintptr_t)(&(((struct FillpPcbItem *)0)->unsendNode)));
}

static __inline struct NetBuf *FillpPcbNetbufNodeEntry(char *p)
{
    return (struct NetBuf *)((char *)(p) - (uintptr_t)(&(((struct NetBuf *)0)->p)));
}

/* Below structures are exchanged over network, so there should be no padding, so use pack 1 */
#pragma pack(1)

/* To support extension of header is future.
    1. Each message has parameter optLen which indicates if opt parameter present or not.
    2. Whenever extension are added then special care need to be taken care such that total packet
       doesn't spilt in 2 MSS. Current design do not support.
    3. Data pkt type can't carry any new extension, should use existing MSG or define new MSG type.
    4. All existing message can be extended at end not in between of current header values.
    5. some capabilities which both node to agree up on, should use CONN_REQ, CONN_REQ_ACK and CONN_CONFIRM
       message to exchange.
    6. extension header should be of format: tag, length, value.  Size of extension can be found in first byte
       after each message type.
*/
struct FillpPktHead {
    FILLP_UINT16 flag; /* from MSB [0-3]Version [4-7] Pkt type [8]Ext Flag [9-15] Not used */
    FILLP_UINT16 dataLen;
    FILLP_UINT32 pktNum;
    FILLP_UINT32 seqNum;
};

/*
 * define fillp pack options
 */
#define FILLP_PACK_OPT_HLEN 3
#define FILLP_PACK_OPT_HRBB 0x01

typedef struct InnerfillpPackOption {
    FILLP_UINT8 type;
    FILLP_UINT16 len;
    FILLP_UINT8 value[1];
} FillpPackOption;

typedef struct {
    FILLP_UINT16 seq;
    FILLP_UINT16 totalMean;
    FILLP_UINT32 jitter;
    FILLP_UINT16 rsv;
    FILLP_UINT16 windowMean;
    FILLP_UINT32 windowVar;
} FillpPackOptionPktIvarData;

#define FILLP_PACK_FLAG_WITH_RTT 0x0001
#define FILLP_PACK_FLAG_REQURE_RTT 0x0002
#define FILLP_PACK_FLAG_WITH_RATE_LIMIT 0x0004
#define FILLP_PACK_FLAG_NO_DATA_SEND 0x0008
#define FILLP_PACK_FLAG_ADHOC 0x0010
#define FILLP_PACK_FLAG_PKT_NUM_SEG 0x0020
#define FILLP_PACK_FLAG_OPTS 0x0040
#define FILLP_PACK_FLAG_RCV_LIST_BYTES 0x0080
#define FILLP_PACK_FLAG_OWD 0x0100
#define FILLP_PACK_FLAG_CAL_COST 0x0200U
#define FILLP_PACK_FLAG_POWER_SAVE 0x0400

#define FILLP_PACK_MIN_LEN 32
#define FILLP_PACK_NUM_SEG_LEN 40
#define FILLP_PACK_OPTS_OFFSET_LEN 42
#define FILLP_PACK_RCV_LIST_BYTES_LEN 46
#define FILLP_PACK_OWD_LEN 58

struct FillpPktPack {
    char head[FILLP_HLEN];
    FILLP_UINT16 flag;
    FILLP_UINT16 pktLoss;
    FILLP_UINT32 rate;
    FILLP_UINT32 oppositeSetRate;
    /* recv 0~999,2000~2999, lost 1000~1999, fillp_dataHead->seqNum = 999, lostSeq = 1999.
       if no packet lost, lostSeq and seqNum will be same */
    FILLP_UINT32 lostSeq;
    union {
        FILLP_UINT32 rtt;
        FILLP_UINT32 timestamp;
    } reserved;
    FILLP_UINT32 bgnPktNum;     /* use in appLimited */
    FILLP_UINT32 endPktNum;     /* use in appLimited */
    FILLP_UINT16 optsOffset;    /* options start address relative to the first byte of pack packet */
    FILLP_UINT32 rcvListBytes;  /* data size in recvList */
    FILLP_UINT32 owdPktSendTs;  /* low 32bit send timestamp of the packet which has min owd, calculate minRtt */
    FILLP_UINT32 owdPackDelay;  /* the delta time between min owd packet received and next PACK send */
    FILLP_UINT32 queueingDelay; /* report current "queueing delay", queueingDelay: current_owd - minOwd */
};

struct FillpPktConnReq {
    char head[FILLP_HLEN];
    FILLP_UINT32 cookiePreserveTime; /* for align to 8 bytes */
    FILLP_UINT32 sendCache;          /* client send to server cache , same as server recv cache */
    FILLP_UINT32 recvCache;          /* client recv from server cache, same as server send cache */

    FILLP_ULLONG timestamp; /* Time stamp used for rtt Detective */
};

struct FillpPktFin {
    char head[FILLP_HLEN];
    FILLP_UINT16 flag;
};

struct FillpPktNack {
    char head[FILLP_HLEN];
    FILLP_UINT32 lastPktNum;
};


struct FillpPktNackWithRandnum {
    struct FillpPktNack nack;
    FILLP_ULLONG randomNum;
};

struct FillpSeqPktNum {
    FILLP_UINT32 beginPktNum;
    FILLP_UINT32 beginSeqNum;
    FILLP_UINT32 endPktNum;
};

/* define flow control algorithm */
#define FILLP_SUPPORT_ALG_BASE 0X00u
#define FILLP_SUPPORT_ALG_N(_n)   (0X01u << ((_n)-1))
#define FILLP_SUPPORT_ALG_1   0X01
#define FILLP_SUPPORT_ALG_2   0X02
#define FILLP_SUPPORT_ALG_3    0X04
#define FILLP_SUPPORT_ALG_MSG    0X08
#define FILLP_SUPPORT_ALG_HIGHEST_INDEX 3
#define FILLP_SUPPORT_ALG_HIGHEST FILLP_SUPPORT_ALG_N(FILLP_SUPPORT_ALG_HIGHEST_INDEX)
#define FILLP_SUPPORT_ALGS FILLP_SUPPORT_ALG_3

struct FillpPktConnReqAck {
    char head[FILLP_HLEN];
    FILLP_UINT16 tagCookie;     /* for align to 8 bytes */
    FILLP_UINT16 cookieLength;   /* client send to server cache , same as server recv cache */

    FillpCookieContent cookieContent;
    FILLP_ULLONG timestamp;    /* The same as conn_req->timestamp */
};

struct FillpConnReqAckClient {
    FILLP_CHAR *cookieContent;
    FILLP_ULLONG timestamp;    /* The same as conn_req->timestamp */
    FILLP_UINT16 tagCookie;    /* for align to 8 bytes */
    FILLP_UINT16 cookieLength; /* client send to server cache , same as server recv cache */
    FILLP_UINT16 fcAlgs;
    FILLP_UINT32 peerCharacters;
};

/* each ext para need value(1 bit) and length(1 bit), so totally need 2 bits */
#define FILLP_ONE_EXT_PARA_LENGTH 2

enum FillpPacketExt {
    FILLP_PKT_EXT_START,
    FILLP_PKT_EXT_CONNECT_CONFIRM_CARRY_RTT = 1,
    FILLP_PKT_EXT_CONNECT_CONFIRM_CARRY_PKT_SIZE,
    FILLP_PKT_EXT_CONNECT_CARRY_CHARACTER,
    FILLP_PKT_EXT_CONNECT_CARRY_FC_ALG,
    FILLP_PKT_EXT_BUTT = 0xff
};

struct FillpPktConnConfirm {
    char head[FILLP_HLEN];
    FILLP_UINT16 tagCookie;    /* for align to 8 bytes */
    FILLP_UINT16 cookieLength; /* client send to server cache , same as server recv cache */
    FillpCookieContent cookieContent;
    struct sockaddr_in6 remoteAddr; /* 28bytes */ /* Not used, kept because of backward compatibility */
};

struct FillpPktConnConfirmAck {
    char head[FILLP_HLEN];
    FILLP_UINT32 sendCache;
    FILLP_UINT32 recvCache;
    FILLP_UINT32 pktSize;           /* mtu , from server */
    struct sockaddr_in6 remoteAddr; /* 28bytes */
};

typedef struct InnerfillpDataOption {
    FILLP_UINT8 type;
    FILLP_UINT8 len;
    FILLP_UINT8 value[1];
} FillpDataOption;

#pragma pack()

#define FILLP_PKT_TYPE_DATA 0x1
#define FILLP_PKT_TYPE_NACK 0x3
#define FILLP_PKT_TYPE_PACK 0x5
#define FILLP_PKT_TYPE_CONN_REQ 0X2
#define FILLP_PKT_TYPE_FIN 0x6
#define FILLP_PKT_TYPE_CONN_REQ_ACK 0XA
#define FILLP_PKT_TYPE_CONN_CONFIRM 0XB
#define FILLP_PKT_TYPE_CONN_CONFIRM_ACK 0XC
#define FILLP_PKT_TYPE_HISTORY_NACK 0xD

/*
 * define fillp data option
 */
#define FILLP_DATA_OFFSET_LEN 2
#define FILLP_DATA_OPT_HLEN 2

/*
 * define fillp data options
 */
#define FILLP_OPT_TIMESTAMP 0x01
#define FILLP_OPT_FRAME_INFO 0x02

#define FILLP_OPT_FLAG_TIMESTAMP 0x0001
#define FILLP_OPT_FLAG_FRAME_INFO 0x0002

#define FILLP_OPT_TIMESTAMP_LEN 8
#define FILLP_OPT_FRAME_INFO_LEN sizeof(struct FillpFrameDataOption)

#define FILLP_COOKIE_TAG 0X1

typedef enum InnerfillpClientfourhandshakestateEnum {
    FILLP_CLIENT_FOUR_HANDSHAKE_STATE_INITIAL = 0,
    FILLP_CLIENT_FOUR_HANDSHAKE_STATE_REQSENT = 1,
    FILLP_CLIENT_FOUR_HANDSHAKE_STATE_REQACK_RCVED = 2,
    FILLP_CLIENT_FOUR_HANDSHAKE_STATE_CONFIRM_SENT = 3,
    FILLP_CLIENT_FOUR_HANDSHAKE_STATE_CONFIRMACK_RCVED = 4,
    FILLP_CLIENT_FOUR_HANDSHAKE_STATE_BUTT
} FillpClientfourhandshakestateEnum;

#define FILLP_HEADER_SET_PKT_TYPE(flag, type) ((flag) |= ((FILLP_UINT16)((type)&0x0f) << 8))
#define FILLP_PKT_GET_TYPE(flag) (((flag)&0x0f00) >> 8)
#define FILLP_PKT_GET_FLAG(flag) ((flag) & 0x00ff)

#define FILLP_HEADER_SET_PROTOCOL_VERSION(flag, ver) ((flag) |= ((FILLP_UINT16)((ver)&0x0f) << 12))
#define FILLP_PKT_GET_PROTCOL_VERSION(flag) (((flag)&0xf000) >> 12)

/*
 * PKT_DATA with option or not flag, 1 bit
 */
#define FILLP_HEADER_SET_DAT_WITH_OPTION(flag) ((flag) |= 0x80) // 0x80 -> 0000 0000 1000 0000
#define FILLP_PKT_GET_DAT_WITH_OPTION(flag) ((flag)&0x80)       // 0x80 -> 0000 0000 1000 0000

/*
 * PKT_DATA with flag indicating the last pkt, 1 bit
 */
#define FILLP_HEADER_SET_DAT_WITH_LAST_FLAG(flag) ((flag) |= 0x40) // 0x40 -> 0000 0000 0100 0000
#define FILLP_PKT_GET_DAT_WITH_LAST_FLAG(flag) ((flag)&0x40)

/*
* PKT_DATA with flag indicating the first pkt, 1 bit
*/
#define FILLP_HEADER_SET_DAT_WITH_FIRST_FLAG(flag) ((flag) |= 0x20) // 0x40 -> 0000 0000 0010 0000
#define FILLP_PKT_GET_DAT_WITH_FIRST_FLAG(flag) ((flag) & 0x20)

#define FILLP_PKT_DISCONN_MSG_FLAG_WR 0x0001  /* Not send anymore data */
#define FILLP_PKT_DISCONN_MSG_FLAG_RD 0x0002  /* Won't read anymore data */
#define FILLP_PKT_DISCONN_MSG_FLAG_ACK 0x0004 /* It is an ACK for disconnect message */
#define FILLP_PKT_DISCONN_MSG_FLAG_VER 0x0008 /* version imcompatible */

#define FILLP_PKT_DISCONN_MSG_FLAG_SET_WR(_flag) ((_flag) |= FILLP_PKT_DISCONN_MSG_FLAG_WR)
#define FILLP_PKT_DISCONN_MSG_FLAG_SET_RD(_flag) ((_flag) |= FILLP_PKT_DISCONN_MSG_FLAG_RD)
#define FILLP_PKT_DISCONN_MSG_FLAG_SET_ACK(_flag) ((_flag) |= FILLP_PKT_DISCONN_MSG_FLAG_ACK)
#define FILLP_PKT_DISCONN_MSG_FLAG_SET_VER(_flag) ((_flag) |= FILLP_PKT_DISCONN_MSG_FLAG_VER)

#define FILLP_PKT_DISCONN_MSG_FLAG_IS_WR(_flag) ((_flag)&FILLP_PKT_DISCONN_MSG_FLAG_WR)
#define FILLP_PKT_DISCONN_MSG_FLAG_IS_RD(_flag) ((_flag)&FILLP_PKT_DISCONN_MSG_FLAG_RD)
#define FILLP_PKT_DISCONN_MSG_FLAG_IS_ACK(_flag) ((_flag)&FILLP_PKT_DISCONN_MSG_FLAG_ACK)
#define FILLP_PKT_DISCONN_MSG_FLAG_IS_VER(_flag) ((_flag) & FILLP_PKT_DISCONN_MSG_FLAG_VER)

#define IGNORE_OVERFLOW __attribute__((no_sanitize("unsigned-integer-overflow")))
IGNORE_OVERFLOW static __inline FILLP_INT FillpNumIsbigger(FILLP_UINT32 value1, FILLP_UINT32 value2)
{
    return ((FILLP_INT32)(value1 - value2)) > 0;
}

void FillpSendConnConfirmAck(struct FillpPcb *pcb);
FILLP_INT FillpSendConnReq(struct FillpPcb *pcb);
void FillpSendFin(struct FillpPcb *pcb);
void FillpSendFinAck(struct FillpPcb *pcb, struct sockaddr *remoteAddr);
void FillpSendRst(struct FillpPcb *pcb, struct sockaddr *remoteAddr);
void FillpSendRstWithVersionImcompatible(struct FillpPcb *pcb, struct sockaddr *remoteAddr);

void FillpGenerateCookie(IN FILLP_CONST struct FillpPcb *pcb, IN struct FillpPktConnReq *req,
    IN FILLP_CONST struct sockaddr_in6 *remoteAddr, IN FILLP_UINT16 serverPort, OUT FillpCookieContent *stateCookie);

FILLP_INT FillpValidateCookie(IN FILLP_CONST struct FillpPcb *pcb, IN FILLP_UINT16 serverPort,
    IN FILLP_CONST struct sockaddr_in6 *clientAddr, IN FILLP_CONST FillpCookieContent *stateCookie);

void FillpSendConnReqAck(struct FillpPcb *pcb, FILLP_CONST FillpCookieContent *stateCookie, FILLP_ULLONG timestamp);

void FillpSendConnConfirm(struct FillpPcb *pcb, FILLP_CONST struct FillpConnReqAckClient *reqAck);

void FillpPackTimerCb(void *argPcb);
void FillpFcTimerCb(void *argPcb);
void FillpSendTimerCb(void *argPcb);

void FillpEnableSendTimer(struct FillpPcb *pcb);
void FillpDisableSendTimer(struct FillpPcb *pcb);
void FillpEnablePackTimer(struct FillpPcb *pcb);
void FillpDisablePackTimer(struct FillpPcb *pcb);
void FillpEnableFcTimer(struct FillpPcb *pcb);
void FillpDisableFcTimer(struct FillpPcb *pcb);
void FillpEnableKeepAliveTimer(struct FillpPcb *pcb);
void FillpDisableKeepAliveTimer(struct FillpPcb *pcb);
void FillpEnableDelayNackTimer(struct FillpPcb *pcb);
void FillpDisableDelayNackTimer(struct FillpPcb *pcb);
void FillpEnableDataBurstTimer(struct FillpPcb *pcb);
void FillpDisableDataBurstTimer(struct FillpPcb *pcb);
void FillpEnableConnRetryCheckTimer(struct FillpPcb *pcb);
void FillpDisableConnRetryCheckTimer(struct FillpPcb *pcb);
void FillpEnableFinCheckTimer(struct FillpPcb *pcb);
void FillpDisableFinCheckTimer(struct FillpPcb *pcb);

void FillpConnReqInput(struct FillpPcb *pcb, FILLP_CONST struct NetBuf *p);
void FillpConnReqAckInput(struct FillpPcb *pcb, FILLP_CONST struct NetBuf *p);
void FillpConnConnectionEstFailure(struct FillpPcb *pcb, FILLP_CONST struct NetBuf *p);
void FillpConnConfirmAckInput(struct FillpPcb *pcb, FILLP_CONST struct NetBuf *p);

void FillpFinInput(struct FillpPcb *pcb, FILLP_CONST struct NetBuf *p, FILLP_BOOL *pcbFreed);

struct FtNetconn;

FILLP_INT32 FillpDecodeExtPara(FILLP_CONST FILLP_UCHAR *buf, FILLP_INT bufLen, struct FtNetconn *conn);

#ifdef __cplusplus
}
#endif

#endif /* FILLP_H */
