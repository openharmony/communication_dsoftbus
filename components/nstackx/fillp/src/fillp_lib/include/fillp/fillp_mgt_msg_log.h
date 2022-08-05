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

#ifndef FILLP_MGT_MSG_LOG_H
#define FILLP_MGT_MSG_LOG_H

#include "fillp.h"
#include "log.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef FILLP_MGT_MSG_LOG
enum {
    FILLP_DIRECTION_TX,
    FILLP_DIRECTION_RX,
};

void FillpPktSimpleLog(FILLP_INT sockIndex, FILLP_CONST struct FillpPktHead *hdrInput, FILLP_INT direction);
void FillpConnReqLog(FILLP_INT sockIndex, FILLP_CONST struct FillpPktConnReq *req, FILLP_INT direction);
void FillpConnReqAckRxLog(FILLP_INT sockIndex, FILLP_CONST struct FillpPktHead *hdr,
    FILLP_CONST struct FillpConnReqAckClient *ack, FILLP_CONST FILLP_UCHAR *extPara, FILLP_INT extParaLen);
void FillpConnReqAckTxLog(FILLP_INT sockIndex, FILLP_CONST struct FillpPktConnReqAck *ack,
    FILLP_CONST FILLP_UCHAR *extPara, FILLP_INT extParaLen);
void FillpConnConfirmRxLog(FILLP_INT sockIndex, FILLP_CONST struct FillpPktConnConfirm *confirm,
    FILLP_CONST FILLP_UCHAR *extPara, FILLP_INT extParaLen);
void FillpConnConfirmTxLog(FILLP_INT sockIndex, FILLP_CONST FILLP_UCHAR *data, FILLP_INT dataLen,
    FILLP_INT extParaOffset);
void FillpConnConfirmAckLog(FILLP_INT sockIndex,
    FILLP_CONST struct FillpPktConnConfirmAck *confirmAck, FILLP_INT direction);
void FillpConnFinLog(FILLP_INT sockIndex, FILLP_CONST struct FillpPktFin *fin, FILLP_INT direction);

#define FILLP_PKT_SIMPLE_LOG(_sockIndex, _hdr, _direction) do { \
        /* should check null, because the hdr would be null in tx data */ \
        if (_hdr != FILLP_NULL_PTR && g_fillpLmGlobal.mgtMsgLog) { \
            FillpPktSimpleLog(_sockIndex, _hdr, _direction); \
        } \
    } while (0)

#define FILLP_CONN_REQ_LOG(_sockIndex, _req, _direction) do { \
        if (g_fillpLmGlobal.mgtMsgLog) { \
            FillpConnReqLog(_sockIndex, _req, _direction); \
        } \
    } while (0)

#define FILLP_CONN_REQ_ACK_RX_LOG(_sockIndex, _hdr, _ack, _extParaBuf, _extParaBufLen) do { \
        if (g_fillpLmGlobal.mgtMsgLog) { \
            FillpConnReqAckRxLog(_sockIndex, _hdr, _ack, _extParaBuf, _extParaBufLen); \
        } \
    } while (0)

#define FILLP_CONN_REQ_ACK_TX_LOG(_sockIndex, _ack, _extParaBuf, _extParaBufLen) do { \
        if (g_fillpLmGlobal.mgtMsgLog) { \
            FillpConnReqAckTxLog(_sockIndex, _ack, _extParaBuf, _extParaBufLen); \
        } \
    } while (0)

#define FILLP_CONN_CONFIRM_RX_LOG(_sockIndex, _confirm, _extParaBuf, _extParaBufLen) do { \
        if (g_fillpLmGlobal.mgtMsgLog) { \
            FillpConnConfirmRxLog(_sockIndex, _confirm, _extParaBuf, _extParaBufLen); \
        } \
    } while (0)

#define FILLP_CONN_CONFIRM_TX_LOG(_sockIndex, _data, _dataLen, _extParaOffset) do { \
        if (g_fillpLmGlobal.mgtMsgLog) { \
            FillpConnConfirmTxLog(_sockIndex, _data, _dataLen, _extParaOffset); \
        } \
    } while (0)

#define FILLP_CONN_CONFIRM_ACK_LOG(_sockIndex, _confirmAck, _direction) do { \
        if (g_fillpLmGlobal.mgtMsgLog) { \
            FillpConnConfirmAckLog(_sockIndex, _confirmAck, _direction); \
        } \
    } while (0)

#define FILLP_CONN_FIN_LOG(_sockIndex, _fin, _direction) do { \
        if (g_fillpLmGlobal.mgtMsgLog) { \
            FillpConnFinLog(_sockIndex, _fin, _direction); \
        } \
    } while (0)
#else
#define FILLP_PKT_SIMPLE_LOG(_sockIndex, _hdr, _direction)
#define FILLP_CONN_REQ_LOG(_sockIndex, _req, _direction)
#define FILLP_CONN_REQ_ACK_RX_LOG(_sockIndex, _hdr, _ack, _extParaBuf, _extParaBufLen)
#define FILLP_CONN_REQ_ACK_TX_LOG(_sockIndex, _ack, _extParaBuf, _extParaBufLen)
#define FILLP_CONN_CONFIRM_RX_LOG(_sockIndex, _confirm, _extParaBuf, _extParaBufLen)
#define FILLP_CONN_CONFIRM_TX_LOG(_sockIndex, _data, _dataLen, _extParaOffset) FILLP_UNUSED_PARA(_extParaOffset)
#define FILLP_CONN_CONFIRM_ACK_LOG(_sockIndex, _confirmAck, _direction)
#define FILLP_CONN_FIN_LOG(_sockIndex, _fin, _direction)
#endif

#ifdef __cplusplus
}
#endif

#endif // FILLP_MGT_MSG_LOG_H