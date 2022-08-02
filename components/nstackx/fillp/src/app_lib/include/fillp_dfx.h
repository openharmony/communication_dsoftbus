/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: This file defines fillp dfx function
 * Author:
 * Create: 2022-07-16
 */
#ifndef FILLP_DFX_H
#define FILLP_DFX_H

#include "fillptypes.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    FILLP_DFX_LINK_VERSION_MISMATCH,
    FILLP_DFX_LINK_RETRANSMIT_OUT,
    FILLP_DFX_LINK_KEEPALIVE_TIMEOUT,
    FILLP_DFX_LINK_IP_REMOVED,
    FILLP_DFX_LINK_CLOSE,
    FILLP_DFX_LINK_FIN_INPUT,
    FILLP_DFX_LINK_EVT_MAX,
} FillpDfxLinkEvtType;

typedef enum {
    FILLP_DFX_PKT_PARSE_FAIL,
    FILLP_DFX_PKT_SEMI_RELIABLE_DROP,
    FILLP_DFX_PKT_EVT_MAX,
} FillpDfxPktEvtType;

void FillpDfxEvtCbSet(void *softObj, FillpDfxEventCb evtCb);
void FillpDfxSockLinkAndQosNotify(FILLP_INT sockIdx, FillpDfxLinkEvtType evtType);
void FillpDfxPktNotify(FILLP_INT sockIdx, FillpDfxPktEvtType evtType, FILLP_UINT32 dropCnt);

#ifdef FILLP_ENABLE_DFX_HIDUMPER
FILLP_INT FillpDfxDump(FILLP_UINT32 argc, const FILLP_CHAR **argv, void *softObj, FillpDfxDumpFunc dump);
#endif /* FILLP_ENABLE_DFX_HIDUMPER */

#ifdef __cplusplus
}
#endif

#endif /* FILLP_DFX_H */