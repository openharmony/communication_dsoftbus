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

#include "spunge_core.h"
#ifdef FILLP_LINUX
#include <errno.h>
#endif
#include <stdio.h>
#include "securec.h"
#include "sysio.h"
#include "res.h"
#include "socket_common.h"
#include "fillp_flow_control.h"
#include "timing_wheel.h"
#include "fillp_buf_item.h"
#include "callbacks.h"
#include "fillp_common.h"
#include "spunge.h"
#include "spunge_stack.h"
#include "spunge_message.h"
#include "fillp_output.h"
#include "fillp_input.h"
#include "fillp_dfx.h"

#ifdef __cplusplus
extern "C" {
#endif

SYS_ARCH_SEM g_resDeinitSem;
#define BIT_MOVE_CNT 3
#define RECV_RATE_PAR_LOW 0.98
#define RECV_RATE_PAT_HIGH 1.02
#define RECV_STATE_THRESHOLD 10

void SpungeFreeInstanceResource(struct SpungeInstance *inst);


void SpungeDoRecvCycle(struct SockOsSocket *osSock, struct SpungeInstance *inst)
{
    FILLP_UINT32 i;
    struct NetBuf buf;
    struct SpungePcb *spcb = FILLP_NULL_PTR;

    if (!OS_SOCK_OPS_FUNC_VALID(osSock, fetchPacket)) {
        return;
    }

    (void)memset_s(&buf, sizeof(buf), 0, sizeof(buf));
    buf.p = inst->tmpBuf[0];
    for (i = 0; i < g_resource.udp.rxBurst; i++) {
        spcb = osSock->ioSock->ops->fetchPacket((void *)osSock, (void *)&buf, 0);
        if (spcb != FILLP_NULL_PTR) {
            FillpDoInput(&spcb->fpcb, &buf, inst);
            continue;
        } else {
            break;
        }
    }
}

static FILLP_UINT32 SpungeCalExpectedBytes(FILLP_UINT32 *sendPktNum, struct SpungePcb *pcb,
    struct FtSocket *sock, struct FillpFlowControl *flowControl, FILLP_LLONG detaTime)
{
    FILLP_UINT32 bytesExpected;
    FILLP_UINT32 pktNum = sock->resConf.udp.txBurst;

    if (flowControl->sendInterval) {
        pktNum = (FILLP_UINT32)(detaTime / flowControl->sendInterval);
    }

    if (pktNum <= (sock->resConf.udp.txBurst)) {
        /* sendRate is kbps */
        FILLP_ULLONG bitsExpected = (FILLP_ULLONG)(detaTime * flowControl->sendRate / FILLP_ONE_SECOND);
        bitsExpected >>= FILLP_TIME_PRECISION;
        bytesExpected = (FILLP_UINT32)(FILLP_UTILS_BIT2BYTE(bitsExpected));
        pcb->fpcb.statistics.traffic.packExpSendBytes += bytesExpected;
        bytesExpected += pcb->fpcb.send.flowControl.remainBytes;
    } else {
        pktNum = sock->resConf.udp.txBurst;
        bytesExpected = (FILLP_UINT32)(pktNum * pcb->fpcb.pktSize);
        pcb->fpcb.statistics.traffic.packExpSendBytes += bytesExpected;
    }
    *sendPktNum = pktNum;
    FILLP_LOGDBG("before_send_cycle fillp_sock_id:%d unRecvNum:%u, unAck:%u\r\n",
        sock->index, pcb->fpcb.send.unrecvList.nodeNum, pcb->fpcb.send.unackList.count);
    return bytesExpected;
}

static void SpungeDoSendUpdate(struct SpungePcb *pcb, FILLP_UINT32 sendBytes, FILLP_UINT32 bytesExpected)
{
    if ((sendBytes > 0) && (bytesExpected >= (FILLP_UINT32)sendBytes)) {
        pcb->fpcb.statistics.traffic.packSendBytes += sendBytes;
        pcb->fpcb.send.flowControl.remainBytes = (bytesExpected - (FILLP_UINT32)sendBytes);
    } else {
        pcb->fpcb.send.flowControl.remainBytes = 0;
    }
}

void SpungeDoSendCycle(struct SpungePcb *pcb, struct SpungeInstance *inst, FILLP_LLONG detaTime)
{
    FILLP_UINT32 sendPktNum;
    FILLP_UINT32 sendBytes = 0;
    FILLP_UINT32 tmpBytes = 0;
    FILLP_UINT32 bytesExpected;

    if ((pcb == FILLP_NULL_PTR) || (pcb->conn == FILLP_NULL_PTR)) {
        FILLP_LOGERR("NULL Pointer");
        return;
    }

    FILLP_SIZE_T pktSize = pcb->fpcb.pktSize;
    struct FillpFlowControl *flowControl = &pcb->fpcb.send.flowControl;
    struct FtNetconn *conn = (struct FtNetconn *)pcb->conn;
    struct FtSocket *sock = (struct FtSocket *)conn->sock;

    if (sock == FILLP_NULL_PTR) {
        FILLP_LOGERR("NULL Pointer");
        return;
    }

    flowControl->sendTime = inst->curTime;
    bytesExpected = SpungeCalExpectedBytes(&sendPktNum, pcb, sock, flowControl, detaTime);

    /* flow control alg may need to change bytesExpected for the this send cycle a according to current status */
    if (pcb->fpcb.algFuncs.updateExpectSendBytes != FILLP_NULL_PTR) {
        pcb->fpcb.algFuncs.updateExpectSendBytes(&pcb->fpcb, &bytesExpected);
    }

    /* If BytesExpected less than pktSize, no need to send, just store the remainBytes */
    if (bytesExpected >= pktSize) {
        /* Make sure that the send bytes won't more than bytesExpected */
        tmpBytes = (FILLP_UINT32)(bytesExpected - pktSize);

        sendBytes = FillpSendOne(&pcb->fpcb, tmpBytes, sendPktNum);
        SpungeDoSendUpdate(pcb, sendBytes, bytesExpected);
    } else {
        pcb->fpcb.send.flowControl.remainBytes = bytesExpected;
    }

    FILLP_LOGDBG("after_send_cycle: fillp_sock_id:%d expected bytes:%u sentBytes:%u remain:%u \r\n",
        sock->index, sendBytes, tmpBytes, pcb->fpcb.send.flowControl.remainBytes);

    if ((pcb->fpcb.send.flowControl.remainBytes) || (!HLIST_EMPTY(&pcb->fpcb.send.unSendList)) ||
        (pcb->fpcb.send.redunList.nodeNum) || (pcb->fpcb.send.unrecvList.nodeNum)) {
        FillpEnableSendTimer(&pcb->fpcb);
    } else {
        FillpDisableSendTimer(&pcb->fpcb);
    }

    return;
}

static void SpungeDestroySockTableSocket(struct FtSocketTable *table, int tableIndex)
{
    struct FtSocket *sock = FILLP_NULL_PTR;

    if (table == FILLP_NULL_PTR) {
        return;
    }

    sock = table->sockPool[tableIndex];
    if (sock == FILLP_NULL_PTR) {
        return;
    }
    (void)SYS_ARCH_RWSEM_DESTROY(&sock->sockConnSem);
    (void)SYS_ARCH_SEM_DESTROY(&sock->connBlockSem);
    (void)SYS_ARCH_SEM_DESTROY(&sock->sockCloseProtect);
    (void)SYS_ARCH_SEM_DESTROY(&sock->epollTaskListLock);
    SpungeFree(sock, SPUNGE_ALLOC_TYPE_CALLOC);
    table->sockPool[tableIndex] = FILLP_NULL_PTR;
}

/* SFT */
struct FtSocketTable *SpungeCreateSockTable(FILLP_UINT maxSock)
{
    int i;
    struct FtSocketTable *table;
    table = (struct FtSocketTable *)SpungeAlloc(1, sizeof(struct FtSocketTable), SPUNGE_ALLOC_TYPE_CALLOC);
    if (table == FILLP_NULL_PTR) {
        FILLP_LOGERR("Failed to allocate memory for socket table \r\n");
        return FILLP_NULL_PTR;
    }

    table->freeQueqe = FillpQueueCreate("sock_free_table", (FILLP_SIZE_T)maxSock, SPUNGE_ALLOC_TYPE_CALLOC);

    if (table->freeQueqe == FILLP_NULL_PTR) {
        FILLP_LOGERR("Fail to create socket table free queue");
        goto ERR_FAIL;
    }

    FillpQueueSetConsSafe(table->freeQueqe, FILLP_TRUE);
    FillpQueueSetProdSafe(table->freeQueqe, FILLP_TRUE);

    table->sockPool =
        (struct FtSocket **)SpungeAlloc(maxSock, (FILLP_SIZE_T)sizeof(struct FtSocket *), SPUNGE_ALLOC_TYPE_CALLOC);
    if (table->sockPool == FILLP_NULL_PTR) {
        FILLP_LOGERR("Failed to allocate memory for sockPool of socket table");
        goto ERR_FAIL;
    }

    table->size = (FILLP_INT)maxSock;
    SYS_ARCH_ATOMIC_SET(&table->used, 0);
    for (i = 0; i < table->size; i++) {
        table->sockPool[i] = FILLP_NULL_PTR;
    }

    return table;

ERR_FAIL:
    if (table->freeQueqe != FILLP_NULL_PTR) {
        FillpQueueDestroy(table->freeQueqe);
        table->freeQueqe = FILLP_NULL_PTR;
    }

    if (table->sockPool != FILLP_NULL_PTR) {
        SpungeFree(table->sockPool, SPUNGE_ALLOC_TYPE_CALLOC);
        table->sockPool = FILLP_NULL_PTR;
    }

    SpungeFree(table, SPUNGE_ALLOC_TYPE_CALLOC);

    return FILLP_NULL_PTR;
}


/* SFT */
void SpungeDestroySockTable(struct FtSocketTable *table)
{
    FILLP_INT i;

    for (i = 0; i < SYS_ARCH_ATOMIC_READ(&table->used); i++) {
        SpungeDestroySockTableSocket(table, i);
    }

    if (table->freeQueqe != FILLP_NULL_PTR) {
        FillpQueueDestroy(table->freeQueqe);
        table->freeQueqe = FILLP_NULL_PTR;
    }

    if (table->sockPool != FILLP_NULL_PTR) {
        SpungeFree(table->sockPool, SPUNGE_ALLOC_TYPE_CALLOC);
        table->sockPool = FILLP_NULL_PTR;
    }

    /* NULL check for table already done at the caller, and also in the above
    check, table is dereferenced without validating, so need to check for NULL
    again here before freeing it */
    SpungeFree(table, SPUNGE_ALLOC_TYPE_CALLOC);
}

static FILLP_INT SpungeInstMsgBoxInit(struct SpungeInstance *inst)
{
    (void)SYS_ARCH_ATOMIC_SET(&inst->msgUsingCount, 0);
    inst->msgBox = FillpQueueCreate("spunge_msg_box", g_spunge->resConf.maxMsgItemNum, SPUNGE_ALLOC_TYPE_MALLOC);
    if (inst->msgBox == FILLP_NULL_PTR) {
        FILLP_LOGERR("Init inst->msgBox Fail");
        return ERR_NORES;
    }

    FillpQueueSetConsSafe(inst->msgBox, FILLP_TRUE);
    FillpQueueSetProdSafe(inst->msgBox, FILLP_TRUE);

    inst->msgPool = SpungeMsgCreatePool(FILLP_MSG_ITEM_INIT_NUM, (int)g_spunge->resConf.maxMsgItemNum);
    if (inst->msgPool == FILLP_NULL_PTR) {
        FILLP_LOGERR("create msg pool fail");
        return ERR_NORES;
    }

    DympSetConsSafe(inst->msgPool, FILLP_TRUE);
    DympSetProdSafe(inst->msgPool, FILLP_TRUE);
    return ERR_OK;
}

static FILLP_INT SpungeInstSendInit(struct SpungeInstance *inst)
{
    int i;

    /* To control on client sending */
    inst->rateControl.connectionNum = FILLP_NULL;

    inst->rateControl.recv.maxRate = g_resource.flowControl.maxRecvRate;

    /* To control on server sending */
    inst->rateControl.send.maxRate = g_resource.flowControl.maxRate;

    inst->thresdSemInited = FILLP_FALSE;
    int ret = SYS_ARCH_SEM_INIT(&inst->threadSem, 1);
    if (ret != FILLP_OK) {
        FILLP_LOGERR("SYS_ARCH_SEM_INIT fails");
        return ERR_NORES;
    }
    inst->thresdSemInited = FILLP_TRUE;

    inst->unsendItem =
        SpungeAlloc(FILLP_UNSEND_BOX_LOOP_CHECK_BURST, sizeof(struct FillpPcbItem *), SPUNGE_ALLOC_TYPE_CALLOC);
    if (inst->unsendItem == FILLP_NULL_PTR) {
        FILLP_LOGERR("inst->unsendItem NULL");
        return ERR_NORES;
    }

    for (i = 0; i < FILLP_VLEN; i++) {
        inst->tmpBuf[i] = SpungeAlloc(1, (sizeof(FILLP_CHAR) * FILLP_MAX_PKT_SIZE), SPUNGE_ALLOC_TYPE_MALLOC);
        if (inst->tmpBuf[i] == FILLP_NULL_PTR) {
            FILLP_LOGERR("inst->tmpBuf[%d] is NULL", i);
            return ERR_NORES;
        }
    }

    HLIST_INIT(&inst->sendPcbList);
    for (i = 0; i < FILLP_INST_UNSEND_BOX_NUM; i++) {
        inst->unsendBox[i] = FillpQueueCreate("socket_send_box", FILLP_INST_UNSEND_BOX_SIZE, SPUNGE_ALLOC_TYPE_MALLOC);
        if (inst->unsendBox[i] == FILLP_NULL_PTR) {
            FILLP_LOGERR("inst->unsendBox[%d] is NULL", i);
            return ERR_NORES;
        }

        FillpQueueSetConsSafe(inst->unsendBox[i], FILLP_FALSE);
        FillpQueueSetProdSafe(inst->unsendBox[i], FILLP_TRUE);
    }
    return ERR_OK;
}

static void SpungeInstTimerInit(struct SpungeInstance *inst)
{
    inst->curTime = SYS_ARCH_GET_CUR_TIME_LONGLONG();

    (void)memset_s(&inst->macInfo, sizeof(FillpMacInfo), 0, sizeof(FillpMacInfo));
    FillpMacTimerExpire(&inst->macInfo, inst->curTime);

    FillpTimingWheelInit(&inst->timingWheel, FILLP_TIMING_WHEEL_ACCURACY);

    /* Init the global timers */
    FtGlobalTimerInit(inst);
    SpungeInitTokenBucket(inst);
}

static FILLP_INT SpungeThreadInit(struct SpungeInstance *inst)
{
    FILLP_THREAD threadId;

    inst->mainThreadParam.func = SpungeInstanceMainThread;
    inst->mainThreadParam.param = inst;
    inst->minSendInterval = FILLP_MAX_SEND_INTERVAL;

    inst->hasInited = FILLP_TRUE;

    (void)FILLP_SYS_START_NEWTHREAD(&inst->mainThreadParam, &threadId);

    return ERR_OK;
}

FILLP_INT SpungeInstInit(struct SpungeInstance *inst)
{
    FILLP_INT err;

    if (inst == FILLP_NULL_PTR) {
        FILLP_LOGERR("Init inst null");
        return ERR_NULLPTR;
    }

    if (inst->hasInited) {
        FILLP_LOGERR("Stack has been inited");
        return ERR_OK;
    }

    err = SpungeInstMsgBoxInit(inst);
    if (err != ERR_OK) {
        goto FAIL;
    }

    HLIST_INIT(&inst->osSockist);
    HLIST_INIT(&inst->pcbList.list);

    err = SpungeInstSendInit(inst);
    if (err != ERR_OK) {
        goto FAIL;
    }

    SpungeInstTimerInit(inst);

    inst->cleanseDataCtr = 0;

    err = SpungeThreadInit(inst);
    if (err != ERR_OK) {
        goto FAIL;
    }

    return ERR_OK;

FAIL:
    SpungeFreeInstanceResource(inst);
    return err;
}

static FILLP_INT SpungeSysCallRegisted(void)
{
    FILLP_INT ret;

    ret = FillpValidateFuncPtr(&g_fillpOsBasicLibFun, sizeof(FillpSysLibBasicCallbackFuncSt));
    if (ret != ERR_OK) {
        SET_ERRNO(FILLP_EINVAL);
        FILLP_LOGERR("FillpValidateFuncPtr g_fillpOsBasicLibFun failed");
        return ret;
    }

    ret = FillpValidateFuncPtr(&g_fillpOsSemLibFun, sizeof(FillpSysLibSemCallbackFuncSt));
    if (ret != ERR_OK) {
        SET_ERRNO(FILLP_EINVAL);
        FILLP_LOGERR("FillpValidateFuncPtr g_fillpOsSemLibFun failed");
        return ret;
    }

    ret = FillpValidateFuncPtr(&g_fillpOsSocketLibFun, sizeof(FillpSysLibSockCallbackFuncSt));
    if (ret != ERR_OK) {
        SET_ERRNO(FILLP_EINVAL);
        FILLP_LOGERR("FillpValidateFuncPtr g_fillpOsSocketLibFun failed");
        return ret;
    }

    return ERR_OK;
}

static void FtFreeEpollResource(void)
{
    if (g_spunge->epitemPool != FILLP_NULL_PTR) {
        DympDestroyPool(g_spunge->epitemPool);
        g_spunge->epitemPool = FILLP_NULL_PTR;
    }

    if (g_spunge->eventpollPool != FILLP_NULL_PTR) {
        DympDestroyPool(g_spunge->eventpollPool);
        g_spunge->eventpollPool = FILLP_NULL_PTR;
    }
}

static FILLP_INT FtAllocateEpollResource(void)
{
    DympoolItemOperaCbSt itemOperaCb = {FILLP_NULL_PTR, FILLP_NULL_PTR};
    g_spunge->epitemPool = DympCreatePool(FILLP_EPOLL_ITEM_INIT_NUM, (int)g_spunge->resConf.maxEpollEventNum,
        sizeof(struct EpItem), FILLP_TRUE, &itemOperaCb);
    if (g_spunge->epitemPool == FILLP_NULL_PTR) {
        FILLP_LOGERR("create mem pool for g_spunge->epitemPool failed");
        return ERR_NORES;
    }
    DympSetConsSafe(g_spunge->epitemPool, FILLP_TRUE);
    DympSetProdSafe(g_spunge->epitemPool, FILLP_TRUE);

    g_spunge->eventpollPool = DympCreatePool(FILLP_EPOLL_ITEM_INIT_NUM, (int)g_spunge->resConf.maxEpollEventNum,
        sizeof(struct EventPoll), FILLP_TRUE, &itemOperaCb);
    if (g_spunge->eventpollPool == FILLP_NULL_PTR) {
        FtFreeEpollResource();
        FILLP_LOGERR("create Dym pool for g_spunge->eventpollPool failed");
        return ERR_NORES;
    }
    DympSetConsSafe(g_spunge->eventpollPool, FILLP_TRUE);
    DympSetProdSafe(g_spunge->eventpollPool, FILLP_TRUE);
    return ERR_OK;
}

static int SpungeAllocInstRes(void)
{
    FILLP_UINT i;
    FILLP_UINT j;
    FILLP_INT err;

    for (i = 0; i < g_spunge->insNum; i++) {
        (void)memset_s(&g_spunge->instPool[i], sizeof(struct SpungeInstance), 0, sizeof(struct SpungeInstance));
        g_spunge->instPool[i].instIndex = (FILLP_INT)i;
        err = SpungeInstInit(&g_spunge->instPool[i]);
        if (err == ERR_OK) {
            continue;
        }
        FILLP_LOGERR("SpungeInstInit failed :: Instance number :: %u", i);

        /* Release instances which are created success */
        if (i > 0) {
            g_spunge->insNum = i;

            g_spunge->hasDeinitBlked = FILLP_TRUE;
            for (j = 0; j < g_spunge->insNum; j++) {
                g_spunge->instPool[j].waitTobeCoreKilled = FILLP_TRUE;
            }

            /* After this step g_spunge will be freed, it should not be accessed, caller has check for NULL pointer
                before accessing, so it will not cause problem */
            (void)SYS_ARCH_SEM_WAIT(&g_resDeinitSem);
        }
        return err;
    }

    return ERR_OK;
}

static void SpungeFreeInstSendRecv(struct SpungeInstance *inst)
{
    int j;
    if (inst->thresdSemInited) {
        (void)SYS_ARCH_SEM_DESTROY(&inst->threadSem);
        inst->thresdSemInited = FILLP_FALSE;
    }

    for (j = 0; j < FILLP_INST_UNSEND_BOX_NUM; j++) {
        if (inst->unsendBox[j] != FILLP_NULL_PTR) {
            FillpQueueDestroy(inst->unsendBox[j]);
            inst->unsendBox[j] = FILLP_NULL_PTR;
        } else {
            break;
        }
    }
    if (inst->unsendItem != FILLP_NULL_PTR) {
        SpungeFree(inst->unsendItem, SPUNGE_ALLOC_TYPE_CALLOC);
        inst->unsendItem = FILLP_NULL_PTR;
    }

    for (j = 0; j < FILLP_VLEN; j++) {
        if (inst->tmpBuf[j] == FILLP_NULL_PTR) {
            break;
        }
        SpungeFree(inst->tmpBuf[j], SPUNGE_ALLOC_TYPE_MALLOC);
        inst->tmpBuf[j] = FILLP_NULL_PTR;
    }
}

void SpungeFreeInstanceResource(struct SpungeInstance *inst)
{
    if (inst == FILLP_NULL_PTR) {
        return;
    }

    if (inst->msgBox != FILLP_NULL_PTR) {
        FillpQueueDestroy(inst->msgBox);
        inst->msgBox = FILLP_NULL_PTR;
    }

    while (SYS_ARCH_ATOMIC_READ(&inst->msgUsingCount) > 0) {
        FILLP_SLEEP_MS(1);
    }

    if (inst->msgPool != FILLP_NULL_PTR) {
        SpungeMsgPoolDestroy(inst->msgPool);
        inst->msgPool = FILLP_NULL_PTR;
    }

    SpungeFreeInstSendRecv(inst);

    inst->hasInited = FILLP_FALSE;
}

static void FtGetSpungeRes(struct SpungeResConf *resConf)
{
    (void)memset_s(resConf, sizeof(struct SpungeResConf), 0, sizeof(struct SpungeResConf));

    resConf->maxInstNum = (FILLP_UINT)UTILS_MIN(g_resource.common.maxInstNum, MAX_SPUNGEINSTANCE_NUM);
    resConf->maxSockNum = g_resource.common.maxSockNum;
    resConf->maxConnNum = g_resource.common.maxConnNum;
    resConf->maxMsgItemNum    = ((FILLP_UINT)g_resource.common.maxSockNum * FILLP_SPUNGE_EVENTG_MULT_NUM);
    resConf->maxTimerItemNum  = ((FILLP_UINT)g_resource.common.maxSockNum * FILLP_ITEM_MULT_NUM);
    resConf->maxEpollEventNum = (FILLP_UINT)(g_resource.common.maxSockNum * FILLP_ITEM_MULT_NUM);
    resConf->maxEpollItemNum  = (FILLP_UINT)(g_resource.common.maxSockNum * FILLP_ITEM_MULT_NUM);
}

void FtGlobalTimerInit(struct SpungeInstance *inst)
{
    /* Initialize the Fairness timer */
    inst->fairTimerNode.cbNode.cb = SpinstLoopFairnessChecker;
    inst->fairTimerNode.cbNode.arg = (void *)inst;
    inst->fairTimerNode.interval = SPUNGE_WEIGHT_ADJUST_INTERVAL;
    FillpTimingWheelAddTimer(&inst->timingWheel, (SYS_ARCH_GET_CUR_TIME_LONGLONG() + inst->fairTimerNode.interval),
        &inst->fairTimerNode);
    /* Initialize the MAC timer */
    inst->macTimerNode.cbNode.cb = SpinstLoopMacTimerChecker;
    inst->macTimerNode.cbNode.arg = (void *)inst;
    inst->macTimerNode.interval = FILLP_KEY_REFRESH_TIME;
    FillpTimingWheelAddTimer(&inst->timingWheel, (SYS_ARCH_GET_CUR_TIME_LONGLONG() + inst->macTimerNode.interval),
        &inst->macTimerNode);
}

static FILLP_INT SpungeCheckCallbacks(void)
{
    return SpungeSysCallRegisted();
}

static FILLP_INT FtInitGlobalUdpIo(void)
{
    g_udpIo.readSet = FILLP_FD_CREATE_FD_SET();
    if (g_udpIo.readSet == FILLP_NULL_PTR) {
        FILLP_LOGERR("Malloc g_udpIo.readSet failed");
        return ERR_NORES;
    }

    g_udpIo.readableSet = FILLP_FD_CREATE_FD_SET();
    if (g_udpIo.readableSet == FILLP_NULL_PTR) {
        FILLP_LOGERR("Malloc g_udpIo.readableSet failed");
        return ERR_NORES;
    }

    HLIST_INIT(&g_udpIo.listenPcbList);

    return ERR_OK;
}

static FILLP_INT FtInitGlobalInstPool(void)
{
    g_spunge->insNum = g_spunge->resConf.maxInstNum;
    g_spunge->instPool = (struct SpungeInstance *)SpungeAlloc(g_spunge->insNum, sizeof(struct SpungeInstance),
        SPUNGE_ALLOC_TYPE_MALLOC);
    if (g_spunge->instPool == FILLP_NULL_PTR) {
        FILLP_LOGERR("Malloc g_spunge->instPool failed");
        return ERR_NORES;
    }

    return ERR_OK;
}

static FILLP_INT FtInitGlobalSockTable(void)
{
    g_spunge->sockTable = SpungeCreateSockTable(g_spunge->resConf.maxSockNum);
    if (g_spunge->sockTable == FILLP_NULL_PTR) {
        FILLP_LOGERR("Malloc g_spunge->sockTable failed");
        return ERR_NORES;
    }
    return ERR_OK;
}

static FILLP_INT FtInitGlobalNetPool(void)
{
    FILLP_UINT netPoolInitSize = FILLP_CONN_ITEM_INIT_NUM;

    if (netPoolInitSize > g_spunge->resConf.maxConnNum) {
        netPoolInitSize = g_spunge->resConf.maxConnNum;
    }

    DympoolItemOperaCbSt itemOperaCb = {FILLP_NULL_PTR, FILLP_NULL_PTR};
    g_spunge->netPool = DympCreatePool((FILLP_INT)netPoolInitSize, (int)g_spunge->resConf.maxConnNum,
        sizeof(struct FtNetconn), FILLP_TRUE, &itemOperaCb);
    if (g_spunge->netPool == FILLP_NULL_PTR) {
        FILLP_LOGERR("Malloc g_spunge->netPool failed");
        return ERR_NORES;
    }

    DympSetConsSafe(g_spunge->netPool, FILLP_TRUE);
    DympSetProdSafe(g_spunge->netPool, FILLP_FALSE);
    return ERR_OK;
}

static void FtFreeGlobalUdpIo(void)
{
    if (g_udpIo.readSet != FILLP_NULL_PTR) {
        FILLP_FD_DESTROY_FD_SET(g_udpIo.readSet);
        g_udpIo.readSet = FILLP_NULL_PTR;
    }

    if (g_udpIo.readableSet != FILLP_NULL_PTR) {
        FILLP_FD_DESTROY_FD_SET(g_udpIo.readableSet);
        g_udpIo.readableSet = FILLP_NULL_PTR;
    }
}

static void FtFreeGlobalSpunge(void)
{
    if (g_spunge == FILLP_NULL_PTR) {
        return;
    }
    g_spunge->hasInited = FILLP_FALSE;

    FtFreeEpollResource();

    if (g_spunge->sockTable != FILLP_NULL_PTR) {
        SpungeDestroySockTable(g_spunge->sockTable);
        g_spunge->sockTable = FILLP_NULL_PTR;
    }

    if (g_spunge->netPool != FILLP_NULL_PTR) {
        DympDestroyPool(g_spunge->netPool);
        g_spunge->netPool = FILLP_NULL_PTR;
    }

    if (g_spunge->instPool != FILLP_NULL_PTR) {
        SpungeFree(g_spunge->instPool, SPUNGE_ALLOC_TYPE_MALLOC);
        g_spunge->instPool = FILLP_NULL_PTR;
    }

    FtFreeGlobalUdpIo();

    SpungeFree(g_spunge, SPUNGE_ALLOC_TYPE_MALLOC);
    g_spunge = FILLP_NULL_PTR;
}

static FILLP_INT FtModuleInit(void)
{
    FILLP_INT err;
    int ret;

    err = FtInitGlobalUdpIo();
    if (err != ERR_OK) {
        return err;
    }

    err = FtInitGlobalInstPool();
    if (err != ERR_OK) {
        return err;
    }

    err = FtInitGlobalSockTable();
    if (err != ERR_OK) {
        return err;
    }

    err = FtInitGlobalNetPool();
    if (err != ERR_OK) {
        return err;
    }

    err = FtAllocateEpollResource();
    if (err != ERR_OK) {
        FILLP_LOGERR("Alloc epoll resource fail");
        return err;
    }

    ret = SYS_ARCH_SEM_INIT(&g_resDeinitSem, 0);
    if (ret != FILLP_OK) {
        FILLP_LOGERR("deinit sem init failed. ");
        return ERR_NORES;
    }

    err = SpungeAllocInstRes();
    if (err != ERR_OK) {
        FILLP_LOGERR("Spunge init instances resource fail");
        (void)SYS_ARCH_SEM_DESTROY(&g_resDeinitSem);
        return err;
    }
    return ERR_OK;
}

FILLP_INT FtInit(void)
{
    FILLP_INT err;

    FILLP_LOGBUTT("init stack");
    if (g_spunge != FILLP_NULL_PTR) {
        FILLP_LOGERR("Init already done");
        return ERR_STACK_ALREADY_INITIALD;
    }

    if (SpungeCheckCallbacks() != ERR_OK) {
        FILLP_LOGERR("User has not registered system callback functions");
        return ERR_ADP_SYS_CALLBACK_NOT_REGISTERED;
    }

    if (SYS_ARCH_INIT() != ERR_OK) {
        FILLP_LOGERR("SYS_ARCH_INIT ssp failed");
        return ERR_NORES;
    }

    g_spunge = (struct Spunge *)SpungeAlloc(1, sizeof(struct Spunge), SPUNGE_ALLOC_TYPE_MALLOC);
    if (g_spunge == FILLP_NULL_PTR) {
        FILLP_LOGERR("Alloc g_spunge fail");
        return ERR_NORES;
    }

    (void)memset_s(g_spunge, sizeof(struct Spunge), FILLP_NULL_NUM, sizeof(struct Spunge));

    FtGetSpungeRes(&g_spunge->resConf);

    err = FtModuleInit();
    if (err != ERR_OK) {
        goto ERR_FAIL;
    }

    FILLP_LOGBUTT("FillP_init: Spunge mem_zone alloc finished!");

    FILLP_LOGBUTT("FillP Core init success!");
    FILLP_LOGBUTT("version " FILLP_VERSION);

    g_spunge->traceFlag = 0;
    g_spunge->hasInited = FILLP_TRUE;
    FILLP_LOGBUTT("Init success");
    return ERR_OK;

ERR_FAIL:
    FtFreeGlobalSpunge();

    FILLP_LOGERR("Init fail,clean up");
    return err;
}


/* starts from LSB bit position, cnt starts from 0 */
#define SPUNGE_SET_BIT(num, pos) ((num) |= (1U << (pos)))

static void SpungZeroInstance(void)
{
    FILLP_BOOL hasDeinitBlked = g_spunge->hasDeinitBlked;
    /* This logic can work for 32 instance in future need to change if more number of
        instance are supported */
    /* instance 0 is already closed so mark in bit field. */
    FILLP_UINT32 instBitClosed = 1;
    FILLP_UINT32 i;
    FILLP_UINT32 instAllBit = (FILLP_UINT32)((1U << g_spunge->insNum) - 1);

    /* In case of blocking FtDestroy 0th instance should post semaphore after all instance threads are exited,
        and all resources are release. In case on non blocking FtDestroy 0th instance should free free all
        reasource no need to post semaphore and need to release semaphore also
        Wait for other instance threads to release respective resource and exit thread */
    while (instBitClosed != instAllBit) {
        FILLP_SLEEP_MS(1);
        for (i = 1; i < g_spunge->insNum; i++) {
            if (g_spunge->instPool[i].hasInited == 0) {
                /* Mark as closed */
                SPUNGE_SET_BIT(instBitClosed, i);
            }
        }
    }

    /* Free all global resource and reset parameters */
    InitGlobalResourceDefault();
    InitGlobalAppResourceDefault();
    FtFreeGlobalSpunge();
    FillpSysOsDeinit();
    FillpDfxDoEvtCbSet(FILLP_NULL_PTR, FILLP_NULL_PTR);

    /* Signal or release deinit sem */
    if (hasDeinitBlked) {
        (void)SYS_ARCH_SEM_POST(&g_resDeinitSem);
    } else {
        (void)SYS_ARCH_SEM_DESTROY(&g_resDeinitSem);
    }
}

void SpungeDestroyInstance(struct SpungeInstance *inst)
{
    FILLP_INT instIdx = inst->instIndex;

    SpungeFreeInstanceResource(inst);

    if (instIdx == 0) {
        SpungZeroInstance();
    }

    FILLP_LOGERR("Destroy finish index: %d", instIdx);
}

static void FtDestroyInner(FILLP_INT block)
{
    FILLP_UINT i;
    FILLP_LOGERR("Destroy stack start, block(%d)", block);

    if ((g_spunge == FILLP_NULL_PTR) || (!g_spunge->hasInited)) {
        return;
    }

    g_spunge->hasDeinitBlked = (FILLP_BOOL)block;

    /*
     * should check g_spunge again,
     * because the g_spunge may be freed in main thread after all the inst is freed
     */
    for (i = 0; g_spunge != FILLP_NULL_PTR && i < g_spunge->insNum; i++) {
        (void)SYS_ARCH_SEM_WAIT(&g_spunge->instPool[i].threadSem);
        g_spunge->instPool[i].waitTobeCoreKilled = FILLP_TRUE;
        (void)SYS_ARCH_SEM_POST(&g_spunge->instPool[i].threadSem);
    }

    if ((block) && (SYS_ARCH_SEM_WAIT(&g_resDeinitSem) == 0)) {
        (void)SYS_ARCH_SEM_DESTROY(&g_resDeinitSem);
    }

    FILLP_LOGERR("Destroy finished");
    return;
}

void FtDestroy(void)
{
    FtDestroyInner(FILLP_TRUE);
}

void FtDestroyNonblock(void)
{
    FtDestroyInner(FILLP_FALSE);
}

void SpungeHandleMsgCycle(struct SpungeInstance *inst)
{
    struct SpungeMsg *msg = FILLP_NULL_PTR;
    FILLP_INT ret;
    FILLP_ULONG i;

    FILLP_ULONG boxItems = FillpQueueValidOnes(inst->msgBox);
    if ((boxItems == 0) || (boxItems > inst->msgBox->size)) {
        boxItems = (FILLP_ULONG)inst->msgBox->size;
    }

    for (i = 0; i < boxItems; i++) {
        ret = FillpQueuePop(inst->msgBox, (void *)&msg, 1);
        if (ret <= 0) {
            break;
        }
        if (msg->msgType < MSG_TYPE_END) {
            g_msgHandler[msg->msgType](msg->value, inst);
        }
        if (!msg->block) {
            DympFree(msg);
        } else {
            (void)SYS_ARCH_SEM_POST(&msg->syncSem);
        }
    }
}

static void SpungeLoopCheckUnsendBox(struct SpungeInstance *inst)
{
    int j;
    FillpQueue *boxQueue = inst->unsendBox[0];
    struct FillpPcbItem **item = inst->unsendItem;
    struct FtNetconn *netconn = FILLP_NULL_PTR;
    struct FillpPcb *fpcb = FILLP_NULL_PTR;
    FILLP_INT count;

    count = FillpQueuePop(boxQueue, (void *)item, FILLP_UNSEND_BOX_LOOP_CHECK_BURST);
    if (count <= 0) {
        return;
    }

    for (j = 0; j < count; j++) {
        netconn = (struct FtNetconn *)item[j]->netconn;
        if (netconn == FILLP_NULL_PTR) {
            FillpFreeBufItem(item[j]);
            continue;
        }

        fpcb = &(netconn->pcb->fpcb);
        HlistAddTail(&fpcb->send.unSendList, &item[j]->unsendNode);
        (void)FillpFrameAddItem(&fpcb->frameHandle, item[j]);
        FillpPcbSendFc(fpcb);
    }
}

static FILLP_BOOL SpungeDelay(struct SpungeInstance *inst, FILLP_LLONG curTime)
{
    FILLP_LLONG timePass = curTime - inst->curTime;

    FILLP_LLONG minSendInterval = (FILLP_LLONG)((FILLP_ULLONG)inst->minSendInterval >> FILLP_TIME_PRECISION);
    if ((timePass > minSendInterval) && (timePass > FILLP_MINIMUM_SELECT_TIME)) {
        minSendInterval = 0;
    } else if (minSendInterval < FILLP_MINIMUM_SELECT_TIME) {
        minSendInterval = FILLP_MINIMUM_SELECT_TIME;
    }

    if (SYS_ARCH_SEM_POST(&inst->threadSem)) {
        FILLP_LOGWAR("sem wait failed");
    }
    if (inst->pcbList.list.size > 0) {
        (void)SysioSelect((FILLP_INT)minSendInterval);
    } else {
        FILLP_SLEEP_MS((FILLP_UINT)FILLP_UTILS_US2MS(minSendInterval));
    }
    if (SYS_ARCH_SEM_WAIT(&inst->threadSem)) {
        FILLP_LOGWAR("sem wait failed");
    }
    return FILLP_TRUE;
}

static FILLP_BOOL SpungeMainDelay(struct SpungeInstance *inst)
{
    FILLP_BOOL isTimeout = FILLP_TRUE;
    FILLP_LLONG curTime = SYS_ARCH_GET_CUR_TIME_LONGLONG();

    if (g_resource.common.fullCpuEnable && (inst->stb.tbFpcbLists.size > 0)) {
        (void)SysioSelect(0);
        inst->curTime = curTime;
        return isTimeout;
    }

    if (curTime < inst->curTime) {
        FILLP_LOGERR("System Time has been changed to past value");
        return isTimeout;
    }
    isTimeout = SpungeDelay(inst, curTime);
    curTime = SYS_ARCH_GET_CUR_TIME_LONGLONG();
    if (curTime < inst->curTime) {
        FILLP_LOGERR("System Time has been changed to past value\r\n");
        return isTimeout;
    }

    inst->curTime = curTime;
    inst->minSendInterval = FILLP_MAX_SEND_INTERVAL;
    return isTimeout;
}

void FillpServerRecvRateAdjustment(struct SpungeInstance *inst, FILLP_UINT32 calcRecvTotalRate, FILLP_INT realRecvConn,
    FILLP_UINT32 *connRecvCalLimit)
{
    static FILLP_UINT8 recvStableState = 0;
    static FILLP_UINT32 prevRecvTotRate = 0;
    static const FILLP_UINT32 maxCalcRecvRate = 0;

    if ((calcRecvTotalRate > (RECV_RATE_PAR_LOW * prevRecvTotRate)) &&
        (calcRecvTotalRate < (RECV_RATE_PAT_HIGH * prevRecvTotRate))) {
        if (recvStableState < RECV_STATE_THRESHOLD) {
            recvStableState++;
        }
    } else {
        if (recvStableState > 0) {
            recvStableState--;
        }
    }

    prevRecvTotRate = calcRecvTotalRate;

    /* Give some space for every connection to grow, since if the network
    conditions are varying for every connection */
    /* If the sum of rate of all connections is less than the historical max
    recv rate, then allow to grow */
    if (recvStableState < FILLP_FC_STABLESTATE_VAL_2) {
        calcRecvTotalRate = (FILLP_UINT32)(calcRecvTotalRate * FILL_FC_SEND_RATE_TOTAL_1);
    } else if (calcRecvTotalRate < (maxCalcRecvRate * FILLP_FC_SEND_RATE_MULTIPLE_FACTOR)) {
        /* Give the enough room for the client to grow the bandwidth */
        calcRecvTotalRate = maxCalcRecvRate;
    } else {
        /* Give 5% room for connections to grow, so that it can achieve the max
            network goodput */
        calcRecvTotalRate = (FILLP_UINT32)(calcRecvTotalRate * FILL_FC_SEND_RATE_TOTAL_2);
    }

    /* If the sum of received rate of all the connections is more than the configured
    rate, then limit it to configured rate.
    Rate should not exceed the configured value */
    if (calcRecvTotalRate > inst->rateControl.recv.maxRate) {
        calcRecvTotalRate = inst->rateControl.recv.maxRate;
    }

    if (realRecvConn > 0) {
        *connRecvCalLimit = (FILLP_UINT32)((double)calcRecvTotalRate / realRecvConn);
    } else {
        /* If there are no connections which are active and connected, then set
        the rate limit for every connection to maximum limit */
        *connRecvCalLimit = inst->rateControl.recv.maxRate;
    }
    /* End of rate adjustment for Data receiving at server side */
}

void FillpServerSendRateAdjustment(struct SpungeInstance *inst, FILLP_UINT32 calcSendTotalRate, FILLP_INT realSendConn,
    FILLP_UINT32 *connSendCalLimit)
{
    static FILLP_UINT8 sendStableState = 0;
    static FILLP_UINT32 prevSendTotRate = 0;
    static const FILLP_UINT32 maxCalcSendRate = 0;

    if ((calcSendTotalRate > (FILLP_FC_PREV_ADJUSTMENT_RATE_LOW_VAL * prevSendTotRate)) &&
        (calcSendTotalRate < (FILLP_FC_PREV_ADJUSTMENT_RATE_HIGH_VAL * prevSendTotRate))) {
        if (sendStableState < FILLP_FC_STABLESTATE_VAL_1) {
            sendStableState++;
        }
    } else {
        if (sendStableState > 0) {
            sendStableState--;
        }
    }

    prevSendTotRate = calcSendTotalRate;

    /* Give some space for every connection to grow, since if the network
    conditions are varying for every connection */
    /* If the sum of rate of all connections is less than the historical max
    recv rate, then allow to grow */
    if (sendStableState < FILLP_FC_STABLESTATE_VAL_2) {
        calcSendTotalRate = (FILLP_UINT32)(calcSendTotalRate * FILL_FC_SEND_RATE_TOTAL_1);
    } else if (calcSendTotalRate < (maxCalcSendRate * FILLP_FC_SEND_RATE_MULTIPLE_FACTOR)) {
        calcSendTotalRate = maxCalcSendRate;
    } else {
        /* Give 5% room for connections to grow, so that it can achieve the max
            network goodput */
        calcSendTotalRate = (FILLP_UINT32)(calcSendTotalRate * FILL_FC_SEND_RATE_TOTAL_2);
    }

    /* If the sum of sending rate as acked by PACK for all the connections is
    more than the configured rate, then limit it to configured rate.
    Rate should not exceed the configured value */
    if (calcSendTotalRate > inst->rateControl.send.maxRate) {
        calcSendTotalRate = inst->rateControl.send.maxRate;
    }

    if (realSendConn > 0) {
        *connSendCalLimit = (FILLP_UINT32)((double)calcSendTotalRate / realSendConn);
    } else {
        /* If there are no connections which are active and connected, then set
        the rate limit for every connection to maximum limit */
        *connSendCalLimit = inst->rateControl.send.maxRate;
    }

    /* End of rate adjustment for Data receiving at server side */
}

void FillpCalculateFairness(struct SpungeInstance *inst)
{
    struct HlistNode *pcbNode = FILLP_NULL_PTR;
    struct SpungePcb *pcb = FILLP_NULL_PTR;
    FILLP_INT realSendConn = 0;
    FILLP_INT realRecvConn = 0;
    struct FtNetconn *conn = FILLP_NULL_PTR;
    FILLP_UINT8 connState;
    FILLP_UINT32 connRecvCalLimit;
    FILLP_UINT32 connSendCalLimit;
    FILLP_UINT32 calcRecvTotalRate = 0;
    FILLP_UINT32 calcSendTotalRate = 0;

    pcbNode = HLIST_FIRST(&inst->pcbList.list);
    while (pcbNode != FILLP_NULL_PTR) {
        pcb = SpungePcbListNodeEntry(pcbNode);
        pcbNode = pcbNode->next;
        conn = (struct FtNetconn *)pcb->conn;

        connState = NETCONN_GET_STATE(conn);
        if (connState > CONN_STATE_CONNECTED) {
            /* Connection state is greater than the connected state, so skip and continue */
            continue;
        }

        if (pcb->fpcb.statistics.pack.periodRecvRate > FILLP_DEFAULT_MIN_RATE) {
            realRecvConn++;
        }

        if (pcb->fpcb.statistics.pack.periodSendRate > FILLP_DEFAULT_MIN_RATE) {
            realSendConn++;
        }

        /* Calculate for Data receiving on server side */
        calcRecvTotalRate = calcRecvTotalRate + pcb->fpcb.statistics.pack.periodRecvRate;

        /* Calculate for Data sending from server side */
        calcSendTotalRate = calcSendTotalRate + pcb->fpcb.statistics.pack.periodAckByPackRate;
    }

    /* Calculation of rate adjustment for Data receiving at server side */
    FillpServerRecvRateAdjustment(inst, calcRecvTotalRate, realRecvConn, &connRecvCalLimit);

    /* Calculation of rate adjustment for Data Sending at server side */
    FillpServerSendRateAdjustment(inst, calcSendTotalRate, realSendConn, &connSendCalLimit);

    pcbNode = HLIST_FIRST(&inst->pcbList.list);
    while (pcbNode != FILLP_NULL_PTR) {
        pcb = SpungePcbListNodeEntry(pcbNode);
        pcbNode = pcbNode->next;

        /* The rate is set to all the connections irrespective of whether the
        connection is idle or not, so that, once the connection starts pumping
        the data, it will have enough window to start with.
        All this algorithm will adjust the rate of all the connections accordingly */
        pcb->rateControl.recv.curMaxRateLimitation = connRecvCalLimit;
        pcb->fpcb.recv.oppositeSetRate = pcb->rateControl.recv.curMaxRateLimitation;

        pcb->rateControl.send.curMaxRateLimitation = connSendCalLimit;
        pcb->fpcb.send.flowControl.sendRateLimit = pcb->rateControl.send.curMaxRateLimitation;
    }
}

FILLP_BOOL FillpKillCore(void)
{
    FILLP_UINT16 i;
    for (i = 0; i < SYS_ARCH_ATOMIC_READ(&g_spunge->sockTable->used); i++) {
        struct FtSocket *sock = g_spunge->sockTable->sockPool[i];

        if ((sock->allocState != SOCK_ALLOC_STATE_FREE)) {
            return FILLP_FALSE;
        }
    }

    return FILLP_TRUE;
}

void FillpCheckPcbNackListToSend(void *args)
{
    struct SpungePcb *pcb = ((struct FillpPcb *)args)->spcb;
    struct Hlist *nackList = FILLP_NULL_PTR;
    FILLP_LLONG curTime;
    struct HlistNode *node = FILLP_NULL_PTR;
    struct HlistNode *tmp = FILLP_NULL_PTR;

    if (pcb == FILLP_NULL_PTR) {
        FILLP_LOGERR("spunge_pcb is NULL");
        return;
    }

    nackList = &(pcb->fpcb.recv.nackList);
    if (nackList->size == 0) {
        return;
    }

    curTime = SYS_ARCH_GET_CUR_TIME_LONGLONG();
    node = HLIST_FIRST(nackList);
    while (node != FILLP_NULL_PTR) {
        struct FillpNackNode *nackNode = FillpNackNodeEntry(node);
        FILLP_LLONG timestamp = nackNode->timestamp;
        /*
        Commenting the timeout check again here, since the timing wheel
        will ensure that the time has elapsed before invoking this timeout
        function
        */
        if (curTime > timestamp) {
            FILLP_UINT32 startPktNum = nackNode->startPktNum;
            FILLP_UINT32 endPktNum = nackNode->endPktNum;
            FillpSendNack(&(pcb->fpcb), startPktNum, endPktNum);
            tmp = node;
            node = node->next;
            HlistDelete(nackList, tmp);
            SpungeFree(nackNode, SPUNGE_ALLOC_TYPE_CALLOC);
            nackNode = FILLP_NULL_PTR;
        } else {
            break;
        }
    }

    /* if all the delay NACKs are sent out, then stop the timer */
    if (nackList->size > 0) {
        FillpEnableDelayNackTimer((struct FillpPcb *)args);
    }
}

void SpinstLoopMacTimerChecker(void *p)
{
    struct SpungeInstance *inst = (struct SpungeInstance *)p;
    /* Check server cookie Refresh */
    /* Duration is put as 30minutes, 1 Minute = 60,000 Milliseconds
     */
    if (((inst->curTime - (FILLP_LLONG)inst->macInfo.switchOverTime) > FILLP_KEY_REFRESH_TIME)) {
        FillpMacTimerExpire(&inst->macInfo, inst->curTime);
    }
    if (!FILLP_TIMING_WHEEL_IS_NODE_ENABLED(&inst->macTimerNode)) {
        FillpTimingWheelAddTimer(&inst->timingWheel, (SYS_ARCH_GET_CUR_TIME_LONGLONG() + inst->macTimerNode.interval),
            &inst->macTimerNode);
    }
}

void SpinstLoopFairnessChecker(void *p)
{
    struct SpungeInstance *inst = (struct SpungeInstance *)p;

    if ((g_resource.flowControl.supportFairness == FILLP_FAIRNESS_TYPE_EQUAL_WEIGHT) &&
        (inst->rateControl.connectionNum > 0)) {
        inst->rateControl.lastControlTime = inst->curTime;
        FillpCalculateFairness(inst);
    }

    if (!FILLP_TIMING_WHEEL_IS_NODE_ENABLED(&inst->fairTimerNode)) {
        FillpTimingWheelAddTimer(&inst->timingWheel, (SYS_ARCH_GET_CUR_TIME_LONGLONG() + inst->fairTimerNode.interval),
            &inst->fairTimerNode);
    }
}

void SpungeEnableTokenTimer(struct SpungeTokenBucke *stb)
{
    if (!FILLP_TIMING_WHEEL_IS_NODE_ENABLED(&stb->tockenTimerNode)) {
        FillpTimingWheelAddTimer(&stb->inst->timingWheel, stb->tockenTimerNode.interval + stb->inst->curTime,
            &stb->tockenTimerNode);
    }
}

void SpungeDisableTokenTimer(struct SpungeTokenBucke *stb)
{
    if (FILLP_TIMING_WHEEL_IS_NODE_ENABLED(&stb->tockenTimerNode)) {
        FillpTimingWheelDelTimer(stb->tockenTimerNode.wheel, &stb->tockenTimerNode);
    }
}

void SpungeTokenTimerCb(void *p)
{
    struct SpungeTokenBucke *stb = (struct SpungeTokenBucke *)p;
    struct SpungeInstance *inst = (struct SpungeInstance *)stb->inst;
    FILLP_ULLONG bitAdded;
    FILLP_UINT32 tokens;

    if (stb->rate != g_resource.flowControl.limitRate) {
        FILLP_UINT32 rate_bck = stb->rate;
        stb->rate = g_resource.flowControl.limitRate;
        stb->tokenCount = 0;

        if (stb->rate != 0) {
            stb->tockenTimerNode.interval = (FILLP_UINT32)(
                ((FILLP_ULLONG)stb->maxPktSize * (FILLP_ULLONG)FILLP_FC_IN_KBPS) / (FILLP_ULLONG)stb->rate);
            if (stb->tockenTimerNode.interval > SPUNGE_TOKEN_TIMER_MAX_INTERVAL) {
                stb->tockenTimerNode.interval = SPUNGE_TOKEN_TIMER_MAX_INTERVAL;
            }
        } else {
            stb->tockenTimerNode.interval = SPUNGE_TOKEN_TIMER_MAX_INTERVAL_RATE_ZERO;
        }

        FILLP_LOGINF("limite rate change from:%u to:%u, timer_interval:%u, maxPktSize:%u", rate_bck, stb->rate,
            stb->tockenTimerNode.interval, stb->maxPktSize);
    }

    bitAdded = (FILLP_ULLONG)(inst->curTime - stb->lastTime) * (FILLP_ULLONG)stb->rate;
    stb->lastTime = inst->curTime;
    tokens = (FILLP_UINT32)((bitAdded / (FILLP_ULLONG)FILLP_BPS_TO_KBPS) >> BIT_MOVE_CNT);
    if ((tokens < stb->maxPktSize) || (stb->tokenCount < stb->maxPktSize)) {
        stb->tokenCount += tokens;
    } else {
        stb->tokenCount = tokens;
    }

    if (stb->tockenTimerNode.interval != SPUNGE_TOKEN_TIMER_MAX_INTERVAL_RATE_ZERO) {
        SpungeEnableTokenTimer(stb);
    }
}

FILLP_INT SpungeItemRouteByToken(struct FillpPcbItem *item, struct FillpPcb *fpcb)
{
    struct SpungeTokenBucke *stb;
    FILLP_INT ret = ERR_OK;

    stb = &fpcb->pcbInst->stb;

    if (stb->tockenTimerNode.interval == SPUNGE_TOKEN_TIMER_MAX_INTERVAL_RATE_ZERO) {
        SpungeTokenTimerCb(stb);
    }
    if ((stb->rate == 0) && (fpcb->send.itemWaitTokenLists.nodeNum == 0)) { /* no limit or limit -> nolimit */
        ret = FillpSendItem(item, fpcb);
    } else if ((stb->tokenCount >= (FILLP_UINT32)item->dataLen) && (fpcb->send.itemWaitTokenLists.nodeNum == 0)) {
        ret = FillpSendItem(item, fpcb);
        if (ret == ERR_OK) {
            stb->tokenCount -= (FILLP_UINT32)item->dataLen;
        }
    } else {
        if (SkipListInsert(&fpcb->send.itemWaitTokenLists, (void *)item, &item->skipListNode, FILLP_TRUE) != ERR_OK) {
            /* this can't be happen */
            FILLP_LOGERR("fillp_sock_id:%d Can't add item <%u,%u> to itemWaitTokenLists", FILLP_GET_SOCKET(fpcb)->index,
                item->seqNum, item->dataLen);
            FillpFreeBufItem(item);
            (void)SYS_ARCH_ATOMIC_INC(&(FILLP_GET_SOCKET(fpcb)->sendEventCount), 1);
#ifdef SOCK_SEND_SEM
            (void)SYS_ARCH_SEM_POST(&fpcb->send.sendSem);
#endif /* SOCK_SEND_SEM */
        } else {
            stb->waitPktCount++;
        }
    }

    return ret;
}

static void SpungeClearItemWaitTokenList(struct SpungeTokenBucke *stb)
{
    struct HlistNode *fpcbNode = HLIST_FIRST(&(stb->tbFpcbLists));
    struct FillpPcb *fpcb = FILLP_NULL_PTR;
    struct FillpPcbItem *item = FILLP_NULL_PTR;

    while (fpcbNode != FILLP_NULL_PTR) {
        fpcb = FillpPcbStbNodeEntry(fpcbNode);
        fpcbNode = fpcbNode->next;
        item = (struct FillpPcbItem *)SkipListPopValue(&(fpcb->send.itemWaitTokenLists));
        while (item != FILLP_NULL_PTR) {
            stb->waitPktCount--;
            /* here item should move to unrecvList, not directly send by udp,
               or the sendrate may be over the max send rate */
            if (SkipListInsert(&fpcb->send.unrecvList, (void *)item, &item->skipListNode, FILLP_TRUE) != ERR_OK) {
                FillpFreeBufItem(item);
                (void)SYS_ARCH_ATOMIC_INC(&(FILLP_GET_SOCKET(fpcb)->sendEventCount), 1);
#ifdef SOCK_SEND_SEM
                (void)SYS_ARCH_SEM_POST(&fpcb->send.sendSem);
#endif /* SOCK_SEND_SEM */
            } else if (item->sendCount > 0) {
                fpcb->send.unrecvRedunListBytes += item->dataLen;
            }
            item = (struct FillpPcbItem *)SkipListPopValue(&(fpcb->send.itemWaitTokenLists));
        }

        if (fpcb->send.unrecvList.nodeNum != 0) {
            FillpEnableSendTimer(fpcb);
        }
    }

    if (stb->waitPktCount != 0) {
        FILLP_LOGERR("waitPktCount %llu is not 0", stb->waitPktCount);
        stb->waitPktCount = 0;
    }
    stb->fpcbCur = HLIST_FIRST(&(stb->tbFpcbLists));
}

void SpungeCheckItemWaitTokenList(struct SpungeTokenBucke *stb)
{
    struct HlistNode *fpcbNode = FILLP_NULL_PTR;
    struct SkipListNode *node = FILLP_NULL_PTR;
    struct FillpPcb *fpcb = FILLP_NULL_PTR;
    struct FillpPcbItem *item = FILLP_NULL_PTR;
    FILLP_UINT32 fpcbCount = (FILLP_UINT32)stb->tbFpcbLists.size;
    FILLP_UINT32 waitListEmptyCount = 0;
    FILLP_INT err;

    if (stb->waitPktCount == 0) {
        return;
    }

    /* stb->rate change from !0 to 0, need to move all item form  itemWaitTokenLists to unSendList */
    if (stb->rate == 0) {
        SpungeClearItemWaitTokenList(stb);
        return;
    }

    fpcbNode = stb->fpcbCur;
    while ((stb->tokenCount > 0) && (stb->waitPktCount > 0) && (waitListEmptyCount < fpcbCount)) {
        if (fpcbNode == FILLP_NULL_PTR) {
            fpcbNode = HLIST_FIRST(&(stb->tbFpcbLists));
        }

        fpcb = FillpPcbStbNodeEntry(fpcbNode);
        node = SkipListGetPop(&(fpcb->send.itemWaitTokenLists));
        if (node == FILLP_NULL_PTR) {
            fpcbNode = fpcbNode->next;
            waitListEmptyCount++;
            continue;
        }

        item = (struct FillpPcbItem *)node->item;
        if (stb->tokenCount < item->dataLen) {
            break;
        }

        stb->waitPktCount--;
        (void)SkipListPopValue(&fpcb->send.itemWaitTokenLists);
        err = FillpSendItem(item, fpcb);
        if (err == ERR_OK) {
            stb->tokenCount -= (FILLP_UINT32)item->dataLen;
        }
        fpcbNode = fpcbNode->next;
        waitListEmptyCount = 0;
    }

    stb->fpcbCur = fpcbNode;
}

void SpungeInitTokenBucket(struct SpungeInstance *inst)
{
    struct SpungeTokenBucke *stb = &inst->stb;

    stb->inst = inst;
    stb->lastTime = inst->curTime;
    stb->rate = g_resource.flowControl.limitRate;
    stb->waitPktCount = 0;
    stb->tokenCount = 0;
    stb->maxPktSize = (FILLP_UINT32)g_appResource.flowControl.pktSize;

    stb->fpcbCur = FILLP_NULL_PTR;
    HLIST_INIT(&(stb->tbFpcbLists));

    FILLP_TIMING_WHEEL_INIT_NODE(&stb->tockenTimerNode);
    stb->tockenTimerNode.cbNode.cb = SpungeTokenTimerCb;
    stb->tockenTimerNode.cbNode.arg = (void *)stb;
    if (stb->rate != 0) {
        stb->tockenTimerNode.interval =
            (FILLP_UINT32)(((FILLP_ULLONG)stb->maxPktSize * (FILLP_ULLONG)FILLP_FC_IN_KBPS) / (FILLP_ULLONG)stb->rate);
        if (stb->tockenTimerNode.interval > SPUNGE_TOKEN_TIMER_MAX_INTERVAL) {
            stb->tockenTimerNode.interval = SPUNGE_TOKEN_TIMER_MAX_INTERVAL;
        }
    } else {
        stb->tockenTimerNode.interval = SPUNGE_TOKEN_TIMER_MAX_INTERVAL_RATE_ZERO;
    }

    FILLP_LOGINF("limite rate:%u, timer_interval:%u, maxPktSize:%u", stb->rate, stb->tockenTimerNode.interval,
        stb->maxPktSize);
    SpungeEnableTokenTimer(stb);
}

void SpungeTokenBucketAddFpcb(struct FillpPcb *fpcb)
{
    struct SpungeTokenBucke *stb = FILLP_NULL_PTR;

    if ((fpcb == FILLP_NULL_PTR) || (fpcb->pcbInst == FILLP_NULL_PTR)) {
        return;
    }

    stb = &fpcb->pcbInst->stb;
    if (stb->maxPktSize < (FILLP_UINT32)fpcb->pktSize) {
        stb->maxPktSize = (FILLP_UINT32)fpcb->pktSize;
    }

    HLIST_INIT_NODE(&(fpcb->stbNode));
    HlistAddTail(&stb->tbFpcbLists, &(fpcb->stbNode));
    FILLP_LOGINF("fillp_sock_id:%d, maxPktSize:%u,"
        "limitRate:%u",
        FILLP_GET_SOCKET(fpcb)->index, stb->maxPktSize, stb->rate);
}

void SpungeTokenBucketDelFpcb(struct FillpPcb *fpcb)
{
    struct HlistNode *node = FILLP_NULL_PTR;
    struct SpungeTokenBucke *stb = FILLP_NULL_PTR;

    if ((fpcb == FILLP_NULL_PTR) || (fpcb->pcbInst == FILLP_NULL_PTR)) {
        return;
    }

    stb = &fpcb->pcbInst->stb;
    if ((stb->fpcbCur != FILLP_NULL_PTR) && (stb->fpcbCur == &(fpcb->stbNode))) {
        stb->fpcbCur = stb->fpcbCur->next;
    }

    node = HLIST_FIRST(&(stb->tbFpcbLists));
    while (node != FILLP_NULL_PTR) {
        if (&(fpcb->stbNode) == node) {
            stb->waitPktCount -= (FILLP_ULLONG)fpcb->send.itemWaitTokenLists.nodeNum;
            HlistDelete(&(stb->tbFpcbLists), node);
            FILLP_LOGINF("fillp_sock_id:%d, limitRate:%u", FILLP_GET_SOCKET(fpcb)->index, stb->rate);
            break;
        }
        node = node->next;
    }
}

/* Return 1 if still alive , or return 0 */
static int SpinstLoopCheckAlive(struct SpungeInstance *inst)
{
    if (inst->waitTobeCoreKilled && FillpKillCore()) {
        inst->waitTobeCoreKilled = FILLP_FALSE;
        return 0;
    }

    return 1;
}

static void SpinstLoopRecv(struct SpungeInstance *inst)
{
    struct HlistNode *osSockNode;
    int readable = 1;
    osSockNode = HLIST_FIRST(&inst->osSockist);
    /* Select doesn't work with sendmmsg/recvmmsg, so in that case it is always
    set as 1 */
    while (osSockNode != FILLP_NULL_PTR) {
        struct SockOsSocket *osSock = SockOsListEntry(osSockNode);
        if (!g_resource.udp.supportMmsg) {
            readable = SysioIsSockReadable((void *)osSock->ioSock);
        }
        osSockNode = osSockNode->next;

        if (readable) {
            SpungeDoRecvCycle(osSock, inst);
        }
    }
}

#if !defined(FILLP_LW_LITEOS)
static void SpungeSetThreadInfo(FILLP_CONST struct SpungeInstance *inst)
{
    FILLP_CHAR threadName[SPUNGE_MAX_THREAD_NAME_LENGTH] = {0};
    FILLP_UINT8 random = (FILLP_UINT8)(FILLP_RAND() & 0xFF);
    (void)inst;
    FILLP_INT ret = sprintf_s(threadName, sizeof(threadName), "%s_%u", "Fillp_core", (FILLP_UINT)random);
    if (ret < ERR_OK) {
        FILLP_LOGWAR("SpungeInstanceMainThread sprintf_s thread name failed(%d), random(%u)", ret, random);
    }
    (void)SysSetThreadName(threadName, sizeof(threadName));

#if defined(FILLP_LINUX)
    {
        pthread_t self;
        self = pthread_self();
        FILLP_LOGINF("FillP Core threadId:%ld", self);
        /* thread resource will be auto recycled
           only this detach set if no other thread try to join it */
        if (pthread_detach(self)) {
            FILLP_LOGERR("Set Detach fail");
        }
    }
#elif defined(FILLP_WIN32)
    FILLP_LOGBUTT("FillP Core threadId:%d", GetCurrentThreadId());
#endif
}
#endif

void SpungeInstanceMainThread(void *p)
{
    struct SpungeInstance *inst = FILLP_NULL_PTR;
    FILLP_BOOL isTimeout;

    if (p == FILLP_NULL_PTR) {
        FILLP_LOGERR("parameter p is NULL");
        return;
    }

    inst = (struct SpungeInstance *)p;
#if !defined(FILLP_LW_LITEOS)
    SpungeSetThreadInfo(inst);
#endif

    if (SYS_ARCH_SEM_WAIT(&inst->threadSem)) {
        FILLP_LOGWAR("sem wait failed");
        return;
    }
    while (inst->hasInited) {
        SpungeHandleMsgCycle(inst);
        SpungeLoopCheckUnsendBox(inst);
        if (!SpinstLoopCheckAlive(inst)) {
            break;
        }
        isTimeout = SpungeMainDelay(inst);
        SpinstLoopRecv(inst);

        if (isTimeout == FILLP_TRUE) {
            FillpTimingWheelLoopCheck(&inst->timingWheel, inst->curTime);
        }

        SpungeCheckItemWaitTokenList(&inst->stb);
    }

    SpungeDestroyInstance(inst);
}

void SpungePushRecvdDataToStack(void *arg)
{
    struct FillpPcb *pcb = (struct FillpPcb *)arg;
    struct FillpPcbItem *item = SkipListPopValue(&pcb->recv.recvBoxPlaceInOrder);
    while (item != FILLP_NULL_PTR) {
        FillpDataToStack(pcb, item);
        item = SkipListPopValue(&pcb->recv.recvBoxPlaceInOrder);
    }

    FillpEnableDataBurstTimer(pcb);
}

#ifdef __cplusplus
}
#endif
