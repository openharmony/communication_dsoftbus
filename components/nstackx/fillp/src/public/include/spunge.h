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

#ifndef SPUNGE_H
#define SPUNGE_H
#include "sockets.h"
#include "lf_ring.h"
#include "queue.h"
#include "hlist.h"
#include "log.h"
#include "dympool.h"
#include "fillp_cookie.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UDP_HASH_TABLE_SIZE 128

#define FILLP_ETH_DEVICE_SIZE 16

#define FILLP_MAC_ADDRESS_SIZE 6

#define FILLP_INST_UNSEND_BOX_NUM 1

#define FILLP_INST_WIFI_INFO_NUM 4

#define FILLP_EPOLL_ITEM_INIT_NUM 5
#define FILLP_MSG_ITEM_INIT_NUM 10
#define FILLP_CONN_ITEM_INIT_NUM 5

struct SpungeResConf {
    FILLP_UINT maxInstNum;
    FILLP_UINT maxSockNum;
    FILLP_UINT maxTimerItemNum;
    FILLP_UINT maxMsgItemNum;
    FILLP_UINT maxConnNum;
    FILLP_UINT maxEpollItemNum;
    FILLP_UINT maxEpollEventNum;
};

struct SpungePcbList {
    struct Hlist list;
};

struct SpungePcbRes {
    struct SpungePcbList list;
};

struct SpungePcbhashbucket {
    struct Hlist list;
};

struct SpungeServerRateControlItem {
    FILLP_INT totalWeight;
    FILLP_UINT32 maxRate;
};

struct SpungeServerRateControl {
    FILLP_LLONG lastControlTime;
    FILLP_INT connectionNum;
    FILLP_CHAR pad[4];
    struct SpungeServerRateControlItem send;
    struct SpungeServerRateControlItem recv;
};

struct SpungeTokenBucke {
    FILLP_LLONG lastTime;
    FILLP_UINT32 rate;         /* kpbs */
    FILLP_UINT32 tokenCount;   /* bytes */
    FILLP_UINT32 maxPktSize;   /* bytes */
    FILLP_ULLONG waitPktCount; /* pkt */
    struct Hlist tbFpcbLists;
    struct HlistNode *fpcbCur;
    struct SpungeInstance *inst;
    struct FillpTimingWheelTimerNode tockenTimerNode;
};

struct SpungeInstance {
    FILLP_LLONG curTime;
    FILLP_LLONG minSendInterval;
    FillpQueue *msgBox;
    DympoolType *msgPool;
    struct ThreadParam mainThreadParam;
    struct SpungePcbList pcbList; /* Recrd all connections */
    struct Hlist osSockist;
    struct SpungeServerRateControl rateControl;
    struct FillpTimingWheel timingWheel;
    FillpQueue *unsendBox[FILLP_INST_UNSEND_BOX_NUM];
    SYS_ARCH_SEM threadSem;     /* Used when do send */
    FILLP_BOOL thresdSemInited;
    struct FillpPcbItem **unsendItem;
    struct Hlist sendPcbList;

    FILLP_INT instIndex;
    FILLP_UINT netMask;
    FILLP_BOOL hasInited;
    FILLP_BOOL waitTobeCoreKilled;
    FILLP_UINT8 srcMac[FILLP_MAC_ADDRESS_SIZE];
    FILLP_UINT8 destMac[FILLP_MAC_ADDRESS_SIZE];
    FILLP_UINT8 cleanseDataCtr;
    FILLP_UINT8 pad[1];

    FillpMacInfo macInfo;

    struct FillpTimingWheelTimerNode macTimerNode;
    struct FillpTimingWheelTimerNode fairTimerNode;
    FILLP_CHAR *tmpBuf[FILLP_VLEN];
    struct SpungePcb tempSpcb;
    struct SpungeTokenBucke stb;
    SysArchAtomic msgUsingCount;
};

void SpinstAddToPcbList(struct SpungeInstance *inst, struct HlistNode *node);
void SpinstDeleteFromPcbList(struct SpungeInstance *inst, struct HlistNode *node);

struct Spunge {
    struct SpungeResConf resConf;
    FILLP_UINT insNum;
    FILLP_BOOL hasInited;
    FILLP_BOOL hasDeinitBlked;
    FILLP_UINT8 traceFlag;
    FILLP_UINT8 pad;
    void *traceHandle;
    struct FtSocketTable *sockTable; /* alloc socket source */
    DympoolType *netPool;

    DympoolType *epitemPool;    /* epitem */
    DympoolType *eventpollPool; /* eventpoll */

    struct SpungeInstance *instPool;
};

extern struct Spunge *g_spunge;
#define SPUNGE_GET_CUR_INSTANCE() (&g_spunge->instPool[0])

#ifdef FILLP_LINUX
extern FILLP_CHAR *g_ethdevice;
#endif
#define SPUNGE_STACK_VALID (g_spunge && g_spunge->hasInited)

void SpungeEpollEventCallback(struct FtSocket *sock, FILLP_INT event, FILLP_INT count);
void SpungeEpollAppRecvOne(struct FtSocket *sock);

void SockSetOsSocket(struct FtSocket *ftSock, struct SockOsSocket *osSock);

#ifdef __cplusplus
}
#endif

#endif