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

#ifndef FILLP_FRAME_H
#define FILLP_FRAME_H

#include "hlist.h"
#include "fillptypes.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FILLP_FRAME_IS_VIDEO(_type) ((_type) == VIDEO_I || (_type) == VIDEO_P)

#pragma pack(1)
struct FillpFrameDataOption {
    FILLP_UINT8 frameType;
    FILLP_UINT8 level;
    FILLP_UINT16 seqNum;
    FILLP_UINT8 subSeqNum;
    FILLP_UINT8 bitMap;
    FILLP_UINT32 fragSize; /* the size of the fragment to which the pkt belongs */
    FILLP_UINT32 txTimestamp; /* tx timestamp of the frame in struct FrameInfo */
};
#pragma pack()

struct FillpFrag {
    FILLP_UINT32 size; /* size of the fragment */
    FILLP_UINT32 procSize; /* current size of received data of this fragment,
                              procSize == size means the slice is completed */
    FILLP_UINT32 seqNum; /* fragment sequence number of the frame */
};

struct FillpFrameInfo {
    FILLP_UINT32 seqNum;
    FILLP_INT type; /* frame type, I or P */
    FILLP_UINT32 size; /* frame size */
    FILLP_UINT32 fragCnt; /* fragment count of the frame */
    FILLP_UINT32 totalItemCnt; /* packet count of the frame */
    FILLP_UINT32 txTimestamp; /* tx timestamp of the frame in struct FrameInfo */
    FILLP_LLONG firstPktRxTime; /* rx time of the first pkt of the frame */
    FILLP_LLONG lastPktRxTime; /* rx time of the last pkt of the frame */
};

struct FillpFrame {
    struct FillpFrameInfo info;
    struct FillpFrag curFrag;
    FILLP_BOOL rxStarted; /* first pkt of the first fragment has been received */
    FILLP_BOOL lastFragRecvd; /* the last fragment has been received */
};

typedef void (*FillpFrameRxCompleteCb)(void *cbArg, FILLP_CONST struct FillpFrameInfo *rxInfo);

struct FillpFrameStats {
    FILLP_UINT32 iFrameCount;
    FILLP_ULLONG iFrameTotalSize;

    FILLP_UINT32 pFrameCount;
    FILLP_ULLONG pFrameTotalSize;
};

struct FillpFrameHandle {
    FillpFrameRxCompleteCb rxCb;
    void *rxCbArg;

    struct FillpFrame curFrame; /* for sending, store the frame from uplayer,
                                 * used to recognize the boundary of the frame.
                                 * warning: should be only accessed in the FtSendFrame */

    struct FillpFrameStats stats;
};

struct FillpPcbItem;

/* frame info shared by all the items in same frame fragment */
struct FillpFrameItem {
    struct FrameInfo info;
    FILLP_UINT32 fragSize; /* size of the fragment the item belongs to */
    SysArchAtomic refCnt;
};

static inline void FillpFrameSetRxCb(struct FillpFrameHandle *h,
    FillpFrameRxCompleteCb cb, void *cbArg)
{
    if (h != FILLP_NULL_PTR) {
        h->rxCb = cb;
        h->rxCbArg = cbArg;
    }
}

void FillpFrameInit(struct FillpFrameHandle *h);
void FillpFrameFreeItem(struct FillpPcbItem *item);
FILLP_INT FillpFrameAddItem(struct FillpFrameHandle *h, struct FillpPcbItem *item);
void FillpFrameItemPut(struct FillpFrameItem *frameItem);
struct FillpFrameItem *FillpFrameItemAlloc(FILLP_CONST struct FrameInfo *frame);
void FillpFrameItemReference(struct FillpPcbItem *item, struct FillpFrameItem *frameItem);
void FillpFrameTxInitItem(struct FillpFrameHandle *h, struct FillpPcbItem *item,
    const struct FrameInfo *info, FILLP_UINT32 sliceSize, FILLP_BOOL firstPkt);
FILLP_UINT32 FillpFrameGetPktDataOptLen(FILLP_UINT32 flag, FILLP_UINT32 pktDataOptLen);
FILLP_UINT16 FillpFrameBuildOption(const struct FillpPcbItem *item, FILLP_UINT8 *option);
FILLP_INT FillpFrameParseOption(struct FillpFrameHandle *h,
    struct FillpPcbItem *item, FILLP_UINT8 *option, FILLP_UINT8 optLen);
void FillpFrameRx(struct FillpFrameHandle *h, const struct FillpPcbItem *item);

#ifdef __cplusplus
}
#endif

#endif /* FILLP_FRAME_H */
