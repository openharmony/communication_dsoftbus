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

#include "fillp_frame.h"
#include "fillp_common.h"

#define FRAME_VIDEO_FRAME_TYPE_STR(_type) (((_type) == VIDEO_I) ? "I" : "P")

#ifdef __cplusplus
extern "C" {
#endif

void FillpFrameInit(struct FillpFrameHandle *h)
{
    if (h != FILLP_NULL_PTR) {
        (void)memset_s(h, sizeof(struct FillpFrameHandle), 0, sizeof(struct FillpFrameHandle));
    }
}

static inline void FillpFrameItemHold(struct FillpFrameItem *frameItem)
{
    FILLP_INT refCnt = SYS_ARCH_ATOMIC_INC(&frameItem->refCnt, 1);
    FILLP_LOGDBG("item refcnt: %d, seq: %d", refCnt, frameItem->info.seqNum);
}

void FillpFrameItemPut(struct FillpFrameItem *frameItem)
{
    if (frameItem != FILLP_NULL_PTR) {
        if (SYS_ARCH_ATOMIC_DEC_AND_TEST(&frameItem->refCnt)) {
            FILLP_LOGDBG("free frame item of seq: %d", frameItem->info.seqNum);
            SpungeFree(frameItem, SPUNGE_ALLOC_TYPE_CALLOC);
        }
    }
}

struct FillpFrameItem *FillpFrameItemAlloc(FILLP_CONST struct FrameInfo *frame)
{
    struct FillpFrameItem *frameItem = FILLP_NULL_PTR;

    if (frame != FILLP_NULL_PTR) {
        frameItem = SpungeAlloc(1, sizeof(struct FillpFrameItem), SPUNGE_ALLOC_TYPE_CALLOC);
        if (frameItem == FILLP_NULL_PTR) {
            FILLP_LOGERR("alloc frame item failed, seq: %d", frame->seqNum);
        } else {
            frameItem->info = *frame;
            /* hold the frame item until the sending of socket app ended */
            FillpFrameItemHold(frameItem);
            FILLP_LOGDBG("alloc frame item succeeded, seq: %d", frame->seqNum);
        }
    }

    return frameItem;
}

void FillpFrameItemReference(struct FillpPcbItem *item, struct FillpFrameItem *frameItem)
{
    if (frameItem != FILLP_NULL_PTR) {
        FillpFrameItemHold(frameItem);
        item->frame = frameItem;
    } else {
        item->frame = FILLP_NULL_PTR;
    }
}

static void FillpFrameAddItemStats(struct FillpFrameHandle *h, FILLP_INT frameType,
    FILLP_UINT32 size, FILLP_BOOL newFrame)
{
    if (frameType == VIDEO_I) {
        if (newFrame) {
            h->stats.iFrameCount++;
        }
        h->stats.iFrameTotalSize += size;
    } else {
        if (newFrame) {
            h->stats.pFrameCount++;
        }
        h->stats.pFrameTotalSize += size;
    }
}

FILLP_INT FillpFrameAddItem(struct FillpFrameHandle *h, struct FillpPcbItem *item)
{
    struct FrameInfo *info = FILLP_NULL_PTR;

    if (item->frame == FILLP_NULL_PTR || !FILLP_FRAME_IS_VIDEO(item->frame->info.frameType)) {
        return NONE;
    }

    info = &item->frame->info;

    if (UTILS_FLAGS_CHECK(item->flags, FILLP_ITEM_FLAGS_FIRST_PKT)) {
        FillpFrameAddItemStats(h, info->frameType, item->frame->fragSize,
            UTILS_FLAGS_CHECK(item->flags, FILLP_ITEM_FLAGS_FRAME_FIRST_FRAG_START));
    }

    /* check FRAME_FLAGS_FIRST_FRAG_START after FRAME_FLAGS_FIRST_FRAG_PKT to statistics the fragment */
    if (!UTILS_FLAGS_CHECK(item->flags, FILLP_ITEM_FLAGS_FRAME_FIRST_FRAG_START)) {
        return NONE;
    }

    return info->frameType;
}

void FillpFrameFreeItem(struct FillpPcbItem *item)
{
    FillpFrameItemPut(item->frame);
    item->frame = FILLP_NULL_PTR;
}

void FillpFrameTxInitItem(struct FillpFrameHandle *h, struct FillpPcbItem *item,
    const struct FrameInfo *info, FILLP_UINT32 fragSize, FILLP_BOOL firstPkt)
{
    if (item->frame != FILLP_NULL_PTR && info != FILLP_NULL_PTR && FILLP_FRAME_IS_VIDEO(info->frameType)) {
        item->frame->fragSize = fragSize;

        if (firstPkt) {
            if (h->curFrame.info.size == 0 || (FILLP_UINT32)info->seqNum != h->curFrame.info.seqNum) {
                FILLP_LOGDBG("start sending a new frame, seq: %d", info->seqNum);
                UTILS_FLAGS_SET(item->flags, FILLP_ITEM_FLAGS_FRAME_FIRST_FRAG_START);
                h->curFrame.info.type = info->frameType;
                h->curFrame.info.seqNum = (FILLP_UINT32)info->seqNum;
                h->curFrame.info.size = fragSize;
                h->curFrame.info.fragCnt = 1;
            } else {
                h->curFrame.info.size += fragSize;
                h->curFrame.info.fragCnt++;
            }

            if (UTILS_FLAGS_CHECK(info->bitMap, FRAME_INFO_BITMAP_FRAME_END)) {
                UTILS_FLAGS_SET(item->flags, FILLP_ITEM_FLAGS_FRAME_LAST_FRAG_START);
                FILLP_LOGDBG("frame %d end, total size: %u", info->seqNum, h->curFrame.info.size);
            }

            UTILS_FLAGS_SET(item->dataOptFlag, FILLP_OPT_FLAG_FRAME_INFO);
            FILLP_LOGDBG("set the first pkt flag of seq: %d, seqNo %d", info->seqNum, info->subSeqNum);
        }
    }
}

FILLP_UINT32 FillpFrameGetPktDataOptLen(FILLP_UINT32 flag, FILLP_UINT32 pktDataOptLen)
{
    FILLP_UINT32 optLen = pktDataOptLen;
    if (UTILS_FLAGS_CHECK(flag, FILLP_OPT_FLAG_FRAME_INFO)) {
        optLen = UTILS_MAX(pktDataOptLen, FILLP_DATA_OFFSET_LEN);
        optLen += FILLP_OPT_FRAME_INFO_LEN + FILLP_DATA_OPT_HLEN;
    }

    return optLen;
}

FILLP_UINT16 FillpFrameBuildOption(const struct FillpPcbItem *item, FILLP_UINT8 *option)
{
    const struct FrameInfo *info = FILLP_NULL_PTR;
    FillpDataOption *dataOpt = FILLP_NULL_PTR;
    struct FillpFrameDataOption *frameOpt = FILLP_NULL_PTR;

    info = &item->frame->info;
    dataOpt = (FillpDataOption *)option;
    dataOpt->type = FILLP_OPT_FRAME_INFO;
    dataOpt->len = FILLP_OPT_FRAME_INFO_LEN;

    frameOpt = (struct FillpFrameDataOption *)&dataOpt->value[0];
    frameOpt->frameType = (FILLP_UINT8)info->frameType;
    frameOpt->level = (FILLP_UINT8)info->level;
    frameOpt->seqNum = FILLP_HTONS((FILLP_UINT16)info->seqNum);
    frameOpt->subSeqNum = (FILLP_UINT8)info->subSeqNum;
    frameOpt->bitMap = (FILLP_UINT8)(item->flags & FILLP_ITEM_FLAGS_FRAME_OPT_BITMAP_MASK);
    frameOpt->fragSize = FILLP_HTONL(item->frame->fragSize);
    frameOpt->txTimestamp = FILLP_HTONL((FILLP_UINT32)info->timestamp);

    FILLP_LOGDTL("fill option of frame %s, seq: %d, seqNo: %d, bitmap: 0x%x",
        FRAME_VIDEO_FRAME_TYPE_STR(info->frameType), info->seqNum, info->subSeqNum, frameOpt->bitMap);

    return (FILLP_UINT16)(FILLP_DATA_OPT_HLEN + FILLP_OPT_FRAME_INFO_LEN);
}

FILLP_INT FillpFrameParseOption(struct FillpFrameHandle *h,
    struct FillpPcbItem *item, FILLP_UINT8 *option, FILLP_UINT8 optLen)
{
    struct FillpFrameDataOption *frameOpt = FILLP_NULL_PTR;
    struct FillpFrameItem *frameItem = FILLP_NULL_PTR;
    struct FrameInfo info;

    if (optLen < FILLP_OPT_FRAME_INFO_LEN) {
        FILLP_LOGERR("invalid frame info len %u, seqNum: %u, pktNum: %u", optLen, item->seqNum, item->pktNum);
        return FILLP_EINVAL;
    }

    frameOpt = (struct FillpFrameDataOption *)option;

    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.frameType = frameOpt->frameType;
    info.level = frameOpt->level;
    info.seqNum = FILLP_NTOHS(frameOpt->seqNum);
    info.subSeqNum = frameOpt->subSeqNum;
    info.timestamp = FILLP_NTOHL(frameOpt->txTimestamp);

    frameItem = FillpFrameItemAlloc(&info);
    if (frameItem == FILLP_NULL_PTR) {
        FILLP_LOGERR("alloc frame item failed, reset the rx status! seq: %d", info.seqNum);
        h->curFrame.rxStarted = FILLP_FALSE;
        return FILLP_OK;
    }

    frameItem->fragSize = FILLP_NTOHL(frameOpt->fragSize);
    FILLP_LOGDBG("get a fragment, seq: %d, fragment seq: %d, size: %u, timestamp: %ld, bitmap: 0x%x",
        frameItem->info.seqNum, frameItem->info.subSeqNum, frameItem->fragSize,
        frameItem->info.timestamp, frameOpt->bitMap);

    item->frame = frameItem;
    UTILS_FLAGS_RESET(item->flags);
    UTILS_FLAGS_SET(item->flags, (FILLP_UINT32)frameOpt->bitMap | FILLP_ITEM_FLAGS_FIRST_PKT);
    return ERR_OK;
}

static void FillpFrameRxNewFrag(struct FillpFrame *frame, const struct FillpPcbItem *item)
{
    if (UTILS_FLAGS_CHECK(item->flags, FILLP_ITEM_FLAGS_FRAME_FIRST_FRAG_START)) {
        frame->rxStarted = FILLP_TRUE;
        frame->lastFragRecvd = FILLP_FALSE;
        frame->info.firstPktRxTime = item->rxTimeStamp;
        frame->info.lastPktRxTime = item->rxTimeStamp;
        frame->info.size = 0;
        frame->info.fragCnt = 0;
        frame->info.totalItemCnt = 0;
        frame->info.seqNum = (FILLP_UINT32)item->frame->info.seqNum;
        frame->info.type = item->frame->info.frameType;
        frame->info.txTimestamp = (FILLP_UINT32)item->frame->info.timestamp;
    }

    if (!frame->rxStarted) {
        FILLP_LOGERR("first fragment is NOT received!!!");
        return;
    }

    frame->info.size += item->frame->fragSize;
    frame->info.fragCnt++;

    if (UTILS_FLAGS_CHECK(item->flags, FILLP_ITEM_FLAGS_FRAME_LAST_FRAG_START)) {
        frame->lastFragRecvd = FILLP_TRUE;
    }

    frame->curFrag.size = item->frame->fragSize;
    frame->curFrag.procSize = 0;
    frame->curFrag.seqNum = (FILLP_UINT32)item->frame->info.subSeqNum;
}

static inline void FillpFrameStatistics(struct FillpFrameHandle *h)
{
    if (h->curFrame.info.type == VIDEO_I) {
        h->stats.iFrameTotalSize += h->curFrame.info.size;
        h->stats.iFrameCount++;
    } else {
        h->stats.pFrameTotalSize += h->curFrame.info.size;
        h->stats.pFrameCount++;
    }
}

static void FillpFrameRxUpdateAndNotify(struct FillpFrameHandle *h, const struct FillpPcbItem *item)
{
    h->curFrame.info.totalItemCnt++;
    h->curFrame.info.firstPktRxTime = UTILS_MIN(h->curFrame.info.firstPktRxTime, item->rxTimeStamp);
    h->curFrame.info.lastPktRxTime = UTILS_MAX(h->curFrame.info.lastPktRxTime, item->rxTimeStamp);

    h->curFrame.curFrag.procSize += item->dataLen;
    if (h->curFrame.curFrag.size == h->curFrame.curFrag.procSize) {
        if (h->curFrame.lastFragRecvd) {
            FILLP_LOGINF("recv a %s frame, seq: %u, frame size: %u, fragment cnt: %u, total pkt cnt: %u,"
                " first pkt rx time: %lld, last pkt rx time: %lld",
                FRAME_VIDEO_FRAME_TYPE_STR(h->curFrame.info.type), h->curFrame.info.seqNum,
                h->curFrame.info.size, h->curFrame.info.fragCnt, h->curFrame.info.totalItemCnt,
                h->curFrame.info.firstPktRxTime, h->curFrame.info.lastPktRxTime);
            if (h->rxCb != FILLP_NULL_PTR) {
                h->rxCb(h->rxCbArg, &h->curFrame.info);
            }

            FillpFrameStatistics(h);
            h->curFrame.rxStarted = FILLP_FALSE;
        } else {
            FILLP_LOGDBG("recv a fragment of %s frame, seq: %u, fragment seq: %u, size: %u",
                FRAME_VIDEO_FRAME_TYPE_STR(h->curFrame.info.type),
                h->curFrame.info.seqNum, h->curFrame.curFrag.seqNum, h->curFrame.curFrag.size);
        }
    }
}

void FillpFrameRx(struct FillpFrameHandle *h, const struct FillpPcbItem *item)
{
    if (item->frame != FILLP_NULL_PTR && UTILS_FLAGS_CHECK(item->flags, FILLP_ITEM_FLAGS_FIRST_PKT)) {
        FillpFrameRxNewFrag(&h->curFrame, item);
    }

    if (!h->curFrame.rxStarted) {
        return;
    }

    FillpFrameRxUpdateAndNotify(h, item);
}

#ifdef __cplusplus
}
#endif

