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

#ifndef FILLP_TIMEING_WHEEL_H
#define FILLP_TIMEING_WHEEL_H

#include "hlist.h"
#include "opt.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FILLP_SECOND_IN_US 1000000
#define FILLP_MICROSECOND_IN_NS 1000

#define FILLP_TIMING_WHEEL_SEC_FLAG 0x01
#define FILLP_TIMING_WHEEL_MIN_FLAG 0x02
#define FILLP_TIMING_WHEEL_HOUR_FLAG 0x04

#define FILLP_TIMING_WHEEL_SET_SEC(status) ((status) |= FILLP_TIMING_WHEEL_SEC_FLAG)
#define FILLP_TIMING_WHEEL_SET_MIN(status) ((status) |= FILLP_TIMING_WHEEL_MIN_FLAG)
#define FILLP_TIMING_WHEEL_SET_HOUR(status) ((status) |= FILLP_TIMING_WHEEL_HOUR_FLAG)

#define FILLP_TIMING_WHEEL_CLEAR_SEC(status) ((status) = (status) & (FILLP_UINT32)(~FILLP_TIMING_WHEEL_SEC_FLAG))
#define FILLP_TIMING_WHEEL_CLEAR_MIN(status) ((status) = (status) & (FILLP_UINT32)(~FILLP_TIMING_WHEEL_MIN_FLAG))
#define FILLP_TIMING_WHEEL_CLEAR_HOUR(status) ((status) = (status) & (FILLP_UINT32)(~FILLP_TIMING_WHEEL_HOUR_FLAG))

#define FILLP_TIMING_WHEEL_IS_SEC_CLEAR(status) (!((status)&FILLP_TIMING_WHEEL_SEC_FLAG))
#define FILLP_TIMING_WHEEL_IS_MIN_CLEAR(status) (!((status)&FILLP_TIMING_WHEEL_MIN_FLAG))
#define FILLP_TIMING_WHEEL_IS_HOUR_CLEAR(status) (!((status)&FILLP_TIMING_WHEEL_HOUR_FLAG))

#define FILLP_TIMING_WHEEL_IS_CLEAR(status) ((status) == 0)

struct FillpTimingWheelHand {
    struct Hlist slotList[FILLP_TIMING_WHEEL_SLOT_NUM];
    FILLP_LLONG curSlotTime;

    FILLP_INT accuracy;
    FILLP_INT handLength;
    FILLP_INT curTick;
};

struct FillpTimingWheel {
    struct FillpTimingWheelHand secHand;
    struct FillpTimingWheelHand minHand;
    struct FillpTimingWheelHand hourHand;

    FILLP_LLONG curTime;
    /* secHand->cur_tick + minHand->cur_tick * SLOT_NUM + hourHand->cur_tick * SLOT_NUM * SLOT_NUM */
    FILLP_LLONG tickTime;
    FILLP_LLONG accuracy;
    /* Current loop, the cb may calls */
    struct Hlist curCbList;
    /* for hour check , then recycle */
    struct Hlist hourCycleList;
    /* Is in callback function context */
    FILLP_UINT8 inCbContext;
    FILLP_LLONG nextMinimalExpireTime;
};

typedef void (*FillpTimingWheelCb)(void *arg);
struct FillpTimingWheelCbNode {
    void *arg;
    FillpTimingWheelCb cb;
};

struct FillpTimingWheelTimerNode {
    struct HlistNode secNode;
    struct HlistNode minNode;
    struct HlistNode hourNode;
    struct HlistNode cycleNode;
    struct HlistNode cbListNode;
    struct FillpTimingWheel *wheel;

    FILLP_LLONG expireTime;
    struct FillpTimingWheelCbNode cbNode;
    FILLP_UINT32 interval; /* If cyclical */
    FILLP_UINT32 status;
};

#define FILLP_TIMING_WHEEL_INIT_NODE(node) \
    do {                                   \
        (node)->wheel = FILLP_NULL_PTR;    \
        (node)->status = 0;                \
    } while (0)

#define FILLP_TIMING_WHEEL_IS_NODE_ENABLED(timerNode) \
    ((timerNode)->wheel &&                            \
        (!FILLP_TIMING_WHEEL_IS_CLEAR((timerNode)->status) || HLISTNODE_LINKED(&(timerNode)->cbListNode)))


static __inline struct FillpTimingWheelTimerNode *FillpTimingWheelHourNodeEntry(struct HlistNode *hourNode)
{
    return (struct FillpTimingWheelTimerNode *)((char *)(hourNode) -
        (uintptr_t)(&(((struct FillpTimingWheelTimerNode *)0)->hourNode)));
}

static __inline struct FillpTimingWheelTimerNode *FillpTimingWheelMinNodeEntry(struct HlistNode *minNode)
{
    return (struct FillpTimingWheelTimerNode *)((char *)(minNode) -
        (uintptr_t)(&(((struct FillpTimingWheelTimerNode *)0)->minNode)));
}

static __inline struct FillpTimingWheelTimerNode *FillpTimingWheelSecNodeEntry(struct HlistNode *secNode)
{
    return (struct FillpTimingWheelTimerNode *)((char *)(secNode) -
        (uintptr_t)(&(((struct FillpTimingWheelTimerNode *)0)->secNode)));
}

static __inline struct FillpTimingWheelTimerNode *FillpTimingWheelCycleNodeEntry(struct HlistNode *cycleNode)
{
    return (struct FillpTimingWheelTimerNode *)((char *)(cycleNode) -
        (uintptr_t)(&(((struct FillpTimingWheelTimerNode *)0)->cycleNode)));
}

static __inline struct FillpTimingWheelTimerNode *FillpTimingWheelCblistNodeEntry(struct HlistNode *cbNode)
{
    return (struct FillpTimingWheelTimerNode *)((char *)(cbNode) -
        (uintptr_t)(&(((struct FillpTimingWheelTimerNode *)0)->cbListNode)));
}

void FillpTimingWheelInit(struct FillpTimingWheel *ftWheel, FILLP_LLONG accuracy);

void FillpTimingWheelAddTimer(struct FillpTimingWheel *ftWheel, FILLP_LLONG expireTime,
    struct FillpTimingWheelTimerNode *timerNode);

void FillpTimingWheelLoopCheck(struct FillpTimingWheel *ftWheel, FILLP_LLONG curTime);

void FillpTimingWheelDelTimer(struct FillpTimingWheel *ftWheel, struct FillpTimingWheelTimerNode *timerNode);

#ifdef __cplusplus
}
#endif

#endif /* FILLP_TIMEING_WHEEL_H */