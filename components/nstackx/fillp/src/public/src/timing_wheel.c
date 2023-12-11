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

#include "fillp_function.h"
#include "utils.h"
#include "log.h"
#include "timing_wheel.h"

#ifdef __cplusplus
extern "C" {
#endif

static void FillpTimingWheelAddTimerInner(struct FillpTimingWheel *ftWheel, FILLP_LLONG expireTime,
    struct FillpTimingWheelTimerNode *timerNode);

static void FillpTimingWheelRunPending(struct FillpTimingWheel *wheel, struct FillpTimingWheelTimerNode *timerNode)
{
    if (FILLP_TIMING_WHEEL_IS_CLEAR(timerNode->status)) {
        HlistAddTail(&wheel->curCbList, &timerNode->cbListNode);
    }
}

static void FillpTimingWheelHandHourTick(struct FillpTimingWheel *wheel, FILLP_LLONG tickDiff)
{
    FILLP_INT i;
    struct FillpTimingWheelHand *hourHand = &wheel->hourHand;
    struct HlistNode *hourNode = FILLP_NULL_PTR;
    struct HlistNode *tmpNode = FILLP_NULL_PTR;
    struct FillpTimingWheelTimerNode *timerNode = FILLP_NULL_PTR;
    FILLP_INT tickLoop = (FILLP_INT)UTILS_MIN(tickDiff, FILLP_TIMING_WHEEL_SLOT_NUM - 1);
    FILLP_INT tmpIndex = hourHand->curTick;

    if ((tmpIndex >= FILLP_TIMING_WHEEL_SLOT_NUM) || (tmpIndex < 0)) {
        return;
    }

    for (i = 0; i <= tickLoop; i++) {
        /* Need to handle the current tick, because maybe some timer added after current tick triggled before */
        hourNode = HLIST_FIRST(&hourHand->slotList[tmpIndex]);
        while (hourNode != FILLP_NULL_PTR) {
            timerNode = FillpTimingWheelHourNodeEntry(hourNode);
            tmpNode = hourNode;
            hourNode = hourNode->next;
            if (wheel->curTime > timerNode->expireTime) {
                HlistDelete(&hourHand->slotList[tmpIndex], tmpNode);
                FILLP_TIMING_WHEEL_CLEAR_HOUR(timerNode->status);
                FillpTimingWheelRunPending(wheel, timerNode);
            } else if (wheel->curTime + wheel->hourHand.handLength > timerNode->expireTime) {
                HlistAddTail(&wheel->hourCycleList, &timerNode->cycleNode);
            }
        }

        tmpIndex++;
        if (tmpIndex == FILLP_TIMING_WHEEL_SLOT_NUM) {
            tmpIndex = 0;
        }
    }

    hourHand->curTick = (FILLP_INT)((hourHand->curTick + tickDiff) % FILLP_TIMING_WHEEL_SLOT_NUM);

    tmpNode = HLIST_FIRST(&wheel->hourCycleList);
    while (tmpNode != FILLP_NULL_PTR) {
        timerNode = FillpTimingWheelCycleNodeEntry(tmpNode);
        HlistDelNode(tmpNode);
        FillpTimingWheelDelTimer(wheel, timerNode);
        FillpTimingWheelAddTimerInner(wheel, timerNode->expireTime, timerNode);

        tmpNode = HLIST_FIRST(&wheel->hourCycleList);
    }
}

static void FillpTimingWheelHandMinTick(struct FillpTimingWheel *wheel, FILLP_LLONG tickDiff)
{
    FILLP_INT i;
    struct FillpTimingWheelHand *minHand = &wheel->minHand;
    struct HlistNode *minNode = FILLP_NULL_PTR;
    struct HlistNode *tmpNode = FILLP_NULL_PTR;
    FILLP_INT tmpIndex = minHand->curTick;
    struct FillpTimingWheelTimerNode *timerNode = FILLP_NULL_PTR;
    FILLP_INT tickLoop = (FILLP_INT)UTILS_MIN(tickDiff, FILLP_TIMING_WHEEL_SLOT_NUM - 1);
    FILLP_INT minTick = (FILLP_INT)(tickDiff + minHand->curTick);
    FILLP_INT hourTick = minTick / FILLP_TIMING_WHEEL_SLOT_NUM;

    if ((tmpIndex >= FILLP_TIMING_WHEEL_SLOT_NUM) || (tmpIndex < 0)) {
        return;
    }

    for (i = 0; i <= tickLoop; i++) {
        /* Need to handle the current tick, because maybe some timer added after current tick triggled before */
        minNode = HLIST_FIRST(&minHand->slotList[tmpIndex]);
        while (minNode != FILLP_NULL_PTR) {
            tmpNode = minNode->next;
            timerNode = FillpTimingWheelMinNodeEntry(minNode);
            HlistDelete(&minHand->slotList[tmpIndex], minNode);

            FILLP_TIMING_WHEEL_CLEAR_MIN(timerNode->status);
            FillpTimingWheelRunPending(wheel, timerNode);

            minNode = tmpNode;
        }

        tmpIndex++;
        if (tmpIndex == FILLP_TIMING_WHEEL_SLOT_NUM) {
            tmpIndex = 0;
        }
    }

    minHand->curTick = minTick % FILLP_TIMING_WHEEL_SLOT_NUM;
    if (hourTick > 0) {
        FillpTimingWheelHandHourTick(wheel, hourTick);
    }
}

static void FillpTimingWheelHandSecTick(struct FillpTimingWheel *wheel, FILLP_INT tickDiff)
{
    FILLP_INT i;
    struct FillpTimingWheelHand *secHand = &wheel->secHand;
    struct HlistNode *secNode = FILLP_NULL_PTR;
    struct HlistNode *tmpNode = FILLP_NULL_PTR;
    FILLP_INT tmpIndex = wheel->secHand.curTick;
    struct FillpTimingWheelTimerNode *timerNode = FILLP_NULL_PTR;
    FILLP_INT tickLoop = UTILS_MIN(tickDiff, FILLP_TIMING_WHEEL_SLOT_NUM - 1);
    FILLP_INT secTick = (tickDiff + secHand->curTick);
    FILLP_INT minTick = secTick / FILLP_TIMING_WHEEL_SLOT_NUM;

    if ((tmpIndex < 0) || (tmpIndex >= FILLP_TIMING_WHEEL_SLOT_NUM)) {
        return;
    }

    for (i = 0; i <= tickLoop; i++) {
        /* Need to handle the current tick, because maybe some timer added after current tick triggled before */
        secNode = HLIST_FIRST(&secHand->slotList[tmpIndex]);
        while (secNode != FILLP_NULL_PTR) {
            tmpNode = secNode->next;
            timerNode = FillpTimingWheelSecNodeEntry(secNode);

            HlistDelete(&secHand->slotList[tmpIndex], secNode);

            FILLP_TIMING_WHEEL_CLEAR_SEC(timerNode->status);
            FillpTimingWheelRunPending(wheel, timerNode);
            secNode = tmpNode;
        }

        tmpIndex++;
        if (tmpIndex == FILLP_TIMING_WHEEL_SLOT_NUM) {
            tmpIndex = 0;
        }
    }

    secHand->curTick = secTick % FILLP_TIMING_WHEEL_SLOT_NUM;
    if (minTick > 0) {
        FillpTimingWheelHandMinTick(wheel, minTick);
    }
}

static void FillpInitTimingWheelTimeHand(struct FillpTimingWheelHand *hand, FILLP_INT accuracy)
{
    if (accuracy == 0) {
        FILLP_LOGERR("accuracy can't be 0");
        return;
    }
    FILLP_INT i;
    hand->curTick = 0;
    hand->accuracy = accuracy;
    hand->curSlotTime = SYS_ARCH_GET_CUR_TIME_LONGLONG();
    hand->handLength = accuracy * FILLP_TIMING_WHEEL_SLOT_NUM;

    for (i = 0; i < FILLP_TIMING_WHEEL_SLOT_NUM; i++) {
        HLIST_INIT(&hand->slotList[i]);
    }
}

void FillpTimingWheelInit(struct FillpTimingWheel *ftWheel, FILLP_LLONG accuracy)
{
    ftWheel->curTime = SYS_ARCH_GET_CUR_TIME_LONGLONG();
    if (accuracy <= 0) {
        accuracy = 1;
    }
    ftWheel->accuracy = accuracy;
    ftWheel->inCbContext = FILLP_FALSE;
    HLIST_INIT(&ftWheel->curCbList);
    HLIST_INIT(&ftWheel->hourCycleList);
    FillpInitTimingWheelTimeHand(&ftWheel->secHand, (FILLP_INT)accuracy);
    FillpInitTimingWheelTimeHand(&ftWheel->minHand, (FILLP_INT)(accuracy * FILLP_TIMING_WHEEL_SLOT_NUM));
    FillpInitTimingWheelTimeHand(&ftWheel->hourHand,
        (FILLP_INT)(accuracy * FILLP_TIMING_WHEEL_SLOT_NUM * FILLP_TIMING_WHEEL_SLOT_NUM));
    ftWheel->tickTime = 0;
}

static void FillpTimingWheelAddTimerInner(struct FillpTimingWheel *ftWheel, FILLP_LLONG expireTime,
    struct FillpTimingWheelTimerNode *timerNode)
{
    FILLP_LLONG timeDiff;
    FILLP_INT tickDiff;
    FILLP_INT secTick;
    FILLP_INT minTick;
    FILLP_INT hourTick;

    HLIST_INIT_NODE(&timerNode->hourNode);
    HLIST_INIT_NODE(&timerNode->minNode);
    HLIST_INIT_NODE(&timerNode->secNode);

    timerNode->status = 0;
    timerNode->expireTime = expireTime;

    timeDiff = expireTime - ftWheel->curTime;
    if ((timeDiff < 0) || (timeDiff < ftWheel->secHand.accuracy)) {
        timeDiff = ftWheel->secHand.accuracy;
    }

    tickDiff = (FILLP_INT)(timeDiff / ftWheel->secHand.accuracy);

    secTick = ftWheel->secHand.curTick + tickDiff;
    HlistAddTail(&ftWheel->secHand.slotList[secTick % FILLP_TIMING_WHEEL_SLOT_NUM], &timerNode->secNode);
    FILLP_TIMING_WHEEL_SET_SEC(timerNode->status);

    if (secTick >= FILLP_TIMING_WHEEL_SLOT_NUM) {
        minTick = (secTick) / FILLP_TIMING_WHEEL_SLOT_NUM;

        minTick += ftWheel->minHand.curTick;
        HlistAddTail(&ftWheel->minHand.slotList[minTick % FILLP_TIMING_WHEEL_SLOT_NUM], &timerNode->minNode);
        FILLP_TIMING_WHEEL_SET_MIN(timerNode->status);

        hourTick = minTick / FILLP_TIMING_WHEEL_SLOT_NUM;
        if (hourTick > 0) {
            hourTick += ftWheel->hourHand.curTick;
            HlistAddTail(&ftWheel->hourHand.slotList[hourTick % FILLP_TIMING_WHEEL_SLOT_NUM],
                &timerNode->hourNode);
            FILLP_TIMING_WHEEL_SET_HOUR(timerNode->status);
        }
    }

    timerNode->wheel = ftWheel;
}

void FillpTimingWheelAddTimer(struct FillpTimingWheel *ftWheel, FILLP_LLONG expireTime,
    struct FillpTimingWheelTimerNode *timerNode)
{
    if (FILLP_TIMING_WHEEL_IS_NODE_ENABLED(timerNode)) {
        return;
    }

    FillpTimingWheelAddTimerInner(ftWheel, expireTime, timerNode);
}

void FillpTimingWheelDelTimer(struct FillpTimingWheel *ftWheel, struct FillpTimingWheelTimerNode *timerNode)
{
    if (!FILLP_TIMING_WHEEL_IS_NODE_ENABLED(timerNode)) {
        return;
    }

    if (HLISTNODE_LINKED(&timerNode->cbListNode)) {
        HlistDelete(&ftWheel->curCbList, &timerNode->cbListNode);
    }

    if (!FILLP_TIMING_WHEEL_IS_SEC_CLEAR(timerNode->status)) {
        HlistDelNode(&timerNode->secNode);
        FILLP_TIMING_WHEEL_CLEAR_SEC(timerNode->status);
    }

    if (!FILLP_TIMING_WHEEL_IS_MIN_CLEAR(timerNode->status)) {
        HlistDelNode(&timerNode->minNode);
        FILLP_TIMING_WHEEL_CLEAR_MIN(timerNode->status);
    }

    if (!FILLP_TIMING_WHEEL_IS_HOUR_CLEAR(timerNode->status)) {
        HlistDelNode(&timerNode->hourNode);
        FILLP_TIMING_WHEEL_CLEAR_HOUR(timerNode->status);
    }

    timerNode->wheel = FILLP_NULL_PTR;
    return;
}

void FillpTimingWheelLoopCheck(struct FillpTimingWheel *ftWheel, FILLP_LLONG curTime)
{
    FILLP_LLONG timeDiff = curTime - ftWheel->curTime;
    FILLP_INT tickDiff;
    struct HlistNode *node = FILLP_NULL_PTR;
    if (timeDiff < 0) {
        return;
    }

    tickDiff = (FILLP_INT)(timeDiff / ftWheel->accuracy);
    if (tickDiff == 0) {
        return;
    }

    /* should update before do all callbacks, or it may lead to dead loop */
    ftWheel->curTime = curTime;
    ftWheel->inCbContext = FILLP_TRUE;
    ftWheel->nextMinimalExpireTime = 0;
    FillpTimingWheelHandSecTick(ftWheel, tickDiff);

    node = HLIST_FIRST(&ftWheel->curCbList);
    while (node != FILLP_NULL_PTR) {
        struct FillpTimingWheelTimerNode *timerNode = FillpTimingWheelCblistNodeEntry(node);
        HlistDelete(&ftWheel->curCbList, node);
        if (timerNode->cbNode.cb != FILLP_NULL_PTR) {
            timerNode->cbNode.cb(timerNode->cbNode.arg);
        }
        node = HLIST_FIRST(&ftWheel->curCbList);
    }

    ftWheel->inCbContext = FILLP_FALSE;
}

#ifdef __cplusplus
}
#endif
