/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "softbus_sequence_verification.h"
#include "comm_log.h"

#define MAX_SEQ_BIAS 60

static bool IsDifferentSign(int32_t seqA, int32_t seqB)
{
    if ((seqA >= 0 && seqB >= 0) || (seqA < 0 && seqB < 0)) {
        return false;
    }
    return true;
}

static bool IsPassDuplicateCheck(SeqVerifyInfo *seqVerifyInfo, int32_t recvSeq)
{
    uint32_t offset = (uint32_t)(seqVerifyInfo->maxSeq - recvSeq);
    uint64_t isRepeat = seqVerifyInfo->recvBitmap & (0x1UL << offset);
    if (isRepeat) {
        COMM_LOGI(COMM_VERIFY, "duplicated package seq. recvSeq=%{public}d", recvSeq);
        return false;
    }
    seqVerifyInfo->recvBitmap |= (0x1UL << offset);
    return true;
}

static bool IsPassOverMaxCheck(SeqVerifyInfo *seqVerifyInfo, int32_t recvSeq)
{
    /* consider flip */
    if (recvSeq - seqVerifyInfo->maxSeq < 0) {
        return false;
    }

    if (recvSeq - seqVerifyInfo->minSeq >= MAX_SEQ_BIAS) {
        COMM_LOGE(COMM_VERIFY, "seq bias reach max. MAX_SEQ_BIAS=%{public}d", MAX_SEQ_BIAS);
        return false;
    }
    uint32_t seqOffset = (uint32_t)(recvSeq - seqVerifyInfo->maxSeq + 1);
    seqVerifyInfo->maxSeq = ++recvSeq;
    seqVerifyInfo->recvBitmap = seqVerifyInfo->recvBitmap << seqOffset;
    /* 1: represent the penultimate bit of recvBitmap is 1. */
    seqVerifyInfo->recvBitmap |= (0x1UL << 1);
    return true;
}

static bool IsPassAllRangeCheck(SeqVerifyInfo *seqVerifyInfo, int32_t recvSeq)
{
    if (recvSeq == seqVerifyInfo->minSeq) {
        seqVerifyInfo->minSeq = ++recvSeq;
        return true;
    }

    if (recvSeq > seqVerifyInfo->minSeq) {
        if (recvSeq < seqVerifyInfo->maxSeq) {
            return IsPassDuplicateCheck(seqVerifyInfo, recvSeq);
        }
        return IsPassOverMaxCheck(seqVerifyInfo, recvSeq);
    }
    return false;
}

static bool IsPassNormalCheck(SeqVerifyInfo *seqVerifyInfo, int32_t recvSeq)
{
    /* normal case */
    if (recvSeq == seqVerifyInfo->minSeq) {
        seqVerifyInfo->minSeq = recvSeq + 1;
        seqVerifyInfo->maxSeq = recvSeq + 1;
        return true;
    }
    /* first disorder package, recvSeq and minSeq/maxSeq are same signs. */
    if (!IsDifferentSign(recvSeq, seqVerifyInfo->minSeq)) {
        if (recvSeq > seqVerifyInfo->maxSeq) {
            return IsPassOverMaxCheck(seqVerifyInfo, recvSeq);
        }
        return false;
    }
    /* first disorder package, recvSeq and minSeq/maxSeq are different signs. */
    return IsPassOverMaxCheck(seqVerifyInfo, recvSeq);
}

static bool IsPassNoflipDisorderCheck(SeqVerifyInfo *seqVerifyInfo, int32_t recvSeq)
{
    if (seqVerifyInfo->minSeq >= 0) {
        if (recvSeq >= 0) {
            return IsPassAllRangeCheck(seqVerifyInfo, recvSeq);
        }
        return IsPassOverMaxCheck(seqVerifyInfo, recvSeq);
    }
    if (seqVerifyInfo->maxSeq < 0) {
        if (recvSeq < 0) {
            return IsPassAllRangeCheck(seqVerifyInfo, recvSeq);
        }
        return IsPassOverMaxCheck(seqVerifyInfo, recvSeq);
    }
    /* can not reach here. */
    return false;
}

static bool IsPassFlipPositiveCheck(SeqVerifyInfo *seqVerifyInfo, int32_t recvSeq)
{
    if (recvSeq >= 0) {
        if (recvSeq < seqVerifyInfo->maxSeq) {
            return IsPassDuplicateCheck(seqVerifyInfo, recvSeq);
        }
        return IsPassOverMaxCheck(seqVerifyInfo, recvSeq);
    } else {
        if (recvSeq == seqVerifyInfo->minSeq) {
            seqVerifyInfo->minSeq = ++recvSeq;
            return true;
        }
        if (recvSeq > seqVerifyInfo->minSeq) {
            return IsPassDuplicateCheck(seqVerifyInfo, recvSeq);
        }
        return false;
    }
    /* can not reach here. */
    return false;
}

static bool IsPassFlipNegativeCheck(SeqVerifyInfo *seqVerifyInfo, int32_t recvSeq)
{
    if (recvSeq >= 0) {
        if (recvSeq == seqVerifyInfo->minSeq) {
            seqVerifyInfo->minSeq = ++recvSeq;
            return true;
        }
        if (recvSeq > seqVerifyInfo->minSeq) {
            return IsPassDuplicateCheck(seqVerifyInfo, recvSeq);
        }
        return false;
    } else {
        if (recvSeq < seqVerifyInfo->maxSeq) {
            return IsPassDuplicateCheck(seqVerifyInfo, recvSeq);
        }
        return IsPassOverMaxCheck(seqVerifyInfo, recvSeq);
    }
    /* can not reach here. */
    return false;
}

bool IsPassSeqCheck(SeqVerifyInfo *seqVerifyInfo, int32_t recvSeq)
{
    if (seqVerifyInfo == NULL) {
        COMM_LOGE(COMM_VERIFY, "invalid param.");
        return false;
    }
    bool isDifferentSign = IsDifferentSign(seqVerifyInfo->minSeq, seqVerifyInfo->maxSeq);
    if (seqVerifyInfo->minSeq == seqVerifyInfo->maxSeq) {
        return IsPassNormalCheck(seqVerifyInfo, recvSeq);
    }
    if ((seqVerifyInfo->minSeq < seqVerifyInfo->maxSeq) && !isDifferentSign) {
        return IsPassNoflipDisorderCheck(seqVerifyInfo, recvSeq);
    }
    if ((seqVerifyInfo->minSeq > seqVerifyInfo->maxSeq) && isDifferentSign) {
        return IsPassFlipNegativeCheck(seqVerifyInfo, recvSeq);
    }
    if ((seqVerifyInfo->minSeq < seqVerifyInfo->maxSeq) && isDifferentSign) {
        return IsPassFlipPositiveCheck(seqVerifyInfo, recvSeq);
    }
    /* can not reach here. */
    return false;
}
