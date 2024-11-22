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

#include <gtest/gtest.h>

#include "softbus_sequence_verification.h"

using namespace testing::ext;

namespace {
const int32_t MAX_RECEIVE_SEQUENCE = 5;
}

namespace OHOS {
class SequenceVerificationTest : public testing::Test {
public:
    static void SetUpTestCase(void) { }
    static void TearDownTestCase(void) { }
};

/**
 * @tc.name: Softbus_SeqVerifyTest_Test_NormalCase_001
 * @tc.desc: Verify normal case, seq >= 0.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceVerificationTest, Softbus_SeqVerifyTest_Test_NormalCase_001, TestSize.Level0)
{
    SeqVerifyInfo seqInfo = { 0 };
    for (int32_t recvSeq = 0; recvSeq < MAX_RECEIVE_SEQUENCE; recvSeq++) {
        bool ret = IsPassSeqCheck(&seqInfo, recvSeq);
        EXPECT_EQ(ret, true);
    }
}

/**
 * @tc.name: Softbus_SeqVerifyTest_Test_NormalCase_002
 * @tc.desc: Verify normal case, seq < 0.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceVerificationTest, Softbus_SeqVerifyTest_Test_NormalCase_002, TestSize.Level0)
{
    SeqVerifyInfo seqInfo = { 0 };
    /* 2: offset */
    seqInfo.minSeq = INT32_MIN + 1;
    seqInfo.maxSeq = INT32_MIN + 1;
    int32_t recvSeq = INT32_MIN + 1;
    for (int32_t i = 0; i < MAX_RECEIVE_SEQUENCE; i++) {
        bool ret = IsPassSeqCheck(&seqInfo, recvSeq++);
        EXPECT_EQ(ret, true);
    }
}

/**
 * @tc.name: Softbus_SeqVerifyTest_Test_NormalCase_003
 * @tc.desc: Verify normal case and seq flip negative.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceVerificationTest, Softbus_SeqVerifyTest_Test_NormalCase_003, TestSize.Level0)
{
    SeqVerifyInfo seqInfo = { 0 };
    /* 2: offset */
    seqInfo.minSeq = INT32_MAX - 2;
    seqInfo.maxSeq = INT32_MAX - 2;
    int32_t recvSeq = INT32_MAX - 2;

    for (volatile int32_t i = 0; i < 2; i++) {
        bool ret = IsPassSeqCheck(&seqInfo, recvSeq++);
        EXPECT_EQ(ret, true);
    }
}

/**
 * @tc.name: Softbus_SeqVerifyTest_Test_NormalCase_004
 * @tc.desc: Verify normal case and seq flip positive.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceVerificationTest, Softbus_SeqVerifyTest_Test_NormalCase_004, TestSize.Level0)
{
    SeqVerifyInfo seqInfo = { 0 };
    /* -2: offset */
    seqInfo.minSeq = -2;
    seqInfo.maxSeq = -2;
    int32_t recvSeq = -2;
    for (int32_t i = 0; i < MAX_RECEIVE_SEQUENCE; i++) {
        bool ret = IsPassSeqCheck(&seqInfo, recvSeq++);
        EXPECT_EQ(ret, true);
    }
}

/**
 * @tc.name: Softbus_SeqVerifyTest_Test_DisorderCase_001
 * @tc.desc: Verify disorder seq.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceVerificationTest, Softbus_SeqVerifyTest_Test_DisorderCase_001, TestSize.Level0)
{
    SeqVerifyInfo seqInfo = { 0 };
    int32_t recvSeq[MAX_RECEIVE_SEQUENCE] = { 0, 1, 4, 3, 2 };
    for (int32_t i = 0; i < MAX_RECEIVE_SEQUENCE; i++) {
        bool ret = IsPassSeqCheck(&seqInfo, recvSeq[i]);
        EXPECT_EQ(ret, true);
    }
}

/**
 * @tc.name: Softbus_SeqVerifyTest_Test_DisorderCase_002
 * @tc.desc: Verify disorder seq, boundary valueseq(61-1=60[MAX_SEQ_BIAS]).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceVerificationTest, Softbus_SeqVerifyTest_Test_DisorderCase_002, TestSize.Level0)
{
    SeqVerifyInfo seqInfo = { 0 };
    int32_t recvSeq[MAX_RECEIVE_SEQUENCE] = { 0, 1, 11, 8, 7 };
    for (int32_t i = 0; i < MAX_RECEIVE_SEQUENCE; i++) {
        bool ret = IsPassSeqCheck(&seqInfo, recvSeq[i]);
        EXPECT_EQ(ret, true);
    }
}

/**
 * @tc.name: Softbus_SeqVerifyTest_Test_DisorderCase_003
 * @tc.desc: Verify disorder seq, boundary valueseq(62-1>60[MAX_SEQ_BIAS]).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceVerificationTest, Softbus_SeqVerifyTest_Test_DisorderCase_003, TestSize.Level0)
{
    SeqVerifyInfo seqInfo = { 0 };
    int32_t recvSeq[MAX_RECEIVE_SEQUENCE] = { 0, 1, 62, 8, 7 };
    for (int32_t i = 0; i < MAX_RECEIVE_SEQUENCE; i++) {
        bool ret = IsPassSeqCheck(&seqInfo, recvSeq[i]);
        if (i < 2) {
            EXPECT_EQ(ret, true);
        } else if (i == 2) {
            EXPECT_EQ(ret, false);
        } else {
            EXPECT_EQ(ret, true);
        }
    }
}

/**
 * @tc.name: Softbus_SeqVerifyTest_Test_DisorderCase_004
 * @tc.desc: Verify disorder seq, boundary valueseq(99-39=60[MAX_SEQ_BIAS]).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceVerificationTest, Softbus_SeqVerifyTest_Test_DisorderCase_004, TestSize.Level0)
{
    SeqVerifyInfo seqInfo = { 0 };
    seqInfo.minSeq = -100;
    seqInfo.maxSeq = -100;
    int32_t recvSeq[MAX_RECEIVE_SEQUENCE] = { -100, -99, -39, -56, -50 };
    for (int32_t i = 0; i < MAX_RECEIVE_SEQUENCE; i++) {
        bool ret = IsPassSeqCheck(&seqInfo, recvSeq[i]);
        EXPECT_EQ(ret, true);
    }
}

/**
 * @tc.name: Softbus_SeqVerifyTest_Test_DisorderCase_005
 * @tc.desc: Verify disorder seq, boundary valueseq(99-38>60[MAX_SEQ_BIAS]).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceVerificationTest, Softbus_SeqVerifyTest_Test_DisorderCase_005, TestSize.Level0)
{
    SeqVerifyInfo seqInfo = { 0 };
    seqInfo.minSeq = -100;
    seqInfo.maxSeq = -100;
    int32_t recvSeq[MAX_RECEIVE_SEQUENCE] = { -100, -99, -38, -96, -90 };
    for (int32_t i = 0; i < MAX_RECEIVE_SEQUENCE; i++) {
        bool ret = IsPassSeqCheck(&seqInfo, recvSeq[i]);
        if (i < 2) {
            EXPECT_EQ(ret, true);
        } else if (i == 2) {
            EXPECT_EQ(ret, false);
        } else {
            EXPECT_EQ(ret, true);
        }
    }
}

/**
 * @tc.name: Softbus_SeqVerifyTest_Test_DisorderCase_006
 * @tc.desc: Verify disorder seq, seq flip negative, boundary valueseq.
 * INT32_MIN + 58 - INT32_MIN + INT32_MAX - (INT32_MAX - 1) + 1 = 60[MAX_SEQ_BIAS]
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceVerificationTest, Softbus_SeqVerifyTest_Test_DisorderCase_006, TestSize.Level0)
{
    SeqVerifyInfo seqInfo = { 0 };
    seqInfo.minSeq = INT32_MAX - 2;
    seqInfo.maxSeq = INT32_MAX - 2;
    int32_t recvSeq[MAX_RECEIVE_SEQUENCE] = { INT32_MAX - 2, INT32_MAX - 1, 58, 0, 7 };
    for (int32_t i = 0; i < MAX_RECEIVE_SEQUENCE; i++) {
        bool ret = IsPassSeqCheck(&seqInfo, recvSeq[i]);
        if (i < 2) {
            EXPECT_EQ(ret, true);
        } else {
            EXPECT_EQ(ret, false);
        }
    }
}

/**
 * @tc.name: Softbus_SeqVerifyTest_Test_DisorderCase_007
 * @tc.desc: Verify disorder seq, seq flip negative, boundary valueseq.
 * INT32_MIN + 59 - INT32_MIN + INT32_MAX - (INT32_MAX - 1) + 1 > 60[MAX_SEQ_BIAS]
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceVerificationTest, Softbus_SeqVerifyTest_Test_DisorderCase_007, TestSize.Level0)
{
    SeqVerifyInfo seqInfo = { 0 };
    seqInfo.minSeq = INT32_MAX - 2;
    seqInfo.maxSeq = INT32_MAX - 2;
    int32_t recvSeq[MAX_RECEIVE_SEQUENCE] = { INT32_MAX - 2, INT32_MAX - 1, 59, 0, 7 };
    for (int32_t i = 0; i < MAX_RECEIVE_SEQUENCE; i++) {
        bool ret = IsPassSeqCheck(&seqInfo, recvSeq[i]);
        if (i < 2) {
            EXPECT_EQ(ret, true);
        } else {
            EXPECT_EQ(ret, false);
        }
    }
}

/**
 * @tc.name: Softbus_SeqVerifyTest_Test_DisorderCase_008
 * @tc.desc: Verify disorder seq, seq flip positive, boundary valueseq.
 * 31 + 29 = 60[MAX_SEQ_BIAS]
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceVerificationTest, Softbus_SeqVerifyTest_Test_DisorderCase_008, TestSize.Level0)
{
    SeqVerifyInfo seqInfo = { 0 };
    seqInfo.minSeq = -30;
    seqInfo.maxSeq = -30;
    int32_t recvSeq[MAX_RECEIVE_SEQUENCE] = { -30, -29, 31, 10, 5 };
    for (int32_t i = 0; i < MAX_RECEIVE_SEQUENCE; i++) {
        bool ret = IsPassSeqCheck(&seqInfo, recvSeq[i]);
        EXPECT_EQ(ret, true);
    }
}

/**
 * @tc.name: Softbus_SeqVerifyTest_Test_DisorderCase_009
 * @tc.desc: Verify disorder seq, seq flip positive, boundary valueseq.
 * 32 + 29 > 60[MAX_SEQ_BIAS]
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceVerificationTest, Softbus_SeqVerifyTest_Test_DisorderCase_009, TestSize.Level0)
{
    SeqVerifyInfo seqInfo = { 0 };
    seqInfo.minSeq = -30;
    seqInfo.maxSeq = -30;
    int32_t recvSeq[MAX_RECEIVE_SEQUENCE] = { -30, -29, 32, 0, -3 };
    for (int32_t i = 0; i < MAX_RECEIVE_SEQUENCE; i++) {
        bool ret = IsPassSeqCheck(&seqInfo, recvSeq[i]);
        if (i < 2) {
            EXPECT_EQ(ret, true);
        } else if (i == 2) {
            EXPECT_EQ(ret, false);
        } else {
            EXPECT_EQ(ret, true);
        }
    }
}

/**
 * @tc.name: Softbus_SeqVerifyTest_Test_RepeatCase_001
 * @tc.desc: Verify repeat seq.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceVerificationTest, Softbus_SeqVerifyTest_Test_RepeatCase_001, TestSize.Level0)
{
    SeqVerifyInfo seqInfo = { 0 };
    int32_t recvSeq[MAX_RECEIVE_SEQUENCE] = { 2, 10, 2, 3, 3 };
    for (int32_t i = 0; i < MAX_RECEIVE_SEQUENCE; i++) {
        bool ret = IsPassSeqCheck(&seqInfo, recvSeq[i]);
        if (i < 2 || i == 3) {
            EXPECT_EQ(ret, true);
        } else {
            EXPECT_EQ(ret, false);
        }
    }
}

/**
 * @tc.name: Softbus_SeqVerifyTest_Test_RepeatCase_002
 * @tc.desc: Verify repeat seq.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceVerificationTest, Softbus_SeqVerifyTest_Test_RepeatCase_002, TestSize.Level0)
{
    SeqVerifyInfo seqInfo = { 0 };
    int32_t recvSeq[MAX_RECEIVE_SEQUENCE] = { 0, 10, 1, 5, 5 };
    for (int32_t i = 0; i < MAX_RECEIVE_SEQUENCE; i++) {
        bool ret = IsPassSeqCheck(&seqInfo, recvSeq[i]);
        if (i < 4) {
            EXPECT_EQ(ret, true);
        } else {
            EXPECT_EQ(ret, false);
        }
    }
}

/**
 * @tc.name: Softbus_SeqVerifyTest_Test_RepeatCase_003
 * @tc.desc: Verify repeat seq, flip negative.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceVerificationTest, Softbus_SeqVerifyTest_Test_RepeatCase_003, TestSize.Level0)
{
    SeqVerifyInfo seqInfo = { 0 };
    seqInfo.minSeq = INT32_MAX - 2;
    seqInfo.maxSeq = INT32_MAX - 2;
    int32_t recvSeq[MAX_RECEIVE_SEQUENCE] = { INT32_MAX - 2, INT32_MAX - 1, 5, INT32_MAX - 1, 3 };
    for (int32_t i = 0; i < MAX_RECEIVE_SEQUENCE; i++) {
        bool ret = IsPassSeqCheck(&seqInfo, recvSeq[i]);
        if (i < 2) {
            EXPECT_EQ(ret, true);
        } else {
            EXPECT_EQ(ret, false);
        }
    }
}

/**
 * @tc.name: Softbus_SeqVerifyTest_Test_RepeatCase_004
 * @tc.desc: Verify repeat seq, flip negative.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceVerificationTest, Softbus_SeqVerifyTest_Test_RepeatCase_004, TestSize.Level0)
{
    SeqVerifyInfo seqInfo = { 0 };
    seqInfo.minSeq = INT32_MAX - 2;
    seqInfo.maxSeq = INT32_MAX - 2;
    int32_t recvSeq[MAX_RECEIVE_SEQUENCE] = { INT32_MAX - 2, 0, 5, 0, 3 };
    for (int32_t i = 0; i < MAX_RECEIVE_SEQUENCE; i++) {
        bool ret = IsPassSeqCheck(&seqInfo, recvSeq[i]);
        if (i < 1) {
            EXPECT_EQ(ret, true);
        } else {
            EXPECT_EQ(ret, false);
        }
    }
}

/**
 * @tc.name: Softbus_SeqVerifyTest_Test_RepeatCase_005
 * @tc.desc: Verify repeat seq, flip positive.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceVerificationTest, Softbus_SeqVerifyTest_Test_RepeatCase_005, TestSize.Level0)
{
    SeqVerifyInfo seqInfo = { 0 };
    seqInfo.minSeq = -10;
    seqInfo.maxSeq = -10;
    int32_t recvSeq[MAX_RECEIVE_SEQUENCE] = { -10, -1, 10, -1, 3 };
    for (int32_t i = 0; i < MAX_RECEIVE_SEQUENCE; i++) {
        bool ret = IsPassSeqCheck(&seqInfo, recvSeq[i]);
        if (i < 3 || i == 4) {
            EXPECT_EQ(ret, true);
        } else {
            EXPECT_EQ(ret, false);
        }
    }
}

/**
 * @tc.name: Softbus_SeqVerifyTest_Test_RepeatCase_006
 * @tc.desc: Verify repeat seq, flip positive.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceVerificationTest, Softbus_SeqVerifyTest_Test_RepeatCase_006, TestSize.Level0)
{
    SeqVerifyInfo seqInfo = { 0 };
    seqInfo.minSeq = -10;
    seqInfo.maxSeq = -10;
    int32_t recvSeq[MAX_RECEIVE_SEQUENCE] = { -10, 1, 10, 1, 3 };
    for (int32_t i = 0; i < MAX_RECEIVE_SEQUENCE; i++) {
        bool ret = IsPassSeqCheck(&seqInfo, recvSeq[i]);
        if (i < 3 || i == 4) {
            EXPECT_EQ(ret, true);
        } else {
            EXPECT_EQ(ret, false);
        }
    }
}

/**
 * @tc.name: Softbus_SeqVerifyTest_Test_RepeatCase_007
 * @tc.desc: Verify repeat seq.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceVerificationTest, Softbus_SeqVerifyTest_Test_RepeatCase_007, TestSize.Level0)
{
    SeqVerifyInfo seqInfo = { 0 };
    seqInfo.minSeq = 0;
    seqInfo.maxSeq = 0;
    int32_t recvSeq[12] = { 0, 1, 2, 3, 4, 3, 3, 10, 5, 5, 5, 5 };
    for (int32_t i = 0; i < 12; i++) {
        bool ret = IsPassSeqCheck(&seqInfo, recvSeq[i]);
        if (i < 5 || i == 7 || i == 8) {
            EXPECT_EQ(ret, true);
        } else {
            EXPECT_EQ(ret, false);
        }
    }
}

/**
 * @tc.name: Softbus_SeqVerifyTest_Test_LessThanMinCase_001
 * @tc.desc: Verify abnormal seq, minSeq positive.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceVerificationTest, Softbus_SeqVerifyTest_Test_LessThanMinCase_001, TestSize.Level0)
{
    SeqVerifyInfo seqInfo = { 0 };
    int32_t recvSeq[MAX_RECEIVE_SEQUENCE] = { -10, -2, 10, 1, 3 };
    for (int32_t i = 0; i < MAX_RECEIVE_SEQUENCE; i++) {
        bool ret = IsPassSeqCheck(&seqInfo, recvSeq[i]);
        if (i >= 2) {
            EXPECT_EQ(ret, true);
        } else {
            EXPECT_EQ(ret, false);
        }
    }
}

/**
 * @tc.name: Softbus_SeqVerifyTest_Test_LessThanMinCase_002
 * @tc.desc: Verify abnormal seq, minSeq negative.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceVerificationTest, Softbus_SeqVerifyTest_Test_LessThanMinCase_002, TestSize.Level0)
{
    SeqVerifyInfo seqInfo = { 0 };
    seqInfo.minSeq = -10;
    seqInfo.maxSeq = -10;
    int32_t recvSeq[MAX_RECEIVE_SEQUENCE] = { -15, -12, 10, 1, 3 };
    for (int32_t i = 0; i < MAX_RECEIVE_SEQUENCE; i++) {
        bool ret = IsPassSeqCheck(&seqInfo, recvSeq[i]);
        if (i >= 2) {
            EXPECT_EQ(ret, true);
        } else {
            EXPECT_EQ(ret, false);
        }
    }
}

/**
 * @tc.name: Softbus_SeqVerifyTest_Test_LessThanMinCase_003
 * @tc.desc: Verify abnormal seq, minSeq negative.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceVerificationTest, Softbus_SeqVerifyTest_Test_LessThanMinCase_003, TestSize.Level0)
{
    SeqVerifyInfo seqInfo = { 0 };
    seqInfo.minSeq = -10;
    seqInfo.maxSeq = 10;
    int32_t recvSeq[MAX_RECEIVE_SEQUENCE] = { -15, -12, 10, 1, 3 };
    for (int32_t i = 0; i < MAX_RECEIVE_SEQUENCE; i++) {
        bool ret = IsPassSeqCheck(&seqInfo, recvSeq[i]);
        if (i >= 2) {
            EXPECT_EQ(ret, true);
        } else {
            EXPECT_EQ(ret, false);
        }
    }
}

/**
 * @tc.name: Softbus_SeqVerifyTest_Test_LessThanMinCase_004
 * @tc.desc: Verify abnormal seq, minSeq negative.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceVerificationTest, Softbus_SeqVerifyTest_Test_LessThanMinCase_004, TestSize.Level0)
{
    SeqVerifyInfo seqInfo = { 0 };
    seqInfo.minSeq = INT32_MAX - 2;
    seqInfo.maxSeq = INT32_MIN + 10;
    int32_t recvSeq[MAX_RECEIVE_SEQUENCE] = { INT32_MAX - 10, INT32_MAX - 5, 0, 1, 3 };
    for (int32_t i = 0; i < MAX_RECEIVE_SEQUENCE; i++) {
        bool ret = IsPassSeqCheck(&seqInfo, recvSeq[i]);
        EXPECT_EQ(ret, false);
    }
}
} // namespace OHOS