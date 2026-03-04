/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <string>
#include <vector>
#include <cstring>

#include "comm_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_tlv_utils.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
class TlvFrame {
public:
    int type_;
    string value_;

    TlvFrame(int type, string value) : type_(type), value_(value) {}
};

class SoftBusTlvUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void) { }
    static void TearDownTestCase(void) { }
};

static string BytesToHexString(const uint8_t *data, uint32_t len)
{
    std::stringstream hexStream;
    for (uint32_t i = 0; i < len; i++) {
        hexStream << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<uint32_t>(data[i]) << ", ";
    }
    return hexStream.str();
}

static void TLvFeatureTest(uint8_t tSize, uint8_t lSize, vector<TlvFrame> &testcases)
{
    COMM_LOGI(COMM_UTILS, "tSize=%{public}u, lSize=%{public}u", tSize, lSize);
    int32_t ret;
    TlvObject *sendObj = CreateTlvObject(tSize, lSize);
    ASSERT_TRUE(sendObj != nullptr);
    for (auto testcase: testcases) {
        COMM_LOGI(COMM_UTILS, "t=%{public}d, l=%{public}d, v=%{public}s",
            testcase.type_, (int)testcase.value_.length(), testcase.value_.c_str());
        ret = AddTlvMember(sendObj, testcase.type_,
            testcase.value_.length(), (const uint8_t *)testcase.value_.c_str());
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
    uint8_t *output = nullptr;
    uint32_t outputSize = 0;
    ret = GetTlvBinary(sendObj, &output, &outputSize);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DestroyTlvObject(sendObj);

    COMM_LOGI(COMM_UTILS, "output=%{public}s, outputSize=%{public}u",
        BytesToHexString(output, outputSize).c_str(), outputSize);

    uint32_t length = 0;
    uint8_t *value = nullptr;
    TlvObject *recvObj = CreateTlvObject(tSize, lSize);
    ASSERT_TRUE(recvObj != nullptr);
    ret = SetTlvBinary(recvObj, output, outputSize);
    EXPECT_EQ(ret, SOFTBUS_OK);

    for (auto testcase: testcases) {
        ret = GetTlvMember(recvObj, testcase.type_, &length, &value);
        EXPECT_EQ(ret, SOFTBUS_OK);
        ASSERT_EQ(length, testcase.value_.length());
        EXPECT_EQ(memcmp(value, testcase.value_.c_str(), length), 0);
    }
    DestroyTlvObject(recvObj);
    SoftBusFree(output);
}

/*
 * @tc.name: TlvUtilsNormalUsage
 * @tc.desc: Verify TLV utility functions work correctly with various test cases including single/multiple TLV frames
 *           and different type length combinations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusTlvUtilsTest, TlvUtilsNormalUsage, TestSize.Level0)
{
    COMM_LOGI(COMM_UTILS, "===TlvUtilsNormalUsage begin");
    vector<vector<TlvFrame>> tlvFrameTestcases = {
        // 1.only one tlv frame, length = 0
        { TlvFrame(1, "") },
        // 2.only one tlv frame, length > 0
        { TlvFrame(1, "test1") },
        // 3.many tlv frames, length = 0
        { TlvFrame(1, ""), TlvFrame(2, ""), TlvFrame(3, "") },
        // 4.many tlv frames, length >= 0
        { TlvFrame(1, "test1"), TlvFrame(2, ""), TlvFrame(3, "test3") },
        // 5.many tlv frames, all length > 0
        { TlvFrame(1, "test1"), TlvFrame(2, "test2"), TlvFrame(3, "test3") },
    };

    for (auto frame: tlvFrameTestcases) {
        TLvFeatureTest(UINT8_T, UINT8_T, frame);
        TLvFeatureTest(UINT8_T, UINT16_T, frame);
        TLvFeatureTest(UINT8_T, UINT32_T, frame);
        TLvFeatureTest(UINT16_T, UINT8_T, frame);
        TLvFeatureTest(UINT16_T, UINT16_T, frame);
        TLvFeatureTest(UINT16_T, UINT32_T, frame);
        TLvFeatureTest(UINT32_T, UINT8_T, frame);
        TLvFeatureTest(UINT32_T, UINT16_T, frame);
        TLvFeatureTest(UINT32_T, UINT32_T, frame);
    }
    COMM_LOGI(COMM_UTILS, "===TlvUtilsNormalUsage end");
}

/*
 * @tc.name: TlvUtilsPackTlvTest
 * @tc.desc: Verify TlvUtilsPackTlv works correctly with valid input parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusTlvUtilsTest, TlvUtilsPackTlvTest, TestSize.Level0)
{
    COMM_LOGI(COMM_UTILS, "===TlvUtilsPackTlvTest begin");
    // mock ts=UINT16_T ls=UINT16_T
    TlvFrame frame1 = TlvFrame(1024, "test1024");
    TlvFrame frame2 = TlvFrame(2048, "test2048");
    uint8_t tlvBytes[] = {
        0x00, 0x04, 0x08, 0x00, 0x74, 0x65, 0x73, 0x74, 0x31, 0x30, 0x32, 0x34, // frame1
        0x00, 0x08, 0x08, 0x00, 0x74, 0x65, 0x73, 0x74, 0x32, 0x30, 0x34, 0x38  // frame2
    };
    // usage1: add one tlv frame
    TlvObject *obj = CreateTlvObject(UINT16_T, UINT16_T);
    ASSERT_TRUE(obj != nullptr);
    int32_t ret = AddTlvMember(obj, frame1.type_, frame1.value_.length(), (const uint8_t *)frame1.value_.c_str());
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint8_t *output = nullptr;
    uint32_t outputSize = 0;
    ret = GetTlvBinary(obj, &output, &outputSize);
    EXPECT_EQ(ret, SOFTBUS_OK);
    COMM_LOGI(COMM_UTILS, "output=%{public}s, outputSize=%{public}u",
        BytesToHexString(output, outputSize).c_str(), outputSize);
    ASSERT_EQ(outputSize, 12); // 12: UINT16_T + UINT16_T + strlen("test1024")
    EXPECT_EQ(memcmp(output, tlvBytes, outputSize), 0);
    SoftBusFree(output);
    output = nullptr;

    // usage2: append one tlv frame after GetTlvBinary
    ret = AddTlvMember(obj, frame2.type_, frame2.value_.length(), (const uint8_t *)frame2.value_.c_str());
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetTlvBinary(obj, &output, &outputSize);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DestroyTlvObject(obj);

    COMM_LOGI(COMM_UTILS, "output=%{public}s, outputSize=%{public}u",
        BytesToHexString(output, outputSize).c_str(), outputSize);
    ASSERT_EQ(outputSize, sizeof(tlvBytes));
    EXPECT_EQ(memcmp(output, tlvBytes, outputSize), 0);
    SoftBusFree(output);
    output = nullptr;
    // usage3: append new tlv frame after SetTlvBinary
    obj = CreateTlvObject(UINT16_T, UINT16_T);
    ASSERT_TRUE(obj != nullptr);
    ret = SetTlvBinary(obj, tlvBytes, 12); // 12: UINT16_T + UINT16_T + strlen("test1024")
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddTlvMember(obj, frame2.type_, frame2.value_.length(), (const uint8_t *)frame2.value_.c_str());
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetTlvBinary(obj, &output, &outputSize);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DestroyTlvObject(obj);

    COMM_LOGI(COMM_UTILS, "output=%{public}s, outputSize=%{public}u",
        BytesToHexString(output, outputSize).c_str(), outputSize);
    ASSERT_EQ(outputSize, sizeof(tlvBytes));
    EXPECT_EQ(memcmp(output, tlvBytes, outputSize), 0);
    SoftBusFree(output);
    output = nullptr;
    COMM_LOGI(COMM_UTILS, "===TlvUtilsPackTlvTest end");
}

/*
 * @tc.name: TlvUtilsUnpackTlvTest
 * @tc.desc: Verify TlvUtilsUnpackTlv works correctly with valid input parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusTlvUtilsTest, TlvUtilsUnpackTlvTest, TestSize.Level0)
{
    COMM_LOGI(COMM_UTILS, "===TlvUtilsUnpackTlvTest begin");
    // mock ts=UINT16_T ls=UINT16_T
    TlvFrame frame1 = TlvFrame(1024, "test1024");
    TlvFrame frame2 = TlvFrame(2048, "test2048");
    uint8_t tlvBytes[] = {
        0x00, 0x04, 0x08, 0x00, 0x74, 0x65, 0x73, 0x74, 0x31, 0x30, 0x32, 0x34, // frame1
        0x00, 0x08, 0x08, 0x00, 0x74, 0x65, 0x73, 0x74, 0x32, 0x30, 0x34, 0x38  // frame2
    };
    // usage 1: parse only one tlv frame
    TlvObject *obj = CreateTlvObject(UINT16_T, UINT16_T);
    ASSERT_TRUE(obj != nullptr);
    int32_t ret = SetTlvBinary(obj, tlvBytes, 12); // 12: UINT16_T + UINT16_T + strlen("test1024")
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint32_t length = 0;
    uint8_t *value = nullptr;
    ret = GetTlvMember(obj, frame1.type_, &length, &value);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ASSERT_EQ(length, frame1.value_.length());
    EXPECT_EQ(memcmp(value, frame1.value_.c_str(), length), 0);
    DestroyTlvObject(obj);
    // usage 2: parse two tlv frames
    obj = CreateTlvObject(UINT16_T, UINT16_T);
    ASSERT_TRUE(obj != nullptr);
    ret = SetTlvBinary(obj, tlvBytes, sizeof(tlvBytes));
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetTlvMember(obj, frame1.type_, &length, &value);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ASSERT_EQ(length, frame1.value_.length());
    EXPECT_EQ(memcmp(value, frame1.value_.c_str(), length), 0);
    ret = GetTlvMember(obj, frame2.type_, &length, &value);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ASSERT_EQ(length, frame2.value_.length());
    EXPECT_EQ(memcmp(value, frame2.value_.c_str(), length), 0);
    DestroyTlvObject(obj);
    COMM_LOGI(COMM_UTILS, "===TlvUtilsUnpackTlvTest end");
}

typedef struct {
    uint32_t type;
    union {
        uint8_t u8;
        uint16_t u16;
        uint32_t u32;
        uint64_t u64;
    };
} TlvNumberFrame;

/*
 * @tc.name: TlvUtilsPackNumberTest
 * @tc.desc: Verify TlvUtilsPackNumber works correctly with valid input parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusTlvUtilsTest, TlvUtilsPackNumberTest, TestSize.Level0)
{
    COMM_LOGI(COMM_UTILS, "===TlvUtilsPackNumberTest begin");
    // mock ts=UINT16_T ls=UINT16_T
    TlvNumberFrame tlvFrames[] = {
        { .type = 0x08, .u8 = 0x1F },
        { .type = 0x16, .u16 = 0x2FF },
        { .type = 0x32, .u32 = 0x3FFF },
        { .type = 0x64, .u64 = 0x4FFFF },
    };
    uint8_t tlvBytes[] = {
        0x08, 0x00, 0x01, 0x00, 0x1F, // .type = 0x08, .u8 = 0x1F
        0x16, 0x00, 0x02, 0x00, 0xFF, 0x02, // .type = 0x16, .u16 = 0x2FF
        0x32, 0x00, 0x04, 0x00, 0xFF, 0x3F, 0x00, 0x00, // .type = 0x32, .u32 = 0x3FFF
        0x64, 0x00, 0x08, 0x00, 0xFF, 0xFF, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00 // .type = 0x64, .u64 = 0x4FFFF
    };

    TlvObject *obj = CreateTlvObject(UINT16_T, UINT16_T);
    ASSERT_TRUE(obj != nullptr);

    int32_t ret = AddTlvMemberU8(obj, tlvFrames[0].type, tlvFrames[0].u8);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddTlvMemberU16(obj, tlvFrames[1].type, tlvFrames[1].u16);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddTlvMemberU32(obj, tlvFrames[2].type, tlvFrames[2].u32);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddTlvMemberU64(obj, tlvFrames[3].type, tlvFrames[3].u64);
    EXPECT_EQ(ret, SOFTBUS_OK);

    uint8_t *output = nullptr;
    uint32_t outputSize = 0;
    ret = GetTlvBinary(obj, &output, &outputSize);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DestroyTlvObject(obj);

    COMM_LOGI(COMM_UTILS, "output=%{public}s, outputSize=%{public}u",
        BytesToHexString(output, outputSize).c_str(), outputSize);
    ASSERT_EQ(outputSize, sizeof(tlvBytes));
    EXPECT_EQ(memcmp(output, tlvBytes, outputSize), 0);
    SoftBusFree(output);
    output = nullptr;
    COMM_LOGI(COMM_UTILS, "===TlvUtilsPackNumberTest end");
}

/*
 * @tc.name: TlvUtilsUnpackNumberTest
 * @tc.desc: Verify TlvUtilsUnpackNumber works correctly with valid input parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusTlvUtilsTest, TlvUtilsUnpackNumberTest, TestSize.Level0)
{
    COMM_LOGI(COMM_UTILS, "===TlvUtilsUnpackNumberTest begin");
    // mock ts=UINT16_T ls=UINT16_T
    TlvNumberFrame tlvFrames[] = {
        { .type = 0x08, .u8 = 0x1F },
        { .type = 0x16, .u16 = 0x2FF },
        { .type = 0x32, .u32 = 0x3FFF },
        { .type = 0x64, .u64 = 0x4FFFF },
    };
    uint8_t tlvBytes[] = {
        0x08, 0x00, 0x01, 0x00, 0x1F, // .type = 0x08, .u8 = 0x1F
        0x16, 0x00, 0x02, 0x00, 0xFF, 0x02, // .type = 0x16, .u16 = 0x2FF
        0x32, 0x00, 0x04, 0x00, 0xFF, 0x3F, 0x00, 0x00, // .type = 0x32, .u32 = 0x3FFF
        0x64, 0x00, 0x08, 0x00, 0xFF, 0xFF, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00 // .type = 0x64, .u64 = 0x4FFFF
    };

    TlvObject *obj = CreateTlvObject(UINT16_T, UINT16_T);
    ASSERT_TRUE(obj != nullptr);
    int32_t ret = SetTlvBinary(obj, tlvBytes, sizeof(tlvBytes));
    EXPECT_EQ(ret, SOFTBUS_OK);

    uint8_t u8 = 0;
    ret = GetTlvMemberU8(obj, tlvFrames[0].type, &u8);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(u8, tlvFrames[0].u8);
    uint16_t u16 = 0;
    ret = GetTlvMemberU16(obj, tlvFrames[1].type, &u16);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(u16, tlvFrames[1].u16);
    uint32_t u32 = 0;
    ret = GetTlvMemberU32(obj, tlvFrames[2].type, &u32);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(u32, tlvFrames[2].u32);
    uint64_t u64 = 0;
    ret = GetTlvMemberU64(obj, tlvFrames[3].type, &u64);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(u64, tlvFrames[3].u64);

    DestroyTlvObject(obj);
    COMM_LOGI(COMM_UTILS, "===TlvUtilsUnpackNumberTest end");
}

/*
 * @tc.name: GetTlvMemberWithBuffer
 * @tc.desc: Verify GetTlvMemberWithBuffer works correctly with valid input parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusTlvUtilsTest, TlvUtilsGetTlvMemberWithBufferTest, TestSize.Level0)
{
    COMM_LOGI(COMM_UTILS, "===TlvUtilsGetTlvMemberWithBufferTest begin");
    // mock ts=UINT16_T ls=UINT16_T
    const uint32_t type1 = 1;
    const uint8_t value1[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    const uint32_t type2 = 2;
    const char value2[] = "test1024";
    const uint32_t type3 = 3;
    uint8_t tlvBytes[] = {
        0x01, 0x00, 0x06, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // type=1, len=6 MAC
        0x02, 0x00, 0x08, 0x00, 0x74, 0x65, 0x73, 0x74, 0x31, 0x30, 0x32, 0x34, // type=2, len=6, NAME
        0x03, 0x00, 0x00, 0x00, // type=3, len=0, empty
    };

    TlvObject *obj = CreateTlvObject(UINT16_T, UINT16_T);
    ASSERT_TRUE(obj != nullptr);
    int32_t ret = SetTlvBinary(obj, tlvBytes, sizeof(tlvBytes));
    EXPECT_EQ(ret, SOFTBUS_OK);

    uint8_t mac[6] = {0}; // 6: mac size
    ret = GetTlvMemberWithSpecifiedBuffer(obj, type1, mac, sizeof(mac));
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(memcmp(value1, mac, sizeof(mac)), 0);

    uint8_t name[16] = {}; // 16: max name len
    uint32_t nameSize = sizeof(name);
    ret = GetTlvMemberWithEstimatedBuffer(obj, type2, name, &nameSize);
    EXPECT_EQ(ret, SOFTBUS_OK);
    for (uint32_t i = 0; i < nameSize; i++) {
        GTEST_LOG_(INFO) << "name=" << name[i];
    }
    EXPECT_EQ(memcmp(value2, name, nameSize), 0);

    uint32_t empty = 0;
    uint8_t emptyBuf[16] = {0}; // 16: not use
    ret = GetTlvMemberWithEstimatedBuffer(obj, type3, emptyBuf, &empty);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(empty, 0);

    DestroyTlvObject(obj);
    COMM_LOGI(COMM_UTILS, "===TlvUtilsGetTlvMemberWithBufferTest end");
}

/*
 * @tc.name: TlvUtilsExceptionDataTest
 * @tc.desc: Verify TlvUtilsExceptionDataTest works correctly with valid input parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusTlvUtilsTest, TlvUtilsExceptionDataTest, TestSize.Level0)
{
    COMM_LOGI(COMM_UTILS, "===TlvUtilsExceptionDataTest begin");
    // mock ts=UINT16_T ls=UINT16_T
    uint8_t tlvBytes[] = {
        0x01, 0x00, 0x08, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // type=1, len=8, value=6
    };

    TlvObject *obj = CreateTlvObject(UINT16_T, UINT16_T);
    ASSERT_TRUE(obj != nullptr);
    int32_t ret = SetTlvBinary(obj, tlvBytes, sizeof(tlvBytes));
    EXPECT_EQ(ret, SOFTBUS_NO_ENOUGH_DATA);

    DestroyTlvObject(obj);
    COMM_LOGI(COMM_UTILS, "===TlvUtilsExceptionDataTest end");
}

/*
 * @tc.name: TlvUtilsCreateTlvObject_InvalidTSize
 * @tc.desc: Verify CreateTlvObject returns nullptr when tSize is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusTlvUtilsTest, TlvUtilsCreateTlvObject_InvalidTSize, TestSize.Level1)
{
    TlvObject *obj = CreateTlvObject(0, UINT8_T); // Invalid tSize
    EXPECT_EQ(obj, nullptr);
    obj = CreateTlvObject(UINT32_T + 1, UINT8_T); // Invalid tSize
    EXPECT_EQ(obj, nullptr);
}

/*
 * @tc.name: TlvUtilsCreateTlvObject_InvalidLSize
 * @tc.desc: Verify CreateTlvObject returns nullptr when lSize is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusTlvUtilsTest, TlvUtilsCreateTlvObject_InvalidLSize, TestSize.Level1)
{
    TlvObject *obj = CreateTlvObject(UINT8_T, 0); // Invalid lSize
    EXPECT_EQ(obj, nullptr);
    obj = CreateTlvObject(UINT8_T, UINT32_T + 1); // Invalid lSize
    EXPECT_EQ(obj, nullptr);
}

/*
 * @tc.name: TlvUtilsDestroyTlvObject_Null
 * @tc.desc: Verify DestroyTlvObject handles nullptr gracefully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusTlvUtilsTest, TlvUtilsDestroyTlvObject_Null, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(DestroyTlvObject(nullptr));
}

/*
 * @tc.name: TlvUtilsAddTlvMember_NullObj
 * @tc.desc: Verify AddTlvMember returns SOFTBUS_INVALID_PARAM when obj is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusTlvUtilsTest, TlvUtilsAddTlvMember_NullObj, TestSize.Level1)
{
    int32_t ret = AddTlvMember(nullptr, 1, 4, reinterpret_cast<const uint8_t *>("test"));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TlvUtilsAddTlvMember_InvalidLength
 * @tc.desc: Verify AddTlvMember returns SOFTBUS_INVALID_PARAM when length is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusTlvUtilsTest, TlvUtilsAddTlvMember_InvalidLength, TestSize.Level1)
{
    TlvObject *obj = CreateTlvObject(UINT8_T, UINT8_T);
    ASSERT_TRUE(obj != nullptr);
    int32_t ret = AddTlvMember(obj, 1, MAX_VALUE_LENGTH + 1, reinterpret_cast<const uint8_t *>("test"));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    EXPECT_NO_FATAL_FAILURE(DestroyTlvObject(obj));
}

/*
 * @tc.name: TlvUtilsAddTlvMember_NullValueWithLength
 * @tc.desc: Verify AddTlvMember returns SOFTBUS_INVALID_PARAM when value is nullptr but length > 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusTlvUtilsTest, TlvUtilsAddTlvMember_NullValueWithLength, TestSize.Level1)
{
    TlvObject *obj = CreateTlvObject(UINT8_T, UINT8_T);
    ASSERT_TRUE(obj != nullptr);
    int32_t ret = AddTlvMember(obj, 1, 4, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    EXPECT_NO_FATAL_FAILURE(DestroyTlvObject(obj));
}

/*
 * @tc.name: TlvUtilsGetTlvMember_NotFound
 * @tc.desc: Verify GetTlvMember returns SOFTBUS_NOT_FIND when type is not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusTlvUtilsTest, TlvUtilsGetTlvMember_NotFound, TestSize.Level1)
{
    TlvObject *obj = CreateTlvObject(UINT8_T, UINT8_T);
    ASSERT_TRUE(obj != nullptr);
    uint32_t length = 0;
    uint8_t *value = nullptr;
    int32_t ret = GetTlvMember(obj, 999, &length, &value);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    EXPECT_NO_FATAL_FAILURE(DestroyTlvObject(obj));
}

/*
 * @tc.name: TlvUtilsGetTlvBinary_NoMembers
 * @tc.desc: Verify GetTlvBinary returns SOFTBUS_NOT_FIND when object has no members
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusTlvUtilsTest, TlvUtilsGetTlvBinary_NoMembers, TestSize.Level1)
{
    TlvObject *obj = CreateTlvObject(UINT8_T, UINT8_T);
    ASSERT_TRUE(obj != nullptr);
    uint8_t *output = nullptr;
    uint32_t outputSize = 0;
    int32_t ret = GetTlvBinary(obj, &output, &outputSize);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    EXPECT_NO_FATAL_FAILURE(DestroyTlvObject(obj));
}

/*
 * @tc.name: TlvUtilsGetTlvBinary_NullParams
 * @tc.desc: Verify GetTlvBinary returns SOFTBUS_INVALID_PARAM when parameters are nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusTlvUtilsTest, TlvUtilsGetTlvBinary_NullParams, TestSize.Level1)
{
    TlvObject *obj = CreateTlvObject(UINT8_T, UINT8_T);
    ASSERT_TRUE(obj != nullptr);
    uint8_t *output = nullptr;
    uint32_t outputSize = 0;
    int32_t ret = GetTlvBinary(nullptr, &output, &outputSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetTlvBinary(obj, nullptr, &outputSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetTlvBinary(obj, &output, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    EXPECT_NO_FATAL_FAILURE(DestroyTlvObject(obj));
}

/*
 * @tc.name: TlvUtilsSetTlvBinary_InvalidSize
 * @tc.desc: Verify SetTlvBinary returns SOFTBUS_INVALID_DATA_HEAD when inputSize is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusTlvUtilsTest, TlvUtilsSetTlvBinary_InvalidSize, TestSize.Level1)
{
    TlvObject *obj = CreateTlvObject(UINT8_T, UINT8_T);
    ASSERT_TRUE(obj != nullptr);
    uint8_t input[] = {0x01, 0x04};
    int32_t ret = SetTlvBinary(obj, input, MAX_TLV_BINARY_LENGTH + 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_DATA_HEAD);
    EXPECT_NO_FATAL_FAILURE(DestroyTlvObject(obj));
}

/*
 * @tc.name: TlvUtilsSetTlvBinary_NullParams
 * @tc.desc: Verify SetTlvBinary returns SOFTBUS_INVALID_PARAM when parameters are nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusTlvUtilsTest, TlvUtilsSetTlvBinary_NullParams, TestSize.Level1)
{
    TlvObject *obj = CreateTlvObject(UINT8_T, UINT8_T);
    ASSERT_TRUE(obj != nullptr);
    uint8_t input[] = {0x01, 0x04};
    int32_t ret = SetTlvBinary(nullptr, input, sizeof(input));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SetTlvBinary(obj, nullptr, sizeof(input));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    EXPECT_NO_FATAL_FAILURE(DestroyTlvObject(obj));
}

/*
 * @tc.name: TlvUtilsGetTlvMemberWithSpecifiedBuffer_SizeMismatch
 * @tc.desc: Verify GetTlvMemberWithSpecifiedBuffer returns SOFTBUS_INVALID_PARAM when size doesn't match
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusTlvUtilsTest, TlvUtilsGetTlvMemberWithSpecifiedBuffer_SizeMismatch, TestSize.Level1)
{
    TlvObject *obj = CreateTlvObject(UINT8_T, UINT8_T);
    ASSERT_TRUE(obj != nullptr);
    AddTlvMember(obj, 1, 4, reinterpret_cast<const uint8_t *>("test"));
    uint8_t buffer[10] = {0};
    int32_t ret = GetTlvMemberWithSpecifiedBuffer(obj, 1, buffer, 10); // Wrong size
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    EXPECT_NO_FATAL_FAILURE(DestroyTlvObject(obj));
}

/*
 * @tc.name: TlvUtilsGetTlvMemberWithEstimatedBuffer_NullParams
 * @tc.desc: Verify GetTlvMemberWithEstimatedBuffer returns SOFTBUS_INVALID_PARAM when parameters are nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusTlvUtilsTest, TlvUtilsGetTlvMemberWithEstimatedBuffer_NullParams, TestSize.Level1)
{
    TlvObject *obj = CreateTlvObject(UINT8_T, UINT8_T);
    ASSERT_TRUE(obj != nullptr);
    uint8_t buffer[10] = {0};
    uint32_t size = 0;
    int32_t ret = GetTlvMemberWithEstimatedBuffer(nullptr, 1, buffer, &size);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetTlvMemberWithEstimatedBuffer(obj, 1, nullptr, &size);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetTlvMemberWithEstimatedBuffer(obj, 1, buffer, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    EXPECT_NO_FATAL_FAILURE(DestroyTlvObject(obj));
}

/*
 * @tc.name: TlvUtilsAddGetTlvMemberU8
 * @tc.desc: Verify AddTlvMemberU8 and GetTlvMemberU8 work correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusTlvUtilsTest, TlvUtilsAddGetTlvMemberU8, TestSize.Level1)
{
    TlvObject *obj = CreateTlvObject(UINT8_T, UINT8_T);
    ASSERT_TRUE(obj != nullptr);
    int32_t ret = AddTlvMemberU8(obj, 1, 0xAB);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint8_t value;
    ret = GetTlvMemberU8(obj, 1, &value);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(value, 0xAB);
    EXPECT_NO_FATAL_FAILURE(DestroyTlvObject(obj));
}

/*
 * @tc.name: TlvUtilsAddGetTlvMemberU16
 * @tc.desc: Verify AddTlvMemberU16 and GetTlvMemberU16 work correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusTlvUtilsTest, TlvUtilsAddGetTlvMemberU16, TestSize.Level1)
{
    TlvObject *obj = CreateTlvObject(UINT8_T, UINT8_T);
    ASSERT_TRUE(obj != nullptr);
    int32_t ret = AddTlvMemberU16(obj, 1, 0xABCD);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint16_t value;
    ret = GetTlvMemberU16(obj, 1, &value);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(value, 0xABCD);
    EXPECT_NO_FATAL_FAILURE(DestroyTlvObject(obj));
}

/*
 * @tc.name: TlvUtilsAddGetTlvMemberU32
 * @tc.desc: Verify AddTlvMemberU32 and GetTlvMemberU32 work correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusTlvUtilsTest, TlvUtilsAddGetTlvMemberU32, TestSize.Level1)
{
    TlvObject *obj = CreateTlvObject(UINT8_T, UINT8_T);
    ASSERT_TRUE(obj != nullptr);
    int32_t ret = AddTlvMemberU32(obj, 1, 0xABCD1234);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint32_t value;
    ret = GetTlvMemberU32(obj, 1, &value);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(value, 0xABCD1234u);
    EXPECT_NO_FATAL_FAILURE(DestroyTlvObject(obj));
}

/*
 * @tc.name: TlvUtilsAddGetTlvMemberU64
 * @tc.desc: Verify AddTlvMemberU64 and GetTlvMemberU64 work correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusTlvUtilsTest, TlvUtilsAddGetTlvMemberU64, TestSize.Level1)
{
    TlvObject *obj = CreateTlvObject(UINT8_T, UINT8_T);
    ASSERT_TRUE(obj != nullptr);
    int32_t ret = AddTlvMemberU64(obj, 1, 0xABCD1234567890EF);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint64_t value;
    ret = GetTlvMemberU64(obj, 1, &value);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(value, 0xABCD1234567890EF);
    EXPECT_NO_FATAL_FAILURE(DestroyTlvObject(obj));
}
} // namespace OHOS
