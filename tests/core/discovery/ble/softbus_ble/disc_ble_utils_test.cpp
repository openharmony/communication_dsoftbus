/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <securec.h>

#include "disc_ble_constant.h"
#include "disc_ble_utils.h"
#include "disc_log.h"
#include "softbus_broadcast_type.h"
#include "softbus_error_code.h"

static uint8_t g_vaildAdvData[] = { 0x04, 0x05, 0x10, 0x00, 0x00, 0x02, 0x00, 0x18, 0xE8, 0x31, 0xF7, 0x63, 0x0B, 0x76,
    0x19, 0xAE, 0x21, 0x0E, 0x56, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E };
static uint8_t g_vaildRspData[] = { 0x0F, 0x43, 0x01, 0xAA, 0x00, 0x61, 0x01, 0x3A, 0x4D, 0x79, 0x20, 0x44, 0x65, 0x76,
    0x69, 0x63, 0x65, 0x00 };

static uint8_t g_invalidAdvData[] = { 0x00, 0x00 };
static uint8_t g_invalidRspData[] = { 0x00, 0x00 };

using namespace testing::ext;
namespace OHOS {
class DiscBleUtilsTest : public testing::Test {
public:
    DiscBleUtilsTest() { }
    ~DiscBleUtilsTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};
void DiscBleUtilsTest::SetUpTestCase(void) { }

void DiscBleUtilsTest::TearDownTestCase(void) { }

/*
 * @tc.name: CheckBitMapEmptyTest_001
 * @tc.desc: Test CheckBitMapEmpty should return true when all capBitMap are 0.
 * @tc.type: FUNC
 * @tc.require:Check bitMap is empty
 */
HWTEST_F(DiscBleUtilsTest, CheckBitMapEmptyTest_001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, CheckBitMapEmptyTest_001, Start");

    DeviceInfo info = { { 0 } };
    info.capabilityBitmapNum = DISC_MAX_CAPABILITY_NUM;

    bool ret = CheckBitMapEmpty(info.capabilityBitmapNum, info.capabilityBitmap);
    EXPECT_TRUE(ret);

    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, CheckBitMapEmptyTest_001, End");
}

/*
 * @tc.name: CheckBitMapEmptyTest_002
 * @tc.desc: Test CheckBitMapEmpty should return false when capBitMap is not 0.
 * @tc.type: FUNC
 * @tc.require:Check bitMap is not empty
 */
HWTEST_F(DiscBleUtilsTest, CheckBitMapEmptyTest_002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, CheckBitMapEmptyTest_002, Start");

    DeviceInfo info = { { 0 } };
    info.capabilityBitmapNum = DISC_MAX_CAPABILITY_NUM;
    uint32_t pos = INT32_MAX_BIT_NUM;
    SetCapBitMapPos(info.capabilityBitmapNum, info.capabilityBitmap, pos);

    bool ret = CheckBitMapEmpty(info.capabilityBitmapNum, info.capabilityBitmap);
    EXPECT_FALSE(ret);

    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, CheckBitMapEmptyTest_002, End");
}

/*
 * @tc.name: CheckCapBitMapExistTest_001
 * @tc.desc: Test CheckCapBitMapExist should return false when pos greater than or equal to capBitMapNum
 * @tc.type: FUNC
 * @tc.require:Check cap bitMap pos is invaild
 */
HWTEST_F(DiscBleUtilsTest, CheckCapBitMapExistTest_001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, CheckCapBitMapExistTest_001, Start");

    DeviceInfo info = { { 0 } };
    info.capabilityBitmapNum = DISC_MAX_CAPABILITY_NUM;
    uint32_t pos = info.capabilityBitmapNum * INT32_MAX_BIT_NUM;

    bool ret = CheckCapBitMapExist(info.capabilityBitmapNum, info.capabilityBitmap, pos);
    EXPECT_FALSE(ret);

    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, CheckCapBitMapExistTest_001, End");
}

/*
 * @tc.name: CheckCapBitMapExistTest_002
 * @tc.desc: Test CheckCapBitMapExist should return false when capBitMap is all 0.
 * @tc.type: FUNC
 * @tc.require:Check cap bitMap not exist
 */
HWTEST_F(DiscBleUtilsTest, CheckCapBitMapExistTest_002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, CheckCapBitMapExistTest_002, Start");

    DeviceInfo info = { { 0 } };
    info.capabilityBitmapNum = DISC_MAX_CAPABILITY_NUM;
    uint32_t pos = INT32_MAX_BIT_NUM;

    bool ret = CheckCapBitMapExist(info.capabilityBitmapNum, info.capabilityBitmap, pos);
    EXPECT_FALSE(ret);

    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, CheckCapBitMapExistTest_002, End");
}

/*
 * @tc.name: CheckCapBitMapExistTest_003
 * @tc.desc: Test CheckCapBitMapExist should return true when the pos offset in capBitMap is 1
 * @tc.type: FUNC
 * @tc.require:Check cap bitMap pos offset exist
 */
HWTEST_F(DiscBleUtilsTest, CheckCapBitMapExistTest_003, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, CheckCapBitMapExistTest_003, Start");

    DeviceInfo info = { { 0 } };
    info.capabilityBitmapNum = DISC_MAX_CAPABILITY_NUM;
    uint32_t pos = INT32_MAX_BIT_NUM;
    SetCapBitMapPos(info.capabilityBitmapNum, info.capabilityBitmap, pos);

    bool ret = CheckCapBitMapExist(info.capabilityBitmapNum, info.capabilityBitmap, pos);
    EXPECT_TRUE(ret);

    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, CheckCapBitMapExistTest_003, End");
}

/*
 * @tc.name: SetCapBitMapPosTest_001
 * @tc.desc: Test SetCapBitMapPos should failed when pos greater than or equal to capBitMapNum.
 * @tc.type: FUNC
 * @tc.require:Set cap bitMap pos is invaild
 */
HWTEST_F(DiscBleUtilsTest, SetCapBitMapPosTest_001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, SetCapBitMapPosTest_001, Start");

    DeviceInfo info = { { 0 } };
    info.capabilityBitmapNum = DISC_MAX_CAPABILITY_NUM;
    uint32_t pos = info.capabilityBitmapNum * INT32_MAX_BIT_NUM;
    SetCapBitMapPos(info.capabilityBitmapNum, info.capabilityBitmap, pos);

    for (int32_t i = 0; i < info.capabilityBitmapNum; i++) {
        EXPECT_EQ(info.capabilityBitmap[i], 0x0);
    }

    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, SetCapBitMapPosTest_001, End");
}

/*
 * @tc.name: SetCapBitMapPosTest_002
 * @tc.desc: Test SetCapBitMapPos should success when set cap bit map at pos offset.
 * @tc.type: FUNC
 * @tc.require:Set cap bitMap at pos offset success
 */
HWTEST_F(DiscBleUtilsTest, SetCapBitMapPosTest_002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, SetCapBitMapPosTest_002, Start");

    DeviceInfo info = { { 0 } };
    info.capabilityBitmapNum = DISC_MAX_CAPABILITY_NUM;
    uint32_t pos = INT32_MAX_BIT_NUM;

    SetCapBitMapPos(info.capabilityBitmapNum, info.capabilityBitmap, pos);
    for (int32_t i = 0; i < info.capabilityBitmapNum; i++) {
        if (i == (pos / INT32_MAX_BIT_NUM)) {
            EXPECT_EQ(info.capabilityBitmap[i], 0x1);
        } else {
            EXPECT_EQ(info.capabilityBitmap[i], 0x0);
        }
    }

    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, SetCapBitMapPosTest_002, End");
}

/*
 * @tc.name: UnsetCapBitMapPosTest_001
 * @tc.desc: Test UnsetCapBitMapPos should failed when pos greater than or equal to capBitMapNum.
 * @tc.type: FUNC
 * @tc.require:Unset cap bitMap pos is invaild
 */
HWTEST_F(DiscBleUtilsTest, UnsetCapBitMapPosTest_001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, UnsetCapBitMapPosTest_001, Start");

    DeviceInfo info = { { 0 } };
    info.capabilityBitmapNum = DISC_MAX_CAPABILITY_NUM;
    uint32_t pos = info.capabilityBitmapNum * INT32_MAX_BIT_NUM;

    UnsetCapBitMapPos(info.capabilityBitmapNum, info.capabilityBitmap, pos);
    for (int32_t i = 0; i < info.capabilityBitmapNum; i++) {
        EXPECT_EQ(info.capabilityBitmap[i], 0x0);
    }

    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, UnsetCapBitMapPosTest_001, End");
}

/*
 * @tc.name: UnsetCapBitMapPosTest_002
 * @tc.desc: Test UnsetCapBitMapPos should success when SetCapBitMapPos is successfully set at the pos offset,
 *           UnsetCapBitMapPos successfully unset the pos offset.
 * @tc.type: FUNC
 * @tc.require:Unset cap bitMap success at pos offset
 */
HWTEST_F(DiscBleUtilsTest, UnsetCapBitMapPosTest_002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, UnsetCapBitMapPosTest_002, Start");

    DeviceInfo info = { { 0 } };
    info.capabilityBitmapNum = DISC_MAX_CAPABILITY_NUM;
    uint32_t pos = INT32_MAX_BIT_NUM;

    SetCapBitMapPos(info.capabilityBitmapNum, info.capabilityBitmap, pos);
    for (int32_t i = 0; i < info.capabilityBitmapNum; i++) {
        if (i == (pos / INT32_MAX_BIT_NUM)) {
            EXPECT_EQ(info.capabilityBitmap[i], 0x1);
        } else {
            EXPECT_EQ(info.capabilityBitmap[i], 0x0);
        }
    }
    UnsetCapBitMapPos(info.capabilityBitmapNum, info.capabilityBitmap, pos);
    for (int32_t i = 0; i < info.capabilityBitmapNum; i++) {
        EXPECT_EQ(info.capabilityBitmap[i], 0x0);
    }

    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, UnsetCapBitMapPosTest_002, End");
}

/*
 * @tc.name: DiscBleGetDeviceName_001
 * @tc.desc: Test DiscBleGetDeviceName should return SOFTBUS_INVALID_PARAM when deviceName is nullptr or size is zero.
 * @tc.type: FUNC
 * @tc.require:Invalid input parameter test
 */
HWTEST_F(DiscBleUtilsTest, DiscBleGetDeviceName_001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, DiscBleGetDeviceName_001, Start");

    char deviceName[DISC_MAX_DEVICE_NAME_LEN] = { 0 };
    int32_t ret = DiscBleGetDeviceName(nullptr, DISC_MAX_DEVICE_NAME_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = DiscBleGetDeviceName(deviceName, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, DiscBleGetDeviceName_001, End");
}

/*
 * @tc.name: DiscBleGetDeviceIdHash_001
 * @tc.desc: Test DiscBleGetDeviceIdHash should return SOFTBUS_INVALID_PARAM when devIdHash is nullptr or len is greater
 *           then DISC_MAX_DEVICE_ID_LEN.
 * @tc.type: FUNC
 * @tc.require:Invalid input parameter test
 */
HWTEST_F(DiscBleUtilsTest, DiscBleGetDeviceIdHash_001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, DiscBleGetDeviceIdHash_001, Start");

    uint8_t devIdHash[DISC_MAX_DEVICE_ID_LEN] = { 0 };
    int32_t ret = DiscBleGetDeviceIdHash(nullptr, DISC_MAX_DEVICE_ID_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = DiscBleGetDeviceIdHash(devIdHash, DISC_MAX_DEVICE_ID_LEN + 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, DiscBleGetDeviceIdHash_001, End");
}

/*
 * @tc.name: DiscBleGetShortUserIdHash_001
 * @tc.desc: Test DiscBleGetShortUserIdHash should return false when hashStr is nullptr or len is greater
 *           then SHORT_USER_ID_HASH_LEN.
 * @tc.type: FUNC
 * @tc.require:Invalid input parameter test
 */
HWTEST_F(DiscBleUtilsTest, DiscBleGetShortUserIdHash_001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, DiscBleGetShortUserIdHash_001, Start");

    uint8_t hashStr[SHORT_USER_ID_HASH_LEN] = { 0 };
    int32_t ret = DiscBleGetShortUserIdHash(nullptr, SHORT_USER_ID_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = DiscBleGetShortUserIdHash(hashStr, SHORT_USER_ID_HASH_LEN + 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, DiscBleGetShortUserIdHash_001, End");
}

/*
 * @tc.name: AssembleTLVTest_001
 * @tc.desc: Test AssembleTLV should return SOFTBUS_DISCOVER_BLE_ASSEMBLE_DATA_FAIL when remainLen equals 0.
 * @tc.type: FUNC
 * @tc.require:Invalid input parameter test
 */
HWTEST_F(DiscBleUtilsTest, AssembleTLVTest_001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, AssembleTLVTest_001, Start");

    BroadcastData broadcastData = { { { 0 } } };
    broadcastData.dataLen = BROADCAST_MAX_LEN;
    char deviceIdHash[SHORT_DEVICE_ID_HASH_LENGTH + 1] = { 0 };
    int32_t ret =
        AssembleTLV(&broadcastData, TLV_TYPE_DEVICE_ID_HASH, (const void *)deviceIdHash, SHORT_DEVICE_ID_HASH_LENGTH);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_BLE_ASSEMBLE_DATA_FAIL);

    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, AssembleTLVTest_001, End");
}

/*
 * @tc.name: AssembleTLVTest_002
 * @tc.desc: Test AssembleTLV should return SOFTBUS_OK when assemble deviceName length more then 15.
 * @tc.type: FUNC
 * @tc.require:Invalid input parameter test
 */
HWTEST_F(DiscBleUtilsTest, AssembleTLVTest_002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, AssembleTLVTest_002, Start");

    BroadcastData broadcastData = { { { 0 } } };
    char deviceName[] = "longlonglongdeviceName";
    int32_t ret = AssembleTLV(&broadcastData, TLV_TYPE_DEVICE_NAME, (const void *)deviceName, strlen(deviceName) + 1);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, AssembleTLVTest_002, End");
}

/*
 * @tc.name: GetDeviceInfoFromDisAdvData_001
 * @tc.desc: Test GetDeviceInfoFromDisAdvData should return SOFTBUS_INVALID_PARAM when bcLen is greater then
 *           ADV_DATA_MAX_LEN
 * @tc.type: FUNC
 * @tc.require:Invalid input parameter test
 */
HWTEST_F(DiscBleUtilsTest, GetDeviceInfoFromDisAdvData_001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, GetDeviceInfoFromDisAdvData_001, Start");

    DeviceInfo info = { { 0 } };
    DeviceWrapper device = { .info = &info };
    BroadcastReportInfo reportInfo = { 0 };
    reportInfo.packet.bcData.id = SERVICE_UUID;
    reportInfo.packet.bcData.type = BC_DATA_TYPE_SERVICE;
    reportInfo.packet.rspData.id = MANU_COMPANY_ID;
    reportInfo.packet.rspData.type = BC_DATA_TYPE_MANUFACTURER;
    reportInfo.packet.bcData.payload = &g_invalidAdvData[0];
    reportInfo.packet.bcData.payloadLen = ADV_DATA_MAX_LEN + 1; // bcLen > ADV_DATA_MAX_LEN
    reportInfo.packet.rspData.payload = &g_invalidRspData[0];
    reportInfo.packet.rspData.payloadLen = REAL_RESP_DATA_MAX_LEN;

    int32_t ret = GetDeviceInfoFromDisAdvData(
        &device, reinterpret_cast<const uint8_t *>(&reportInfo), sizeof(BroadcastReportInfo));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, GetDeviceInfoFromDisAdvData_001, End");
}

/*
 * @tc.name: GetDeviceInfoFromDisAdvData_002
 * @tc.desc: Test GetDeviceInfoFromDisAdvData should return SOFTBUS_INVALID_PARAM when bcLen is less then POS_TLV
 * @tc.type: FUNC
 * @tc.require:Invalid input parameter test
 */
HWTEST_F(DiscBleUtilsTest, GetDeviceInfoFromDisAdvData_002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, GetDeviceInfoFromDisAdvData_002, Start");

    DeviceInfo info = { { 0 } };
    DeviceWrapper device = { .info = &info };
    BroadcastReportInfo reportInfo = { 0 };
    reportInfo.packet.bcData.id = SERVICE_UUID;
    reportInfo.packet.bcData.type = BC_DATA_TYPE_SERVICE;
    reportInfo.packet.rspData.id = MANU_COMPANY_ID;
    reportInfo.packet.rspData.type = BC_DATA_TYPE_MANUFACTURER;
    reportInfo.packet.bcData.payload = &g_invalidAdvData[0];
    reportInfo.packet.bcData.payloadLen = sizeof(g_invalidAdvData); // bcLen < POS_TLV
    reportInfo.packet.rspData.payload = &g_invalidRspData[0];
    reportInfo.packet.rspData.payloadLen = REAL_RESP_DATA_MAX_LEN;

    int32_t ret = GetDeviceInfoFromDisAdvData(
        &device, reinterpret_cast<const uint8_t *>(&reportInfo), sizeof(BroadcastReportInfo));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, GetDeviceInfoFromDisAdvData_002, End");
}

/*
 * @tc.name: TestGetNeedUpdateAdvertiser001
 * @tc.desc: Test GetDeviceInfoFromDisAdvData should return SOFTBUS_INVALID_PARAM when rspLen is greater then
 *           REAL_RESP_DATA_MAX_LEN
 * @tc.type: FUNC
 * @tc.require:Invalid input parameter test
 */
HWTEST_F(DiscBleUtilsTest, GetDeviceInfoFromDisAdvData_003, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, GetDeviceInfoFromDisAdvData_003, Start");

    DeviceInfo info = { { 0 } };
    DeviceWrapper device = { .info = &info };
    BroadcastReportInfo reportInfo = { 0 };
    reportInfo.packet.bcData.id = SERVICE_UUID;
    reportInfo.packet.bcData.type = BC_DATA_TYPE_SERVICE;
    reportInfo.packet.rspData.id = MANU_COMPANY_ID;
    reportInfo.packet.rspData.type = BC_DATA_TYPE_MANUFACTURER;
    reportInfo.packet.bcData.payload = &g_vaildAdvData[0];
    reportInfo.packet.bcData.payloadLen = sizeof(g_vaildAdvData);
    reportInfo.packet.rspData.payload = &g_vaildRspData[0];
    reportInfo.packet.rspData.payloadLen = REAL_RESP_DATA_MAX_LEN + 1; // rspLen > REAL_RESP_DATA_MAX_LEN

    int32_t ret = GetDeviceInfoFromDisAdvData(
        &device, reinterpret_cast<const uint8_t *>(&reportInfo), sizeof(BroadcastReportInfo));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, GetDeviceInfoFromDisAdvData_003, End");
}

/*
 * @tc.name: GetDeviceInfoFromDisAdvData_004
 * @tc.desc: Test GetNeedUpdateAdvertiser should return SOFTBUS_BC_MGR_UNEXPECTED_PACKETS when rspData.payload
 *           is nullptr.
 * @tc.type: FUNC
 * @tc.require:Invalid input parameter test
 */
HWTEST_F(DiscBleUtilsTest, GetDeviceInfoFromDisAdvData_004, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, GetDeviceInfoFromDisAdvData_004, Start");

    DeviceInfo info = { { 0 } };
    DeviceWrapper device = { .info = &info };
    BroadcastReportInfo reportInfo = { 0 };
    reportInfo.packet.bcData.id = SERVICE_UUID;
    reportInfo.packet.bcData.type = BC_DATA_TYPE_SERVICE;
    reportInfo.packet.rspData.id = MANU_COMPANY_ID;
    reportInfo.packet.rspData.type = BC_DATA_TYPE_MANUFACTURER;
    reportInfo.packet.bcData.payload = &g_vaildAdvData[0];
    reportInfo.packet.bcData.payloadLen = sizeof(g_vaildAdvData);
    reportInfo.packet.rspData.payload = nullptr;
    reportInfo.packet.rspData.payloadLen = sizeof(g_vaildRspData);

    int32_t ret = GetDeviceInfoFromDisAdvData(
        &device, reinterpret_cast<const uint8_t *>(&reportInfo), sizeof(BroadcastReportInfo));
    EXPECT_EQ(ret, SOFTBUS_BC_MGR_UNEXPECTED_PACKETS);

    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, GetDeviceInfoFromDisAdvData_004, End");
}

/*
 * @tc.name: GetDeviceInfoFromDisAdvData_005
 * @tc.desc: Test GetDeviceInfoFromDisAdvData should return SOFTBUS_BC_MGR_UNEXPECTED_PACKETS
 *           when rspLenis equals zero.
 * @tc.type: FUNC
 * @tc.require:Invalid input parameter test
 */
HWTEST_F(DiscBleUtilsTest, GetDeviceInfoFromDisAdvData_005, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, GetDeviceInfoFromDisAdvData_005, Start");

    DeviceInfo info = { { 0 } };
    DeviceWrapper device = { .info = &info };
    BroadcastReportInfo reportInfo = { 0 };
    reportInfo.packet.bcData.id = SERVICE_UUID;
    reportInfo.packet.bcData.type = BC_DATA_TYPE_SERVICE;
    reportInfo.packet.rspData.id = MANU_COMPANY_ID;
    reportInfo.packet.rspData.type = BC_DATA_TYPE_MANUFACTURER;
    reportInfo.packet.bcData.payload = &g_vaildAdvData[0];
    reportInfo.packet.bcData.payloadLen = sizeof(g_vaildAdvData);
    reportInfo.packet.rspData.payload = &g_vaildRspData[0];
    reportInfo.packet.rspData.payloadLen = 0;

    int32_t ret = GetDeviceInfoFromDisAdvData(
        &device, reinterpret_cast<const uint8_t *>(&reportInfo), sizeof(BroadcastReportInfo));
    EXPECT_EQ(ret, SOFTBUS_BC_MGR_UNEXPECTED_PACKETS);

    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, GetDeviceInfoFromDisAdvData_005, End");
}

/*
 * @tc.name: GetDeviceInfoFromDisAdvData_006
 * @tc.desc: Test GetNeedUpdateAdvertiser should return SOFTBUS_OK when paramter is vaild.
 * @tc.type: FUNC
 * @tc.require:Valid input parameter test
 */
HWTEST_F(DiscBleUtilsTest, GetDeviceInfoFromDisAdvData_006, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, GetDeviceInfoFromDisAdvData_006, Start");

    DeviceInfo info = { { 0 } };
    DeviceWrapper device = { .info = &info };
    BroadcastReportInfo reportInfo = { 0 };
    reportInfo.packet.bcData.id = SERVICE_UUID;
    reportInfo.packet.bcData.type = BC_DATA_TYPE_SERVICE;
    reportInfo.packet.rspData.id = MANU_COMPANY_ID;
    reportInfo.packet.rspData.type = BC_DATA_TYPE_MANUFACTURER;
    reportInfo.packet.bcData.payload = &g_vaildAdvData[0];
    reportInfo.packet.bcData.payloadLen = sizeof(g_vaildAdvData);
    reportInfo.packet.rspData.payload = &g_vaildRspData[0];
    reportInfo.packet.rspData.payloadLen = sizeof(g_vaildRspData);

    int32_t ret = GetDeviceInfoFromDisAdvData(
        &device, reinterpret_cast<const uint8_t *>(&reportInfo), sizeof(BroadcastReportInfo));
    EXPECT_EQ(ret, SOFTBUS_OK);

    DISC_LOGI(DISC_TEST, "DiscBleUtilsTest, GetDeviceInfoFromDisAdvData_006, End");
}
} // namespace OHOS
