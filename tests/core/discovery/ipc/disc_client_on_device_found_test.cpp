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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "bus_center_manager.h"
#include "lnn_bus_center_ipc.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

using namespace testing::ext;
using testing::_;
using testing::AtLeast;
using testing::Eq;
using testing::Field;
using testing::Ge;
using testing::NiceMock;
using testing::NotNull;
using testing::Return;

namespace {
constexpr int32_t CAPABILITY_CASTPLUS = 1 << 3;
constexpr int32_t CAPABILITY_OSD = 1 << 7;
constexpr int32_t g_callingPid1 = 1;
constexpr int32_t g_callingPid2 = 2;
const std::string g_pkgName1 = "pkgName1";
const std::string g_pkgName2 = "pkgName2";
const std::vector<char> g_invalidPkgName(PKG_NAME_SIZE_MAX + 1, 'X');
const SubscribeInfo g_subscribeInfoCast = {
    .subscribeId = 1,
    .capability = "castPlus",
};
const SubscribeInfo g_subscribeInfoOsd = {
    .subscribeId = 2,
    .capability = "osdCapability",
};
const DeviceInfo g_deviceInfoCast = {
    .capabilityBitmapNum = 1,
    .capabilityBitmap = { CAPABILITY_CASTPLUS },
};
const DeviceInfo g_deviceInfoOsd = {
    .capabilityBitmapNum = 1,
    .capabilityBitmap = { CAPABILITY_OSD },
};
const InnerDeviceInfoAddtions g_additions = {};

class BusCenterInterface {
public:
    virtual int32_t ClientOnRefreshDeviceFound(const char *pkgName, int32_t pid, const void *device,
        uint32_t deviceLen) = 0;
    virtual int32_t LnnStartDiscDevice(const char *pkgName, const SubscribeInfo *info, const InnerCallback *cb,
        bool isInnerRequest) = 0;
    virtual int32_t LnnStopDiscDevice(const char *pkgName, int32_t subscribeId, bool isInnerRequest) = 0;
    virtual void LnnRefreshDeviceOnlineStateAndDevIdInfo(const char *pkgName, DeviceInfo *device,
        const InnerDeviceInfoAddtions *additions) = 0;
};

class BusCenterMock : public BusCenterInterface {
public:
    BusCenterMock()
    {
        mock_ = this;
        ON_CALL(*this, ClientOnRefreshDeviceFound).WillByDefault(Return(SOFTBUS_OK));
        ON_CALL(*this, LnnStartDiscDevice).WillByDefault(ActionLnnStartDiscDevice);
        ON_CALL(*this, LnnStopDiscDevice).WillByDefault(Return(SOFTBUS_OK));
        innerCallback_.serverCb.OnServerDeviceFound = nullptr;
    }
    ~BusCenterMock()
    {
        mock_ = nullptr;
        innerCallback_.serverCb.OnServerDeviceFound = nullptr;
    }

    MOCK_METHOD(int32_t, ClientOnRefreshDeviceFound, (const char *pkgName, int32_t pid, const void *device,
        uint32_t deviceLen), (override));
    MOCK_METHOD(int32_t, LnnStartDiscDevice, (const char *pkgName, const SubscribeInfo *info, const InnerCallback *cb,
        bool isInnerRequest), (override));
    MOCK_METHOD(int32_t, LnnStopDiscDevice, (const char *pkgName, int32_t subscribeId,
        bool isInnerRequest), (override));
    MOCK_METHOD(void, LnnRefreshDeviceOnlineStateAndDevIdInfo, (const char *pkgName, DeviceInfo *device,
        const InnerDeviceInfoAddtions *additions), (override));

    static BusCenterMock *GetMock()
    {
        return mock_;
    }
    static int32_t ActionLnnStartDiscDevice(const char *pkgName, const SubscribeInfo *info, const InnerCallback *cb,
        bool isInnerRequest)
    {
        if (cb == nullptr || cb->serverCb.OnServerDeviceFound == nullptr) {
            return SOFTBUS_INVALID_PARAM;
        }
        innerCallback_.serverCb.OnServerDeviceFound = cb->serverCb.OnServerDeviceFound;
        return SOFTBUS_OK;
    }
    static int32_t CallbackOnServerDeviceFound(const char *pkgName, const DeviceInfo *device,
        const InnerDeviceInfoAddtions *additions)
    {
        if (innerCallback_.serverCb.OnServerDeviceFound == nullptr) {
            return SOFTBUS_NO_INIT;
        }
        return innerCallback_.serverCb.OnServerDeviceFound(pkgName, device, additions);
    }

private:
    static inline BusCenterMock *mock_ = nullptr;
    static inline InnerCallback innerCallback_ = {};
};

extern "C" {
int32_t ClientOnRefreshDeviceFound(const char *pkgName, int32_t pid, const void *device, uint32_t deviceLen)
{
    return BusCenterMock::GetMock()->ClientOnRefreshDeviceFound(pkgName, pid, device, deviceLen);
}

int32_t LnnStartDiscDevice(const char *pkgName, const SubscribeInfo *info, const InnerCallback *cb,
    bool isInnerRequest)
{
    return BusCenterMock::GetMock()->LnnStartDiscDevice(pkgName, info, cb, isInnerRequest);
}

int32_t LnnStopDiscDevice(const char *pkgName, int32_t subscribeId, bool isInnerRequest)
{
    return BusCenterMock::GetMock()->LnnStopDiscDevice(pkgName, subscribeId, isInnerRequest);
}

void LnnRefreshDeviceOnlineStateAndDevIdInfo(const char *pkgName, DeviceInfo *device,
    const InnerDeviceInfoAddtions *additions)
{
    return BusCenterMock::GetMock()->LnnRefreshDeviceOnlineStateAndDevIdInfo(pkgName, device, additions);
}
} // extern "C"
} // namespace

namespace OHOS {
class DiscClientOnDeviceFoundTest : public testing::Test {
public:
    static void SetUpTestCase() { }
    static void TearDownTestCase() { }
    void SetUp() override { }
    void TearDown() override { }
};

MATCHER_P(EqStr, expect, "string not equal")
{
    return expect == std::string(arg);
}

/*
 * @tc.name: LnnIpcRefreshLNNFailed001
 * @tc.desc: should not call LnnStartDiscDevice when call LnnIpcRefreshLNN with invalid params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscClientOnDeviceFoundTest, LnnIpcRefreshLNNFailed001, TestSize.Level1)
{
    NiceMock<BusCenterMock> mock;
    EXPECT_CALL(mock, LnnStartDiscDevice).Times(0);

    int32_t ret = LnnIpcRefreshLNN(nullptr, g_callingPid1, &g_subscribeInfoCast);
    EXPECT_NE(ret, SOFTBUS_OK);

    ret = LnnIpcRefreshLNN(&g_invalidPkgName[0], g_callingPid1, &g_subscribeInfoCast);
    EXPECT_NE(ret, SOFTBUS_OK);

    ret = LnnIpcRefreshLNN(g_pkgName1.c_str(), g_callingPid1, nullptr);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnIpcRefreshLNNSuccess001
 * @tc.desc: should call LnnStartDiscDevice when call LnnIpcRefreshLNN with valid params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscClientOnDeviceFoundTest, LnnIpcRefreshLNNSuccess001, TestSize.Level1)
{
    NiceMock<BusCenterMock> mock;
    int32_t ret = SOFTBUS_OK;
    {
        EXPECT_CALL(mock, LnnStartDiscDevice(EqStr(g_pkgName1),
            Field(&SubscribeInfo::subscribeId, Eq(g_subscribeInfoCast.subscribeId)), NotNull(), _)).Times(1);
        ret = LnnIpcRefreshLNN(g_pkgName1.c_str(), g_callingPid1, &g_subscribeInfoCast);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
    {
        EXPECT_CALL(mock, LnnStartDiscDevice(EqStr(g_pkgName2),
            Field(&SubscribeInfo::subscribeId, Eq(g_subscribeInfoOsd.subscribeId)), NotNull(), _)).Times(1);
        ret = LnnIpcRefreshLNN(g_pkgName2.c_str(), g_callingPid2, &g_subscribeInfoOsd);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
}

/*
 * @tc.name: LnnIpcStopRefreshLNNFailed001
 * @tc.desc: should not call LnnStopDiscDevice when call LnnIpcStopRefreshLNN with invalid params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscClientOnDeviceFoundTest, LnnIpcStopRefreshLNNFailed001, TestSize.Level1)
{
    NiceMock<BusCenterMock> mock;
    EXPECT_CALL(mock, LnnStopDiscDevice).Times(0);

    int32_t ret = LnnIpcStopRefreshLNN(nullptr, g_callingPid1, g_subscribeInfoCast.subscribeId);
    EXPECT_NE(ret, SOFTBUS_OK);

    ret = LnnIpcStopRefreshLNN(&g_invalidPkgName[0], g_callingPid1, g_subscribeInfoCast.subscribeId);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnIpcStopRefreshLNNSuccess001
 * @tc.desc: should call LnnStopDiscDevice when call LnnIpcStopRefreshLNN with valid params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscClientOnDeviceFoundTest, LnnIpcStopRefreshLNNSuccess001, TestSize.Level1)
{
    NiceMock<BusCenterMock> mock;
    int32_t ret = SOFTBUS_OK;
    {
        EXPECT_CALL(mock, LnnStopDiscDevice(EqStr(g_pkgName1), g_subscribeInfoCast.subscribeId, _)).Times(1);
        ret = LnnIpcStopRefreshLNN(g_pkgName1.c_str(), g_callingPid1, g_subscribeInfoCast.subscribeId);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
    {
        EXPECT_CALL(mock, LnnStopDiscDevice(EqStr(g_pkgName2), g_subscribeInfoOsd.subscribeId, _)).Times(1);
        ret = LnnIpcStopRefreshLNN(g_pkgName2.c_str(), g_callingPid2, g_subscribeInfoOsd.subscribeId);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
}

/*
 * @tc.name: OnServerDeviceFoundFailed001
 * @tc.desc: should not report device when call OnServerDeviceFound with invalid params or uninterested params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscClientOnDeviceFoundTest, OnServerDeviceFoundFailed001, TestSize.Level1)
{
    NiceMock<BusCenterMock> mock;
    EXPECT_CALL(mock, ClientOnRefreshDeviceFound).Times(0);

    int32_t ret = mock.CallbackOnServerDeviceFound(g_pkgName1.c_str(), &g_deviceInfoCast, &g_additions);
    EXPECT_NE(ret, SOFTBUS_OK);

    ret = LnnIpcRefreshLNN(g_pkgName1.c_str(), g_callingPid1, &g_subscribeInfoCast);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = mock.CallbackOnServerDeviceFound(nullptr, &g_deviceInfoCast, &g_additions);
    EXPECT_NE(ret, SOFTBUS_OK);

    ret = mock.CallbackOnServerDeviceFound(g_pkgName1.c_str(), nullptr, &g_additions);
    EXPECT_NE(ret, SOFTBUS_OK);

    ret = mock.CallbackOnServerDeviceFound(g_pkgName1.c_str(), &g_deviceInfoCast, nullptr);
    EXPECT_NE(ret, SOFTBUS_OK);

    ret = mock.CallbackOnServerDeviceFound(g_pkgName2.c_str(), &g_deviceInfoCast, &g_additions);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = LnnIpcStopRefreshLNN(g_pkgName1.c_str(), g_callingPid1, g_subscribeInfoCast.subscribeId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = mock.CallbackOnServerDeviceFound(g_pkgName1.c_str(), &g_deviceInfoCast, &g_additions);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: OnServerDeviceFoundSuccess001
 * @tc.desc: should report cast when refresh cast and cast device found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscClientOnDeviceFoundTest, OnServerDeviceFoundSuccess001, TestSize.Level1)
{
    NiceMock<BusCenterMock> mock;

    int32_t ret = LnnIpcRefreshLNN(g_pkgName1.c_str(), g_callingPid1, &g_subscribeInfoCast);
    EXPECT_EQ(ret, SOFTBUS_OK);
    {
        EXPECT_CALL(mock, ClientOnRefreshDeviceFound(EqStr(g_pkgName1), g_callingPid1, NotNull(), Ge(1))).Times(1);
        ret = mock.CallbackOnServerDeviceFound(g_pkgName1.c_str(), &g_deviceInfoCast, &g_additions);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
    ret = LnnIpcStopRefreshLNN(g_pkgName1.c_str(), g_callingPid1, g_subscribeInfoCast.subscribeId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: OnServerDeviceFoundWhenRefreshRepeatRequest001
 * @tc.desc: should report device once when refresh cast twice with same params and one cast device found
 *           should not report cast when refresh cast twice with same params and stop refresh cast once
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscClientOnDeviceFoundTest, OnServerDeviceFoundWhenRefreshRepeatRequest001, TestSize.Level1)
{
    NiceMock<BusCenterMock> mock;

    int32_t ret = LnnIpcRefreshLNN(g_pkgName1.c_str(), g_callingPid1, &g_subscribeInfoCast);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnIpcRefreshLNN(g_pkgName1.c_str(), g_callingPid1, &g_subscribeInfoCast);
    EXPECT_EQ(ret, SOFTBUS_OK);
    {
        EXPECT_CALL(mock, ClientOnRefreshDeviceFound(EqStr(g_pkgName1), g_callingPid1, NotNull(), Ge(1))).Times(1);
        ret = mock.CallbackOnServerDeviceFound(g_pkgName1.c_str(), &g_deviceInfoCast, &g_additions);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
    ret = LnnIpcStopRefreshLNN(g_pkgName1.c_str(), g_callingPid1, g_subscribeInfoCast.subscribeId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    {
        EXPECT_CALL(mock, ClientOnRefreshDeviceFound).Times(0);
        ret = mock.CallbackOnServerDeviceFound(g_pkgName1.c_str(), &g_deviceInfoCast, &g_additions);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
}

/*
 * @tc.name: OnServerDeviceFoundWhenRefreshWithSamePkgPid001
 * @tc.desc: should report osd when refresh osd & cast with same pkgName, pid and stop refresh cast
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscClientOnDeviceFoundTest, OnServerDeviceFoundWhenRefreshWithSamePkgPid001, TestSize.Level1)
{
    NiceMock<BusCenterMock> mock;

    int32_t ret = LnnIpcRefreshLNN(g_pkgName1.c_str(), g_callingPid1, &g_subscribeInfoCast);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnIpcRefreshLNN(g_pkgName1.c_str(), g_callingPid1, &g_subscribeInfoOsd);
    EXPECT_EQ(ret, SOFTBUS_OK);
    {
        EXPECT_CALL(mock, ClientOnRefreshDeviceFound(EqStr(g_pkgName1), g_callingPid1, NotNull(), Ge(1)))
            .Times(AtLeast(1));
        ret = mock.CallbackOnServerDeviceFound(g_pkgName1.c_str(), &g_deviceInfoCast, &g_additions);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
    {
        EXPECT_CALL(mock, ClientOnRefreshDeviceFound(EqStr(g_pkgName1), g_callingPid1, NotNull(), Ge(1)))
            .Times(AtLeast(1));
        ret = mock.CallbackOnServerDeviceFound(g_pkgName1.c_str(), &g_deviceInfoOsd, &g_additions);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
    ret = LnnIpcStopRefreshLNN(g_pkgName1.c_str(), g_callingPid1, g_subscribeInfoCast.subscribeId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    {
        EXPECT_CALL(mock, ClientOnRefreshDeviceFound(EqStr(g_pkgName1), g_callingPid1, NotNull(), Ge(1))).Times(1);
        ret = mock.CallbackOnServerDeviceFound(g_pkgName1.c_str(), &g_deviceInfoOsd, &g_additions);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
    ret = LnnIpcStopRefreshLNN(g_pkgName1.c_str(), g_callingPid1, g_subscribeInfoOsd.subscribeId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    {
        EXPECT_CALL(mock, ClientOnRefreshDeviceFound).Times(0);
        ret = mock.CallbackOnServerDeviceFound(g_pkgName1.c_str(), &g_deviceInfoOsd, &g_additions);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
}

/*
 * @tc.name: OnServerDeviceFoundWhenRefreshWithDiffPid001
 * @tc.desc: should report osd when refresh osd & cast with different pid and stop refresh cast
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscClientOnDeviceFoundTest, OnServerDeviceFoundWhenRefreshWithDiffPid001, TestSize.Level1)
{
    NiceMock<BusCenterMock> mock;

    int32_t ret = LnnIpcRefreshLNN(g_pkgName1.c_str(), g_callingPid1, &g_subscribeInfoCast);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnIpcRefreshLNN(g_pkgName1.c_str(), g_callingPid2, &g_subscribeInfoOsd);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnIpcStopRefreshLNN(g_pkgName1.c_str(), g_callingPid1, g_subscribeInfoCast.subscribeId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    {
        EXPECT_CALL(mock, ClientOnRefreshDeviceFound(EqStr(g_pkgName1), g_callingPid2, NotNull(), Ge(1))).Times(1);
        ret = mock.CallbackOnServerDeviceFound(g_pkgName1.c_str(), &g_deviceInfoOsd, &g_additions);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
    ret = LnnIpcStopRefreshLNN(g_pkgName1.c_str(), g_callingPid2, g_subscribeInfoOsd.subscribeId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    {
        EXPECT_CALL(mock, ClientOnRefreshDeviceFound).Times(0);
        ret = mock.CallbackOnServerDeviceFound(g_pkgName1.c_str(), &g_deviceInfoOsd, &g_additions);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
}

/*
 * @tc.name: OnServerDeviceFoundWhenRefreshWithDiffPkg001
 * @tc.desc: should report osd and not report cast when refresh osd & cast with different pkgName and stop refresh cast
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscClientOnDeviceFoundTest, OnServerDeviceFoundWhenRefreshWithDiffPkg001, TestSize.Level1)
{
    NiceMock<BusCenterMock> mock;

    int32_t ret = LnnIpcRefreshLNN(g_pkgName1.c_str(), g_callingPid1, &g_subscribeInfoCast);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnIpcRefreshLNN(g_pkgName2.c_str(), g_callingPid1, &g_subscribeInfoOsd);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnIpcStopRefreshLNN(g_pkgName1.c_str(), g_callingPid1, g_subscribeInfoCast.subscribeId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    {
        EXPECT_CALL(mock, ClientOnRefreshDeviceFound).Times(0);
        ret = mock.CallbackOnServerDeviceFound(g_pkgName1.c_str(), &g_deviceInfoCast, &g_additions);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
    {
        EXPECT_CALL(mock, ClientOnRefreshDeviceFound(EqStr(g_pkgName2), g_callingPid1, NotNull(), Ge(1))).Times(1);
        ret = mock.CallbackOnServerDeviceFound(g_pkgName2.c_str(), &g_deviceInfoOsd, &g_additions);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
    ret = LnnIpcStopRefreshLNN(g_pkgName2.c_str(), g_callingPid1, g_subscribeInfoOsd.subscribeId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    {
        EXPECT_CALL(mock, ClientOnRefreshDeviceFound).Times(0);
        ret = mock.CallbackOnServerDeviceFound(g_pkgName2.c_str(), &g_deviceInfoOsd, &g_additions);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
}
} // namespace OHOS
