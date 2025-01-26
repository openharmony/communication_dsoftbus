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

#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;

using TestFfrtMsgHandleInfo = struct {
    uint32_t param1;
    uint64_t param2;
};

static SoftBusCond g_cond = {0};
static SoftBusMutex g_lock = {0};

static int32_t g_msgHandleRes = SOFTBUS_INVALID_PARAM;
static SoftBusHandler g_testFfrtLoopHandler;
static bool g_isNeedCondWait = true;

class MessageHandlerFfrtTest : public testing::Test {
public:
    MessageHandlerFfrtTest() {}
    ~MessageHandlerFfrtTest() {}
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void MessageHandlerFfrtTest::SetUpTestCase()
{
    SoftBusLooper *looper = CreateNewLooper("Lnn_Lp");
    ASSERT_NE(looper, nullptr) << "create lnn_looper fail";
    SetLooper(LOOP_TYPE_LNN, looper);
}

void MessageHandlerFfrtTest::TearDownTestCase()
{
    SoftBusLooper *looper = GetLooper(LOOP_TYPE_LNN);
    EXPECT_NE(looper, nullptr);
    DestroyLooper(looper);
}

void MessageHandlerFfrtTest::SetUp()
{
    (void)SoftBusMutexInit(&g_lock, nullptr);
    (void)SoftBusCondInit(&g_cond);
}

void MessageHandlerFfrtTest::TearDown()
{
    (void)SoftBusCondDestroy(&g_cond);
    (void)SoftBusCondDestroy(&g_lock);
}

static void CondSignal(void)
{
    if (SoftBusMutexLock(&g_lock) != SOFTBUS_OK) {
        GTEST_LOG_(ERROR) << "mutex lock fail";
        return;
    }
    if (SoftBusCondSignal(&g_cond) != SOFTBUS_OK) {
        GTEST_LOG_(ERROR) << "cond signal fail";
        (void)SoftBusMutexUnlock(&g_lock);
        return;
    }
    (void)SoftBusMutexUnlock(&g_lock);
    g_isNeedCondWait = false;
}

static void CondWait(void)
{
    if (SoftBusMutexLock(&g_lock) != SOFTBUS_OK) {
        GTEST_LOG_(ERROR) << "mutex lock fail";
        return;
    }
    if (SoftBusCondWait(&g_cond, &g_lock, nullptr) != SOFTBUS_OK) {
        GTEST_LOG_(ERROR) << "cond wait fail";
        (void)SoftBusMutexUnlock(&g_lock);
        return;
    }
    (void)SoftBusMutexUnlock(&g_lock);
}

static void TestFfrtFreeMessage(SoftBusMessage *msg)
{
    if (msg == nullptr) {
        GTEST_LOG_(ERROR) << "invalid param";
        return;
    }
    if (msg->obj != nullptr) {
        SoftBusFree(msg->obj);
        msg->obj = nullptr;
    }
    SoftBusFree(msg);
    msg = nullptr;
    g_msgHandleRes = SOFTBUS_OK;
}

static int32_t TestFfrtPostMsgToHandler(int32_t msgType, void *obj, uint64_t delayMillis,
    void (*FreeMessageCustom)(SoftBusMessage *msg))
{
    SoftBusMessage *msg = MallocMessage();
    if (msg == nullptr) {
        GTEST_LOG_(ERROR) << "calloc test ffrt handler msg fail";
        return SOFTBUS_MALLOC_ERR;
    }
    if (g_testFfrtLoopHandler.looper == nullptr) {
        GTEST_LOG_(ERROR) << "testFfrtLoopHandler looper not init";
        FreeMessage(msg);
        return SOFTBUS_NO_INIT;
    }
    msg->what = msgType;
    msg->handler = &g_testFfrtLoopHandler;
    msg->FreeMessage = FreeMessageCustom;
    msg->obj = obj;
    if (delayMillis == 0) {
        g_testFfrtLoopHandler.looper->PostMessage(g_testFfrtLoopHandler.looper, msg);
    } else {
        g_testFfrtLoopHandler.looper->PostMessageDelay(g_testFfrtLoopHandler.looper, msg, delayMillis);
    }
    return SOFTBUS_OK;
}

static void FfrtMsgHandler(SoftBusMessage *msg)
{
    if (msg == nullptr) {
        GTEST_LOG_(ERROR) << "invalid msg when handle ffrtMsg";
        return;
    }
    GTEST_LOG_(INFO) << "handle ffrtMsg";
    CondSignal();
    return;
}

static int32_t TestFfrtRemoveMsgInfo(const SoftBusMessage *msg, void *data)
{
    if (msg == NULL || msg->obj == NULL || data == NULL) {
        GTEST_LOG_(ERROR) << "invalid param";
        return SOFTBUS_INVALID_PARAM;
    }
    TestFfrtMsgHandleInfo *srcInfo = (TestFfrtMsgHandleInfo*)msg->obj;
    TestFfrtMsgHandleInfo *dstInfo = (TestFfrtMsgHandleInfo*)data;
    if (srcInfo->param1 == dstInfo->param1 && srcInfo->param2 == dstInfo->param2) {
        GTEST_LOG_(INFO) << "remove testffrt msg succ";
        g_msgHandleRes = SOFTBUS_OK;
        return SOFTBUS_OK;
    }
    g_msgHandleRes = SOFTBUS_NOT_FIND;
    return SOFTBUS_INVALID_PARAM;
}

static void TestFfrtRemoveMsgCustom(int32_t param1, int32_t param2)
{
    TestFfrtMsgHandleInfo info = {};
    info.param1 = param1;
    info.param2 = param2;
    g_testFfrtLoopHandler.looper->RemoveMessageCustom(g_testFfrtLoopHandler.looper,
        &g_testFfrtLoopHandler, TestFfrtRemoveMsgInfo, &info);
}

static void TestFfrtRemoveMsg(int32_t msgType)
{
    g_testFfrtLoopHandler.looper->RemoveMessage(g_testFfrtLoopHandler.looper,
        &g_testFfrtLoopHandler, msgType);
}

static int32_t InitTestFfrtLooper(int type)
{
    g_testFfrtLoopHandler.name = (char *)"testFfrtLoopHandler";
    g_testFfrtLoopHandler.HandleMessage = FfrtMsgHandler;
    g_testFfrtLoopHandler.looper = GetLooper(type);
    if (g_testFfrtLoopHandler.looper == nullptr) {
        GTEST_LOG_(INFO) << "test ffrt init looper fail";
        return SOFTBUS_NO_INIT;
    }
    return SOFTBUS_OK;
}

static void DeInitTestFfrtLooper(void)
{
    g_testFfrtLoopHandler.HandleMessage = nullptr;
    g_testFfrtLoopHandler.looper = nullptr;
}

/**
 * @tc.name: LooperCreateDestroyTest001
 * @tc.desc: test create and destroy looper with buscenter_lp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MessageHandlerFfrtTest, LooperCreateDestroyTest001, TestSize.Level1)
{
    SoftBusLooper *looper = CreateNewLooper(nullptr);
    EXPECT_EQ(looper, nullptr);
    looper = CreateNewLooper("Test_Max_Loop_Name_Len");
    EXPECT_EQ(looper, nullptr);
    DestroyLooper(nullptr);
    looper = CreateNewLooper("BusCenter_Lp");
    ASSERT_NE(looper, nullptr) << "create BusCenter_Lp fail";
    SetLooper(LOOP_TYPE_DEFAULT, looper);
    DestroyLooper(looper);

    looper = CreateNewLooper("BusCenter_Lp");
    ASSERT_NE(looper, nullptr) << "create BusCenter_Lp fail";
    SetLooper(LOOP_TYPE_DEFAULT, looper);
    uint64_t delayMillis = 200;
    int32_t ret = InitTestFfrtLooper(LOOP_TYPE_DEFAULT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TestFfrtPostMsgToHandler(0, nullptr, delayMillis, TestFfrtFreeMessage);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DeInitTestFfrtLooper();
    DestroyLooper(looper);

    looper = CreateNewLooper("BusCenter_Lp");
    ASSERT_NE(looper, nullptr) << "create BusCenter_Lp fail";
    SetLooper(LOOP_TYPE_DEFAULT, looper);
    ret = InitTestFfrtLooper(LOOP_TYPE_DEFAULT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    g_isNeedCondWait = true;
    ret = TestFfrtPostMsgToHandler(0, nullptr, delayMillis, TestFfrtFreeMessage);
    EXPECT_EQ(ret, SOFTBUS_OK);
    if (g_isNeedCondWait) {
        CondWait();
    }
    DeInitTestFfrtLooper();
    EXPECT_EQ(g_testFfrtLoopHandler.HandleMessage, nullptr);
    EXPECT_EQ(g_testFfrtLoopHandler.looper, nullptr);
    DestroyLooper(looper);
}

/**
 * @tc.name: LnnPostFfrtMsgTest001
 * @tc.desc: test msg handle with lnn_lp, wait signal before destroy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MessageHandlerFfrtTest, LnnPostFfrtMsgTest001, TestSize.Level1)
{
    int32_t ret = InitTestFfrtLooper(LOOP_TYPE_LNN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    g_isNeedCondWait = true;
    ret = TestFfrtPostMsgToHandler(0, nullptr, 0, TestFfrtFreeMessage);
    EXPECT_EQ(ret, SOFTBUS_OK);
    if (g_isNeedCondWait) {
        CondWait();
    }
    DeInitTestFfrtLooper();
    EXPECT_EQ(g_testFfrtLoopHandler.HandleMessage, nullptr);
    EXPECT_EQ(g_testFfrtLoopHandler.looper, nullptr);
}

/**
 * @tc.name: LooperCreateLnnLpTest002
 * @tc.desc: test msg handle with lnn_lp, no wait signal before destroy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MessageHandlerFfrtTest, LooperCreateLnnLpTest002, TestSize.Level1)
{
    SoftBusLooper *looper = CreateNewLooper("BusCenter_Lp");
    ASSERT_NE(looper, nullptr) << "create BusCenter_Lp fail";
    SetLooper(LOOP_TYPE_DEFAULT, looper);
    int32_t ret = InitTestFfrtLooper(LOOP_TYPE_DEFAULT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TestFfrtPostMsgToHandler(0, nullptr, 0, TestFfrtFreeMessage);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DeInitTestFfrtLooper();
    EXPECT_EQ(g_testFfrtLoopHandler.HandleMessage, nullptr);
    EXPECT_EQ(g_testFfrtLoopHandler.looper, nullptr);
    DestroyLooper(looper);
    SoftBusLooper *looperExt = GetLooper(LOOP_TYPE_DEFAULT);
    EXPECT_EQ(looperExt, nullptr);
}

/**
 * @tc.name: LooperCreateLnnLpTest003
 * @tc.desc: test destroy looper after batch post msg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MessageHandlerFfrtTest, LooperCreateLnnLpTest003, TestSize.Level1)
{
    SoftBusLooper *looper = CreateNewLooper("BusCenter_Lp");
    ASSERT_NE(looper, nullptr) << "create BusCenter_Lp fail";
    SetLooper(LOOP_TYPE_DEFAULT, looper);
    int32_t ret = InitTestFfrtLooper(LOOP_TYPE_DEFAULT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint64_t delayMillis = 10;
    for (int i = 0; i < 1000; i++) {
        ret = TestFfrtPostMsgToHandler(0, nullptr, delayMillis, TestFfrtFreeMessage);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
    DeInitTestFfrtLooper();
    EXPECT_EQ(g_testFfrtLoopHandler.HandleMessage, nullptr);
    EXPECT_EQ(g_testFfrtLoopHandler.looper, nullptr);
    DestroyLooper(looper);
    SoftBusLooper *looperExt = GetLooper(LOOP_TYPE_DEFAULT);
    EXPECT_EQ(looperExt, nullptr);
}

/**
 * @tc.name: LooperCreateLnnLpTest004
 * @tc.desc: test destroy looper after batch post msg and remove
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MessageHandlerFfrtTest, LooperCreateLnnLpTest004, TestSize.Level1)
{
    SoftBusLooper *looper = CreateNewLooper("BusCenter_Lp");
    ASSERT_NE(looper, nullptr) << "create BusCenter_Lp fail";
    SetLooper(LOOP_TYPE_DEFAULT, looper);
    int32_t ret = InitTestFfrtLooper(LOOP_TYPE_DEFAULT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint64_t delayMillis = 10;
    int32_t msgType = 1;
    for (int i = 0; i < 1000; i++) {
        ret = TestFfrtPostMsgToHandler(msgType, nullptr, delayMillis, TestFfrtFreeMessage);
        EXPECT_EQ(ret, SOFTBUS_OK);
        if (i % 10 == 0) {
            TestFfrtRemoveMsg(msgType);
        }
    }
    DeInitTestFfrtLooper();
    EXPECT_EQ(g_testFfrtLoopHandler.HandleMessage, nullptr);
    EXPECT_EQ(g_testFfrtLoopHandler.looper, nullptr);
    DestroyLooper(looper);
    SoftBusLooper *looperExt = GetLooper(LOOP_TYPE_DEFAULT);
    EXPECT_EQ(looperExt, nullptr);
}

/**
 * @tc.name: LooperCreateLnnLpTest005
 * @tc.desc: test lnn looper msg handle with delay, multi post
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MessageHandlerFfrtTest, LooperCreateLnnLpTest005, TestSize.Level1)
{
    int32_t ret = InitTestFfrtLooper(LOOP_TYPE_LNN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint64_t delayMillis1 = 200;
    uint64_t delayMillis2 = 100;
    g_isNeedCondWait = true;
    ret = TestFfrtPostMsgToHandler(0, nullptr, delayMillis1, TestFfrtFreeMessage);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TestFfrtPostMsgToHandler(0, nullptr, delayMillis2, TestFfrtFreeMessage);
    EXPECT_EQ(ret, SOFTBUS_OK);
    if (g_isNeedCondWait) {
        CondWait();
    }
    g_isNeedCondWait = true;
    if (g_isNeedCondWait) {
        CondWait();
    }
    DeInitTestFfrtLooper();
    EXPECT_EQ(g_testFfrtLoopHandler.HandleMessage, nullptr);
    EXPECT_EQ(g_testFfrtLoopHandler.looper, nullptr);
}

/**
 * @tc.name: LooperRemoveMsgTest001
 * @tc.desc: test custom remove msg, match target msg, post delay 200ms
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MessageHandlerFfrtTest, LooperRemoveMsgTest001, TestSize.Level1)
{
    int32_t ret = InitTestFfrtLooper(LOOP_TYPE_LNN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint64_t delayMillis = 200;
    uint32_t param1 = 1;
    uint64_t param2 = 2;
    TestFfrtMsgHandleInfo *info = static_cast<TestFfrtMsgHandleInfo *>(SoftBusCalloc(sizeof(TestFfrtMsgHandleInfo)));
    ASSERT_NE(info, nullptr) << "calloc ffrt msg handle info fail";
    info->param1 = param1;
    info->param2 = param2;
    ret = TestFfrtPostMsgToHandler(0, info, delayMillis, TestFfrtFreeMessage);
    EXPECT_EQ(ret, SOFTBUS_OK);
    g_msgHandleRes = SOFTBUS_INVALID_PARAM;
    TestFfrtRemoveMsgCustom(param1, param2);
    EXPECT_EQ(g_msgHandleRes, SOFTBUS_OK);

    TestFfrtMsgHandleInfo *info1 = static_cast<TestFfrtMsgHandleInfo *>(SoftBusCalloc(sizeof(TestFfrtMsgHandleInfo)));
    ASSERT_NE(info1, nullptr) << "calloc ffrt msg handle info fail";
    info1->param1 = param1;
    info1->param2 = param2;
    ret = TestFfrtPostMsgToHandler(0, info1, 0, TestFfrtFreeMessage);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TestFfrtRemoveMsgCustom(param1, param2);
    DeInitTestFfrtLooper();
    EXPECT_EQ(g_testFfrtLoopHandler.HandleMessage, nullptr);
    EXPECT_EQ(g_testFfrtLoopHandler.looper, nullptr);
}

/**
 * @tc.name: LooperRemoveMsgTest002
 * @tc.desc: test custom remove msg, not match target msg, post delay 200ms
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MessageHandlerFfrtTest, LooperRemoveMsgTest002, TestSize.Level1)
{
    int32_t ret = InitTestFfrtLooper(LOOP_TYPE_LNN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint64_t delayMillis = 200;
    uint32_t param1 = 1;
    uint64_t param2 = 2;
    TestFfrtMsgHandleInfo *info = static_cast<TestFfrtMsgHandleInfo *>(SoftBusCalloc(sizeof(TestFfrtMsgHandleInfo)));
    ASSERT_NE(info, nullptr) << "calloc ffrt msg handle info fail";
    info->param1 = param1;
    info->param2 = param2;
    g_isNeedCondWait = true;
    ret = TestFfrtPostMsgToHandler(0, info, delayMillis, TestFfrtFreeMessage);
    EXPECT_EQ(ret, SOFTBUS_OK);
    g_msgHandleRes = SOFTBUS_INVALID_PARAM;
    TestFfrtRemoveMsgCustom(param2, param1);
    EXPECT_EQ(g_msgHandleRes, SOFTBUS_NOT_FIND);
    if (g_isNeedCondWait) {
        CondWait();
    }
    DeInitTestFfrtLooper();
    EXPECT_EQ(g_testFfrtLoopHandler.HandleMessage, nullptr);
    EXPECT_EQ(g_testFfrtLoopHandler.looper, nullptr);
}

/**
 * @tc.name: LooperRemoveMsgTest003
 * @tc.desc: test remove msg without custom, post delay 200ms
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MessageHandlerFfrtTest, LooperRemoveMsgTest003, TestSize.Level1)
{
    int32_t ret = InitTestFfrtLooper(LOOP_TYPE_LNN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint64_t delayMillis = 200;
    TestFfrtMsgHandleInfo *info = static_cast<TestFfrtMsgHandleInfo *>(SoftBusCalloc(sizeof(TestFfrtMsgHandleInfo)));
    ASSERT_NE(info, nullptr) << "calloc ffrt msg handle info fail";
    info->param1 = 1;
    info->param2 = 2;
    int32_t msgType = 1;
    ret = TestFfrtPostMsgToHandler(msgType, info, delayMillis, TestFfrtFreeMessage);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TestFfrtRemoveMsg(msgType);
    DeInitTestFfrtLooper();
    EXPECT_EQ(g_testFfrtLoopHandler.HandleMessage, nullptr);
    EXPECT_EQ(g_testFfrtLoopHandler.looper, nullptr);
}

/**
 * @tc.name: LooperFreeMsgTest001
 * @tc.desc: test free msg custom
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MessageHandlerFfrtTest, LooperFreeMsgTest001, TestSize.Level1)
{
    int32_t ret = InitTestFfrtLooper(LOOP_TYPE_LNN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TestFfrtMsgHandleInfo *info = static_cast<TestFfrtMsgHandleInfo *>(SoftBusCalloc(sizeof(TestFfrtMsgHandleInfo)));
    ASSERT_NE(info, nullptr) << "calloc ffrt msg handle info fail";
    uint64_t delayMillis = 100;
    info->param1 = 1;
    info->param2 = 2;
    g_isNeedCondWait = true;
    ret = TestFfrtPostMsgToHandler(0, info, delayMillis, TestFfrtFreeMessage);
    EXPECT_EQ(ret, SOFTBUS_OK);
    if (g_isNeedCondWait) {
        CondWait();
    }
    DeInitTestFfrtLooper();
    EXPECT_EQ(g_testFfrtLoopHandler.HandleMessage, nullptr);
    EXPECT_EQ(g_testFfrtLoopHandler.looper, nullptr);
}

/**
 * @tc.name: LooperFreeMsgTest002
 * @tc.desc: test free msg without custom
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MessageHandlerFfrtTest, LooperFreeMsgTest002, TestSize.Level1)
{
    int32_t ret = TestFfrtPostMsgToHandler(0, nullptr, 0, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ret = InitTestFfrtLooper(LOOP_TYPE_LNN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint64_t delayMillis = 100;
    g_isNeedCondWait = true;
    ret = TestFfrtPostMsgToHandler(0, nullptr, delayMillis, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    if (g_isNeedCondWait) {
        CondWait();
    }
    DeInitTestFfrtLooper();
    EXPECT_EQ(g_testFfrtLoopHandler.HandleMessage, nullptr);
    EXPECT_EQ(g_testFfrtLoopHandler.looper, nullptr);
}

/**
 * @tc.name: LooperSetDumpable001
 * @tc.desc: test SetLooperDumpable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MessageHandlerFfrtTest, LooperSetDumpable001, TestSize.Level1)
{
    SoftBusLooper *looper = GetLooper(LOOP_TYPE_LNN);
    ASSERT_NE(looper, nullptr) << "create lnn_looper fail";
    SetLooperDumpable(nullptr, false);
    EXPECT_TRUE(looper->dumpable);
    SetLooperDumpable(looper, false);
    EXPECT_FALSE(looper->dumpable);
    SetLooperDumpable(looper, true);
    EXPECT_TRUE(looper->dumpable);
    DumpLooper(nullptr);
    DumpLooper(looper);
}
} // namespace OHOS
