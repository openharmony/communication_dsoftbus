/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "softbushidumper_fuzzer.h"

#include <securec.h>

#include "comm_log.h"
#include "fuzz_data_generator.h"
#include "message_handler.h"
#include "softbus_error_code.h"
#include "legacy/softbus_hidumper.h"
#include "legacy/softbus_hidumper_bc_mgr.h"
#include "legacy/softbus_hidumper_broadcast.h"
#include "legacy/softbus_hidumper_buscenter.h"
#include "legacy/softbus_hidumper_conn.h"
#include "legacy/softbus_hidumper_disc.h"
#include "legacy/softbus_hidumper_interface.h"
#include "legacy/softbus_hidumper_nstack.h"
#include "legacy/softbus_hidumper_trans.h"

namespace {
const char *DUMP_CMD = "test";

std::vector<const char *> CMD_ALARM = {"alert", "-l", DUMP_CMD};
std::vector<const char *> CMD_BCMGR = {"broadcastMgr", "-l", DUMP_CMD};
std::vector<const char *> CMD_BROADCAST = {"broadcast", "-l", DUMP_CMD};
std::vector<const char *> CMD_BUSCENTER = {"buscenter", "-l", DUMP_CMD};
std::vector<const char *> CMD_CONN = {"conn", "-l", DUMP_CMD};
std::vector<const char *> CMD_DISC = {"disc", "-l", DUMP_CMD};
std::vector<const char *> CMD_NSTACK_DSTREAM = {"dstream", "-l", DUMP_CMD};
std::vector<const char *> CMD_NSTACK_DFILE = {"dfile", "-l", DUMP_CMD};
std::vector<const char *> CMD_NSTACK_DFINDER = {"dfinder", "-l", DUMP_CMD};
std::vector<const char *> CMD_NSTACK_DMSG = {"dmsg", "-l", DUMP_CMD};
std::vector<const char *> CMD_STATS = {"stats", "-l", DUMP_CMD};
std::vector<const char *> CMD_TRANS = {"trans", "-l", DUMP_CMD};

const std::vector<std::vector<const char *>> DUMP_CMD_LIST = {CMD_ALARM, CMD_BCMGR, CMD_BROADCAST, CMD_BUSCENTER,
    CMD_CONN, CMD_DISC, CMD_NSTACK_DSTREAM, CMD_NSTACK_DFILE, CMD_NSTACK_DFINDER, CMD_NSTACK_DMSG, CMD_STATS,
    CMD_TRANS};

void DoDump(void)
{
    std::vector<const char *> dumpCmd;
    if (!GenerateFromList(dumpCmd, DUMP_CMD_LIST) || dumpCmd.empty()) {
        return;
    }

    SoftBusDumpDispatch(1, dumpCmd.size(), const_cast<const char **>(&dumpCmd[0]));
}

static int32_t SoftBusVarDumpCallback(int32_t fd)
{
    (void)fd;
    return SOFTBUS_OK;
}

class TestEnv {
public:
    TestEnv()
    {
        isInited_ = false;
        int32_t ret = LooperInit();
        COMM_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, COMM_TEST, "init looper failed");
        ret = SoftBusHiDumperInit();
        COMM_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, COMM_TEST, "init hidumper failed");

        SoftBusRegBcMgrVarDump(DUMP_CMD, &SoftBusVarDumpCallback);
        SoftBusRegBroadcastVarDump(DUMP_CMD, &SoftBusVarDumpCallback);
        SoftBusRegBusCenterVarDump(const_cast<char *>(DUMP_CMD), &SoftBusVarDumpCallback);
        SoftBusRegConnVarDump(DUMP_CMD, &SoftBusVarDumpCallback);
        SoftBusRegDiscVarDump(const_cast<char *>(DUMP_CMD), &SoftBusVarDumpCallback);
        SoftBusRegTransVarDump(DUMP_CMD, &SoftBusVarDumpCallback);
        SoftBusRegConnVarDump(DUMP_CMD, &SoftBusVarDumpCallback);
        isInited_ = true;
    }

    ~TestEnv()
    {
        isInited_ = false;
        LooperDeinit();
        SoftBusHiDumperDeinit();
    }

    bool IsInited(void)
    {
        return isInited_;
    }

private:
    volatile bool isInited_;
};
} // anonymous namespace

extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    static TestEnv env;
    if (!env.IsInited()) {
        return 0;
    }

    DataGenerator::Write(data, size);
    DoDump();
    DataGenerator::Clear();
    return 0;
}