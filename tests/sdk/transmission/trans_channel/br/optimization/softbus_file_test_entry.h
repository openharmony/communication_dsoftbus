#ifndef SOFTBUS_TEST_ENTERY_H
#define SOFTBUS_TEST_ENTERY_H

#include <string>
#include <unordered_map>

const std::string FILE_TEST_PKG_NAME = "com.huawei.plrdtest.dsoftbus";
const std::string FILE_TEST_PKG_NAME_DEMO = "com.huawei.plrdtest.dsoftbus1";
const std::string FILE_SESSION_NAME = "com.huawei.plrdtest.dsoftbus.JtSendFile_10";
const std::string FILE_SESSION_NAME_DEMO = "com.huawei.plrdtest.dsoftbus.JtSendFile_demo";

enum TEST_SIDE {
    PASSIVE_OPENSESSION_WAY = 0,
    ACTIVE_OPENSESSION_WAY,
    ACTIVE_ANOTHER_OPENSESSION_WAY
};

struct SoftbusTestEntry {
    int testSide_;
    bool isTestWithPhone_;
    int aliveTime_;
    int transNums_;
    int pressureNums_;
};

const SoftbusTestEntry *GetTestEntry(void);

#endif