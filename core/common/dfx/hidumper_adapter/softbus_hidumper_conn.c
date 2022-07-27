/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include <stdio.h>
#include <string.h>
#include "softbus_hidumper.h"
#include "softbus_hidumper_conn.h"

static void SoftBusDumpConnHelp(int fd)
{
    dprintf(fd, "s%\n", "test");
}

int SoftBusConnDumpHander(int fd, int argc, const char **argv)
{
    if (argc == 0 || strcmp(argv[0], "-h") == 0) {
        SoftBusDumpConnHelp(fd);
        return 0;
    }

    return 1;
}
