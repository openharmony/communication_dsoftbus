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
#include "softbus_hidumper_disc.h"

#define SOFTBUS_DISC_DUMP_BLEINFOMANGER "BleInfoManager"
#define SOFTBUS_DISC_DUMP_BLEADVERTISER "BleAdvertiser"
#define SOFTBUS_DISC_DUMP_BLELISTENER "BleListener"
#define SOFTBUS_DISC_DUMP_PUBLICMGR "PublicMgr"
#define SOFTBUS_DISC_DUMP_SUBSCRIBEMGR "SubscribeMgr"
#define SOFTBUS_DISC_DUMP_CAPABILITYDATA "CapabilityData"
#define SOFTBUS_DISC_DUMP_LOCALDEVINFO "LocalDevInfo"

static void SoftBusDumpDiscHelp(int fd)
{
    dprintf(fd, "Usage: [-h] [-l] [disc] [conn] [buscenter] [trans] [dstream] [dfile] [dfinder] [dmsg]\n");
    dprintf(fd, "   -h         List all the dump item of disc\n");
    dprintf(fd, "   -l         List all the dump item of disc\n");
    dprintf(fd, "   BleInfoManager       List all the dump item of conn\n");
    dprintf(fd, "   BleAdvertiser  List all the dump item of buscenter\n");
    dprintf(fd, "   BleListener      List all the dump item of trans\n"); 
    dprintf(fd, "   PublicMgr    List all the dump item of dstream\n");
    dprintf(fd, "   SubscribeMgr      List all the dump item of dfile\n");
    dprintf(fd, "   CapabilityData    List all the dump item of dfinder\n");
    dprintf(fd, "   LocalDevInfo       List all the dump item of dmsg\n");
}

static void SoftBusDumpDiscBleInfoManager(int fd)
{
    dprintf(fd, "BleInfoManager info:");
}

static void SoftBusDumpDiscBleAdvertiser(int fd)
{
    dprintf(fd, "BleAdvertiser info:");
}

static void SoftBusDumpDiscBleListener(int fd)
{
    dprintf(fd, "BleListener info:");
}

static void SoftBusDumpDiscPublicMgr(int fd)
{
    dprintf(fd, "PublicMgr info:");
}

static void SoftBusDumpDiscSubscribeMgr(int fd)
{
    dprintf(fd, "Subscribe Manager info:");
}

static void SoftBusDumpDiscCapabilityData(int fd)
{
    dprintf(fd, "CapabilityData info:");
}

static void SoftBusDumpDiscLocalDevInfo(int fd)
{
    dprintf(fd, "LocalDevInfo info:");
}

int SoftBusDiscDumpHander(int fd, int argc, const char **argv)
{
    if (argc == 0 || strcmp(argv[0], "-h") == 0) {
        SoftBusDumpDiscHelp(fd);
        return 0;
    }

    if (strcmp(argv[0], "-l") == 0) {
        if (strcmp(argv[1], SOFTBUS_DISC_DUMP_BLEINFOMANGER) == 0) {
            SoftBusDumpDiscBleInfoManager(fd);
        } else if (strcmp(argv[1], SOFTBUS_DISC_DUMP_BLEADVERTISER) == 0) {
            SoftBusDumpDiscBleAdvertiser(fd);
        } else if (strcmp(argv[1], SOFTBUS_DISC_DUMP_BLELISTENER) == 0) {
            SoftBusDumpDiscBleListener(fd);
        } else if (strcmp(argv[1], SOFTBUS_DISC_DUMP_PUBLICMGR) == 0) {
            SoftBusDumpDiscPublicMgr(fd);
        } else if (strcmp(argv[1], SOFTBUS_DISC_DUMP_SUBSCRIBEMGR) == 0) {
            SoftBusDumpDiscSubscribeMgr(fd);
        } else if (strcmp(argv[1], SOFTBUS_DISC_DUMP_CAPABILITYDATA) == 0) {
            SoftBusDumpDiscCapabilityData(fd);
        } else if (strcmp(argv[1], SOFTBUS_DISC_DUMP_LOCALDEVINFO) == 0) {
            SoftBusDumpDiscLocalDevInfo(fd);
        }
    }
    return 1;
}
