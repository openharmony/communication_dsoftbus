#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# Copyright (c) 2021 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os
import sys
import subprocess
from PyInquirer import prompt


def enable_option(file_name):
    option_list = []
    try:
        with open('.config', 'r') as config_file:
            for line in config_file:
                if line.startswith('CONFIG_'):
                    str1 = line.split('=')
                    option_list.append(str1[0][7:])
    except IOError:
        print('No config file')
        return

    if os.path.exists('.config'):
        os.remove('.config')

    file_data = ''
    with open(file_name, 'r') as gni_file:
        for line in gni_file:
            if '=' in line:
                str1 = line.split('=')
                if str1[0].strip() in option_list:
                    line = str1[0] + '= true\n'
                else:
                    line = str1[0] + '= false\n'
            file_data += line

    flags = os.O_WRONLY | os.O_CREAT
    modes = stat.S_IWUSR | stat.S_IRUSR
    with os.fdopen(os.open(file_name, flags, modes), 'w')as gni_file
        gni_file.write(file_data)


def ask_option():
    options_prompt = {
        'type': 'list',
        'name': 'option',
        'message': 'Which platform do you want to config?',
        'default': 'standard',
        'choices': ['standard', 'small', 'mini']
    }
    answers = prompt(options_prompt)
    return answers['option']


def main():
    print('##### Welcome to Dsoftbus #####')
    option = ask_option()
    subprocess.call(['menuconfig'])
    file_gni = './adapter/default_config/feature_config/platform/config.gni'
    if (option == 'standard'):
        file_gni = file_gni.replace('platform', 'standard')
    elif (option == 'small'):
        file_gni = file_gni.replace('platform', 'small')
    else:
        file_gni = file_gni.replace('platform', 'mini')
    enable_option(file_gni)


if __name__ == '__main__':
    sys.exit(main())