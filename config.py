#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# Copyright (c) 2020 Huawei Device Co., Ltd.
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
from PyInquirer import prompt


def enable_option(file_name):
    option_list = []
    try:
        with open('.config', 'r') as f:
            for line in f:
                if line.startswith('CONFIG_'):
                    str1 = line.split('=')
                    option_list.append(str1[0][7:])
    except IOError:
        print('No config file')
        return

    if os.path.exists('.config'):
        os.system('rm .config')

    file_data = ''
    with open(file_name, 'r') as f:
        for line in f:
            if '=' in line:
                str1 = line.split('=')
                if str1[0].strip() in option_list:
                    line = str1[0] + '= true\n'
                else:
                    line = str1[0] + '= false\n'
            file_data += line

    with open(file_name, 'w') as f:
        f.write(file_data)

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

def update_config_file():
    option = ask_option()
    os.system('menuconfig')
    if (option == 'standard'):
        enable_option('./adapter/default_config/feature_config/standard/config.gni')
    elif (option == 'small'):
        enable_option('./adapter/default_config/feature_config/small/config.gni')
    else:
        enable_option('./adapter/default_config/feature_config/mini/config.gni')

if __name__ == '__main__':
    print('##### Welcome to Dsoftbus #####')
    update_config_file()