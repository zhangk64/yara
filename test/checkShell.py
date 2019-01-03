#!/usr/bin/env python 
# -*- coding:utf-8 -*-
import yara
import os
import sys
reload(sys)
sys.setdefaultencoding('utf8')

# 将yara规则编译
def getRules(path):
    index = 0
    filepath = {}
    for dirpath, dirs, files in os.walk(path):
        for file in files:
            ypath = os.path.join(dirpath, file)
            key = "rule" + str(index)
            filepath[key] = ypath
            index += 1
    yararule = yara.compile(filepaths=filepath)
    return yararule

# 扫描结果处理
def processResult(result):
    for key in result:
        for dic in result[key]:
            lis = dic['strings']
            for i, k in enumerate(lis):
                print i, repr(k['data'])

# 扫描函数
def scan(rule, path):
    global cnt
    for file in os.listdir(path.decode("utf-8")):
        mapath = os.path.join(path, file)
        # 如果是文件则匹配yara规则
        if os.path.isfile(mapath):
            # print mapath
            fp = open(mapath, 'rb')
            matches = rule.match(data=fp.read())
            if len(matches) > 0:
                cnt += 1
                print mapath
                # print matches
                processResult(matches)
        # 如果是目录则递归查找目录下的文件
        if os.path.isdir(mapath):
            scan(rule,mapath)

if __name__ == '__main__':
    cnt = 0
    rulepath = sys.path[0] + "/rules"  # yara规则目录
    malpath = sys.path[0] + "/webshell"  # 本地待检测目录
    yararule = getRules(rulepath)
    scan(yararule, malpath)
    print "cnt:", cnt
