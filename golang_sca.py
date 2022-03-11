# Project:  Golang SCA
# Author:   fdl66
import os
import re
import sys
import json
import time
import random
import requests

CACHE_FILE = "cache_dict.json"
OUTPUT_FILE = "output/res.json"


SINGLE_REQUIRE_REG = r"^require[\s]+(.*?)[\s]+v(\S+)[\s]*.*$"
MULTI_REQUIRE_REG = r"(.*?)[\s]+v(\S+)[\s]*.*"


def _dir_dfs(tmp_path, file_list, root_path):
    """
    遍历目录
    :param tmp_path: 入参，路径
    :param file_list: 出参，文件列表
    :param root_path: 文件根路径
    :return: None
    """
    now_path = os.path.join(root_path, tmp_path)

    if os.path.isfile(now_path):
        file_list.append(now_path)

    elif os.path.isdir(now_path):
        for item in os.listdir(now_path):
            _dir_dfs(item, file_list, now_path)


def _parse_one_line(one_line, parse_reg, result):
    """
    根据正则解析go.mod文件的一行内容
    :param one_line:    [IN]    go.mod文件的原生内容
    :param parse_reg:   [IN]    行解析正则
    :param result:      [OUT]   将解析好的数据字典（库名、库版本号）添加到此列表中
    :return: None
    """
    match_groups = re.search(parse_reg, one_line, re.S)
    if not match_groups:
        print("[{}] parse failed".format(one_line))
        return

    go_module_name = match_groups.group(1)
    go_module_version = match_groups.group(2)
    if not go_module_name or not go_module_version:
        print("[{}] parse failed".format(one_line))
        return

    result.append({
        "name": go_module_name.lower(),
        "version": "v{}".format(go_module_version.lower())
    })


def parse_go_mod_file(go_mod_path):
    """
    解析一个go.mod文件
    :param go_mod_path: go.mod文件路径
    :return: go.mod文件所包含的所有依赖库
        [{
            "name": "github.com/gin-gonic/gin",
            "version": "v1.6.0"
        }, ...]
    """
    all_require_mod = list()
    with open(go_mod_path, 'r') as f_obj:
        one_line = f_obj.readline()
        add_flag = False

        while one_line is not None:
            one_line = one_line.strip()

            if one_line.find("require") != -1 and one_line.find("(") != -1:
                add_flag = True

            elif add_flag and one_line.find(")") != -1 and one_line.find("(") == -1:
                add_flag = False

            elif not add_flag and one_line.find("require") != -1:
                _parse_one_line(one_line, SINGLE_REQUIRE_REG, all_require_mod)

            elif add_flag and one_line:
                _parse_one_line(one_line, MULTI_REQUIRE_REG, all_require_mod)

            one_line = f_obj.readline()
            if not one_line:
                break

    return all_require_mod


def dup_mods(mods):
    tmp_list = ["{} {}".format(item["name"], item["version"]) for item in mods]
    tmp_list = list(set(tmp_list))
    res_list = []
    for item in tmp_list:
        mod = item.split()
        res_list.append({
            "name": mod[0],
            "version": mod[1]
        })

    return res_list


def get_mod_advisories_from_cache(mod):
    """
    从缓存中获取一个库的威胁信息
    TODO: 缓存过期、文件锁（单线程暂时没有必要）
    :param mod: 字符串 eg: ("github.com/gin-gonic/gin v1.6.0")
    :return: advisories or None         PS: [] 表示没有威胁， None 表示没有查询过 或者 缓存失效
    """
    if not os.path.isfile(CACHE_FILE):
        return None

    with open(CACHE_FILE, 'r') as f_obj:
        cache_cont = ("".join(f_obj.readlines())).strip()
        if not cache_cont:
            return None

    cache_dict = json.loads(cache_cont)
    if mod in cache_dict:
        return cache_dict[mod]["advisories"]

    return None


def get_mod_advisories_by_req(mod_name, mod_version):
    """
    获取某个模块的安全警告信息
    :param mod_name: 模块名
    :param mod_version: 模块版本号
    :return: 警告信息
    """
    # eg: https://deps.dev/_/s/go/p/github.com%2Fburntsushi%2Ftoml/v/v0.3.1
    req_url = "https://deps.dev/_/s/go/p/{}/v/{}".format(mod_name.replace("/", "%2F"), mod_version)
    tmp_header = {
        "authority": "deps.dev",
        "method": "GET",
        "path": "/_/s/go/p/{}/v/{}".format(mod_name.replace("/", "%2F"), mod_version),
        "scheme": "https",
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br",
        "accept-language": "zh-CN,zh;q=0.9",
        "cache-control": "no-cache",
        "cookie": "_dd_s=logs=1&id=babf963a-d7e6-4a02-a1c4-daab4a25b32c&created=1646924177416&expire=1646928762715",
        "pragma": "no-cache",
        "referer": "https://deps.dev/go/{}/{}".format(mod_name.replace("/", "%2F"), mod_version),
        "sec-ch-ua": "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"98\", \"Google Chrome\";v=\"98\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36"
    }
    try:
        req_res = requests.get(req_url, headers=tmp_header, verify=False, timeout=10)
        if not req_res:
            print("[{} {}] get advisories failed, request failed".format(mod_name, mod_version))
            return None

        elif req_res.status_code != 200:
            print("[{} {}] get advisories failed, res:[{}][{}]".format(
                mod_name, mod_version, req_res.status_code, req_res.text))
            return None

        return json.loads(req_res.text)["version"]["advisories"]

    except Exception as ex:
        print(ex)
        print("[{} {} {}] get advisories failed!!!".format(mod_name, mod_version, req_url))
        return None


def _update_save_file(file_path, mod, advisories):
    if os.path.isfile(file_path):
        with open(file_path, 'r') as f_obj:
            file_cont = ("".join(f_obj.readlines())).strip()
    else:
        file_cont = ""

    dict_fmt = json.loads(file_cont) if file_cont else dict()
    dict_fmt["{} {}".format(mod["name"], mod["version"])] = {
        "name": mod["name"],
        "version": mod["version"],
        "time": time.time(),
        "advisories": advisories
    }

    with open(file_path, 'w') as f_obj:
        f_obj.write(json.dumps(dict_fmt))


def save_one_res(mod, advisories, update_cache=False):
    # 缓存更新
    if update_cache:
        _update_save_file(CACHE_FILE, mod, advisories)

    # 保存结果
    _update_save_file(OUTPUT_FILE, mod, advisories)


def print_help():
    print("python3 golang_sca.py file/dir ...")


def parse_args():
    len_argv = len(sys.argv)
    if len_argv < 2 or len_argv > 256:
        print_help()
        raise Exception("params error!")

    valid_files = []
    for idx in range(1, len_argv):
        _dir_dfs(sys.argv[idx], valid_files, "")

    return valid_files


def main():
    files = parse_args()

    mods = list()
    for go_mod in files:
        mods.extend(parse_go_mod_file(go_mod))

    # 去重
    mods = dup_mods(mods)

    for mod in mods:
        mod_cache = get_mod_advisories_from_cache("{} {}".format(mod["name"], mod["version"]))
        # 缓存命中
        if mod_cache is not None:
            save_one_res(mod, mod_cache, False)

        # 缓存未命中
        else:
            save_one_res(mod, get_mod_advisories_by_req(mod["name"], mod["version"]), True)
            time.sleep(float(random.randint(1, 30)) / 10)


if __name__ == '__main__':
    main()
    print("finish!!!")
