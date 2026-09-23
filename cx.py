# -*- coding: utf8 -*-

import os
import time
import urllib3
import asyncio
import re
import json
import base64
import requests

from Crypto.Cipher import AES

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ================= 配置区 start =================

# 学习通账号密码
user_info = {
    'username': os.environ["CHAOXING_USERNAME"],
    'password': os.environ["CHAOXING_PASSWORD"],
    'schoolid': os.environ.get("CHAOXING_SCHOOL", "None")
}

# Server酱 SendKey
server_chan_sckey = os.environ.get("CHAOXING_SERVER", "")

# Server酱开关
server_chan_status = os.environ.get(
    "CHAOXING_SERVEROR", "False"
).lower() in ("true", "1", "yes", "on")

server_chan = {
    'status': server_chan_status,
    'key': server_chan_sckey
}

# cookies缓存
cookies_path = "cookies.json"

# 已处理签到活动ID
activeid_path = "activeid.txt"

# ================= 配置区 end =================


class AutoSign(object):

    def __init__(self, username, password, schoolid=None):

        self.username = username
        self.password = password
        self.schoolid = schoolid

        self.headers = {
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'User-Agent': (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/131.0.0.0 Safari/537.36'
            )
        }

        self.session = requests.Session()
        self.session.headers.update(self.headers)

        # 先尝试使用缓存Cookie
        if not self.check_cookies_status(username):
            print("正在使用新登录接口登录学习通...")
            login_success = self.login(password, schoolid, username)

            if login_success:
                self.save_cookies(username)
            else:
                print("学习通登录失败")
        else:
            print("使用已有Cookie登录成功")

    # =========================================================
    # AES加密
    # =========================================================

    @staticmethod
    def aes_encrypt(text):
        """
        学习通目前登录接口使用 AES-128-CBC
        Key 和 IV:
        u2oh6Vu^HWe4_AES
        """

        key = b"u2oh6Vu^HWe4_AES"
        iv = b"u2oh6Vu^HWe4_AES"

        text = text.encode("utf-8")

        # PKCS7 padding
        pad_len = 16 - (len(text) % 16)
        text += bytes([pad_len]) * pad_len

        cipher = AES.new(key, AES.MODE_CBC, iv)

        encrypted = cipher.encrypt(text)

        return base64.b64encode(encrypted).decode("utf-8")

    # =========================================================
    # 保存Cookie
    # =========================================================

    def save_cookies(self, username):

        try:
            new_cookies = self.session.cookies.get_dict()

            data = {}

            if os.path.exists(cookies_path):
                with open(cookies_path, "r", encoding="utf-8") as f:
                    try:
                        data = json.load(f)
                    except Exception:
                        data = {}

            data[username] = new_cookies

            with open(cookies_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)

            print("Cookie保存成功")

        except Exception as e:
            print("Cookie保存失败：{}".format(type(e).__name__))

    # =========================================================
    # 检查Cookie
    # =========================================================

    def check_cookies_status(self, username):

        if not os.path.exists(cookies_path):
            return False

        try:
            with open(cookies_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if username not in data:
                return False

            cookies = data[username]

            if not cookies:
                return False

            # 写入Session
            for key, value in cookies.items():
                self.session.cookies.set(key, value)

            # 检查登录状态
            r = self.session.get(
                "https://i.chaoxing.com/base",
                allow_redirects=False,
                timeout=15
            )

            # 302通常说明需要重新登录
            if r.status_code in (301, 302, 303, 307, 308):
                print("Cookie已失效，需要重新登录")
                return False

            if r.status_code != 200:
                print("Cookie状态异常，需要重新登录")
                return False

            # 如果页面明显跳转到登录页面，也认为失效
            if "login" in r.url.lower():
                print("Cookie已失效，需要重新登录")
                return False

            print("Cookie有效")
            return True

        except Exception as e:
            print("Cookie检查失败，将重新登录")
            return False

    # =========================================================
    # 新版学习通登录
    # =========================================================

    def login(self, password, schoolid, username):

        login_url = "https://passport2.chaoxing.com/fanyalogin"

        login_headers = {
            "User-Agent": self.headers["User-Agent"],
            "Referer": (
                "https://passport2.chaoxing.com/login"
                "?fid=&newversion=true"
                "&refer=http%3A%2F%2Fi.chaoxing.com"
            ),
            "Content-Type": "application/x-www-form-urlencoded"
        }

        try:

            # 用户名和密码AES加密
            encrypted_username = self.aes_encrypt(username)
            encrypted_password = self.aes_encrypt(password)

            login_data = {
                "fid": "-1",
                "uname": encrypted_username,
                "password": encrypted_password,
                "refer": "http%253A%252F%252Fi.chaoxing.com",
                "t": "true",
                "forbidotherlogin": "0",
                "validate": "",
                "doubleFactorLogin": "0",
                "independentId": "0",
                "independentNameId": "0"
            }

            response = self.session.post(
                login_url,
                headers=login_headers,
                data=login_data,
                timeout=20
            )

            print("学习通登录接口状态码：{}".format(response.status_code))

            # 尝试解析JSON
            try:
                result = response.json()
            except Exception:
                print("登录接口返回的内容不是JSON")
                print("登录接口响应异常")
                return False

            # 登录成功
            if result.get("status") is True:

                print("登录成功")

                # 登录成功后再检查Cookie
                if self.session.cookies.get_dict():
                    print("已获取学习通Cookie")

                return True

            # 登录失败
            print("登录失败")

            # 输出服务器给出的错误原因，但绝不输出密码
            message = result.get("msg")
            if message:
                print("学习通返回：{}".format(message))

            return False

        except requests.RequestException as e:

            print("学习通登录网络请求失败")
            print("错误类型：{}".format(type(e).__name__))

            return False

        except Exception as e:

            print("学习通登录发生异常")
            print("错误类型：{}".format(type(e).__name__))

            return False

    # =========================================================
    # 检查活动ID
    # =========================================================

    def check_activeid(self, activeid):

        if not os.path.exists(activeid_path):
            with open(activeid_path, 'w', encoding='utf-8') as f:
                f.write("")

        with open(activeid_path, 'r', encoding='utf-8') as f:
            s = f.read()

            if str(activeid) in s:
                return True

        with open(activeid_path, 'a', encoding='utf-8') as f:
            f.write(str(activeid) + "\n")

        return False

    # =========================================================
    # 获取课程
    # =========================================================

        # =========================================================
    # 获取课程
    # =========================================================

    def get_all_classid(self):

        url = "https://mooc1-2.chaoxing.com/visit/interaction"

        try:
            r = self.session.get(
                url,
                headers={
                    **self.headers,
                    "Referer": "https://i.chaoxing.com/"
                },
                allow_redirects=True,
                verify=False,
                timeout=20
            )

            print("课程列表接口状态码：{}".format(r.status_code))
            print("课程列表最终URL：{}".format(r.url))

            # 如果被重新定向到登录页面
            if "login" in r.url.lower():
                print("课程列表请求被重定向到登录页面")
                return []

            html = r.text

            # -------------------------------------------------
            # 新版/不同HTML格式的通用解析
            # -------------------------------------------------

            pattern = re.compile(
                r'<input[^>]+name=["\']courseId["\'][^>]+'
                r'value=["\']([^"\']+)["\'][^>]*>'
                r'.{0,3000}?'
                r'<input[^>]+name=["\']classId["\'][^>]+'
                r'value=["\']([^"\']+)["\'][^>]*>',
                re.I | re.S
            )

            matches = pattern.findall(html)

            result = []

            for courseid, classid in matches:

                # 尝试在附近寻找课程名称
                classname = "未知课程"

                # 找到当前 classId 附近的HTML
                class_pos = html.find(
                    'value="{}"'.format(classid)
                )

                if class_pos == -1:
                    class_pos = html.find(
                        "value='{}'".format(classid)
                    )

                if class_pos != -1:

                    nearby = html[
                        max(0, class_pos - 1500):
                        class_pos + 3000
                    ]

                    title_match = re.search(
                        r'<a[^>]+title=["\']([^"\']+)["\']',
                        nearby,
                        re.I
                    )

                    if title_match:
                        classname = title_match.group(1).strip()

                result.append(
                    (
                        courseid,
                        classid,
                        classname
                    )
                )

            # 去重
            unique_result = []

            seen = set()

            for item in result:

                key = (
                    str(item[0]),
                    str(item[1])
                )

                if key not in seen:

                    seen.add(key)
                    unique_result.append(item)

            print(
                "获取到课程数量：{}".format(
                    len(unique_result)
                )
            )

            # 调试：如果还是0，打印网页的一些基本信息
            if not unique_result:

                print(
                    "课程页面HTML长度：{}".format(
                        len(html)
                    )
                )

                print(
                    "课程页面标题：{}".format(
                        re.findall(
                            r"<title[^>]*>(.*?)</title>",
                            html,
                            re.I | re.S
                        )[:1]
                    )
                )

                # 不打印整个HTML，避免日志过长
                print(
                    "课程页面前500字符：{}".format(
                        re.sub(
                            r"\s+",
                            " ",
                            html[:500]
                        )
                    )
                )

            return unique_result

        except requests.RequestException as e:

            print("获取课程网络请求失败")
            print(
                "错误类型：{}".format(
                    type(e).__name__
                )
            )

            return []

        except Exception as e:

            print("获取课程失败")
            print(
                "错误类型：{}".format(
                    type(e).__name__
                )
            )

            return []
    # =========================================================

    async def get_activeid(self, classid, courseid, classname):

        re_rule = (
            r'<div class="Mct" onclick="activeDetail\((.*),2,null\)">'
            r'[\s].*[\s].*[\s].*[\s].*'
            r'<dd class="green">.*</dd>'
            r'[\s]+[\s]</a>[\s]+</dl>'
            r'[\s]+<div class="Mct_center wid660 fl">'
            r'[\s]+<a href="javascript:;" shape="rect">(.*)</a>'
        )

        try:

            url = (
                'https://mobilelearn.chaoxing.com/widget/pcpick/stu/index'
                '?courseId={}&jclassId={}'
            ).format(courseid, classid)

            r = self.session.get(
                url,
                headers=self.headers,
                verify=False,
                timeout=20
            )

            res = re.findall(re_rule, r.text)

            if res:

                return {
                    'classid': classid,
                    'courseid': courseid,
                    'activeid': res[0][0],
                    'classname': classname,
                    'sign_type': res[0][1]
                }

        except Exception:
            return None

        return None

    # =========================================================
    # 普通签到
    # =========================================================

    def general_sign(self, classid, courseid, activeid):

        url = (
            'https://mobilelearn.chaoxing.com/'
            'widget/sign/pcStuSignController/preSign'
            '?activeId={}&classId={}&fid=39037&courseId={}'
        ).format(activeid, classid, courseid)

        try:

            r = self.session.get(
                url,
                headers=self.headers,
                verify=False,
                timeout=20
            )

            title_list = re.findall(r'<title>(.*)</title>', r.text)

            if not title_list:
                return {
                    'date': time.strftime(
                        "%m-%d %H:%M",
                        time.localtime()
                    ),
                    'status': '签到接口返回异常'
                }

            title = title_list[0]

            if "签到成功" not in title:

                return self.tphoto_sign(activeid)

            sign_date_list = re.findall(
                r'<em id="st">(.*)</em>',
                r.text
            )

            sign_date = (
                sign_date_list[0]
                if sign_date_list
                else time.strftime("%m-%d %H:%M")
            )

            return {
                'date': sign_date,
                'status': title
            }

        except Exception as e:

            return {
                'date': time.strftime("%m-%d %H:%M"),
                'status': '签到请求异常'
            }

    # =========================================================
    # 手势签到
    # =========================================================

    def hand_sign(self, classid, courseid, activeid):

        hand_sign_url = (
            "https://mobilelearn.chaoxing.com/"
            "widget/sign/pcStuSignController/signIn"
            "?courseId={}&classId={}&activeId={}"
        ).format(courseid, classid, activeid)

        try:

            r = self.session.get(
                hand_sign_url,
                headers=self.headers,
                verify=False,
                timeout=20
            )

            title = re.findall(r'<title>(.*)</title>', r.text)

            sign_date = re.findall(
                r'<em id="st">(.*)</em>',
                r.text
            )

            return {
                'date': sign_date[0] if sign_date else time.strftime(
                    "%m-%d %H:%M"
                ),
                'status': title[0] if title else r.text[:100]
            }

        except Exception:

            return {
                'date': time.strftime("%m-%d %H:%M"),
                'status': '手势签到请求异常'
            }

    # =========================================================
    # 二维码签到
    # =========================================================

    def qcode_sign(self, activeId):

        params = {
            'name': '',
            'activeId': activeId,
            'uid': '',
            'clientip': '',
            'useragent': '',
            'latitude': '-1',
            'longitude': '-1',
            'fid': '',
            'appType': '15'
        }

        try:

            res = self.session.get(
                'https://mobilelearn.chaoxing.com/pptSign/stuSignajax',
                params=params,
                timeout=20
            )

            return {
                'date': time.strftime("%m-%d %H:%M"),
                'status': res.text
            }

        except Exception:

            return {
                'date': time.strftime("%m-%d %H:%M"),
                'status': '二维码签到请求异常'
            }

    # =========================================================
    # 位置签到
    # =========================================================

    def addr_sign(self, activeId):

        params = {
            'name': '',
            'activeId': activeId,
            'address': '中国',
            'uid': '',
            'clientip': '0.0.0.0',
            'latitude': '-2',
            'longitude': '-1',
            'fid': '',
            'appType': '15',
            'ifTiJiao': '1'
        }

        try:

            res = self.session.get(
                'https://mobilelearn.chaoxing.com/pptSign/stuSignajax',
                params=params,
                timeout=20
            )

            return {
                'date': time.strftime("%m-%d %H:%M"),
                'status': res.text
            }

        except Exception:

            return {
                'date': time.strftime("%m-%d %H:%M"),
                'status': '位置签到请求异常'
            }

    # =========================================================
    # 拍照签到
    # =========================================================

    def tphoto_sign(self, activeId):

        params = {
            'name': '',
            'activeId': activeId,
            'address': '中国',
            'uid': '',
            'clientip': '0.0.0.0',
            'latitude': '-2',
            'longitude': '-1',
            'fid': '',
            'appType': '15',
            'ifTiJiao': '1',
            'objectId': '5712278eff455f9bcd76a85cd95c5de3'
        }

        try:

            res = self.session.get(
                'https://mobilelearn.chaoxing.com/pptSign/stuSignajax',
                params=params,
                timeout=20
            )

            return {
                'date': time.strftime("%m-%d %H:%M"),
                'status': res.text
            }

        except Exception:

            return {
                'date': time.strftime("%m-%d %H:%M"),
                'status': '拍照签到请求异常'
            }

    # =========================================================
    # 签到类型判断
    # =========================================================

    def sign_in(self, classid, courseid, activeid, sign_type):

        if self.check_activeid(activeid):
            return None

        if "手势" in sign_type:

            return self.hand_sign(
                classid,
                courseid,
                activeid
            )

        elif "二维码" in sign_type:

            return self.qcode_sign(activeid)

        elif "位置" in sign_type:

            return self.addr_sign(activeid)

        else:

            return self.general_sign(
                classid,
                courseid,
                activeid
            )

    # =========================================================
    # 执行全部签到
    # =========================================================

    def sign_tasks_run(self):

        tasks = []
        final_msg = []

        classid_courseId = self.get_all_classid()

        if not classid_courseId:

            print("没有获取到课程")

            return []

        # 获取所有课程签到任务
        for i in classid_courseId:

            coroutine = self.get_activeid(
                i[1],
                i[0],
                i[2]
            )

            tasks.append(coroutine)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            result = loop.run_until_complete(
                asyncio.gather(*tasks)
            )
        finally:
            loop.close()

        for d in result:

            if d is None:
                continue

            try:

                print(
                    "发现签到任务：{} / {}".format(
                        d['classname'],
                        d['sign_type']
                    )
                )

                s = self.sign_in(
                    d['classid'],
                    d['courseid'],
                    d['activeid'],
                    d['sign_type']
                )

                if not s:
                    continue

                sign_msg = {
                    'name': d['classname'],
                    'date': s['date'],
                    'status': s['status']
                }

                final_msg.append(sign_msg)

            except Exception as e:

                print(
                    "处理签到任务失败：{}".format(
                        type(e).__name__
                    )
                )

        return final_msg


# =========================================================
# Server酱
# =========================================================

def server_chan_send(msg):

    if not server_chan['status']:
        print("Server酱通知未开启")
        return

    sendkey = server_chan['key']

    if not sendkey:
        print("未配置Server酱 SendKey")
        return

    # 生成正文
    desp = ""

    for d in msg:

        desp += (
            "| **课程名** | {} |\n"
            "| :---: | :--- |\n"
            "| **签到时间** | {} |\n"
            "| **签到状态** | {} |\n\n"
        ).format(
            d['name'],
            d['date'],
            d['status']
        )

    # Server酱Turbo
    if sendkey.startswith("SCT"):

        url = "https://sctapi.ftqq.com/{}.send".format(
            sendkey
        )

    # Server酱³
    elif sendkey.startswith("sctp"):

        match = re.match(r"^sctp(\d+)t", sendkey)

        if not match:
            print("Server酱³ SendKey格式错误")
            return

        uid = match.group(1)

        url = (
            "https://{}.push.ft07.com/send/{}.send"
        ).format(uid, sendkey)

    else:

        print("无法识别Server酱 SendKey格式")
        return

    params = {
        'title': '您的学习通签到消息来啦！！',
        'desp': desp
    }

    try:

        response = requests.post(
            url,
            json=params,
            timeout=15
        )

        result = response.json()

        if result.get("code") == 0:
            print("Server酱推送成功")
        else:
            print("Server酱推送失败")

    except Exception:

        print("Server酱推送请求异常")


# =========================================================
# 主程序
# =========================================================

def local_run():

    if not os.path.exists(activeid_path):
        with open(
            activeid_path,
            'w',
            encoding='utf-8'
        ) as f:
            f.write("")

    print("====================================")
    print("学习通自动签到程序启动")
    print("====================================")

    s = AutoSign(
        user_info['username'],
        user_info['password'],
        user_info.get('schoolid')
    )

    # 如果登录过程中没有获取到Cookie，则停止
    if not s.session.cookies.get_dict():
        print("未获取到学习通Cookie")
        return "登录失败"

    print("学习通登录状态正常，开始获取课程...")

    result = s.sign_tasks_run()

    if result:

        print("发现 {} 个签到结果".format(len(result)))

        if server_chan['status']:
            server_chan_send(result)

        return result

    else:

        print("暂无签到任务")

        return "暂无签到任务"


if __name__ == '__main__':
    print(local_run())
