'''
任务：通过对登陆页面进行抓包，然后分析请求，得出需要提交的数据和得到的方法后进行自动模拟登陆
实现思路：
1.通过本地时间戳和进行base64加密的用户名等构成一个GET请求URL，来获取服务器传来的登陆参数
2.获得服务器参数后再通过对用户名和密码的加密来构成整个表单，然后提交到表单的地址
3.然后得到一个通行证，获取通信证的URL，对这个URL进行访问
4.URL的响应内容会返回五个URL，然后对这五个URL进行访问
5.其中一个URL的响应会有用户id，提取id
6.通过用户id构成一个home页面的请求地址进行请求，通过响应结果即可判断出是否已经登录成功
PS：其实得到用户id后就表示已经登录成功了
'''
import base64 as bs             # 用于用户名的加密
import requests                 # 用于发起请求
import time                     # 用于设置请求参数
import urllib3                  # 用于去除https请求时的警告信息，强迫症
import json                     # 用于通过json字符转成字典形式，主要使用loads方法
import random                   # 用于设置参数请求
import rsa                      # 用于密码的加密
from binascii import b2a_hex    # 用于简化加密后的密码进行传输
import re                       # 用于匹配字符串
urllib3.disable_warnings()      # 去除警告信息


# 创建类，通过输入用户名和密码，实现模拟登陆新浪微博，登陆后自动登录到我的首页页面
class SinaLogin(object):
    # 设置头信息
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36',
        'Referer': 'https://weibo.com/'
    }

    # 创建会话并设置头信息，保存提取参数URL和提交参数URL
    def __init__(self, user, password):
        self.user = user
        self.password = password
        self.sess = requests.Session()
        self.sess.headers.update(self.headers)
        self.url_param = 'https://login.sina.com.cn/sso/prelogin.php'
        self.url_post = 'https://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.19)'

    # 对传入16进制的pubkey和e进行RSA加密，返回加密后的密码
    def encrypt_password(self, n, e, servertime, nonce):
        n = int(n, 16)
        e = int(e, 16)
        pub_key = rsa.PublicKey(n, e)
        enc_password = rsa.encrypt((str(servertime) + '\t' + nonce + '\n' + self.password).encode(), pub_key)
        # [me.servertime, me.nonce].join("\t") + "\n" + b)
        return b2a_hex(enc_password).decode()

    # 对用户名进行加密，返回加密后的密码
    def encrypt_user(self):
        enc_user = bs.b64encode(self.user.encode())
        return enc_user.decode()

    # 通过传入提取参数的url来获取表单需要的参数
    def get_param(self, url, su):
        param = {
            'entry': 'weibo',
            'callback': 'sinaSSOController.preloginCallBack',
            'su': su,
            'rsakt': 'mod',
            'checkpin': '1',
            'client': 'ssologin.js(v1.4.19)',
            '_': int(time.time()*1000)
        }
        response = self.sess.get(url=url, params=param, verify=False)
        # 对返回的状态码进行分析，如果成功则返回具体json数据，不成功则返回None
        if response.status_code == 200:
            # 提取数据，因为返回的数据不是正常的json格式，无法通过respone.json获取，只能自己提取并返回json数据
            res_json = response.content.decode().split('(')[1].split(')')[0]
            res_json = json.loads(res_json)
            return res_json
        else:
            print('无法获取表单参数，将无法进行登录操作')

    # 提交表单，返回响应页面，否则返回None
    def post_data(self):
        enc_user = self.encrypt_user()
        param_json = self.get_param(self.url_param, enc_user)
        # 对获取表单参数断言，如果没有获取成功则无法向下执行提交表单
        assert param_json
        print('获取表单参数成功！')
        enc_password = self.encrypt_password(param_json['pubkey'], '10001', param_json['servertime'], param_json['nonce'])
        data = {
            'encoding': 'UTF-8',
            'entry': 'weibo',
            'from': '',
            'gateway': '1',
            'nonce': param_json['nonce'],
            'pagerefer': '',
            'prelt': random.choice(range(99, 999)),     # 这个参数通过看源码，其实是两行代码执行的时间差再减去一个数得到的
            'pwencode': 'rsa2',                         # 这个数是服务器传来的或者为0都可以，而且该参数不影响登陆。
            'qrcode_flag': 'false',
            'returntype': 'META',
            'rsakv': param_json['rsakv'],
            'savestate': '7',
            'servertime': param_json['servertime'],
            'service': 'miniblog',
            'sp': enc_password,
            'sr': '1920*1080',
            'su': enc_user,
            'url': 'https://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack',
            'useticket': '1',
            'vsnf': '1',
        }
        response = self.sess.post(url=self.url_post, data=data, verify=False)
        if response.status_code == 200:
            return response
        else:
            print('上传表单失败！')

    # 实现登录操作
    def login(self):
        # 提交表单，在该函数内已经有获取表单操作了
        response = self.post_data()
        # 提交成功则继续执行，否则打断
        assert response.status_code == 200
        print('获取通行证成功！')
        # 表达提交成功后，获取通行证响应页面的URL并进行请求
        url_pass = re.findall('location.replace\("(.*)"\)', response.content.decode('GBK'))[0]
        res = self.sess.get(url_pass, verify=False)

        # 获得通行证中的URL响应数据后，提取其中的五个URL，然后分别按顺序进行请求操作
        url_list = re.findall('setCrossDomainUrlList\((.*)\);', res.content.decode('GBK'))[0]

        url_1 = re.findall("replace\('(.*)'\)", res.content.decode('GBK'))[0]
        url_list = json.loads(url_list)['arrURL']
        res_list = []
        for i in url_list:
            res_list.append(self.sess.get(i, verify=False))
        self.sess.get(url_1, verify=False)

        # 上面的五个请求中，其中有一个响应页面中含有用户的id，进行id提取
        user_id = re.findall('"uniqueid":"(.*?)",', res_list[0].content.decode())[0]

        # 将提取到的id拼接URL，然后请求用户的home页面，通过对页面中的标题来判断是否成功登陆了
        r = self.sess.get('https://weibo.com/u/' + user_id + '/home', verify=False)
        title = re.findall('<title>(.*)</title>', r.text)[0]
        if title == '我的首页 微博-随时随地发现新鲜事':
            print('登录成功！')
            print('页面标题为：', title)


if __name__ == '__main__':
    # 创建登陆类，并进行登陆
    log = SinaLogin('13025668791', 'qq13653041784')
    log.login()
