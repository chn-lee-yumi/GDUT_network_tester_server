"""Drcom认证计费系统接入模块，使用模拟登录。"""
import requests

USERNAME = admin
PASSWORD = "123456"
URL = "http://10.0.3.26:8080/"


def login():
    """登录drcom，返回登录成功的requests.Session"""
    login = False
    retry_times = 0
    while not login:
        s = requests.Session()
        a = s.get(URL + "login.do?P=logincor")
        # print("cookie(JSESSIONID):", a.cookies["JSESSIONID"])
        checkcode = a.text.split('name="checkcode" type="text" value="')[1][:4].strip('"').strip('"')
        # print("checkcode:", checkcode)

        s.get(URL + "login_random.do?P=execute&randomNum=0.8177881855212492")

        datas = {
            "loginFlag": 1,
            # "adminName": "",
            "usercode": USERNAME,
            # "adminRealName": "",
            "account": USERNAME,
            "password": PASSWORD,
            # "str_random": "",
            "checkcode": checkcode,
            # "Submit": ""
        }
        b = s.post(URL + "loginactioncor.do?P=into", data=datas)
        # print("login text:", b.text)
        if b.text.find("浏览器必须支持框架，才能正常显示") != -1:
            # print("[INFO] Login success!")
            login = True
        else:
            # print("[WARN] Login failed!")
            login = False

        if login:
            return s
        else:
            retry_times += 1
            if retry_times == 5:
                raise RuntimeError('Drcom登录失败')


def query_user_info(number, s):
    datas = {
        "judgeClause": " AND A.FLDUSERNAME LIKE '" + str(number) + "' ",
        "judgeClauseTotalRecords": 1,
        "includeDeleteUsers": "false",
        "page": 1,
        "start": 0,
        "limit": 50
    }
    c = s.post(URL + "user_query.do?P=queryUsers", data=datas)
    # 内部ID：c.json()['data'][0]['FLDUSERID']
    return c.json()


def get_user_id(number, s):
    c = query_user_info(number, s)
    return c['data'][0]['FLDUSERID']


def get_user_info(number, s):
    userid = get_user_id(number, s)
    c = s.get(URL + "user_register.do?P=getUserInfo&edtUserId=%d&math=0.6319344603534873" % userid)
    return c.json()


def get_vlan(number, s):
    c = get_user_info(number, s)
    data = {
        'pvlan': c['edtBindPVlan'],
        'cvlan': c['edtBindVlan']
    }
    return data


def logout(s):
    s.close()


def get_number_from_ip(ip, s):
    datas = {
        "callCount": 1,
        # "httpSessionId": "1",
        "scriptSessionId": "6A13523A9DEE29DEA74D7E73F88EDEEF",  # 可以瞎写，没用的，但是又不能缺
        "page": "/onlineuser.do",
        "c0-scriptName": "OnlineUserServiceSupport",
        "c0-methodName": "selectMain",
        "c0-id": "1",  # 可以瞎写
        "c0-e1": "string:1",
        "c0-e2": "string:100",
        "c0-e3": "string:7",
        "c0-e4": "string:" + ip,
        "c0-e5": "string:1",
        "c0-e6": "string:",
        "c0-e7": "string:",
        "c0-e8": "string:2",
        "c0-e9": "string:1",
        "c0-e10": "boolean:false",
        "c0-e11": "string:%2Fusr%2Flocal%2Ftomcat%2Fwebapps%2FDrcomManager%2Fupload%2F",
        "c0-e12": "string:1115",
        "c0-e13": "3-2-%e8%b4%a6%e5%8f%b7-0-0%2c4-1-%e7%94%a8%e6%88%b7%e5%90%8d%e7%a7%b0-0-0",  # 优化版。urldecode可知。
        # "c0-e13": "string:1-3-%E5%85%A8%E9%80%89-0-0%2C2-3-%E8%AF%A6%E7%BB%86%E8%B5%84%E6%96%99-0-0%2C3-2-%E8%B4%A6%E5%8F%B7-0-0%2C4-1-%E7%94%A8%E6%88%B7%E5%90%8D%E7%A7%B0-0-0%2C25-1-%E4%B8%8A%E7%BA%BF%E6%97%B6%E9%97%B4-0-0%2C5-1-%E5%9C%A8%E7%BA%BFIPv4-0-0%2C6-1-%E5%9C%A8%E7%BA%BFIPv6-0-0%2C7-1-MAC-0-0%2C18-0-CVLAN%20ID-0-0%2C19-0-PVLAN%20ID-0-0%2C26-1-NASID-0-0%2C20-0-NASIP-0-0%2C21-0-NASPORT-0-0%2C8-0-%E4%BD%BF%E7%94%A8%E6%97%B6%E9%95%BF%EF%BC%88%E5%88%86%E9%92%9F%EF%BC%89-0-0%2C9-0-%E4%BD%BF%E7%94%A8%E6%B5%81%E9%87%8F%EF%BC%88KB%EF%BC%89-0-0%2C10-0-%E5%9B%BD%E9%99%85%E4%B8%8A%E8%A1%8C%EF%BC%88KB%EF%BC%89-0-0%2C11-0-%E5%9B%BD%E9%99%85%E4%B8%8B%E8%A1%8C%EF%BC%88KB%EF%BC%89-0-0%2C12-0-%E5%9B%BD%E5%86%85%E4%B8%8A%E8%A1%8C%EF%BC%88KB%EF%BC%89-0-0%2C13-0-%E5%9B%BD%E5%86%85%E4%B8%8B%E8%A1%8C%EF%BC%88KB%EF%BC%89-0-0%2C14-0-%E5%85%B6%E5%AE%83%E6%B5%81%E9%87%8F%EF%BC%88KB%EF%BC%89-0-0%2C15-0-%E6%8E%A5%E5%85%A5%E8%AE%BE%E5%A4%87-0-0%2C16-2-%E7%99%BB%E5%BD%95%E7%BC%96%E5%8F%B7-0-0%2C17-0-%E5%86%85%E9%83%A8%E7%BC%96%E5%8F%B7-0-0%2C22-1-%E8%BF%90%E8%90%A5%E5%95%86%E8%B4%A6%E5%8F%B7-0-0%2C23-0-%E4%B8%BB%E6%9C%BA%E5%90%8D-0-0%2C24-0-%E7%BB%88%E7%AB%AF%E7%B1%BB%E5%9E%8B-0-0",
        "c0-param0": "Array:[reference:c0-e1,reference:c0-e2,reference:c0-e3,reference:c0-e4,reference:c0-e5,reference:c0-e6,reference:c0-e7,reference:c0-e8,reference:c0-e9,reference:c0-e10,reference:c0-e11,reference:c0-e12,reference:c0-e13]",
    }
    a = s.post(URL + "dwr/plainjs/OnlineUserServiceSupport.selectMain.dwr", data=datas)  # 7522423961701274914.xml
    # print(a.text)
    filename = a.text[a.text.find("s1=") + 4:a.text.find("\";")]
    # print(filename)
    b = s.get(URL + "upload/" + filename)
    user_info = b.text.split("]]></cell><cell><![CDATA[")
    # print(user_info[2],user_info[3])
    # datas = {
    #     "path": "/usr/local/tomcat/webapps/DrcomManager/upload/" + filename
    # }
    # s.post(URL + "onlineuser.do?P=delFile&t=0.21321742553037448", data=datas)
    return {'username': user_info[3], 'number': user_info[2]}


if __name__ == '__main__':
    session = login()
    # print(get_vlan("3118000001", session))
    print(get_number_from_ip("10.22.52.133", session))
