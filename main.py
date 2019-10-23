from datetime import timedelta
from flask import Flask, request
import json
import time
import logging
import mod_weixin as Weixin

time.sleep(10)  # 等待其它服务启动

app = Flask(__name__)
app.send_file_max_age_default = timedelta(seconds=30)

logging.basicConfig(level=logging.WARNING, filename='/home/netter/netter.log', filemode='a',
                    format='%(levelname)s: %(message)s')

server_datas = {
    '内网': {
        'IP': '10.0.4.6',
        '1min': [0, 0],  # 平均延迟（ms），丢包率（%）
        '5min': [0, 0],
        '15min': [0, 0]
    },
    '移动': {
        'IP': '183.236.19.129',
        '1min': [0, 0],
        '5min': [0, 0],
        '15min': [0, 0]
    },
    '联通': {
        'IP': '211.97.3.131',
        '1min': [0, 0],
        '5min': [0, 0],
        '15min': [0, 0]
    },
    #'电信': {
    #    'IP': '121.8.203.145',
    #    '1min': [0, 0],
    #    '5min': [0, 0],
    #    '15min': [0, 0]
    #},
    '教育网': {
        'IP': '210.38.1.49',
        '1min': [0, 0],
        '5min': [0, 0],
        '15min': [0, 0]
    }
}

client_upload_time = {}
data_update_time = 0

high_drop_timestamp = 0  # 高丢包率限制：开始统计客户端数目的时间（2分钟内达到3个ip则解除限制）
high_drop_enable = False  # 高丢包率限制是否解除 True=解除限制 高丢包率限制解除5分钟后且所有丢包率小于50%时重新加上限制
high_drop_ip = set()  # 高丢包率的ip

high_delay_timestamp = 0
high_delay_enable = False  # 高延迟限制是否解除 True=解除限制 高延迟限制解除5分钟后且所有延迟小于7时重新加上限制
high_delay_ip = set()

wg = "wangguan_key"  # 网管客户端特征key的名字。如果客户端提交上来的数据带有这个key，会被特殊对待。为了防止恶意构造数据攻击，当校园网实际出问题时需要多个普通客户端才能进行判断，而收到网管客户端的数据则可以直接判断。


@app.route("/")
def index():
    try:
        client_ip = request.headers['X-Forwarded-For'].split(',')[0]
    except:
        client_ip = request.remote_addr
    logging.warning("/ %s" % client_ip)
    return app.send_static_file("index.html")


@app.route("/FAQ")
def faq():
    try:
        client_ip = request.headers['X-Forwarded-For'].split(',')[0]
    except:
        client_ip = request.remote_addr
    logging.warning("/FAQ %s" % client_ip)
    return app.send_static_file("FAQ.html")


@app.route("/api/get_servers")
def api_get_servers():
    try:
        client_ip = request.headers['X-Forwarded-For'].split(',')[0]
    except:
        client_ip = request.remote_addr
    logging.warning("/api/get_servers %s" % client_ip)
    data = {}
    for name in server_datas:
        data[name] = server_datas[name]['IP']
    data["本地"] = client_ip
    return json.dumps(data)


@app.route("/api/upload_result", methods=['POST'])
def api_upload_result():
    global high_drop_ip, high_drop_timestamp, high_drop_enable, high_delay_ip, high_delay_timestamp, high_delay_enable, data_update_time, session, ip_userinfo, client_upload_time
    """客户端提交一个json，格式：
    {'内网':[1,0],'电信':[2.5,1]}  # 延迟，丢包率
    """
    try:
        client_ip = request.headers['X-Forwarded-For'].split(',')[0]
    except:
        client_ip = request.remote_addr
    logging.warning("/api/upload_result %s %s" % (client_ip, request.get_data(as_text=True)))
    try:
        data = json.loads(request.get_data(as_text=True))
        real_time = time.time()
        upload_time = data["time"] / 1e9
        # 检查是否过量上传
        if client_ip in client_upload_time:
            if upload_time < client_upload_time[client_ip] + 55:  # 上传时间间隔小于55s的不接受，怀疑恶意攻击
                logging.warning("上传间隔异常： %s %d %d" % (client_ip, upload_time, client_upload_time[client_ip]))
                userinfo = get_userinfo(client_ip)
                Weixin.send_msg("[疑似攻击] 上传间隔异常 %.1f秒 %s %s %s %s" % (upload_time - client_upload_time[
                    client_ip], client_ip, userinfo['number'], userinfo['username'], request.get_data(as_text=True)))
                return ''
        # 更新上传时间
        client_upload_time[client_ip] = real_time
        # 检查时间戳
        time_delta = real_time - data_update_time
        if time_delta < 0:  # 早于更新时间的不接受
            return ''
        if not (upload_time + 63 > time.time() > upload_time - 60):  # 时间偏差太大的不接受
            logging.warning("时间偏差过大： %s %d %d" % (client_ip, time.time(), upload_time))
            return ''
        # 检查TTL-IP恶意构造攻击
        ttl = data["TTL"]
        if ttl == 255 and client_ip[:5] != "10.30":
            userinfo = get_userinfo(client_ip)
            Weixin.send_msg("[疑似攻击] TTL与IP不对应 %d %s %s %s %s" % (
                ttl, client_ip, userinfo['number'], userinfo['username'], request.get_data(as_text=True)))
            return ''
        # 检查TTL
        if ttl != 255:  # TTL仅接受255
            logging.warning("TTL异常： %s" % client_ip)
            return ''
        # 检查IP，10.30为学生宿舍的IP（主要是防止教师公寓的IP，出口策略不同）
        if client_ip[:5] != "10.30":
            logging.warning("IP异常： %s" % client_ip)
            return ''
        # 检查本地延迟
        if data["本地"][0] >= 1 or data["本地"][1] > 0:  # 本地延迟/丢包过大，怀疑使用Wi-Fi/垃圾路由器，不接受
            logging.warning("本地延迟/丢包过大： %s %.3f %.1f%%" % (client_ip, data["本地"][0], data["本地"][1]))
            return ''
        # 遍历和更新数据
        for k, v in data.items():
            if k in server_datas:

                # 检查丢包率
                if not high_drop_enable and v[1] > 70:  # 丢包率大于70，触发高丢包率限制检测
                    logging.warning("丢包率过大： %s %.1f%%" % (client_ip, v[1]))
                    if wg in data:  # 如果是网管客户端，直接解除限制，否则需要两分钟三个客户端
                        high_drop_enable = True
                        high_drop_timestamp = real_time
                    else:
                        userinfo = get_userinfo(client_ip)
                        Weixin.send_msg("[疑似攻击] 丢包率过大 %.1f%% %s %s %s" % (
                            v[1], userinfo['number'], userinfo['username'], request.get_data(as_text=True)))
                        if high_drop_timestamp + 120 > real_time:  # 还在2分钟时限内
                            high_drop_ip.add(high_drop_ip)
                        else:
                            high_drop_timestamp = real_time  # 重新计时
                            high_drop_ip = {high_drop_ip}
                        # 判断ip数量是否可以触发
                        if len(high_drop_ip) >= 3:
                            high_drop_enable = True
                        else:
                            continue

                # 检查延迟
                if not high_delay_enable and v[0] > 8:  # 延迟大于8
                    logging.warning("延迟过大： %s %.1f%%" % (client_ip, v[1]))
                    if wg in data:  # 如果是网管客户端，直接解除限制，否则需要两分钟三个客户端
                        high_delay_enable = True
                        high_delay_timestamp = real_time
                    else:
                        userinfo = get_userinfo(client_ip)
                        Weixin.send_msg("[疑似攻击] 延迟过大 %.1f%% %s %s %s" % (
                            v[0], userinfo['number'], userinfo['username'], request.get_data(as_text=True)))
                        if high_delay_timestamp + 120 > real_time:  # 还在2分钟时限内
                            high_delay_ip.add(high_delay_ip)
                        else:
                            high_delay_timestamp = real_time  # 重新计时
                            high_delay_ip = {high_delay_ip}
                        # 判断ip数量是否可以触发
                        if len(high_delay_ip) >= 3:
                            high_delay_enable = True
                        else:
                            continue

                # 更新数据
                if time_delta >= 15 * 60:
                    server_datas[k]['15min'] = v
                if time_delta >= 5 * 60:
                    server_datas[k]['5min'] = v
                if time_delta >= 60:
                    server_datas[k]['1min'] = v

                if time_delta < 15 * 60:
                    server_datas[k]['15min'][0] = v[0] * time_delta / (15 * 60) + server_datas[k]['15min'][0] * (
                            15 * 60 - time_delta) / (15 * 60)
                    server_datas[k]['15min'][1] = v[1] * time_delta / (15 * 60) + server_datas[k]['15min'][1] * (
                            15 * 60 - time_delta) / (15 * 60)
                if time_delta < 5 * 60:
                    server_datas[k]['5min'][0] = v[0] * time_delta / (5 * 60) + server_datas[k]['5min'][0] * (
                            5 * 60 - time_delta) / (5 * 60)
                    server_datas[k]['5min'][1] = v[1] * time_delta / (5 * 60) + server_datas[k]['5min'][1] * (
                            5 * 60 - time_delta) / (5 * 60)
                if time_delta < 60:
                    server_datas[k]['1min'][0] = v[0] * time_delta / 60 + server_datas[k]['1min'][0] * (
                            60 - time_delta) / 60
                    server_datas[k]['1min'][1] = v[1] * time_delta / 60 + server_datas[k]['1min'][1] * (
                            60 - time_delta) / 60

                for t in ['1min', '5min', '15min']:
                    server_datas[k][t][0] = round(server_datas[k][t][0], 5)
                    server_datas[k][t][1] = round(server_datas[k][t][1], 3)
                    if server_datas[k][t][1] < 0.01:
                        server_datas[k][t][1] = 0

        # 查看是否满足加上高丢包率限制的条件
        if high_drop_enable and high_drop_timestamp + 300 + 120 < real_time:  # 高丢包率限制解除持续5分钟
            all_less_than_50 = True
            for k in server_datas:
                for t in ['1min', '5min', '15min']:
                    if server_datas[k][t][1] >= 50:
                        all_less_than_50 = False
            if all_less_than_50:  # 所有丢包率小于50%则加上限制
                high_drop_enable = False

        data_update_time = real_time  # 上传不代表数据会更新，更新成功后刷新这个时间

    except:
        pass

    return ''


@app.route("/api/status")
def api_status():
    datas = dict()
    datas['time'] = data_update_time
    datas['client'] = count_clients()
    datas['data'] = server_datas
    return json.dumps(datas)


@app.route("/api/version")
def api_version():
    return '1.0'


def count_clients():
    count_time = time.time()
    clients_num = 0
    for k, v in client_upload_time.items():
        if v > count_time - 60:
            clients_num += 1
    return clients_num


################

import mod_drcom_manager as Drcom

session = Drcom.login()  # drcom, for eggs_admin
ip_userinfo = dict()


@app.route("/admin/")
def eggs_admin():
    try:
        client_ip = request.headers['X-Forwarded-For'].split(',')[0]
    except:
        client_ip = request.remote_addr
    logging.warning("/admin/ %s" % client_ip)
    userinfo = get_userinfo(client_ip)
    Weixin.send_msg("[扫后台警告] %s %s %s" % (client_ip, userinfo['number'], userinfo['username']))
    with open("/home/netter/netter_eggs.log", "a") as f:
        f.write("%s %s\n" % (userinfo['number'], userinfo['username']))
    return "扫什么后台漏洞，再扫就查你水表！%s %s" % (userinfo['number'], userinfo['username'])


@app.route("/api/debug/1")
def debug1():
    global ip_userinfo
    return json.dumps(ip_userinfo)


@app.route("/api/debug/2")
def debug2():
    global client_upload_time
    return json.dumps(client_upload_time)


def get_userinfo(client_ip):
    global session, ip_userinfo
    if client_ip in ip_userinfo and time.time() - ip_userinfo[client_ip]["time"] <= 60:  # 先检查缓存，缓存60s
        userinfo = ip_userinfo[client_ip]
    else:
        try:
            userinfo = Drcom.get_number_from_ip(client_ip, session)
            ip_userinfo[client_ip] = userinfo
            ip_userinfo[client_ip]["time"] = time.time()
        except:
            try:
                session = Drcom.login()
                userinfo = Drcom.get_number_from_ip(client_ip, session)
                ip_userinfo[client_ip] = userinfo
                ip_userinfo[client_ip]["time"] = time.time()
            except:
                userinfo = {
                    'number': '',
                    'username': ''
                }
                ip_userinfo[client_ip] = {
                    'number': '',
                    'username': '',
                    'time': time.time()
                }
    return userinfo


################

if __name__ == '__main__':
    app.run('0.0.0.0', port=8084)
