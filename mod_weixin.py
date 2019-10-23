# encoding: utf-8
import json
import time
import requests

corpid = "wx01jk34htas36"
corpsecret = ['', '', '', 'gayhubsdf-e3g2-214328yr9hiojfSfoPDo']

'''
该模块用于发送微信推送
用法：token=refreshtoken()
返回字符串access_token。
用法：sendweixinmsg(msg, agentid)
msg为推送内容
agentid为应用id
无返回值，结果会输出到屏幕。
TODO：处理网络异常。
'''

token = [''] * len(corpsecret)


def get_token(agentid):
    try:
        a = requests.get(
            "https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=" + corpid + "&corpsecret=" + corpsecret[
                agentid]).text
        a = json.loads(a)
        return a['access_token']
    except:
        print("[Error] Get Weixin token error!")
        return 0


def send_msg(msg, agentid=3):  # agentid: 3=Netter监控
    global token
    datas = {
        "touser": "@all",
        "msgtype": "text",
        "agentid": str(agentid),
        "text": {
            "content": msg
        }
    }
    try:
        a = requests.post("https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=" + token[agentid],
                          data=json.dumps(datas))
        b = json.loads(a.text)  # 检查是否发送成功
        if b['errcode'] != 0:  # 可能是token过期，重新获取token
            refresh_token()
            requests.post("https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=" + token[agentid],
                          data=json.dumps(datas))
    except:
        print("[Error] Send Weixin message error!")
        return


def refresh_token():
    # 注：这里需要根据需要定制，我使用了编号为3的应用（查看看微信企业号后台，根据需要自行设置）
    token[3] = get_token(3)


if __name__ == '__main__':
    refresh_token()
    send_msg("测试", 3)
