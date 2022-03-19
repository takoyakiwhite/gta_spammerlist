import flask,time,random,os,datetime
from flask import redirect, request,abort
import logging
from ratelimit import limits
log = logging.getLogger('werkzeug')

app=flask.Flask(__name__)
app.debug=True

allows=['Universe.exe']
#获取ip
def get_banned():
    with open('banned_ips.txt','r',encoding='utf-8') as f:
        x=f.read()
        if x!='':
            banned_ips=x.replace('[','').replace(']','').replace("'",'').replace('"','').replace(' ','').split(',')
        else:
            banned_ips=[]
        f.close()
        return banned_ips
limits_ip={}    
ip_times={}
banned_ips=get_banned()



def get_client_ip():
    try:
        real_ip = request.META['HTTP_X_FORWARDED_FOR']
        client_ip = real_ip.split(",")[0]
    except:
        try:
            client_ip = request.META['REMOTE_ADDR']
        except:
            client_ip = request.remote_addr
    return client_ip
#限制ip 阻止cc攻击
def ip_limits(ip):
    if ip in limits_ip:
        if time.time()-limits_ip[ip]>=60:
            limits_ip[ip]=time.time()
            ip_times[ip]=0
        if time.time() -limits_ip[ip]<=5:
            if ip_times[ip]>=5:
                banned_ips.append(ip)
                with open('banned_ips.txt','w',encoding='utf-8') as f:
                    f.write(str(banned_ips))
                    f.close()
                    print(f'[{str(datetime.datetime.now())[:-7]}] 已加黑 {ip}')
            else:
                ip_times[ip]+=1
        else:
            limits_ip[ip]=time.time()
    else:
        limits_ip[ip]=time.time()
        ip_times[ip]=1 



@app.before_request
@limits(calls=100,period=10)
def before_r():
    log.setLevel(logging.DEBUG)
    ip=get_client_ip()
    if ip in banned_ips:
        return abort(403)
    if request.path.find('.ico')==-1 and not 'https://' in request.url and request.headers.get('User-Agent')=="python-requests/2.27.1":
        #print(f"[{str(datetime.datetime.now())[:-7]}] {ip}\n{request.headers.get('User-Agent')}\n")
        ip_limits(ip)
    else:
        #print(f"[{str(datetime.datetime.now())[:-7]}] {ip}\n{request.headers.get('User-Agent')}\n")
        ip_limits(ip)
        return abort(400)





@app.route('/getADBotScid',methods=['GET'])
def gets():
    with open('scid.cfg','r',encoding='utf-8') as f:
        scids=f.read()
        f.close()
        return scids
#客户端检测存在差异与否
@app.route('/getFile/<file>')
def get_file(file):
    if file in allows:
        if os.path.exists(file):
            with open(file,'rb')as f:
                return f.read()
        else:
            return abort(404)
    else:
        return abort(405)



@app.route('/sentScids',methods=['POST'])
def posts():
    sc=fl=all=0
    ids=request.data.decode('utf-8').split('\n')
    try:
        ids.remove('')
    except:
        pass
    for id in ids:
        if len(id)>=5:
            with open('scid.cfg','r',encoding='utf-8') as f:
                x=f.read()
                f.close()
            if '\n'+id+'\n' in x or id+'\n' == x :
                fl+=1
            else:
                with open('scid.cfg','a',encoding='utf-8') as f:
                    f.write(id+'\n')
                    f.close()
                    sc+=1
        all+=1
    return f'上传{sc}个新广告机 重复广告机{fl}个 共计上传{all}个广告机\n'



@app.route('/')
def fucku():
    return abort(408)


@app.route('/<any>')
def fucku2(any):
    return abort(408)


@app.errorhandler(Exception)
def anti_dos(e):
    log.setLevel(logging.NOTSET)
    ip=get_client_ip()
    # fake_url=['http://www.baidu.com/','https://baike.baidu.com/','http://www.sogou.com/','https://www.google.com/','https://www.youtube.com/','https://www.dnddos.com/','https://play.google.com/store/apps','https://chrome.google.com/']
    # cc=fake_url[random.randint(0,len(fake_url)-1)]
    # print(f'[{str(datetime.datetime.now())[:-7]}] 臭狗IP{ip}')
    if not ip in banned_ips:
        banned_ips.append(ip)
        with open('banned_ips.txt','w',encoding='utf-8') as f:
            f.write(str(banned_ips))
            f.close()
            print(f'[{str(datetime.datetime.now())[:-7]}] 已加黑 {ip}')
    return str(e)

app.run('0.0.0.0',port=5000)