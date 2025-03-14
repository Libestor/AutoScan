# 自动黑盒扫描器
## 项目介绍
本项目是一个自动黑盒扫描器，用于自动化测试。
## 项目结构
1. 爬虫
2. 通用漏洞扫描
3. POC扫描功能
## 项目运行
### 编译
```bash
go build cmd/main.go 
```
项目需要配置**chroeme浏览器**，需要安装**chromedriver**，并且需要配置chromedriver的路径
之后在config.yml总配置即可，默认使用config.yml配置
```bash
AutoScan有四种扫描模式
全量扫描模式：
                 AutoScan -u http://127.0.0.1 -f ./pocDir [-out-json ./result.json]
poc扫描模式：
                 AutoScan -u http://127.0.0.1 -poc -f ./pocDir [-out-json ./result.json]
爬虫扫描模式：
                 AutoScan -u http://127.0.0.1 -spider [-out-json ./spider.json]
通用漏洞扫描模式：
                 AutoScan -u http://127.0.0.1 -vul sql -p username [-out-json ./spider.json]
spider的扫描结果可以直接导入到vul扫描中：
                 AutoScan  -vul sql -f ./spider.json -vul xss,sql [-out-json ./spider.json]
参数说明：
  -b value
        post请求的body参数，使用','分割，或者多次使用-b传入
  -c string
        配置文件的路径
  -f string
        指定文件或者目录
  -j value
        post请求的json参数，使用','分割，或者多次使用-j传入
  -out-json string
        输出为json文件
  -p value
        get请求的param参数，使用','分割，或者多次使用-p传入
  -poc
        使用poc进行扫描
  -spider
        使用爬虫进行扫描
  -u string
        目标URL
  -vul value
        使用vul选择需要扫描的类型，如sql,xss
```
## 架构介绍
后续更新。。。
## 免责声明
请勿利用项目内的相关技术从事非法测试，由于使用本工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具仅用于安全性自测，和授权的扫描。