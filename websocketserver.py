import socket # 导入 socket，侦听端口、接收数据、发送数据等
import threading # 导入 threading
import hashlib, base64 #通过接收浏览器的key生成websocket会话所需要的token
import struct # 对发送和接收的数据包进行解包、打包等
import time # 对时间的处理

connectList = {} # 连接客户fd，元组
gCodeLength = 0 # 实际载荷长度
gHeaderLength = 0 # websocket 数据头部长度
PRINT_FLAG = True # 是否开启打印

# 调用 socket 的 send 方法发送 msg 信息给 web 端
"""
在建立websocket会话后，服务端通过socket通道发送数据到浏览器端时调用此函数，
主要作用是在实际数据包头部增加websocket数据特有的帧。
"""
def sendMessage(msg):
  global connectList
  # 使用 bytes 格式，避免后面拼接的时候出现异常, u/U - unicode字符串，r/R:非转义的原始字符串 
  sendMsg = b""
  sendMsg += b"\x81"
  backStr = []
  backStr.append("\x81")
  dataLength = len(msg.encode())
  if PRINT_FLAG:
    print("Info: send message is %s and len is %d" % (msg, len(msg.encode("utf-8"))))
  # 数据长度的三种情况
  if dataLength <= 125:
    sendMsg += str.encode(chr(dataLength))
  elif dataLength <= 65535:
    sendMsg += struct.pack('b', 126)
    sendMsg += struct.pack('>h', dataLength)
  elif dataLength <= (2^64-1):
    sendMsg += struct.pack('b', 127)
    sendMsg += struct.pack('>q', dataLength)
  else:
    print(u"消息太长了")
  sendMsg += msg.encode("utf-8")

  for connect in connectList.values():
    if sendMsg != None and len(sendMsg) > 0:
      connect.send(sendMsg)

# 计算web端提交的数据长度并返回
"""
WebSocket 传输内容支持文本或二进制数据，这些数据的边界靠帧（frame）来维护，
其中帧的第二个字节低7位用来表示信息内容的长度（payload len）。
数据长度一共有三种情况，全都由低7位的值认定，
如果取值在126以内，不包括126，则数据真实长度就是低7位的值。
如果取值为126，则需要额外的两个字节来表示数据的真实长度，16位的无符号整数。
如果取值127，那么需要额外的8个字节表示数据的真实长度，64位的无符号整数。
--------------------------------------------------------------------
此函数在建立websocket会话，接受用户发送的数据后调用，
通过解包接收到的bytes信息计算出用户发送过来的数据总长度及数据帧头部的大小。
websocket帧在封装不同长度的内容时头部大小是不一样的，
需要此函数处理后计算出所有数据是否接收完毕。
"""
def getDataLength(msg):
    global gCodeLength
    global gHeaderLength
    gCodeLength = msg[1] & 127
    if gCodeLength == 126:
        gCodeLength = struct.unpack('>H', msg[2:4])[0]
        gHeaderLength = 8
    elif gCodeLength == 127:
        gCodeLength = struct.unpack('>Q', msg[2:10])[0]
        gHeaderLength = 14
    else:  
        gHeaderLength = 6  
    gCodeLength = int(gCodeLength)
    return gCodeLength  


# 解析web端提交的bytes信息，返回str信息（可以解析中文信息）
'''
浏览器在建立websocket会话后发送过来的bytes数据是有掩码加密的，
此函数在建立websocket会话接受完用户发送的所有数据后调用，
提取出用户发送过来的实际内容。
'''
def parseData(msg):
  global gCodeLength
  gCodeLength = msg[1] & 127
  if gCodeLength == 126:
    gCodeLength = struct.unpack(">H", msg[2:4])[0]
    masks = msg[4:8]
    data = msg[8:]
  elif gCodeLength == 127:
    gCodeLength = struct.unpack(">Q", msg[2:10])[0]
    masks = msg[10:14]
    data = msg[14:]
  else:
    masks = msg[2:6]
    data = msg[6:]
  enBytes = b""
  cnBytes = []
  for i, d in enumerate(data):
    nv = chr(d ^ masks[i%4])
    nvBytes = nv.encode()
    nvLen = len(nvBytes)
    if nvLen == 1:
      enBytes += nvBytes
    else:
      enBytes += b"%s"
      cnBytes.append(ord(nvBytes.decode()))
  if len(cnBytes) > 2:
    cnStr = ""
    cLen = len(cnBytes)
    count = int(cLen/3)
    for x in range(count):
      i = x * 3
      b = bytes([cnBytes[i], cnBytes[i+1], cnBytes[i+2]])
      cnStr += b.decode()
    new = enBytes.replace(b"%s%s%s", b"%s")
    new = new.decode()
    res = (new % tuple(list(cnStr)))
  else:
    res = enBytes.decode()
  return res

# 删除连接，从集合中删除连接对象 item
def deleteConnect(item):
  global connectList
  del connectList['connect'+item]

# 定义 WebSocket 类（基于线程对象）
class WebSocket(threading.Thread):
  def __init__(self, conn, index, name, remote, path = ''):
    # 初始化线程
    threading.Thread.__init__(self)
    # 初始化数据，全部存储在自己的数据结构中 self
    self.conn = conn
    self.index = index
    self.name = name
    self.remote = remote
    self.path = path
    # WebSocket 握手加密密钥 RFC6455
    self.GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    self.buffer = ""
    self.bufferUtf8 = b""
    self.lengthBuffer = 0

  def generateToken(self, WebSocketKey):
    WebSocketKey = WebSocketKey + self.GUID
    SerWebSocketKey = hashlib.sha1(WebSocketKey.encode(encoding='utf-8')).digest()
    WebSocketToken = base64.b64encode(SerWebSocketKey) # 返回的是一个 bytes 对象
    return WebSocketToken.decode('utf-8')
  # 运行线程 - 重写 thread 的 run 方法，当实例的 start 被调用时，此方法会被执行
  '''
  1. 当没有建立socket会话时，服务端接受数据进行验证和匹配，并发送欢迎信息，此处需要考虑接受到的数据不符合要求时的动作。
  2. 当建立socket会话后，服务端接受数据并进行广播，此处需要考虑用户提交的数据是否接受完毕的问题。
  '''
  def run(self):
    if PRINT_FLAG:
      print('Socket %s start.' % self.index)
    global gCodeLength
    global gHeaderLength
    self.handshaken = False
    while True:
      if self.handshaken == False:
        if PRINT_FLAG:
          print('Info: Socket %s start handshaken with %s.' % (self.index, self.remote))
        #socket会话收到的只能是utf-8编码的信息，将接收到的bytes数据，通过utf-8编码方式解码为unicode编码进行处理
        self.buffer = self.conn.recv(1024).decode('utf-8')
        if PRINT_FLAG:
          print("Info: Socket %s self.buffer is {%s}" % (self.index, self.buffer))
        if self.buffer.find("\r\n\r\n") != -1:
          headers = {}
          #按照这种标志分割一次,结果为：header data
          header, data = self.buffer.split("\r\n\r\n", 1)
          # 对 header 进行分割后，取出后面的 n-1 个部分
          for line in header.split("\r\n")[1:]:
            key, value = line.split(": ", 1)
            headers[key] = value
          try:
            WebSocketKey = headers["Sec-WebSocket-Key"]
          except KeyError:
            print("Socket %s handshaken failed!" % (self.index))
            deleteConnect(str(self.index))
            self.conn.close()
            break
          WebSocketToken = self.generateToken(WebSocketKey)
          headers["Location"] = ("ws://%s%s" % (headers["Host"], self.path))
          #握手过程，服务器构建握手的信息，进行验证和匹配
          #Upgrade: WebSocket 表示为一个特殊的 http 请求，请求的目的为从 http 协议升级到 websocket 协议
          handshake = "HTTP/1.1 101 Switching Protocols\r\n"\
                      "Connection: Upgrade\r\n"\
                      "Sec-WebSocket-Accept: " + WebSocketToken + "\r\n"\
                      "Upgrade: websocket\r\n\r\n"
          # 前方以 bytes 类型接收，此处以 bytes 类型进行发送
          self.conn.send(handshake.encode(encoding="utf-8"))
          self.handshaken = True
          sendMessage("Welcome " + self.name + " !")
          gCodeLength = 0
        else:
          print("Socket %s Error2!" % (self.index))
          deleteConnect(str(self.index))
          self.conn.close()
          break
      else:
        # 每次接收 128 字节数据，需要判断是否接收完毕所有数据，如没有接收完，需要循环接收处理
        mm = self.conn.recv(128)
        # 计算接收的长度，判断是否接收完，如未接收完需要继续接收
        if gCodeLength == 0:
          # 调用些函数可以计算并修改全局变量 gCodeLength 和 gHeaderLength 的值
          getDataLength(mm)
        self.lengthBuffer += len(mm)
        self.bufferUtf8 += mm
        if self.lengthBuffer - gHeaderLength < gCodeLength:
          if PRINT_FLAG:
            print("Info: 数据未接收完毕，继续接收")
          continue
        else:
          if PRINT_FLAG:
            print("gCodeLength:", gCodeLength)
            print("Info line 204: Recv信息 %s，长度为 %d:" % (self.bufferUtf8, len(self.bufferUtf8)))
          if not self.bufferUtf8:
            continue
          recvMsg = parseData(self.bufferUtf8)
          if recvMsg == "quit":
            print("Socket %s Logout!" % (self.index))
            nowTime = time.strftime("%H:%M:%S", time.localtime(time.time()))
            sendMessage("%s %s say: %s" % (nowTime, self.remote, self.name+" Logout"))
            deleteConnect(str(self.index))
            self.conn.close()
            break
          else:
            nowTime = time.strftime("%H:%M:%S", time.localtime(time.time()))
            sendMessage("%s %s say: %s" % (nowTime, self.remote, recvMsg))
          gCodeLength = 0
          self.lengthBuffer = 0
          self.bufferUtf8 = b""

        print("Info: mm %s" % (mm))

# WebSocketServer
class WebSocketServer(object):
  # 构造函数
  def __init__(self):
    self.socket = None
    self.i = 0

  # 开启操作
  def run(self):
    if PRINT_FLAG:
      print('WebSocketServer Start.')
    self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ip = '127.0.0.1'
    port = 8080
    if PRINT_FLAG:
      print("WebSocketServer is listening %s:%d"%(ip, port))
    # 将IP和端口绑定在服务器上
    self.socket.bind((ip, port))
    # listen函数使用主动连接套接口变为被连接套接口，使得一个进程可以接受其它进程的请求，从而成为一个服务器进程。
    # 在TCP服务器编程中listen函数把进程变为一个服务器，并指定相应的套接字变为被动连接,其中的能存储的请求不明的socket数目。
    self.socket.listen(50)

    while True:
      # 服务器响应请求，返回连接客户的信息（连接fd，客户地址）
      connnect, address = self.socket.accept()
      # 根据连接的客户信息，创建 WebSocket 对象（本质是一个线程）
      # sockfd, index, 用户名, 地址
      newSocket = WebSocket(connnect, self.i, address[0], address)
      # 线程启动
      newSocket.start()
      # 更新连接的集合 (hash表的对应关系)-name->sockfd
      connectList['connect'+str(self.i)] = connnect
      self.i += 1

# __name__ 代表当前模块名，当前模块/文件被直接运行时，其值为 __main__
# 即当前模块直接运行时，以下代码模块将被行动；当是被导入时，代码不被运行
if __name__ == "__main__":
  wss = WebSocketServer()
  wss.run()