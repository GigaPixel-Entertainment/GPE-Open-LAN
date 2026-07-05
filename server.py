print("""
####################
#                  #
#     Open-LAN     #
#                  #
####################
by Gigapixel Entertainment LLC
""")

print("""
REQUIRED IMPORTS:
(use pip to install)
cryptography,
websockets,
http,
io,
traceback,
threading,
secrets,
pathlib,
msgpack,
asyncio,
bcrypt,
psutil,
socket,
select,
base64,
time,
json,
sys,
ssl,
os
""")

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from websockets.asyncio.server import serve, broadcast, ServerConnection
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from http.server import BaseHTTPRequestHandler
from cryptography.fernet import Fernet
from http import cookies
from io import BytesIO
import traceback
import threading
import secrets
import pathlib
import msgpack
import asyncio
import bcrypt
import psutil # type: ignore
import socket
import select
import base64
import time
import json
import sys
import ssl

PORT = 33333
WS_PORT = 33334
WSS_PORT = 33335
SOCKET_BACKLOG_NUM = 5
MAX_RETRY_ATTEMPTS = 10
RETRY_ATTEMPTS_CLEAR_AFTER_SEC = 120
NUM_ENCRYPT_ROUNDS = 15

CWD = pathlib.Path(__file__).resolve().parent
CA_CERT_DIR = CWD / "CA_CERT"
CHATS_DIR = CWD / "Chats/"
CHATS_KEY = CHATS_DIR / "meta.key"
CSS_DIR = CWD / "CSS/"
MEDIA_DIR = CWD / "Media/"
USERS_DIR = CWD / "Users/"

PRIVATE_DIRS = [
    USERS_DIR,
    CHATS_DIR,
    CA_CERT_DIR
]

FILEEXT_TO_MIME = {
    ".png": "image/png",
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8"
}

WS_CLIENTS = set()
VALID_TOKENS = {}
SHORT_REDIRECT_TOKENS = {}

print("Generating encryption key")
PRIV_KEY = ec.generate_private_key(ec.SECP256R1())
PUB_KEY = PRIV_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint
)
print("Key generated successfully")

users = []

chats = []
chatKey = None
fernet = None

class HTTPRequestParser(BaseHTTPRequestHandler):
    def __init__(self, request_bytes):
        self.rfile = BytesIO(request_bytes)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        
        self.parse_request()

    def send_error(self, code, message=None, explain=None):
        self.error_code = code
        self.error_message = message

def genChatKey():
    key = Fernet.generate_key()
    with open(CHATS_KEY, "wb") as f:
        f.write(key)
        f.close()

def loadUsers():
    print("Loading users")

    if not USERS_DIR.exists():
        USERS_DIR.mkdir()
    

    for usr in USERS_DIR.iterdir():
        if usr.is_file():
            with open(usr, "rb") as f:
                users.append(msgpack.unpackb(f.read()))
                f.close()
    
    print("Users loaded")

def loadChats():
    global chatKey
    global fernet

    print("Loading chats")

    if not CHATS_DIR.exists():
        CHATS_DIR.mkdir()

    if not CHATS_KEY.exists():
        print("Generating new chat key!")
        genChatKey()
    
    print("Reading chat key")
    with open(CHATS_KEY, "rb") as f:
        chatKey = f.read()
        f.close()
    
    fernet = Fernet(chatKey)
    
    for chat in CHATS_DIR.iterdir():
        if chat.is_file() and chat.suffix == ".enc":
            try:
                with open(chat, "rb") as f:
                    fileContents = msgpack.unpackb(f.read())
                    metadata = fileContents["meta"]
                    messages = fileContents["messages"]

                    for msg in messages:
                        msg["content"] = fernet.decrypt(msg["content"]).decode("utf-16")

                    chats.append({"CID": metadata["CID"], "messages": messages})
                    f.close()
            except Exception:
                traceback.print_exc()
                print(f"Failed to load chat! {chat.name}")
    
    print("Chats loaded")

def saveChats():
    print("Saving chats")

    for chat in chats:
        try:
            chatID = chat["CID"]
            with open(CHATS_DIR / f"{chatID}.enc", "wb") as f:
                metadata = {"CID": chatID}
                messages = []

                for msg in chat["messages"]:
                    messages.append({"time":msg["time"], "content":fernet.encrypt(msg["content"].encode("utf-16")), "user":msg["user"]})

                f.write(msgpack.packb({"meta":metadata,"messages":messages}))
                f.close()
        except Exception:
            traceback.print_exc()
            print(f"Failed to save chat! {chat}")
    
    print("Chats saved")
        
def getUsernameFromAuthToken(token):
    for username, tk in VALID_TOKENS.items():
        if tk["TOKEN"] == token:
            return username
    
    return None

def getUserInfoFromUsername(username):
    for user in users:
        if user["USRNAME"] == username:
            return user
        
    return None

def getUserInfoFromToken(token):
    username = getUsernameFromAuthToken(token)

    if username == None:
        return None
    
    return getUserInfoFromUsername(username)

def getChatFromCID(CID):
    for chat in chats:
        if chat["CID"] == CID:
            return chat
    
    return None

def tokenInChat(token, CID):
    chat = getChatFromCID(CID)

    if chat == None:
        return False

    userInfo = getUserInfoFromToken(token)

    if userInfo == None:
        return False
    
    if not CID in userInfo["Chats"]:
        return False
    
    return True

def getIpAddrs():
    ip_list = []
    interfaces = psutil.net_if_addrs()
    
    for interface_name, interface_addresses in interfaces.items():
        for address in interface_addresses:
            if address.family == socket.AF_INET and not address.address.startswith("127."):
                print(f"Interface: {interface_name} -> IP Address: {address.address}")
                ip_list.append(address.address)
                
    return ip_list

def formatHttpResponse(filePath: pathlib.Path):
    if not filePath.is_file():
        print(f"Invalid fetch {filePath}!")

        return formatErrorResponse(404)
    
    fileContents = bytes()
    with open(filePath, "rb") as f:
        fileContents = f.read()
        f.close()

    mime = FILEEXT_TO_MIME[filePath.suffix]

    return (
        "HTTP/1.1 200 OK\r\n"
        f"Content-Type: {mime}\r\n"
        f"Content-Length: {len(fileContents)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("utf-8") + fileContents

def formatLoginResponse(username):
    if not username:
        return formatErrorResponse(500)

    token = secrets.token_urlsafe(256)
    VALID_TOKENS[username] = {"TOKEN": token, "EXPIRES": time.time() + (1*24*60*60)} # Expires in 1 day
    return (
        "HTTP/1.1 308 Permanent Redirect\r\n"
        f"Set-Cookie: authToken={token}; Secure; HttpOnly; SameSite=Strict; Path=/\r\n"
        f"Location: /app.html\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("utf-8")

def formatErrorResponse(statusCode):
    if statusCode == 400:
        return "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n".encode("utf-8")
    elif statusCode == 401:
        return "HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n".encode("utf-8")
    elif statusCode == 404:
        return "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n".encode("utf-8")
    elif statusCode == 500:
        return "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n".encode("utf-8")
    
    return "HTTP/1.1 418 I'm a teapot\r\nConnection: close\r\n\r\n".encode("utf-8")

def closeSocket(sk: socket.socket):
    try:
        sk.shutdown(socket.SHUT_WR)
        sk.close()
    except:
        pass

def isSafePath(path: pathlib.Path):
    reqPath = path.resolve()

    for privDir in PRIVATE_DIRS:
        if privDir.resolve() in reqPath.parents:
            return False

    if CWD.resolve() in reqPath.parents:
        return True

def handleRequest(sk: socket.socket):
    request = sk.recv(4096)
    parsed = HTTPRequestParser(request)

    if parsed.error_code:
        print(f"Failed to parse {request.decode("utf-8")}")
        closeSocket(sk)
        return
    
    method = parsed.command
    path = parsed.path
    pathSplit = path.split("?")
    page = pathSplit[0]
    uri = {}

    if len(pathSplit) > 1:
        for pair in pathSplit[1].split("&"):
            if len(pair.split("=")) > 1:
                uri[pair.split("=")[0]] = pair.split("=")[1]

    if method == "GET":
        if page == "/":
            page = "/index.html"
        
        pagePath = CWD / page.removeprefix("/")

        if page == "/api/wsports":
            sk.sendall(f"HTTP/1.1 200 OK\r\nWs-Port: {WS_PORT}\r\nWss-Port: {WSS_PORT}\r\nContent-Type: text/plain\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode("utf-8"))
        elif page == "/api/login":
            if "TK" in uri:
                username = isValidRedirectToken(uri["TK"])

                if username != None:
                    sk.sendall(formatLoginResponse(username))
        elif isSafePath(pagePath):
            sk.sendall(formatHttpResponse(pagePath))
        else:
            sk.sendall(formatErrorResponse(400))
    elif method == "POST":
        pass

    closeSocket(sk)

def isValidRedirectToken(redirectToken):
    for k, v in SHORT_REDIRECT_TOKENS.items():
        if "TOKEN" in v and v["TOKEN"] == redirectToken and v["EXPIRES"] > time.time():
            SHORT_REDIRECT_TOKENS.pop(k)
            return k
    
    return None


def isValidToken(authToken, username=None):
    if username:
        if not username in VALID_TOKENS:
            return False

        if "EXPIRES" in VALID_TOKENS[username] and VALID_TOKENS[username]["EXPIRES"] < time.time():
            VALID_TOKENS[username] = None
            return False
            
        if "TOKEN" in VALID_TOKENS[username] and VALID_TOKENS[username]["TOKEN"] == authToken:
            return True
        
    else:
        for key, value in VALID_TOKENS.items():
            if "EXPIRES" in value and value["EXPIRES"] < time.time():
                VALID_TOKENS[key] = None
                if "TOKEN" in value and value["TOKEN"] == authToken:
                    return False
            
            if "TOKEN" in value and value["TOKEN"] == authToken:
                return True

    return False

async def getAuth(connection, request):
    cookie_header = request.headers.get("Cookie")
    
    if cookie_header:
        parser = cookies.SimpleCookie()
        parser.load(cookie_header)
        
        parsed_cookies = {key: morsel.value for key, morsel in parser.items()}
        
        connection.authToken = parsed_cookies.get("authToken")

async def wsSendEncrypted(ws: ServerConnection, data: str):
    iv = secrets.token_bytes(12)
    encryptor = Cipher(algorithms.AES256(getattr(ws, "secretKey")), modes.GCM(iv)).encryptor()
    ciphertext = encryptor.update(data.encode("utf-8")) + encryptor.finalize() + encryptor.tag

    await ws.send(json.dumps({"encryption":"AES","iv":iv.hex(),"body":ciphertext.hex()}))

async def checkAuthTokenEncrypted(ws: ServerConnection, authToken: str):
    if not isValidToken(authToken):
        await wsSendEncrypted(ws, json.dumps({"type":"auth_expired"}))
        await ws.close()
        return False
    return True

async def wsHandler(ws: ServerConnection):
    WS_CLIENTS.add(ws)

    authToken = getattr(ws, "authToken", None)

    try:
        async for message in ws:
            msgDecoded = json.loads(message)

            if "type" in msgDecoded and msgDecoded["type"] == "encrypt-key-xch":
                clientKey = ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256R1(),
                    bytes.fromhex(msgDecoded["publicKey"])
                )

                setattr(ws, "secretKey", PRIV_KEY.exchange(ec.ECDH(), clientKey))

                await ws.send(json.dumps({"type":"encrypt-key-xch", "publicKey": PUB_KEY.hex()}))
                continue
            
            if "encryption" in msgDecoded and msgDecoded["encryption"] == "AES":
                key = getattr(ws, "secretKey", None)
                if key == None:
                    print("Encrypted message sent without key!")
                    raise ConnectionRefusedError

                decryptor = Cipher(algorithms.AES256(key), modes.GCM(bytes.fromhex(msgDecoded["iv"]))).decryptor()
                decryptedText = decryptor.update(bytes.fromhex(msgDecoded["body"]))[:-16]
                
                decryptedBody = json.loads(decryptedText.decode("utf-8"))

                if decryptedBody["type"] == "login":
                    found = False
                
                    for usr in users:
                        if usr["USRNAME"] == decryptedBody["username"]:
                            if bcrypt.checkpw(base64.b64decode(decryptedBody["password"]), usr["PWD"].encode("utf-8")):
                                token = secrets.token_urlsafe(32)
                                SHORT_REDIRECT_TOKENS[usr["USRNAME"]] = {"TOKEN":token,"EXPIRES":time.time() + 60} # 1 minute
                                await wsSendEncrypted(ws, json.dumps({"type":"loginSuccess","redirect":f"/api/login?TK={token}"}))
                                found = True
                            else:
                                await wsSendEncrypted(ws, json.dumps({"type":"loginFailed"}))
                    
                    if not found:
                        await wsSendEncrypted(ws, json.dumps({"type":"loginFailed"}))
                
                if decryptedBody["type"] == "reqUser":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        userinfo = getUserInfoFromToken(authToken)

                        if userinfo == None:
                            await wsSendEncrypted(ws, json.dumps({"type":"reqUserFailed", "message": "User not found!"}))
                            continue
                        
                        await wsSendEncrypted(ws, json.dumps({
                            "type": "reqUserSuccess",
                            "username": userinfo["USRNAME"],
                            "UID": userinfo["UID"],
                            "friends": userinfo["Friends"],
                            "chats": userinfo["Chats"]
                        }))
                    else:
                        break

                if decryptedBody["type"] == "reqChat":
                    if await checkAuthTokenEncrypted(ws, authToken):
                        if not tokenInChat(authToken, decryptedBody["CID"]):
                            await wsSendEncrypted(ws, json.dumps({"type":"reqChatFailed","message":"User not in chat!"}))
                            continue
                        
                        chat = getChatFromCID(decryptedBody["CID"])

                        if chat == None:
                            await wsSendEncrypted(ws, json.dumps({"type":"reqChatFailed","message":"Chat not found!"}))
                            continue

                        await wsSendEncrypted(ws, json.dumps({"type":"reqChatSuccess", "chat": chat}))
                    else:
                        break
                continue
            

    except Exception:
        traceback.print_exc()
    finally:
        WS_CLIENTS.remove(ws)

async def shutdownWs(shutdownEvent):
    print("Stopping Websocket!")
    for ws in list(WS_CLIENTS):
        await ws.close()

    shutdownEvent.set()
    asyncio.get_running_loop().stop()

async def wsListen(ipAddrs, context, shutdownEvent):
    servers = []

    for addr in ipAddrs:
        servers.append(serve(wsHandler, addr, WSS_PORT, ssl=context, process_request=getAuth))
        print(f"wss://{addr}/{WSS_PORT}")
        servers.append(serve(wsHandler, addr, WS_PORT, process_request=getAuth))
        print(f"ws://{addr}/{WS_PORT}")

    print("Websockets running")
    
    await asyncio.gather(*servers, shutdownEvent.wait())

def wsBootstrap(loop: asyncio.AbstractEventLoop):
    print("Websocket Bootstrap")
    asyncio.set_event_loop(loop)
    loop.run_forever()

if __name__ == "__main__":
    numErr = 0
    lastErr = time.time()

    loadUsers()
    loadChats()
    
    ipAddrs = getIpAddrs()
    
    if len(ipAddrs) == 0:
        print("No valid network interfaces found! Please connect to a network")
        sys.exit(-1)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CA_CERT_DIR / "server.crt", keyfile=CA_CERT_DIR / "server.key")
    
    socketList: list[socket.socket] = []
    for addr in ipAddrs:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((addr, PORT))
        sock.listen(SOCKET_BACKLOG_NUM)

        socketList.append(sock)
        print(f"Listening on {addr}:{PORT}")
    
    wsLoop = asyncio.new_event_loop()
    wsShutdownEvent = asyncio.Event()
    wsThread = threading.Thread(target=wsBootstrap, args=(wsLoop,), daemon=True)
    wsThread.start()

    asyncio.run_coroutine_threadsafe(wsListen(ipAddrs, context, wsShutdownEvent), wsLoop)

    print("HTTP Primed and ready to go")
    
    while True:
        try:
            read_sockets, _, _ = select.select(socketList, [], [])
            
            for notified_socket in read_sockets:
                cSocket, ip = notified_socket.accept()
                peekBytes = cSocket.recv(3, socket.MSG_PEEK)

                if len(peekBytes) < 3:
                    closeSocket(cSocket)
                    continue

                if peekBytes[0] == 0x16:
                    try:
                        with context.wrap_socket(cSocket, server_side=True) as secureSk:
                            handleRequest(secureSk)
                    except ssl.SSLError as e:
                        print(f"SSL Handshake failure: {e}")
                    except Exception as e:
                        print(f"Error handling connection: {e}")
                elif peekBytes in (b'GET', b'POS', b'PUT', b'DEL', b'HEA', b'OPT'):
                    handleRequest(cSocket)
                else:
                    print(f"Unknown Protocol. Bytes: {peekBytes}")
                
                closeSocket(cSocket)
        except KeyboardInterrupt:
            print("opythat!")
            break
        except Exception:
            traceback.print_exc()

            if time.time() - lastErr >= RETRY_ATTEMPTS_CLEAR_AFTER_SEC:
                numErr = 0

            if numErr < MAX_RETRY_ATTEMPTS:
                numErr += 1
                print(f"Attempting to recover ({numErr})")
            else:
                print("Max Retry Attempts Exceeded")
                break
    
    print("Shutting down Websocket thread (5s)")
    asyncio.run_coroutine_threadsafe(shutdownWs(wsShutdownEvent), loop=wsLoop)
    wsThread.join(5)

    if wsThread.is_alive():
        print("Forcibly shutting down Websocket thread!")
        wsLoop.close()

    print("Shutting down sockets")
    for sk in socketList:
        sk.close()

    saveChats()
