import socket, threading, queue, time
import json

class ChatServer:
    def __init__(self, ip:str, port:int):
        self.Server_Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.Server_Socket.bind((ip, port))
        self.Server_Socket.listen(5)
        self.Clients = []
        self.Clients_Mutex = threading.Lock()

        self.LiveChatLogMutex = threading.Lock()
        self.LiveChatLog = [] # List[Dict]

        self.ID_infos = [ # 등록된 로그인 정보
                {"id":"A", "pw":"A1234A"}
                ]

    def Listen(self):
        while True:
            client_socket, addr = self.Server_Socket.accept()
            print(f"Connected by {addr} from ""Main_Server.py"" ")
            threading.Thread(target=self.Handle_Client, args=(client_socket, addr)).start()
            print(f"Clients -> {self.Clients}")

    def Handle_Client(self, client_socket, addr:tuple):
        print(f"Client<{client_socket}> connected by {addr} from Main_Server.py")
        while True:
            try:
                Receive_Data = client_socket.recv(1024)
                print(f'받은 데이터 -> {Receive_Data}')
                print("신원 검증 시작")
                Receive_Data = Receive_Data.decode('utf-8')
                id_json:dict = dict( json.loads(Receive_Data) )
                if "id" in id_json and "pw" in id_json:
                    #if id_json["id"] == "A" and id_json["pw"] == "A1234A":
                    if any( True  for saved_id in self.ID_infos.copy() if saved_id["id"] == id_json["id"] and saved_id["pw"] == id_json["pw"] ):
                        print("신원 검증 성공")
                        client_socket.send(bytes(json.dumps({"status":"success"}),encoding='utf-8'))
                        time.sleep(0.1)
                        self.add_client_socket(client_socket)
                        while True:
                            Chat_Data = client_socket.recv(128)
                            print(f"DATA_SIZE -> {Chat_Data} // {len(Chat_Data)}")
                            time.sleep(0.3)
                            self.send_message_to_them_clients(id_json["id"], Chat_Data)
                            #client_socket.send(b'I am [SERVER]')
                            continue
                    else:
                        client_socket.send(bytes(json.dumps({"status":"fail"}),encoding='utf-8'))
                        return
                else:
                    print("WHO ARE YOU ?;;")
                    return
            except:
                print("문제 발생")
                self.remove_client(client_socket)
                quit()

        
    def add_client_socket(self, socket_obj)->bool:
        with self.Clients_Mutex:
            self.Clients.append(socket_obj)
        return True

    def remove_client(self,socket_obj)->bool:
        with self.Clients_Mutex:
            self.Clients.remove(socket_obj)
        return True

    def add_chat_msg_log(self,socket_obj,username:str,msg:str)->bool:
        with self.LiveChatLogMutex:
            self.LiveChatLog.append({"username":"username", "msg": msg})
        return True

    def send_message_to_them_clients(self, username:str, msg:bytes):
        send_data = bytes(json.dumps({"username":username, "msg":msg.decode()}),encoding='utf-8')
        with self.Clients_Mutex:
            for client_sock in self.Clients:
                try:
                    print(client_sock, username, msg)

                    client_sock.send(send_data)
                except:
                    #if invalid ,,,,,, SOCKET OBJECT?!?!? REMOVE IT  
                    self.Clients.remove(client_sock)
                    continue
                time.sleep(0.3)

                    

a = {"a":"abc"}
json.dumps(a)
print(str(json.dumps(a)))

Server_Instance = ChatServer('192.168.0.100', 4090)
Server_Instance.Listen()
