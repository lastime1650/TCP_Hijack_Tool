import json
import socket, threading
import time


class ChatClient:
    def __init__(self, ip:str, port:int):
        self.Client_Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.Client_Socket.connect((ip, port))

        self.my_id = {}
        self.my_id['id'] = 'A'
        self.my_id['pw'] = 'A1234A'
        self.Client_Socket.send(bytes(json.dumps(self.my_id), encoding='utf-8'))

        # login  check
        welcome_msg = self.Client_Socket.recv(512)
        welcome_status = dict( json.loads(welcome_msg) )
        print(welcome_status)

        if welcome_status["status"] == "fail":
            print("이 아이디는 서버에 없음")
            quit()

        time.sleep(0.1)
        # Receive
        threading.Thread(target=self.Recv,daemon=True).start()
        time.sleep(0.1)
        threading.Thread(target=self.Send,daemon=True).start()
        print("지금부터 입력한 값은 채팅에 포함됩니다. ")
        while  True: pass

    def Send(self):
        while  True:

            time.sleep(2)
            user_msg = input("")
            if(len(user_msg) < 1):
                print("메시지를 입력해주세요~")
                continue

            self.Client_Socket.send( bytes( user_msg.encode() ) )
            time.sleep(2)

    def Recv(self):
        while True:
            data = self.Client_Socket.recv(128)
            if len(data) == 0: quit()

            #print(data)
            print(dict(json.loads(data)))

            time.sleep(0.1)

if __name__ == '__main__':



    chat_client_inst_A_ = ChatClient('192.168.0.100', 4090)