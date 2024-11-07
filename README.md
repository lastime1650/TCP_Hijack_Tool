# TCP_Hijack_Tool
이것은 피해자 클라이언트 <-> 서버 사이에 중간자가 세션에 침투하였을 때, 피해자의 TCP세션을 하이재킹하는 도구입니다.

---

#세션 하이재킹?

세션 하이재킹은 **세션을 가로채는 공격**입니다. 
![initial](https://github.com/lastime1650/TCP_Hijack_Tool/blob/main/images/image2.png)
<br>위 사진에서는 세션 하이재킹이 어떻게 진행되는 지 자세하게 흐름 순으로 설명하고 있습니다.

### (1): <피해자->서버간 3-way handshaking에 관여>
<br>먼저 피해자 클라이언트가 서버에 세션 요청(flags:SYN)하는 것을 중간자가 알아야합니다.
그리고 서버로부터 SYN+ACK 플래그를 받아야, 피해자가 자신을 서버가 받아드렸다는 것을 인지하게 됩니다. 
하지만, 여기서 중간자가 3-way handshaking의 마지막 단계를 서버에게 전송하는 것을 막고, 피해자의 IP로 스푸핑된 RST패킷을 서버에게 전달하여 중간자가 임의로 피해자의 연결을 서버의 관점에서 연결을 종료한 것처럼 끊어버리게 만들어야합니다. 
> [!Important]
> 종료하는 이유는 공격자가 대신 피해자 행세로 할 것이기 때문입니다. 
> <br>연결을 끊어버리지만, 피해자 입장에서는 이를 모르기 때문에, 서버와 연결하고 있음을 인지합니다.
> <br>어짜피 피해자는 마지막단계에서 ACK를 보내기만 하면됩니다. 그 다음에는 데이터 통신을 합니다. 

### (2): 중간자->서버 세션 맺음
<br>중간자는 서버에 연결을 요청하여 둘 간의 TCP 세션을 맺습니다.
> [!IMPORTANT]
> 어짜피, 서버에서 신원을 검증하는 부분이 있다 한들, 피해자로부터 신원 정보를 받아서 그대로 전달하면됩니다.
> <br>중간자가 패킷을 실제로 전달하지만, 전송하는 **Payload의 근원지는 피해자**입니다.
> <br>서버에서 신원을 검증에 필요한 데이터를 필요로 하는 경우, 피해자의 Payload를 그대로 가져와서 전달합니다.

### (3): 피해자<->중간자 간 지속적인 세션 유지
<br>중간자는 피해자 관점에서 서버가 됩니다. 적절한 TCP의 seq, ack 번호를 직접 계산하여 TCP 세션을 유지해야만 합니다. 
<br>만약 피해자가 PSH+ACK, 데이터를 전달하려는 경우, 이를 받아 서버에 고스란히 전달하고, 서버의 ACK를 받으면 피해자에게 알려줘야합니다. (피해자<->중간자 간 유효한 seq, ack번호 준수. )

### (4): 중간자<->서버 간 지속적인 세션 유지
<br>중간자는 서버 관점에서 피해자가 됩니다. 이 또한 적절한 TCP의 seq, ack번호를 직접 계산해서 세션을 유지해야합니다. 
<br>만약 서버가 PSH+ACK, 데이터를 전달하려는 경우, 이를 받아 피해자에게 고스란히 전달하고, 피해자의 ACK를 받으면 서버에게 알려줘야합니다. (중간자<->서버 간 유효한 seq, ack번호 준수. )

---
 
# 알아야 할 것
먼저, 이 도구로부터 중요한 점은 다음과 같습니다.<br>

(1) *"스푸핑"*이 원할히 진행되고 있어야합니다.

> [!Important]
> 여기서 스푸핑은 피해자가 알고 있는 " 서버의 MAC주소 " 를 " 중간자의 MAC주소로 변경 " 해야한다는 점입니다.

<br>

(2) 이 TCP 하이재킹 공격은 공격자가 IP를 피해자로 스푸핑하여 서버에게 RST를 보내고, 중간자<->서버 간 TCP세션은 " SCAPY " 도구로 맺습니다

> [!CAUTION]
> SCAPY도구로 TCP세션을 맺는 경우, OS가 자체적으로 이를 거부합니다. ( 내부->외부로 **RST 패킷**을 날려버리는 문제 발생 ) 

(3) 피해자 클라이언트는 중간자를 실제 서버로 여깁니다. 실제 서버는 중간자를 피해자 클라이언트로 여깁니다.

(4) SCAPY기반으로만 개발되었습니다. 
> [!IMPORTANT]
> 가장 중요한 점.
> <br>1.중간자는 피해자 클라이언트간의 **세션 유지**할 수 있도록 Seq번호와 Ack번호를 모두 순차적으로 빠짐없이 관리해야합니다. ( 신뢰성 )
> <br>2.중간자는 서버간의 **세션 유지**할 수 있도록 Seq번호와 Ack번호를 모두 순차적으로 빠짐없이 관리해야합니다. ( 신뢰성 )

> [!CAUTION]
> 만약 하나라도 관리하지 않으면, TCP 송신자는 Retransmission(재전송)패킷을 지속적으로 날려, 통신에서 문제가 **누적**될 수 있어, 연결이 끊어질 수 있습니다.

(5) 모든 TCP 세션에 적용되지 않을 수 있습니다. PSH+ACK가 트리거 되었을 때, 이를 감지하고 세션을 유지하는 역할을 합니다. 

(6) Scapy기반 세션 유지, 불안정할 수 있습니다.
![initial](https://github.com/lastime1650/TCP_Hijack_Tool/blob/main/images/image1.png)
위 사진은 이 도구를 통한 피해자 클라이언트<->중간자<->서버간의 세션 유지를 하고 있지만, 한번 씩 retransmission이 발생하는 것을 보여주고 있습니다. 

---
# 샘플 채팅 서버 로직
![initial](https://github.com/lastime1650/TCP_Hijack_Tool/blob/main/images/image3.png)
 위 사진에서는 [샘플_채팅_클라이언트_및 서버](https://github.com/lastime1650/TCP_Hijack_Tool/tree/main/Sample_Chat_Sources)에 대한 동작 구조를 설명하고 있습니다. 
 <br>또한 클라이언트 단에서는, send(전송), recv(수신)을 "비동기"스레드로 처리합니다. 
 <br>각 메시지의 제한 길이는 **128**로 잡았습니다. 
> [!Note]
> JSON 송수신은 다음과 같습니다.
> <br> Send(전송): bytes( json.dumps(/*딕셔너리 변수*/), encoding='utf-8')
> <br> Recv(수신): dict( json.loads(/*상대에서 덤프한 JSON bytes 변수*/) )
