# TCP_Hijack_Tool
이것은 피해자 클라이언트 <-> 서버 사이에 중간자가 세션에 침투하였을 때, 피해자의 TCP세션을 하이재킹하는 도구입니다.


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

