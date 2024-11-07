# TCP_Hijack_Tool
이것은 피해자 클라이언트 <-> 서버 사이에 중간자가 세션에 침투하였을 때, 피해자의 TCP세션을 하이재킹하는 도구입니다.


# 알아야 할 것
먼저, 중요한 점은 *"스푸핑"*이 원할히 진행되고 있어야합니다.

여기서 스푸핑은 피해자가 알고 있는 " 서버의 MAC주소 " 를 " 중간자의 MAC주소로 변경 " 해야한다는 점입니다. 

이 TCP 하이재킹 공격은 공격자가 IP를 피해자로 스푸핑하여 서버에게 RST를 보내고, 중간자<->서버 간 TCP세션은 " SCAPY " 도구로 맺습니다

[!CAUTION]
SCAPY도구로 TCP세션을 맺는 경우, 
