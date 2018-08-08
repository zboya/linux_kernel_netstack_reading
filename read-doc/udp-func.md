https://www.aliyun.com/jiaocheng/206271.html

2. 两台主机建立udp通信所走过的函数列表
 
^
|       sys_read                fs/read_write.c
|       sock_read               net/socket.c
|       sock_recvmsg            net/socket.c
|       inet_recvmsg            net/ipv4/af_inet.c
|       udp_recvmsg             net/ipv4/udp.c
|       skb_recv_datagram       net/core/datagram.c
|       -------------------------------------------
|       sock_queue_rcv_skb      include/net/sock.h
|       udp_queue_rcv_skb       net/ipv4/udp.c
|       udp_rcv                 net/ipv4/udp.c
|       ip_local_deliver_finish net/ipv4/ip_input.c
|       ip_local_deliver        net/ipv4/ip_input.c
|       ip_recv                 net/ipv4/ip_input.c
|       net_rx_action           net/dev.c
|       -------------------------------------------
|       netif_rx                net/dev.c
|       el3_rx                  driver/net/3c309.c
|       el3_interrupt           driver/net/3c309.c
 
==========================
 
|       sys_write               fs/read_write.c
|       sock_writev             net/socket.c                   
|       sock_sendmsg            net/socket.c
|       inet_sendmsg            net/ipv4/af_inet.c
|       udp_sendmsg             net/ipv4/udp.c
|       ip_build_xmit           net/ipv4/ip_output.c
|       output_maybe_reroute    net/ipv4/ip_output.c
|       ip_output               net/ipv4/ip_output.c
|       ip_finish_output        net/ipv4/ip_output.c
|       dev_queue_xmit          net/dev.c
|       --------------------------------------------
|       el3_start_xmit          driver/net/3c309.c
V
 