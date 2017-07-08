package snort.test.Helpers;

import java.io.UnsupportedEncodingException;

import org.jnetpcap.PcapHeader;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;

import org.jnetpcap.protocol.lan.Ethernet;

import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;

import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.tcpip.Http;

import backtype.storm.tuple.Values;

public class CreateValue {
	public String protocol = "null";
	public String sip = "null";
	public String dip = "null";
	public int sport = -1;
	public int dport = -1;
	
	public byte[] payload;//应用层部分
	//ip options
	public boolean sameip = false; //check if source ip is the same as destination ip
	public int dsize = -1;//应用层长度
	public int total_len = -1;//整个报文长度
	public int MF = -1;
	public int DF = -1;
	public int Reserved = -1;
	public int ip_proto = -1;//ip protocol,可以是number or name（2 or ICMP）
	public int fragoffset = -1;//ip fragment offset field
	public int ttl = -1;//ip time to live value
	public int tos = -1;
	public int id = -1;
	//tcp options
	public int flags = -1;//check if TCP flag bits are present
	public long seq = -1;
	public long ack = -1;
	public int window = -1;//check for a specific TCP window size
	//icmp options
	public int itype = -1;
	public int icode = -1;
	public int icmp_id = -1;
	public int icmp_seq = -1;
	//not need return
	private Ethernet ether = new Ethernet();
	private Ip4 ip4 = new Ip4();
	private Ip6 ip6 = new Ip6();
	
	private Udp udp = new Udp();
	private Tcp tcp = new Tcp();
	private Http http = new Http();
	private Icmp icmp = new Icmp();
	private Arp arp = new Arp();

	public CreateValue(){}

	public void anal(PcapPacket pkt){
		//判断网络层协议
		if(pkt.hasHeader(Ethernet.ID)) {
			
			 pkt.getHeader(ether);
			int ether_type = ether.type();
			total_len = ether.getPayloadLength() + 14;
			if(ether_type == 0x0800) {//ipv4
				protocol = "ip";				
				pkt.getHeader(ip4);
				sip = FormatUtils.ip(ip4.source());
				dip = FormatUtils.ip(ip4.destination());
				if(sip.equals(dip))
					sameip = true;
				MF = ip4.flags_MF();
				DF = ip4.flags_DF();
				Reserved = ip4.flags_Reserved();
				fragoffset = ip4.offset();
				ttl = ip4.ttl();
				tos = ip4.tos();				
				id = ip4.id();				
				ip_proto = ip4.type();
				
				if (pkt.hasHeader(Tcp.ID)) {//tcp6
					pkt.getHeader(tcp);
					protocol = "tcp";
					sport = tcp.source();
					dport = tcp.destination();
					ack = tcp.ack();
					flags = tcp.flags();
					seq = tcp.seq();
					window = tcp.window();
					payload = tcp.getPayload();
					dsize = tcp.getPayloadLength();
					if(pkt.hasHeader(Http.ID)) {
						protocol = "http";		
					}			
				}
				else if(pkt.hasHeader(Udp.ID)) {//udp17
					pkt.getHeader(udp);
					protocol = "udp";
					sport = udp.source();
					dport = udp.destination();
					payload = udp.getPayload();
					dsize = udp.getPayloadLength();
					return;					
				}
				else if(pkt.hasHeader(Icmp.ID)) {//icmp1
					pkt.getHeader(icmp);
					protocol = "icmp";
					payload = icmp.getPayload();
					dsize = icmp.getPayloadLength();					
					return;
					
				}
				else {//other protocol or ip protocol
					payload = ip4.getPayload();
					dsize = ip4.getPayloadLength();					
				}				
			}
			else if(ether_type == 0x86dd) {//ipv6
				protocol = "ip";
				pkt.getHeader(ip6);
				sip = IPv6BytetoString(ip6.source(), ip6.source().length);
				dip = IPv6BytetoString(ip6.destination(), ip6.destination().length);
				if(pkt.hasHeader(Icmp.ID)) {
					pkt.getHeader(icmp);
					protocol = "icmp";
					ip_proto = 1;
					payload = icmp.getPayload();
					dsize = icmp.getPayloadLength();
					return;
				}
				else if(pkt.hasHeader(Udp.ID)) {
					pkt.getHeader(udp);
					protocol = "udp";
					ip_proto = 17;
					sport = udp.source();
					dport = udp.destination();
					payload = udp.getPayload();
					dsize = udp.getPayloadLength();
					return;		
				}
				else if(pkt.hasHeader(Tcp.ID)){
					pkt.getHeader(tcp);
					protocol = "tcp";
					ip_proto = 6;
					sport = tcp.source();
					dport = tcp.destination();
					ack = tcp.ack();
					payload = tcp.getPayload();
					dsize = tcp.getPayloadLength();
					if(pkt.hasHeader(Http.ID)) {
						protocol = "http";		
					}
				}
				else {
					payload = ip6.getPayload();
					dsize = ip6.getPayloadLength();
				}
			}
			else if(ether_type == 0x0806) {//arp
				protocol = "arp";
				pkt.getHeader(arp);
				payload = arp.getPayload();
				dsize = arp.getPayloadLength();
			}
		}		
	}
	
	public String IPv6BytetoString (byte[] a,int length)
	{
		String cer="";
		if(length==16){
			for(int i=0;i<length;i++)
			{
				String hex=Integer.toHexString(a[i] & 0xFF);
				if(hex.length()==1){
	        		hex ='0'+hex;
	        	}
				if(i%2==1&&i!=length-1){
				cer=cer+hex+":";
				}else{
					cer=cer+hex;
				}
			}
			
		}
		else if(length==4){
			for(int i=0; i<length; i++){
				cer+=a[i];
				if(i<length-1){
					cer+=".";
				}
			}
		}		
		return cer;
	}
}
