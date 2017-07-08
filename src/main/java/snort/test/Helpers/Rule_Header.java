package snort.test.Helpers;

import java.util.ArrayList;
import java.util.regex.Pattern;
public class Rule_Header {
	public String action;
	public String protocol;
	public String sip;	
	//parsed sip info
	public int sip_type;//0表示any，1表示正值，-1表示非值。2 表示外网，-2表示内网
	public int sip_val; 
	public int sip_mask;//-1表示无mask
	
	public String sport;
	//parsed sport info
	public int sport_low;
	public int sport_high;
	public int sport_val;	
	public int sport_type;//0表示any，-1表示！，1表示正, 	
	public String direction;
	public String dip;
	//parsed sip info
	public int dip_type;//0表示any，1表示正值，-1表示非值。2 表示外网，-2表示内网
	public int dip_val; 
	public int dip_mask;//-1表示无mask
	
	public String dport;
	//parsed dport info
	public int dport_low;
	public int dport_high;
	public int dport_val;//-1表示为范围，否则为单值
	public int dport_type;
	
	public ArrayList<String> rule_option = new ArrayList<String>(110);
	public ArrayList<RuleOption> parsed_rule_option = new ArrayList<RuleOption>(110);
	
	//for test time
	private long lastTime;
	private long curTime;
	private long duringTime;
	private long start;
	private long end;
	
	public boolean equal(Rule_Header r_h){
		if(action.equals(r_h.action)&&protocol.equals(r_h.protocol)&&sip.equals(r_h.sip)&&sport.equals(r_h.sport)&&direction.equals(r_h.direction)&&dip.equals(r_h.dip)&&dport.equals(r_h.dport)){
			return true;
		}else{
			return false;
		}
	}
	public boolean match(Packet_Header pk){
		lastTime = System.nanoTime();
		String sip_tmp = "";
		String dip_tmp = "";
		String pk_protocol = pk.protocol;
		int pk_sip = pk.sip_val;
		int pk_dip = pk.dip_val;
		int pk_sport = pk.sport;
		int pk_dport = pk.dport;
		
		boolean isProtocolMatch = protocolMatch(pk_protocol, protocol);
		if(!isProtocolMatch) {
			return false;
		}
		//为了分步骤测试效率
		
		boolean isForwardMatch = portMatch(pk_sport, sport_type, sport_val, sport_low, sport_high) &&
		          				 portMatch(pk_dport, sport_type, sport_val, sport_low, sport_high) &&
		          				 addrMatch(pk_sip, sip_type, sip_val, sip_mask) &&
		          				 addrMatch(pk_dip, dip_type, dip_val, dip_mask) ;
		
		if(isForwardMatch) {
			return true;
		}
		return false;		
	}
	public Rule_Header(){}
	
	public Rule_Header(String[] r_h,String r_o){
		if(r_h[0].equals("#")) {
			action = r_h[1];
			protocol = r_h[2];
			sip = r_h[3];
			sport = r_h[4];
			direction = r_h[5];
			dip = r_h[6];
			dport = r_h[7];
			rule_option.add(r_o);		
		}
		else {
			action = r_h[0];
			protocol = r_h[1];
			sip = r_h[2];
			sport = r_h[3];
			direction = r_h[4];
			dip = r_h[5];
			dport = r_h[6];
			rule_option.add(r_o);
			
		}
		
	}
	
	public static boolean protocolMatch(String pk_protocol, String rule_protocol) {
	if(rule_protocol.equals(pk_protocol)==false){//proto:ip(tcp(http)/udp/icmp/igmp)/arp/
		if(rule_protocol.equals("ip") ) {
			if(!(pk_protocol.equals("tcp")||pk_protocol.equals("udp")||pk_protocol.equals("icmp")||pk_protocol.equals("igmp")||pk_protocol.equals("http"))){
				return false;
			}				
		}
		else if(rule_protocol.equals("tcp")) {
			if(!pk_protocol.equals("http")){
				return false;
			}								
		}
		else {
			return false;
		}		
	}
	return true;		
}

	
public static boolean addrMatch(int pk_addr, int ip_type, int ip_val , int ip_mask) {
	if(ip_type == 0) //any
		return true;
	if(ip_type == 2 || ip_type == -2) {//exteranl or internal
		boolean isInter = ((pk_addr >= 167772160 && pk_addr <= 184549375)||
				(pk_addr >= -1408237568 && pk_addr <= -1407188993) ||
				(pk_addr >= -1062731776 && pk_addr <= -1062666241));
		if(isInter) {
			if(ip_type == -2)
				return true;
			return false;
		}
		else {
			if(ip_type == 2) 
				return true;
			return false;
		}
		
	}
	if(ip_type == 1) {//正值
		return (pk_addr & ip_mask) == (ip_val & ip_mask);
	}
	else{//非
		return !((pk_addr & ip_mask) == (ip_val & ip_mask));
	}
}


public boolean portMatch(int pk_port, int port_type, int port_val, int port_low, int port_high) {
		if(port_type == 0) //any
			return true;
		else if(port_type == 1){//正
			if(port_val != -1) {//单值
				if(port_val == pk_port)
					return true;
				return false;
			}
			else{//范围
				if(pk_port >= port_low && pk_port <= port_high)
					return true;
				return false;				
			}
		}
		else{//负
			if(port_val != -1) {//单值
				if(port_val == pk_port)
					return false;
				return true;
			}
			else{//范围
				if(pk_port >= port_low && pk_port <= port_high)
					return false;
				return true;				
			}
			
		}			
	}
}
