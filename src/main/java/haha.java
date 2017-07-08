import java.util.regex.Pattern;

public class haha {
	// for test address match
	public static void main(String[] args){
		
		System.out.println(convertAddrStri2Int("10.0.0.0"));
		System.out.println(convertAddrStri2Int("10.255.255.255"));
		System.out.println(convertAddrStri2Int("192.168.0.0"));
		System.out.println(convertAddrStri2Int("192.168.255.255"));
		System.out.println(convertAddrStri2Int("172.16.0.0"));
		System.out.println(convertAddrStri2Int("172.31.255.255"));
		int mask = 0xFFFFFFFF << 1;
		System.out.println(convertAddrStri2Int("172.16.0.1") == -1408237567);
		System.out.println(convertAddrStri2Int("10.10.10.11")&mask);
		
		int a = 0;
		changePara(a);
		System.out.println(a);
		
		
		String rule_protocol = "tcp";
		String rule_sip = "![10.1.1.1,10.1.0.4/24]";
		String rule_dip = "[10.1.1.1]";
		String rule_sport = "!1:10";
		String rule_dport = "1:10";
		
		String pk_protocol = "tcp";
		String pk_sip = "10.1.1.1";
		String pk_dip = "10.1.1.22";
		int pk_sport = 9;
		int pk_dport = 11;
		
		String direction="<>";
		
		boolean isProtocolMatch = protocolMatch(pk_protocol, rule_protocol);
		if(isProtocolMatch) {
			boolean isForwardMatch = protocolMatch(pk_protocol, rule_protocol) &&
			          addrMatch(pk_sip, rule_sip) &&
			          addrMatch(pk_dip, rule_dip) &&
			          portMatch(pk_sport, rule_sport) &&
			          portMatch(pk_dport, rule_dport);
			System.out.println("> diection match is:"+isForwardMatch);
			if(direction.equals("<>")) {
				boolean isBackwordMatch =  addrMatch(pk_sip, rule_dip) &&
				          				   addrMatch(pk_dip, rule_sip) &&
				                           portMatch(pk_sport, rule_dport) &&
				                           portMatch(pk_dport, rule_sport);
				System.out.println("<> diection match is:"+isBackwordMatch);
				         
			}
			
		}
		else {
			System.out.println("protocol dont match");
		}
			
		
		
	}	
	public static void changePara(int a) {
		a = 9;
	}
		
	public static int convertAddrStri2Int(String addr)	{
		String[] networkips = addr.split("\\.");
		int ipAddr = (Integer.parseInt(networkips[0]) << 24)
	            | (Integer.parseInt(networkips[1]) << 16)
	            | (Integer.parseInt(networkips[2]) << 8)
	            | Integer.parseInt(networkips[3]);
		return ipAddr;
	}
	public static boolean protocolMatch(String pk_protocol, String rule_protocol) {
		if(rule_protocol.equals(pk_protocol)==false){//proto:ip(tcp(http)/udp/icmp/igmp)/arp/
			if(rule_protocol.equals("ip") ) {
				if(!(pk_protocol.equals("tcp")||pk_protocol.equals("udp")||pk_protocol.equals("icmp")||pk_protocol.equals("igmp")||pk_protocol.equals("http"))){
					System.out.println("rule_pro==ip and return");
					return false;
				}				
			}
			else if(rule_protocol.equals("tcp")) {
				if(!pk_protocol.equals("http")){
					System.out.println("rule_pro==tcp,and return");
					return false;
				}								
			}
			else {
				System.out.println("rule_pro!=ip or tcp and return");
				return false;
			}
			System.out.println("rule_protocol matches pk_protocol");
			//System.out.println("packet_ptocol);rotocol:"+pk.pro			
		}
		return true;		
	}
	
	public static boolean isInRange(String pk_ip, String rule_ip) {
		String[] networkips = pk_ip.split("\\.");
		int ipAddr = (Integer.parseInt(networkips[0]) << 24)
                | (Integer.parseInt(networkips[1]) << 16)
                | (Integer.parseInt(networkips[2]) << 8)
                | Integer.parseInt(networkips[3]);
        int type = Integer.parseInt(rule_ip.replaceAll(".*/", ""));
        int mask1 = 0xFFFFFFFF << (32 - type);
        String maskIp = rule_ip.replaceAll("/.*", "");
        String[] maskIps = maskIp.split("\\.");
        int cidrIpAddr = (Integer.parseInt(maskIps[0]) << 24)
                | (Integer.parseInt(maskIps[1]) << 16)
                | (Integer.parseInt(maskIps[2]) << 8)
                | Integer.parseInt(maskIps[3]);

        return (ipAddr & mask1) == (cidrIpAddr & mask1);
	}
	
	public static boolean addrMatch(String pk_addr, String rule_addr) {
		//对内外网进行匹配
		String tmp_addr;
		Pattern pattern1 = Pattern.compile("^10.*");
		Pattern pattern2 = Pattern.compile("^172.(16|17|18|19|2[0-9]|30|31).*");
		Pattern pattern3 = Pattern.compile("^192.168.*");
		if(pattern1.matcher(pk_addr).matches()||pattern2.matcher(pk_addr).matches()||pattern3.matcher(pk_addr).matches()){
			System.out.println("tmp_addr = $HOME_NET");
			tmp_addr = "$HOME_NET";
		}			
		else{
			System.out.println("tmp_addr = $EXTERNAL_NET");
			tmp_addr = "$EXTERNAL_NET";
		}					
		if(!rule_addr.contains("!")) {//判断rule_addr
			if(!(rule_addr.contains(pk_addr) || rule_addr.equals(tmp_addr))){//如果sip不直接匹配，判断CIDR格式
				if(rule_addr.contains("[")) { //rule_addr list
					String rule_addr_list = rule_addr.substring(1,rule_addr.length()-1);
					System.out.println("rule_addr_list is:"+rule_addr_list);
					String[] rule_addrs = rule_addr_list.split(",");
					int travel_rule_addrs = 0;
					for(travel_rule_addrs=0; travel_rule_addrs<rule_addrs.length; travel_rule_addrs++) {
						System.out.println("rule addrs is:"+rule_addrs[travel_rule_addrs]);
						if(rule_addrs[travel_rule_addrs].contains("/")) {//CIDR sip addr只考虑
							System.out.println("rule addrs is:"+rule_addrs[travel_rule_addrs]);
							if(isInRange(pk_addr, rule_addrs[travel_rule_addrs])) {
								System.out.println("is in range");
								break;
							}
								
						}						
					}
					if(travel_rule_addrs == rule_addrs.length) {
						System.out.println("rule_addr dont mactch pk addr list");
						return false;						
					}					
				}
				else {//single rule_addr
					if(!(rule_addr.contains("/") && isInRange(pk_addr, rule_addr))) {//CIDR rule_addr
						System.out.println(" single rule addr dont match pk addr");
						return false;										
					}					
				}
			}
		}
		else{//rule addr中含有！
			if(rule_addr.contains(pk_addr) || rule_addr.equals(tmp_addr)) {//直接匹配命中
				System.out.println("! addr and direct match");
				return false;
			}
			if(rule_addr.contains("[")) {//!rule_addr list
				String rule_addr_list = rule_addr.substring(2,rule_addr.length()-1);
				System.out.println("rule_addr_list is:"+rule_addr_list);
				String[] rule_addrs = rule_addr_list.split(",");
				int travel_rule_addrs = 0;
				for(travel_rule_addrs=0; travel_rule_addrs<rule_addrs.length; travel_rule_addrs++) {
					if(rule_addrs[travel_rule_addrs].contains("/")) {//CIDR sip addr只考虑
						if(isInRange(pk_addr, rule_addrs[travel_rule_addrs])) {
							System.out.println("! addr and match CIDR list");
							return false;
						}							
					}					
				}
			}
			else{//single rule addr
				if(rule_addr.contains("/") && isInRange(pk_addr, rule_addr)) {
					System.out.println("!single rule_addr and mactch CIDR");
					return false;
				}			
			}	
		}
		return true;		
	}
	
	public static boolean portMatch(int pk_port, String rule_port) {
		if(rule_port.equals("any")==false){//rule_port
			System.out.println("rule_port.equals(any)==false");
			if (!rule_port.contains("!")) {
				if (rule_port.contains(""+pk_port)==false){
					System.out.println("rule_port.contains(pk.sport)==false");
					if(rule_port.contains(":")){
						String[] ports = rule_port.split(":");
						int start_port = Integer.parseInt(ports[0]);
						int end_port = Integer.parseInt(ports[1]);
						System.out.println("the start port is:"+start_port+",end port is:"+end_port);
						if(pk_port > end_port || pk_port < start_port) {
							System.out.println("pk_port > end_port || pk_port < start_port");
							return false;
						}
					}
					else {
						System.out.println("rule_port dont match pk_port");
						return false;
					}
				}			
			}
			else {
				if (rule_port.contains(""+pk_port)){
					System.out.println("negative rule_port.contains pk_port");
					return false;
				}
				if(rule_port.contains(":")){
					
					String[] ports = rule_port.split(":");
					int start_port = Integer.parseInt(ports[0].substring(1));
					int end_port = Integer.parseInt(ports[1]);
					System.out.println("negative the start port is:"+start_port+",end port is:"+end_port);
					if(pk_port <= end_port && pk_port >= start_port) {
						System.out.println("negative pk_port <= end_port && pk_port >= start_port");
						return false;
					}
				}
				else {
					System.out.println("negative rule_port dont match pk_port");
					return false;
				}
				
			}
		}
		return true;			
	}
		
	

  
}
