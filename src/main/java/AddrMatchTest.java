import snort.test.Helpers.*;
import snort.test.Bolts.Rule_Bolt;
public class AddrMatchTest {
	public AddrMatchTest(){};
	public static void main(String[] args) {
		Rule_Header rh = new Rule_Header();
		rh.sip = "10.0.0.1/31";
		rh.dip = "$EXTERNAL_NET";
		rh.dport = "13:";
		rh.sport = "!13";
		String pkt_ip = "10.0.0.0";
		int pk_addr = Rule_Bolt.convertAddrStr2Int(pkt_ip);
		rh = Rule_Bolt.parseRuleHeader(rh);
		System.out.println(pk_addr+" "+ rh.sip_type+" "+rh.sip_val+" "+rh.sip_mask);
		System.out.println(pk_addr+" "+ rh.dip_type+" "+rh.dip_val+" "+rh.dip_mask);
		boolean sipMatch = rh.addrMatch(pk_addr, rh.sip_type, rh.sip_val, rh.sip_mask);
		boolean dipMatch = rh.addrMatch(pk_addr, rh.dip_type, rh.dip_val, rh.dip_mask);
		System.out.println(sipMatch);
		System.out.println(dipMatch);
	}
}
