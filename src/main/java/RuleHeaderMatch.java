import snort.test.Helpers.*;

public class RuleHeaderMatch {
	public static void main(String[] args){
		Rule_Header rh = new Rule_Header();
		rh.action="alert";
		rh.protocol = "tcp";
		rh.sip = "![10.1.1.1,10.1.0.4/24]";
		rh.dip = "[10.1.1.1]";
		rh.sport = "[12:13]";
		rh.dport = "10:";
		rh.direction="<>";
		
		Packet_Header ph= new Packet_Header();
		ph.protocol = "tcp";
		ph.sip = "10.1.1.2";
		ph.dip = "10.1.1.1";
		ph.sport = 18;
		ph.dport = 11;
		
		System.out.println(rh.match(ph)+"");
		
	}			

}
