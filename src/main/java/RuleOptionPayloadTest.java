import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import snort.test.Helpers.*;
import snort.test.Bolts.*;


public class RuleOptionPayloadTest {
	
	byte[] payload = {};
	public static void main(String args[]) {
//		String str = "fan fam come came om on youyour can fam come dodone it hou dao will can come dodone attach to youyour";
//		byte[] payload = str.getBytes();
//		byte[] payload = {0x05,0x3a,(byte) 0xf2,0x33,0x55,0x48,0x33,(byte) 0xcc,0x6a,(byte) 0x85,(byte) 0xb1,(byte) 0x85,0x45,(byte) 0xf8,(byte) 0x94,0x34,0x72,0x3c,(byte) 0xea,0x0b,(byte) 0xe4,0x34,0x47,0x40,(byte) 0xc1,(byte) 0xf6};
//		byte[] payload = {0x30,0x45,0x00,0x00,0x28,0x12,(byte) 0xed,0x40,0x00, 0x40,(byte) 0x06,(byte) 0x47,(byte) 0xac,(byte) 0x0d,(byte) 0x08,0x03,(byte) 0xf3,0x75,(byte) 0xaf,0x59,(byte) 0x8d,(byte) 0xd2,(byte) 0xd5,0x01,(byte) 0xbb,(byte) 0x01};
		byte[] payload = {0x61,0x67,0x00,0x00,0x00,0x01,(byte) 0x00,0x00,0x00, 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x05,(byte) 0x70,(byte) 0x6c,0x75,(byte) 0x74,(byte) 0x6f,0x04,(byte) 0x70,(byte) 0x6c,(byte) 0x75,0x6d,(byte) 0x03,(byte) 0x6e,0x65,0x74,0x00,0x00,0x01,0x00,0x01};
//		String s = new String(b);
//		System.out .println(s);
		
		//开始测试ruleOption
		//构造packet
		Packet_Header ph = new Packet_Header();
		ph.fragoffset = 1;
		ph.ttl = 5;
		ph.tos= 5;
		ph.id = 5;
		ph.MF = 1;
		ph.DF =0;
		ph.Reserved = 1;
		ph.ip_proto=5;
		ph.ack=5;
		ph.dsize = 5;
		ph.seq = 5;
		ph.window = 5;
		ph.flags = 0x80;
		
		
		
		//构造ruleOption
		RuleOption ro = new RuleOption();
		Map<String,String> m0 = new HashMap<String,String>();
		m0.put(" fragoffset", "1");
		m0.put(" ttl", ">3");
//		m0.put(" ttl", ">=3");
//		m0.put(" ttl" , "3-5");
//		m0.put(" ttl", "3-");
//		m0.put(" ttl", "-5");
//		m0.put(" ttl", "5");
//		m0.put(" tos", "!5");
		m0.put(" tos", "5");
		m0.put(" id", "5");
//		m0.put(" fragbits", "+MR");//every
		m0.put(" fragbits", "MDR*");//any one
//		m0.put(" fragbits", "*MDR");
//		m0.put(" fragbits", "!MDR");
		m0.put(" ip_proto", "5");
//		m0.put(" ack", "5");
//		m0.put(" dsize", "3<>4");
//		m0.put(" dsize", "<5");
		m0.put(" dsize", ">5");
		m0.put(" seq", "5");
//		m0.put(" window", "!5");
//		m0.put(" window", "5");
//		m0.put(" flags", "*CEUAPRSF");
//		m0.put(" flags", "!CEUAPRSF");
//		m0.put(" flags", "+CEUAPRSF");
//		m0.put(" flags", "*12UAPRSF");
		m0.put(" flags", "*12");
//		m0.put(" flags", "+12UAPRSF");
		ro.headMap = m0;

		 //content:"|30 45 00|"; depth:6; content:"G"; within:8; distance:8;
		
		Map<String,String> m = new HashMap<String,String>();
//		m.put(" content","\"3|55|H|33cc|j|85|\"");
//		m.put(" depth", "12");
		m.put(" content", "\"ag|00 00 00 01|\"");
		m.put(" depth", "12");
		m.put(" offset", "0");
		
		
	
		ro.conMap.add(m);
		Map<String,String> m1 = new HashMap<String,String>();
//		m1.put(" content", "\"E\"");
//		m1.put(" offset", "12");
		m1.put(" content", "\"|70|luto|04 70|\"");
		m1.put(" within", "14");
		m1.put(" distance", "14");
		ro.conMap.add(m1);
		//如果还要测headMap，就在ph和ro.headMap上赋值即可。
		DealOption dp = new DealOption(ph);
		dp.Detect(ro, payload);
		
	}
	

 
	
	

}
