import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import snort.test.Helpers.RuleOption;
import snort.test.Helpers.Rule_Header;

public class test {
	//for test rule filter
	public static void main(String args[]) {
		int h = 0x88;
		System.out.println(h);
	
//		try {
//			byte[] payload = {(byte) 128,(byte)128, (byte)128, (byte)128};	
//			String oris;		
//			oris = new String(payload,"utf-8");
//				
//			String orib = BytetoHexString(payload,payload.length);
//			System.out.println(oris);
//			System.out.println(oris.length());
//			System.out.println(orib);
//			System.out.println(orib.length());
//		} catch (UnsupportedEncodingException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
		
		ArrayList<Integer> a = new ArrayList<Integer>();
		a.add(1);
		a.add(2);
		a.add(3);
		a.add(4);
		a.add(6);
		a.add(7);
		
		for(int i =0; i<a.size(); i++){
			if(a.get(i) % 2 ==0)
				a.remove(i);
		}
		
		for(int i =0; i<a.size(); i++){
			System.out.println(a.get(i));
		}
	}
	
	 public static String BytetoHexString (byte[] a,int length)//将byte数组转化为16进制字符串
		{
			String cer="";
			for(int i=0;i<length;i++)
			{
				String hex=Integer.toHexString(a[i] & 0xFF);
				if(hex.length()==1){
        		hex ='0'+hex;
        	}
					cer=cer+hex;

			}
			return cer;
		}
	

}
/*|0| : 2  "" 0
 *A|0|: 2  A 0
 *A|0|A: 3 A 0 A 
 *|0|A :3 "" 0 A
 *A   :1   A
 *
 *总结：一定是 str+byte+str
 *     
 * */
 