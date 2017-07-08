package snort.test.Helpers;

import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Packet_Header {
	public int version=-1;//4 or 6
	public String protocol="";
	public String sip="";
	public int sip_val = -1;
	public int sport=-1;
	public String dip="";
	public int dip_val = -1;
	public int dport=-1;
	
	public byte[] payload;//抓取到的应用层数据包
	public int dsize;//payload（应用层）的长度
	//规则选项属性
	public int DF;
	public int MF;
	public int Reserved;
	public int ip_proto;//ip protocol的类型，可以是number或者string（2或者IGMP）
	
	//ip options
	public boolean sameip = false; //check if source ip is the same as destination ip
	public int fragoffset = -1;//ip fragment offset field
	public int ttl = -1;//ip time to live value
	public int tos = -1;
	public int id = -1;
	//public String ipopts = null;//check if a specific IP option is present
	//tcp options
	public int flags = -1;//check if TCP flag bits are present
	public long seq = -1;
	public long ack = -1;
	public int window = -1;//check for a specific TCP window size
		
	public int fraLen=14;//以太网帧长，单位字节
	public int ipLen=-1;//ip报头长度，单位为字节
	public int tcpLen=20;//tcp报头长度,单位为字节
	public int udpLen=8;	
	public FileWriter fw;
	
	public Packet_Header(){}
	
	public int BytetoInt (byte[] a,int length)
	{
		
		int cer=0;
		for(int i=0;i<length;i++)
		{
			cer=cer*16*16;
			cer=cer+(a[i]&0xff);
		}
		return cer;
	}
	
	public String IPv4BytetoString (byte[] a,int length)
	{
		String cer="";
		for(int i=0;i<length;i++)
		{
			String hex=Integer.toString(a[i]&0xFF);
			if(i!=length-1){
        		hex =hex+".";
        	}
			
				cer=cer+hex;
			
		}
		return cer;
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
	
	public String BytetoString (byte[] a,int length)
	{
		String cer="";
		for(int i=0;i<length;i++)
		{
			String hex=Integer.toBinaryString(a[i]&0xFF);
			if(hex.length()==1){
        		hex ='0'+hex;
        	}
			
				cer=cer+hex;
			
		}
		return cer;
	}
	
	public String BytetoHexString (byte[] a,int length)
	{
		String cer="";
		for(int i=0;i<length;i++)
		{
			String hex=Integer.toHexString(a[i]&0xFF);
			if(hex.length()==1){
        		hex ='0'+hex;
        	}
			
				cer=cer+hex;
			
		}
		return cer;
	}
}
