
package snort.test.Spouts;

import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import snort.test.Helpers.CreateValue;
import snort.test.Helpers.Packet_Header;
import snort.test.Helpers.KafkaProperties;
import snort.test.Helpers.Pcap_Reader;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.packet.JRegistry;

import backtype.storm.spout.SpoutOutputCollector;
import backtype.storm.task.TopologyContext;
import backtype.storm.topology.IRichSpout;
import backtype.storm.topology.OutputFieldsDeclarer;
import backtype.storm.tuple.Fields;
import backtype.storm.tuple.Values;

import java.util.Properties;
//
//import kafka.consumer.ConsumerConfig;
//import kafka.consumer.ConsumerIterator;
//import kafka.consumer.KafkaStream;
//import kafka.javaapi.consumer.ConsumerConnector;

public class Volume_Spout implements Serializable,IRichSpout  {

	private SpoutOutputCollector outputCollector;
	PcapIf device;
	Pcap pcap; 
	boolean linux = true;
	int hsize = 0;
	StringBuilder errbuf = new StringBuilder(); // For any error msgs
	private PcapPacket packet = null;  
	private String deviceName = null;	
	private String filter = null;
	private String srcFilename =null ;
	private String dstFilename = null;
	private int sampLen = 64*1024;
	public int countPacket = 0;
	private int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
	private int timeout = 10 ; // 10 seconds in millis
	private long pktlen = 0;//record the transport flow
	private int count = 0;
	
	private long lastTime = -1;
	private long curTime = -1;
	private long duringTime = 0;
	private int packnum = 0;
	private CreateValue cv;
    private String topic=null;
	public String src=null;
	public String dst=null;
	int id;
	long time = 0;
	long slots = 0;
	long throughput = 0;
	
    public Volume_Spout(){};
   
    public Volume_Spout(String deviceName, int count, String filter, String srcFilename, String dstFilename, int sampLen,String topic){
    	this.deviceName = "eth0";
    	this.count = count; 
    	this.filter = filter;
    	this.srcFilename = srcFilename;
    	this.dstFilename = dstFilename;
    	if(sampLen<0)
    		this.sampLen = 64*1024;
    	this.sampLen = sampLen;
    	this.topic=topic;
    }
    
    public Volume_Spout(String deviceName, String count, String filter, String srcFilename, String dstFilename, String sampLen,String topic){
    	this.deviceName = "eth0";
    	this.count = Integer.parseInt(count); //閺堫亙濞囬悽顭掔礉閺冪姵鏅�
    	this.filter = filter;
    	this.srcFilename = srcFilename;
    	this.dstFilename = dstFilename;
    	int slen=0;
    	if(Integer.parseInt(sampLen)<0)
            slen = 64*1024;// Capture all packets, no trucation
    	this.sampLen = slen;
    	this.topic=topic;
    }
    
    PcapIf getDevice(){
    	List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
    	int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
			return null;
		}
		int i = 0,chooseid=8;
		for (PcapIf device : alldevs) {
			//System.out.println(i+"device is "+device.getName()+" and "+device.getName().equals("eth0"));
			String description =(device.getDescription() != null) ? device.getDescription(): "No description available";
			if(device.getName().equals("eth0")||device.getName().equals("em1"))//245或者200的内网卡
				chooseid=i;		
			System.out.printf("#%d: %s [%s]\n", i, device.getName(), description);
			i++;
		}
		System.out.println("the choose is:"+chooseid);
		return alldevs.get(chooseid);
    }
	
	public void open(Map arg0, TopologyContext arg1, SpoutOutputCollector spoutOutputCollector) {
		// TODO Auto-generated method stub
		this.outputCollector = spoutOutputCollector;		
        try { 
        	cv = new CreateValue();
        	//open device
            
        	if(srcFilename!=null){
        		pcap=Pcap.openOffline("/opt/res4Snort/inside.pcap", errbuf);     		
        		if (pcap == null) {
        			System.err.printf("Error while opening srcfile  for capture: "+ errbuf.toString());
        			return;
        		}
			id = JRegistry.mapDLTToId(pcap.datalink());
			 packet=new PcapPacket(JMemory.POINTER);
        	}
        	else
        	{
        		this.sampLen=64*1024;
        		device = getDevice();     		
        		pcap =Pcap.openLive(device.getName(), this.sampLen, this.flags, this.timeout, errbuf);
        		if (pcap == null) {
        			System.err.printf("Error while opening device for capture: "+ errbuf.toString());
        			return;
        		}
			id = JRegistry.mapDLTToId(pcap.datalink());
			packet=new PcapPacket(JMemory.POINTER);
        	}     	
        } catch (Exception e) {
            e.printStackTrace();
        }
	}
	
	public void nextTuple() {
		try{
		    if(pcap.nextEx(packet)==1) {			
		    	cv.anal(packet);		    	
		    	this.outputCollector.emit("volume",new Values(cv.protocol,cv.sip,cv.sport,cv.dip,cv.dport,cv.dsize,cv.ip_proto,cv.DF,cv.MF,cv.Reserved,cv.fragoffset,cv.ttl,cv.tos,cv.id,cv.flags,cv.seq,cv.ack,cv.window,cv.sameip,cv.payload,cv.total_len));
       	   	}    
		} catch(Exception e) {
			System.out.println("in volumeSpout"+" fail to deal with packet:"+e.getMessage());
		}			   
	}
	
	public void declareOutputFields(OutputFieldsDeclarer outputFieldsDeclarer) {
		outputFieldsDeclarer.declareStream("volume",new Fields("protocol","sip","sport","dip","dport","dsize","ip_proto","DF","MF","Reserved","fragoffset","ttl","tos","id","flags","seq","ack","window","sameip","payload","total_len"));
	}

	public Map<String, Object> getComponentConfiguration() {
		// TODO Auto-generated method stub
		return null;
	}
	
	public void ack(Object arg0) {
		// TODO Auto-generated method stub
		
	}

	public void activate() {
		// TODO Auto-generated method stub
		
	}

	public void close() {
		// TODO Auto-generated method stub
		//pcap.close();
	}

	public void deactivate() {
		// TODO Auto-generated method stub
		
	}

	public void fail(Object arg0) {
		// TODO Auto-generated method stub
		
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
