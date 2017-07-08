
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import snort.test.Helpers.CreateValue;
import snort.test.Helpers.Packet_Header;
import snort.test.Helpers.KafkaProperties;

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

public class VolumeSpoutTest {
	public static void main(String args[]) {
		int id;
		PcapPacket packet = null;  
		FileWriter fw;
		try {
			fw = new FileWriter("//Users//jessief//upload//packetParser");
		
		StringBuilder errbuf = new StringBuilder(); // For any error msgs
		Pcap pcap = Pcap.openOffline("//Users//jessief//upload//inside.pcap", errbuf);
	
		if (pcap == null) {
			System.err.printf("Error while opening srcfile  for capture: "+ errbuf.toString());
			return;
		}
		
		id = JRegistry.mapDLTToId(pcap.datalink());
		 packet=new PcapPacket(JMemory.POINTER);
		 
		 if(pcap.nextEx(packet)==1)
			{
				CreateValue cv = new CreateValue();
				cv.anal(packet);
				fw.write("protocol:"+cv.protocol+",sip:"+cv.sip+",sport:"+cv.sport+",dip:"+cv.dip+",dport:"+cv.dport+",dsize:"+cv.dsize+",ip_proto:"+cv.ip_proto+",DF:"+cv.DF+",MF:"+cv.MF+",Reserved:"+cv.Reserved+",cv.fragoffset:"+cv.fragoffset+",cv.ttl:"+cv.ttl+",cv.tos:"+cv.tos+",cv.id:"+cv.id+",cv.flags"+cv.flags+",cv.seq:"+cv.seq+",cv.ack:"+cv.ack+",cv.window:"+cv.window+",cv.sameip:"+cv.sameip+"\n");
			}
				
		}catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	} 
}
