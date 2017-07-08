package snort.test.Bolts;

import java.util.ArrayList;
import java.util.Map;

import backtype.storm.task.OutputCollector;
import backtype.storm.task.TopologyContext;
import backtype.storm.topology.BasicOutputCollector;
import backtype.storm.topology.FailedException;
import backtype.storm.topology.IBasicBolt;
import backtype.storm.topology.OutputFieldsDeclarer;
import backtype.storm.tuple.Fields;
import backtype.storm.tuple.Tuple;
import backtype.storm.tuple.Values;

import java.io.*; 

import snort.test.Helpers.Packet_Header;
import snort.test.Helpers.Rule_Header;



public class Result_Bolt implements IBasicBolt{

	private BasicOutputCollector outputCollector;
	public FileOutputStream out;
	public FileWriter fw ;
	private String name_bolt;
	private int rpack1, rpack2, rpack3, ppack1, ppack2, ppack3, detect1, detect2, detect3;
	private long rflow1, rflow2,rflow3, pflow1, pflow2, pflow3;
	private long lastTime;
	private long curTime;
	private long rtime1;
	private long ptime1;
	
	public Result_Bolt(){}
	public Result_Bolt(String nm){
		name_bolt =nm;
	}
	public void declareOutputFields(OutputFieldsDeclarer declarer) {
		// TODO Auto-generated method stub
		declarer.declare(new Fields("timestamp","throughput","countPacket"));
	}

	public Map<String, Object> getComponentConfiguration() {
		// TODO Auto-generated method stub
		return null;
	}

	public void prepare(Map stormConf, TopologyContext context) {
		//////////////
		try {
			fw = new FileWriter("//opt//res4Snort//Result");
			lastTime = System.currentTimeMillis()/1000;
			rpack1 = ppack1 = detect1 =0;
			rflow1 = pflow1 = 0;
			rtime1 = ptime1 = 0;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	
	}

	public void execute(Tuple tuple, BasicOutputCollector collector) {
		// TODO Auto-generated method stub
		outputCollector = collector;
		outputCollector.setContext(tuple);  
		String name=tuple.getSourceComponent();  
		try {
			if(name.equals("RuleBolt1")){
				rpack1 = (Integer)tuple.getValueByField("packnum");
				rflow1 = (Long)tuple.getValueByField("flow")*8;//转化成bit
				rtime1 = (Long)tuple.getValueByField("time");
			}
			else if(name.equals("PayloadBolt1")){
				ppack1 = (Integer)tuple.getValueByField("packnum");
				detect1 = (Integer)tuple.getValueByField("detect");
				pflow1 = (Long)tuple.getValueByField("flow")*8;//转化成bit
				ptime1 = (Long)tuple.getValueByField("time");
			}
			
			long total_flow = (rflow1+ pflow1);
			//Result 1s接收一次，实时输出
			fw.write("ruleBolt:"+ rpack1+"/"+ rflow1+"/"+rtime1+"s"+" ;PayloadBolt:"+detect1+"/"+ ppack1+"/"+ pflow1+"/"+ptime1+"s"+";total:"+detect1+"/"+(rpack1+ppack1)+"/"+total_flow+"pps\n");
	    	fw.flush();		
		} catch(FailedException e) {
	    	System.out.println("Bolt fail to deal with packet");
	    } catch(IOException e){
	    	
	    	e.printStackTrace();
	    }
	}

	public void cleanup() {
		// TODO Auto-generated method stub
		
	}

}
