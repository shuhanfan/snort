
package snort.test.Topologies;
import java.util.HashMap;

import snort.test.Spouts.*;
import snort.test.Bolts.*;
import backtype.storm.Config;
import backtype.storm.LocalCluster;
import backtype.storm.StormSubmitter;
import backtype.storm.generated.AlreadyAliveException;
import backtype.storm.generated.InvalidTopologyException;
import backtype.storm.topology.TopologyBuilder;
import backtype.storm.tuple.Fields;
import backtype.storm.utils.Utils;


public class PcapTopo4jnetpcap {
	public static void main(String[] args) {
		TopologyBuilder builder = new TopologyBuilder();
		 Config conf = new Config();
		 if (args == null || args.length == 0) {
			 conf.put("storm.zookeeper.port", 2000);		 
			 builder.setSpout("RuleSpout", new Rule_Spout(), 1);
			 builder.setSpout("VolumeSpout", new Volume_Spout(null,-1,null,null,null,-1,"topic2"), 1);
			 builder.setBolt("RuleBolt1", new Rule_Bolt("RuleBolt1"),1).allGrouping("RuleSpout","rule").shuffleGrouping("VolumeSpout","volume");
			 builder.setBolt("PayloadBolt1", new Payload_Bolt(),1).allGrouping("RuleSpout","rule").allGrouping("RuleBolt1","payload");
			 builder.setBolt("ResultBolt", new Result_Bolt(),1).allGrouping("RuleBolt1","result").allGrouping("PayloadBolt1");
			 conf.setNumWorkers(5);
			 LocalCluster cluster = new LocalCluster();
			 cluster.submitTopology("PcapTopo4jnetpcap", conf, builder.createTopology()); 			
		     Utils.sleep(1000000);
			 cluster.killTopology("PcapTopo4jnetpcap");
			 cluster.shutdown();
		 }
		 else{		 
			 builder.setSpout("RuleSpout", new Rule_Spout(), 1);
			 builder.setSpout("VolumeSpout", new Volume_Spout(null,-1,null,null,null,-1,"topic2"), 1);
			 builder.setBolt("RuleBolt1", new Rule_Bolt("RuleBolt1"),1).allGrouping("RuleSpout","rule").shuffleGrouping("VolumeSpout","volume");
			 builder.setBolt("PayloadBolt1", new Payload_Bolt(),1).allGrouping("RuleSpout","rule").allGrouping("RuleBolt1","payload");
			 builder.setBolt("ResultBolt", new Result_Bolt(),1).allGrouping("RuleBolt1","result").allGrouping("PayloadBolt1");
			 conf.setNumWorkers(5);
        	 try{
        		 StormSubmitter.submitTopology(args[0], conf, builder.createTopology());
        	 }catch (InvalidTopologyException e ){
        		 e.printStackTrace();
        	 } catch (AlreadyAliveException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
        	 
		 }
	   
        
	}
}
