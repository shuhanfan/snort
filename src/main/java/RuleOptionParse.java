import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import snort.test.Helpers.*;
import snort.test.Bolts.*;
import snort.test.Bolts.Rule_Bolt;
/*
 * read rules from file and parse rules into the Rule_Header format
 */
public class RuleOptionParse {
	public static void main(String args[]) {
		
		try{
			FileInputStream fis = new FileInputStream("//Users//jessief//upload//community_rules");
			FileWriter fw = new FileWriter("//Users//jessief//upload//parsed_rules");
			ArrayList<Rule_Header> rhset = new ArrayList<Rule_Header>(500);
			int count = 0;
			String str = null;
			InputStreamReader isr = new InputStreamReader(fis);
			BufferedReader br = new BufferedReader(isr);
			//parse rule header and classify rules by the same header
			while ((str = br.readLine()) != null){
				count++;
				System.out.println("count:"+count);
				String aaa="\\(";
				String rule_header=null;
				String rule_option=null;
				Pattern pattern_web = Pattern.compile(aaa);	
				Matcher matcher_web = pattern_web.matcher(str);
				if (matcher_web.find()) {
					System.out.println("matcher_web.find()");
					rule_header = str.substring(0, matcher_web.start());
					///***///
					System.out.println("rule_header:"+rule_header);
					rule_option = str.substring(matcher_web.start()+1,str.length()-1);
					///***///
					System.out.println("rule_option:"+rule_option);
					
					String tmp[]=rule_header.split(" ");
					Rule_Header tmp_header = new Rule_Header(tmp,rule_option);
					int hea_i = 0;
					int rhset_size = rhset.size();
					for(hea_i = 0; hea_i < rhset_size; hea_i++){
						if(rhset.get(hea_i).equal(tmp_header)==true){
							rhset.get(hea_i).rule_option.add(rule_option);
							break;
						}
					}
					if(hea_i==rhset_size){
						rhset.add(tmp_header);
						
					}
				}
			}
			
			//parse rule option and print it
			for(int i= 0; i< rhset.size(); i++) {
				Rule_Header rh= rhset.get(i);
				rh.parsed_rule_option = Rule_Bolt.parseRuleOption(rh.rule_option);
				ArrayList<RuleOption> ro_list = rh.parsed_rule_option;
				System.out.println("\n");
				System.out.println(rh.action +" "+rh.protocol+" "+ rh.sip+" " + rh.sport+" " + rh.dip +" "+ rh.dport);
				for(int j =0; j<ro_list.size(); j++){
					RuleOption ro= ro_list.get(j);
					 for (String key : ro.headMap.keySet()) {
						   fw.write(key + ":" + ro.headMap.get(key) + ";");
					}
					 fw.write("\n");
					 for ( int n = 0 ; n <ro.conMap.size(); n++){
						 Map<String, String> map = ro.conMap.get(n);
						 for (String key : map.keySet()) {
							   fw.write(key + ":" + map.get(key) + ";");
						}
						 fw.write("\n");
						 
					 }
					
					
				}
			}
		}catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}
	


	
	

}
