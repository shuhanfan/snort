package snort.test.Helpers;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

public class RuleOption {
	public Map<String,String> headMap;
	public ArrayList<Map<String,String>> conMap;
	public RuleOption(){
		headMap = new LinkedHashMap<String,String>(20);
		conMap = new ArrayList<Map<String, String> >(10);
	}
}
