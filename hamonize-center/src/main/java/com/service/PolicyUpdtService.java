package com.service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.mapper.IOrgMapper;
import com.mapper.IPolicyProgramMapper;
import com.mapper.IPolicyUpdtMapper;
import com.model.PolicyProgrmVo;
import com.model.PolicyUpdtVo;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class PolicyUpdtService {

	@Autowired
	RestApiService restApiService;

	@Autowired
	PolicyProgramService policyProgramService;

	@Autowired
	IPolicyUpdtMapper iUpdtMapper;

	@Autowired
	IPolicyProgramMapper iPolicyProgramMapper;
	
	@Autowired
	IOrgMapper orgmapper;

	private Logger logger = LoggerFactory.getLogger(this.getClass());
	
	public List<PolicyUpdtVo> updtList(PolicyUpdtVo vo) {
		
		List<PolicyUpdtVo> list = iUpdtMapper.updtList(vo);
		
		return list;
		
	}

	public int getUpdtHistoryLastJob(PolicyUpdtVo vo) {
		return iUpdtMapper.getUpdtHistoryLastJob(vo);
	}
	
	public int updtSave(Map<String, Object> params) {
		return iUpdtMapper.updtSave(params);
		
	}
	public int updatePolicyProgrm(Map<String, Object> params) throws ParseException {
		
		int policyDelRet = 0;
		String former_ppm_name = iPolicyProgramMapper.getProgramApplc(params);
		policyDelRet = iUpdtMapper.updatePolicyProgrm(params);
		String ppm_name = iPolicyProgramMapper.getProgramApplc(params);
		System.out.println("former_ppm_name=========="+former_ppm_name);
		System.out.println("ppm_name=========="+ppm_name);
		// if(ppm_name == null){
		// 	ppm_name = "";
		// }else if(former_ppm_name == null){
		// 	former_ppm_name = "";
		// }
		params.put("ppm_name", ppm_name);
		params.put("former_ppm_name", former_ppm_name);
		// try {
		// 	policyProgramService.applyProgramPolicy(params);
		// } catch (InterruptedException e) {
		// 	// TODO Auto-generated catch block
		// 	e.printStackTrace();
		// }
		return policyDelRet;
		
	}
	public int updtDelete(Map<String, Object> params) {
		return iUpdtMapper.updtDelete(params);
		
	}
	
	public PolicyUpdtVo updtApplcView(PolicyUpdtVo vo){
		return iUpdtMapper.updtApplcView(vo);
		
	}
	public int updtCompareSave(Map<String, Object> params) {
		return iUpdtMapper.updtCompareSave(params);
	}
	public int updtCompareUpdate(Map<String, Object> params) {
		return iUpdtMapper.updtCompareUpdate(params);
	}

	// public List<Map<String, Object>> updtResult(Map<String, Object> params) throws ParseException{
	// 	System.out.println("params==============="+params.toString());
	// 	JSONParser qq = new JSONParser();
	// 	int insCount = 0;
	// 	int delCount = 0;
	// 	JSONObject aa = (JSONObject) qq.parse(params.get("packageList").toString());
	// 	if(aa.get("INS").toString() != ""){
	// 	insCount = aa.get("INS").toString().split(",").length;
	// 	}
	// 	if(aa.get("DEL").toString() != ""){
	// 	delCount = aa.get("DEL").toString().split(",").length;
	// 	}
	// 	return iUpdtMapper.updtResult(params);
	// }

	public JSONObject applyPackagePolicy(Map<String, Object> params) throws ParseException, InterruptedException{
		//Long segSeq = Long.parseLong(params.get("org_seq").toString());
		String[] listA = {};
		String[] listB = {};
		if(params.get("ppm_name").toString() != "")
		listA = params.get("ppm_name").toString().split(",");
		if(params.get("former_ppm_name").toString() != "")
		listB = params.get("former_ppm_name").toString().split(",");

		ArrayList<String> ppm_name = new ArrayList<String>(Arrays.asList(listA));
		ArrayList<String> former_ppm_name = new ArrayList<String>(Arrays.asList(listB));
		//former_ppm_name 차집합 ppm_name
		former_ppm_name.removeAll(ppm_name);
		
		//String output = "{\\\"INS\\\":\\\""+String.join(",",ppm_name)+"\\\",\\\"DEL\\\":\\\""+String.join(",",former_ppm_name)+"\\\"}";
		String output = "";
		JSONObject updtPolicy = new JSONObject();
		
		if(!ppm_name.isEmpty())
		{
			updtPolicy.put("INS", String.join(",",ppm_name));
		}
		if(!former_ppm_name.isEmpty())
		{
			updtPolicy.put("DEL", String.join(",",former_ppm_name));
		}
		output = updtPolicy.toJSONString();
		output = output.replaceAll("\"", "\\\\\\\"");
		System.out.println("output======"+output);
		params.put("output", output);
		params.put("policyFilePath","/etc/hamonize/updt/updtInfo.hm");
		params.put("policyRunFilePath","/etc/hamonize/runupdt");
		params.put("before_url","umanage");

		JSONObject result = restApiService.makePolicyToGroup(params);
		System.out.println("ResultID====="+result);
		// updtPolicy.clear();
		// updtPolicy.put("INS", String.join(",",ppm_name));
		// updtPolicy.put("DEL", String.join(",",former_ppm_name));
		// output = updtPolicy.toJSONString();
		// params.put("packageList", output);
		// updtResult(params);
		//System.out.println(updtResult(params));

		return result;

	}

}
