package com.github.sophiedankel.permeate.rules;

import java.util.HashMap;
import java.util.ArrayList;
import java.io.File;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;


public class APICallParse {
	private HashMap<String, ArrayList<APICall>> APICalls;
	private int numberOfCalls;
	private ArrayList<String> methodNames;
	
	// search by path and method
	public APICall getAPICall(String path, String method) 
	{
		//System.out.println("path: " + path + "method: " + method);
		int i=0;
		ArrayList<APICall> calls = APICalls.get(path);
		if (calls == null)
			return null;
		while (calls.get(i).getMethod() != method && i < calls.size()-1)
			i++;
		if (i == calls.size())
			return null;
		return calls.get(i);
	}
	
	
	//////////
	public boolean emptyAPICallList(String path)
	{
		return (APICalls.get(path) == null);
	}
	
	
	public int getNumberOfCalls() 
	{
		return numberOfCalls;
	}
	public ArrayList<String> getMethodNames() 
	{
		return this.methodNames;
	}
	public HashMap<String, ArrayList<APICall>> getAPICalls() 
	{
		return this.APICalls;
	}
	public APICallParse() 
	{
		APICalls = new HashMap<String, ArrayList<APICall>>();
		numberOfCalls = 0;
		methodNames = new ArrayList<String>();
	}
	public APICallParse(String fileName) {
		APICalls = new HashMap<String, ArrayList<APICall>>();
		this.loadAPICallList(fileName);
		this.loadMethodNames();
	}
	private void loadMethodNames() {
		ArrayList<String> methods = new ArrayList<String>();
		ArrayList<String> keySet = new ArrayList<String>(APICalls.keySet());
		ArrayList<APICall> APICallList;
		String method;
		for (int i=0; i<keySet.size(); i++) {
			APICallList = APICalls.get(keySet.get(i));
			for (int j=0; j<APICallList.size(); j++) {
				method = APICallList.get(j).getMethod();
				if (!methods.contains(method))
						methods.add(method);
			}
		}
		this.methodNames = methods;
	}
	private void loadAPICallList(String fileName) {
		numberOfCalls = 0;
		File file = new File(fileName);
		BufferedReader reader = null;
		try {
			reader = new BufferedReader(new FileReader(file));
		    String line = reader.readLine(); // ignore first line of file
		    while ((line = reader.readLine()) != null) {
		    	if (line.indexOf('(') > 0)	{	// this indicates that the line contains a call
		    		APICall apiCall = new APICall(line);
		    		numberOfCalls++;
		    		if (!APICalls.containsKey(apiCall.getKey())) {
		    			ArrayList<APICall> list = new ArrayList<APICall>();
		    			APICalls.put(apiCall.getKey(), list);
		    		}
		    		APICalls.get(apiCall.getKey()).add(apiCall);
		    				    		
		    	}
		    }
		} catch (FileNotFoundException e) {
		    e.printStackTrace();
		} catch (IOException e) {
		    e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
		    try {
		        if (reader != null) {
		            reader.close();
		        }
		    } catch (IOException e) {
		    }
		}
	}
	
	public static void main(String[] args) {
		String fileName = "APICalls.txt";
		APICallParse parser = new APICallParse(fileName);
		HashMap<String, ArrayList<APICall>> APICalls = parser.APICalls;

		ArrayList<String> keySet = new ArrayList<String>(APICalls.keySet());
		
		/**
		ArrayList<APICall> valueList;
		String mostMethodsKey = keySet.get(0);
		for (int i=0; i<keySet.size(); i++) {
			System.out.println("\nPath: " + keySet.get(i));
			valueList = APICalls.get(keySet.get(i));
			if (valueList.size() > APICalls.get(mostMethodsKey).size())
				mostMethodsKey = keySet.get(i);
			for (int j=0; j<valueList.size(); j++)
				System.out.println(j+1 + ": " + valueList.get(j).toString());
		} 
		
		System.out.println();
		System.out.println("Number of API calls: " + parser.getNumberOfCalls()); 
		System.out.println("Number of owners: " + keySet.size());
		//System.out.println("Owner with most methods: " + mostMethodsKey + " with " +
				//APICalls.get(mostMethodsKey).size() + " methods");
		
		
		String m = "getCellLocation", p = "android.telephony.TelephonyManager";
		System.out.println("method: " + m + "\tpath: " + p + "\nperms: " + 
							parser.getPermissions(p, m).toString());
		m = "updateMessageOnIcc";
		p = "android.telephony.SmsManager";
		System.out.println("method: " + m + "\tpath: " + p + "\nperms: " + 
							parser.getPermissions(p, m).toString());
		*/
	
	}
}

