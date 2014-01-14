package com.github.sophiedankel.permeate.rules;

import java.util.ArrayList;

public class APICall {
	private String key; // hash key is the path of API call with . delimiters
	private String method; 
	private String parameters;
	private String notes;
	private ArrayList<PermissionRecord> permissions;
	private String parseKey(String keyStr) {
		String result = "";
		int endIndex = keyStr.indexOf('(');
		int beginIndex = keyStr.lastIndexOf('.', endIndex);
		result = keyStr.substring(0, beginIndex);
		return result;
	}
	private String parseMethod(String methodStr) {
		String result = "";
		int endIndex = methodStr.indexOf('(');
		int beginIndex = methodStr.lastIndexOf('.', endIndex) + 1;
		result = methodStr.substring(beginIndex, endIndex);
		return result;
	}
	private String parseParams(String paramStr) {
		String result = "";
		int beginIndex = paramStr.indexOf('(') + 1;
		int endIndex = paramStr.indexOf(')');
		result = paramStr.substring(beginIndex, endIndex);
		return result;
	}
	private ArrayList<PermissionRecord> parsePermissions(String permStr) {			
		ArrayList<PermissionRecord> permList = new ArrayList<PermissionRecord>();
		permStr = permStr.toUpperCase();
		String name = "";
		int nameIndex = -1;
		if (!permStr.isEmpty()) {
			PermissionRecord record;
			String[] splitArray = permStr.split(" ");
			boolean isRequired = !permStr.contains(" OR ");
			for (int i=0; i<splitArray.length; i++) {
				if (splitArray[i].equals("OR") || splitArray[i].equals("AND"))
					continue;
				else {
					nameIndex = splitArray[i].lastIndexOf('.');
					if (nameIndex >= 0)
						name = splitArray[i].substring(nameIndex);
					record = new PermissionRecord(name, isRequired);
					permList.add(record);
				}
			}
		}
		return permList;
	}
	public APICall(String line) {
		String[] splitLine = line.split("\t");
		this.key = parseKey(splitLine[0]);
		this.method = parseMethod(splitLine[0]);
		this.parameters = parseParams(splitLine[0]);
		this.permissions = parsePermissions(splitLine[1]);
		this.notes = (splitLine.length > 2) ? splitLine[2] : "";
	}
	public String toString() {
		return String.format("%40s\t%s\t%s", this.method, this.key, this.notes);
	}	
	public String getKey() {
		return this.key;
	}
	public String getMethod() {
		return this.method;
	}
	public String getParams() {
		return this.parameters;
	}
	public ArrayList<PermissionRecord> getPermissions() {
		return this.permissions;
	}
	public String getNotes() {
		return this.notes;
	}
}