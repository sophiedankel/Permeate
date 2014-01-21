package com.github.sophiedankel.permeate.structures;


public class PermissionRecord 
{
	private static final String PERMISSION_PATH = "android.permission";
	private String name;
	private Boolean isRequired;
	public PermissionRecord(String permName, Boolean required) 
	{
		name = PERMISSION_PATH + permName;
		isRequired = required;
	}
	public PermissionRecord() 
	{
		name = PERMISSION_PATH;
		isRequired = true;
	}
	public String toString()
	{
		String result = name + "\t";
		if (isRequired)
			result += "REQUIRED";
		else
			result += "OPTIONAL";
		return result;
	}
	public String getName() 
	{
		return name;
	}
	public void setName(String permName) {
		name += permName;
	}
	public Boolean isRequired() {
		return isRequired;
	}
	public void setIsRequired(boolean required) {
		isRequired = required;
	}
}
