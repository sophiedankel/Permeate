package com.github.sophiedankel.permeate.rules;

import static com.android.SdkConstants.ANDROID_MANIFEST_XML;
import static com.android.SdkConstants.ANDROID_URI;
import static com.android.SdkConstants.ATTR_NAME;
import static com.android.SdkConstants.ATTR_PERMISSION;
import static com.android.SdkConstants.TAG_ACTIVITY;
import static com.android.SdkConstants.TAG_PERMISSION;
import static com.android.SdkConstants.TAG_PROVIDER;
import static com.android.SdkConstants.TAG_RECEIVER;
import static com.android.SdkConstants.TAG_SERVICE;
import static com.android.SdkConstants.TAG_USES_PERMISSION;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;

import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;

import com.android.annotations.NonNull;
import com.android.annotations.Nullable;
import com.android.tools.lint.detector.api.Category;
import com.android.tools.lint.detector.api.ClassContext;
import com.android.tools.lint.detector.api.Context;
import com.android.tools.lint.detector.api.Detector;
import com.android.tools.lint.detector.api.Implementation;
import com.android.tools.lint.detector.api.Issue;
import com.android.tools.lint.detector.api.Scope;
import com.android.tools.lint.detector.api.Severity;
import com.android.tools.lint.detector.api.Speed;
import com.android.tools.lint.detector.api.XmlContext;
import com.github.sophiedankel.permeate.structures.APICall;
import com.github.sophiedankel.permeate.structures.APICallParse;
import com.github.sophiedankel.permeate.structures.PermissionRecord;

public class PermeateDetector extends Detector implements Detector.XmlScanner, Detector.ClassScanner {
	
	/** List of issues: Declared permissions detector */
	public static final Issue DECLARED_ISSUE = Issue.create(
            "FindsDeclaredPermissions", //$NON-NLS-1$
            "Finds all declared permissions",
            "Looks for all user-defined and system-defined permission declarations in " +
            "AndroidManifest.xml file.",
            
            "Identifying all declared permissions is the first step to detecting which " +
            "declared permissions are unnecessary.",
            
            Category.SECURITY,
            2,
            Severity.WARNING,
            new Implementation(
            		PermeateDetector.class,
                    EnumSet.of(Scope.MANIFEST)));
	
	
	/** Enforced permissions detector */
	public static final Issue ENFORCED_ISSUE = Issue.create(
            "FindsEnforcedPermissions", //$NON-NLS-1$
            "Finds all permissions enforcements",
            "Looks for all android:permission attributes within activity, service, BroadcastReceiver " +
            " and ContentProvider elements in the AndroidManifest.xml file.",
            
            "Identifying activities, services, broadcasts and providers that enforce permissions will " +
            "help to track where permissions are being used and whether or not they are necessary.",
            
            Category.SECURITY,
            2,
            Severity.WARNING,
            new Implementation(
            		PermeateDetector.class,
                    EnumSet.of(Scope.MANIFEST)));
	

	/** Used permissions detector */
	public static final Issue USED_ISSUE = Issue.create(
			"FindsUsedPermissions", //$NON-NLS-1$
	        "Finds all permission usage",
	        "Looks for <uses-permission> attributes in AndroidManifest.xml file.",
	            
	        "Identifying the app's requested permission usage will help in determining which " +
	        "included permissions are unnecessary.",
	           
	        Category.SECURITY,
	        2,
	        Severity.WARNING,
	        new Implementation(
	        	PermeateDetector.class,
	        	EnumSet.of(Scope.MANIFEST)));
	
	
	public static final Issue PERMISSION_REFERENCE_ISSUE = Issue.create(
			"FindsXMLPermissionReferences", //$NON-NLS-1$
	        "Finds all references to permissions in AndroidManifest.xml",
	        "Looks in AndroidManifest.xml file for the following attributes: <uses-permission>; " + 
	        		"user-defined or system-defined permission declarations; android:permission attributes " +
	        		"within activity, service, BroadcastReceiver and ContentProvider elements.",
	            
	        "Identifying the all references to permissions delcared app's manifest will help in determining which " +
	        "of the included permissions are unnecessary.",
	           
	        Category.SECURITY,
	        2,
	        Severity.WARNING,
	        new Implementation(
	        	PermeateDetector.class,
	        	EnumSet.of(Scope.MANIFEST)));
	
	
	/** Permission-required API call detector */
	public static final Issue API_CALL_ISSUE = Issue.create(
            "PermissionRequiredAPICalls", //$NON-NLS-1$
            "API calls requiring any permission",
            "Finds instances of permission-required API calls in class file",

            "This detector finds all API calls which require permission declaration and puts together a list "
            + "of the permissions necessary for the app to run.",

            Category.SECURITY,
            2,
            Severity.WARNING,
            new Implementation(
            		PermeateDetector.class,
                    Scope.CLASS_FILE_SCOPE));
	
	public static final Issue OVER_PRIVILEGE_ISSUE = Issue.create(
            "FindsOverPrivilegedApps", //$NON-NLS-1$
            "Determines if the app is over-privileged",
            "Compares permissions found in AndroidManifest.xml with permissions used " +
            "and reports when XML permissions are unnecessarily specified.",
            
            "This issue is detected after the project is checked, when the permission comparisons " +
            		"are made. This is part of the results reporting mechanism for Permeate.",
            
            Category.SECURITY,
            3,
            Severity.WARNING,
            new Implementation(
            		PermeateDetector.class,
            		EnumSet.of(Scope.MANIFEST)));
	
	public static final Issue UNDER_PRIVILEGE_ISSUE = Issue.create(
            "FindsUnderPrivilegedApps", //$NON-NLS-1$
            "Determines if the app is under-privileged",
            "Compares permissions found in AndroidManifest.xml with permissions used " +
            "and reports when XML permissions are missing.",
            
            "This issue is detected after the project is checked, when the permission comparisons " +
            		"are made. This is part of the results reporting mechanism for Permeate.",
            
            Category.SECURITY,
            3,
            Severity.WARNING,
            new Implementation(
            		PermeateDetector.class,
            		EnumSet.of(Scope.MANIFEST)));
	
	
	private String fileName = "APICalls.txt";
	private APICallParse parser = new APICallParse(fileName);
	private ArrayList<PermissionRecord> allPermissionsList;
	private ArrayList<String> xmlPermissionsList;
    

    /** Constructs a new {@link PermeateDetector} */
    public PermeateDetector() {
    	allPermissionsList = new ArrayList<PermissionRecord>();
    	xmlPermissionsList = new ArrayList<String>();
    }
   
    @Override
    @Nullable
    public List<String> getApplicableCallNames() {
    	return parser.getMethodNames();
    }
    
    @Override
    public void checkCall(@NonNull ClassContext context, @NonNull ClassNode classNode,
            @NonNull MethodNode method, @NonNull MethodInsnNode call) {
        if (!context.getProject().getReportIssues()) {
            // If this is a library project not being analyzed, ignore it
            return;
        }

        String path = call.owner.replace('/', '.');
        
        // records of permissions for this api call
        ArrayList<PermissionRecord> permissionsList = null;
        APICall apicall = null;

        if (!parser.emptyAPICallList(path)) {

            apicall = parser.getAPICall(path, call.name);
            if (apicall != null) {
            	permissionsList = apicall.getPermissions();
            }
        }
        if (permissionsList != null) {
        	for (int i=0; i< permissionsList.size(); i++)
        	{
        		if (! allPermissionsList.contains(permissionsList.get(i))) {
        			allPermissionsList.add(permissionsList.get(i));
        		}
        	}
        }
        context.report(API_CALL_ISSUE, method, call, context.getLocation(call),
                    "\n\nFound API call:\t" + path + "." + call.name + "\nPermissions:\t" + 
                    permissionsList, null);
            
    }
    
    
    
	/** XML Scanner implementation starts here */
    
	@NonNull
    @Override
    public Speed getSpeed() {
        return Speed.FAST;
    }
	
	@Override
    public boolean appliesTo(@NonNull Context context, @NonNull File file) {
        return file.getName().equals(ANDROID_MANIFEST_XML);
    }
	
	@Override
    public Collection<String> getApplicableElements() {		
		return Arrays.asList(  
				// IF enforced
				TAG_ACTIVITY, 
				TAG_PROVIDER, 
				TAG_RECEIVER, 
				// IF declared
				TAG_SERVICE, 
				// IF used
				TAG_PERMISSION,  
				TAG_USES_PERMISSION
				);
	}
	
	
	
	// for XmlScanner implementation
	@Override
    public void visitElement(@NonNull XmlContext context, @NonNull Element element) {
        Attr permissionNode = element.getAttributeNodeNS(ANDROID_URI, ATTR_PERMISSION);
        Attr nameNode = element.getAttributeNodeNS(ANDROID_URI, ATTR_NAME);
		String message = "", tagName = element.getTagName();
		//Issue myIssue = null;
		// 
		//System.out.print("\nTag name : ");
		//System.out.print(tagName);
		if (tagName == TAG_PERMISSION || tagName == TAG_USES_PERMISSION) {
			if (nameNode != null) {
				String permissionName = nameNode.getValue();
				// add to list
				if (! xmlPermissionsList.contains(permissionName)) {
					xmlPermissionsList.add(permissionName);
				}
				context.report(PERMISSION_REFERENCE_ISSUE, element, context.getLocation(nameNode), message, null);
			}
		}
        else if (tagName == TAG_ACTIVITY || tagName == TAG_PROVIDER || 
    			tagName == TAG_RECEIVER || tagName == TAG_SERVICE) {
        	if (permissionNode != null) {
				String permissionName = permissionNode.getValue();
				// add to list
				if (! xmlPermissionsList.contains(permissionName)) {
					xmlPermissionsList.add(permissionName);
				}
				context.report(PERMISSION_REFERENCE_ISSUE, element, context.getLocation(permissionNode), message, null);
			}
        }
        	
        	
        	/**
        	if (tagName == TAG_SERVICE) { // declared
        		myIssue = DECLARED_ISSUE;
        		message = "ISSUE: Permission declaration detected in XML file, name: " + permissionName;

        	}
        	else if (tagName == TAG_PERMISSION || tagName == TAG_USES_PERMISSION) { // used
        		myIssue = USED_ISSUE;
        		message = "ISSUE: Permission usage detected in XML file, name: " + permissionName;

        	}
        	else if (tagName == TAG_ACTIVITY || tagName == TAG_PROVIDER || 
        			tagName == TAG_RECEIVER || tagName == TAG_SERVICE) {	// enforced        			
        		myIssue = ENFORCED_ISSUE;
        		// some activity tags not going into this if statement
        		if (permissionNode != null) {
        			message = "ISSUE: The " + tagName + " implemented by the class " + nameNode.getValue() +
        					" requires permission " + permissionNode.getValue() + " to execute";
        		}
        	}
        	
        	
        	if (myIssue == null) {
        		message = "No applicable issue.";
        		System.out.println(message);
        	}
        	
        	
        	context.report(PERMISSION_REFERENCE_ISSUE, element, context.getLocation(nameNode), message, null);
            **/
       
    }
	
	 @Override
	    public void afterCheckProject(@NonNull Context context) {
		 Issue myIssue = null;
		 String message = "\n";
		 // comparison stuff
		 if (allPermissionsList.size() == xmlPermissionsList.size()) {
			 message += "Everything is OK: permissions match up.";
		 }
		 else if (allPermissionsList.size() > xmlPermissionsList.size()) {
			 message += "permissions missing from XML file: program can't run";
			 myIssue = UNDER_PRIVILEGE_ISSUE;
		 }
		 else {
			 message += "unused permissions in xml file - over-privilege";
			 myIssue = OVER_PRIVILEGE_ISSUE;
		 }
		 
		 if (myIssue == null)
			 System.out.println(message);
		 else
			 context.report(myIssue, null, message, null);
         
         System.out.println("API CALL permissions");
         for (int i=0; i< allPermissionsList.size(); i++) {
        	 System.out.println(i + ": " + allPermissionsList.get(i).toString());
         }
         
         System.out.println("XML permissions");
         for (int i=0; i< xmlPermissionsList.size(); i++) {
        	 System.out.println(i + ": " + xmlPermissionsList.get(i));
         }

				 
		//permission record allPermissionsList 
	     //string xmlPermissionsList
	 }

}
