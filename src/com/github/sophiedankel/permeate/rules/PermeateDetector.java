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
	
	/** List of issues */
	
	public static final Issue PERMEATE_DETECTOR_ISSUE = Issue.create(
            "CorrectPermissions", //$NON-NLS-1$
            "Determines if the app contains the proper permissions",
            "Compares permissions found in AndroidManifest.xml with permissions used " +
            "and reports when XML permissions are inconsistent.",
            
            "This issue is detected after the project is checked, when the permission comparisons " +
            		"are made. This invokes all of the checks and reporting mechanisms for Permeate.",
            
            Category.SECURITY,
            5,
            Severity.INFORMATIONAL,
            new Implementation(
            		PermeateDetector.class,
            		EnumSet.of(Scope.MANIFEST, Scope.CLASS_FILE)));
	
	
	private String fileName = "APICalls.txt";
	private APICallParse parser = new APICallParse(fileName);
	private ArrayList<PermissionRecord> allPermissionsList;
	private ArrayList<String> xmlPermissionsList;
    

    /** Constructs a new {@link PermeateDetector} and initializes lists*/
    public PermeateDetector() {
    	allPermissionsList = new ArrayList<PermissionRecord>();
    	xmlPermissionsList = new ArrayList<String>();
    }
   
    @Override
    @Nullable
    public List<String> getApplicableCallNames() {
    	return parser.getMethodNames();
    }
    
    /** Checks class files for API calls that require permissions. */
    @Override
    public void checkCall(@NonNull ClassContext context, @NonNull ClassNode classNode,
            @NonNull MethodNode method, @NonNull MethodInsnNode call) {
        if (!context.getProject().getReportIssues()) {
            // If this is a library project not being analyzed, ignore it
            return;
        }
       
        String path = call.owner.replace('/', '.');
        
        // records of permissions for this api call
        ArrayList<PermissionRecord> permissionsToAdd = null;
        APICall apicall = null;

        if (!parser.emptyAPICallList(path)) {

            apicall = parser.getAPICall(path, call.name);
            if (apicall != null) {
            	permissionsToAdd = apicall.getPermissions();
            }
        }
        if (permissionsToAdd != null) {
        	for (int i=0; i< permissionsToAdd.size(); i++)
        	{
        		boolean contains = false;
        		String name = permissionsToAdd.get(i).getName();
        		//System.out.println("Comparing " + name + " to list of size " + allPermissionsList.size());
        		for (int j=0; j< allPermissionsList.size(); j++) {
        			//System.out.println("Is equal to: " + allPermissionsList.get(j).getName());
        			if (allPermissionsList.get(j).getName().equals(permissionsToAdd.get(i).getName())) {
        				contains = true;
        			}
        		}
        		if (!contains) {
        			allPermissionsList.add(permissionsToAdd.get(i));
        		}
        	}
        }   
        
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
				TAG_SERVICE, 
				// IF declared
				TAG_PERMISSION,  
				// IF used
				TAG_USES_PERMISSION
				);
	}
	
	
	
    /** Checks AndroidManifest.xml for permission references (use, declaration, or enforcement). */
	@Override
    public void visitElement(@NonNull XmlContext context, @NonNull Element element) {
        Attr permissionNode = element.getAttributeNodeNS(ANDROID_URI, ATTR_PERMISSION);
        Attr nameNode = element.getAttributeNodeNS(ANDROID_URI, ATTR_NAME);
		String tagName = element.getTagName();
		
		if (tagName == TAG_PERMISSION || tagName == TAG_USES_PERMISSION) {
			if (nameNode != null) {
				String permissionName = nameNode.getValue();
				// add to list
				if (! xmlPermissionsList.contains(permissionName)) {
					xmlPermissionsList.add(permissionName);
				}
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
			}
        }            
    }
	
    /** Determines if permissions are correct and reports back to user. */
	 @Override
	    public void afterCheckProject(@NonNull Context context) {
		 String message = "\n";		 
		 
		 System.out.println("CLASS PERMISSIONS");
		 for (int i=0; i< allPermissionsList.size(); i++) {
			 System.out.println(allPermissionsList.get(i));
		 }
		 System.out.println("XML PERMISSIONS");
		 for (int i=0; i< xmlPermissionsList.size(); i++) {
			 System.out.println(xmlPermissionsList.get(i));
		 }
		 
		 // string list of all permissions found in bytecode
		 ArrayList<String> classPermissionsList = new ArrayList<String>();
		 for (int i=0; i<allPermissionsList.size(); i++) {
			 classPermissionsList.add(allPermissionsList.get(i).getName());
		 }
		 
		 // comparison
		 if (classPermissionsList.equals(xmlPermissionsList)) {
			 message += "Everything is OK: permissions match up";
		 }
		 else if (classPermissionsList.size() < xmlPermissionsList.size()) {
			 message += "Unused permissions in XML file - over-privilege";
			 xmlPermissionsList.removeAll(classPermissionsList);
			 for (int i=0; i<xmlPermissionsList.size(); i++) {
				 System.out.println("Unused: " + xmlPermissionsList.get(i));
			 }
		 }
		 else if (classPermissionsList.size() > xmlPermissionsList.size()) {
			 message += "Permissions missing from XML file: program can't run";
			 classPermissionsList.removeAll(xmlPermissionsList);
			 for (int i=0; i<classPermissionsList.size(); i++) {
				 System.out.println("Undeclared: " + classPermissionsList.get(i));
			 }
		 }
		 else { // TODO: handle the case where it is over-declared, under-declared and also not equal number of permissions
			 message += "Both over-declared and under-declared";
		 }
		 System.out.println(message);
		 context.report(PERMEATE_DETECTOR_ISSUE, null, message, null);
	 }
}
