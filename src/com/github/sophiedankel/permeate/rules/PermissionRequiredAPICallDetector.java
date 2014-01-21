package com.github.sophiedankel.permeate.rules;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.android.annotations.NonNull;
import com.android.annotations.Nullable;
import com.android.tools.lint.detector.api.Category;
import com.android.tools.lint.detector.api.ClassContext;
import com.android.tools.lint.detector.api.Detector;
import com.android.tools.lint.detector.api.Detector.ClassScanner;
import com.android.tools.lint.detector.api.Implementation;
import com.android.tools.lint.detector.api.Issue;
import com.android.tools.lint.detector.api.Scope;
import com.android.tools.lint.detector.api.Severity;

import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import structures.APICall;
import structures.APICallParse;
import structures.PermissionRecord;


public class PermissionRequiredAPICallDetector extends Detector implements ClassScanner {
	
	public static final Issue ISSUE = Issue.create(
            "PermissionRequiredAPICalls", //$NON-NLS-1$
            "API calls requiring any permission",
            "Finds instances of permission-required API calls in class file",

            "This detector finds all API calls which require permission declaration and puts together a list "
            + "of the permissions necessary for the app to run.",

            Category.SECURITY,
            2,
            Severity.WARNING,
            new Implementation(
            		PermissionRequiredAPICallDetector.class,
                    Scope.CLASS_FILE_SCOPE));
	
	
	private String fileName = "APICalls.txt";
	private APICallParse parser = new APICallParse(fileName);
	private ArrayList<PermissionRecord> allPermissionsList;

    

    /** Constructs a new {@link PermissionRequiredAPICallDetector} */
    public PermissionRequiredAPICallDetector() {
    }
   
    @Override
    @Nullable
    public List<String> getApplicableCallNames() {
        //return parser.getMethodNames();
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
        
        ArrayList<PermissionRecord> permissionsList = null;
        APICall apicall = null;

        if (!parser.emptyAPICallList(path)) {

            apicall = parser.getAPICall(path, call.name);
            if (apicall != null) {
            	permissionsList = apicall.getPermissions();
            }
        }
        if (permissionsList != null) {
        	allPermissionsList.addAll(permissionsList);
            context.report(ISSUE, method, call, context.getLocation(call),
                        "\n\nFound API call:\t" + path + "." + call.name + "\nPermissions:\t" + 
                        permissionsList, null);
            }
        }
    }

