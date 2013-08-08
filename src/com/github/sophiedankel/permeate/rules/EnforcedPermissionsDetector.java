package com.github.sophiedankel.permeate.rules;

import static com.android.SdkConstants.ANDROID_MANIFEST_XML;
import static com.android.SdkConstants.ANDROID_URI;
import static com.android.SdkConstants.ATTR_NAME;
import static com.android.SdkConstants.ATTR_PERMISSION;
import static com.android.SdkConstants.TAG_ACTIVITY;
import static com.android.SdkConstants.TAG_PROVIDER;
import static com.android.SdkConstants.TAG_RECEIVER;
import static com.android.SdkConstants.TAG_SERVICE;

import com.android.annotations.NonNull;
import com.android.tools.lint.detector.api.Category;
import com.android.tools.lint.detector.api.Context;
import com.android.tools.lint.detector.api.Detector;
import com.android.tools.lint.detector.api.Implementation;
import com.android.tools.lint.detector.api.Issue;
import com.android.tools.lint.detector.api.Scope;
import com.android.tools.lint.detector.api.Severity;
import com.android.tools.lint.detector.api.Speed;
import com.android.tools.lint.detector.api.XmlContext;

import org.w3c.dom.Attr;
import org.w3c.dom.Element;

import java.io.File;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Collection;

public class EnforcedPermissionsDetector extends Detector implements Detector.XmlScanner {
	/** The issue detected */
	public static final Issue ISSUE = Issue.create(
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
            		EnforcedPermissionsDetector.class,
                    EnumSet.of(Scope.MANIFEST)));
	
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
				TAG_ACTIVITY, 
				TAG_PROVIDER, 
				TAG_RECEIVER, 
				TAG_SERVICE
		);
    }
	
	@Override
    public void visitElement(@NonNull XmlContext context, @NonNull Element element) {
        Attr permissionNode = element.getAttributeNodeNS(ANDROID_URI, ATTR_PERMISSION);
        Attr nameNode = element.getAttributeNodeNS(ANDROID_URI, ATTR_NAME);
        if (permissionNode != null) {
            String tagName = element.getTagName();
            context.report(ISSUE, element, context.getLocation(nameNode),
            		"The " + tagName + " implemented by the class " + nameNode.getValue() +
            		" requires permission " + permissionNode.getValue() + " to execute", null);
        }
    }

}
