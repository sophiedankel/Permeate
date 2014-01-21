
package com.github.sophiedankel.permeate.rules;

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


import java.util.Arrays;
import java.util.List;

public class BluetoothAPIDetector extends Detector implements ClassScanner {
	
	public static final Issue ISSUE = Issue.create(
            "BluetoothAPICall", //$NON-NLS-1$
            "API call requiring BLUETOOTH permission",
            "Finds instance of bluetooth isEnabled API call in class file",

            "The BluetoothAdapter.isEnabled() is an API call commonly found in apps using bluetooth " +
            "functionality. It requires access to android.permission.BLUETOOTH. This detector looks " +
            "for instances of this particular API call in java bytecode.",

            Category.SECURITY,
            2,
            Severity.WARNING,
            new Implementation(
                    BluetoothAPIDetector.class,
                    Scope.CLASS_FILE_SCOPE));
	
    private static final String BLUETOOTH_OWNER = "android/bluetooth/BluetoothAdapter"; //$NON-NLS-1$
    private static final String ENABLED_METHOD = "isEnabled"; //$NON-NLS-1$
    

    /** Constructs a new {@link BluetoothAPIDetector} */
    public BluetoothAPIDetector() {
    }
    
    @Override
    @Nullable
    public List<String> getApplicableCallNames() {
        return Arrays.asList(ENABLED_METHOD);
    }

    @Override
    public void checkCall(@NonNull ClassContext context, @NonNull ClassNode classNode,
            @NonNull MethodNode method, @NonNull MethodInsnNode call) {
        if (!context.getProject().getReportIssues()) {
            // If this is a library project not being analyzed, ignore it
            return;
        }

        if (call.owner.equals(BLUETOOTH_OWNER)) {
            String name = call.name;
            if (name.equals(ENABLED_METHOD)) {
            	context.report(ISSUE, method, call, context.getLocation(call),
                        "Found an instance of isEnabled() call", null);
            }
        }
    }
}
