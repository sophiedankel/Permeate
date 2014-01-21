package com.github.sophiedankel.permeate.rules;

import static com.android.SdkConstants.ANDROID_URI;

import com.android.annotations.NonNull;
import com.android.tools.lint.detector.api.Category;
import com.android.tools.lint.detector.api.ClassContext;
import com.android.tools.lint.detector.api.Context;
import com.android.tools.lint.detector.api.Detector;
import com.android.tools.lint.detector.api.Detector.ClassScanner;
import com.android.tools.lint.detector.api.Implementation;
import com.android.tools.lint.detector.api.Issue;
import com.android.tools.lint.detector.api.Scope;
import com.android.tools.lint.detector.api.Severity;

import org.w3c.dom.Attr;
import org.w3c.dom.Element;

import java.io.File;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Collection;

public class SystemPermissionReferenceDetector extends Detector implements ClassScanner {
	
	public static final Issue ISSUE = Issue.create(
            "PermissionReferences", //$NON-NLS-1$
            "System permission references",
            "Finds all references to system permissions in class file",

            "Knowing about the references made to permissions will help determine which permissions" +
            " are actually being used and which aren't.",

            Category.SECURITY,
            2,
            Severity.WARNING,
            new Implementation(
                    SystemPermissionReferenceDetector.class,
                    Scope.CLASS_FILE_SCOPE));
	
	// List of permissions have the protection levels signature or systemOrSignature.
    // This list must be sorted alphabetically.
    private static final String[] SYSTEM_PERMISSIONS = new String[] {
        "android.intent.category.MASTER_CLEAR.permission.C2D_MESSAGE",
        "android.permission.ACCESS_CACHE_FILESYSTEM",
        "android.permission.ACCESS_CHECKIN_PROPERTIES",
        "android.permission.ACCESS_MTP",
        "android.permission.ACCESS_SURFACE_FLINGER",
        "android.permission.ACCOUNT_MANAGER",
        "android.permission.ALLOW_ANY_CODEC_FOR_PLAYBACK",
        "android.permission.ASEC_ACCESS",
        "android.permission.ASEC_CREATE",
        "android.permission.ASEC_DESTROY",
        "android.permission.ASEC_MOUNT_UNMOUNT",
        "android.permission.ASEC_RENAME",
        "android.permission.BACKUP",
        "android.permission.BIND_APPWIDGET",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.BIND_INPUT_METHOD",
        "android.permission.BIND_PACKAGE_VERIFIER",
        "android.permission.BIND_REMOTEVIEWS",
        "android.permission.BIND_TEXT_SERVICE",
        "android.permission.BIND_VPN_SERVICE",
        "android.permission.BIND_WALLPAPER",
        "android.permission.BRICK",
        "android.permission.BROADCAST_PACKAGE_REMOVED",
        "android.permission.BROADCAST_SMS",
        "android.permission.BROADCAST_WAP_PUSH",
        "android.permission.CALL_PRIVILEGED",
        "android.permission.CHANGE_BACKGROUND_DATA_SETTING",
        "android.permission.CHANGE_COMPONENT_ENABLED_STATE",
        "android.permission.CLEAR_APP_USER_DATA",
        "android.permission.CONFIRM_FULL_BACKUP",
        "android.permission.CONNECTIVITY_INTERNAL",
        "android.permission.CONTROL_LOCATION_UPDATES",
        "android.permission.COPY_PROTECTED_DATA",
        "android.permission.CRYPT_KEEPER",
        "android.permission.DELETE_CACHE_FILES",
        "android.permission.DELETE_PACKAGES",
        "android.permission.DEVICE_POWER",
        "android.permission.DIAGNOSTIC",
        "android.permission.DUMP",
        "android.permission.FACTORY_TEST",
        "android.permission.FORCE_BACK",
        "android.permission.FORCE_STOP_PACKAGES",
        "android.permission.GLOBAL_SEARCH",
        "android.permission.GLOBAL_SEARCH_CONTROL",
        "android.permission.HARDWARE_TEST",
        "android.permission.INJECT_EVENTS",
        "android.permission.INSTALL_LOCATION_PROVIDER",
        "android.permission.INSTALL_PACKAGES",
        "android.permission.INTERNAL_SYSTEM_WINDOW",
        "android.permission.MANAGE_APP_TOKENS",
        "android.permission.MANAGE_NETWORK_POLICY",
        "android.permission.MANAGE_USB",
        "android.permission.MASTER_CLEAR",
        "android.permission.MODIFY_NETWORK_ACCOUNTING",
        "android.permission.MODIFY_PHONE_STATE",
        "android.permission.MOVE_PACKAGE",
        "android.permission.NET_ADMIN",
        "android.permission.MODIFY_PHONE_STATE",
        "android.permission.PACKAGE_USAGE_STATS",
        "android.permission.PACKAGE_VERIFICATION_AGENT",
        "android.permission.PERFORM_CDMA_PROVISIONING",
        "android.permission.READ_FRAME_BUFFER",
        "android.permission.READ_INPUT_STATE",
        "android.permission.READ_NETWORK_USAGE_HISTORY",
        "android.permission.READ_PRIVILEGED_PHONE_STATE",
        "android.permission.REBOOT",
        "android.permission.RECEIVE_EMERGENCY_BROADCAST",
        "android.permission.REMOVE_TASKS",
        "android.permission.RETRIEVE_WINDOW_CONTENT",
        "android.permission.SEND_SMS_NO_CONFIRMATION",
        "android.permission.SET_ACTIVITY_WATCHER",
        "android.permission.SET_ORIENTATION",
        "android.permission.SET_POINTER_SPEED",
        "android.permission.SET_PREFERRED_APPLICATIONS",
        "android.permission.SET_SCREEN_COMPATIBILITY",
        "android.permission.SET_TIME",
        "android.permission.SET_WALLPAPER_COMPONENT",
        "android.permission.SHUTDOWN",
        "android.permission.STATUS_BAR",
        "android.permission.STATUS_BAR_SERVICE",
        "android.permission.STOP_APP_SWITCHES",
        "android.permission.UPDATE_DEVICE_STATS",
        "android.permission.WRITE_APN_SETTINGS",
        "android.permission.WRITE_GSERVICES",
        "android.permission.WRITE_MEDIA_STORAGE",
        "android.permission.WRITE_SECURE_SETTINGS"
    };

    /** Constructs a new {@link SystemPermissionReferenceDetector} */
    public SystemPermissionReferenceDetector() {
    }

}
