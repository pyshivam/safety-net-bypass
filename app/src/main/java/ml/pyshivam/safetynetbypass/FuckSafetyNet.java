package ml.pyshivam.safetynetbypass;

import android.util.Log;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

import java.io.File;

import org.json.JSONObject;


public class FuckSafetyNet implements IXposedHookLoadPackage {
    private String[] keyWords = {"/su", "XposedBridge", "xposed", "xposed.installer", "app_process32_", "app_process64_", "supolicy", "sukernel", "libsupol.so", "SuperSUDaemon", "daemonsu", "Superuser", "chatter.pie", "libxposed"};
    private static final String CLASS_DROIDGUARD = "com.google.ccc.abuse.droidguard.DroidGuard";


    public boolean checkFileBool(File file, String packagename, String checktype) {
        for (int i = 0; i < keyWords.length; i++) {
            if (file.toString().contains(keyWords[i])) {
                if ((!file.toString().contains("sum")) && (!file.toString().contains("sub")) && (!file.toString().contains("surface"))) {
                    Log.d("BypassSafetyNet", "Found matching string - " + file + ". Caller: " + packagename + ". Checktype: " + checktype);
                    XposedBridge.log("BypassSafetyNet: Found matching string - " + file + ". Caller: " + packagename + ". Checktype: " + checktype);
                    return true;
                }
            }
        }
        return false;

    }


    public void handleLoadPackage(final LoadPackageParam lpparam) throws Throwable {
        if ("android".equals(lpparam.packageName) || ("droidguard".contains(lpparam.packageName)) || ("google.android.gms".contains(lpparam.packageName)) || ("walletnfcrel".contains(lpparam.packageName))) {
            XposedHelpers.findAndHookMethod(File.class, "exists", new XC_MethodHook() {
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    File file = (File) param.thisObject;
                    if (new File("/sys/fs/selinux/enforce").equals(file)) {
                        param.setResult(Boolean.TRUE);
                    } else if (new File("/system/bin/su").equals(file) || new File("/system/xbin/su").equals(file)) {
                        param.setResult(Boolean.FALSE);
                    }
                }
            });

            XposedHelpers.findAndHookMethod(File.class, "canExecute",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param)
                                throws Throwable {
                            File file = (File) param.thisObject;
                            if (checkFileBool(file, lpparam.packageName, "canExecute")) {
                                param.setResult(false);

                            }
                        }


                    });

            XposedHelpers.findAndHookMethod(File.class, "canRead",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param)
                                throws Throwable {
                            File file = (File) param.thisObject;
                            if (checkFileBool(file, lpparam.packageName, "canRead")) {
                                param.setResult(false);


                            }
                        }
                    });

            XposedHelpers.findAndHookMethod(File.class, "canWrite",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param)
                                throws Throwable {
                            File file = (File) param.thisObject;
                            if (checkFileBool(file, lpparam.packageName, "canWrite")) {
                                param.setResult(false);

                            }
                        }
                    });
        }
        XposedHelpers.findAndHookMethod(JSONObject.class, "getBoolean", String.class, new XC_MethodHook() {
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                String name = (String) param.args[0];
                XposedBridge.log("Parameters of " + param.args[0]);
                if ("ctsProfileMatch".equals(name)) {
                    param.setResult(Boolean.TRUE);
                }

                if ("isValidSignature".equals(name)) {
                    param.setResult(Boolean.TRUE);

                }


            }

            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                super.afterHookedMethod(param);
                String name = (String) param.args[0];


                if ("basicIntegrity".equals(name)) {
                    param.setResult(Boolean.TRUE);

                }
            }
        });


    }
}

