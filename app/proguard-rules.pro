# Add project specific ProGuard rules here.
# By default, the flags in this file are appended to flags specified
# in the Android SDK.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# Keep Xposed related classes
-keep class de.robv.android.xposed.** { *; }
-keep class app.aoki.yuki.hcefhook.xposed.** { *; }

# Keep native hook classes
-keepclassmembers class * {
    native <methods>;
}
