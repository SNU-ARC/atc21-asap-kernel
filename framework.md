There can be many workarounds to make Android framework to write to pseudo files. This is an example for `app_switch_start`. All path names are relatvie to AOSP home directory.

frameworks/base/services/core/java/com/android/server/wm/ActivityStarter.java (this is where app switch starts)

```java
import static android.os.Process.notifySwitchStart;
...
int execute() {
...
	notifySwitchStart();
...
}
```

frameworks/base/core/java/android/os/Process.java

```java
public static final void notifySwitchStart(void) {
         Os.notifySwitchStart();
     }
```

libcore/luni/src/main/java/android/system/Os.java

```java
public static void notifySwitchStart(void) {
             Libcore.rawOs.notifySwitchStart(void);
     }
```

libcore/luni/src/main/java/libcore/io/Os.java

```java
public void notifySwitchStart(void);
```

libcore/luni/src/main/java/libcore/io/ForwardingOs.java (implement this to suppress overriding error)

```java
public void notifySwitchStart(void) { System.out.println("do nothing" + pid); }
```

libcore/luni/src/main/java/libcore/io/Linux.java

```java
public native void notifySwitchStart(void);
```

libcore/luni/src/main/native/libcore_io_Linux.cpp

```java
...
NATIVE_METHOD(Linux, notifySwitchStart, "(V)V"),
...

static void Linux_notifySwitchStart(JNIEnv*, jobject) {
         FILE *fp = NULL;
         const char filepath[100] = "/proc/sys/vm/app_switch_start";

         fp = fopen(filepath, "w");
         if (!fp) {
                 __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "open fail");
                 return;
         }
         fprintf(fp, "%d", 1);
         fclose(fp);
         return;
 }
```
