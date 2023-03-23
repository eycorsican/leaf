/// Example:
///
/// Note: the protect method could be identified as unused code on the Android
/// side and stripped by ProGuard, you may need to add a keep rule to let
/// ProGuard knows we need the code, e.g.:
///
/// -keep class com.leaf.and.aleaf.** { *; }
///
/// // Sets a callback method to protect sockets.
/// //
/// // Expects a method with the given name and signature `(I)Z`.
/// #[allow(non_snake_case)]
/// #[no_mangle]
/// pub unsafe extern "system" fn Java_com_leaf_and_aleaf_SimpleVpnService_setProtectSocketCallback(
///     mut env: JNIEnv,
///     class: JClass,
///     name: JString,
/// ) {
///     let Ok(name) = env.get_string(&name) else {
///         return;
///     };
///     let name: String = name.into();
///     if let Ok(class_g) = env.new_global_ref(class) {
///         leaf::mobile::callback::android::set_protect_socket_callback(class_g, name);
///     }
/// }
///
/// #[allow(non_snake_case)]
/// #[no_mangle]
/// pub unsafe extern "system" fn JNI_OnLoad(vm: JavaVM, _: *mut std::os::raw::c_void) -> jint {
///     leaf::mobile::callback::android::set_jvm(vm);
///     JNI_VERSION_1_6
/// }
///
/// #[allow(non_snake_case)]
/// #[no_mangle]
/// pub unsafe extern "system" fn JNI_OnUnload(vm: JavaVM, _: *mut std::os::raw::c_void) {
///     leaf::mobile::callback::android::unset_protect_socket_callback();
///     leaf::mobile::callback::android::unset_jvm();
/// }
#[cfg(target_os = "android")]
pub mod android {
    use std::os::unix::io::RawFd;

    use anyhow::{anyhow, Result};
    use jni::{objects::*, JavaVM};
    use parking_lot::RwLock;

    static JVM: RwLock<Option<JavaVM>> = RwLock::new(None);
    static CALLBACK_PROTECT_SOCKET: RwLock<Option<CallbackProtectSocket>> = RwLock::new(None);

    struct CallbackProtectSocket {
        class: GlobalRef,
        name: String,
    }

    pub fn set_jvm(vm: JavaVM) {
        *JVM.write() = Some(vm);
    }

    pub fn unset_jvm() {
        *JVM.write() = None;
    }

    pub fn set_protect_socket_callback(class: GlobalRef, name: String) {
        *CALLBACK_PROTECT_SOCKET.write() = Some(CallbackProtectSocket { class, name });
    }

    pub fn unset_protect_socket_callback() {
        *CALLBACK_PROTECT_SOCKET.write() = None;
    }

    pub fn is_protect_socket_callback_set() -> bool {
        CALLBACK_PROTECT_SOCKET.read().is_some()
    }

    pub fn protect_socket(fd: RawFd) -> Result<()> {
        let jvm_g = JVM.read();
        let Some(vm) = jvm_g.as_ref() else {
            return Err(anyhow!("Java VM not set"));
        };
        let cb_g = CALLBACK_PROTECT_SOCKET.read();
        let Some(cb) = cb_g.as_ref() else {
            return Err(anyhow!("protect socket callback not set"));
        };
        let mut env = vm
            .attach_current_thread_permanently()
            .map_err(|e| anyhow!("cannot attach current thread to VM: {:?}", e))?;
        let success = env
            .call_method(&cb.class, &cb.name, "(I)Z", &[JValue::Int(fd as i32)])
            .map_err(|e| anyhow!("cannot call method: {:?}", e))?;
        if !success.z().unwrap_or(false) {
            return Err(anyhow!("protect socket failed"));
        }
        Ok(())
    }
}
