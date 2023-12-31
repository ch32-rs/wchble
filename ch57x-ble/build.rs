use std::env;
use std::path::PathBuf;

#[derive(Debug)]
pub struct ParseCallback;

impl bindgen::callbacks::ParseCallbacks for ParseCallback {
    fn int_macro(&self, name: &str, _value: i64) -> Option<bindgen::callbacks::IntKind> {
        if name.ends_with("_UUID") || name.starts_with("GAP_APPEARE_") {
            Some(bindgen::callbacks::IntKind::U16)
        } else if name.starts_with("ATT_ERR_")
            || name.starts_with("GAP_ADTYPE_")
            || name.starts_with("ble")
            || name.starts_with("GATT_PERMIT_")
            || name.starts_with("GATT_PERMIT")
        {
            Some(bindgen::callbacks::IntKind::U8)
        } else {
            None
        }
    }

    fn process_comment(&self, comment: &str) -> Option<String> {
        println!("comment: {}", comment);
        let mut s = comment.to_string();
        s = s.replace("@note", "\n");
        let mut first = true;
        let mut ret = String::new();
        for l in s.lines() {
            if l.trim().starts_with("@param") {
                if first {
                    ret += "\n# Arguments\n";
                    first = false;
                }
                let line = l.trim().replace("@param ", "").trim().to_string();
                if line.contains(" - ") {
                    ret += "* `";
                    ret += &line.replace(" - ", "` - ");
                    ret += "\n";
                } else {
                    ret += &l.trim().replace("@param ", "* ");
                    ret += "\n";
                }
            } else {
                ret += &l.trim();
                ret += "\n";
            }
        }

        s = ret.replace("<BR>", "\n");
        s = s.replace("@brief", "");
        //        s = s.replace("@param", "\n* ");

        s = s.replace("!<", "");

        if s.contains("@param") {}

        if s.contains("@return") {
            let segs: Vec<&str> = s.split("@return").collect();
            let tail = segs[1]
                .lines()
                .filter(|s| !s.is_empty())
                .map(|s| {
                    let s = s.trim().to_string();
                    if s.contains(": ") {
                        "* `".to_string() + &s.replace(": ", "` - ")
                    } else {
                        "* ".to_string() + &s
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");

            Some(segs[0].trim().to_string() + "\n# Returns\n" + &tail)
        } else {
            Some(s.trim().into())
        }
    }
}

fn main() {
    println!("cargo:rerun-if-changed=CH57xBLE_LIB.h");

    let bindings = bindgen::Builder::default()
        .header("CH57xBLE_LIB.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .use_core()
        .parse_callbacks(Box::new(ParseCallback))
        .blocklist_type(".*?_pthread_.*?")
        .blocklist_type("__darwin_.*?")
        .blocklist_item("_?_DARWIN_.*?")
        .blocklist_item("__PTHREAD_.*?")
        .blocklist_item("__mbstate_t")
        .blocklist_item("__builtin_va_list")
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
