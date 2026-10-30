//! Structural recognition of the existing native Windows fixture input.
use std::{collections::BTreeMap, path::Path};
use syn::visit::Visit;

pub(super) fn reviewed(relative: &Path, syntax: &syn::File, setters: usize, clears: usize) -> bool {
    let expected = match relative.to_str() {
        Some("tools/memcordon-ci/src/windows_current_control_cases.rs") => 4,
        Some("tools/memcordon-ci/src/windows_current_service_restart.rs") => 1,
        _ => return false,
    };
    if setters != expected || clears != expected || !provider_valid() {
        return false;
    }
    let declaration: syn::Item = if expected == 4 {
        syn::parse_quote! {
            #[path = "../../../crates/memcordon-cli/src/bin/consumer_readiness_windows/fixture_environment.rs"]
            mod fixture_environment;
        }
    } else {
        syn::parse_quote! { use super::{HeldProcess, fixture_environment, write_new}; }
    };
    if !syntax.items.contains(&declaration) {
        return false;
    }
    let mut review = Copies::default();
    review.visit_file(syntax);
    !review.invalid
        && review.copies == expected
        && review.namespace_identifiers == review.sources + 1
}

#[derive(Clone, Copy)]
enum Inventory {
    Filtered,
    Direct,
}

#[derive(Default)]
struct Copies {
    inventories: BTreeMap<String, Inventory>,
    cleared: std::collections::BTreeSet<String>,
    // Conservative across lexical scopes: a later same-name shadow or clear
    // cannot restore proof invalidated by a mutable borrow of the outer value.
    tainted: std::collections::BTreeSet<String>,
    copies: usize,
    sources: usize,
    namespace_identifiers: usize,
    invalid: bool,
}

fn path_name(expression: &syn::Expr) -> Option<String> {
    match expression {
        syn::Expr::Path(path) => path.path.get_ident().map(ToString::to_string),
        syn::Expr::MethodCall(call) => path_name(&call.receiver),
        _ => None,
    }
}

impl<'ast> Visit<'ast> for Copies {
    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        if ident == "fixture_environment" {
            self.namespace_identifiers += 1;
        }
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        let inventories = self.inventories.clone();
        let cleared = self.cleared.clone();
        syn::visit::visit_block(self, block);
        self.inventories = inventories;
        self.cleared = cleared;
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if !matches!(&local.pat, syn::Pat::Ident(_)) {
            self.check_bindings(&local.pat);
        }
        if let syn::Pat::Ident(binding) = &local.pat {
            let name = binding.ident.to_string();
            if self.inventories.contains_key(&name) {
                self.invalid = true;
            }
            self.cleared.remove(&name);
            let direct: syn::Expr = syn::parse_quote! { fixture_environment::entries()? };
            let filtered: syn::Expr = syn::parse_quote! {
                fixture_environment::entries()?.into_iter()
                    .filter(|entry| entry.name.first() != Some(&u16::from(b'=')))
                    .collect::<Vec<_>>()
            };
            if local.attrs.is_empty()
                && binding.by_ref.is_none()
                && binding.mutability.is_none()
                && binding.subpat.is_none()
                && let Some(initializer) = &local.init
                && initializer.diverge.is_none()
            {
                let inventory = if initializer.expr.as_ref() == &direct {
                    Some(Inventory::Direct)
                } else if initializer.expr.as_ref() == &filtered {
                    Some(Inventory::Filtered)
                } else {
                    None
                };
                if let Some(inventory) = inventory {
                    self.inventories.insert(name, inventory);
                    self.sources += 1;
                }
            }
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if let Some(name) = path_name(&call.receiver) {
            if self.inventories.contains_key(&name) {
                self.invalid = true;
            }
            if call.method == "env_clear" && call.args.is_empty() && call.turbofish.is_none() {
                self.cleared.insert(name);
            }
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_assign(&mut self, expression: &'ast syn::ExprAssign) {
        self.invalidate_write(&expression.left, true);
        syn::visit::visit_expr_assign(self, expression);
    }

    fn visit_expr_reference(&mut self, expression: &'ast syn::ExprReference) {
        if expression.mutability.is_some() {
            self.invalidate_write(&expression.expr, false);
        }
        syn::visit::visit_expr_reference(self, expression);
    }

    fn visit_expr_closure(&mut self, expression: &'ast syn::ExprClosure) {
        let cleared = self.cleared.clone();
        for pattern in &expression.inputs {
            self.check_bindings(pattern);
        }
        syn::visit::visit_expr_closure(self, expression);
        self.cleared = cleared;
    }

    fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
        for input in &function.sig.inputs {
            if let syn::FnArg::Typed(argument) = input {
                self.check_bindings(&argument.pat);
            }
        }
        syn::visit::visit_item_fn(self, function);
    }

    fn visit_expr_for_loop(&mut self, expression: &'ast syn::ExprForLoop) {
        for (name, kind) in &self.inventories {
            let inventory: syn::Ident = syn::parse_str(name).expect("inventory identifier");
            for name in &self.cleared {
                if self.tainted.contains(name) {
                    continue;
                }
                let command: syn::Ident = syn::parse_str(name).expect("command identifier");
                let expected: syn::ExprForLoop = match kind {
                    Inventory::Filtered => syn::parse_quote! {
                        for entry in &#inventory {
                            #command.env(std::ffi::OsString::from_wide(&entry.name), std::ffi::OsString::from_wide(&entry.value),);
                        }
                    },
                    Inventory::Direct => syn::parse_quote! {
                        for entry in &#inventory {
                            if entry.name.first() != Some(&u16::from(b'=')) {
                                #command.env(std::ffi::OsString::from_wide(&entry.name), std::ffi::OsString::from_wide(&entry.value));
                            }
                        }
                    },
                };
                if expression == &expected {
                    self.copies += 1;
                    return;
                }
            }
        }
        self.check_bindings(&expression.pat);
        syn::visit::visit_expr_for_loop(self, expression);
    }

    fn visit_expr_let(&mut self, expression: &'ast syn::ExprLet) {
        self.check_bindings(&expression.pat);
        syn::visit::visit_expr_let(self, expression);
    }

    fn visit_arm(&mut self, arm: &'ast syn::Arm) {
        self.check_bindings(&arm.pat);
        syn::visit::visit_arm(self, arm);
    }
}

impl Copies {
    fn invalidate_write(&mut self, expression: &syn::Expr, assignment: bool) {
        struct Names(Vec<String>);
        impl<'ast> Visit<'ast> for Names {
            fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
                if let Some(name) = path.path.get_ident() {
                    self.0.push(name.to_string());
                }
            }
        }
        let mut names = Names(Vec::new());
        names.visit_expr(expression);
        for name in names.0 {
            if self.inventories.contains_key(&name) || assignment && self.cleared.contains(&name) {
                self.invalid = true;
            }
            if self.cleared.remove(&name) {
                self.tainted.insert(name);
            }
        }
    }
    fn check_bindings(&mut self, pattern: &syn::Pat) {
        struct Bindings(Vec<String>);
        impl<'ast> Visit<'ast> for Bindings {
            fn visit_pat_ident(&mut self, pattern: &'ast syn::PatIdent) {
                self.0.push(pattern.ident.to_string());
                syn::visit::visit_pat_ident(self, pattern);
            }
        }
        let mut bindings = Bindings(Vec::new());
        bindings.visit_pat(pattern);
        for name in bindings.0 {
            if self.inventories.contains_key(&name) {
                self.invalid = true;
            }
            self.cleared.remove(&name);
        }
    }
}

fn provider_valid() -> bool {
    provider_matches(include_str!(
        "../../../crates/memcordon-cli/src/bin/consumer_readiness_windows/fixture_environment.rs"
    ))
}

pub(super) fn provider_matches(source: &str) -> bool {
    let Ok(actual) = syn::parse_file(source) else {
        return false;
    };
    let expected: syn::File = syn::parse_quote! {
        #[cfg(windows)]
        #[allow(unsafe_code)]
        pub fn entries() -> std::io::Result<Vec<memcordon_core::WindowsEnvironmentEntryV1>> {
            use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, GetSystemWindowsDirectoryW, SYSTEM_INFO,};
            let mut directory = [0u16; 2048];
            let length = unsafe { GetSystemWindowsDirectoryW(directory.as_mut_ptr(), directory.len() as u32) };
            if length == 0 { return Err(std::io::Error::last_os_error()); }
            if length as usize >= directory.len() || directory[length as usize] != 0 {
                return Err(std::io::Error::other("native system Windows directory exceeds bound",));
            }
            let mut system: SYSTEM_INFO = unsafe { std::mem::zeroed() };
            unsafe { GetSystemInfo(&mut system) };
            let architecture = unsafe { system.Anonymous.Anonymous.wProcessorArchitecture };
            from_system(&directory[..length as usize], architecture)
        }
        pub fn from_system(directory: &[u16], architecture: u16,) -> std::io::Result<Vec<memcordon_core::WindowsEnvironmentEntryV1>> {
            if directory.len() < 3 || directory.len() >= 2048
                || !matches!(directory[0], 65..=90 | 97..=122) || directory[1] != b':' as u16
                || directory[2] != b'\\' as u16 || directory.iter().any(|unit| matches!(*unit, 0 | 37 | 61)) {
                return Err(std::io::Error::other("native system Windows directory is not a bounded absolute drive path",));
            }
            let architecture = match architecture {
                9 => "AMD64", 12 => "ARM64",
                _ => { return Err(std::io::Error::other("unsupported native frontend architecture",)); }
            };
            let drive = match directory[0] { lower @ 97..=122 => lower - 32, upper => upper, };
            Ok(vec![
                memcordon_core::WindowsEnvironmentEntryV1 { name: vec![u16::from(b'='), drive, u16::from(b':')], value: vec![drive, u16::from(b':'), u16::from(b'\\')], },
                memcordon_core::WindowsEnvironmentEntryV1 { name: "PROCESSOR_ARCHITECTURE".encode_utf16().collect(), value: architecture.encode_utf16().collect(), },
                memcordon_core::WindowsEnvironmentEntryV1 { name: "SystemRoot".encode_utf16().collect(), value: directory.to_vec(), },
            ])
        }
    };
    actual.items == expected.items
}
