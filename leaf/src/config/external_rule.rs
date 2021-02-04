use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::anyhow;
use anyhow::Result;
use protobuf::Message;

use super::{geosite, internal};

pub fn load_file_or_default(filter: &str, default: &str) -> Result<(String, String)> {
    let parts: Vec<&str> = filter.split(':').collect();
    let (file, code) = if parts.len() == 3 {
        let path = if Path::new(parts[1]).is_absolute() {
            parts[1].to_string()
        } else {
            let mut file = std::env::current_exe().unwrap();
            file.pop();
            file.push(parts[1]);
            file.to_str().unwrap().to_string()
        };
        (path, parts[2].to_string())
    } else if parts.len() == 2 {
        let mut file = std::env::current_exe().unwrap();
        file.pop();
        file.push(default);
        (file.to_str().unwrap().to_string(), parts[1].to_string())
    } else {
        return Err(anyhow!("invalid external rule: {}", filter));
    };
    Ok((file, code))
}

pub fn load_mmdb_rule(filter: &str) -> Result<(String, String)> {
    load_file_or_default(filter, "geo.mmdb")
}

pub fn load_site_rule(filter: &str) -> Result<(String, String)> {
    load_file_or_default(filter, "site.dat")
}

pub fn add_external_rule(
    rule: &mut internal::RoutingRule,
    ext_external: &str,
    site_group_lists: &mut HashMap<String, geosite::SiteGroupList>,
) -> Result<()> {
    if ext_external.starts_with("mmdb") {
        let (file, code) = match load_mmdb_rule(&ext_external) {
            Ok((f, c)) => (f, c),
            Err(e) => {
                return Err(anyhow!("load mmdb rule failed: {}", e));
            }
        };
        let mut mmdb = internal::RoutingRule_Mmdb::new();
        mmdb.file = file;
        mmdb.country_code = code;
        rule.mmdbs.push(mmdb)
    }

    if ext_external.starts_with("site") {
        let (file, code) = match load_site_rule(&ext_external) {
            Ok((f, c)) => (f, c),
            Err(e) => {
                return Err(anyhow!("load site rule failed: {}", e));
            }
        };
        let site_group_list = match site_group_lists.get(&file) {
            Some(l) => l,
            None => {
                let mut f = match File::open(&file) {
                    Ok(f) => f,
                    Err(e) => {
                        return Err(anyhow!("open dat file {} failed: {}", &file, e));
                    }
                };
                let mut buf = Vec::new();
                match f.read_to_end(&mut buf) {
                    Ok(_) => (),
                    Err(e) => {
                        return Err(anyhow!("reading dat file {} failed: {}", &file, e));
                    }
                }
                let site_group_list = match geosite::SiteGroupList::parse_from_bytes(&buf) {
                    Ok(v) => v,
                    Err(e) => {
                        return Err(anyhow!("dat file {} has invalid format: {}", &file, e));
                    }
                };
                site_group_lists.insert(file.clone(), site_group_list);
                site_group_lists.get(&file).unwrap()
            }
        };

        for site_group in site_group_list.site_group.iter() {
            if site_group.tag == code.to_uppercase() {
                for domain in site_group.domain.iter() {
                    let mut domain_rule = match domain.field_type {
                        geosite::Domain_Type::Plain => {
                            let mut d = internal::RoutingRule_Domain::new();
                            d.field_type = internal::RoutingRule_Domain_Type::PLAIN;
                            d
                        }
                        geosite::Domain_Type::Domain => {
                            let mut d = internal::RoutingRule_Domain::new();
                            d.field_type = internal::RoutingRule_Domain_Type::DOMAIN;
                            d
                        }
                        geosite::Domain_Type::Full => {
                            let mut d = internal::RoutingRule_Domain::new();
                            d.field_type = internal::RoutingRule_Domain_Type::FULL;
                            d
                        }
                        _ => {
                            continue;
                        }
                    };
                    domain_rule.value = domain.value.clone();
                    rule.domains.push(domain_rule);
                }
                println!(
                    "loaded {} domain rules from [{}] for tag [{}]",
                    rule.domains.len(),
                    file,
                    code
                );
                break; // assume at most 1 matched tag
            }
        }
    }
    Ok(())
}
