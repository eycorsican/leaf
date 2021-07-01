use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use anyhow::anyhow;
use anyhow::Result;

use super::{geosite, internal};

pub fn load_file_or_default(filter: &str, default: &str) -> Result<(String, String)> {
    let parts: Vec<&str> = filter.split(':').collect();
    let (file, code) = if parts.len() == 3 {
        let path = if Path::new(parts[1]).is_absolute() {
            parts[1].to_string()
        } else {
            let asset_loc = Path::new(&*crate::option::ASSET_LOCATION);
            asset_loc.join(parts[1]).to_string_lossy().to_string()
        };
        (path, parts[2].to_string())
    } else if parts.len() == 2 {
        let asset_loc = Path::new(&*crate::option::ASSET_LOCATION);
        let path = asset_loc.join(default).to_string_lossy().to_string();
        (path, parts[1].to_string())
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

pub fn add_external_rule(rule: &mut internal::Router_Rule, ext_external: &str) -> Result<()> {
    if ext_external.starts_with("mmdb") {
        let (file, code) = match load_mmdb_rule(ext_external) {
            Ok((f, c)) => (f, c),
            Err(e) => {
                return Err(anyhow!("load mmdb rule failed: {}", e));
            }
        };
        let mut mmdb = internal::Router_Rule_Mmdb::new();
        mmdb.file = file;
        mmdb.country_code = code;
        rule.mmdbs.push(mmdb)
    }

    if ext_external.starts_with("site") {
        let (file, code) = match load_site_rule(ext_external) {
            Ok((f, c)) => (f, c),
            Err(e) => {
                return Err(anyhow!("load site rule failed: {}", e));
            }
        };

        // Loads SiteGroup objects one by one instead of loading the whole list.
        let mut reader = BufReader::with_capacity(2048, File::open(&file)?);
        let mut input = protobuf::CodedInputStream::new(&mut reader);
        while !input.eof()? {
            let _ = input.read_raw_byte()?; // skip
            let mut site_group = input.read_message::<geosite::SiteGroup>()?;
            if site_group.tag == code.to_uppercase() {
                for domain in site_group.domain.iter_mut() {
                    let mut domain_rule = match domain.field_type {
                        geosite::Domain_Type::Plain => {
                            let mut d = internal::Router_Rule_Domain::new();
                            d.field_type = internal::Router_Rule_Domain_Type::PLAIN;
                            d
                        }
                        geosite::Domain_Type::Domain => {
                            let mut d = internal::Router_Rule_Domain::new();
                            d.field_type = internal::Router_Rule_Domain_Type::DOMAIN;
                            d
                        }
                        geosite::Domain_Type::Full => {
                            let mut d = internal::Router_Rule_Domain::new();
                            d.field_type = internal::Router_Rule_Domain_Type::FULL;
                            d
                        }
                        _ => {
                            continue;
                        }
                    };
                    let value = std::mem::take(&mut domain.value);
                    domain_rule.value = value;
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
