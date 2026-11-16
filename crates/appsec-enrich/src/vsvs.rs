use crate::cmdb::AppInfo;

#[derive(Debug, Clone, PartialEq)]
pub struct VsvsResult {
    pub vector: String,
    pub score: f64,
    pub rating: String,
}

pub fn vsvs_score(base_vector: Option<&str>, app: &AppInfo) -> Option<VsvsResult> {
    let v = base_vector?;
    let base = appsec_cvss::parse(v)?;
    let mav = app.mav(base.av);
    let (vector, score) = appsec_cvss::environmental(Some(v), mav, app.cr(), app.ir(), app.ar())?;
    let rating = appsec_cvss::rating(Some(score)).to_string();
    Some(VsvsResult {
        vector,
        score,
        rating,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(externally_facing: bool, pci: bool, pan: bool, pii: bool) -> AppInfo {
        AppInfo {
            externally_facing,
            pci_scoped: pci,
            processes_pan: pan,
            pii,
            ..Default::default()
        }
    }

    #[test]
    fn none_base_vector_is_none() {
        assert_eq!(vsvs_score(None, &app(true, false, false, false)), None);
    }

    #[test]
    fn malformed_base_vector_is_none() {
        assert_eq!(
            vsvs_score(Some("not a vector"), &app(true, false, false, false)),
            None
        );
    }

    #[test]
    fn internal_sensitive_app_downgrades_mav_and_raises_requirements() {
        let a = app(false, true, false, true);
        let r = vsvs_score(Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), &a).unwrap();
        assert_eq!(
            r.vector,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C/CR:H/IR:H/AR:M/MAV:A"
        );
        assert_eq!(r.score, 7.9);
        assert_eq!(r.rating, "High");
    }

    #[test]
    fn externally_facing_unremarkable_app_keeps_mav_and_uses_medium_requirements() {
        let a = app(true, false, false, false);
        let r = vsvs_score(Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), &a).unwrap();
        assert_eq!(
            r.vector,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C/CR:M/IR:M/AR:M/MAV:N"
        );
        assert_eq!(r.score, 8.8);
        assert_eq!(r.rating, "High");
    }

    #[test]
    fn zero_impact_vector_yields_a_none_rating() {
        let a = app(true, true, true, true);
        let r = vsvs_score(Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), &a).unwrap();
        assert_eq!(r.score, 0.0);
        assert_eq!(r.rating, "None");
    }
}
