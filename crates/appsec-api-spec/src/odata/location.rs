use std::collections::BTreeSet;

use crate::format::Syntax;
use crate::libraries::ApiLibrary;
use crate::location::Convention;

const fn convention(basis: &'static str) -> Convention {
    Convention {
        path: "$metadata.xml",
        syntax: Syntax::Xml,
        confident: false,
        accepted_directories: &[],
        basis,
        code_first: true,
    }
}

const ASP_NET_CORE: Convention = convention(
    "ASP.NET Core OData builds the CSDL from its EDM model at run time and serves it at \
     $metadata, so a static copy is validated and repaired but never created",
);
const CAP: Convention = convention(
    "SAP CAP compiles the CSDL from the .cds model at run time or with cds compile, so a static \
     copy is validated and repaired but never created",
);
const OLINGO: Convention = convention(
    "Apache Olingo builds the CSDL from the application's EDM provider at run time, so a static \
     copy is validated and repaired but never created",
);
pub(crate) const FALLBACK: Convention = convention(
    "OData services generate their CSDL from the model at run time, so a static copy is \
     validated and repaired but never created",
);

fn library_convention(library: ApiLibrary) -> Convention {
    match library {
        ApiLibrary::AspNetCoreOData => ASP_NET_CORE,
        ApiLibrary::SapCap => CAP,
        ApiLibrary::Olingo => OLINGO,
        _ => FALLBACK,
    }
}

pub fn convention_for(libraries: &BTreeSet<ApiLibrary>) -> Convention {
    let all: Vec<Convention> = libraries.iter().map(|l| library_convention(*l)).collect();
    match all.first() {
        Some(first) if all.iter().all(|other| other == first) => *first,
        _ => FALLBACK,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ApiLibrary::*;

    fn of(libraries: &[ApiLibrary]) -> Convention {
        convention_for(&libraries.iter().copied().collect())
    }

    #[test]
    fn every_library_generates_its_csdl() {
        assert_eq!(of(&[AspNetCoreOData]), ASP_NET_CORE);
        assert_eq!(of(&[SapCap]), CAP);
        assert_eq!(of(&[Olingo]), OLINGO);
        assert_eq!(of(&[Kafka]), FALLBACK);
        assert_eq!(of(&[SapCap, Olingo]), FALLBACK);
        for library in [AspNetCoreOData, SapCap, Olingo] {
            let convention = of(&[library]);
            assert!(convention.code_first && !convention.confident);
            assert!(convention.basis.contains("never created"));
        }
    }

    #[test]
    fn conventions_are_xml_documents() {
        let built = convention("b");
        assert_eq!(built.syntax, Syntax::Xml);
        assert_eq!(built.path, "$metadata.xml");
    }
}
