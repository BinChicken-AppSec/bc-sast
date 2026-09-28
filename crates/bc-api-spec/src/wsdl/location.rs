//! Where a WSDL document belongs, by SOAP server library convention.
//!
//! | Library | Location (relative to the service root) | Basis |
//! |---|---|---|
//! | JAX-WS (Metro, Apache CXF, Jakarta XML Web Services) | `src/main/resources/wsdl/service.wsdl` | JAX-WS builds the WSDL from the annotated endpoint at run time unless `@WebService(wsdlLocation = ...)` names a packaged one; `src/main/resources/wsdl/` is where CXF's and the JAX-WS Maven plugins' examples keep WSDL files |
//! | Spring Web Services | `src/main/resources/wsdl/service.wsdl` | `SimpleWsdl11Definition` publishes a classpath WSDL the application names; `DefaultWsdl11Definition` builds one from an XSD at run time |
//! | WCF, CoreWCF, ASMX, spyne | `wsdl/service.wsdl` | They generate the WSDL from the service contract at run time (`?wsdl`); the file is a reviewed snapshot |
//! | PHP `SoapServer`, Node.js `soap` | `wsdl/service.wsdl` | The server loads a WSDL file the application names; `wsdl/` at the service root is neutral |
//! | Anything else | `wsdl/service.wsdl` | Neutral |
//!
//! None is confident: every library reads a WSDL from wherever the code
//! names it, so an existing document is never moved. These locations were
//! written without documentation access and are listed for verification
//! in `TODO.md`.

use std::collections::BTreeSet;

use crate::format::Syntax;
use crate::libraries::ApiLibrary;
use crate::location::Convention;

const fn convention(path: &'static str, code_first: bool, basis: &'static str) -> Convention {
    Convention {
        path,
        syntax: Syntax::Xml,
        confident: false,
        accepted_directories: &[],
        basis,
        code_first,
    }
}

const JAX_WS: Convention = convention(
    "src/main/resources/wsdl/service.wsdl",
    true,
    "JAX-WS builds the WSDL from the annotated endpoint at run time unless \
     @WebService(wsdlLocation) names a packaged one; src/main/resources/wsdl/ is where CXF and \
     the JAX-WS Maven plugins keep WSDL files",
);
const SPRING_WS: Convention = convention(
    "src/main/resources/wsdl/service.wsdl",
    false,
    "Spring-WS publishes a classpath WSDL the application names (SimpleWsdl11Definition) or \
     builds one from an XSD at run time (DefaultWsdl11Definition)",
);
const GENERATED: Convention = convention(
    "wsdl/service.wsdl",
    true,
    "the framework generates the WSDL from the service contract at run time (?wsdl); \
     wsdl/service.wsdl at the service root is a reviewed snapshot of it",
);
const NAMED: Convention = convention(
    "wsdl/service.wsdl",
    false,
    "the SOAP server loads a WSDL file the application names; wsdl/ at the service root is \
     neutral",
);
pub(crate) const FALLBACK: Convention = convention(
    "wsdl/service.wsdl",
    false,
    "no SOAP library reads a WSDL from a fixed place; wsdl/service.wsdl at the service root is \
     neutral",
);

fn library_convention(library: ApiLibrary) -> Convention {
    use ApiLibrary::*;
    match library {
        JaxWs => JAX_WS,
        SpringWs => SPRING_WS,
        Wcf | CoreWcf | Asmx | Spyne => GENERATED,
        PhpSoap | NodeSoap => NAMED,
        _ => FALLBACK,
    }
}

/// The convention for a service using `libraries`; disagreements fall
/// back to the neutral location.
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
    fn each_library_maps_to_its_convention() {
        assert_eq!(of(&[JaxWs]), JAX_WS);
        assert!(of(&[JaxWs]).code_first);
        assert_eq!(of(&[SpringWs]), SPRING_WS);
        for generated in [Wcf, CoreWcf, Asmx, Spyne] {
            assert_eq!(of(&[generated]), GENERATED);
        }
        assert_eq!(of(&[PhpSoap]), NAMED);
        assert_eq!(of(&[NodeSoap]).path, "wsdl/service.wsdl");
        assert_eq!(of(&[Kafka]), FALLBACK);
        assert_eq!(of(&[]), FALLBACK);
        assert_eq!(of(&[Wcf, CoreWcf]), GENERATED);
        assert_eq!(of(&[JaxWs, SpringWs]), FALLBACK);
        for library in [JaxWs, SpringWs, Wcf, PhpSoap] {
            assert!(!of(&[library]).confident);
            assert_eq!(of(&[library]).syntax, Syntax::Xml);
        }
    }

    #[test]
    fn conventions_are_wsdl_documents() {
        let built = convention("a.wsdl", false, "b");
        assert_eq!(built.syntax, Syntax::Xml);
        assert!(!built.confident && built.accepted_directories.is_empty());
    }
}
