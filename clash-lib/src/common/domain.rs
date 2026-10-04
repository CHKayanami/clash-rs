/// Matchable domain names contain only nonempty labels. This deliberately
/// leaves character restrictions to the protocol or rule format that owns them.
pub(crate) fn has_valid_domain_labels(domain: &str) -> bool {
    let bytes = domain.as_bytes();
    !bytes.is_empty()
        && bytes.first() != Some(&b'.')
        && bytes.last() != Some(&b'.')
        && !domain.contains("..")
}
