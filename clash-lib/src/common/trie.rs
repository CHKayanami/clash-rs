use std::{collections::HashMap, sync::Arc};

static DOMAIN_STEP: &str = ".";
static COMPLEX_WILDCARD: &str = "+";
static DOT_WILDCARD: &str = "";
static WILDCARD: &str = "*";

#[derive(Clone)]
pub struct Node<T> {
    children: HashMap<String, Node<T>>,
    data: Option<Arc<T>>,
}

impl<T> Default for Node<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Node<T> {
    pub fn new() -> Self {
        Node {
            children: HashMap::new(),
            data: None,
        }
    }

    pub fn get_data(&self) -> Option<&T> {
        self.data.as_deref()
    }

    pub fn get_child(&self, s: &str) -> Option<&Self> {
        self.children.get(s)
    }

    pub fn get_child_mut(&mut self, s: &str) -> Option<&mut Self> {
        self.children.get_mut(s)
    }

    pub fn has_child(&self, s: &str) -> bool {
        self.get_child(s).is_some()
    }

    pub fn add_child(&mut self, s: &str, child: Node<T>) {
        self.children.insert(s.to_string(), child);
    }

    pub fn get_children(&self) -> &HashMap<String, Node<T>> {
        &self.children
    }
}
#[derive(Clone)]
pub struct StringTrie<T> {
    root: Node<T>,
}

impl<T> Default for StringTrie<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> StringTrie<T> {
    pub fn new() -> Self {
        StringTrie { root: Node::new() }
    }

    pub fn insert(&mut self, domain: &str, data: Arc<T>) -> bool {
        let (parts, valid) = valid_and_split_domain(domain);
        if !valid {
            return false;
        }

        let mut parts = parts.unwrap();

        match parts[0] {
            p if p == COMPLEX_WILDCARD => {
                self.insert_inner(&parts[1..], data.clone());
                parts[0] = DOT_WILDCARD;
                self.insert_inner(&parts, data);
            }
            _ => self.insert_inner(&parts, data),
        }

        true
    }

    pub fn search(&self, domain: &str) -> Option<&Node<T>> {
        let (parts, valid) = valid_and_split_domain(domain);
        if !valid {
            return None;
        }

        let parts = parts.unwrap();
        if parts.iter().any(|part| part.is_empty()) {
            return None;
        }
        if let Some(node) = Self::search_inner(&self.root, &parts)
            && node.data.is_some()
        {
            return Some(node);
        }
        None
    }

    pub fn traverse<F>(&self, mut f: F)
    where
        F: FnMut(&String, &T) -> bool,
    {
        self.traverse_parts(|parts, data| {
            let domain = parts.iter().rev().copied().collect::<Vec<_>>()
                .join(DOMAIN_STEP);
            let key = if domain.is_empty() {
                COMPLEX_WILDCARD.to_owned()
            } else if domain.starts_with(DOMAIN_STEP) {
                COMPLEX_WILDCARD.to_owned() + &domain
            } else { domain };
            f(&key, data)
        });
    }

    /// Borrow labels in root-to-leaf order. Unlike the rendered string, this
    /// distinguishes an empty suffix marker from a literal '+' label.
    pub(crate) fn traverse_parts<F>(&self, mut f: F)
    where
        F: FnMut(&[&str], &T) -> bool,
    {
        fn visit<'a, T, F>(node: &'a Node<T>, parts: &mut Vec<&'a str>, f: &mut F) -> bool
        where
            F: FnMut(&[&str], &T) -> bool,
        {
            for (key, child) in node.get_children() {
                parts.push(key);
                if let Some(data) = child.get_data()
                    && !f(parts, data)
                {
                    return false;
                }
                if !visit(child, parts, f) { return false; }
                parts.pop();
            }
            true
        }
        visit(&self.root, &mut Vec::new(), &mut f);
    }

    fn insert_inner(&mut self, parts: &[&str], data: Arc<T>) {
        let mut node = &mut self.root;

        for i in (0..parts.len()).rev() {
            let part = parts[i];
            if !node.has_child(part) {
                node.add_child(part, Node::new())
            }

            node = node.get_child_mut(part).unwrap();
        }

        node.data = Some(data);
    }

    fn search_inner<'a>(node: &'a Node<T>, parts: &[&str]) -> Option<&'a Node<T>> {
        if parts.is_empty() {
            return Some(node);
        }

        if let Some(c) = node.get_child(*parts.last().unwrap())
            && let Some(n) = Self::search_inner(c, &parts[0..parts.len() - 1])
            && n.data.is_some()
        {
            return Some(n);
        }

        if let Some(c) = node.get_child(WILDCARD)
            && let Some(n) = Self::search_inner(c, &parts[0..parts.len() - 1])
            && n.data.is_some()
        {
            return Some(n);
        }

        node.get_child(DOT_WILDCARD)
    }
}

pub fn valid_and_split_domain(domain: &str) -> (Option<Vec<&str>>, bool) {
    if !domain.is_empty() && domain.ends_with('.') {
        return (None, false);
    }

    let parts: Vec<&str> = domain.split(DOMAIN_STEP).collect();
    if parts.len() == 1 {
        if parts[0].is_empty() {
            return (None, false);
        }
        return (Some(parts), true);
    }

    for p in parts.iter().skip(1) {
        if p == &"" {
            return (None, false);
        }
    }

    (Some(parts), true)
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, sync::Arc};

    use crate::common::trie::StringTrie;

    static LOCAL_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

    #[test]
    fn test_basic() {
        let mut tree = StringTrie::new();

        let domains = vec!["example.com", "google.com", "localhost"];

        for d in domains {
            tree.insert(d, Arc::new(LOCAL_IP));
        }

        let node = tree.search("example.com").expect("should be not nil");
        assert_eq!(node.data.as_ref().expect("data nil").as_ref(), &LOCAL_IP);
        assert!(!tree.insert("", Arc::new(LOCAL_IP)));
        assert!(tree.search("").is_none());
        assert!(tree.search("localhost").is_some());
        assert!(tree.search("www.google.com").is_none());
    }

    #[test]
    fn test_wildcard() {
        let mut tree = StringTrie::new();

        let domains = vec![
            "*.example.com",
            "sub.*.example.com",
            "*.dev",
            ".org",
            ".example.net",
            ".apple.*",
            "+.foo.com",
            "+.stun.*.*",
            "+.stun.*.*.*",
            "+.stun.*.*.*.*",
            "stun.l.google.com",
        ];

        for d in domains {
            tree.insert(d, Arc::new(LOCAL_IP));
        }

        assert!(tree.search("sub.example.com").is_some());
        assert!(tree.search("sub.foo.example.com").is_some());
        assert!(tree.search("test.org").is_some());
        assert!(tree.search("test.example.net").is_some());
        assert!(tree.search("test.apple.com").is_some());
        assert!(tree.search("foo.com").is_some());
        assert!(tree.search("global.stun.website.com").is_some());

        assert!(tree.search("foo.sub.example.com").is_none());
        assert!(tree.search("foo.example.dev").is_none());
        assert!(tree.search("example.com").is_none());
    }

    #[test]
    fn test_priority() {
        let mut tree = StringTrie::new();

        let domains = [".dev", "example.dev", "*.example.dev", "test.example.dev"];

        for (idx, d) in domains.iter().enumerate() {
            tree.insert(d, Arc::new(idx));
        }

        let assert_fn = |k: &str| -> Arc<usize> {
            tree.search(k).unwrap().data.clone().unwrap()
        };

        assert_eq!(assert_fn("test.dev"), Arc::new(0));
        assert_eq!(assert_fn("foo.bar.dev"), Arc::new(0));
        assert_eq!(assert_fn("example.dev"), Arc::new(1));
        assert_eq!(assert_fn("foo.example.dev"), Arc::new(2));
        assert_eq!(assert_fn("test.example.dev"), Arc::new(3));
    }

    #[test]
    fn test_traverse_stops_in_subtree() {
        let mut tree = StringTrie::new();
        for domain in ["example.com", "a.example.com", "b.example.com", "other.net"] {
            tree.insert(domain, Arc::new(LOCAL_IP));
        }
        let mut calls = 0;
        tree.traverse(|_, _| {
            calls += 1;
            false
        });
        assert_eq!(calls, 1);
    }

    #[test]
    fn test_boundary() {
        let mut tree = StringTrie::new();

        tree.insert("*.dev", Arc::new(LOCAL_IP));
        assert!(!tree.insert(".", Arc::new(LOCAL_IP)));
        assert!(!tree.insert("..dev", Arc::new(LOCAL_IP)));
        assert!(tree.search("dev").is_none());
    }

    #[test]
    fn test_wildcard_boundary() {
        let mut tree = StringTrie::new();
        tree.insert("+.*", Arc::new(LOCAL_IP));
        tree.insert("stun.*.*.*", Arc::new(LOCAL_IP));

        assert!(tree.search("example.com").is_some());
    }
}
