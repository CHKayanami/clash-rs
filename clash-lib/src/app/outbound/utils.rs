use std::collections::{HashMap, VecDeque};

use crate::{Error, config::internal::proxy::OutboundGroupProtocol};

// copy paste from https://github.com/Dreamacro/clash/blob/6a661bff0c185f38c4bd9d21c91a3233ba5fdb97/config/utils.go#L21
pub fn proxy_groups_dag_sort(
    groups: &mut [OutboundGroupProtocol],
) -> Result<(), Error> {
    let n = groups.len();
    if n <= 1 {
        return Ok(());
    }

    let mut name_to_idx = HashMap::with_capacity(n);
    for (idx, group) in groups.iter().enumerate() {
        let name = group.name();
        if name_to_idx.insert(name, idx).is_some() {
            return Err(Error::InvalidConfig(format!(
                "duplicate proxy group name: {name}"
            )));
        }
    }

    // adj[i] stores the indices of groups that depend on group i.
    // j depends on i => i -> j
    let mut adj = vec![Vec::new(); n];
    let mut in_degree = vec![0; n];

    for (j, group) in groups.iter().enumerate() {
        if let Some(proxies) = group.proxies() {
            for proxy in proxies {
                if let Some(&i) = name_to_idx.get(proxy.as_str()) {
                    adj[i].push(j);
                    in_degree[j] += 1;
                }
            }
        }
    }

    let mut queue = VecDeque::new();
    for i in 0..n {
        if in_degree[i] == 0 {
            queue.push_back(i);
        }
    }

    let mut order = Vec::with_capacity(n);
    while let Some(u) = queue.pop_front() {
        order.push(u);
        for &v in &adj[u] {
            in_degree[v] -= 1;
            if in_degree[v] == 0 {
                queue.push_back(v);
            }
        }
    }

    if order.len() < n {
        let mut looped_groups = Vec::new();
        for i in 0..n {
            if in_degree[i] > 0 {
                looped_groups.push(groups[i].name().to_owned());
            }
        }
        return Err(Error::InvalidConfig(format!(
            "loop detected in proxy groups: {looped_groups:?}"
        )));
    }

    // pos[i] represents the final sorted position where groups[i] should go.
    // Since our dependency edges flow from child (dependency) to parent, Kahn's algorithm
    // naturally outputs child groups first. Thus the natural order of Kahn's output is
    // the correct target sequence.
    let mut pos = vec![0; n];
    for (k, &orig_idx) in order.iter().enumerate() {
        pos[orig_idx] = k;
    }

    // Inplace permutation sorting cycle (O(N) swaps, O(1) extra space for elements, 0 clones)
    for i in 0..n {
        while pos[i] != i {
            let next_idx = pos[i];
            groups.swap(i, next_idx);
            pos.swap(i, next_idx);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::config::internal::proxy::{
        OutboundGroupFallback, OutboundGroupLoadBalance, OutboundGroupProtocol,
        OutboundGroupRelay, OutboundGroupSelect, OutboundGroupSmart,
        OutboundGroupUrlTest,
    };

    #[test]
    fn test_proxy_groups_dag_sort_ok() {
        let g1 = OutboundGroupRelay {
            name: "relay".to_owned(),
            proxies: Some(vec![
                "ss".to_owned(),
                "auto".to_owned(),
                "fallback-auto".to_owned(),
                "load-balance".to_owned(),
                "smart".to_owned(),
                "select".to_owned(),
                "DIRECT".to_owned(),
            ]),
            ..Default::default()
        };
        let g2 = OutboundGroupUrlTest {
            name: "auto".to_owned(),
            proxies: Some(vec!["ss".to_owned(), "DIRECT".to_owned()]),
            ..Default::default()
        };
        let g3 = OutboundGroupFallback {
            name: "fallback-auto".to_owned(),
            proxies: Some(vec!["ss".to_owned(), "DIRECT".to_owned()]),
            ..Default::default()
        };
        let g4 = OutboundGroupLoadBalance {
            name: "load-balance".to_owned(),
            proxies: Some(vec!["ss".to_owned(), "DIRECT".to_owned()]),
            ..Default::default()
        };
        let g5 = OutboundGroupSmart {
            name: "smart".to_owned(),
            proxies: Some(vec!["ss".to_owned(), "DIRECT".to_owned()]),
            ..Default::default()
        };
        let g6 = OutboundGroupSelect {
            name: "select".to_owned(),
            proxies: Some(vec![
                "ss".to_owned(),
                "DIRECT".to_owned(),
                "REJECT".to_owned(),
            ]),
            ..Default::default()
        };

        let mut groups = vec![
            OutboundGroupProtocol::Relay(g1),
            OutboundGroupProtocol::UrlTest(g2),
            OutboundGroupProtocol::Fallback(g3),
            OutboundGroupProtocol::LoadBalance(g4),
            OutboundGroupProtocol::Smart(g5),
            OutboundGroupProtocol::Select(g6),
        ];

        super::proxy_groups_dag_sort(&mut groups).unwrap();

        assert_eq!(groups.last().unwrap().name(), "relay");
    }

    #[test]
    fn test_proxy_groups_dag_sort_cycle() {
        let g1 = OutboundGroupRelay {
            name: "relay".to_owned(),
            proxies: Some(vec![
                "ss".to_owned(),
                "auto".to_owned(),
                "fallback-auto".to_owned(),
            ]),
            ..Default::default()
        };
        let g2 = OutboundGroupUrlTest {
            name: "auto".to_owned(),
            proxies: Some(vec![
                "ss".to_owned(),
                "DIRECT".to_owned(),
                "cycle".to_owned(),
            ]),
            ..Default::default()
        };
        let g3 = OutboundGroupFallback {
            name: "cycle".to_owned(),
            proxies: Some(vec![
                "ss".to_owned(),
                "DIRECT".to_owned(),
                "relay".to_owned(),
            ]),
            ..Default::default()
        };

        let mut groups = vec![
            OutboundGroupProtocol::Relay(g1),
            OutboundGroupProtocol::UrlTest(g2),
            OutboundGroupProtocol::Fallback(g3),
        ];

        let e = super::proxy_groups_dag_sort(&mut groups).unwrap_err();
        assert!(e.to_string().contains("loop detected in proxy groups"));
    }
}
