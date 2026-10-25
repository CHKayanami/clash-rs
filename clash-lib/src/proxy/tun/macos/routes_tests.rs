use std::{cell::RefCell, rc::Rc};

use super::*;

#[derive(Default)]
struct State {
    installed: Vec<Route>,
    fail_add: Option<Route>,
    deleted: Vec<Route>,
    pretend_add: bool,
}

struct Fake(Rc<RefCell<State>>);

impl Backend for Fake {
    fn refresh(&mut self) -> io::Result<()> { Ok(()) }
    fn contains(&self, route: &Route) -> bool { self.0.borrow().installed.contains(route) }

    fn add(&mut self, route: &Route) -> io::Result<bool> {
        let mut state = self.0.borrow_mut();
        if state.fail_add.as_ref() == Some(route) {
            return Err(io::Error::other("injected route conflict"));
        }
        if state.installed.contains(route) { return Ok(false); }
        if state.pretend_add { return Ok(true); }
        state.installed.push(route.clone());
        Ok(true)
    }

    fn delete(&mut self, route: &Route) -> io::Result<()> {
        let mut state = self.0.borrow_mut();
        state.installed.retain(|installed| installed != route);
        state.deleted.push(route.clone());
        Ok(())
    }
}

fn route(network: &str, interface: &str) -> Route {
    Route { destination: network.parse().unwrap(), interface: interface.to_owned(),
        gateway: None, scoped: false }
}

#[test]
fn startup_failure_rolls_back_only_owned_routes() {
    let existing = route("10.0.0.0/8", "en0");
    let created = route("0.0.0.0/1", "utun1989");
    let conflict = route("128.0.0.0/1", "utun1989");
    let state = Rc::new(RefCell::new(State {
        installed: vec![existing.clone()], fail_add: Some(conflict.clone()),
        ..Default::default()
    }));
    let mut routes = Routes::new(Fake(state.clone()));
    assert!(routes.update(vec![existing.clone(), created.clone(), conflict]).is_err());
    drop(routes);
    assert_eq!(state.borrow().installed, vec![existing]);
    assert_eq!(state.borrow().deleted, vec![created]);
}

#[test]
fn interface_or_gateway_change_replaces_routes_and_preserves_existing() {
    let existing = route("10.0.0.0/8", "en0");
    let old = route("192.168.0.0/16", "en0");
    let mut new = route("192.168.0.0/16", "en1");
    new.gateway = Some("192.168.1.1".parse().unwrap());
    let state = Rc::new(RefCell::new(State {
        installed: vec![existing.clone()], ..Default::default()
    }));
    let mut routes = Routes::new(Fake(state.clone()));
    routes.update(vec![existing.clone(), old.clone()]).unwrap();
    routes.update(vec![existing.clone(), new.clone()]).unwrap();
    assert!(state.borrow().installed.contains(&new));
    assert!(!state.borrow().installed.contains(&old));
    drop(routes);
    assert_eq!(state.borrow().installed, vec![existing]);
}

#[test]
fn failed_network_switch_restores_previous_routes() {
    let old = route("192.168.0.0/16", "en0");
    let new = route("192.168.0.0/16", "en1");
    let state = Rc::new(RefCell::new(State::default()));
    let mut routes = Routes::new(Fake(state.clone()));
    routes.update(vec![old.clone()]).unwrap();
    state.borrow_mut().fail_add = Some(new.clone());
    assert!(routes.update(vec![new]).is_err());
    assert_eq!(state.borrow().installed, vec![old]);
    drop(routes);
    assert!(state.borrow().installed.is_empty());
}

#[test]
fn ipv6_link_local_gateway_keeps_its_scope() {
    let native = NativeRoute::new("::".parse().unwrap(), 0)
        .with_if_name("en1".to_owned()).with_if_index(2)
        .with_gateway("fe80::1".parse().unwrap());
    let route = Route::from_native(&native).unwrap();
    assert_eq!(route.gateway, Some("fe80::1".parse().unwrap()));
    let encoded = route.native(7).unwrap();
    assert_eq!(encoded.if_index(), Some(7));
    assert_eq!(encoded.gateway(), Some("fe80:7::1".parse().unwrap()));
}

#[test]
fn externally_deleted_routes_are_repaired_even_when_desired_is_unchanged() {
    let route = route("0.0.0.0/1", "utun1989");
    let state = Rc::new(RefCell::new(State::default()));
    let mut routes = Routes::new(Fake(state.clone()));
    routes.update(vec![route.clone()]).unwrap();
    state.borrow_mut().installed.clear();
    routes.update(vec![route.clone()]).unwrap();
    assert_eq!(state.borrow().installed, vec![route]);
    drop(routes);
    assert!(state.borrow().installed.is_empty());
}

#[test]
fn exclusions_preserve_lan_and_ipv6_routes_without_installing_bypasses() {
    let networks = vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()];
    let excludes = vec!["192.168.0.0/16".parse().unwrap(), "fd00::/8".parse().unwrap()];
    let result = exclude_networks(networks, &excludes);
    for network in &result {
        for exclude in &excludes {
            assert!(!network.contains(exclude));
            assert!(!exclude.contains(network));
        }
    }
    for address in ["8.8.8.8", "192.167.255.255", "192.169.0.0", "2001:db8::1"] {
        let address: IpAddr = address.parse().unwrap();
        assert!(result.iter().any(|network| network.contains(&address)));
    }
    assert!(exclude_networks(vec!["10.0.0.0/8".parse().unwrap()],
        &["0.0.0.0/0".parse().unwrap()]).is_empty());
}

#[test]
fn full_capture_never_replaces_the_physical_default_route() {
    let cfg = TunConfig { route_all: true, ..Default::default() };
    let plan = Plan::new(&cfg, "utun1989");
    assert_eq!(plan.routes.len(), 2);
    assert!(plan.routes.iter().all(|route| route.destination.prefix_len() == 1));
}

#[test]
fn successful_ack_without_an_installed_route_is_rejected() {
    let state = Rc::new(RefCell::new(State { pretend_add: true, ..Default::default() }));
    let mut routes = Routes::new(Fake(state.clone()));
    let error = routes.update(vec![route("0.0.0.0/1", "utun1989")]).unwrap_err();
    assert!(error.to_string().contains("kernel did not install"));
    assert!(state.borrow().installed.is_empty());
}
