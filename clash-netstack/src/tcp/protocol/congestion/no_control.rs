// Derived from smoltcp commit 6b126ba1e965add8d765dffee0338756ffdfb6da.
// Copyright (C) smoltcp contributors; licensed under 0BSD.
// See the protocol directory's LICENSE-0BSD.txt.

use super::Controller;

#[derive(Debug)]

pub struct NoControl;

impl Controller for NoControl {
    fn window(&self) -> usize {
        usize::MAX
    }
}
