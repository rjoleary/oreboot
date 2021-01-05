use std::{fs, io};

extern crate uefi;
use uefi::*;

#[test]
fn parse_ovmf() -> io::Result<()> {
    let ovmf = fs::read("tests/testdata/OVMF.rom")?;

    let mut sections = Vec::new();
    let result = fv_traverse(&ovmf, &mut |ctx| sections.push(ctx));
    if let Err(err) = result {
        assert!(false, "{}", err);
    }

    assert_eq!(sections.len(), 4);
    Ok(())
}
