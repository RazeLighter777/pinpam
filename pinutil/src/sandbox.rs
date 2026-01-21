use landlock::{
    ABI, Access, AccessFs, AccessNet, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetError, RulesetStatus, path_beneath_rules
};


pub fn pinutil_sandbox() -> Result<(), RulesetError> {
    let abi = ABI::V6;
    let status = Ruleset::default()
        .handle_access(AccessFs::from_write(abi))?
        .handle_access(AccessNet::from_all(abi))?
        .create()?
        .add_rules(path_beneath_rules(
            &["/dev"],
            AccessFs::from_write(abi),
        ))?
        .restrict_self()?;
    match status.ruleset {
        // The FullyEnforced case must be tested by the developer.
        RulesetStatus::FullyEnforced => println!("Fully sandboxed."),
        RulesetStatus::PartiallyEnforced => println!("Partially sandboxed."),
        // Users should be warned that they are not protected.
        RulesetStatus::NotEnforced => println!("Not sandboxed! Please update your kernel or enable landlock."),
    }
    Ok(())
}