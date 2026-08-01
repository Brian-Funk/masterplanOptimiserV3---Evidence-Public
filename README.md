# Controller accountability evidence archive

This public repository is a reviewed template and documentation site for deterministic, self-contained portable evidence bundles. It does not contain a deployment's evidence records. Each Masterplan deployment keeps its local signed hash-chained ledger as the authoritative record. A controller may use a separately governed repository as an additional off-server copy, not as the primary evidence store.

## Safe workflow

1. Keep deployment evidence private unless the controller explicitly approves a reviewed public subset.
2. Bootstrap a deployment archive through one reviewed pull request whose base has an empty tree and whose head contains exactly the static template files.
3. Create a branch and pull request for every later change.
4. Permit ingestion pull requests to add only `instances/<instance_id>/bundles/<bundle_id>/evidence.bundle` and `bundle.sha256`.
5. Run `python tools/verify_evidence_repo.py .` using the protected default-branch verifier.
6. Require the exact checks named `Evidence verification` and `Ingestion path validation` before merge.
7. Require the branch to be up to date and block force pushes, branch deletion, workflow changes and token-owner bypass.

Documentation for operators and reviewers is published through GitHub Pages from the files in `docs/`. Documentation and repository-maintenance changes require Code Owner review, while any pull request that touches `instances/` must still satisfy the strict two-file ingestion-path check.

The integrated Server uploader is disabled by default. When explicitly enabled for a separately governed private deployment archive, it may use only a Fine-grained GitHub personal access token scoped to that one private repository. The token must not have Administration write, Workflows write, Secrets, Environments write, Releases write, Issues, organisation administration or protected-branch bypass.

Never add database files, backups, private keys, secrets, names, personal email addresses, task content, or schedules. The token is never part of a bundle, summary, ledger, database, backup or diagnostic.

A valid signature proves that the identified key signed the exact statement. It does not prove physical deletion, absence of copies outside controlled systems, or legal compliance.
