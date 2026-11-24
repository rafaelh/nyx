# CONTEXT

The following terms are used in this repository:

- **Tactic** is a high-level goal, as in the [MITRE ATT&CK framework](https://attack.mitre.org/).
  The only tactic nyx currently implements is reconnaissance, the `recon` subcommand.

- **Technique** is a way of achieving a tactical goal, also corresponding to the MITRE ATT&CK
  framework. They are implemented by a **procedure**.

- **Procedure** this is an implementation of a **technique**, containing one or more **jobs**.

- **Job** this is a unit of work performed as part of a **procedure**.

- **Analysis** is a record nyx produces itself rather than one a procedure observes: findings,
  candidate ranks, third parties from CNAMEs, and addresses egress refused to dial. It isn't part
  of a procedure, and doesn't run any jobs.

