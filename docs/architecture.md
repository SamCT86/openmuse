# Architecture
A planner proposes typed actions. The registry publishes tool manifests. Policy evaluates risk, and the executor runs one tool only after policy allows it. The audit sink records redacted metadata and hash-links entries. The model never receives host approval secrets.

Trust boundaries: planner output and all external content are untrusted; policy, approval authority, secret store, and tool sandbox belong to the trusted host. Connectors should run out of process in future releases.
