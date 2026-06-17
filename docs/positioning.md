## Where GCO fits

GCO is an **authority-propagation** primitive, not an action-content monitor. The
distinction matters, because the two solve different problems and a serious
agent-security stack wants both.

### Two different layers

**Action-content monitors** (e.g. command-blocking hooks, secret-prevention
layers, YAML pattern rules) operate at the leaf: each individual tool call is
inspected and a policy decides whether *that specific action* is dangerous -
block `rm -rf /`, block a secret being piped to an external host, flag a
reverse shell. This is real, immediately useful, and deployable today. It is
strong exactly where the action happens and the hook is present.

**GCO operates one layer down**, on authority rather than content. It does not
ask "is this command dangerous." It asks "does this node still hold the
authority its parent had, or did it escape the governance scope as the
computation branched?" A Governance Context Object travels with execution,
binds to an attested workload identity, and can only *tighten* as it propagates
to sub-calls and delegated tool servers - never widen. A descendant cannot
grant itself more authority than its parent.

### Why both are needed

Per-action monitors share a known blind spot, which their own authors tend to
name as a roadmap item: **individually-benign steps that compose into harm
across a sequence or across nodes.** Read a file, encode it, send it - each
step passes the content check; the composition is the attack. That is the
aggregation problem described in the recursion-blindspot position paper, and it
is not a content-rule problem. It is an authority- and flow-scope problem.

GCO addresses the structural side: as computation spreads across a recursion or
tool-call tree (including MCP tool servers, which carry none of the root's
in-forward-pass governance by default), GCO is the layer that keeps authority
from silently escaping. It is weak as a standalone product - it governs nothing
by itself; it is a primitive that a runtime enforces - and useful precisely as
the missing layer beneath content-level monitors.

### What GCO does NOT do

To be explicit, so this is not mistaken for another pattern-matcher:

- It does **not** inspect the content of an action or decide whether a specific
  command is dangerous.
- It does **not** prevent prompt injection, perform DLP, or scrub secrets.
- It does **not** provide host or sandbox isolation.
- It governs **authority propagation across a call tree** - that is the whole of
  its job, and it depends on deployment controls outside this package to be
  enforcing rather than advisory.

Think of a content monitor as a smoke detector in each room and GCO as the
building's access-control system. Neither replaces the other.
