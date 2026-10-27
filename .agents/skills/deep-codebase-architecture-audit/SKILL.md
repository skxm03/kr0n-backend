---
name: deep-codebase-architecture-audit

description: Perform a deep, evidence-driven architectural audit of the codebase. Study the domain, history, dependencies, runtime flows, persistence, concurrency, failure modes, testing surface, and module boundaries to uncover real architectural problems, then present the findings as an interactive visual report for investigation.

disable-model-invocation: true
---

# Deep Codebase Architecture Audit

Perform a **deep architectural investigation** of the codebase.

The goal is NOT to produce generic best practices, style suggestions, or a list of things that "could be cleaner."

The goal is to discover **real architectural problems already present in the system**:

- hidden coupling
- misplaced ownership
- leaky abstractions
- shallow modules
- accidental complexity
- duplicated domain knowledge
- transaction boundary problems
- incorrect dependency direction
- fragile initialization
- implicit contracts
- concurrency hazards
- inconsistent state transitions
- error-handling holes
- testing seams that don't correspond to real behavior
- infrastructure concerns leaking into domain code
- domain concerns leaking into infrastructure
- abstractions that exist without actually reducing complexity
- modules whose names and responsibilities don't match what they actually do
- code paths that will become painful as the system grows
- architecture that makes common changes unnecessarily expensive
- architecture that makes certain failures difficult to reason about
- architecture that prevents independent testing
- places where future features will force unrelated modules to change

The audit should feel like having a senior/staff engineer spend substantial time understanding the system before making any recommendations.

**Do not manufacture problems.**

If an area is well-designed, say so and move on.

---

# 1. Investigation Philosophy

Treat the repository as a system, not as a collection of files.

Do not begin by scanning for familiar smells and immediately proposing patterns.

First construct a mental model of:

````text
Domain
  ↓
Modules
  ↓
Dependencies
  ↓
Runtime flows
  ↓
State transitions
  ↓
Persistence
  ↓
Infrastructure
  ↓
Operational behavior

Then look for contradictions between those layers.

The strongest findings usually come from places where:

the conceptual ownership says one thing, but the code ownership says another.

or:

the interface suggests one abstraction, while callers still need to understand the implementation.

or:

a change that should be local actually requires modifications across several unrelated modules.

2. Establish Scope

Before investigating deeply, determine what kind of system this is.

Identify:

language(s)
framework(s)
application type
executable entrypoints
modules/packages
persistence layer
external dependencies
background workers
queues
caches
RPC
HTTP
WebSockets
scheduled jobs
event handlers
CLI commands
deployment configuration
infrastructure configuration

Do not assume the architecture from directory names.

Verify it from imports, call sites, initialization, and runtime wiring.

3. Read the Repository's Own Language

Before making architectural judgments, search for:

CONTEXT.md
README.md
docs/
docs/adr/
architecture/
design/

Read relevant architecture documents and ADRs.

Extract:

domain terminology
module responsibilities
architectural principles
explicit invariants
intentional constraints
previous architectural decisions
known tradeoffs

Use the repository's terminology when describing findings.

Do not rename concepts merely to fit generic software architecture vocabulary.

If the repository has an ADR explaining why something looks unusual, investigate whether that decision is still holding up before calling it a problem.

4. Study Git History

Do not only inspect the current tree.

Use git history to understand where the architecture came from.

Start with:

git log --oneline --decorate --graph

Then investigate:

git log --stat
git log -- <important-path>
git blame <important-file>

Look for:

files repeatedly modified together
modules that constantly change together
large refactors
reverted changes
bug-fix clusters
repeated fixes in the same area
modules that accumulate responsibilities
code that has been copied and modified
architectural decisions that were partially implemented
TODOs that have survived for a long time
comments describing constraints that the code no longer appears to enforce

Use history as evidence, not as proof.

A file being frequently changed does not automatically mean it is architecturally bad.

5. Build a Dependency Model

Construct a practical dependency graph.

At minimum identify:

Module A
   ↓
Module B
   ↓
Repository
   ↓
Database

but also:

HTTP
  ↓
Handler
  ↓
Application logic
  ↓
Domain logic
  ↓
Repository
  ↓
Database

and:

Producer
  ↓
Queue
  ↓
Consumer
  ↓
External system

Look for:

Dependency inversion failures

Examples:

Domain → PostgreSQL driver
Domain → Redis
Domain → HTTP framework
Domain → Kafka

when those dependencies should be replaceable.

Dependency cycles

Especially:

A → B → C → A

or softer cycles where modules are conceptually coupled despite avoiding an import cycle.

Wide dependency surfaces

A module that requires knowledge of many unrelated modules to perform a simple operation.

Hidden dependencies

Global state, package-level initialization, environment variables, singleton registries, implicit context values, database assumptions, or ordering requirements.

6. Trace Real Runtime Flows

Do not analyze only static dependencies.

Pick important user-visible operations and trace them end-to-end.

For each important flow:

Request
  ↓
Authentication
  ↓
Handler
  ↓
Application logic
  ↓
Domain logic
  ↓
Repository
  ↓
Database
  ↓
Events
  ↓
Workers
  ↓
External systems

Trace at least:

one normal successful path
one failure path
one transaction-heavy path
one asynchronous path
one path involving external infrastructure

For each flow determine:

where validation happens
where authorization happens
where business rules happen
where state changes
where transactions begin/end
where events are emitted
what happens if the next step fails
whether retries are safe
whether operations are idempotent
what state is persisted before failure
what state is persisted after failure

This is where many architectural problems will be discovered.

7. Investigate Ownership

For every significant concept ask:

Which module owns this concept?

Then compare that answer with the code.

Look for cases where:

Module A

knows the internal schema or invariants of:

Module B

Examples:

raw SQL against another module's tables
JSON structures belonging to another domain
duplicated validation rules
duplicated enum definitions
duplicated state machines
another module reaching into repository internals
business rules implemented in controllers
business rules implemented in database triggers without corresponding domain ownership
infrastructure code deciding domain behavior

These are high-value findings.

8. Investigate Module Depth

For each important module ask:

What complexity does this module hide?

If the answer is:

almost none

the module may be shallow.

Use the deletion test:

If this module disappeared, would the complexity disappear, or would it simply move somewhere else?

If deleting the module merely moves the same complexity into callers, that is a signal that the module is not providing enough depth.

Look for:

interfaces that mirror implementations line-for-line
repositories that merely forward every method
services that merely call one repository method
utility packages containing unrelated behavior
"manager" or "helper" packages with unclear ownership
abstractions introduced solely to make tests compile

Do not automatically recommend deleting them.

Determine whether they are actually buying locality, leverage, or replaceability.

9. Investigate Seams

Find the places where modules communicate.

For each seam ask:

Who owns the contract?
What information crosses it?
How much implementation detail leaks?
Can either side change independently?
Can the seam be tested independently?

Look for:

concrete types crossing module boundaries unnecessarily
database models crossing domain boundaries
framework request/response types leaking inward
infrastructure types becoming domain contracts
giant interfaces
interfaces defined by the wrong side
functions requiring excessive context
shared mutable objects
implicit assumptions about call ordering

A good seam should make change cheaper.

If it doesn't, question why it exists.

10. Investigate State Machines

For systems with meaningful state, explicitly reconstruct state transitions.

Example:

PENDING
   ↓
PROCESSING
   ↓
COMPLETED

Then find every place that can modify the state.

Look for:

transitions happening in multiple modules
invalid transitions not being rejected
states represented as arbitrary strings
partial transitions
database state and in-memory state diverging
events emitted before state persistence
state persistence happening without corresponding events
retries producing duplicate transitions
workers assuming a state that the API does not guarantee

State-machine bugs are often architectural rather than local coding mistakes.

11. Investigate Transactions

Identify every significant transaction boundary.

Ask:

Who owns the transaction?
What operations participate?
What happens if operation 3 fails?
What happens if the process crashes after operation 2?

Look specifically for:

transactions crossing inappropriate module boundaries
repositories silently creating transactions
services assuming atomicity they don't actually have
external side effects inside database transactions
database commits followed by unreliable event publishing
event publishing followed by database rollback
missing outbox patterns where durability actually requires one
excessively large transactions
transactions that depend on network calls

Do not recommend an outbox simply because it is popular.

Only surface it when the system has an actual consistency problem that warrants it.

12. Investigate Asynchronous Systems

For queues, workers, events, and background processing, reconstruct:

Producer
  ↓
Message
  ↓
Broker
  ↓
Consumer
  ↓
Side effects

Determine:

delivery semantics
retry behavior
acknowledgement timing
idempotency
dead-letter behavior
ordering assumptions
duplicate handling
poison messages
visibility timeouts / consumer crashes
observability
backpressure

Look for places where the architecture implicitly assumes:

"this happens exactly once"

when the infrastructure actually provides:

"this may happen more than once"
13. Investigate Error Architecture

Do not merely search for TODO or panic.

Trace errors through layers.

Ask:

Database error
   ↓
Repository
   ↓
Application layer
   ↓
HTTP/RPC

Determine:

where errors are translated
where domain errors originate
whether infrastructure errors leak upward
whether errors lose useful context
whether callers can distinguish expected vs unexpected failures
whether retryable failures are distinguishable
whether errors are being string-compared
whether HTTP status codes are coupled to domain errors

Look for architecture where callers need to understand implementation details to handle failures correctly.

14. Investigate Testing Architecture

Do not count tests.

Study what the tests are forced to know.

Ask:

Can domain behavior be tested without infrastructure?
Do tests require real databases unnecessarily?
Are tests mocking implementation details?
Are integration tests compensating for weak unit seams?
Are important behaviors only tested through HTTP?
Are repositories over-mocked?
Are interfaces created solely for mocks?
Are tests asserting implementation rather than behavior?
Can important failure modes actually be produced deterministically?

Use:

The interface is the test surface.

If a module is hard to test through its intended public surface, investigate why.

15. Investigate Concurrency

Look for:

shared mutable state
goroutine lifecycle problems
race-prone caches
locks with unclear ownership
channel ownership ambiguity
worker shutdown problems
background goroutines with no cancellation
context misuse
duplicate processing
concurrent updates to the same database records
optimistic/pessimistic locking assumptions

Do not report "could have a race" without tracing the actual access pattern.

16. Investigate Persistence

Study the relationship between:

Domain model
Database model
Repository
Migration
Queries

Look for:

database schema leaking into unrelated modules
domain concepts represented by overly generic tables
duplicated persistence logic
raw SQL bypassing repository ownership
inconsistent transaction handling
N+1 queries
accidental full-table scans
missing indexes on important access paths
persistence models pretending to be domain models
schema constraints that the application assumes but the DB does not enforce

Use query patterns and actual call sites as evidence.

17. Investigate Configuration and Initialization

Find all initialization paths.

Look for:

global initialization
hidden side effects during package import
environment variables read throughout the codebase
configuration accessed directly from deep modules
initialization ordering dependencies
optional dependencies that are actually mandatory
constructors that require huge dependency graphs
runtime registries that depend on registration order

Ask:

Could the application be assembled explicitly from a composition root?

If not, identify why.

18. Investigate External Boundaries

For every external system:

PostgreSQL
Redis
RabbitMQ
S3
HTTP APIs
gRPC
Judge systems
Email providers

identify:

adapter
retry policy
timeout policy
error translation
ownership
idempotency
observability
test seam

Look for external system details leaking into domain logic.

19. Investigate Security Architecture

Do not perform a generic security checklist.

Trace actual security flows:

Identity
  ↓
Authentication
  ↓
Authorization
  ↓
Resource ownership
  ↓
Mutation

Look for:

authorization performed too late
authorization duplicated inconsistently
tenant isolation assumptions
IDOR-style access paths
internal endpoints exposed externally
trusted headers crossing unsafe boundaries
privilege checks living in controllers while background workers bypass them
secrets flowing through inappropriate layers
unsafe deserialization
user-controlled data reaching infrastructure without validation

Only report issues supported by code evidence.

20. Investigate Observability

For important operations ask:

If this breaks in production, can an engineer reconstruct what happened?

Check:

structured logs
request IDs
correlation IDs
job IDs
user/resource IDs where appropriate
metrics
traces
queue visibility
error context

Look for architectural blind spots rather than merely missing log statements.

21. Investigate Change Locality

This is one of the highest-value investigations.

Use git history and hypothetical changes.

For important concepts ask:

If this concept changes, how many modules must change?

Examples:

Add a new permission type
Change organization state
Add a new upload backend
Add a new notification channel
Change submission lifecycle
Add a new assignment type
Change authentication provider

Trace the actual files that would need modification.

If one conceptual change repeatedly crosses unrelated modules, report it.

Call this:

Change locality failure.

22. Investigate Duplication of Knowledge

Do not only search for duplicated code.

Search for duplicated decisions.

Examples:

"Can this user access X?"

implemented in four places.

Or:

"What states can a submission enter?"

encoded independently in:

API
worker
database
frontend

Or:

"What constitutes a valid upload?"

implemented separately in multiple paths.

Duplicated knowledge is often more dangerous than duplicated code.

23. Investigate Naming vs Reality

Compare:

package name
type name
function name

with what the code actually does.

Find:

"Service" types that own domain state
"Repository" types performing business logic
"Utils" containing core domain behavior
"Manager" types acting as orchestrators
modules whose names describe infrastructure rather than concepts
abstractions whose names promise more than they provide

Do not rename things merely for aesthetics.

Only report naming problems when the mismatch makes architecture harder to understand.

24. Investigate the Negative Space

Look for important things that don't exist.

Examples:

no explicit transaction owner
no owner for state transitions
no idempotency mechanism
no adapter around a critical external dependency
no authorization seam
no durable event boundary
no lifecycle owner for goroutines
no source of truth for a concept
no explicit contract for a queue message

The absence of an abstraction can itself be an architectural problem.

But prove that the missing thing is actually required by the behavior of the system.

25. Produce Findings

Every finding must contain:

Title

A precise architectural statement.

Bad:

Code is messy.

Good:

Audit owns organization persistence knowledge that belongs to the organization module.

Evidence

Point to the actual:

file
function
type
call path
migration
configuration
git history

Whenever possible include line references.

Observed behavior

Explain what the code currently does.

Architectural problem

Explain why that structure creates friction.

Consequence

Explain what becomes harder:

change
testing
reasoning
reliability
scaling
security
operations
Blast radius

Identify what else is coupled to the problem.

Confidence

Use:

High
Medium
Low

High confidence requires direct code evidence.

Severity

Use:

Architectural
Significant
Moderate
Minor

Do not turn this into a numeric score.

Possible direction

Give a direction, not an implementation dump.

For example:

Move restoration knowledge behind a domain-owned seam.

rather than immediately generating 500 lines of code.

26. Distinguish Problems From Opportunities

Separate findings into:

Structural Problems

The current architecture is actively creating friction or risk.

Latent Problems

The current architecture works, but a foreseeable change will expose the weakness.

Deepening Opportunities

The architecture is functional, but a module could hide significantly more complexity and provide a stronger seam.

Non-Problems

Things that may look unusual but are justified by the system's constraints.

This is important.

The audit should explicitly say:

"I investigated this and do not consider it a problem."

That prevents architecture reviews from becoming endless refactoring machines.

27. Do Not Prescribe Patterns

Do not produce findings like:

Use Repository Pattern
Use CQRS
Use Event Sourcing
Use Hexagonal Architecture
Use Factory Pattern
Use Dependency Injection
Use Kafka
Use Redis

unless the codebase has a concrete problem that the proposed mechanism addresses.

Architecture is not a pattern shopping list.

Start with:

Observed problem
        ↓
Root cause
        ↓
Architectural consequence
        ↓
Possible direction

Only then discuss patterns if they actually fit.

28. Rank Investigation Priority Without Ranking Architectural Quality

You may prioritize which findings deserve investigation first based on:

blast radius
frequency
evidence strength
change cost
operational impact

Do NOT produce:

1. Best architecture
2. Second best architecture
3. Worst module

The purpose is investigation, not scoring.

29. Generate a Visual HTML Report

Write a self-contained report to:

$TMPDIR/architecture-audit-<timestamp>.html

falling back to:

/tmp

or:

%TEMP%

on Windows.

Do not write the report into the repository.

Open it automatically:

open <path>

macOS

xdg-open <path>

Linux

start <path>

Windows.

Tell the user the absolute path.

Use:

Tailwind via CDN
Mermaid via CDN
custom CSS
SVG diagrams where useful

The report should feel like a serious engineering investigation, not a generated checklist.

30. Report Structure

Start with:

System Map

Show:

Domain
Modules
Infrastructure
External Systems

and how they interact.

Executive Summary

Give a concise explanation of:

what the system appears to be
where its architecture is strong
where the main architectural friction is concentrated
which areas deserve deeper investigation

Do not provide a generic "overall architecture score."

Findings

Each finding gets a large card containing:

┌─────────────────────────────────────────────┐
│ Finding                                     │
│                                             │
│ Title                                       │
│                                             │
│ Evidence                                    │
│                                             │
│ Current Architecture                        │
│                                             │
│ Problem                                     │
│                                             │
│ Why It Matters                              │
│                                             │
│ Blast Radius                                │
│                                             │
│ Confidence                                  │
│                                             │
│ Possible Direction                          │
│                                             │
│ Before Diagram                              │
│                                             │
│ After / Target Shape                        │
└─────────────────────────────────────────────┘

Include actual code excerpts when they make the finding obvious.

Keep excerpts short.

31. Visualize Important Findings

Use Mermaid for:

dependency graphs
sequence diagrams
transaction flows
event flows
state machines

Use custom HTML/SVG for:

module cross-sections
coupling diagrams
before/after architecture
responsibility maps

Every major finding should have a visual representation when one materially improves understanding.

32. Include a Change-Impact Map

Create a section showing:

Concept
  ↓
Files touched
  ↓
Modules touched
  ↓
External systems touched

Highlight concepts where a seemingly local change crosses many architectural seams.

33. Include a "Why I Think This Is Real" Section

For each major finding explicitly show the evidence chain:

Git history
     +
Current code
     +
Call graph
     +
Runtime flow
     =
Finding

This is critical.

Do not make architectural claims based solely on intuition.

34. Include an "Investigated but Rejected" Section

Record interesting things that were investigated but determined not to be problems.

Example:

Potential concern:
Repository interfaces appear verbose.

Investigation:
All repositories are used behind genuine transactional seams
and have independent implementations.

Conclusion:
Not currently an architectural problem.

This prevents future audits from repeatedly rediscovering the same false positives.

35. Top Investigation Targets

End with:

What deserves investigation first?

Choose the findings with the greatest combination of:

evidence
architectural impact
blast radius
change locality
likelihood of causing future friction

Do not call something "best."

Instead say:

"This is the first area I would investigate because..."

Do not prescribe the final architecture yet.

36. After the Report

Ask exactly:

Which finding would you like to investigate?

Do not immediately modify the code.

Do not generate an interface.

Do not perform the refactor.

The first phase is understanding.

37. Investigation Loop

Once the user chooses a finding, enter a deep investigation loop.

For the chosen finding:

Re-read all relevant files.
Trace all important callers.
Trace all important implementations.
Inspect related tests.
Inspect relevant git history.
Inspect migrations/configuration if relevant.
Identify hidden dependencies.
Identify invariants.
Identify failure modes.
Identify alternative architectural shapes.

Then present:

Current shape
      ↓
Actual problem
      ↓
Root cause
      ↓
Constraints
      ↓
Possible architectural shapes

Do not jump straight to code.

38. Decision Grilling

Once the problem is sufficiently understood, challenge the proposed direction.

Ask questions such as:

Who owns this concept?
Who should own this invariant?
What knowledge should cross this seam?
What should the caller be allowed to know?
What happens when the operation fails halfway through?
What happens during retries?
What happens if two workers execute concurrently?
What happens if the external dependency is unavailable?
What would a test need to construct?
Which module should change if this schema changes?
Which module should change if this business rule changes?
Can this module be understood without reading its callers?
What complexity disappears behind the proposed seam?
Does the seam create locality or merely move code?
Does this abstraction have enough depth to justify itself?
What happens if the proposed abstraction is deleted?
What assumptions are currently implicit?
Which existing behavior must remain unchanged?

Be adversarial about architecture, not about the user.

39. Design Alternatives

When a meaningful architectural decision is reached, produce at least two plausible designs when the problem warrants it.

For each:

Design A
- Ownership
- Seam
- Dependencies
- Transaction behavior
- Testing surface
- Failure behavior
- Migration cost

Design B
- Ownership
- Seam
- Dependencies
- Transaction behavior
- Testing surface
- Failure behavior
- Migration cost

Do not declare a winner automatically.

Explain the tradeoffs and let the user choose unless one option violates an explicit system constraint.

40. Implementation Only After Agreement

Once the architectural shape is agreed upon:

Define the smallest change set.
Identify affected modules.
Identify migration strategy.
Identify compatibility concerns.
Identify tests that should survive unchanged.
Identify new tests required by the new seam.
Implement incrementally.
Run relevant tests.
Review the resulting dependency graph.
Verify that the original problem actually disappeared.

The final question should be:

Did we remove complexity, or merely move it?

Core Principles

Throughout the investigation use these principles:

1. Follow ownership

A module should own the knowledge required to change its concept.

2. Protect locality

A change to one concept should require changes in as few unrelated places as possible.

3. Interfaces are test surfaces

An interface is valuable when it allows meaningful behavior to be tested independently.

4. Abstraction must hide complexity

An abstraction that merely forwards calls is not automatically useful.

5. Prefer deep modules

A good module hides substantial complexity behind a relatively small conceptual surface.

6. Do not abstract hypothetical futures

Look for real pressure in the existing system.

7. History is evidence

Repeated changes and bug fixes reveal architectural pressure.

8. Runtime behavior matters

Static structure alone cannot explain distributed systems, queues, transactions, concurrency, or failure.

9. Don't confuse unfamiliar with wrong

Unusual architecture is not automatically bad architecture.

10. Don't refactor for aesthetics

Every proposed architectural change must connect to a concrete problem.

11. Preserve working complexity

Do not destroy useful complexity merely because it looks sophisticated.

12. Prefer deletion when possible

If an abstraction does not buy meaningful locality or leverage, consider whether it should exist at all.

Final Standard

A successful run should leave the user thinking:

"This actually studied my codebase."

Not:

"It gave me a list of generic architecture tips."

Every major finding should be defensible by pointing at the repository and explaining:

Here is what the system does.
Here is where that behavior actually lives.
Here is where ownership becomes unclear.
Here is the coupling this creates.
Here is the evidence that this is already causing friction.
Here is what future change will become harder.

Do not invent architecture problems to make the report look impressive.

A report with three deeply investigated findings is better than a report with thirty shallow ones.


### One thing I'd specifically keep from your existing skill

Your existing `improve-codebase-architecture` is more of a **deepening/refactoring skill**. I'd keep this one separate as an **audit/investigation skill**:

```text
deep-codebase-architecture-audit
             │
             │ finds problems
             ▼
improve-codebase-architecture
             │
             │ explores deepening opportunities
             ▼
grilling
             │
             │ makes architectural decisions
             ▼
implementation
````
