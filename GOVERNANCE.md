# Governance

This document describes the governance structure, roles, and decision-making processes for the Arbitus project.

## Table of Contents

- [Project Status](#project-status)
- [Roles and Responsibilities](#roles-and-responsibilities)
- [Decision Making](#decision-making)
- [Becoming a Maintainer](#becoming-a-maintainer)
- [Voting](#voting)
- [Code of Conduct](#code-of-conduct)
- [Security Disclosures](#security-disclosures)
- [Changes to Governance](#changes-to-governance)

---

## Project Status

Arbitus is currently in the **early adoption phase** with a single founder/maintainer. As the community grows, this governance document will evolve to include additional maintainers and more formalized processes.

The goal is to transition to a **community-governed project** as contributors demonstrate sustained involvement and expertise.

---

## Roles and Responsibilities

### Contributor

Anyone who submits pull requests, reports issues, or participates in discussions.

**Responsibilities:**
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md)
- Adhere to the [Contributing Guidelines](CONTRIBUTING.md)
- Submit well-documented issues and pull requests
- Respond to feedback on their contributions

**Privileges:**
- Credit in release notes and commit history
- Recognition in the contributors list
- Ability to propose features and suggest direction

### Maintainer

Individuals with commit access who are responsible for the project's direction, code quality, and community health.

**Current Maintainers:**

| Name | GitHub | Affiliation | Focus Areas |
|------|--------|-------------|-------------|
| Natan Velten | [@nfvelten](https://github.com/nfvelten) | Independent | Architecture, Security, Core |

**Responsibilities:**
- Review and merge pull requests
- Triage issues and set priorities
- Ensure code quality and test coverage
- Maintain backward compatibility
- Respond to security issues promptly
- Participate in project direction discussions
- Mentor new contributors
- Keep documentation up to date

**Time Commitment:**
Maintainers are expected to spend at least **4-8 hours per week** on project activities, including:
- Code review and PR management
- Issue triage
- Community engagement (Discord, discussions)
- Release management

**Privileges:**
- Commit access to the repository
- Ability to merge pull requests
- Vote on project decisions
- Represent the project in public communications
- Access to project infrastructure (CI/CD, secrets)

---

## Decision Making

### Types of Decisions

| Decision Type | Process | Timeframe |
|---------------|---------|-----------|
| **Minor changes** (bug fixes, docs, refactor) | Lazy consensus | Immediate mergeafter review |
| **Features** (new capabilities) | Maintainer consensus via issue/PR | 1-2 weeks discussion |
| **Breaking changes** | 2/3 maintainer approval | 2 weeks minimum discussion |
| **Governance changes** | 2/3 maintainer approval | 2 weeks minimum discussion |
| **Security issues** | Private discussion among maintainers | Immediate |

### Lazy Consensus

For minor changes, maintainers may proceed without explicit approval from all maintainers if:
- The change is non-controversial
- At least one other maintainer has reviewed and approved
- No maintainer has raised objections within **3 business days**

If an objection is raised, the proposal moves to formal discussion.

### Proposal Process

For larger changes (features, breaking changes, governance):

1. **Issue First**: Open a GitHub issue describing the proposal
2. **Discussion**: Allow community feedback for **1-2 weeks**
3. **Decision**: Maintainers vote or reach consensus
4. **Documentation**: Record the decision in the issue/PR
5. **Implementation**: Proceed with accepted changes

---

## Becoming a Maintainer

### Path to Maintainership

Maintainers are selected from active contributors who have demonstrated:

1. **Sustained Contribution**
   - At least **10 significant pull requests** merged
   - Active participation in code review
   - Contributions across multiple areas (code, docs, tests)

2. **Technical Expertise**
   - Deep understanding of Arbitus architecture
   - Ability to review complex changes independently
   - Knowledge of security implications

3. **Community Engagement**
   - Helpful responses to issues and discussions
   - Mentorship of new contributors
   - Adherence to Code of Conduct

4. **Alignment with Project Values**
   - Security-first mindset
   - Backward compatibility commitment
   - Quality over speed

### Nomination Process

1. An existing maintainer nominates a contributor via a private Slack channel or GitHub discussion
2. Maintainers discuss the nominee's contributions and fit
3. Vote is held (see [Voting](#voting))
4. If approved, the nominee is contacted with an invitation

### Onboarding

New maintainers will:
1. Be added to the `MAINTAINERS.md` file
2. Receive commit access to the repository
3. Be added to the maintainers Slack/Discord channel
4. Review the [Maintainer Responsibilities](#maintainer) section

---

## Voting

### When Voting is Required

- Adding new maintainers
- Removing maintainers (inactivity or detrimental behavior)
- Breaking changes to public APIs
- Governance modifications
- Resolving disputes that cannot reach consensus

### Voting Process

1. A maintainer calls for a vote in the appropriate channel
2. Each maintainer votes: **YES**, **NO**, or **ABSTAIN**
3. Voting period lasts **5 business days**
4. Results are recorded publicly (for public decisions)

### Approval Criteria

| Decision Type | Approval Threshold |
|---------------|---------------------|
| New maintainer | Majority YES, zero NOvotes |
| Breaking change | 2/3 of maintainers |
| Governance change | 2/3 of maintainers |
| Maintainer removal | 2/3 of maintainers |

### Company Affiliation Limit

To ensure diverse representation, no single company may hold more than **50% of maintainer votes**. If a company's representation exceeds this limit during voting, votes are proportionally adjusted.

---

## Code of Conduct

All contributors and maintainers must adhere to the [CNCF Code of Conduct](https://github.com/cncf/foundation/blob/main/code-of-conduct.md).

### Enforcement

Code of Conduct violations will be handled by maintainers. For serious violations involving maintainers, the matter will be escalated to the CNCF Code of Conduct Committee.

### Reporting

Report violations to:
- Email: conduct@arbitusgateway.dev (once created)
- Or privately to any maintainer

---

## Security Disclosures

Security is a core focus of Arbitus. We take all security issues seriously.

### Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities.

Instead, report security issues privately via:
- GitHub Security Advisories: [github.com/arbitusgateway/arbitus/security/advisories](https://github.com/arbitusgateway/arbitus/security/advisories)
- Email: security@arbitusgateway.dev (once created)

### Security Response Process

1. **Acknowledgment**: Within **24 hours**
2. **Triage**: Within **3 business days**
3. **Fix Development**: Depends on severity
   - Critical: 1-3 days
   - High: 1 week
   - Medium/Low: 2 weeks
4. **Disclosure**: After fix is released, following responsible disclosure timeline

### Security Advisory Team

Maintainers with commit access are part of the security response team. Additional contributors may be added for specific expertise.

---

## Changes to Governance

### Process

1. Open a GitHub issue titled "Governance Change: [description]"
2. Allow **2 weeks** for community discussion
3. Maintain a vote requiring **2/3 approval**
4. Update GOVERNANCE.md via pull request

### Editorial Changes

Minor editorial changes (typos, clarifications, link updates) can be made via lazy consensus without formal voting.

---

## Project Resources

### Communication Channels

- **GitHub Issues**: Bug reports, feature requests
- **GitHub Discussions**: General questions, ideas
- **Discord**: [Arbitus Community](#) (once created) - Real-time discussion

### Roadmap

The project roadmap is maintained in GitHub Projects/Milestones and updated quarterly. Maintainers may propose roadmap items, and community input is welcome.

### Release Cadence

- **Patch releases** (x.y.Z): As needed for bug fixes
- **Minor releases** (x.Y.z): Monthly for features
- **Major releases** (X.y.z): Breaking changes, as needed

---

## Acknowledgments

This governance document is based on best practices from:
- [CNCF Project Template](https://github.com/cncf/project-template)
- [Envoy Governance](https://github.com/envoyproxy/envoy/blob/main/GOVERNANCE.md)
- [Cilium Governance](https://github.com/cilium/community/blob/main/GOVERNANCE.md)
- [Open Source Guides](https://opensource.guide/leadership-and-governance/)

---

## License

This document is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).