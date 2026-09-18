# First Commit Hackathon — Judging Criteria & Constraints

**Event:** First Commit (Event 01 of the Bharat Builds Tour) — WeMakeDevs × AWS
**Dates:** September 17–20, 2026 (Thu–Sun), online across India, with an optional in-person day Saturday Sept 19 (8 AM–8 PM) at Polaris School of Technology, Bangalore
**Source:** wemakedevs.org/aws/first-commit (and its /schedule page), as published as of September 10, 2026

---

## 1. Judging Criteria

The event lists five criteria that judges use to choose winners. No numeric weighting is published for any of them — treat all five as equally load-bearing.

### 1. Idea and Impact
> "The theme is open, so the problem is yours to find. Does it solve a real problem? And what changes for the people on the other side of it? A small problem solved well beats a big one solved vaguely."

- The theme itself is **open** — no fixed category to build within.
- Judges are explicitly told to value a **small, well-solved problem over a large, vaguely-solved one**.
- The test is stated as "what changes for the people on the other side of it" — i.e., real-world use case and who actually benefits.

### 2. Built on AWS
> "There are two tracks. Build It runs on the open-source stack on your own machine, and Ship It runs on AWS services, which is where the grand prize is decided. Selected teams that want to deploy get credits from us to do it. **Using an AWS open-source project or AWS services is mandatory to win a prize.**"

- This is a **hard requirement**, not just a scoring factor — a project that doesn't use AWS (open-source stack or managed services) cannot win a prize at all, regardless of the other four criteria.
- For **Ship It**: real AWS services are used, and "architecture and cost decisions are part of the work" — i.e., *how* you used AWS (service choices, cost-consciousness) is itself scored, not just the fact that you deployed.
- For **Build It**: the open-source AWS stack must be used (Strands Agents SDK, PartyRock, Cedar, SAM CLI + LocalStack, OpenSearch, Firecracker, Corretto, etc.) — this is the AWS-usage requirement satisfied without an AWS account.
- Local projects and deployed projects are stated to be **"scored with the same care"** — Build It is not treated as a lesser track — **except** that cloud usage (architecture/cost judgment) is only scored within Ship It, since that's the only track where those decisions exist.

### 3. Learning
> "Four days should leave you knowing something you didn't on Thursday: a first deploy, a first agent, a service you had never touched. **Tell us what you learned, and it counts towards your score.**"

- This is scored on what you **report having learned**, not just implicitly inferred by judges — meaning the submission needs an explicit statement of what was new.
- Examples given: a first deployment, a first AI agent, a first time touching a particular AWS service.
- Framed as something that should genuinely happen over the four days — not prior knowledge restated.

### 4. The Execution
> "Does it work? Not perfect, not polished. Working. **One feature that runs beats five that almost do.**"

- Functionality is explicitly prioritized over completeness or polish.
- A narrow, reliably-working scope is stated to score **better** than a broad, half-working one.

### 5. The Demo Video
> "Three minutes, recorded, to show what it does, who it is for, and where AWS fits. **There is no live demo, so the video is what the judges see.**"

- Exactly what the video must cover: (a) what the product does, (b) who it's for, (c) where/how AWS fits in.
- **No live demo exists in this event** — the recorded video is the entire basis for judges seeing the product work. If it's not shown clearly in the video, judges don't see it at all.
- Length is specified as three minutes (a maximum/target, not "at least").

### Additional judging notes (stated separately from the five criteria)
> "We judge what you built, not what you spent. Local projects and deployed projects are scored with the same care. Cloud usage counts only in Ship It, where architecture and cost decisions are part of the work. Best UI is judged on design and usability."

- **Spend is not a judging factor** — a lower-cost or free-tier Ship It build isn't penalized relative to one that used more.
- **Build It vs Ship It parity** is explicitly stated on the four core criteria; the *architecture/cost* dimension inside "Built on AWS" is Ship-It-only by nature.
- **Best UI** (a separate prize, not one of the five main criteria) is judged purely on **design and usability**, independent of which track the project came from.

---

## 2. Constraints & Rules

### Eligibility
- Open to **university students across India** only.
- Student status must be **verified through the AWS Builder Center** (a free, ~2-minute signup, no credit card required).

### Team
- Team size: **1 to 4 people**.
- Registration and participation are **free**.
- Teams can be formed via the WeMakeDevs Discord before or during the event if you don't already have one.

### Format
- **Fully hybrid**: an online track (Thu–Sun, accessible from anywhere in India) and an **optional** in-person day.
- In-person component: **Saturday Sept 19 only**, 8 AM–8 PM, at Polaris School of Technology, Bangalore — limited seats, requires a **separate Luma signup**.
- Explicitly stated: **"The Bangalore day is optional and has limited seats, and being there doesn't add to your score."** In-person attendance gives workshops, project feedback, and swag — not a judging advantage.
- Fully-online participants get the **same theme, same judging, and same prizes**, with **no cap on numbers**.

### No pre-event building
- **"Project work starts when the clock does."** Learning and practicing the tools beforehand is allowed and encouraged (workshops run the week before); writing the actual project code before the event officially starts is not.

### Track-specific hard requirements

**Build It (open-source, local)**
- Must run using the open-source AWS stack: Strands Agents SDK, PartyRock, Cedar, SAM CLI + LocalStack, OpenSearch, Firecracker, Corretto.
- **No AWS account required. No credit card required. No bill.**

**Ship It (AWS deployed)**
- Must be **deployed live on AWS** and submitted with a **public URL**.
- Requires an **AWS account** — a debit card or RuPay card is accepted for verification, with an approximate **₹2 verification charge**.
- Architecture and cost decisions are explicitly part of the score for this track (see Judging Criteria §2 above).

### AWS credits
- Every **registered participant** gets **$100 in AWS credit** on top of the standard AWS free tier, redeemable at registration.
- This is separate from any additional prize credits (Ship It winner: $3,000; Build It winner: $1,000–2,000 range; runner-ups: $1,000 each — see prize section of the event page for exact current figures, as these can be updated by organizers).
- Credits are intended to **cover the weekend's usage** for the Ship It track.

### Submission requirements
Mandatory:
1. A working project (either track).
2. A **three-minute recorded demo video** — no live demos are judged.
3. Documentation of the **problem, stack, and challenges** faced.
4. **Ship It only:** a public URL to the deployed application.
5. **Ship It only:** architecture documentation that includes cost considerations.
6. A **learning statement** — what the team learned during the event.

Optional (but tied to a separate prize):
- A blog post published on the **AWS Builder Center**, explaining the problem, stack, and challenges, with the post **linked in the submission**. Top 5 blog posts win a prize.

### Certificates
- **Every team that submits a project** receives a participation certificate.
- Winning teams receive additional certificates.

### Prior knowledge
- No prior AWS experience is required to participate — workshops run the week before the event, and the Build It track needs no AWS account at all.

### What's *not yet* published (as of Sept 10, 2026)
The event's own schedule page states:
> "The hours are being finalised: the kickoff call, mentor sessions, and the deadline the clock stops on. They land on this page first, and everyone registered is told the same day."

Specifically still unpublished:
- Exact kickoff time/date
- Exact submission deadline time
- Workshop and mentor-session times
- Judging period and results-announcement time
- Detailed Saturday in-person agenda beyond the 8 AM–8 PM window

**Recommendation:** re-check `wemakedevs.org/aws/first-commit/schedule` and the event Discord closer to Sept 17 for these exact hours, since "everyone registered is told the same day" they're announced.

---

## 3. Quick-reference judging checklist

Use this as a submission self-check — each line ties back to a specific criterion or constraint above.

- [ ] Solves one **specific**, real problem (not a vague category) — *Idea & Impact*
- [ ] Uses either the AWS open-source stack (Build It) or real AWS services (Ship It) — **mandatory to win any prize** — *Built on AWS*
- [ ] Ship It only: architecture and cost decisions are documented and defensible — *Built on AWS*
- [ ] Explicit "what we learned" statement included in the submission — *Learning*
- [ ] Core feature(s) actually work end-to-end, even if scope is narrow — *Execution*
- [ ] 3-minute video covers: what it does, who it's for, where AWS fits — *Demo Video*
- [ ] Video is the *only* thing judges see work — nothing critical is left for a live demo — *Demo Video*
- [ ] Ship It only: public URL included and reachable — *Submission requirement*
- [ ] Problem/stack/challenges documentation included — *Submission requirement*
- [ ] AWS Builder Center profile + student verification completed — *Eligibility*
- [ ] (Optional) Blog post published on AWS Builder Center and linked in submission — *Blog prize*
