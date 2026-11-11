# Data that leaves the platform

What ShipBrace sends to outside services, what users must be told, and what the
product already does about it. Written 2026-10-01.

**This is not legal advice.** It records the reasoning behind the product's
choices. Have a lawyer review it, and the privacy policy text below, before
real users sign up, and again for each country you launch in.

## 1. Known flaws in packages: OSV.dev

**What is sent.** The names and exact versions of the public npm packages an
app installs, read from its lockfile. Nothing else: no code, no file names, no
private package names (a private package's name can itself be confidential, so
anything not installed from the public npm registry is never sent).

**Who receives it.** OSV.dev, a free public database run by Google's
open-source security team.

**What the law and the data's licence require, and what the product does.**

| Obligation | Why | What the product does |
| --- | --- | --- |
| Credit the source of the flaw data | Much of OSV's npm data comes from the GitHub Advisory Database under the CC-BY 4.0 licence, which requires attribution wherever the data is shown | Every result shows the notice: OSV.dev, GitHub Advisory Database, CC-BY 4.0 (`OSV_NOTICE`). It shows on the checklist item whether or not anything was found |
| Tell users what leaves their system | Transparency is required by most privacy laws (for example GDPR Articles 13–14) when personal data is involved, and is expected in any case by customers handing over their code. Package names are usually not personal data, but a lockfile can occasionally reveal something about a person or company | The notice on the item says what was sent and to whom, on every review |
| Tell users **before** the first send | A notice after the fact informs; it does not let someone decline | **Not built yet** — there is no sign-up flow. When sign-up is built, it must show this disclosure before the first review runs (see section 4) |
| Let users decline | Good practice, and required in some contracts | A switch per GitHub account or organisation (Settings on app.shipbrace.com, built 2026-10-10); `PACKAGE_LOOKUP=off` turns it off for everyone |
| Name the service in the privacy policy | Privacy policies must list the outside services personal data may go to | Draft text in section 5 |

## 2. The AI step: the model provider

**This is the bigger one.** When the AI step is switched on, excerpts of the
user's source code are sent to the model provider (today, Anthropic's API) so
the model can suggest where to look. Source code can contain personal data,
trade secrets, and occasionally credentials (the platform redacts secrets it
recognises before sending, but cannot promise to catch all of them).

**The AI also reads the app's own cleaning functions (added 2026-11-10).**
When a visitor's value passes through a function the app wrote itself to make
it safe, on the way to something dangerous, that function's code (at most
4,000 characters each, at most 30 functions per review, recognised secrets
removed) and the one line it feeds are sent to the same provider, and the
model is asked whether the function really protects that line. This is the
one place where what the model says changes the report directly, so users
must be told both things:

- If the model says a function does not work, the automated rules trace the
  path again without it, and only a path that is then open is reported, as
  "needs fixing", worded as the AI's reading.
- If the model says a function works, a finding the rules would have reported
  is listed as "worth a look" instead. It is never removed, never shown as
  passed, and the GitHub check is then neutral rather than green.

It runs under the same switch and for the same people as the rest of the AI
step (today: the owner's account only), has its own deployment switch
(`AI_CLEANER_CHECK`), and uses a smaller model from the same provider.

| Obligation | What the product does |
| --- | --- |
| Tell users their code is sent to an AI provider, and which one | Said in the notices before the first review and beside the switch (app.shipbrace.com, Settings), including that the AI reads the app's own cleaning functions. Still to do before opening up: name it in the privacy policy |
| Tell users when the report says something because of the AI | Each such finding names the function and says an AI read it; the report's footer says how many functions were read and what changed, or that the AI did not run |
| Let users decline | The review works with no AI at all; the AI step only runs when a key is configured. Needs to become a per-user choice |
| A data processing agreement with the provider | Needed if users' code contains personal data and you serve users under GDPR or similar laws. Anthropic offers one for API customers; sign it before launch |

## 3. What is never sent

- Repository contents to anyone other than the AI provider above, and only
  when the AI step is on.
- Private package names, to anyone.
- Secrets the platform recognises: they are redacted before any finding exists.

### What is kept (added 2026-10-09)

Not sent anywhere, but stored, so the privacy policy must cover it. With a
database configured, every review of a GitHub push is kept: the repository's
name and owner, the commit, and the full review, which includes short
excerpts of the code around each finding (redacted as above). Nothing is
deleted yet. Until sign-in exists, a kept review is reached by an unguessable
link that only the GitHub check shows; anyone that link is passed to can
read it.

## 4. Before launch: checklist

1. Show both disclosures (sections 1 and 2) during sign-up, before the first
   review, with a way to turn each off.
2. Make both switches per-user settings, not only server settings.
3. Publish a privacy policy that includes section 5.
4. Sign the AI provider's data processing agreement.
5. Have a lawyer review this page and the policy.
6. Decide how long kept reviews are stored, delete them after that, and
   delete a repository's reviews when the App is uninstalled from it. Put
   kept reviews behind sign-in.

## 5. Draft privacy policy text

> **Outside services we use to check your app**
>
> *Known flaws in packages.* To tell you whether any package your app uses has
> a publicly known security flaw, we send the names and versions of your
> app's public packages to OSV.dev, a free database run by Google. We do not
> send your code, your file names, or the names of private packages. You can
> turn this off in your settings. Flaw information comes from OSV.dev and the
> GitHub Advisory Database and is used under the Creative Commons Attribution
> 4.0 licence.
>
> *AI-assisted review.* If you turn on AI-assisted review, parts of your
> app's source code are sent to Anthropic, which provides the AI model, so it
> can suggest places to check. It also reads any functions your app wrote
> itself to clean visitors' input, and says whether each one really protects
> the place it is used. What the AI says about those functions can add a
> finding to your report or move one to "worth a look"; either way the report
> says it is the AI's reading, and it never marks anything as passed.
> Anthropic processes this data under our agreement with them and does not
> use it to train its models. [Confirm against the current Anthropic
> commercial terms before publishing.] You can use the security review
> without this feature.
