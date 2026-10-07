# Product Security Engineer Take-Home: Federated Identity

> ⚠️ Feel free to use AI. Understand what each line of the code does though.
> 

Congrats on making it this far in the interview process! 🎉
Here is a take-home task for you to show us where you shine the most 🙂🚀

## The problem

Build the identity layer that several applications trust to identify a user. You'll stand up an Identity Provider (IDP) and at least two relying applications (Service Providers, SPs). A user signs in once at the IDP, and each SP establishes an authenticated session for that user off that sign-in.

## What we're evaluating

You'll use AI for this. Everyone does, and we want to see how you work with it. We're not checking whether you can implement an auth protocol; pick a vetted one and let the model scaffold it.

We're looking at three things:

1. Whether you can assemble several services into a system that holds up against an adversary.
2. How you handle the decisions the protocol leaves to you: key management and rotation, SP onboarding, compromise containment, session lifecycle.
3. Your scoping. This is your stage: pick the work where you can do something strong, build it well, and own what you set aside.

## Scope and time

Plan on roughly several hours: most of it scoping and then building with AI, the rest on a short writeup and a demo video. Pick the properties you think matter most and build them to a standard you'd defend in a review.

What you ship has to be genuinely secure and well done. This is your choice on where to shine, and your chance to show off your ability. It is completely fine to set conscious scope cuts where necessary — just like in a real project. Just make sure to reason that decision well.

## What to build

An IDP and at least two SPs, running as separate services that authenticate each other over the network. A user authenticates at the IDP; each SP ends with an authenticated session it can justify.

Make it straightforward for us to bring the system up, and tell us how in the README.

You choose the protocol and the libraries. Use vetted libraries for the protocol and the crypto primitives. Don't write your own signing, or crypto. Build the system like you would in a real application.

## Possible features

Pick at least two and build them well. You can also propose your own, as long as it adds real security value.

1. **Cross-SP integrity.** An artifact issued for one SP is useless at any other SP, and at the IDP.
2. **Mutual authentication and onboarding.** The IDP and each SP authenticate each other, and a new SP can be onboarded without redeploying the IDP.
3. **Signing-key rotation without downtime.** The IDP rotates its signing key live. Artifacts issued before a rotation keep verifying until they expire.
4. **Compromise containment.** When a signing key or an SP is compromised, you can contain the blast radius. Build at least one containment path.
5. **Session lifecycle.** Sessions begin, expire, and can be ended, and logout or revocation actually takes effect.
6. **Persistence.** Keys, registered SPs, and sessions survive a restart of any single service. Secrets are handled deliberately at rest.

## Optional extensions

If your chosen properties are solid and you have time, range is welcome: single logout across SPs, refresh and re-authentication, step-up auth, a CI gate that fails on a real finding, or a defense against a specific attack you think matters.

## Code standards (not optional)

- Python, FastAPI, Pydantic, fully async.
- Multiple services that run as separate processes and talk over the network. Easy for us to start; a compose file is welcome but not required.
- Typed throughout. API, service, and persistence layers kept separate. No hardcoded HTTP status codes or secrets.
- Seeded users and at least two SPs. No production user directory or polished login UI required.

## Writeup

A short README:

1. **What you built and what you cut, up front.** Which properties, which you skipped, and why.
2. **Key decisions.** How your services trust each other, your key and session model, and the one or two calls you're least sure about.
3. **Threat model.** The adversaries you weighed and the residual risk you're accepting, with a quick data-flow sketch. Hand-drawn or mermaid is fine.
4. **AI usage.** Where it helped, where it was wrong, and how you caught it.

## Submission

A GitHub repo with the code, README, and a demo video walking us through the application and one of your major architectural decisions.