# Android-to-Windows feature map

## Classification

- **Foundation**: domain contract, UI placeholder, or architectural boundary exists now.
- **Read-only discovery**: safe observation without system changes.
- **User-mode implementation**: future implementation that must satisfy transactional safety without a kernel driver.
- **Advanced WFP**: future Windows Filtering Platform work requiring a dedicated design and approval.
- **Private Browser**: future isolated browser work; no browser engine is selected in this phase.
- **Deferred WDK/kernel work**: explicitly outside the current roadmap until separately justified and approved.

| Android capability | Windows mapping | Classification | Foundation status and future boundary |
|---|---|---|---|
| App Connection Lock | Program Connection Lock | Foundation → User-mode implementation → Advanced WFP | Policies and UI exist; enforcement is inactive. WFP is separately gated. |
| Standard, High, Extreme, Custom levels | Protection modes and profiles | Foundation → User-mode implementation | Models and validation exist; no engine applies them. |
| Encrypted DNS and system-wide blocking | DNS Protection and system policy | Foundation → Read-only discovery → User-mode implementation → Advanced WFP | DNS read-only discovery exists; no DNS or blocking setting changes. |
| Compatibility Guard | Program compatibility exclusions and recovery | Foundation → User-mode implementation | Exclusion models exist; future changes require rollback. |
| Wi-Fi/mobile transition protection | Wi-Fi/Ethernet/cellular transition handling | Read-only discovery → User-mode implementation | Adapter type discovery exists; cost and transition enforcement are deferred. |
| Mobile Data Watch | Metered and Cellular Data Watch | Foundation → Read-only discovery → User-mode implementation | UI exists; cost classification and quotas are deferred. |
| Aggressive App Watch | Aggressive Program Watch | Foundation → User-mode implementation → Advanced WFP | Placeholder only; no process or traffic monitoring. |
| Schedules | Protection schedules | Foundation → User-mode implementation | Cross-midnight schedule contracts and validation exist. |
| Parent and child controls | Parent-protected settings and child policy | Foundation → User-mode implementation | Approval contracts exist; no credentials or remote control. |
| Allowlist and blocklist | Program/destination allowlist and blocklist | Foundation → User-mode implementation → Advanced WFP | UI and policy boundary exist; no rules are installed. |
| Protection statistics | Activity and Statistics | Foundation → User-mode implementation | Empty counters exist; the UI shows no fake data. |
| Optional request logging | Privacy-controlled activity logging | User-mode implementation | Deferred pending retention, redaction, consent, and export design. |
| Low-noise notifications | Notification priorities and native notifications | Foundation → User-mode implementation | Priority model exists; native notification delivery is deferred. |
| Boot/startup recovery | User-approved startup and last-known-good recovery | Foundation → User-mode implementation | Contracts exist; no startup entry is created. |
| Battery and performance modes | Power-aware protection modes | Read-only discovery → User-mode implementation | Placeholder exists; battery discovery is not implemented. |
| Secure Website Protection | Browser and destination safety signals | User-mode implementation → Private Browser | Deferred; no traffic interception or browser integration. |
| Private Browser/incognito isolation | Private Browser | Private Browser | UI placeholder only; WebView2 and browser architecture require later approval. |
| Fullscreen video gestures | Private Browser media controls | Private Browser | Deferred with browser implementation. |
| Automatic Skip-button handling | Private Browser accessibility automation | Private Browser | Deferred; must be opt-in, transparent, and site-compatible. |
| File Safety | File Safety | Foundation → User-mode implementation | UI placeholder only; no scanning or file mutation. |
| Signed updates and rollback | Verified update channel and rollback | Foundation → User-mode implementation | Documentation boundary exists; no updater or installer is built. |
| Automatic protection-list updates | Signed policy-list refresh | User-mode implementation | Deferred pending authenticity, rollback, privacy, and failure design. |
| Universal licensing | Shared Android/Android TV/Windows licence | Foundation → User-mode implementation | Three-device pool and trial contracts exist; no server communication. |
| Kernel enforcement from future requirements | Dedicated driver phase | Deferred WDK/kernel work | No WDK, driver, signing, installation, or kernel code is present. |
