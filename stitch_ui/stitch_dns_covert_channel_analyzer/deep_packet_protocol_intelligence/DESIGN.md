---
name: Deep Packet & Protocol Intelligence
colors:
  surface: '#0e1321'
  surface-dim: '#0e1321'
  surface-bright: '#343948'
  surface-container-lowest: '#090e1c'
  surface-container-low: '#161b2a'
  surface-container: '#1a1f2e'
  surface-container-high: '#252a39'
  surface-container-highest: '#303444'
  on-surface: '#dee2f6'
  on-surface-variant: '#bbc9cf'
  inverse-surface: '#dee2f6'
  inverse-on-surface: '#2b303f'
  outline: '#859399'
  outline-variant: '#3c494e'
  surface-tint: '#47d6ff'
  primary: '#a5e7ff'
  on-primary: '#003543'
  primary-container: '#00d2ff'
  on-primary-container: '#00566a'
  inverse-primary: '#00677f'
  secondary: '#aec6ff'
  on-secondary: '#002e6b'
  secondary-container: '#508eff'
  on-secondary-container: '#00275e'
  tertiary: '#b8e3ff'
  on-tertiary: '#00354a'
  tertiary-container: '#6bccff'
  on-tertiary-container: '#005575'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#b6ebff'
  primary-fixed-dim: '#47d6ff'
  on-primary-fixed: '#001f28'
  on-primary-fixed-variant: '#004e60'
  secondary-fixed: '#d8e2ff'
  secondary-fixed-dim: '#aec6ff'
  on-secondary-fixed: '#001a43'
  on-secondary-fixed-variant: '#004397'
  tertiary-fixed: '#c4e7ff'
  tertiary-fixed-dim: '#7bd0ff'
  on-tertiary-fixed: '#001e2c'
  on-tertiary-fixed-variant: '#004c69'
  background: '#0e1321'
  on-background: '#dee2f6'
  surface-variant: '#303444'
typography:
  display-lg:
    fontFamily: Plus Jakarta Sans
    fontSize: 36px
    fontWeight: '700'
    lineHeight: 44px
  headline-lg:
    fontFamily: Plus Jakarta Sans
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
  headline-lg-mobile:
    fontFamily: Plus Jakarta Sans
    fontSize: 20px
    fontWeight: '600'
    lineHeight: 28px
  headline-md:
    fontFamily: Plus Jakarta Sans
    fontSize: 18px
    fontWeight: '600'
    lineHeight: 24px
  headline-sm:
    fontFamily: Plus Jakarta Sans
    fontSize: 15px
    fontWeight: '600'
    lineHeight: 20px
  body-lg:
    fontFamily: Inter
    fontSize: 15px
    fontWeight: '400'
    lineHeight: 22px
  body-md:
    fontFamily: Inter
    fontSize: 13px
    fontWeight: '400'
    lineHeight: 18px
  body-sm:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 16px
  label-mono-lg:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '500'
    lineHeight: 18px
  label-mono-md:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '500'
    lineHeight: 16px
  label-mono-sm:
    fontFamily: JetBrains Mono
    fontSize: 10px
    fontWeight: '400'
    lineHeight: 14px
  label-sans-caps:
    fontFamily: Inter
    fontSize: 10px
    fontWeight: '700'
    lineHeight: 12px
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  gutter: 0.75rem
  gutter-desktop: 1rem
  margin: 0.75rem
  margin-desktop: 1.5rem
  space-xs: 0.25rem
  space-sm: 0.5rem
  space-md: 0.75rem
  space-lg: 1rem
  space-xl: 1.5rem
---

## Brand & Style

This design system sets the visual, structural, and behavioral foundations for an advanced DNS steganography and covert channel analysis environment. The experience balances deep institutional utility with tactical visual modernism—evoking the surgical precision of Wireshark integrated into the telemetry richness of modern SOC dashboards like Cloudflare Radar and Datadog Network Performance Monitoring.

### Aesthetic Foundation & Design Movement
The interface operates under a **Technical Dark Glassmorphism** aesthetic combined with high-density data architectures:
- **Optical Precision:** Semi-translucent layered obsidian surfaces grounded against deep cosmic navy canvases.
- **Luminescent Telemetry:** Targeted 1px gradient borders, directional highlights, and soft, restrained emissive glows indicate active protocol streams, anomalies, and payload exfiltration vectors.
- **Density & Legibility:** Maximized screen real-estate utilization via compact vertical spacing, high data-to-ink ratios, and split viewports designed for concurrent timeline monitoring, byte inspection, and entropy distribution.

### Emotional Target & Audience
The platform addresses security researchers, SOC analysts, and university networks students. The interface communicates:
- **Authoritative Control:** Calm, mission-critical stability that eliminates visual fatigue during prolonged live-traffic surveillance.
- **Analytical Clarity:** Instantaneous signal-to-noise separation between legitimate recursive DNS resolutions and covert TXT/CNAME/NULL tunneling signatures.
- **Tactile Responsiveness:** Micro-interactions that mirror network-packet velocity with snappy frame execution, precise cursor feedback, and real-time state changes.

## Colors

The color system delivers high spectral contrast over deep multi-tier navy foundations. Ambient luminescence is strictly functional, reserved for alerting thresholds, protocol tags, and stream flow vectors.

### Surface Canvas Hierarchy
- **Base Canvas (`#0A0F1D`):** Primary viewport substrate, void layer for canvas backdrops and frame isolation.
- **Surface Elevation 1 (`#0D1527`):** Side panels, telemetry sidecars, secondary inspector gutters, and structural dividers.
- **Surface Elevation 2 (`#131E36`):** Floating toolbars, protocol payload cards, tabular record rows, and modal dialogs.
- **Surface Elevated Interactive (`#1E2C4F`):** Hover states, active table selections, and focused node headers.

### Primary Accents & Network Telemetry
- **Electric Cyan (`#00D2FF`):** Dominant focus target, selected packet indicators, active DNS queries, primary CTA elements, and glowing stroke terminals.
- **Protocol Cobalt (`#0070F3`):** Header structural actions, secondary button fills, selected state fills, and standard TCP/UDP stream labels.
- **Sky Signal (`#38BDF8`):** Data-link layer tags, auxiliary graph nodes, micro-metric readouts, and secondary link hovers.

### Semantic Status Colors
- **Delivered / Verified Clean (`#10B981`):** Verified recursive queries, authoritative zone passes, integrity matches, and baseline standard deviation bounds.
- **Heuristic Warning / Anomaly (`#F59E0B`):** Shannon entropy spikes, high-frequency NXDOMAIN bursts, abnormal TXT character distribution, and query rate outliers.
- **Covert Channel / High Threat (`#EF4444`):** Decoded exfiltration payloads, base64/base32 tunneling detection, confirmed malicious nameservers, and kill-switch commands.

### Functional Borders & Glass Tokens
- **Borders Neutral:** `rgba(56, 189, 248, 0.08)` for structural grid divisions.
- **Borders Highlight:** `rgba(0, 210, 255, 0.24)` for active card outlines and focused inputs.
- **Borders Threat Alert:** `rgba(239, 68, 68, 0.36)` with localized `0 0 12px rgba(239, 68, 68, 0.2)` glow for flagged packets.

## Typography

The typographic strategy leverages a dual-engine model: **JetBrains Mono** for low-level protocol structures and forensic inspection, paired with **Inter** and **Plus Jakarta Sans** for ergonomic operational interfaces.

### Typographic Roles
- **Display & Section Headers (`Plus Jakarta Sans`):** Clean, geometric neo-grotesque figures provide modern structural hierarchy at module entry points without feeling decorative.
- **Interface & Operational Text (`Inter`):** Selected for high micro-legibility at 12px and 13px sizes across nested property sheets, documentation annotations, and workflow triggers.
- **Packet & Packet Dump Monospace (`JetBrains Mono`):** Used universally for raw hexadecimal dumps, ASCII translation panes, base32/64 decoded entropy strings, IP 4-tuples, and Shannon metric values. Enables strict tabular column alignment essential for hex-view grid integrity.

### Tabular Formatting
- All numeric readouts, packet counters, TTL counts, and bandwidth bitrates must render using monospaced numeral features (`tnum` / font-variant-numeric: tabular-nums) to prevent horizontal jitter during high-throughput live capture rendering.
- All cap-height alignments in data tables maintain strict 12px or 10px heights to prevent row-height expansion in high-density tables.

## Layout & Spacing

To accommodate complex protocol inspection tools, the layout system relies on a **Dockable Multi-Pane Layout** with dynamic edge anchoring.

### Spatial Grid & Screen Allocation
- **Primary Grid:** 12-column variable fluid grid system optimized for data-dense 1920x1080 and 2560x1440 workstation displays.
- **Docking Structure:**
  - **Left Rail (64px fixed):** Global navigation, simulation controllers, and capture state toggles.
  - **Primary Upper Split (60% default viewport height):** Stream capture packet table, real-time query waterfall, and bandwidth timeline.
  - **Primary Lower Split (40% default viewport height):** Synchronized 3-way forensic split: Protocol Tree breakdown (left), Hexadecimal Raw Wire Dump (center), and Payload Entropy & Anomaly Heuristics (right).

### Responsive Adaptation
- **Desktop (≥ 1280px):** Full simultaneous multi-pane capture and hex breakdown. Horizontal scrolling is prohibited within standard containers; tables utilize strict fixed column definitions with overflow clipping.
- **Laptop / Tablet Landscape (1024px – 1279px):** Inspector tabs switch to stacked segmented panes; the hex inspector moves into a collapsible drawer.
- **Compact Views (< 1024px):** Primarily reserved for simulation summary statistics, node health alerts, and educational tutorial modules. Live multi-packet packet capture reflows into a single vertical card stack with modal inspection.

### Component Spacing Metric
Spacing adheres strictly to a **4px modular rhythm** (`0.25rem`), favoring tight compact intervals (`0.5rem` and `0.75rem`) to maximize visual payload capacity per vertical inch.

## Elevation & Depth

Visual hierarchy uses **Tactile Glassmorphism** layered over deep navy tonal tiers. Traditional dropping drop-shadows are largely abandoned in favor of luminous backdrops and ambient inner glows that simulate illuminated optical control surfaces.

### Elevation Surface Hierarchy
- **Tier 0 (Backdrop Void - `#0A0F1D`):** Non-interactive canvas; hosts the subtle SVG wireframe grid representing the network simulation mesh.
- **Tier 1 (Static Panels - `#0D1527` with 85% opacity):** `backdrop-filter: blur(16px)`. Framed by a continuous 1px outline of `rgba(56, 189, 248, 0.08)`.
- **Tier 2 (Interactive Modules & Cards - `#131E36` with 70% opacity):** `backdrop-filter: blur(20px)`. Receives ambient highlight on its top edge using `linear-gradient(180deg, rgba(0, 210, 255, 0.12) 0%, rgba(0, 210, 255, 0) 100%)`.
- **Tier 3 (Floating Overlays, Payloads & Popovers - `#182442` with 95% opacity):** `backdrop-filter: blur(28px)`. Soft perimeter shadow: `0 8px 32px -4px rgba(0, 0, 0, 0.6), 0 0 0 1px rgba(0, 210, 255, 0.25)`.

### Emissive Glow Tokens
- **Cyan Signal Pulse:** `box-shadow: 0 0 16px rgba(0, 210, 255, 0.18)` used for active sniffing indicators and matching search terms.
- **Threat Vector Warning:** `box-shadow: 0 0 20px rgba(239, 68, 68, 0.22)` reserved for high-probability DNS exfiltration tunnels (e.g., base32-encoded subdomains exceeding 52 characters).
- **Legitimate Stream Affirmation:** `box-shadow: 0 0 12px rgba(16, 185, 129, 0.15)` for authenticated DNSSEC signatures.

## Shapes

The interface adopts a **Surgical Industrial** shape profile. Geometric roundness is kept minimal (`roundedness: 1` / `0.25rem` base) to preserve the sharp, engineered aesthetic typical of mission-critical military and aerospace displays.

### Radius Assignments
- **Micro Tokens (`rounded-sm` / `0.125rem`):** Monospace hex byte cells, inline protocol badges, tabular tag chips, and custom scrollbar thumbs.
- **Base Components (`rounded` / `0.25rem`):** Buttons, text fields, hex view selection bounds, status badges, and tab segments.
- **Structural Modules (`rounded-lg` / `0.5rem`):** Diagnostic panels, payload inspectors, timeline graph wrappers, and modal windows.
- **Maximum Threshold (`rounded-xl` / `0.75rem`):** Floating command palettes and top-level simulation orchestrator headers.

Curved pill shapes (`9999px`) are prohibited except for binary status toggle indicators, preserving structural rectangular alignment throughout dense data views.

## Components

### 1. Packet Table & Live Stream Data Grid
- **Structure:** Monospace-first compact tabular layout with locked 28px row height.
- **Styling:** Alternate zebra rows utilizing `#0D1527` and `#0A0F1D`. Row borders are 1px solid `rgba(255, 255, 255, 0.03)`.
- **Hover & Selected State:** Hover triggers a soft cyan glow accent on the left border (3px solid `#00D2FF`) with a background tint of `rgba(0, 210, 255, 0.05)`. Selected row changes background to `rgba(0, 112, 243, 0.16)` with a persistent 1px inner border.
- **Anomaly Highlighting:** Covert-channel candidate rows display a red left bar (`#EF4444`) with a faint red wash across the record.

### 2. Hexadecimal Wire Inspector & ASCII Decode View
- **Layout:** Three-column view aligned via `JetBrains Mono`: Byte Offset Column (e.g., `0000  0010`), 16-Byte Hex Matrix (split into two 8-byte blocks), and ASCII Translation Column.
- **Interactive Highlighting:** Hovering over any byte in the Hex Matrix synchronously highlights its corresponding ASCII representation and its protocol layer definition in the tree view.
- **Steganography Color coding:** Normal DNS header bytes render in muted cyan-gray (`#94A3B8`). Injected covert data (such as null-record padding or encoded subdomain labels) lights up in bright `#00D2FF` or alert `#EF4444`.

### 3. Action Buttons & Sim Controllers
- **Primary Cyber Action:** Background of `linear-gradient(135deg, #0070F3 0%, #00D2FF 100%)`, text `#0A0F1D` (JetBrains Mono bold), `box-shadow: 0 0 14px rgba(0, 210, 255, 0.3)`. Border radius `0.25rem`.
- **Secondary / Tactical Wire Button:** Background `#131E36`, 1px border of `rgba(56, 189, 248, 0.25)`, text `#38BDF8`. Hover updates border to `#00D2FF` with background `rgba(0, 210, 255, 0.08)`.
- **Destructive / Threat Mitigation Action:** Background `rgba(239, 68, 68, 0.12)`, border 1px solid `rgba(239, 68, 68, 0.4)`, text `#EF4444`. Hover introduces `0 0 12px rgba(239, 68, 68, 0.25)`.

### 4. Protocol Tree & Heuristic Cards
- **Tree View:** Nested directory lines rendered in `rgba(56, 189, 248, 0.15)`. Expandable chevrons with smooth 90-degree rotations. Field names in muted slate, parsed values in `JetBrains Mono` white.
- **Entropy Gauge Card:** Container in `#0D1527` with a 1px glass rim. Includes a dynamic Shannon Entropy bar ranging from 0.0 to 8.0:
  - 0.0 – 3.5: Green (`#10B981`)
  - 3.6 – 4.5: Amber (`#F59E0B`)
  - > 4.5: Red (`#EF4444`) with high-frequency strobe animation indicating compressed/encrypted covert payload.

### 5. Filter & Query Inputs (Wireshark Display Filter Style)
- **Input Styling:** Surface `#0A0F1D`, 1px border `rgba(56, 189, 248, 0.2)`. Height 34px. Monospace text input with real-time protocol syntax validation:
  - Valid syntax (e.g., `dns.flags.response == 1 && dns.qry.name contains "covert"`): Background shifts to `rgba(16, 185, 129, 0.05)`, border `#10B981`.
  - Invalid syntax: Background shifts to `rgba(239, 68, 68, 0.05)`, border `#EF4444`.

### 6. Chips & Status Badges
- **DNS Query Types (A, AAAA, TXT, CNAME, NULL, PTR):** 18px height, `0.125rem` radius, `JetBrains Mono` 10px uppercase, padding `0 6px`. 
  - TXT / NULL records receive high-visibility outlines (`#38BDF8`) due to common covert channel usage.
- **Traffic Veracity Badges:** Pill-style indicators with a pulsing 6px dot:
  - Clean: `#10B981` dot with `rgba(16, 185, 129, 0.12)` background.
  - Exfiltration Confirmed: `#EF4444` dot with `rgba(239, 68, 68, 0.18)` background and bright red border.