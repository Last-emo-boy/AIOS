# UI Designer Analysis

## Visual Direction

AgentOS should feel like a dense operational console: quiet, high contrast, fast to scan and terminal-native. Avoid decorative UI. Use stable panes, clear labels, compact status indicators and predictable keyboard navigation.

## Proposed Layout

Desktop terminal layout:

```text
+------------------------------------------------------------------+
| AgentOS  local-only  healthy:degraded=0  approvals=1  run=latest |
+-------------------+----------------------------------------------+
| Dashboard         | Run Workspace                                |
| Runs              | plan / current step / observations            |
| Approvals         |                                              |
| Recovery          +----------------------------------------------+
| Capabilities      | Event Feed / Audit Timeline                   |
| Ecosystem         |                                              |
| Support           +----------------------------------------------+
| Release           | Command Palette / Preview                     |
+-------------------+----------------------------------------------+
```

Narrow terminal fallback:

- top status line
- tab strip
- single focused panel
- command palette overlay
- compact attention list

## Component Set

- Status bar
- Navigation rail
- Tab strip
- Run list
- Run workspace
- Approval card
- Recovery card
- Artifact detail
- Event timeline
- Command palette
- Preview panel
- Support bundle result panel
- Degraded state banner

## Visual Hierarchy

Priority order:

1. blocked or unsafe state
2. pending human decision
3. currently executing or recovering run
4. degraded ecosystem/runtime state
5. available capabilities
6. historical audit detail

## Interaction Rules

- High-risk commands open preview before dispatch.
- Approval cards show approve and deny with equal visual weight.
- Expired or stale approvals are disabled and labeled.
- Secret-like values are never rendered raw.
- Shell-like input is displayed as rejected, not silently ignored.
- All panels must have stable dimensions to prevent layout jumps.

## Accessibility

- No color-only status.
- ASCII-safe fallback.
- High contrast text.
- Keyboard-first navigation.
- Fixed-width tables with truncation plus detail view.
- Avoid negative letter spacing or viewport-scaled text.

## Recommendation

Implement full-screen shell with existing line renderers embedded as panels first. Then incrementally replace panels with structured table/card renderers.
