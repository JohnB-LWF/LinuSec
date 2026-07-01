We are going to expand the functionality of this script project so it's possible to see more information from the tui dashboard and so we can see detailed reports of each category and why it's rated what it is, like "HIGH, MEDIUM, and LOW," and ways to correct it?

The current code is already close to supporting this. Each parser builds a small report with severity, metrics, and examples, and modules/hardening.py already computes a top-level recommendation list. The main gap is that tui/dashboard.py only renders those fields, so the dashboard has no “why this severity” explanation or drill-down flow yet.

The cleanest expansion is to move from a flat report shape to an explanation-rich one. For each category, add fields like severity_reason, triggered_rules, thresholds, risk_score, and remediation, then have the TUI show those in a detail panel. That would let the UI say things like “HIGH because insecure_home_dir_count > 0” or “MEDIUM because there are open ports but the firewall is active,” instead of only showing the label. You can already see the rule logic in modules/system.py, modules/permissions.py, modules/logs.py, modules/services.py, and modules/users.py.

A practical roadmap would be:

1. Add explanation data to each module report.
Return a structure like why, evidence, thresholds, and recommended_fixes alongside severity.

2. Make the TUI interactive instead of static.
Let the user select a category and open a drill-down pane with:

severity
triggering rules
sample evidence
impact
remediation steps
copyable commands

3. Surface remediation by category.
modules/hardening.py already has some fixes, but they should be broken out per module so the dashboard can show category-specific guidance, not just a generic list.

4. Add scoring transparency.
Use a numeric score under the hood, then map it to HIGH/MEDIUM/LOW. That makes the reason for the label explicit and easier to tune.

5. Add trend/history support.
Compare the current run to previous reports so the dashboard can show “improved,” “regressed,” or “new issue detected.”

6. Add raw evidence expansion.
Show the first few matching lines, counts, and a “view more” control so users can inspect the underlying findings without leaving the TUI.

We can implement this in two slices: first extend the report schema with severity_reason and remediation, then update tui/dashboard.py to render a selectable category detail view.

The dashboard should have options to view more detailed information for each category, as well as a help option with relavent help information.
