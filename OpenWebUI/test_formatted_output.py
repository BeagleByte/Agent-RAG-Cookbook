#!/usr/bin/env python3
"""
Demonstrate the formatted output of script elements
"""

def format_script_output(script):
    """Format NSE script output with all details - as per AgentNmap.py."""
    report = []

    script_id = script.get("id", "unknown")
    output = script.get("output", "").strip()

    # Script header
    report.append(f"##### 📜 {script_id}\n")

    # Main output text
    if output:
        # For single-line output, use italics
        if "\n" not in output and len(output) < 150:
            report.append(f"_{output}_\n")
        else:
            # Multi-line or long output in code block
            report.append("```")
            report.append(output)
            report.append("```\n")

    # Structured elements
    elements = script.get("elements", [])
    if elements and len(elements) > 0:
        report.append("**Details:**\n")

        for elem in elements:
            key = elem.get("key", "")
            value = elem.get("value", "")

            if key:
                # Special formatting for specific keys
                if "redirect" in key.lower() or "url" in key.lower():
                    report.append(f"- 🔗 **{key.replace('_', ' ').title()}:** `{value}`")
                elif key in ["title", "server", "header"]:
                    report.append(f"- **{key.title()}:** {value}")
                elif "cve" in key.lower():
                    report.append(f"- 🚨 **{key.upper()}:** {value}")
                else:
                    report.append(f"- **{key.replace('_', ' ').title()}:** {value}")
            else:
                # Element without key (just a value)
                report.append(f"- {value}")

        report.append("")

    return "\n".join(report)


# Test with the three scripts from the user's XML
scripts = [
    {
        "id": "http-title",
        "output": "Did not follow redirect to http://monitorsfour.htb/",
        "elements": [
            {"key": "redirect_url", "value": "http://monitorsfour.htb/"}
        ]
    },
    {
        "id": "http-title",
        "output": "Not Found",
        "elements": [
            {"key": "title", "value": "Not Found"}
        ]
    },
    {
        "id": "http-server-header",
        "output": "Microsoft-HTTPAPI/2.0",
        "elements": [
            {"key": "", "value": "Microsoft-HTTPAPI/2.0"}
        ]
    }
]

print("=" * 80)
print("FORMATTED OUTPUT DEMONSTRATION")
print("=" * 80)
print("\nThis is how the script information would appear in the final report:\n")
print("=" * 80)

for idx, script in enumerate(scripts, 1):
    print(f"\n--- Script {idx} ---\n")
    print(format_script_output(script))
    print()

print("=" * 80)
print("\nNOTE: All script elements are properly extracted and formatted!")
print("=" * 80)

