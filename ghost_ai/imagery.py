"""
Ghost AI — Imagery & ASCII Art
Terminal branding assets.
"""

GHOST_BANNER = r"""
  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗     █████╗ ██╗
 ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝    ██╔══██╗██║
 ██║  ███╗███████║██║   ██║███████╗   ██║       ███████║██║
 ██║   ██║██╔══██║██║   ██║╚════██║   ██║       ██╔══██║██║
 ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║       ██║  ██║██║
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝       ╚═╝  ╚═╝╚═╝

          👻  Security Intelligence Platform  👻
          GitHub API Integration · No Wallet
"""

GHOST_SVG = """<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 120'>
  <defs>
    <radialGradient id='glow' cx='50%' cy='40%' r='50%'>
      <stop offset='0%' stop-color='#00f5ff' stop-opacity='0.8'/>
      <stop offset='100%' stop-color='#0a0a1a' stop-opacity='0'/>
    </radialGradient>
  </defs>
  <!-- Ghost body -->
  <ellipse cx='50' cy='48' rx='32' ry='36' fill='#1a1a2e' stroke='#00f5ff' stroke-width='1.5'/>
  <rect x='18' y='48' width='64' height='42' fill='#1a1a2e'/>
  <!-- Wavy bottom -->
  <path d='M18 90 Q26 80 34 90 Q42 100 50 90 Q58 80 66 90 Q74 100 82 90 L82 95 Q74 105 66 95 Q58 85 50 95 Q42 105 34 95 Q26 85 18 95 Z'
        fill='#0a0a1a' stroke='#00f5ff' stroke-width='1'/>
  <!-- Eyes -->
  <ellipse cx='38' cy='44' rx='7' ry='8' fill='#00f5ff' opacity='0.9'/>
  <ellipse cx='62' cy='44' rx='7' ry='8' fill='#00f5ff' opacity='0.9'/>
  <circle cx='40' cy='45' r='3' fill='#0a0a1a'/>
  <circle cx='64' cy='45' r='3' fill='#0a0a1a'/>
  <!-- Glow overlay -->
  <ellipse cx='50' cy='48' rx='32' ry='36' fill='url(#glow)'/>
</svg>"""


SEVERITY_ICONS = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "🔵",
}


def print_banner() -> None:
    print(GHOST_BANNER)


def severity_icon(severity: str) -> str:
    return SEVERITY_ICONS.get(severity.lower(), "⚪")
