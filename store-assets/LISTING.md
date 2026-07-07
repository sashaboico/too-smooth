# Chrome Web Store Listing — TooSmooth

## Name
TooSmooth — AI Phishing Detector

## Short description (132 chars max)
Paste any email or message and see if it's AI-generated phishing, with an explainable feature-by-feature breakdown.

(117 chars)

## Category
Productivity

## Language
English

## Detailed description

TooSmooth is a simple popup: paste any email, DM, or message you're unsure about, and
it classifies it as legitimate, human-written phishing, or AI-generated phishing —
with an explainable breakdown of exactly which manipulation signals fired and why.

Built on a classifier trained on a public phishing email corpus (~145k messages) plus
123 hand-labeled AI-generated phishing examples, including deliberate adversarial
evasion cases (typo injection, casual low-pressure framing) used to stress-test the
detector against attempts to dodge it.

Features analyzed:
• Urgency signal density
• Personalization depth
• Authority spoofing signals
• Emotional pressure index
• Syntactic smoothness (the core AI-detection signal)
• Manipulation arc indicators

A risk score (0–100) drives a green/yellow/red verdict card in the popup. Nothing is
read automatically from your inbox or any page — you paste text yourself, and nothing
you submit is stored: analysis happens per-request over HTTPS and the text is discarded
once the verdict is returned.

Open source: github.com/sashaboico/too-smooth

## Assets checklist
- [x] Promotional tile 440x280 — store-assets/promo_tile_440x280.png
- [x] Icons 16/48/128 — extension/icons/
- [x] Screenshots — store-assets/screenshot_1280x800_verdict.png (verdict card over a
      real WIRED newsletter, Gmail blurred in the background) and
      store-assets/screenshot_640x400_empty_state.png (empty popup state)
- [ ] Privacy policy URL — https://sashaboico.github.io/too-smooth/privacy-policy.html
      (live once GitHub Pages is enabled — see Track C)
