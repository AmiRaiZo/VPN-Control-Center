from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_root_mount_uses_router_outermost_without_global_dom_monkeypatch():
    main = (ROOT / "frontend/src/main.jsx").read_text(encoding="utf-8")
    html = (ROOT / "frontend/index.html").read_text(encoding="utf-8")
    assert "installDomMutationResilience" not in main
    assert "Node.prototype" not in html
    assert "window.__VP_PANEL_REACT_ROOT__" in main
    assert main.index("<BrowserRouter>") < main.index("<AppErrorBoundary>") < main.index("<UIProvider>") < main.index("<App />")

def test_document_opt_outs_of_external_translation_dom_rewrites():
    html = (ROOT / "frontend/index.html").read_text(encoding="utf-8")
    assert 'name="google" content="notranslate"' in html
    assert '<html lang="fa" dir="rtl" translate="no" class="notranslate">' in html
    assert '<div id="root" class="notranslate" translate="no" data-translate="no"></div>' in html


def test_release_identity_is_24000():
    assert (ROOT / "VERSION").read_text(encoding="utf-8").strip() == "2.4.0"
    assert 'version="2.4.0"' in (ROOT / "backend/app/main.py").read_text(encoding="utf-8")
    assert "const releaseNumber = '24000'" in (ROOT / "frontend/vite.config.js").read_text(encoding="utf-8")
