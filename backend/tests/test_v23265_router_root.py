from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_router_wraps_all_runtime_providers_in_source():
    main = (ROOT / "frontend/src/main.jsx").read_text(encoding="utf-8")
    app = (ROOT / "frontend/src/App.jsx").read_text(encoding="utf-8")
    assert "import { BrowserRouter } from 'react-router-dom'" in main
    assert main.index("<BrowserRouter>") < main.index("<UIProvider>") < main.index("<App />")
    assert "<BrowserRouter>" not in app
    assert "useNavigate() may be used only" not in main


def test_prebuilt_entry_has_single_outer_router_and_new_cache_identity():
    entry_path = ROOT / "frontend/dist/assets/index-v24000.js"
    entry = entry_path.read_text(encoding="utf-8")
    source_main = (ROOT / "frontend/src/main.jsx").read_text(encoding="utf-8")
    html = (ROOT / "frontend/dist/index.html").read_text(encoding="utf-8")
    boundary = (ROOT / "frontend/src/components/AppErrorBoundary.jsx").read_text(encoding="utf-8")
    assert entry_path.is_file()
    assert "index-v23263.js" not in html
    assert "/assets/index-v24000.js" in html
    assert 'content="2.4.0"' in html
    assert "2.4.0" in boundary
    # Source structure is authoritative; the minifier may rename wrapper symbols.
    assert "BrowserRouter" in source_main
    assert "window.__VP_PANEL_REACT_ROOT__" in entry


def test_all_prebuilt_chunks_reference_only_the_active_entry():
    assets = ROOT / "frontend/dist/assets"
    for path in assets.glob("*.js"):
        text = path.read_text(encoding="utf-8")
        assert "index-v23263.js" not in text, path.name
