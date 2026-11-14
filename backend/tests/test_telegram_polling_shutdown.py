import ast
import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"


def _load_background_runner(monkeypatch):
    app_package = types.ModuleType("app")
    app_package.__path__ = [str(BACKEND / "app")]
    config = types.ModuleType("app.config")
    config.get_settings = Mock(return_value=object())
    scheduler = types.ModuleType("app.services.scheduler")
    scheduler.start_scheduler = Mock()
    security = types.ModuleType("app.services.security_hardening")
    security.validate_runtime_security = Mock()
    controller = types.ModuleType("app.services.telegram_controller")
    controller.start_telegram_controller = Mock()
    controller.stop_telegram_controller = Mock()
    services = types.ModuleType("app.services")
    services.__path__ = [str(BACKEND / "app" / "services")]

    for name, module in {
        "app": app_package,
        "app.config": config,
        "app.services": services,
        "app.services.scheduler": scheduler,
        "app.services.security_hardening": security,
        "app.services.telegram_controller": controller,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)

    spec = importlib.util.spec_from_file_location(
        "isolated_background_runner", BACKEND / "app" / "background_runner.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, scheduler.start_scheduler, controller


def test_dedicated_runner_starts_and_shuts_down_scheduler_without_importing_controller(monkeypatch):
    runner, start_scheduler, controller = _load_background_runner(monkeypatch)
    scheduler_instance = Mock()
    start_scheduler.return_value = scheduler_instance
    runner._STOP = Mock()
    monkeypatch.setattr(runner.signal, "signal", Mock())

    runner.main()

    start_scheduler.assert_called_once_with()
    scheduler_instance.shutdown.assert_called_once_with(wait=False)
    controller.start_telegram_controller.assert_not_called()
    controller.stop_telegram_controller.assert_not_called()


def test_api_startup_starts_scheduler_when_enabled_without_starting_controller():
    source = (BACKEND / "app" / "main.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    startup = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "on_startup"
    )
    scheduler_gate = next(
        node for node in startup.body
        if isinstance(node, ast.If)
        and "RUN_BACKGROUND_JOBS" in ast.get_source_segment(source, node)
    )
    start_scheduler = Mock(return_value=Mock())
    namespace = {
        "get_settings": Mock(return_value=types.SimpleNamespace(RUN_BACKGROUND_JOBS=True)),
        "start_scheduler": start_scheduler,
        "logger": Mock(),
        "_scheduler": None,
    }
    exec(compile(ast.Module(body=[scheduler_gate], type_ignores=[]), "main.py", "exec"), namespace)  # noqa: S102

    start_scheduler.assert_called_once_with()
    assert "telegram_controller" not in ast.get_source_segment(source, scheduler_gate)


def test_notification_test_and_login_alerts_do_not_expose_dead_controller_callbacks():
    backup = (BACKEND / "app" / "routers" / "backup.py").read_text(encoding="utf-8")
    notifier = (BACKEND / "app" / "services" / "telegram_notifier.py").read_text(encoding="utf-8")
    test_route = backup[backup.index("def test_telegram_control"):backup.index("@router.post(\"/telegram-settings/send-backup-now\")")]
    assert "_tg.send_text(" in test_route
    assert "telegram_controller" not in test_route
    assert "_send_main_menu" not in test_route
    assert "login_failure_keyboard" not in notifier
    assert '"callback_data": f"banip:' not in notifier


def test_legacy_group_control_api_and_frontend_tab_are_not_registered():
    main = (BACKEND / "app" / "main.py").read_text(encoding="utf-8")
    frontend = (ROOT / "frontend" / "src" / "pages" / "TelegramBot.jsx").read_text(encoding="utf-8")
    assert "telegram_groups" not in main
    assert "TelegramAdminGroups" not in frontend
    assert "TelegramDeliverySettings" in frontend

