"""Custom routing, smart routing, connections, cores, settings, logs, about."""
from __future__ import annotations

import os
import subprocess
from datetime import datetime

import psutil
from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (QApplication, QCheckBox, QComboBox, QFileDialog, QFormLayout, QGridLayout, QGroupBox,
                               QHBoxLayout, QInputDialog, QLabel, QLineEdit, QMessageBox, QPlainTextEdit,
                               QPushButton, QScrollArea, QSpinBox, QTabWidget, QVBoxLayout, QWidget)

from .. import cores, paths, tunnels, winutil
from ..learner import base_domain
from ..presets import DISCORD_DOMAINS, PRESET_TITLES, TELEGRAM_CIDRS
from ..rules_text import KINDS_HELP, parse_text, to_text
from .common import HelpButton, human_bytes, run_bg, with_help
from .help_texts import SETTINGS_HELP
from .widgets import btn, group_header, page_title, selected_data, set_row, table

QUICK = {
    "Discord": DISCORD_DOMAINS + ["Discord.exe", "DiscordPTB.exe", "DiscordCanary.exe", "Update.exe"],
    "YouTube": ["youtube.com", "googlevideo.com", "ytimg.com", "youtu.be", "ggpht.com", "youtube-nocookie.com",
                "youtubei.googleapis.com"],
    "Telegram": ["telegram.org", "t.me", "telegram.me", "telesco.pe", "tdesktop.com", "Telegram.exe",
                 *TELEGRAM_CIDRS],
    "ChatGPT": ["openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com", "sora.com"],
    "Claude": ["anthropic.com", "claude.ai", "claude.com", "claudeusercontent.com"],
    "Gemini": ["gemini.google.com", "aistudio.google.com", "generativelanguage.googleapis.com"],
    "Instagram/Facebook": ["instagram.com", "cdninstagram.com", "facebook.com", "fbcdn.net", "fb.com",
                           "messenger.com"],
    "X / Twitter": ["x.com", "twitter.com", "twimg.com", "t.co"],
    "WhatsApp": ["whatsapp.com", "whatsapp.net", "wa.me"],
}


def _open_path(p) -> None:
    if os.name == "nt":
        os.startfile(str(p))  # noqa: S606 - our own data folder
    else:
        subprocess.Popen(["xdg-open", str(p)])


# ======================================================================= Custom routing
class CustomRoutingPage(QWidget):
    """Batch editor for the user's own lists. Lists apply in every mode; in «Своя маршрутизация»
    they are the only thing that decides."""

    def __init__(self, app):
        super().__init__()
        self.app = app
        v = QVBoxLayout(self)
        v.addWidget(page_title("Своя маршрутизация",
                               "Впишите домены, IP, подсети и программы — по одному на строку или сразу пачкой. "
                               "Нажмите «Сохранить и применить»: VPN не перезапускается, звонки не обрываются.",
                               "mode_custom"))
        hint = QLabel(KINDS_HELP.replace("\n", "<br>").replace("  ", "&nbsp;&nbsp;"))
        hint.setObjectName("muted")
        hint.setStyleSheet("font-family: Consolas, monospace; font-size: 9pt;")
        hint_box = QGroupBox("Формат строк")
        hb = QVBoxLayout(hint_box)
        hb.addWidget(hint)
        hint_box.setCheckable(True)
        hint_box.setChecked(False)
        hint.setVisible(False)
        hint_box.toggled.connect(hint.setVisible)
        v.addWidget(hint_box)

        cols = QHBoxLayout()
        self.editors: dict[str, QPlainTextEdit] = {}
        self.counts: dict[str, QLabel] = {}
        for verdict, title, key in (("proxy", "Через VPN", "custom_vpn"), ("direct", "Напрямую", "custom_direct")):
            g = QGroupBox()
            gv = QVBoxLayout(g)
            gv.addWidget(group_header(title, key))
            ed = QPlainTextEdit()
            ed.setStyleSheet("font-family: Consolas, monospace;")
            ed.setPlaceholderText("youtube.com\n*.discord.gg\n91.108.4.0/22\n1.2.3.4\nTelegram.exe")
            gv.addWidget(ed, 1)
            cnt = QLabel()
            cnt.setObjectName("muted")
            gv.addWidget(cnt)
            r = QHBoxLayout()
            r.addWidget(btn("Импорт из файла…", lambda _=False, vv=verdict: self.import_file(vv)))
            r.addWidget(btn("Экспорт…", lambda _=False, vv=verdict: self.export_file(vv)))
            r.addWidget(btn("Очистить", lambda _=False, e=ed: e.clear()))
            r.addStretch()
            gv.addLayout(r)
            ed.textChanged.connect(lambda vv=verdict: self._count(vv))
            self.editors[verdict] = ed
            self.counts[verdict] = cnt
            cols.addWidget(g, 1)
        v.addLayout(cols, 1)

        pick = QHBoxLayout()
        pick.addWidget(btn("Выбрать из запущенных программ…", self.pick_programs, "primary"))
        pick.addWidget(btn("Выбрать из открытых сайтов…", self.pick_sites))
        pick.addWidget(HelpButton("pickers"))
        pick.addStretch()
        v.addLayout(pick)

        qa_head = QHBoxLayout()
        qa_head.addWidget(QLabel("Быстро добавить в «Через VPN»:"))
        qa_head.addWidget(HelpButton("quick_add"))
        qa_head.addStretch()
        v.addLayout(qa_head)
        qa = QGridLayout()
        for i, name in enumerate(QUICK):
            qa.addWidget(btn(name, lambda _=False, nn=name: self.quick_add(nn)), i // 5, i % 5)
        v.addLayout(qa)

        bottom = QHBoxLayout()
        self.use_presets = QCheckBox("В режиме «Своя маршрутизация» также использовать готовые базы")
        self.use_presets.setChecked(bool(app.settings["custom_use_presets"]))
        bottom.addWidget(with_help(self.use_presets, "custom_presets"))
        bottom.addStretch()
        bottom.addWidget(btn("Отменить изменения", self.load))
        bottom.addWidget(btn("Сохранить и применить", self.save, "primary"))
        v.addLayout(bottom)
        self.load()

    @property
    def learner(self):
        return self.app.engine.learner

    def _count(self, verdict: str) -> None:
        entries, errors = parse_text(self.editors[verdict].toPlainText())
        txt = f"Записей: {len(entries)}"
        if errors:
            txt += f" · <span style='color:#fca5a5'>ошибок: {len(errors)}</span>"
        self.counts[verdict].setText(txt)

    def load(self) -> None:
        for verdict, ed in self.editors.items():
            ed.setPlainText(to_text(self.learner.db.user_entries(verdict)))
        self.use_presets.setChecked(bool(self.app.settings["custom_use_presets"]))

    def save(self) -> None:
        parsed = {}
        all_errors = []
        for verdict, ed in self.editors.items():
            entries, errors = parse_text(ed.toPlainText())
            parsed[verdict] = entries
            all_errors += [f"{'VPN' if verdict == 'proxy' else 'Напрямую'}: {e}" for e in errors]
        both = set(parsed["proxy"]) & set(parsed["direct"])
        if both:
            QMessageBox.warning(self, "Конфликт", "Эти записи есть в обоих списках — оставьте в одном:\n" +
                                "\n".join(v for _, v in list(both)[:15]))
            return
        if all_errors and QMessageBox.question(
                self, "Есть ошибки", "Некоторые строки не распознаны и будут пропущены:\n\n" +
                "\n".join(all_errors[:15]) + ("\n…" if len(all_errors) > 15 else "") +
                "\n\nСохранить остальное?") != QMessageBox.Yes:
            return
        for verdict, entries in parsed.items():
            self.learner.db.replace_user(verdict, entries)
        self.learner.apply()
        presets_changed = self.use_presets.isChecked() != bool(self.app.settings["custom_use_presets"])
        self.app.settings["custom_use_presets"] = self.use_presets.isChecked()
        self.app.settings.save()
        self.load()
        if presets_changed:
            run_bg(self.app.engine.reload)
        self.app.status(f"Сохранено: через VPN — {len(parsed['proxy'])}, напрямую — {len(parsed['direct'])}. "
                        "Применено без перезапуска.")
        self.app.smart.reload()

    def add_entries(self, verdict: str, values: list[str]) -> None:
        """Put values into one list, take them out of the other, save right away."""
        other = "direct" if verdict == "proxy" else "proxy"
        low = {x.lower() for x in values}
        ed_o = self.editors[other]
        ed_o.setPlainText("\n".join(ln for ln in ed_o.toPlainText().splitlines()
                                    if ln.split("#", 1)[0].strip().lower() not in low))
        ed = self.editors[verdict]
        cur = ed.toPlainText().rstrip()
        have = {ln.split("#", 1)[0].strip().lower() for ln in cur.splitlines()}
        add = [x for x in values if x.lower() not in have]
        if add:
            ed.setPlainText((cur + "\n" if cur else "") + "\n".join(add))
        self.save()
        where = "через VPN" if verdict == "proxy" else "напрямую"
        self.app.status(f"{', '.join(values[:4])}{' …' if len(values) > 4 else ''} — теперь {where}")

    def pick_programs(self) -> None:
        from .pages3 import ProcessPicker
        ProcessPicker(self, lambda verdict, exes: self.add_entries(
            verdict, sorted({os.path.basename(e.replace("\\", "/")) for e in exes}))).exec()

    def pick_sites(self) -> None:
        from .pages3 import SitePicker
        if self.app.engine.state != "running":
            QMessageBox.information(self, "Сайты", "Сначала включите VPN и откройте нужные сайты.")
            return
        SitePicker(self, self.app, self.add_entries).exec()

    def quick_add(self, name: str) -> None:
        ed = self.editors["proxy"]
        cur = ed.toPlainText().rstrip()
        have = {ln.strip().lower() for ln in cur.splitlines()}
        add = [x for x in QUICK[name] if x.lower() not in have]
        ed.setPlainText((cur + "\n" if cur else "") + f"# {name}\n" + "\n".join(add))

    def import_file(self, verdict: str) -> None:
        fn, _ = QFileDialog.getOpenFileName(self, "Импорт списка", "", "Текст (*.txt *.list *.lst *.csv);;Все (*)")
        if fn:
            with open(fn, encoding="utf-8", errors="replace") as fh:
                ed = self.editors[verdict]
                cur = ed.toPlainText().rstrip()
                ed.setPlainText((cur + "\n" if cur else "") + fh.read())

    def export_file(self, verdict: str) -> None:
        fn, _ = QFileDialog.getSaveFileName(self, "Экспорт списка", f"nexusvpn-{verdict}.txt", "Текст (*.txt)")
        if fn:
            with open(fn, "w", encoding="utf-8") as fh:
                fh.write(self.editors[verdict].toPlainText())


# ======================================================================= Smart routing
class SmartPage(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        v = QVBoxLayout(self)
        v.addWidget(page_title("Умная маршрутизация", "Что программа узнала сама. Ваши правила (страница «Своя "
                                                      "маршрутизация») всегда важнее автоматических.", "mode_smart"))
        tabs = QTabWidget()
        v.addWidget(tabs, 1)

        w = QWidget()
        wv = QVBoxLayout(w)
        fr = QHBoxLayout()
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Поиск по домену / программе…")
        self.filter.textChanged.connect(self.reload)
        self.kind_f = QComboBox()
        for k, t in (("", "Все"), ("proxy", "Через VPN"), ("direct", "Напрямую"), ("user", "Мои"), ("auto", "Авто")):
            self.kind_f.addItem(t, k)
        self.kind_f.currentIndexChanged.connect(self.reload)
        fr.addWidget(self.filter, 1)
        fr.addWidget(self.kind_f)
        fr.addWidget(HelpButton("learned"))
        wv.addLayout(fr)
        self.rules = table(["Значение", "Тип", "Маршрут", "Источник", "Программа", "Причина", "Обновлено"], 0)
        wv.addWidget(self.rules, 1)
        br = QHBoxLayout()
        br.addWidget(btn("→ Через VPN", lambda: self.set_selected("proxy")))
        br.addWidget(btn("→ Напрямую", lambda: self.set_selected("direct")))
        br.addWidget(btn("Удалить", self.delete_selected))
        br.addWidget(btn("Проверить сайт…", self.test_site, "primary"))
        br.addStretch()
        br.addWidget(btn("Забыть всё автоматическое", self.clear_auto, "danger"))
        wv.addLayout(br)
        tabs.addTab(w, "Изученное")

        a = QWidget()
        av = QVBoxLayout(a)
        av.addWidget(with_help(QLabel("Запущенные программы с сетевыми соединениями:"), "apps"))
        self.apps = table(["Программа", "Путь", "Соединений", "Текущее правило"], 1)
        av.addWidget(self.apps, 1)
        ar = QHBoxLayout()
        ar.addWidget(btn("Обновить список", self.reload_apps))
        ar.addWidget(btn("Программа → через VPN", lambda: self.app_rule("proxy"), "primary"))
        ar.addWidget(btn("Программа → напрямую", lambda: self.app_rule("direct")))
        ar.addWidget(btn("Сбросить", lambda: self.app_rule(None)))
        ar.addStretch()
        av.addLayout(ar)
        tabs.addTab(a, "Программы")

        p = QWidget()
        pv = QVBoxLayout(p)
        pv.addWidget(with_help(QLabel("Готовые базы (обновляются автоматически раз в сутки):"), "presets"))
        self.preset_boxes: dict[str, QCheckBox] = {}
        for key, title in PRESET_TITLES.items():
            cb = QCheckBox(title)
            cb.setChecked(bool(app.settings[key]))
            self.preset_boxes[key] = cb
            pv.addWidget(cb)
        pr = QHBoxLayout()
        pr.addWidget(btn("Применить", self.apply_presets, "primary"))
        pr.addWidget(btn("Обновить базы сейчас", lambda: self.update_rules()))
        pr.addStretch()
        pv.addLayout(pr)
        pv.addStretch()
        tabs.addTab(p, "Базы правил")
        tabs.currentChanged.connect(lambda i: self.reload_apps() if i == 1 else None)
        self.reload()

    @property
    def db(self):
        return self.app.engine.learner.db

    def reload(self) -> None:
        q = self.filter.text().strip().lower()
        k = self.kind_f.currentData()
        rows = [r for r in self.db.all() if r["value"] != "placeholder.invalid"]
        if q:
            rows = [r for r in rows if q in r["value"].lower() or q in (r["process"] or "").lower()]
        if k in ("proxy", "direct"):
            rows = [r for r in rows if r["verdict"] == k]
        elif k in ("user", "auto"):
            rows = [r for r in rows if r["source"] == k]
        kinds = {"domain": "домен", "full": "точный домен", "keyword": "ключевое слово", "process": "программа",
                 "ip": "IP/подсеть"}
        self.rules.setSortingEnabled(False)
        self.rules.setRowCount(len(rows))
        for i, r in enumerate(rows):
            set_row(self.rules, i, [
                r["value"], kinds.get(r["kind"], r["kind"]), "VPN" if r["verdict"] == "proxy" else "напрямую",
                "моё" if r["source"] == "user" else "авто", r["process"] or "", r["note"] or "",
                datetime.fromtimestamp(r["updated"] or 0).strftime("%d.%m %H:%M")], (r["kind"], r["value"]))
            self.rules.item(i, 2).setForeground(Qt.cyan if r["verdict"] == "proxy" else Qt.green)
        self.rules.setSortingEnabled(True)

    def set_selected(self, verdict: str) -> None:
        for kind, value in selected_data(self.rules):
            self.app.engine.learner.set_rule(kind, value, verdict)
        self.reload()
        self.app.custom.load()

    def delete_selected(self) -> None:
        for kind, value in selected_data(self.rules):
            self.app.engine.learner.remove_rule(kind, value)
        self.reload()
        self.app.custom.load()

    def clear_auto(self) -> None:
        if QMessageBox.question(self, "Сброс", "Удалить все автоматически изученные правила? Ваши правила "
                                               "останутся.") == QMessageBox.Yes:
            self.db.clear_auto()
            self.app.engine.learner.apply()
            self.reload()

    def test_site(self) -> None:
        if self.app.engine.state != "running":
            QMessageBox.information(self, "Проверка", "Сначала подключитесь.")
            return
        host, ok = QInputDialog.getText(self, "Проверить сайт", "Домен (например, youtube.com):")
        if not ok or not host.strip():
            return
        host = host.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
        from ..config_builder import probe_ports
        from ..learner import probe
        pd, pp = probe_ports(self.app.settings)
        self.app.status(f"Проверка {host}…")

        def done(res):
            d, p = res
            text = (f"Напрямую: {'✔ работает' if d.ok else '✖ ' + d.reason}  {d.ms or ''} мс\n"
                    f"Через VPN: {'✔ работает' if p.ok else '✖ ' + p.reason}  {p.ms or ''} мс")
            dom = base_domain(host)
            if not d.ok and p.ok:
                if QMessageBox.question(self, host, text + f"\n\nОтправлять {dom} через VPN?") == QMessageBox.Yes:
                    self.app.engine.learner.set_rule("domain", dom, "proxy")
                    self.app.custom.load()
            else:
                QMessageBox.information(self, host, text)
            self.reload()
            self.app.status("")
        run_bg(lambda: (probe(pd, host), probe(pp, host)), done=done)

    def reload_apps(self) -> None:
        counts: dict[int, int] = {}
        try:
            for c in psutil.net_connections("inet"):
                if c.pid and c.raddr:
                    counts[c.pid] = counts.get(c.pid, 0) + 1
        except (psutil.Error, OSError):
            pass
        rows: dict[str, list] = {}
        for pid, n in counts.items():
            try:
                pr = psutil.Process(pid)
                name, exe = pr.name(), pr.exe()
            except (psutil.Error, OSError):
                continue
            if name in rows:
                rows[name][2] += n
            else:
                rows[name] = [name, exe, n]
        self.apps.setSortingEnabled(False)
        self.apps.setRowCount(len(rows))
        for i, (name, exe, n) in enumerate(sorted(rows.values(), key=lambda r: -r[2])):
            r = self.db.get("process", name)
            rule = "" if not r else ("VPN" if r["verdict"] == "proxy" else "напрямую") + f" ({r['source']})"
            set_row(self.apps, i, [name, exe, n, rule], name)
        self.apps.setSortingEnabled(True)

    def app_rule(self, verdict: str | None) -> None:
        for name in selected_data(self.apps):
            if verdict is None:
                self.app.engine.learner.remove_rule("process", name)
            else:
                self.app.engine.learner.set_rule("process", name, verdict)
        self.reload_apps()
        self.reload()
        self.app.custom.load()

    def apply_presets(self) -> None:
        for k, cb in self.preset_boxes.items():
            self.app.settings[k] = cb.isChecked()
        self.app.settings.save()
        self.update_rules(reload=True)

    def update_rules(self, reload: bool = False) -> None:
        self.app.status("Загрузка баз правил…")

        def done(res):
            bad = {k: v for k, v in res.items() if v != "ok"}
            self.app.status("Базы обновлены" if not bad else f"Ошибки: {', '.join(bad)}")
            if reload:
                run_bg(self.app.engine.reload)
        run_bg(self.app.service.update_rules, done=done, failed=self.app.status)


# ======================================================================= Connections
class ConnectionsPage(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        v = QVBoxLayout(self)
        v.addWidget(page_title("Соединения", "Живой список. Если что-то не грузится — выберите строку и "
                                             "отправьте через VPN одной кнопкой.", "conns"))
        self.tbl = table(["Хост", "Программа", "Сеть", "Маршрут", "Правило", "↑", "↓", "Время"], 0)
        v.addWidget(self.tbl, 1)
        r = QHBoxLayout()
        r.addWidget(btn("→ Через VPN", lambda: self.route("proxy"), "primary"))
        r.addWidget(btn("→ Напрямую", lambda: self.route("direct")))
        r.addWidget(btn("Закрыть соединение", self.close_sel))
        r.addWidget(btn("Закрыть все", self.close_all))
        self.pause = QCheckBox("Пауза")
        r.addWidget(self.pause)
        r.addStretch()
        self.total = QLabel()
        r.addWidget(self.total)
        v.addLayout(r)
        t = QTimer(self)
        t.timeout.connect(self.poll)
        t.start(2000)

    def poll(self) -> None:
        if not self.isVisible() or self.pause.isChecked() or self.app.engine.state != "running":
            return
        run_bg(lambda: self.app.engine.api().connections(), done=self.render)

    def render(self, data: dict) -> None:
        conns = data.get("connections") or []
        self.total.setText(f"Всего: {len(conns)}   ↑ {human_bytes(data.get('uploadTotal', 0))}   "
                           f"↓ {human_bytes(data.get('downloadTotal', 0))}")
        now = datetime.now().astimezone()
        self.tbl.setSortingEnabled(False)
        self.tbl.setRowCount(len(conns))
        for i, c in enumerate(conns):
            md = c.get("metadata") or {}
            host = md.get("host") or md.get("destinationIP", "")
            proc = (md.get("processPath") or "").replace("/", "\\").rsplit("\\", 1)[-1].split(" (")[0]
            chain = " → ".join(reversed(c.get("chains") or []))
            try:
                dur = int((now - datetime.fromisoformat(c.get("start", "").replace("Z", "+00:00"))).total_seconds())
            except ValueError:
                dur = 0
            set_row(self.tbl, i, [f"{host}:{md.get('destinationPort', '')}", proc, md.get("network", ""), chain,
                                  c.get("rule", ""), human_bytes(c.get("upload", 0)),
                                  human_bytes(c.get("download", 0)), f"{dur // 60}:{dur % 60:02d}"],
                    (c.get("id"), md.get("host") or md.get("destinationIP", ""), proc))
        self.tbl.setSortingEnabled(True)

    def route(self, verdict: str) -> None:
        for cid, host, _proc in selected_data(self.tbl):
            if host and any(ch.isalpha() for ch in host.split(":")[0]):
                self.app.engine.learner.set_rule("domain", base_domain(host), verdict)
            elif host:
                self.app.engine.learner.set_rule("ip", host + ("/128" if ":" in host else "/32"), verdict)
            try:
                self.app.engine.api().close_connection(cid)
            except OSError:
                pass
        self.app.custom.load()
        self.app.status("Правило добавлено в «Своя маршрутизация», соединение перезапущено")

    def close_sel(self) -> None:
        for cid, *_ in selected_data(self.tbl):
            run_bg(self.app.engine.api().close_connection, cid)

    def close_all(self) -> None:
        run_bg(self.app.engine.api().close_all)


# ======================================================================= Cores
class CoresPage(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        v = QVBoxLayout(self)
        v.addWidget(page_title("Обновления", "Программа обновляется из вашего репозитория GitHub, ядра — с "
                                             "официальных страниц. О новых версиях программа сообщает сама.",
                               "updates"))
        ag = QGroupBox("Программа NexusVPN Pro")
        af = QFormLayout(ag)
        self.app_cur = QLabel()
        self.app_latest = QLabel("—")
        self.app_latest.setWordWrap(True)
        self.app_latest.setTextFormat(Qt.RichText)
        af.addRow("Установлена:", self.app_cur)
        af.addRow("На GitHub:", self.app_latest)
        ar = QHBoxLayout()
        ar.addWidget(btn("Проверить обновление программы", self.check_app))
        self.app_install_btn = btn("Установить обновление", self.install_app, "primary")
        self.app_install_btn.setEnabled(False)
        ar.addWidget(self.app_install_btn)
        ar.addStretch()
        af.addRow(ar)
        s = app.settings
        self.app_check = QCheckBox("Проверять обновления программы автоматически (каждые 6 часов)")
        self.app_check.setChecked(bool(s["app_update_check"]))
        self.app_check.toggled.connect(lambda x: (s.set("app_update_check", x), s.save()))
        af.addRow(with_help(self.app_check, "app_update_check"))
        self.app_auto = QCheckBox("Устанавливать обновления программы без вопросов (не во время звонка)")
        self.app_auto.setChecked(bool(s["app_update_auto"]))
        self.app_auto.toggled.connect(lambda x: (s.set("app_update_auto", x), s.save()))
        af.addRow(with_help(self.app_auto, "app_update_auto"))
        self.repo = QLineEdit(s["update_repo"])
        from .. import build_info
        self.repo.setPlaceholderText(build_info.REPO)
        self.token = QLineEdit(s["update_token"])
        self.token.setEchoMode(QLineEdit.Password)
        self.token.setPlaceholderText("нужен только для приватного репозитория")
        for w, key in ((self.repo, "update_repo"), (self.token, "update_token")):
            w.editingFinished.connect(lambda ww=w, kk=key: (s.set(kk, ww.text().strip()), s.save()))
        af.addRow("Репозиторий:", with_help(self.repo, "update_repo", True))
        af.addRow("Токен GitHub:", with_help(self.token, "update_token", True))
        v.addWidget(ag)
        v.addWidget(QLabel("<b>Ядра</b>"))
        self.tbl = table(["Компонент", "Назначение", "Установлено", "Последняя", "Статус"], 1)
        self.tbl.setSortingEnabled(False)
        self.tbl.setMaximumHeight(190)
        v.addWidget(self.tbl)
        r = QHBoxLayout()
        r.addWidget(btn("Проверить обновления", self.check))
        r.addWidget(btn("Обновить всё", lambda: self.update_all(False), "primary"))
        r.addWidget(btn("Переустановить", lambda: self.update_all(True)))
        r.addWidget(btn("Откатить выбранное", self.rollback))
        r.addStretch()
        v.addLayout(r)
        og = QGroupBox()
        ov = QHBoxLayout(og)
        self.ovpn_lbl = QLabel()
        ov.addWidget(self.ovpn_lbl, 1)
        ov.addWidget(HelpButton("openvpn"))
        ov.addWidget(btn("Установить / обновить OpenVPN", self.install_openvpn))
        v.addWidget(og)
        self.rules_lbl = QLabel()
        self.rules_lbl.setObjectName("muted")
        v.addWidget(self.rules_lbl)
        rr = QHBoxLayout()
        rr.addWidget(btn("Обновить базы правил", lambda: self.app.smart.update_rules()))
        rr.addWidget(btn("Открыть папку данных", lambda: _open_path(paths.DATA_DIR)))
        rr.addStretch()
        v.addLayout(rr)
        self.auto = QCheckBox("Автоматически обновлять ядра (раз в сутки, не во время звонков)")
        self.auto.setChecked(bool(app.settings["core_auto_update"]))
        self.auto.toggled.connect(lambda x: (app.settings.set("core_auto_update", x), app.settings.save()))
        v.addWidget(with_help(self.auto, SETTINGS_HELP["core_auto_update"]))
        v.addStretch()
        self.info: dict = {}
        self.app_info: dict = {}
        self.render_local()

    def show_app_info(self, info: dict) -> None:
        from .. import updater
        self.app_info = info
        self.app_cur.setText(updater.current_version_text())
        if not info:
            return
        when = info.get("published", "")[:10]
        if info.get("newer"):
            notes = info.get("notes", "").replace("\n", "<br>")[:600]
            self.app_latest.setText(f"<b style='color:#4ade80'>{info['name']}</b> от {when} — доступно обновление"
                                    + (f"<br><span style='color:#94a3b8'>{notes}</span>" if notes else ""))
        else:
            self.app_latest.setText(f"{info['name']} от {when} — у вас последняя версия")
        self.app_install_btn.setEnabled(bool(info.get("newer")))

    def check_app(self) -> None:
        self.app.status("Проверка обновлений программы…")

        def done(info):
            self.app.update_info = info
            self.show_app_info(info)
            self.app.home.show_update(info)
            self.app.status("Доступна новая версия" if info.get("newer") else "У вас последняя версия программы")

        def failed(e):
            self.app_latest.setText(f"<span style='color:#fca5a5'>{e}</span>")
            self.app.status(f"Проверка обновлений: {e}")
        run_bg(self.app.service.check_app_update, done=done, failed=failed)

    def install_app(self) -> None:
        if self.app_info.get("newer"):
            self.app.install_app_update(self.app_info)

    PURPOSE = {"sing-box": "основное: TUN, правила, VLESS/VMess/Trojan/SS/Hy2/TUIC/WireGuard",
               "xray": "VLESS XHTTP", "mihomo": "AmneziaWG 1.0–3.1"}

    def render_local(self) -> None:
        from .. import updater
        self.app_cur.setText(updater.current_version_text())
        self.tbl.setRowCount(len(cores.SPECS))
        for i, name in enumerate(cores.SPECS):
            inf = self.info.get(name, {})
            cur = cores.installed_version(name) or "не установлено"
            status = "доступно обновление" if inf.get("update") else ("актуально" if inf.get("latest") else "")
            if not inf.get("latest") and inf.get("url"):
                status = inf["url"][:80]
            set_row(self.tbl, i, [name, self.PURPOSE.get(name, ""), cur, inf.get("latest", "—"), status], name)
        ov = tunnels.openvpn_version()
        self.ovpn_lbl.setText(f"<b>OpenVPN</b> (для .ovpn): {ov or 'не установлен'}"
                              + ("" if winutil.IS_WIN else " — установка доступна только в Windows"))
        age = cores.rules_age_days()
        self.rules_lbl.setText("Базы правил: " + ("не загружены" if age > 1e8 else f"обновлены {age:.1f} дн. назад"))

    def check(self) -> None:
        self.app.status("Проверка версий…")
        run_bg(self.app.service.check_cores, done=lambda i: (setattr(self, "info", i), self.render_local(),
                                                             self.app.status("")))

    def update_all(self, force: bool) -> None:
        self.app.status("Загрузка ядер…")
        run_bg(self.app.service.update_cores, None, False, force,
               done=lambda m: (self.app.status("; ".join(m)), self.check()), failed=self.app.status)

    def install_openvpn(self) -> None:
        if not winutil.IS_WIN:
            QMessageBox.information(self, "OpenVPN", "Установка OpenVPN доступна только в Windows.")
            return
        if QMessageBox.question(self, "OpenVPN", "Скачать и установить официальный OpenVPN (openvpn.net)? "
                                                 "Установка займёт около минуты.") != QMessageBox.Yes:
            return
        self.app.status("Установка OpenVPN…")
        run_bg(cores.install_openvpn, self.app.engine.proxy_ports(),
               done=lambda v: (self.app.status(f"OpenVPN {v} установлен"), self.render_local()),
               failed=lambda e: QMessageBox.warning(self, "OpenVPN", e))

    def rollback(self) -> None:
        for name in selected_data(self.tbl):
            was = self.app.engine.state == "running"
            if was:
                self.app.engine.stop()
            ok = cores.rollback(name)
            if was:
                run_bg(self.app.engine.start)
            self.app.status(f"{name}: " + ("откат выполнен" if ok else "нет резервной копии"))
        self.render_local()


# ======================================================================= Settings
class SettingsPage(QWidget):
    FIELDS = [
        ("Трафик мимо VPN", [
            ("direct_bypass", "Что не через VPN", [
                ("full", "Мимо программы — напрямую через вашу сетевую карту"),
                ("core", "Через программу (совместимость со всеми правилами)")]),
            ("proxy_voice_tun", "Discord и Telegram работают и в режиме «Системный прокси»", bool),
        ]),
        ("Подключение", [
            ("tun_stack", "Стек TUN", ["gvisor", "mixed", "system"]),
            ("tun_mtu", "MTU", (1200, 9000)),
            ("strict_route", "Строгая маршрутизация (без утечек)", bool),
            ("endpoint_independent_nat", "Endpoint-independent NAT (Discord, игры, P2P)", bool),
            ("udp_timeout", "Таймаут UDP-сессий", ["1m", "2m", "5m", "10m", "30m"]),
            ("ipv6_mode", "IPv6", ["off", "prefer"]),
            ("mixed_port", "Порт прокси (HTTP+SOCKS)", (1024, 65000)),
            ("clash_api_port", "Порт API ядра", (1024, 65000)),
            ("bypass_lan", "Локальная сеть напрямую", bool),
            ("auto_detect_interface", "Автовыбор сетевого интерфейса", bool),
        ]),
        ("DNS", [
            ("dns_local", "Локальный DNS (для прямых сайтов)", str),
            ("dns_local_alt", "Резервный локальный DNS", str),
            ("dns_remote", "DNS через VPN (DoH/DoT/UDP)", str),
            ("dns_strategy", "Стратегия", ["ipv4_only", "prefer_ipv4", "prefer_ipv6"]),
            ("dns_fakeip", "FakeIP для VPN-доменов", bool),
        ]),
        ("Умная маршрутизация", [
            ("learn_enabled", "Обучение включено", bool),
            ("learn_auto_apply", "Применять изученное автоматически", bool),
            ("learn_apps", "Обучаться по программам (игры, клиенты без домена)", bool),
            ("learn_probe_interval", "Зависание соединения, сек", (3, 120)),
            ("learn_min_bytes", "Минимум байт ответа", (100, 1_000_000)),
            ("learn_workers", "Параллельных проверок", (1, 32)),
            ("block_quic_direct", "Блокировать QUIC для прямых сайтов", bool),
        ]),
        ("Discord", [
            ("preset_discord", "Discord через VPN (текст, голос, видео, стримы)", bool),
            ("discord_isolate", "Отдельный выбор сервера для Discord", bool),
        ]),
        ("Надёжность", [
            ("auto_selector", "При сбоях переключаться на «Авто»", bool),
            ("health_check_url", "URL проверки", str),
            ("health_check_interval", "Интервал проверки, сек", (30, 3600)),
            ("auto_switch_failures", "Сбоев до переключения сервера", (1, 20)),
            ("sub_auto_update_hours", "Обновлять подписки, ч", (1, 720)),
            ("rules_auto_update", "Автообновление баз правил", bool),
            ("core_auto_update", "Автообновление ядер", bool),
        ]),
        ("Система", [
            ("autostart", "Запускать при входе в Windows", bool),
            ("start_minimized", "Запускать свёрнутым в трей", bool),
            ("log_level", "Уровень журнала ядра", ["error", "warn", "info", "debug"]),
            ("log_max_mb", "Размер файла журнала, МБ", (1, 200)),
            ("process_exclusions", "Программы всегда напрямую", list),
            ("process_force_vpn", "Программы всегда через VPN", list),

            ("openvpn_exe", "Путь к openvpn.exe", str),
        ]),
    ]

    def __init__(self, app):
        super().__init__()
        self.app = app
        outer = QVBoxLayout(self)
        outer.addWidget(page_title("Настройки", "Нажмите «?» рядом с любым параметром, чтобы узнать, что он делает."))
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        inner = QWidget()
        iv = QVBoxLayout(inner)
        self.widgets: dict[str, tuple[QWidget, object]] = {}
        for group, fields in self.FIELDS:
            g = QGroupBox(group)
            f = QFormLayout(g)
            for key, label, kind in fields:
                w = self._make(key, kind)
                tip = SETTINGS_HELP.get(key, "")
                if kind is bool:
                    w.setText(label)
                    f.addRow(with_help(w, f"<b>{label}</b><br>{tip}") if tip else w)
                else:
                    f.addRow(label + ":", with_help(w, f"<b>{label}</b><br>{tip}", True) if tip else w)
                self.widgets[key] = (w, kind)
            iv.addWidget(g)
        iv.addStretch()
        scroll.setWidget(inner)
        outer.addWidget(scroll, 1)
        r = QHBoxLayout()
        r.addWidget(btn("Сохранить и применить", self.save, "primary"))
        r.addWidget(btn("Отменить изменения", self.load))
        r.addWidget(btn("Сбросить по умолчанию", self.reset, "danger"))
        r.addStretch()
        outer.addLayout(r)
        self.load()

    def _make(self, key, kind):
        if kind is bool:
            return QCheckBox()
        if isinstance(kind, tuple):
            sp = QSpinBox()
            sp.setRange(*kind)
            return sp
        if isinstance(kind, list) and kind:
            cb = QComboBox()
            cb.setEditable(key == "udp_timeout")
            for item in kind:
                value, text = item if isinstance(item, tuple) else (item, item)
                cb.addItem(text, value)
            return cb
        return QLineEdit()

    def load(self) -> None:
        s = self.app.settings
        if winutil.IS_WIN:
            s["autostart"] = winutil.autostart_enabled()
        for key, (w, kind) in self.widgets.items():
            val = s[key]
            if kind is bool:
                w.setChecked(bool(val))
            elif isinstance(kind, tuple):
                w.setValue(int(val))
            elif kind is list:
                w.setText(", ".join(val or []))
            elif isinstance(kind, list):
                i = w.findData(val)
                if i >= 0:
                    w.setCurrentIndex(i)
                else:
                    w.setCurrentText(str(val))
            else:
                w.setText(str(val))

    def save(self) -> None:
        s = self.app.settings
        old_auto = bool(s["autostart"])
        for key, (w, kind) in self.widgets.items():
            if kind is bool:
                s[key] = w.isChecked()
            elif isinstance(kind, tuple):
                s[key] = w.value()
            elif kind is list:
                s[key] = [x.strip() for x in w.text().split(",") if x.strip()]
            elif isinstance(kind, list):
                data = w.currentData()
                s[key] = data if data is not None and w.currentText() == w.itemText(w.currentIndex()) else w.currentText()
            else:
                s[key] = w.text().strip()
        s.save()
        if bool(s["autostart"]) != old_auto:
            ok, msg = winutil.set_autostart(bool(s["autostart"]))
            if not ok:
                QMessageBox.warning(self, "Автозапуск", msg)
        self.app.status("Настройки сохранены")
        run_bg(self.app.engine.reload)

    def reset(self) -> None:
        if QMessageBox.question(self, "Сброс", "Вернуть все настройки по умолчанию? Подписки сохранятся.") \
                != QMessageBox.Yes:
            return
        subs, secret = self.app.settings["subscriptions"], self.app.settings["clash_secret"]
        self.app.settings.reset()
        self.app.settings.update(subscriptions=subs, clash_secret=secret)
        self.app.settings.save()
        self.load()
        run_bg(self.app.engine.reload)


# ======================================================================= Logs
class LogsPage(QWidget):
    SOURCES = [("Программа", None), ("sing-box", "sing-box.log"), ("xray", "xray.log"), ("mihomo", "mihomo.log")]

    def __init__(self, app, ring):
        super().__init__()
        self.app, self.ring = app, ring
        v = QVBoxLayout(self)
        v.addWidget(page_title("Журнал"))
        self.src = QComboBox()
        for t, _ in self.SOURCES:
            self.src.addItem(t)
        self.src.currentIndexChanged.connect(self.refresh)
        r = QHBoxLayout()
        r.addWidget(self.src)
        r.addWidget(btn("Копировать", lambda: QApplication.clipboard().setText(self.text.toPlainText())))
        r.addWidget(btn("Открыть папку журналов", lambda: _open_path(paths.LOGS_DIR)))
        r.addStretch()
        v.addLayout(r)
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.text.setMaximumBlockCount(5000)
        self.text.setStyleSheet("font-family: Consolas, monospace; font-size: 9pt;")
        v.addWidget(self.text, 1)
        t = QTimer(self)
        t.timeout.connect(self.refresh)
        t.start(2000)

    def refresh(self) -> None:
        if not self.isVisible():
            return
        fn = self.SOURCES[self.src.currentIndex()][1]
        if fn is None:
            body = "\n".join(list(self.ring)[-1500:])
        else:
            try:
                with open(paths.LOGS_DIR / fn, "rb") as fh:
                    fh.seek(0, 2)
                    fh.seek(max(0, fh.tell() - 200_000))
                    body = fh.read().decode("utf-8", "replace")
            except OSError:
                body = "(журнал пуст)"
        if body != self.text.toPlainText():
            sb = self.text.verticalScrollBar()
            at_end = sb.value() >= sb.maximum() - 4
            self.text.setPlainText(body)
            if at_end:
                sb.setValue(sb.maximum())


# ======================================================================= About
class AboutPage(QWidget):
    def __init__(self, app):
        super().__init__()
        v = QVBoxLayout(self)
        t = QLabel(paths.APP_NAME)
        t.setObjectName("brand")
        v.addWidget(t)
        v.addWidget(QLabel(f"Версия {paths.APP_VERSION}"))
        d = QLabel(paths.APP_DESCRIPTION)
        d.setWordWrap(True)
        d.setStyleSheet("font-size: 11pt;")
        v.addWidget(d)
        feats = QLabel(
            "<ul>"
            "<li><b>Протоколы:</b> VLESS (Reality, Vision, XHTTP, gRPC, WS), VMess, Trojan, Shadowsocks/SS-2022, "
            "Hysteria2, TUIC v5, WireGuard, <b>AmneziaWG 1.0–3.1</b>, <b>OpenVPN</b>, <b>IKEv2</b>, AnyTLS, "
            "SOCKS5, HTTP(S)</li>"
            "<li><b>Подписки:</b> 3x-ui, Marzban, Remnawave, Hiddify, Clash/Mihomo YAML, sing-box JSON, "
            "AmneziaVPN vpn://</li>"
            "<li><b>Режимы:</b> Всё через VPN · Своя маршрутизация · Умная маршрутизация</li>"
            "<li><b>Ядра:</b> sing-box, Xray, mihomo — обновление в один клик с автоматическим откатом</li>"
            "<li><b>Discord:</b> голос и видео через VPN, отдельная группа UDP-серверов, звонки не обрываются</li>"
            "<li><b>Надёжность:</b> watchdog, автопереключение серверов, восстановление после сна и смены сети</li>"
            "</ul>")
        feats.setWordWrap(True)
        v.addWidget(feats)
        dl = QLabel(f"Данные программы: {paths.DATA_DIR}")
        dl.setObjectName("muted")
        dl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        v.addWidget(dl)
        v.addWidget(QPushButton("Открыть папку данных", clicked=lambda: _open_path(paths.DATA_DIR)))
        v.addStretch()


# ======================================================================= Uninstall
class UninstallPage(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        from .. import uninstall
        v = QVBoxLayout(self)
        v.addWidget(page_title("Удаление программы", "Полностью убирает NexusVPN Pro с компьютера.", "uninstall"))
        installed = uninstall.is_installed()
        what = QLabel(
            "<b>Будет удалено:</b><ul>"
            "<li>программа и все её файлы" + (" (через стандартный деинсталлятор Windows)" if installed
                                                 else f" — папка {paths.BASE_DIR}") + "</li>"
            "<li>ярлыки на рабочем столе и в меню «Пуск», запись в «Установленных приложениях»</li>"
            "<li>автозапуск (задание Планировщика), правила Брандмауэра Windows</li>"
            "<li>подключения IKEv2, созданные программой; настройки системного прокси возвращаются как были</li>"
            "<li>ядра, базы правил, журналы</li></ul>"
            "OpenVPN, если вы его ставили, — отдельная программа: удаляется через «Установленные приложения».")
        what.setWordWrap(True)
        what.setTextFormat(Qt.RichText)
        v.addWidget(what)
        self.purge = QCheckBox("Удалить также настройки, подписки, серверы и изученные правила")
        self.purge.setChecked(True)
        v.addWidget(with_help(self.purge, "uninstall_purge"))
        row = QHBoxLayout()
        row.addWidget(btn("Удалить NexusVPN Pro", self.run, "danger"))
        row.addStretch()
        v.addLayout(row)
        v.addStretch()

    def run(self) -> None:
        extra = "\n\nНастройки и подписки тоже будут удалены." if self.purge.isChecked() else \
            "\n\nНастройки и подписки останутся — пригодятся при повторной установке."
        if QMessageBox.question(self, "Удаление", "Удалить NexusVPN Pro с этого компьютера?" + extra,
                                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        self.app.uninstall(self.purge.isChecked())
