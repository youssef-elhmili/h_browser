#!/usr/bin/env python3
"""
H Browser - Simple Python Web Browser using PySide6 (Qt for Python) and Qt WebEngine.

Features:
- Tabbed browsing
- Address bar with Enter to navigate
- Back / Forward / Reload / Home buttons
- Simple bookmarks (saved to bookmarks.json)
- Status bar showing load progress
- Open URL in new tab
- Persisted history and optional saved logins/passwords (using OS keyring when available)
- Automatic saving of logins when login forms are submitted (uses QWebChannel)

Requirements:
- Python 3.8+
- pip install PySide6
- Optional (recommended): pip install keyring

Run:
    python3 h_browser.py

This file is a single-file minimal browser intended for learning and small tasks.
Use at your own risk. This is NOT a full-featured secure browser. If you enable saving passwords,
those will be stored using the OS keyring when available.
"""

import json
import os
import sys
from datetime import datetime
from typing import Optional

from PySide6.QtCore import QUrl, Slot, QSize, QObject
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QApplication,
    QLineEdit,
    QMainWindow,
    QToolBar,
    QVBoxLayout,
    QWidget,
    QTabWidget,
    QStatusBar,
    QInputDialog,
    QMessageBox,
    QFileDialog,
)
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWebChannel import QWebChannel

# Optional dependency for secure password storage
try:
    import keyring
    KEYRING_AVAILABLE = True
except Exception:
    keyring = None
    KEYRING_AVAILABLE = False

BOOKMARKS_FILE = "bookmarks.json"
HISTORY_FILE = "history.json"
LOGINS_FILE = "logins.json"  # metadata (origin -> {username, fallback_password})
HOME_PAGE = "https://www.google.com"


# Bridge object exposed to page JS via QWebChannel. JS calls saveCredentials(origin, username, password)
class JSBridge(QObject):
    def __init__(self, mainwindow):
        super().__init__()
        self.mainwindow = mainwindow

    @Slot(str, str, str)
    def saveCredentials(self, origin: str, username: str, password: str):
        # Called from page JS when a form is submitted
        try:
            self.mainwindow.save_login_auto(origin, username, password)
        except Exception:
            pass


class BrowserTab(QWidget):
    def __init__(self, parent=None, url: str = HOME_PAGE):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)
        self.webview = QWebEngineView()
        self.webview.setUrl(QUrl(url))

        # Address bar
        self.urlbar = QLineEdit()
        self.urlbar.returnPressed.connect(self.on_enter_url)

        # Hook webview signals
        self.webview.urlChanged.connect(self.update_urlbar)
        self.webview.loadProgress.connect(self.on_load_progress)
        self.webview.titleChanged.connect(self.on_title_changed)

        self.layout.addWidget(self.urlbar)
        self.layout.addWidget(self.webview)
        self.setLayout(self.layout)

    @Slot()
    def on_enter_url(self):
        url_text = self.urlbar.text().strip()
        if not url_text:
            return
        if not url_text.startswith(("http://", "https://")):
            url_text = "http://" + url_text
        self.webview.setUrl(QUrl(url_text))

    @Slot(QUrl)
    def update_urlbar(self, qurl: QUrl):
        # keep address bar in sync (do not overwrite while user typing could be improved)
        self.urlbar.setText(qurl.toString())

    @Slot(int)
    def on_load_progress(self, progress: int):
        # parent will update status bar
        w = self.window()
        if hasattr(w, "statusBar") and w.statusBar():
            w.statusBar().showMessage(f"Loading... {progress}%")

    @Slot(str)
    def on_title_changed(self, title: str):
        # update tab text
        mw = self.window()
        if isinstance(mw, MainWindow):
            idx = mw.tabs.indexOf(self)
            if idx != -1:
                mw.tabs.setTabText(idx, title[:40])


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("H Browser - Minimal Python Browser")
        self.resize(1000, 700)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.currentChanged.connect(self.on_tab_changed)
        self.setCentralWidget(self.tabs)

        self.status = QStatusBar()
        self.setStatusBar(self.status)

        # persisted data
        self.bookmarks = self.load_bookmarks()
        self.history = self.load_history()
        self.logins = self.load_logins_metadata()

        # JS bridge + webchannel for auto-saving credentials
        self.js_bridge = JSBridge(self)
        self.web_channel = QWebChannel()
        self.web_channel.registerObject('hbridge', self.js_bridge)

        self._create_toolbar()
        self._create_menu()

        # Open an initial tab
        self.add_new_tab(HOME_PAGE, label="Home")

    def _create_toolbar(self):
        navtb = QToolBar("Navigation")
        navtb.setIconSize(QSize(16, 16))
        self.addToolBar(navtb)

        back_btn = QAction("Back", self)
        back_btn.triggered.connect(lambda: self._safe_call('back'))
        navtb.addAction(back_btn)

        forward_btn = QAction("Forward", self)
        forward_btn.triggered.connect(lambda: self._safe_call('forward'))
        navtb.addAction(forward_btn)

        reload_btn = QAction("Reload", self)
        reload_btn.triggered.connect(lambda: self._safe_call('reload'))
        navtb.addAction(reload_btn)

        home_btn = QAction("Home", self)
        home_btn.triggered.connect(self.go_home)
        navtb.addAction(home_btn)

        newtab_btn = QAction("New Tab", self)
        newtab_btn.triggered.connect(lambda: self.add_new_tab(HOME_PAGE))
        navtb.addAction(newtab_btn)

        bookmark_btn = QAction("Bookmark", self)
        bookmark_btn.triggered.connect(self.add_bookmark_for_current)
        navtb.addAction(bookmark_btn)

        open_file_btn = QAction("Open File", self)
        open_file_btn.triggered.connect(self.open_file)
        navtb.addAction(open_file_btn)

    def _create_menu(self):
        menubar = self.menuBar()

        file_menu = menubar.addMenu("File")
        open_action = QAction("Open URL...", self)
        open_action.triggered.connect(self.open_url_dialog)
        file_menu.addAction(open_action)

        save_bookmarks_action = QAction("Export Bookmarks...", self)
        save_bookmarks_action.triggered.connect(self.export_bookmarks)
        file_menu.addAction(save_bookmarks_action)

        # Passwords / logins menu
        pwd_menu = menubar.addMenu("Logins")
        save_login_action = QAction("Save Login for Current Site...", self)
        save_login_action.triggered.connect(self.save_login_for_current)
        pwd_menu.addAction(save_login_action)

        autofill_action = QAction("Autofill Login for Current Site", self)
        autofill_action.triggered.connect(self.autofill_login_for_current)
        pwd_menu.addAction(autofill_action)

        manage_action = QAction("Manage Saved Logins...", self)
        manage_action.triggered.connect(self.manage_logins)
        pwd_menu.addAction(manage_action)

        # History menu
        history_menu = menubar.addMenu("History")
        view_history_action = QAction("View History...", self)
        view_history_action.triggered.connect(self.view_history)
        history_menu.addAction(view_history_action)

        # Bookmarks menu
        bookmarks_menu = menubar.addMenu("Bookmarks")
        self.bookmarks_menu = bookmarks_menu
        self.refresh_bookmarks_menu()

    def _safe_call(self, method_name: str):
        """Call back/forward/reload safely if a webview exists."""
        web = self.current_webview()
        if not web:
            return
        try:
            getattr(web, method_name)()
        except Exception:
            pass

    # -------------------- Bookmarks --------------------
    def load_bookmarks(self):
        if os.path.exists(BOOKMARKS_FILE):
            try:
                with open(BOOKMARKS_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return []
        return []

    def save_bookmarks(self):
        try:
            with open(BOOKMARKS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.bookmarks, f, indent=2)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to save bookmarks: {e}")

    def refresh_bookmarks_menu(self):
        self.bookmarks_menu.clear()
        for bm in self.bookmarks:
            act = QAction(bm.get("title", bm.get("url")), self)
            act.triggered.connect(lambda checked=False, url=bm.get("url"): self.add_new_tab(url))
            self.bookmarks_menu.addAction(act)
        if not self.bookmarks:
            self.bookmarks_menu.addAction(QAction("(no bookmarks)", self))

    def add_bookmark_for_current(self):
        web = self.current_webview()
        if not web:
            return
        url = web.url().toString()
        title = web.title() or url
        self.bookmarks.append({"title": title, "url": url})
        self.save_bookmarks()
        self.refresh_bookmarks_menu()
        self.status.showMessage("Added bookmark", 3000)

    def export_bookmarks(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export bookmarks to JSON", "", "JSON Files (*.json);;All Files(*)")
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(self.bookmarks, f, indent=2)
                QMessageBox.information(self, "Exported", f"Bookmarks exported to {path}")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Could not export bookmarks: {e}")

    # -------------------- History --------------------
    def load_history(self):
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return []
        return []

    def save_history(self):
        try:
            with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                json.dump(self.history, f, indent=2)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to save history: {e}")

    def record_history(self, url: str, title: Optional[str]):
        entry = {
            "url": url,
            "title": title or "",
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
        # Avoid immediate duplicates (same URL as last)
        if not self.history or self.history[-1].get("url") != url:
            self.history.append(entry)
            # keep last 2000 entries max
            if len(self.history) > 2000:
                self.history = self.history[-2000:]
            self.save_history()

    def view_history(self):
        # Show a simple dialog with recent history entries
        if not self.history:
            QMessageBox.information(self, "History", "No history recorded yet.")
            return
        lines = []
        for e in reversed(self.history[-200:]):
            t = e.get("timestamp", "")
            title = e.get("title", "")
            url = e.get("url")
            lines.append(f"{t} - {title} - {url}")
        dlg = QMessageBox(self)
        dlg.setWindowTitle("History (most recent first)")
        dlg.setText("\n".join(lines[:200]))
        dlg.exec()

    # -------------------- Logins / Passwords --------------------
    def load_logins_metadata(self):
        if os.path.exists(LOGINS_FILE):
            try:
                with open(LOGINS_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def save_logins_metadata(self):
        try:
            with open(LOGINS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.logins, f, indent=2)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to save logins metadata: {e}")

    def current_origin(self) -> Optional[str]:
        web = self.current_webview()
        if not web:
            return None
        q = web.url()
        if not q.isValid() or q.scheme() == 'file':
            return None
        host = q.host()
        if not host:
            return None
        return f"{q.scheme()}://{host}"

    def save_login_for_current(self):
        origin = self.current_origin()
        if not origin:
            QMessageBox.warning(self, "Save Login", "No valid origin for current page.")
            return
        username, ok = QInputDialog.getText(self, "Save Login", "Username:")
        if not ok or not username:
            return
        password, ok = QInputDialog.getText(self, "Save Login", "Password:", QLineEdit.Password)
        if not ok:
            return
        # store metadata
        self.logins[origin] = self.logins.get(origin, {})
        self.logins[origin]['username'] = username
        # store secret
        if KEYRING_AVAILABLE:
            try:
                keyring.set_password(f"H Browser:{origin}", username or "", password)
                # ensure no fallback stored
                if 'fallback_password' in self.logins[origin]:
                    self.logins[origin].pop('fallback_password', None)
                self.save_logins_metadata()
                QMessageBox.information(self, "Saved", "Login saved to system keyring.")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to save password to keyring: {e}")
        else:
            # fallback: store password in metadata (insecure)
            self.logins[origin]['fallback_password'] = password
            self.save_logins_metadata()
            QMessageBox.warning(self, "Saved (insecure)", "Keyring not available: saved password in local metadata (insecure). Install 'keyring' for secure storage.")

    def save_login_auto(self, origin: str, username: str, password: str):
        """Automatically save credentials reported from page JS. Minimal checks to avoid spamming."""
        if not origin or not password:
            return
        # normalize origin
        origin = origin.rstrip('/')
        info = self.logins.get(origin, {})
        existing_user = info.get('username')

        # If keyring available, compare existing secret to avoid duplicate writes
        if KEYRING_AVAILABLE and existing_user:
            try:
                existing_pw = keyring.get_password(f"H Browser:{origin}", existing_user) or ''
                if existing_pw == password and existing_user == username:
                    # nothing to do
                    return
            except Exception:
                pass

        # Save metadata username if not present or changed
        if username:
            info['username'] = username
        elif 'username' not in info:
            # store blank username marker
            info['username'] = ''

        # Save secret
        if KEYRING_AVAILABLE:
            try:
                keyring.set_password(f"H Browser:{origin}", username or '', password)
                # remove fallback if any
                info.pop('fallback_password', None)
            except Exception:
                # fallback to metadata if keyring fails
                info['fallback_password'] = password
        else:
            info['fallback_password'] = password

        self.logins[origin] = info
        self.save_logins_metadata()
        # show a brief non-blocking status message
        try:
            self.status.showMessage(f"Saved login for {origin}", 3000)
        except Exception:
            pass

    def autofill_login_for_current(self):
        origin = self.current_origin()
        if not origin:
            QMessageBox.warning(self, "Autofill", "No valid origin for current page.")
            return
        info = self.logins.get(origin)
        if not info or 'username' not in info:
            QMessageBox.information(self, "Autofill", "No saved login for this site.")
            return
        username = info.get('username')
        password = None
        if KEYRING_AVAILABLE:
            try:
                password = keyring.get_password(f"H Browser:{origin}", username or '')
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to read password from keyring: {e}")
                return
        else:
            password = info.get('fallback_password')
            if not password:
                QMessageBox.information(self, "Autofill", "No stored password (and keyring not available).")
                return

        # Inject JS to fill the first username/password inputs (will NOT auto-submit)
        web = self.current_webview()
        if not web:
            return
        import json as _json
        js = "(function(){\n"
        js += "  var u = document.querySelector('input[type=email], input[type=text], input[name*=user], input[id*=user], input[name*=login], input[id*=login]');\n"
        js += "  var p = document.querySelector('input[type=password]');\n"
        js += f"  if(u) u.value = {_json.dumps(username)};\n"
        js += f"  if(p) p.value = {_json.dumps(password)};\n"
        js += "  return !!(u||p);\n"
        js += "})();"

        def _on_js_result(res):
            if res:
                QMessageBox.information(self, "Autofill", "Filled username/password fields (did not submit).")
            else:
                QMessageBox.information(self, "Autofill", "Could not find form fields to fill on this page.")

        web.page().runJavaScript(js, _on_js_result)

    def manage_logins(self):
        # present a simple chooser for origins
        origins = list(self.logins.keys())
        if not origins:
            QMessageBox.information(self, "Manage Logins", "No saved logins.")
            return
        origin, ok = QInputDialog.getItem(self, "Manage Logins", "Saved sites:", origins, 0, False)
        if not ok or not origin:
            return
        info = self.logins.get(origin, {})
        username = info.get('username', '')
        # options: show username, delete
        choice, ok = QInputDialog.getItem(self, "Saved Login", f"Site: {origin}\nUsername: {username}", ["Delete", "Cancel"], 1, False)
        if not ok or choice == "Cancel":
            return
        if choice == "Delete":
            # delete from metadata
            self.logins.pop(origin, None)
            # delete from keyring if available
            if KEYRING_AVAILABLE and username is not None:
                try:
                    keyring.delete_password(f"H Browser:{origin}", username or '')
                except Exception:
                    # ignore
                    pass
            self.save_logins_metadata()
            QMessageBox.information(self, "Deleted", "Saved login deleted.")

    # -------------------- URL / Tabs --------------------
    def open_url_dialog(self):
        url, ok = QInputDialog.getText(self, "Open URL", "Enter URL:")
        if ok and url:
            if not url.startswith(("http://", "https://")):
                url = "http://" + url
            self.add_new_tab(url)

    def open_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open HTML file", "", "HTML Files (*.htm *.html);;All Files(*)")
        if path:
            qurl = QUrl.fromLocalFile(path)
            self.add_new_tab(qurl.toString())

    def add_new_tab(self, url: str = HOME_PAGE, label: str = None):
        browser = BrowserTab(self, url)
        i = self.tabs.addTab(browser, label or "New Tab")
        self.tabs.setCurrentIndex(i)
        # update URL bar of new tab when page loads
        browser.webview.loadFinished.connect(lambda ok, b=browser: self._on_tab_loaded(b, ok))
        # ensure the page has access to our QWebChannel object
        try:
            browser.webview.page().setWebChannel(self.web_channel)
        except Exception:
            pass

    def _on_tab_loaded(self, tab: BrowserTab, ok: bool):
        # called when a tab finishes loading
        # record history and show status
        self.on_load_finished(tab, ok)
        if ok:
            # inject JS that attaches to form submit events and calls our bridge
            js = r"(function(){\n" \
                 r"  if(window.__hbrowser_autosave_installed) return;\n" \
                 r"  var s = document.createElement('script');\n" \
                 r"  s.src = 'qrc:///qtwebchannel/qwebchannel.js';\n" \
                 r"  s.onload = function(){\n" \
                 r"    try{\n" \
                 r"      new QWebChannel(qt.webChannelTransport, function(channel){\n" \
                 r"        window.hbridge = channel.objects.hbridge;\n" \
                 r"        function attachForm(f){\n" \
                 r"          try{\n" \
                 r"            f.addEventListener('submit', function(e){\n" \
                 r"              try{\n" \
                 r"                var pwd = f.querySelector('input[type=password]');\n" \
                 r"                if(!pwd) return;\n" \
                 r"                var user = f.querySelector('input[type=email], input[type=text], input[name*=user], input[id*=user], input[name*=login], input[id*=login]');\n" \
                 r"                var u = user ? user.value : '';\n" \
                 r"                var p = pwd.value;\n" \
                 r"                try{ window.hbridge.saveCredentials(location.origin, u, p); }catch(_e){}\n" \
                 r"              }catch(_e){}\n" \
                 r"            }, true);\n" \
                 r"          }catch(_e){}\n" \
                 r"        }\n" \
                 r"        Array.from(document.forms).forEach(attachForm);\n" \
                 r"        var mo = new MutationObserver(function(muts){\n" \
                 r"          muts.forEach(function(m){\n" \
                 r"            m.addedNodes.forEach(function(n){\n" \
                 r"              if(n && n.tagName && n.tagName.toLowerCase()==='form') attachForm(n);\n" \
                 r"            });\n" \
                 r"          });\n" \
                 r"        });\n" \
                 r"        mo.observe(document, {childList:true, subtree:true});\n" \
                 r"        window.__hbrowser_autosave_installed = true;\n" \
                 r"      });\n" \
                 r"    }catch(_e){}\n" \
                 r"  };\n" \
                 r"  document.head.appendChild(s);\n" \
                 r"})();"
            try:
                tab.webview.page().runJavaScript(js)
            except Exception:
                pass

    def on_load_finished(self, tab: BrowserTab, ok: bool):
        if ok:
            # record history on successful load
            try:
                url = tab.webview.url().toString()
                title = tab.webview.title()
                self.record_history(url, title)
            except Exception:
                pass
            self.status.showMessage("Load finished", 2000)
        else:
            self.status.showMessage("Failed to load page", 2000)

    def close_tab(self, i: int):
        if self.tabs.count() < 2:
            return
        self.tabs.removeTab(i)

    def on_tab_changed(self, i: int):
        cur = self.tabs.widget(i)
        if isinstance(cur, BrowserTab):
            self.status.showMessage(cur.webview.url().toString(), 2000)

    def current_webview(self) -> Optional[QWebEngineView]:
        cur = self.tabs.currentWidget()
        if isinstance(cur, BrowserTab):
            return cur.webview
        return None

    def go_home(self):
        w = self.current_webview()
        if w:
            w.setUrl(QUrl(HOME_PAGE))


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("H Browser")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
