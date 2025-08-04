import sys
from PyQt5.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve
from PyQt5.QtGui import QPixmap, QIcon, QFont, QColor
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QLabel, QSplashScreen, QWidget, QVBoxLayout,
    QLineEdit, QPushButton, QComboBox, QSpinBox, QTextEdit, QMessageBox,
    QGroupBox, QFormLayout, QHBoxLayout, QGraphicsDropShadowEffect
)
import os

class SplashScreen(QSplashScreen):
    def __init__(self):
        pixmap = QPixmap(400, 300)
        pixmap.fill(Qt.black)
        super().__init__(pixmap)
        self.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint)

        self.label = QLabel("T-Flood", self)
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setStyleSheet("color: red; font-size: 32px; font-weight: bold;")
        self.label.setGeometry(0, 100, 400, 50)

        self.status = QLabel("Loading modules...", self)
        self.status = QLabel("This Tool was developped by AMAIRA SAFWEN ...", self)

        self.status.setAlignment(Qt.AlignCenter)
        self.status.setStyleSheet("color: white;")
        self.status.setGeometry(0, 160, 400, 30)

        self.fade_anim = QPropertyAnimation(self.label, b"windowOpacity")
        self.fade_anim.setDuration(1500)
        self.fade_anim.setStartValue(0)
        self.fade_anim.setEndValue(1)
        self.fade_anim.start()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("T-Flood : DDos Attack Simulation - By AMAIRA SAFWEN")
        self.setGeometry(400, 200, 700, 600)
        icon_path = os.path.join(os.path.dirname(__file__), 'assets', 'icon.png')
        self.setWindowIcon(QIcon(icon_path))
        self.setStyleSheet("""
            QWidget {
                background-color: #121212;
                color: #ffffff;
                font-family: 'Segoe UI';
                font-size: 12pt;
            }
       QGroupBox {
    border: 1px solid #444;
    border-radius: 10px;
    margin-top: 20px; /* more space on top */
    padding-top: 30px; /* space so the title text doesn't overlap content */
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 3px 0 3px;
    color: #ff4c4c;
    font-weight: bold;
    font-size: 14pt;
}

            QLineEdit, QComboBox, QSpinBox {
                background-color: #1e1e1e;
                border: 1px solid #333;
                border-radius: 6px;
                padding: 6px;
                color: #ddd;
            }
            QTextEdit {
                background-color: #1e1e1e;
                border: 1px solid #333;
                color: #ccc;
                padding: 10px;
                border-radius: 6px;
                font-family: 'Courier New';
            }
        """)

        self.init_ui()

    def init_ui(self):
        central_widget = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)

        # GroupBox: Attack Settings
        sim_group = QGroupBox("Attack Settings")
        form = QFormLayout()

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Target (https://T-flood.com / 192.168.1.1)")
        form.addRow("Target:", self.target_input)

        self.sim_type = QComboBox()
        self.sim_type.addItems(["HTTP Load", "SYN Flooding", "UDP Load"])
        form.addRow("Flooding Type:", self.sim_type)

        self.threads = QSpinBox()
        self.threads.setRange(1, 10000)
        self.threads.setValue(100)
        form.addRow("Threads:", self.threads)

        self.duration = QSpinBox()
        self.duration.setRange(1, 3600)
        self.duration.setValue(60)
        form.addRow("Duration (seconds):", self.duration)

        sim_group.setLayout(form)
        layout.addWidget(sim_group)

        # Buttons
        button_layout = QHBoxLayout()

        self.start_btn = QPushButton("Flood")
        self.start_btn.setObjectName("startBtn")
        self._style_button(self.start_btn, "#1e90ff")
        self.start_btn.clicked.connect(self.start_simulation)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setObjectName("stopBtn")
        self._style_button(self.stop_btn, "#d9534f")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_simulation)

        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.stop_btn)
        layout.addLayout(button_layout)

        # Log area
        log_box = QGroupBox("Logs")
        log_layout = QVBoxLayout()

        self.logs = QTextEdit()
        self.logs.setReadOnly(True)
        log_layout.addWidget(self.logs)
        log_box.setLayout(log_layout)

        layout.addWidget(log_box)
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        self.simulation_running = False

    def _style_button(self, btn, color_hex):
        color = QColor(color_hex)
        btn.setStyleSheet(f"""
            QPushButton #{btn.objectName()} {{
                background-color: {color.name()};
                color: white;
                font-weight: bold;
                border-radius: 10px;
                padding: 12px 30px;
            }}
            QPushButton #{btn.objectName()}:hover:!disabled {{
                background-color: {color.lighter(130).name()};
            }}
            QPushButton #{btn.objectName()}:disabled {{
                background-color: #555;
            }}
        """)
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(20)
        shadow.setColor(color)
        shadow.setOffset(0, 0)
        btn.setGraphicsEffect(shadow)

        # Animation
        anim = QPropertyAnimation(btn, b"geometry")
        anim.setDuration(250)
        anim.setEasingCurve(QEasingCurve.OutBack)
        anim.setStartValue(btn.geometry())
        anim.setEndValue(btn.geometry().adjusted(-2, -2, 2, 2))
        anim.setLoopCount(1)
        anim.start()

    def start_simulation(self):
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Input Error", "Please enter a valid target.")
            return

        self.logs.append(f"[+] Flooding started on {target} using {self.sim_type.currentText()} for {self.duration.value()} seconds.")
        self.simulation_running = True
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def stop_simulation(self):
        if self.simulation_running:
            self.logs.append("[-] Flooding stopped.")
            self.simulation_running = False
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)


def main():
    app = QApplication(sys.argv)
    splash = SplashScreen()
    splash.show()
    QTimer.singleShot(2000, splash.close)

    win = MainWindow()
    QTimer.singleShot(2000, win.show)
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
