import logging
import sys
import shutil
from colorama import Fore, Style, init as colorama_init

# ===================== 彩色日志工具 =====================

colorama_init(autoreset=True)

class ColoredFormatter(logging.Formatter):
    LEVEL_STYLES = {
        logging.DEBUG: (Fore.BLUE, False),
        logging.INFO: (Fore.GREEN, False),
        logging.WARNING: (Fore.YELLOW, True),
        logging.ERROR: (Fore.RED, True),
        logging.CRITICAL: (Fore.MAGENTA, True),
    }

    def __init__(self, fmt: str, datefmt: str | None = None, use_color: bool = True):
        super().__init__(fmt, datefmt)
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        levelno = record.levelno
        original_levelname = record.levelname

        try:
            padded = original_levelname.ljust(8)
            if self.use_color and levelno in self.LEVEL_STYLES:
                color, bold = self.LEVEL_STYLES[levelno]
                if bold:
                    levelname_color = f"{Style.BRIGHT}{color}{padded}{Style.RESET_ALL}"
                else:
                    levelname_color = f"{color}{padded}{Style.RESET_ALL}"
                record.levelname = levelname_color
            else:
                record.levelname = padded

            return super().format(record)
        finally:
            record.levelname = original_levelname

class BottomConsoleHandler(logging.StreamHandler):
    """
    自定义 Handler：将日志输出到终端底部
    """
    def emit(self, record):
        try:
            msg = self.format(record)
            columns, lines = shutil.get_terminal_size()
            sys.stdout.write(f"\033[s\033[{lines};1H\033[K{msg}\033[u")
            sys.stdout.flush()
        except Exception:
            self.handleError(record)


def setup_logging(
    level: int = logging.INFO,
    use_color: bool = True,
    log_to_file: str | None = None,
    enabled: bool = True,
) -> None:

    root = logging.getLogger()

    while root.handlers:
        root.handlers.pop()

    if not enabled:
        root.setLevel(logging.CRITICAL + 1)
        root.addHandler(logging.NullHandler())
        return

    root.setLevel(level)

    if log_to_file:
        file_handler = logging.FileHandler(log_to_file, encoding="utf-8")
        file_fmt = "%(asctime)s %(levelname)s [%(name)s] %(message)s"
        file_formatter = logging.Formatter(
            fmt=file_fmt,
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_formatter)
        root.addHandler(file_handler)
        
        return

    console_handler = BottomConsoleHandler(sys.stdout)
    console_fmt = "%(asctime)s %(levelname)s [%(name)s] %(message)s"
    console_formatter = ColoredFormatter(
        fmt=console_fmt,
        datefmt="%H:%M:%S",
        use_color=use_color,
    )
    console_handler.setFormatter(console_formatter)
    root.addHandler(console_handler)

