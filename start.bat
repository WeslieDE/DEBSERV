@echo off
REM Prüfen, ob der venv-Ordner existiert
IF NOT EXIST "venv" (
    echo Erstelle virtuelles Environment...
    python -m venv venv
    call venv\Scripts\activate.bat
    echo Aktualisiere pip...
    python -m pip install --upgrade pip setuptools wheel
    echo Installiere Pakete...
    pip install --upgrade --force-reinstall cryptography
) ELSE (
    echo Virtuelles Environment existiert bereits.
    call venv\Scripts\activate.bat
)

REM Starte den Entwicklungsserver
python dev_webserver.py

pause