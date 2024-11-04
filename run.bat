@echo off

rem Set the path to your Python installation (change if needed)
set PYTHONPATH=C:\Users\User\AppData\Local\Programs\Python\Python312

rem Ensure Python is installed and accessible from the command line
python --version


rem Start the auth server in a new command window with a customized title
start "Auth Server" cmd /k "%PYTHONPATH%\python auth\server.py"

rem Start the msg server in a new command window with a customized title
start "Msg Server" cmd /k "%PYTHONPATH%\python msg\msg_server.py"

rem Wait for 5 seconds to allow the servers to fully initialize (adjust as needed)
timeout /t 1 /nobreak

rem Start the client in a new command window with a customized title
start "Client" cmd /k "%PYTHONPATH%\python client\client.py"

echo All scripts launched successfully!

pause
