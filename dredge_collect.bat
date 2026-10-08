@echo off
powershell -ExecutionPolicy Bypass -File "%~dp0dredge_collect.ps1" %*
