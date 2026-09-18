@echo off
echo ============================================
echo   XZT-IIoT — GitHub setup helper
echo ============================================
echo.
echo Step 1: Initializing local git repository...
git init
git add .
git commit -m "XZT-IIoT: explainable zero-trust IIoT security with adversarial evasion study"
echo.
echo Step 2: Done. Now:
echo   1. Go to github.com and click "New repository"
echo      (do NOT check "Initialize with README" - we already have one)
echo   2. Copy the repository URL it gives you (looks like
echo      https://github.com/YOUR_USERNAME/xzt-iiot.git)
echo.
set /p repourl="Paste that URL here and press Enter: "
git remote add origin %repourl%
git branch -M main
git push -u origin main
echo.
echo Done! Your browser should have opened to log in to GitHub if needed.
pause
