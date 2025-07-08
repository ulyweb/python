#!/bin/bash

echo "🔧 Creating Python virtual environment in ./venv..."
python3 -m venv venv

echo "✅ Virtual environment created."

echo "📦 Installing required packages: flask, bcrypt..."
venv/bin/pip install --upgrade pip
venv/bin/pip install flask bcrypt

echo "✅ Packages installed."

echo ""
echo "🚀 To activate the virtual environment and run the app:"
echo "   source venv/bin/activate"
echo "   python app.py"
echo ""
echo "🌐 Then open your browser to http://localhost:5000"
