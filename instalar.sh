#!/bin/bash
# audit_box — Script de instalación (Kali Linux / Debian / Ubuntu)

echo "🔧 Instalando dependencias del sistema..."
sudo apt-get update -q
sudo apt-get install -y nmap nikto whatweb python3 python3-pip

echo "🐍 Instalando dependencias Python..."
pip3 install flask Pillow pypdf python-docx dnspython requests --break-system-packages

echo "📦 Instalando nuclei..."
NUCLEI_VER=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
  | grep tag_name | cut -d '"' -f4)
ARCH=$(uname -m)
[ "$ARCH" = "x86_64" ] && ARCH="amd64"
[ "$ARCH" = "aarch64" ] && ARCH="arm64"
wget -q "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VER}/nuclei_${NUCLEI_VER#v}_linux_${ARCH}.zip" \
  -O /tmp/nuclei.zip
unzip -qo /tmp/nuclei.zip -d /tmp/nuclei_bin
sudo mv /tmp/nuclei_bin/nuclei /usr/local/bin/nuclei
sudo chmod +x /usr/local/bin/nuclei
nuclei -update-templates -silent 2>/dev/null || true

echo ""
echo "✅ Instalación completa."
echo ""
echo "Para iniciar audit_box:"
echo "  cd audit_box"
echo "  python3 app.py"
echo ""
echo "Luego abre: http://localhost:5000"
