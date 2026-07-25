%define app_name    gost-proxy
%define version     1.0.0
%define release     1%{?dist}
%define arch        x86_64

Name:           %{app_name}
Version:        %{version}
Release:        %{release}
Summary:        Прокси-сервер с шифрованием ГОСТ Р 34.12-2015 (Кузнечик)
Group:          System Environment/Networking
License:        MIT
URL:            https://github.com/user/gost-proxy
Source0:        %{app_name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  make

%description
Прокси-сервер и клиент с шифрованием ГОСТ Р 34.12-2015 "Кузнечик".
Ядро шифрования реализовано на ассемблере x86-64 (NASM) для максимальной
производительности. Транспорт — UDP (аналог Hysteria2).

# ─── Пакет клиента ───
%package client
Summary:        Клиент ГОСТ Прокси-Сервера
Group:          System Environment/Networking
Requires:       glibc

%description client
Клиент для подключения к ГОСТ Прокси-Серверу.
Шифрует и расшифровывает данные с использованием ГОСТ Р 34.12-2015 (Кузнечик).

# ─── Пакет сервера ───
%package server
Summary:        ГОСТ Прокси-Сервер
Group:          System Environment/Networking
Requires:       glibc

%description server
Прокси-сервер с шифрованием ГОСТ Р 34.12-2015 "Кузнечик".
Поддерживает до 256 одновременных сессий, многопоточную обработку.

# ─── Prep ───
%prep
%setup -q -n %{app_name}-%{version}

# ─── Build ───
%build
make

# ─── Install ───
%install
rm -rf %{buildroot}

# Директории
install -d %{buildroot}%{_bindir}
install -d %{buildroot}%{_sysconfdir}/%{app_name}
install -d %{buildroot}%{_unitdir}
install -d %{buildroot}%{_mandir}/man1

# Бинарники
install -m 0755 build/gost-server %{buildroot}%{_bindir}/gost-server
install -m 0755 build/gost-client %{buildroot}%{_bindir}/gost-client

# Конфигурация (JSON)
install -m 0644 config/server.json %{buildroot}%{_sysconfdir}/%{app_name}/server.json
install -m 0644 config/client.json %{buildroot}%{_sysconfdir}/%{app_name}/client.json

# Systemd unit файлы
cat > %{buildroot}%{_unitdir}/gost-proxy-server.service << 'EOF'
[Unit]
Description=ГОСТ Прокси-Сервер
After=network.target

[Service]
Type=simple
ExecStart=%{_bindir}/gost-server %{_sysconfdir}/%{app_name}/server.json
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# Man pages
echo ".TH GOST-SERVER 1 \"2025-07-24\" \"gost-proxy %{version}\"" > %{buildroot}%{_mandir}/man1/gost-server.1
echo ".SH NAME\n gost-server \\- ГОСТ Прокси-Сервер" >> %{buildroot}%{_mandir}/man1/gost-server.1
echo ".SH SYNOPSIS\n .B gost-server [\fIport\fR]" >> %{buildroot}%{_mandir}/man1/gost-server.1

echo ".TH GOST-CLIENT 1 \"2025-07-24\" \"gost-proxy %{version}\"" > %{buildroot}%{_mandir}/man1/gost-client.1
echo ".SH NAME\n gost-client \\- Клиент ГОСТ Прокси-Сервера" >> %{buildroot}%{_mandir}/man1/gost-client.1
echo ".SH SYNOPSIS\n .B gost-client [\fIserver_ip\fR] [\fIport\fR]" >> %{buildroot}%{_mandir}/man1/gost-client.1

# ─── Files ───
%files client
%{_bindir}/gost-client
%{_sysconfdir}/%{app_name}/client.json
%{_mandir}/man1/gost-client.1*

%files server
%{_bindir}/gost-server
%{_sysconfdir}/%{app_name}/server.json
%{_unitdir}/gost-proxy-server.service
%{_mandir}/man1/gost-server.1*

%post server
%systemd_post gost-proxy-server.service

%preun server
%systemd_preun gost-proxy-server.service

%postun server
%systemd_postun_with_restart gost-proxy-server.service

# ─── Changelog ───
%changelog
* Thu Jul 24 2025 Developer <dev@example.com> - 1.0.0-1
- Initial RPM release
- ГОСТ Р 34.12-2015 (Кузнечик) на NASM x86-64
- UDP-транспорт (аналог Hysteria2)
- JSON-конфигурация (server.json, client.json)
- Сервер и клиент
