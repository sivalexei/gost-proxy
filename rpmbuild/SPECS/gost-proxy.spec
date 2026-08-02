%define app_name    gost-proxy
%define version     1.0.0
%define release     2%{?dist}
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
# nasm нужен для src/core/tcp_helpers.asm
BuildRequires:  nasm

%description
Прокси-сервер и клиент с шифрованием ГОСТ Р 34.12-2015 "Кузнечик".
Шифрование — C-реализация по RFC 7801, проверенная на контрольных
векторах §A.1. Транспорт — UDP.

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

# ─── Check ───
# Контрольные векторы RFC 7801 §A.1 — сборка падает, если шифр неверен
%check
make test

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

cat > %{buildroot}%{_unitdir}/gost-proxy-client.service << 'EOF'
[Unit]
Description=ГОСТ Прокси-Клиент
After=network.target

[Service]
Type=simple
ExecStart=%{_bindir}/gost-client %{_sysconfdir}/%{app_name}/client.json
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
%{_unitdir}/gost-proxy-client.service
%{_mandir}/man1/gost-client.1*

%files server
%{_bindir}/gost-server
%{_sysconfdir}/%{app_name}/server.json
%{_unitdir}/gost-proxy-server.service
%{_mandir}/man1/gost-server.1*

%post server
mkdir -p /var/log/gost-proxy
chmod 755 /var/log/gost-proxy
%systemd_post gost-proxy-server.service

%preun server
%systemd_preun gost-proxy-server.service

%postun server
%systemd_postun_with_restart gost-proxy-server.service

%post client
mkdir -p /var/log/gost-proxy
chmod 755 /var/log/gost-proxy
%systemd_post gost-proxy-client.service

%preun client
%systemd_preun gost-proxy-client.service

%postun client
%systemd_postun_with_restart gost-proxy-client.service

# ─── Changelog ───
%changelog
* Sat Aug 01 2026 Developer <dev@example.com> - 1.0.0-2
- Исправлена сборка: устранено дублирование символа kuznyechik_precompute_tables
- Ассемблерная реализация Кузнечика исключена из сборки (не проходила
  контрольные векторы RFC 7801, приводила к зависанию/SIGSEGV при старте)
- Восстановлена корректная таблица S-box, шифрование переведено на
  проверенную C-реализацию (RFC 7801 §A.1)
- Убраны зависимости от /tmp/msquic-full и -lmsquic (не использовались)
- Добавлен BuildRequires: nasm и секция %%check с контрольными векторами
- Бинарники собираются как PIE (снят -no-pie)

* Thu Jul 24 2025 Developer <dev@example.com> - 1.0.0-1
- Initial RPM release
- ГОСТ Р 34.12-2015 (Кузнечик) на NASM x86-64
- UDP-транспорт (аналог Hysteria2)
- JSON-конфигурация (server.json, client.json)
- Сервер и клиент
