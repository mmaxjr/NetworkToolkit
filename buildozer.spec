[app]
title = MAX
package.name = max
package.domain = org.symanet
source.dir = .
source.include_exts = py,png,jpg,kv,atlas
version = 1.0

# Icone do app + splash nativo simples (so texto "MAX", sem logo grande).
# Sem presplash.filename o Android usa o splash padrao feio do Kivy (o
# losango cinza "Loading..."), entao mantemos uma imagem simples aqui.
# A "tela de loading" real com barra animada e' desenhada pelo proprio
# app em Kivy assim que o Python inicia (ver LoadingOverlay).
icon.filename = %(source.dir)s/icon.png
presplash.filename = %(source.dir)s/presplash.png
android.presplash_color = #12141A

requirements = python3==3.11.6,hostpython3==3.11.6,kivy==2.3.0,pyjnius,certifi

# SSH (aba SSH) e' implementado com JSch, uma biblioteca SSH2 100% Java (sem
# nenhum codigo nativo), chamada via pyjnius. Isso substitui uma tentativa
# anterior com paramiko, cujas dependencias nativas (bcrypt, pynacl,
# cryptography) se mostraram muito frageis/impossiveis de cross-compilar
# nesta toolchain (python-for-android + NDK r25b).
#
# O jar do JSch e' baixado por um passo do workflow (para libs/jsch-0.1.55.jar)
# e incluido aqui via add_jars -- gradle_dependencies foi tentado primeiro,
# mas nesta combinacao de buildozer/python-for-android o Gradle so empacotava
# a classe principal (JSch) e nao as classes internas (Session, Channel etc),
# causando ClassNotFoundException em tempo de execucao. add_jars e' o
# mecanismo mais antigo/testado do buildozer para bundlar jars Java puros.
android.add_jars = libs/jsch-0.1.55.jar

orientation = portrait
fullscreen = 0

android.permissions = INTERNET,ACCESS_WIFI_STATE,CHANGE_WIFI_STATE,ACCESS_NETWORK_STATE,ACCESS_FINE_LOCATION,ACCESS_COARSE_LOCATION

android.api = 33
android.minapi = 21
android.ndk = 25b
android.archs = arm64-v8a,armeabi-v7a
android.allow_backup = True

[buildozer]
log_level = 2
warn_on_root = 1
