#!/bin/bash
# =============================================================================
#  Instalasi Wazuh Agent - macOS
#
#  Yang didukung:
#    Intel        macOS Sierra 10.12 ke atas
#    Apple Silicon macOS Big Sur 11 ke atas
#
#  CARA PAKAI
#
#  Interaktif, skrip menanyakan data yang perlu:
#      sudo bash wazuh_macos.sh
#
#  Tanpa interaksi, lewat variabel lingkungan:
#      sudo WAZUH_MANAGER=10.20.30.40 WAZUH_GROUP=mac-endpoint bash wazuh_macos.sh
#
#  Satu baris dari repo:
#      curl -fsSL https://raw.githubusercontent.com/<user>/<repo>/main/wazuh_macos.sh \
#        | sudo WAZUH_MANAGER=10.20.30.40 WAZUH_GROUP=mac-endpoint bash
#
#  VARIABEL LINGKUNGAN
#    WAZUH_MANAGER     IP atau hostname manager (wajib bila tanpa interaksi)
#    WAZUH_GROUP       satu atau lebih group, pisah koma (wajib bila tanpa interaksi)
#    AGENT_NAME        nama agent, bawaan nama komputer
#    WAZUH_VERSION     versi paket, bawaan 4.9.2-1
#    WAZUH_REG_PORT    port pendaftaran, bawaan 1515
#    WAZUH_COMM_PORT   port pengiriman event, bawaan 1514
#    CONNECT_TIMEOUT   lama tunggu sambungan, bawaan 60 detik
#    SKIP_FIM          isi 1 untuk melewati aturan FIM tambahan
#    SKIP_VERIFY       isi 1 untuk melewati verifikasi akhir
#    ASSUME_YES        isi 1 untuk melewati semua konfirmasi
#    PKG_PATH          berkas .pkg lokal, bila tidak ingin mengunduh
#
#  PERBEDAAN PENTING DARI LINUX
#
#  macOS tidak punya auditd. Pengganti terdekatnya adalah Unified Logging
#  System, yang sudah dipantau lewat <location>macos</location> bawaan
#  paket. Jadi skrip ini tidak memasang aturan audit, dan jumlah langkah
#  lebih sedikit daripada versi Linux.
#
#  Direktori pemasangan /Library/Ossec, bukan /var/ossec.
#
#  TIDAK PERLU REBOOT.
# =============================================================================
set -euo pipefail

# ---------- parameter dasar ----------
# Versi agen sebaiknya sama atau lebih rendah daripada versi manager.
# Agen yang lebih baru dari manager tidak didukung dan bisa gagal
# mendaftar.
WAZUH_VERSION="${WAZUH_VERSION:-4.9.2-1}"

# Bentuk yang diterima repositori Wazuh adalah X.Y.Z-R, misalnya 4.9.2-1.
# Diperiksa di awal supaya kesalahan ketik tidak baru ketahuan setelah
# unduhan 6 MB selesai.
if ! [[ "$WAZUH_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+$ ]]; then
    echo "[FAIL] Versi '$WAZUH_VERSION' tidak sah." >&2
    echo "       Bentuk yang benar: X.Y.Z-R, misalnya 4.9.2-1" >&2
    exit 1
fi

WAZUH_REG_PORT="${WAZUH_REG_PORT:-1515}"
WAZUH_COMM_PORT="${WAZUH_COMM_PORT:-1514}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-60}"
SKIP_FIM="${SKIP_FIM:-0}"
SKIP_VERIFY="${SKIP_VERIFY:-0}"
ASSUME_YES="${ASSUME_YES:-0}"
PKG_PATH="${PKG_PATH:-}"

OSSEC_DIR="/Library/Ossec"
OSSEC_CONF="$OSSEC_DIR/etc/ossec.conf"
OSSEC_LOG="$OSSEC_DIR/logs/ossec.log"
LOCAL_OPT="$OSSEC_DIR/etc/local_internal_options.conf"
CLIENT_KEYS="$OSSEC_DIR/etc/client.keys"
PLIST="/Library/LaunchDaemons/com.wazuh.agent.plist"
PKG_ID="com.wazuh.pkg.wazuh-agent"

# Berkas tempat installer paket membaca variabel pendaftaran. Jalur ini
# ditetapkan Wazuh di src/init/register_configure_agent.sh, bukan pilihan
# skrip ini, jadi tidak boleh diubah.
ENV_FILE="/tmp/wazuh_envs"

MARK_BEGIN="<!-- BEGIN hardening-baseline (dikelola skrip instalasi) -->"
MARK_END="<!-- END hardening-baseline -->"
LOGFILE="/var/log/wazuh-agent-install-$(date +%Y%m%d-%H%M%S).log"

R='\033[31m'; G='\033[32m'; Y='\033[33m'; B='\033[34m'; GRY='\033[90m'; N='\033[0m'
STEP=0
STEP_TOTAL=8
WARN_COUNT=0
declare -a WARN_LIST=()

# Semua keluaran berwarna melewati satu pembungkus.
#
# Teks yang dicetak bisa memuat tanda persen, misalnya dari nama berkas
# atau keluaran perintah. Bila teks itu dipakai sebagai string format
# printf, tanda persen diuraikan sebagai penentu format dan keluarannya
# rusak atau hilang. Di sini format selalu tetap, dan teks selalu lewat
# argumen, sehingga isinya tidak pernah diuraikan.
cwrite(){
  local color="$1" prefix="$2"; shift 2
  printf '%b%s%b %s\n' "$color" "$prefix" "$N" "$*"
}

info(){ cwrite "$B"   "[INFO]" "$*"; }
ok(){   cwrite "$G"   "[ OK ]" "$*"; }
dim(){  cwrite "$GRY" "      " "$*"; }
warn(){
  cwrite "$Y" "[WARN]" "$*"
  WARN_LIST+=("$*")
  WARN_COUNT=$((WARN_COUNT + 1))
}
die(){  cwrite "$R" "[FAIL]" "$*" >&2; exit 1; }
step(){
  STEP=$((STEP + 1))
  echo
  cwrite "$Y" "[$STEP/$STEP_TOTAL]" "$*"
}

# $LINENO di dalam trap ber-kutip-tunggal dievaluasi saat error terjadi,
# bukan saat trap dipasang, jadi nomor barisnya memang baris yang gagal.
trap 'printf "\n%b[FAIL]%b Skrip berhenti di baris %s. Pemasangan TIDAK selesai.\n" "$R" "$N" "$LINENO" >&2' ERR

[ "$(id -u)" -eq 0 ] || die "Harus dijalankan sebagai root. Pakai: sudo bash $0"

# Berkas log ditulis ke /var/log yang selalu ada di macOS.
exec > >(tee -a "$LOGFILE") 2>&1

# ---------- validasi ----------

# Menerima IP maupun hostname, karena Wazuh mendukung <address> berupa
# FQDN. Memaksa IP akan menolak manager di belakang DNS atau penyeimbang
# beban.
validate_host() {
    local h="$1"
    [ -n "$h" ] || return 1

    # Bentuk IPv4. Oktet berawalan nol ditolak karena bukan notasi sah
    # dan sebagian pustaka menafsirkannya sebagai oktal, sehingga
    # 010.1.1.1 bisa berarti alamat yang berbeda dari yang dimaksud.
    if [[ "$h" =~ ^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$ ]]; then
        local IFS='.'
        read -r -a oct <<< "$h"
        for o in "${oct[@]}"; do
            (( o <= 255 )) || return 1
        done
        case "$h" in
            0.0.0.0|255.255.255.255) return 1 ;;
        esac
        return 0
    fi

    # Bentuk yang menyerupai IPv4 tapi cacah oktetnya salah, misalnya
    # 10.0.0 atau 1.2.3.4.5. Tanpa pemeriksaan ini bentuk tersebut lolos
    # sebagai hostname karena hanya berisi angka dan titik.
    if [[ "$h" =~ ^[0-9.]+$ ]]; then
        return 1
    fi

    if [[ "$h" == *:* ]] && [[ "$h" =~ ^[0-9A-Fa-f:]+$ ]]; then
        return 0
    fi

    if [[ "$h" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$ ]]; then
        [ "${#h}" -le 253 ] || return 1
        return 0
    fi

    return 1
}

validate_agent_name() {
    local n="$1"
    [[ "$n" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$ ]] || return 1
    return 0
}

# group dipisah koma. Membuang koma akan menggabungkan tiga group menjadi
# satu nama yang tidak ada di manager, dan pendaftaran gagal tanpa
# penjelasan.
clean_groups() {
    local raw="$1" g
    local -a out=() parts=()
    local IFS=','
    read -r -a parts <<< "$raw"
    for g in "${parts[@]}"; do
        g="${g#"${g%%[![:space:]]*}"}"   # buang spasi di depan
        g="${g%"${g##*[![:space:]]}"}"   # buang spasi di belakang
        [ -n "$g" ] || continue
        [[ "$g" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$ ]] || {
            echo "INVALID:$g"
            return 1
        }
        out+=("$g")
    done
    [ "${#out[@]}" -gt 0 ] || return 1
    # IFS disetel di subkulit agar penggabungan memakai koma tanpa
    # mengubah IFS pemanggil.
    printf '%s' "$(IFS=,; echo "${out[*]}")"
    return 0
}

ask() {
    # Membaca masukan dari terminal, bukan dari stdin skrip. Penting untuk
    # pemakaian lewat pipa, misalnya curl ... | bash, karena di sana stdin
    # berisi badan skrip itu sendiri.
    local prompt="$1" varname="$2" answer=""
    if [ ! -t 0 ] && [ ! -r /dev/tty ]; then
        die "Tidak ada terminal untuk bertanya. Pakai variabel lingkungan: WAZUH_MANAGER dan WAZUH_GROUP."
    fi
    if [ -r /dev/tty ]; then
        read -r -p "$prompt" answer < /dev/tty
    else
        read -r -p "$prompt" answer
    fi
    printf -v "$varname" '%s' "$answer" 2>/dev/null || eval "$varname=\$answer"
}

# ---------- deteksi sistem ----------
ARCH_SUFFIX=""
MACOS_VER=""
MACOS_MAJOR=""

detect_macos() {
    [ "$(uname -s)" = "Darwin" ] || die "Skrip ini hanya untuk macOS. Sistem terdeteksi: $(uname -s)"

    MACOS_VER="$(sw_vers -productVersion 2>/dev/null || echo '')"
    [ -n "$MACOS_VER" ] || die "Tidak bisa membaca versi macOS lewat sw_vers."
    MACOS_MAJOR="${MACOS_VER%%.*}"

    # Nama paket berbeda menurut arsitektur prosesor. Memasang paket
    # arm64 di mesin Intel, atau sebaliknya, ditolak installer dengan
    # pesan yang tidak menjelaskan sebabnya.
    #
    # uname -m pada Mac Apple Silicon melaporkan x86_64 bila skrip
    # berjalan di bawah Rosetta, jadi arsitektur asli dibaca dari
    # sysctl, bukan dari uname.
    local cpu_brand native
    cpu_brand="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo '')"
    native="$(uname -m)"
    if sysctl -n sysctl.proc_translated >/dev/null 2>&1; then
        # Kunci ini hanya ada bila proses berjalan di bawah Rosetta.
        if [ "$(sysctl -n sysctl.proc_translated 2>/dev/null)" = "1" ]; then
            native="arm64"
        fi
    fi

    case "$native" in
        arm64)  ARCH_SUFFIX="arm64" ;;
        x86_64) ARCH_SUFFIX="intel64" ;;
        *)      die "Arsitektur '$native' tidak didukung. Yang didukung: arm64 dan x86_64." ;;
    esac

    ok "macOS $MACOS_VER, arsitektur $native (paket $ARCH_SUFFIX)"
    [ -n "$cpu_brand" ] && dim "Prosesor: $cpu_brand"

    # Batas versi menurut dokumentasi Wazuh.
    if [ "$ARCH_SUFFIX" = "arm64" ] && [ "$MACOS_MAJOR" -lt 11 ]; then
        die "Paket arm64 memerlukan macOS Big Sur 11 ke atas. Versi mesin ini: $MACOS_VER"
    fi
    if [ "$ARCH_SUFFIX" = "intel64" ] && [ "$MACOS_MAJOR" -lt 10 ]; then
        die "Paket Intel memerlukan macOS Sierra 10.12 ke atas. Versi mesin ini: $MACOS_VER"
    fi
}

# =============================================================================
#  Langkah 1: data pemasangan
# =============================================================================

echo "=============================================================="
echo "   Pemasangan Wazuh Agent untuk macOS"
echo "   Wazuh $WAZUH_VERSION, cakupan pemantauan penuh"
echo "=============================================================="

detect_macos

# Mode tanpa interaksi aktif bila data wajib sudah ada di variabel
# lingkungan, atau bila ASSUME_YES diisi.
NONINTERACTIVE=0
if [ "$ASSUME_YES" = "1" ] || { [ -n "${WAZUH_MANAGER:-}" ] && [ -n "${WAZUH_GROUP:-}" ]; }; then
    NONINTERACTIVE=1
fi

step "Mengumpulkan data pemasangan"

# --- alamat manager
if [ -z "${WAZUH_MANAGER:-}" ]; then
    [ "$NONINTERACTIVE" = "1" ] && die "WAZUH_MANAGER belum diisi dalam mode tanpa interaksi."
    echo
    dim "Untuk Integrasi Agent dengan Wazuh Manager atau Worker. Boleh IP maupun nama domain."
    dim "Contoh IP      : 192.0.2.10"
    dim "Contoh domain  : wazuh.corp.local"
    dim "Contoh domain  : soc-wazuh.perusahaan.co.id"
    dim "Jangan memakai awalan jaringan seperti 192.0.2.0/24,"
    dim "dan jangan menambahkan port seperti 192.0.2.10:1514."
    tries=0
    while true; do
        tries=$((tries + 1))
        [ "$tries" -gt 5 ] && die "Terlalu banyak masukan tidak sah untuk alamat manager."
        ask "  IP atau domain Wazuh Manager: " WAZUH_MANAGER
        validate_host "$WAZUH_MANAGER" && break
        cwrite "$R" " " "'$WAZUH_MANAGER' bukan IP atau nama domain yang sah."
        case "$WAZUH_MANAGER" in
            */*) cwrite "$R" " " "Tanda garis miring tidak dipakai. Isi alamat saja, misalnya 192.0.2.10" ;;
            *:*) cwrite "$R" " " "port tidak perlu ditulis. Isi alamat saja, misalnya 192.0.2.10" ;;
        esac
    done
else
    validate_host "$WAZUH_MANAGER" \
      || die "WAZUH_MANAGER='$WAZUH_MANAGER' bukan IP atau nama domain yang sah. Contoh benar: 192.0.2.10 atau wazuh.corp.local"
fi

# --- group
if [ -z "${WAZUH_GROUP:-}" ]; then
    [ "$NONINTERACTIVE" = "1" ] && die "WAZUH_GROUP belum diisi dalam mode tanpa interaksi."
    echo
    dim "group menentukan berkas agent.conf mana yang diterima agent ini."
    dim "group harus SUDAH ADA di manager, skrip ini tidak membuatnya."
    dim "Contoh satu group   : default"
    dim "Contoh satu group   : mac-endpoint"
    dim "Contoh banyak group : mac-endpoint,laptop,produksi"
    tries=0
    while true; do
        tries=$((tries + 1))
        [ "$tries" -gt 5 ] && die "Terlalu banyak masukan tidak sah untuk group."
        ask "  group agent: " WAZUH_GROUP
        if cleaned=$(clean_groups "$WAZUH_GROUP" 2>/dev/null); then
            WAZUH_GROUP="$cleaned"
            break
        fi
        cwrite "$R" " " "group tidak sah. Hanya huruf, angka, titik, strip, garis bawah."
        cwrite "$R" " " "Pisahkan dengan koma bila lebih dari satu, misalnya: mac-endpoint,laptop"
    done
else
    if cleaned=$(clean_groups "$WAZUH_GROUP" 2>/dev/null); then
        WAZUH_GROUP="$cleaned"
    else
        die "WAZUH_GROUP='$WAZUH_GROUP' tidak sah. Hanya huruf, angka, titik, strip, garis bawah, dipisah koma. Contoh benar: mac-endpoint,laptop"
    fi
fi

# --- nama agent
if [ -z "${AGENT_NAME:-}" ]; then
    # ComputerName adalah nama yang dilihat pengguna di Pengaturan, dan
    # bisa memuat spasi. scutil --get LocalHostName memberi bentuk yang
    # sudah aman untuk jaringan, jadi itu yang dipakai lebih dulu.
    DEFAULT_NAME="$(scutil --get LocalHostName 2>/dev/null || true)"
    [ -n "$DEFAULT_NAME" ] || DEFAULT_NAME="$(hostname -s 2>/dev/null || echo 'wazuh-mac')"
    if [ "$NONINTERACTIVE" = "1" ]; then
        AGENT_NAME="$DEFAULT_NAME"
    else
        echo
        dim "Nama yang muncul di dashboard manager. Harus unik, tidak boleh"
        dim "sama dengan agent lain yang sudah terdaftar."
        dim "Contoh : mac-finance-01"
        dim "Contoh : mb-direksi-02.corp.local"
        dim "Tekan Enter saja untuk memakai nama mesin ini: $DEFAULT_NAME"
        tries=0
        while true; do
            tries=$((tries + 1))
            [ "$tries" -gt 5 ] && die "Terlalu banyak masukan tidak sah untuk nama agent."
            ask "  Nama agent [$DEFAULT_NAME]: " AGENT_NAME
            AGENT_NAME="${AGENT_NAME:-$DEFAULT_NAME}"
            validate_agent_name "$AGENT_NAME" && break
            cwrite "$R" " " "'$AGENT_NAME' tidak sah. Hanya huruf, angka, titik, strip,"
            cwrite "$R" " " "garis bawah. Tanpa spasi. Panjang 2 sampai 128 karakter."
            AGENT_NAME=""
        done
    fi
fi
validate_agent_name "$AGENT_NAME" \
  || die "Nama agent '$AGENT_NAME' tidak sah. Hanya huruf, angka, titik, strip, garis bawah, 2 sampai 128 karakter. Contoh benar: mac-finance-01"

echo
echo "  Ringkasan:"
echo "    manager       : $WAZUH_MANAGER"
echo "    Nama agent    : $AGENT_NAME"
echo "    group         : $WAZUH_GROUP"
echo "    Versi paket   : $WAZUH_VERSION"
echo "    Arsitektur    : $ARCH_SUFFIX"
echo "    macOS         : $MACOS_VER"
# Baris di bawah hanya muncul bila memang menyimpang dari bawaan, supaya
# ringkasan tidak dipenuhi keterangan yang tidak memberi tahu apa apa.
if [ "$SKIP_FIM" = "1" ];    then echo "    FIM tambahan  : DILEWATI"; fi
if [ "$SKIP_VERIFY" = "1" ]; then echo "    Verifikasi    : DILEWATI"; fi
echo "    Berkas log    : $LOGFILE"
echo

if [ "$NONINTERACTIVE" != "1" ]; then
    ask "  Lanjutkan pemasangan? (Y/n): " CONFIRM
    case "${CONFIRM:-Y}" in
        [Yy]*|"") : ;;
        *) echo "  Dibatalkan."; exit 0 ;;
    esac
fi

# =============================================================================
#  Langkah 2: pemeriksaan kesiapan
# =============================================================================
step "Memeriksa kesiapan mesin"

# port wajib terbuka. Gagal di sini jauh lebih baik daripada pemasangan
# yang dilaporkan berhasil lalu agent diam diam tidak pernah terdaftar.
#
# macOS tidak punya /dev/tcp seperti bash di Linux, jadi dipakai nc yang
# selalu tersedia di sistem.
for p in "$WAZUH_COMM_PORT" "$WAZUH_REG_PORT"; do
    label="pengiriman event"
    [ "$p" = "$WAZUH_REG_PORT" ] && label="pendaftaran"
    if nc -z -G 5 -w 5 "$WAZUH_MANAGER" "$p" >/dev/null 2>&1; then
        ok "port $p ($label) terbuka ke $WAZUH_MANAGER"
    else
        die "port $p ($label) TERTUTUP ke $WAZUH_MANAGER. Periksa firewall dan rute lebih dulu."
    fi
done

# Jam yang meleset membuat korelasi di manager salah dan alert sulit
# diurutkan. Bukan penghalang, tapi perlu diketahui.
if systemsetup -getusingnetworktime 2>/dev/null | grep -qi 'on$'; then
    ok "Jam tersinkron dengan server waktu jaringan"
else
    warn "Jam mungkin TIDAK tersinkron. Penanda waktu alert bisa meleset."
    dim "Perbaiki: sudo systemsetup -setusingnetworktime on"
fi

# Ruang disk. agent menulis log dan basis data FIM.
AVAIL_MB="$(df -m / 2>/dev/null | awk 'NR==2{print $4}')"
if [ -n "$AVAIL_MB" ] && [ "$AVAIL_MB" -lt 2048 ]; then
    warn "Ruang bebas hanya ${AVAIL_MB} MB. Disarankan minimal 2 GB."
else
    ok "Ruang bebas: ${AVAIL_MB:-?} MB"
fi

# --- Pemasangan yang sudah ada.
#
# Skrip postinstall paket macOS hanya mendaftarkan agent pada pemasangan
# BARU. Isinya:
#
#   if [ -z "${upgrade}" ]; then
#       .../register_configure_agent.sh ${DIR}
#   fi
#
# Sementara preinstall menandai pemasangan sebagai upgrade begitu
# direktori /Library/Ossec ditemukan:
#
#   if [ -d "${DIR}" ]; then
#       touch "${DIR}/WAZUH_PKG_UPGRADE"
#       upgrade="true"
#   fi
#
# Jadi memasang ulang di atas pemasangan yang sudah ada TIDAK akan
# menerapkan alamat manager, group, atau nama agent yang baru. Lebih
# jauh lagi, preinstall mencadangkan ossec.conf, client.keys, dan
# local_internal_options.conf lalu postinstall memulihkannya, sehingga
# konfigurasi lama kembali apa adanya.
#
# Karena itu skrip berhenti di sini dengan instruksi, bukan melanjutkan
# dan melaporkan hasil yang tidak benar.
PKG_PRESENT=0
if [ -d "$OSSEC_DIR" ]; then
    PKG_PRESENT=1
elif pkgutil --pkgs 2>/dev/null | grep -qx "$PKG_ID"; then
    PKG_PRESENT=1
fi

if [ "$PKG_PRESENT" -eq 1 ]; then
    OLD_ID=""
    OLD_ID_NUM=""
    if [ -s "$CLIENT_KEYS" ]; then
        OLD_ID="$(awk 'NR==1{print $1" "$2}' "$CLIENT_KEYS" 2>/dev/null || true)"
        OLD_ID_NUM="$(awk 'NR==1{print $1}' "$CLIENT_KEYS" 2>/dev/null || true)"
    fi

    IDENT_LINE=""
    [ -n "$OLD_ID" ] && IDENT_LINE="
        Terdaftar saat ini sebagai: $OLD_ID"

    MANAGER_NOTE=""
    [ -n "$OLD_ID" ] && MANAGER_NOTE="

        Setelah dicabut, hapus juga entri lama di manager. Jalankan ini
        DI SERVER MANAGER, bukan di mesin ini:
          /var/ossec/bin/manage_agents -r ${OLD_ID_NUM:-<id>}"

    echo
    die "$(cat <<MSG
wazuh-agent sudah terpasang di mesin ini.$IDENT_LINE

        Memasang ulang di atasnya TIDAK akan mendaftarkan agent kembali.
        Paket macOS memperlakukan pemasangan di atas $OSSEC_DIR sebagai
        peningkatan versi, lalu memulihkan konfigurasi lama dari cadangan,
        sehingga alamat manager, group, dan nama agent yang baru tidak
        akan diterapkan.

        Ada dua pilihan.

        1. Hanya mengubah pendaftaran, tanpa memasang ulang paket:
             $OSSEC_DIR/bin/agent-auth -m $WAZUH_MANAGER -p $WAZUH_REG_PORT -G '$WAZUH_GROUP' -A '$AGENT_NAME'
             $OSSEC_DIR/bin/wazuh-control restart

        2. Memasang dari awal. Cabut lebih dulu:
             $OSSEC_DIR/bin/wazuh-control stop
             launchctl bootout system $PLIST
             rm -rf $OSSEC_DIR
             rm -rf /Library/StartupItems/WAZUH
             rm -f $PLIST
             pkgutil --forget $PKG_ID

           lalu jalankan skrip ini lagi.$MANAGER_NOTE
MSG
)"
fi
ok "Belum ada wazuh-agent terpasang"

# =============================================================================
#  Langkah 3: mengunduh paket
# =============================================================================
step "Menyiapkan paket wazuh-agent $WAZUH_VERSION"

PKG_URL="https://packages.wazuh.com/4.x/macos/wazuh-agent-${WAZUH_VERSION}.${ARCH_SUFFIX}.pkg"
WORK_DIR="$(mktemp -d /tmp/wazuh-install.XXXXXX)"
PKG_FILE="$WORK_DIR/wazuh-agent.pkg"

cleanup() {
    # Berkas variabel lingkungan memuat alamat manager dan nama group.
    # Paket menghapusnya sendiri setelah dibaca, tetapi bila pemasangan
    # gagal di tengah berkas itu bisa tertinggal.
    rm -f "$ENV_FILE" 2>/dev/null || true
    rm -rf "$WORK_DIR" 2>/dev/null || true
}
trap cleanup EXIT

if [ -n "$PKG_PATH" ]; then
    [ -f "$PKG_PATH" ] || die "Berkas paket tidak ditemukan: $PKG_PATH"
    cp "$PKG_PATH" "$PKG_FILE" || die "Gagal menyalin $PKG_PATH"
    ok "Paket diambil dari berkas lokal: $PKG_PATH"
else
    dim "Mengunduh $PKG_URL"
    if ! curl -fsSL --retry 3 --retry-delay 2 -o "$PKG_FILE" "$PKG_URL"; then
        echo
        die "$(cat <<MSG
Gagal mengunduh paket.

        Periksa:
          - versi $WAZUH_VERSION ada di repositori Wazuh?
          - mesin ini bisa menjangkau packages.wazuh.com?

        Alamat yang dicoba:
          $PKG_URL

        Bila mesin tanpa akses internet, unduh paket di tempat lain lalu:
          sudo PKG_PATH=/jalur/ke/wazuh-agent.pkg bash $0
MSG
)"
    fi
    PKG_SIZE="$(stat -f%z "$PKG_FILE" 2>/dev/null || echo 0)"
    # Paket macOS berukuran sekitar 6 MB. Berkas jauh lebih kecil berarti
    # yang terunduh halaman galat, bukan paket.
    if [ "$PKG_SIZE" -lt 1000000 ]; then
        die "Berkas yang terunduh hanya $PKG_SIZE byte, terlalu kecil untuk paket Wazuh."
    fi
    ok "Paket terunduh ($(echo "$PKG_SIZE" | awk '{printf "%.1f MB", $1/1048576}'))"
fi

# --- Tanda tangan paket.
#
# Paket Wazuh ditandatangani, dan pemasangan paket tidak bertanda tangan
# dengan hak root adalah risiko yang tidak perlu diambil. Pemeriksaan ini
# memakai pkgutil, perkakas bawaan macOS.
SIG_OUT="$(pkgutil --check-signature "$PKG_FILE" 2>&1 || true)"
if printf '%s' "$SIG_OUT" | grep -q 'Status: signed'; then
    SIGNER="$(printf '%s' "$SIG_OUT" | awk '/^ *1\. / {sub(/^ *1\. /,""); print; exit}')"
    ok "Tanda tangan paket sah"
    [ -n "$SIGNER" ] && dim "Penanda tangan: $SIGNER"
else
    warn "Tanda tangan paket TIDAK dapat diperiksa."
    printf '%s\n' "$SIG_OUT" | head -4 | while IFS= read -r l; do dim "$l"; done
    if [ "$NONINTERACTIVE" != "1" ]; then
        ask "  Tetap pasang paket tanpa tanda tangan sah? (y/N): " GO_SIG
        case "${GO_SIG:-N}" in
            [Yy]*) : ;;
            *) echo "  Dibatalkan."; exit 0 ;;
        esac
    fi
fi

# =============================================================================
#  Langkah 4: pemasangan
# =============================================================================
step "Memasang wazuh-agent"

# Variabel pendaftaran diteruskan lewat berkas, bukan lingkungan proses.
# Ini bukan pilihan gaya: installer paket macOS berjalan sebagai proses
# terpisah yang tidak mewarisi lingkungan, dan skrip pascapasang Wazuh
# membacanya dari jalur tetap /tmp/wazuh_envs.
#
# Nilai dikutip tunggal supaya spasi dan karakter khusus tidak diuraikan
# ulang saat berkas ini di-source oleh skrip paket.
{
    printf "WAZUH_MANAGER='%s'\n"      "$WAZUH_MANAGER"
    printf "WAZUH_AGENT_GROUP='%s'\n"  "$WAZUH_GROUP"
    printf "WAZUH_AGENT_NAME='%s'\n"   "$AGENT_NAME"
    # port hanya ditulis bila menyimpang dari bawaan, supaya konfigurasi
    # yang dihasilkan tidak memuat nilai yang sama dengan bawaan.
    if [ "$WAZUH_COMM_PORT" != "1514" ]; then
        printf "WAZUH_MANAGER_PORT='%s'\n" "$WAZUH_COMM_PORT"
    fi
    if [ "$WAZUH_REG_PORT" != "1515" ]; then
        printf "WAZUH_REGISTRATION_PORT='%s'\n" "$WAZUH_REG_PORT"
    fi
} > "$ENV_FILE"
chmod 0600 "$ENV_FILE"
dim "Variabel pendaftaran ditulis ke $ENV_FILE"

INSTALL_OUT="$(mktemp)"
INSTALL_RC=0
installer -pkg "$PKG_FILE" -target / > "$INSTALL_OUT" 2>&1 || INSTALL_RC=$?

if [ "$INSTALL_RC" -ne 0 ]; then
    echo
    cwrite "$R" "      " "Keluaran installer:"
    tail -20 "$INSTALL_OUT" | while IFS= read -r l; do echo "         $l"; done
    rm -f "$INSTALL_OUT"
    die "Pemasangan paket gagal dengan kode $INSTALL_RC. Catatan lengkap di $LOGFILE"
fi
rm -f "$INSTALL_OUT"

[ -d "$OSSEC_DIR" ] || die "Installer selesai tetapi $OSSEC_DIR tidak ada."
[ -f "$OSSEC_CONF" ] || die "Installer selesai tetapi $OSSEC_CONF tidak terbentuk."

ok "Paket wazuh-agent $WAZUH_VERSION terpasang di $OSSEC_DIR"

# Berkas variabel dihapus segera setelah dipakai. Paket seharusnya sudah
# menghapusnya sendiri, tetapi bila pendaftaran dilewati berkas itu
# tertinggal berisi alamat manager dan nama group.
rm -f "$ENV_FILE" 2>/dev/null || true

# =============================================================================
#  Langkah 5: local_internal_options.conf
# =============================================================================
step "Mengatur local_internal_options.conf"

# Hanya berkas lokal yang disentuh. Berkas internal_options.conf ditimpa
# setiap kali paket diperbarui, sehingga perubahan di sana akan hilang.
# Wazuh membaca internal_options.conf lebih dulu lalu local_internal_options.conf
# menimpanya, jadi nilai di berkas lokal yang berlaku.
touch "$LOCAL_OPT"
add_opt(){
  local key="$1" val="$2"
  if grep -qE "^[[:space:]]*${key//./\\.}=" "$LOCAL_OPT" 2>/dev/null; then
    # sed -i di macOS memerlukan argumen akhiran, berbeda dari GNU sed.
    # Akhiran kosong berarti tidak membuat berkas cadangan.
    sed -i '' "s|^[[:space:]]*${key//./\\.}=.*|${key}=${val}|" "$LOCAL_OPT"
  else
    echo "${key}=${val}" >> "$LOCAL_OPT"
  fi
}

# Kedua opsi di bawah menentukan apakah agent mau menjalankan perintah
# yang DIKIRIM manager lewat agent.conf. Bawaannya 0 di
# internal_options.conf, dan tanpa diubah, konfigurasi group yang memuat
# <command> atau <full_command> diterima agent tetapi perintahnya
# diabaikan diam diam, tanpa pesan galat yang menjelaskannya.
add_opt "logcollector.remote_commands"  "1"
add_opt "wazuh_command.remote_commands" "1"

chown root:wazuh "$LOCAL_OPT" 2>/dev/null || true
chmod 0640 "$LOCAL_OPT"
ok "local_internal_options.conf diperbarui, isi lama dipertahankan"
dim "logcollector.remote_commands=1 dan wazuh_command.remote_commands=1"

# =============================================================================
#  Langkah 6: blok konfigurasi ossec.conf
# =============================================================================
step "Menyisipkan blok konfigurasi ke ossec.conf"

cp -p "$OSSEC_CONF" "${OSSEC_CONF}.bak.$(date +%s)"
dim "Cadangan: ${OSSEC_CONF}.bak.*"

# Konfigurasi bawaan di luar marker dibaca lebih dulu. Paket Wazuh untuk
# macOS sudah menyisipkan sumber log sendiri:
#
#   localfile-extra.template      Unified Logging System, dengan query
#                                 untuk sudo, sshd, tccd, screensharingd,
#                                 securityd, dan sessionlogoutd
#   localfile-commands.template   daftar port menyimak lewat netstat
#   syscheck.agent.template       FIM untuk /etc, /usr/bin, /usr/sbin,
#                                 /bin, /sbin
#
# Menambahkan entri yang sama membuat berkas dibaca dua kali, dan setiap
# baris log menghasilkan dua event di manager.
#
# Hanya bagian di LUAR marker yang dibaca, supaya menjalankan skrip
# berulang kali tidak menganggap bloknya sendiri sebagai bawaan.
BASE_CONF="$(awk -v b="$MARK_BEGIN" -v e="$MARK_END" '
    index($0, b) { skip = 1 }
    !skip        { print }
    index($0, e) { skip = 0 }
' "$OSSEC_CONF" 2>/dev/null || true)"

LOGFILES_BLOCK=""
SKIPPED_DUP=0
add_logfile() {
    local path="$1" fmt="${2:-syslog}"
    [ -e "$path" ] || return 0

    # Pencocokan memakai elemen <location> yang lengkap, bukan substring
    # jalurnya, supaya satu jalur tidak dianggap cocok dengan jalur lain
    # yang kebetulan memuatnya.
    if grep -qF "<location>$path</location>" <<< "$BASE_CONF"; then
        dim "sudah ada di konfigurasi bawaan, dilewati: $path"
        SKIPPED_DUP=$((SKIPPED_DUP + 1))
        return 0
    fi

    LOGFILES_BLOCK+="  <localfile>
    <log_format>$fmt</log_format>
    <location>$path</location>
  </localfile>
"
    dim "sumber log ditambahkan: $path"
}

# Berkas log klasik yang masih dipakai macOS. Sebagian besar aktivitas
# sistem kini masuk Unified Logging System, bukan berkas teks, jadi
# daftar ini jauh lebih pendek daripada versi Linux.
add_logfile /var/log/install.log
add_logfile /var/log/system.log

# --- Unified Logging System.
#
# Pengganti auth.log di macOS modern. Paket bawaan sudah memuat satu blok
# dengan query untuk sudo, sshd, dan tccd. Blok tambahan di bawah
# melengkapi cakupannya tanpa menduplikasi yang sudah ada.
ULS_BLOCK=""
if grep -qF "<location>macos</location>" <<< "$BASE_CONF"; then
    ok "Sumber Unified Logging System sudah ada di konfigurasi bawaan"
    dim "Mencakup sudo, sshd, tccd, screensharingd, securityd"
else
    # Tidak seharusnya terjadi pada paket resmi, tetapi bila template
    # bawaan berubah, sumber terpenting di macOS tidak boleh hilang.
    warn "Sumber Unified Logging System tidak ada di konfigurasi bawaan, ditambahkan."
    ULS_BLOCK='  <localfile>
    <location>macos</location>
    <log_format>macos</log_format>
    <query type="trace,log,activity" level="info">(process == "sudo") or (process == "sshd") or (process == "tccd" and message contains "Update Access Record") or (process == "screensharingd" and message contains "Authentication") or (process == "securityd" and eventMessage contains "Session")</query>
  </localfile>
'
fi

# Blok FIM. Dipisah agar bisa dilewati lewat SKIP_FIM.
#
# Blok bawaan memantau /etc, /usr/bin, /usr/sbin, /bin, /sbin tanpa
# realtime. Blok di bawah menambahkan jalur yang khas macOS dan mengatur
# realtime untuk yang paling penting. Wazuh MENGGABUNGKAN beberapa blok
# <syscheck>, jadi dua blok di sini wajar dan memang dimanfaatkan.
FIM_BLOCK=""
if [ "$SKIP_FIM" != "1" ]; then
FIM_BLOCK=$(cat <<'FIMEOF'
  <!-- Pemantauan keutuhan berkas, tambahan khas macOS.
       Wazuh menggabungkan blok syscheck, jadi daftar ini melengkapi
       blok bawaan yang sudah memantau /etc, /usr/bin, dan /usr/sbin. -->
  <syscheck>
    <!-- Persistence lewat agen peluncur.
         Jalur ini setara dengan systemd dan cron di Linux, dan merupakan
         cara paling umum perangkat lunak berbahaya bertahan di macOS. -->
    <directories realtime="yes" check_all="yes">/Library/LaunchAgents</directories>
    <directories realtime="yes" check_all="yes">/Library/LaunchDaemons</directories>
    <directories realtime="yes" check_all="yes">/Library/StartupItems</directories>
    <directories realtime="yes" check_all="yes">/System/Library/LaunchAgents</directories>
    <directories realtime="yes" check_all="yes">/System/Library/LaunchDaemons</directories>

    <!-- Agen peluncur milik pengguna. Tidak memerlukan hak admin untuk
         dibuat, sehingga sering dipakai pada tahap awal serangan. -->
    <directories realtime="yes" check_all="yes">/Users/*/Library/LaunchAgents</directories>

    <!-- Sisipan kernel. Jalur rootkit tingkat kernel di macOS. -->
    <directories realtime="yes" check_all="yes">/Library/Extensions</directories>
    <directories check_all="yes">/System/Library/Extensions</directories>

    <!-- Kredensial dan akun -->
    <directories realtime="yes" check_all="yes" report_changes="yes">/etc/sudoers,/etc/sudoers.d</directories>
    <directories realtime="yes" check_all="yes" report_changes="yes">/etc/ssh</directories>
    <directories realtime="yes" check_all="yes">/private/var/db/dslocal/nodes/Default/users</directories>

    <!-- Berkas konfigurasi shell tingkat sistem -->
    <directories realtime="yes" check_all="yes" report_changes="yes">/etc/profile,/etc/zprofile,/etc/zshrc,/etc/bashrc</directories>

    <!-- Jaringan -->
    <directories realtime="yes" check_all="yes" report_changes="yes">/etc/hosts,/etc/resolv.conf</directories>

    <!-- Daftar aplikasi. Perubahan di sini berarti aplikasi dipasang
         atau diganti, termasuk penggantian aplikasi sah dengan versi
         yang disusupi. -->
    <directories check_all="yes">/Applications</directories>

    <!-- Lokasi yang sering dipakai untuk menaruh muatan -->
    <directories realtime="yes" check_all="yes">/tmp,/private/tmp</directories>
    <directories realtime="yes" check_all="yes">/var/tmp,/private/var/tmp</directories>

    <!-- Isi berkas di bawah TIDAK boleh dikirim ke manager.
         Dengan report_changes="yes", Wazuh melampirkan selisih baris
         sebelum dan sesudah ke dalam alert, dan selisih itu tersimpan di
         manager serta tampil di dashboard. Pada berkas ini artinya kunci
         privat host SSH ikut terkirim, terbaca siapa pun yang punya
         akses dashboard.

         nodiff tetap memantau dan tetap memberi peringatan saat berkas
         berubah. Yang dibuang hanya lampiran isinya. -->
    <nodiff type="sregex">^/etc/ssh/ssh_host_.*_key$</nodiff>
    <nodiff type="sregex">^/private/etc/ssh/ssh_host_.*_key$</nodiff>
    <nodiff type="sregex">^/etc/ssl/private</nodiff>

    <!-- Berkas yang berubah terus menerus. Tanpa pengecualian ini,
         peringatan FIM membanjiri dashboard dan menutupi yang penting. -->
    <ignore type="sregex">\.log$|\.swp$|\.tmp$|\.lock$|\.pid$|\.sock$</ignore>
    <ignore type="sregex">^/Users/[^/]+/Library/Caches</ignore>
    <ignore>/private/var/folders</ignore>
    <ignore>/Library/Ossec</ignore>
    <ignore>/.fseventsd</ignore>
    <ignore>/.Spotlight-V100</ignore>
  </syscheck>
FIMEOF
)
fi

BLOCK=$(cat <<EOF
$MARK_BEGIN
  <!-- Modul berikut TIDAK ditulis ulang di sini, karena konfigurasi
       bawaan agent sudah memuat semuanya dalam keadaan aktif:

         <rootcheck>          pemeriksaan rootkit
         <sca>                penilaian konfigurasi keamanan
         <active-response>    tanggapan aktif dengan verifikasi CA
         <wodle name="syscollector">   inventaris sistem
         <client_buffer>      penyangga kiriman
         <localfile> macos    Unified Logging System

       Wazuh memakai blok yang pertama dibaca dan mengabaikan blok kedua
       dengan nama sama, jadi menambahkannya tidak mengubah apa pun dan
       hanya membuat setiap pesan modul muncul dua kali di ossec.log.

       Pengecualiannya <syscheck>, yang memang DIGABUNG Wazuh, sehingga
       blok tambahan di bawah melengkapi daftar direktori bawaan.

       Dua nilai bawaan yang perlu diubah, yaitu ukuran penyangga dan
       pemindaian seluruh port, diubah di tempat setelah blok ini
       disisipkan. -->

$LOGFILES_BLOCK$ULS_BLOCK
$FIM_BLOCK

  <!-- Perintah berkala untuk hal yang tidak tertangkap FIM maupun log.
       Memerlukan logcollector.remote_commands yang sudah diaktifkan di
       local_internal_options.conf. -->
  <localfile>
    <log_format>full_command</log_format>
    <command>dscl . -list /Users UniqueID | awk '\$2 == 0 {print \$1}'</command>
    <alias>uid-zero-accounts</alias>
    <frequency>3600</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>dscl . -read /Groups/admin GroupMembership 2>/dev/null</command>
    <alias>admin-group-members</alias>
    <frequency>3600</frequency>
  </localfile>

  <!-- Agen peluncur yang terpasang. Daftar ini melengkapi FIM: FIM
       memberi tahu berkasnya berubah, perintah ini memberi tahu apa saja
       yang sedang terdaftar. -->
  <localfile>
    <log_format>full_command</log_format>
    <command>launchctl list 2>/dev/null | awk 'NR>1 {print \$3}' | sort</command>
    <alias>launch-services</alias>
    <frequency>3600</frequency>
  </localfile>

  <!-- Sisipan kernel pihak ketiga. Jumlahnya sedikit pada mesin sehat,
       dan penambahan baru hampir selalu layak diperiksa. -->
  <localfile>
    <log_format>full_command</log_format>
    <command>kmutil showloaded --list-only 2>/dev/null || kextstat -l 2>/dev/null</command>
    <alias>kernel-extensions</alias>
    <frequency>3600</frequency>
  </localfile>

  <!-- Keadaan perlindungan bawaan macOS. Dimatikannya salah satu dari
       ini adalah tanda kuat, dan tidak terlihat dari log biasa. -->
  <localfile>
    <log_format>full_command</log_format>
    <command>echo "SIP: \$(csrutil status 2>/dev/null)"; echo "Gatekeeper: \$(spctl --status 2>/dev/null)"; echo "Firewall: \$(defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null)"; echo "FileVault: \$(fdesetup status 2>/dev/null)"</command>
    <alias>macos-security-posture</alias>
    <frequency>21600</frequency>
  </localfile>

  <!-- Berkas dengan bit setuid di luar jalur baku adalah pola eskalasi
       hak yang sering dipakai. Pencarian dibatasi pada direktori tempat
       berkas setuid yang sah berada, bukan seluruh sistem berkas. -->
  <localfile>
    <log_format>full_command</log_format>
    <command>find /usr /bin /sbin /opt /Applications -xdev -type f -perm -4000 2>/dev/null | sort</command>
    <alias>suid-files</alias>
    <frequency>86400</frequency>
  </localfile>
$MARK_END
EOF
)

# Penyisipan idempoten. Blok lama dibuang lebih dulu bila ada, lalu blok
# baru disisipkan sebelum penutup </ossec_config> yang terakhir.
#
# Python dipakai agar aman terhadap indentasi dan baris panjang. macOS
# membawa python3 sejak Monterey lewat Command Line Tools, tetapi pada
# sistem bersih bisa belum ada, jadi disediakan jalur cadangan dengan
# awk yang hanya memakai perkakas bawaan.
PY=""
for cand in python3 /usr/bin/python3; do
    if command -v "$cand" >/dev/null 2>&1; then PY="$cand"; break; fi
done

if [ -n "$PY" ]; then
    BLOCK="$BLOCK" "$PY" - "$OSSEC_CONF" "$MARK_BEGIN" "$MARK_END" <<'PYEOF'
import os, re, sys
path, mb, me = sys.argv[1], sys.argv[2], sys.argv[3]
block = os.environ["BLOCK"]
s = open(path, encoding="utf-8").read()
s = re.sub(re.escape(mb) + r".*?" + re.escape(me) + r"\n?", "", s, flags=re.S)
idx = s.rfind("</ossec_config>")
if idx == -1:
    sys.exit("</ossec_config> tidak ditemukan di " + path)
out = s[:idx] + block + "\n" + s[idx:]

# Pastikan hasil tetap XML yang sah sebelum ditulis. Berkas ossec.conf
# memuat beberapa blok <ossec_config> sejajar, jadi perlu dibungkus akar
# semu lebih dulu.
import xml.etree.ElementTree as ET
try:
    ET.fromstring("<root>" + re.sub(r"^\s*<\?xml[^>]*\?>", "", out) + "</root>")
except ET.ParseError as e:
    sys.exit("Hasil penyuntingan bukan XML yang sah: %s" % e)

open(path, "w", encoding="utf-8").write(out)
PYEOF
    ok "Blok konfigurasi tersisip dan lolos pemeriksaan XML"
else
    # Jalur cadangan tanpa python3. Blok lama dibuang dengan awk, lalu
    # blok baru disisipkan sebelum penutup terakhir.
    warn "python3 tidak ada, memakai jalur cadangan tanpa pemeriksaan XML."
    dim "Pasang Command Line Tools untuk pemeriksaan penuh: xcode-select --install"

    TMP_CONF="$(mktemp)"
    awk -v b="$MARK_BEGIN" -v e="$MARK_END" '
        index($0, b) { skip = 1 }
        !skip        { print }
        index($0, e) { skip = 0 }
    ' "$OSSEC_CONF" > "$TMP_CONF"

    # Nomor baris penutup </ossec_config> yang terakhir.
    LAST_CLOSE="$(grep -n '</ossec_config>' "$TMP_CONF" | tail -1 | cut -d: -f1)"
    [ -n "$LAST_CLOSE" ] || die "</ossec_config> tidak ditemukan di $OSSEC_CONF"

    {
        head -n "$((LAST_CLOSE - 1))" "$TMP_CONF"
        printf '%s\n' "$BLOCK"
        tail -n "+$LAST_CLOSE" "$TMP_CONF"
    } > "${TMP_CONF}.new"
    mv "${TMP_CONF}.new" "$OSSEC_CONF"
    rm -f "$TMP_CONF"
    ok "Blok konfigurasi tersisip"
fi

chown root:wazuh "$OSSEC_CONF" 2>/dev/null || true
chmod 0640 "$OSSEC_CONF"

if [ "$SKIPPED_DUP" -gt 0 ]; then
    dim "$SKIPPED_DUP sumber log dilewati karena sudah ada di konfigurasi bawaan"
fi

# --- Nilai bawaan yang diubah di tempat.
#
# Blok di bawah sudah ada di konfigurasi bawaan, dan Wazuh mengabaikan
# blok kedua dengan nama sama. Jadi nilainya diubah pada blok yang ada,
# bukan ditambah sebagai blok baru.
if [ -n "$PY" ]; then
    TUNE_OUT="$("$PY" - "$OSSEC_CONF" <<'PYEOF' 2>&1 || true
import re, sys
path = sys.argv[1]
s = open(path, encoding="utf-8").read()
orig = s
changed = []

def tune_block(text, open_re, inner_pairs):
    """Ubah nilai di dalam blok pertama yang cocok open_re."""
    m = re.search(open_re, text)
    if not m:
        return text
    start = m.start()
    tag = re.match(r"\s*<([A-Za-z_][\w-]*)", m.group(0)).group(1)
    close = "</%s>" % tag
    end = text.find(close, start)
    if end == -1:
        return text
    body = text[start:end]
    newbody = body
    for pat, repl, note in inner_pairs:
        newbody, n = re.subn(pat, repl, newbody, count=1)
        if n:
            changed.append(note)
    return text[:start] + newbody + text[end:]

# Penyangga kiriman. Bawaan 5000 antrean dengan 500 event per detik
# terlalu kecil pada mesin yang ramai: antrean penuh berarti event
# dibuang, dan satu satunya tandanya adalah sebaris di ossec.log.
s = tune_block(
    s, r"<client_buffer>",
    [(r"<queue_size>\s*\d+\s*</queue_size>",
      "<queue_size>100000</queue_size>", "queue_size 100000"),
     (r"<events_per_second>\s*\d+\s*</events_per_second>",
      "<events_per_second>1000</events_per_second>", "events_per_second 1000")])

# Pemindaian port. Bawaan all="no" hanya melaporkan port yang menyimak,
# sedangkan all="yes" ikut melaporkan sambungan keluar yang sedang aktif.
s = tune_block(
    s, r"<wodle\s+name=\"syscollector\">",
    [(r"<ports\s+all=\"no\">", "<ports all=\"yes\">", "ports all=yes")])

if s == orig:
    print("TIDAK_ADA_PERUBAHAN")
    sys.exit(0)

import xml.etree.ElementTree as ET
try:
    ET.fromstring("<root>" + re.sub(r"^\s*<\?xml[^>]*\?>", "", s) + "</root>")
except ET.ParseError as e:
    sys.exit("XML_TIDAK_SAH: %s" % e)

open(path, "w", encoding="utf-8").write(s)
print("DIUBAH: " + ", ".join(changed))
PYEOF
)"

    case "$TUNE_OUT" in
        DIUBAH:*)            ok "Nilai bawaan disesuaikan (${TUNE_OUT#DIUBAH: })" ;;
        TIDAK_ADA_PERUBAHAN) dim "Nilai bawaan sudah sesuai, tidak ada yang diubah" ;;
        XML_TIDAK_SAH*)
            warn "Penyesuaian nilai bawaan menghasilkan XML tidak sah, dilewati."
            dim "$TUNE_OUT" ;;
        *)
            warn "Penyesuaian nilai bawaan tidak dapat dipastikan."
            [ -n "$TUNE_OUT" ] && dim "$TUNE_OUT" ;;
    esac
else
    dim "Penyesuaian nilai bawaan dilewati karena python3 tidak ada"
fi

# =============================================================================
#  Langkah 7: menjalankan agent
# =============================================================================
step "Menjalankan wazuh-agent"

# Posisi akhir log dicatat SEBELUM agent dijalankan.
#
# Tanpa penanda ini, verifikasi sambungan membaca seluruh ossec.log. Pada
# mesin yang pernah dipasangi agent, baris 'Connected to the server' dari
# sesi lama membuat pemeriksaan lolos walaupun agent sekarang tidak
# pernah tersambung.
LOG_START=0
if [ -f "$OSSEC_LOG" ]; then
    LOG_START="$(wc -l < "$OSSEC_LOG" 2>/dev/null | tr -d ' ' || echo 0)"
fi

# launchctl bootstrap adalah bentuk yang berlaku sejak macOS 10.11.
# Bentuk lama 'launchctl load' masih jalan tetapi sudah usang dan pada
# sebagian versi gagal diam diam.
if [ -f "$PLIST" ]; then
    launchctl bootout system "$PLIST" >/dev/null 2>&1 || true
    if launchctl bootstrap system "$PLIST" >/dev/null 2>&1; then
        ok "Layanan dimuat lewat launchctl bootstrap"
    elif launchctl load -w "$PLIST" >/dev/null 2>&1; then
        ok "Layanan dimuat lewat launchctl load"
    else
        warn "launchctl tidak dapat memuat layanan, agent dijalankan langsung."
    fi
else
    warn "Berkas layanan $PLIST tidak ada."
    dim "Agent tetap bisa dijalankan, tetapi tidak otomatis saat mesin menyala."
fi

# wazuh-control dipanggil juga, karena bootstrap hanya memuat definisi
# layanan dan tidak selalu langsung menjalankan daemonnya.
"$OSSEC_DIR/bin/wazuh-control" restart >/dev/null 2>&1 || \
  "$OSSEC_DIR/bin/wazuh-control" start >/dev/null 2>&1 || \
  die "wazuh-agent gagal dijalankan. Periksa: $OSSEC_DIR/bin/wazuh-control status"

sleep 3
if "$OSSEC_DIR/bin/wazuh-control" status 2>/dev/null | grep -q 'is running'; then
    ok "Daemon wazuh-agent berjalan"
else
    die "Daemon tidak berjalan setelah dijalankan. Periksa: $OSSEC_DIR/bin/wazuh-control status"
fi

# =============================================================================
#  Langkah 8: pendaftaran, sambungan, dan verifikasi
# =============================================================================
step "Menunggu pendaftaran dan verifikasi pemantauan"

# Pemeriksaan ini yang menentukan. agent bisa berstatus aktif tetapi tidak
# pernah tersambung karena alamat salah, port diblokir, nama bentrok,
# atau group tidak ada di manager.
info "Batas waktu ${CONNECT_TIMEOUT} detik"

# Hanya baris yang muncul setelah restart yang dibaca.
new_log() {
    [ -f "$OSSEC_LOG" ] || return 0
    tail -n "+$((LOG_START + 1))" "$OSSEC_LOG" 2>/dev/null || true
}

CONNECTED=0
FAIL_REASON=""
FAIL_PATTERN="Unable to connect|Invalid server address|Authentication error|Duplicate agent name|Unable to add agent"

for _ in $(seq 1 "$CONNECT_TIMEOUT"); do
    CHUNK="$(new_log)"

    if grep -q "Connected to the server" <<< "$CHUNK"; then
        CONNECTED=1
        FAIL_REASON=""
        break
    fi

    # Pesan gagal dicatat tetapi loop TIDAK dihentikan. Agent yang baru
    # start sering mencatat 'Unable to connect' sekali lalu berhasil
    # beberapa detik kemudian, dan berhenti di pesan pertama akan
    # melaporkan kegagalan pada pemasangan yang sebenarnya berhasil.
    LAST_ERR="$(grep -oE "$FAIL_PATTERN.*" <<< "$CHUNK" 2>/dev/null | tail -1 || true)"
    [ -n "$LAST_ERR" ] && FAIL_REASON="$LAST_ERR"

    sleep 1
done

REGISTERED=0
AGENT_ID=""
if [ -s "$CLIENT_KEYS" ]; then
    REGISTERED=1
    AGENT_ID="$(awk 'NR==1{print $1" ("$2")"}' "$CLIENT_KEYS" 2>/dev/null || true)"
    ok "Terdaftar ke manager: ID $AGENT_ID"
else
    warn "client.keys masih kosong, agent belum terdaftar."
    dim "Penyebab umum: nama agent sudah dipakai agent lain di manager,"
    dim "atau manager menolak pendaftaran baru."
    dim "Periksa di manager: /var/ossec/logs/ossec.log"
fi

if [ "$CONNECTED" -eq 1 ]; then
    ok "agent tersambung ke manager $WAZUH_MANAGER"
elif [ -n "$FAIL_REASON" ]; then
    warn "Gagal tersambung: $FAIL_REASON"
else
    warn "Belum ada pesan sambungan dalam ${CONNECT_TIMEOUT} detik."
fi

# --- verifikasi

V_PASS=0
V_FAIL=0

# Pembungkus 'grep -c' yang selalu menghasilkan angka.
#
# Tanpa ini, 'grep -c pola berkas-yang-tidak-ada || true' menghasilkan
# string KOSONG, bukan nol, karena grep tidak mencetak apa pun saat
# berkasnya tidak terbuka. Perbandingan berikutnya lalu gagal dengan
# '[: : integer expected' dan menghentikan verifikasi di tengah.
count_matches() {
    local pattern="$1" file="$2" n
    [ -f "$file" ] || { echo 0; return 0; }
    n="$(grep -cE "$pattern" "$file" 2>/dev/null | tr -d ' ' || true)"
    case "$n" in
        ''|*[!0-9]*) echo 0 ;;
        *)           echo "$n" ;;
    esac
}

# Seperti count_matches, tetapi komentar XML dibuang lebih dulu.
#
# Diperlukan karena blok yang disisipkan skrip ini memuat komentar
# penjelas yang menyebut nama modul. Tanpa membuang komentar, nama itu
# ikut terhitung dan satu blok nyata dilaporkan sebagai dua.
count_elements() {
    local pattern="$1" file="$2" n
    [ -f "$file" ] || { echo 0; return 0; }
    if [ -z "$PY" ]; then
        count_matches "$pattern" "$file"
        return 0
    fi
    n="$("$PY" -c '
import re, sys
pat, path = sys.argv[1], sys.argv[2]
try:
    s = open(path, encoding="utf-8", errors="replace").read()
except OSError:
    print(0); sys.exit(0)
print(len(re.findall(pat, re.sub(r"<!--.*?-->", "", s, flags=re.S))))
' "$pattern" "$file" 2>/dev/null || true)"
    case "$n" in
        ''|*[!0-9]*) echo 0 ;;
        *)           echo "$n" ;;
    esac
}

vcheck() {
    local state="$1" label="$2" detail="${3:-}"
    case "$state" in
        pass) printf '  %bOK  %b %s %b%s%b\n' "$G" "$N" "$label" "$GRY" "$detail" "$N"; V_PASS=$((V_PASS + 1)) ;;
        warn) printf '  %bWARN%b %s %b%s%b\n' "$Y" "$N" "$label" "$GRY" "$detail" "$N" ;;
        fail) printf '  %bBLM %b %s %b%s%b\n' "$R" "$N" "$label" "$GRY" "$detail" "$N"; V_FAIL=$((V_FAIL + 1))
              WARN_LIST+=("Verifikasi: $label $detail"); WARN_COUNT=$((WARN_COUNT + 1)) ;;
    esac
}

if [ "$SKIP_VERIFY" = "1" ]; then
    dim "Dilewati karena SKIP_VERIFY=1"
else
    echo

    # --- remote_commands.
    #
    # Keduanya diperiksa, bukan hanya yang pertama. logcollector mengurus
    # <localfile> dengan log_format command, sedangkan wazuh_command
    # mengurus modul command yang dikirim manager lewat agent.conf. Salah
    # satu mati berarti sebagian perintah diabaikan tanpa pesan galat.
    for opt in logcollector.remote_commands wazuh_command.remote_commands; do
        if grep -qE "^[[:space:]]*${opt//./\\.}=1[[:space:]]*$" "$LOCAL_OPT" 2>/dev/null; then
            vcheck pass "$opt aktif"
        else
            vcheck fail "$opt aktif" "perintah dari manager akan diabaikan"
        fi
    done

    # --- modul di ossec.conf.
    #
    # Pola diakhiri '[ >]' supaya nama elemen cocok seluruhnya. Tanpa itu,
    # '<sca' juga cocok dengan '<scan_on_start>' dan pemeriksaan selalu
    # lolos tanpa membuktikan apa pun.
    #
    # Blok <syscheck> dikecualikan dari pemeriksaan blok ganda, karena
    # Wazuh MENGGABUNGKAN beberapa blok syscheck menjadi satu daftar
    # direktori. Dua blok di situ wajar dan memang dimanfaatkan.
    for mod in syscheck sca rootcheck active-response client_buffer; do
        COUNT_MOD="$(count_elements "<${mod}[ >]" "$OSSEC_CONF")"
        if [ "$COUNT_MOD" -eq 0 ]; then
            vcheck fail "Modul $mod terdaftar" "tidak ada di ossec.conf"
        elif [ "$COUNT_MOD" -eq 1 ] || [ "$mod" = "syscheck" ]; then
            if [ "$COUNT_MOD" -gt 1 ]; then
                vcheck pass "Modul $mod terdaftar" "$COUNT_MOD blok, digabung Wazuh"
            else
                vcheck pass "Modul $mod terdaftar"
            fi
        else
            vcheck warn "Modul $mod terdaftar" "$COUNT_MOD blok, hanya yang pertama dipakai"
        fi
    done

    COUNT_SYSCOL="$(count_elements '<wodle[ \t]+name="syscollector"' "$OSSEC_CONF")"
    if [ "$COUNT_SYSCOL" -eq 1 ]; then
        vcheck pass "Modul syscollector terdaftar"
    elif [ "$COUNT_SYSCOL" -gt 1 ]; then
        vcheck warn "Modul syscollector terdaftar" "$COUNT_SYSCOL blok, hanya yang pertama dipakai"
    else
        vcheck fail "Modul syscollector terdaftar" "tidak ada di ossec.conf"
    fi

    # --- Unified Logging System.
    #
    # Ini sumber utama di macOS. Tanpa ini, masuk lewat SSH, pemakaian
    # sudo, dan perubahan izin privasi tidak terpantau sama sekali.
    if grep -qF '<location>macos</location>' "$OSSEC_CONF" 2>/dev/null; then
        vcheck pass "Unified Logging System dipantau"
    else
        vcheck fail "Unified Logging System dipantau" "sudo dan sshd tidak terpantau"
    fi

    # --- nilai yang disetel di tempat
    if grep -qE '<ports[[:space:]]+all="yes"' "$OSSEC_CONF" 2>/dev/null; then
        vcheck pass "syscollector memindai seluruh port"
    else
        vcheck warn "syscollector memindai seluruh port" "hanya port menyimak yang dilaporkan"
    fi

    QSIZE="$(grep -oE '<queue_size>[0-9]+</queue_size>' "$OSSEC_CONF" 2>/dev/null \
             | head -1 | tr -cd '0-9' || true)"
    if [ -n "$QSIZE" ] && [ "$QSIZE" -ge 100000 ]; then
        vcheck pass "Penyangga kiriman diperbesar" "queue_size $QSIZE"
    elif [ -n "$QSIZE" ]; then
        vcheck warn "Penyangga kiriman" "queue_size $QSIZE, event bisa dibuang saat lonjakan"
    fi

    # --- sumber log
    SRC_COUNT="$(count_matches '<location>' "$OSSEC_CONF")"
    if [ "$SRC_COUNT" -ge 3 ]; then
        vcheck pass "Sumber log terdaftar" "$SRC_COUNT entri"
    else
        vcheck warn "Sumber log terdaftar" "hanya $SRC_COUNT entri"
    fi

    # --- kebijakan SCA benar berjalan, bukan hanya modulnya aktif.
    #
    # Berkas kebijakan memuat uji versi sistem operasi. Bila versi mesin
    # tidak cocok, seluruh kebijakan dilewati dan pemindaian selesai
    # dalam nol detik tanpa satu pun pemeriksaan dijalankan. Modul tetap
    # melaporkan diri aktif, sehingga keadaan ini mudah terlewat.
    SCA_POLICIES="$(find "$OSSEC_DIR/ruleset/sca" -name '*.yml' 2>/dev/null | wc -l | tr -d ' ' || echo 0)"
    SCA_SKIP="$(grep -h 'sca: INFO: Skipping policy' "$OSSEC_LOG" 2>/dev/null \
                | sed 's/^.*sca: INFO: //' | sort -u | wc -l | tr -d ' ' || echo 0)"
    if [ "$SCA_SKIP" -gt 0 ]; then
        vcheck warn "Kebijakan SCA berjalan" "$SCA_SKIP kebijakan dilewati karena versi tidak cocok"
        grep -h 'sca: INFO: Skipping policy' "$OSSEC_LOG" 2>/dev/null \
          | sed 's/^.*sca: INFO: //' | sort -u | head -3 | while IFS= read -r l; do
            dim "$l"
        done
        dim "Wazuh membawa kebijakan CIS hanya untuk sebagian versi macOS."
    elif [ "$SCA_POLICIES" -gt 0 ]; then
        vcheck pass "Kebijakan SCA tersedia" "$SCA_POLICIES berkas"
    else
        vcheck warn "Kebijakan SCA tersedia" "belum ada, biasanya dikirim manager lewat group"
    fi

    # --- proses agent yang seharusnya hidup
    CTRL_OUT="$("$OSSEC_DIR/bin/wazuh-control" status 2>/dev/null || true)"
    for proc in wazuh-agentd wazuh-logcollector wazuh-syscheckd wazuh-modulesd; do
        if printf '%s' "$CTRL_OUT" | grep -q "$proc is running"; then
            vcheck pass "Proses $proc hidup"
        else
            case "$proc" in
                wazuh-modulesd)
                    vcheck fail "Proses $proc hidup" "syscollector, SCA, dan rootcheck ikut tidak berjalan" ;;
                wazuh-logcollector)
                    vcheck fail "Proses $proc hidup" "pembacaan log berhenti" ;;
                *)
                    vcheck fail "Proses $proc hidup" "modul terkait tidak berjalan" ;;
            esac
        fi
    done

    # --- layanan terdaftar di launchd, bukan hanya proses hidup.
    #
    # Tanpa ini agent berjalan sekarang tetapi tidak menyala kembali
    # setelah mesin dinyalakan ulang, dan itu baru ketahuan berminggu
    # minggu kemudian saat agent terlihat disconnected.
    if launchctl print system/com.wazuh.agent >/dev/null 2>&1; then
        vcheck pass "Layanan terdaftar di launchd" "otomatis saat mesin menyala"
    elif launchctl list 2>/dev/null | grep -q 'com.wazuh.agent'; then
        vcheck pass "Layanan terdaftar di launchd" "otomatis saat mesin menyala"
    else
        vcheck fail "Layanan terdaftar di launchd" "agent tidak menyala setelah reboot"
    fi

    # --- FIM benar berjalan
    if printf '%s' "$(new_log)" | grep -q 'File integrity monitoring scan ended\|Real-time file integrity monitoring started'; then
        vcheck pass "Pemantauan keutuhan berkas berjalan"
    else
        vcheck warn "Pemantauan keutuhan berkas" "pemindaian pertama mungkin masih berlangsung"
    fi

    # --- Full Disk Access.
    #
    # Pada macOS Catalina ke atas, pembacaan sebagian jalur memerlukan
    # izin Full Disk Access untuk proses agent. Tanpa izin itu, FIM pada
    # direktori pengguna gagal diam diam: tidak ada galat, hanya tidak
    # ada event.
    #
    # Keberadaan izin tidak bisa dibaca langsung, jadi yang diperiksa
    # adalah gejalanya, yaitu galat izin di log.
    if printf '%s' "$(new_log)" | grep -qi 'Operation not permitted\|Permission denied'; then
        vcheck warn "Akses berkas penuh" "ada galat izin di log, periksa Full Disk Access"
        dim "Pengaturan Sistem > Privasi & Keamanan > Akses Disk Penuh"
        dim "Tambahkan: $OSSEC_DIR/bin/wazuh-syscheckd dan wazuh-logcollector"
    else
        vcheck pass "Tidak ada galat izin berkas"
    fi

    # --- galat di log agent.
    #
    # Hanya baris sejak restart yang dihitung. Galat dari sesi lama tidak
    # memberi tahu apa pun tentang pemasangan ini.
    NEW_LINES="$(new_log)"
    ERR_COUNT="$(grep -cE 'ERROR|CRITICAL' <<< "$NEW_LINES" 2>/dev/null | tr -d ' ' || true)"
    [ -n "$ERR_COUNT" ] || ERR_COUNT=0
    if [ "$ERR_COUNT" -eq 0 ]; then
        vcheck pass "Tidak ada galat baru di ossec.log"
    else
        vcheck warn "Ada $ERR_COUNT galat sejak agent dijalankan"
        grep -E 'ERROR|CRITICAL' <<< "$NEW_LINES" | tail -4 | while IFS= read -r l; do
            dim "$l"
        done
    fi
fi

# =============================================================================
#  Penutup
# =============================================================================
echo
echo "=============================================================="
echo "   Selesai"
echo "=============================================================="
echo "   agent         : $AGENT_NAME"
echo "   manager       : $WAZUH_MANAGER"
echo "   group         : $WAZUH_GROUP"
echo "   macOS         : $MACOS_VER ($ARCH_SUFFIX)"
echo "   Sumber log    : $(count_matches '<location>' "$OSSEC_CONF") entri"
printf '   Layanan       : '
if "$OSSEC_DIR/bin/wazuh-control" status 2>/dev/null | grep -q 'is running'; then
    printf '%bberjalan%b\n' "$G" "$N"
else
    printf '%btidak berjalan%b\n' "$R" "$N"
fi
printf '   Terdaftar     : '
if [ "$REGISTERED" -eq 1 ]; then
    printf '%bya%b (%s)\n' "$G" "$N" "$AGENT_ID"
else
    printf '%bbelum%b\n' "$Y" "$N"
fi
printf '   Tersambung    : '
if [ "$CONNECTED" -eq 1 ]; then
    printf '%bya%b\n' "$G" "$N"
else
    printf '%bbelum%b\n' "$Y" "$N"
fi
if [ "$SKIP_VERIFY" != "1" ]; then
    printf '   Verifikasi    : '
    if [ "$V_FAIL" -eq 0 ]; then
        printf '%b%s lolos%b\n' "$G" "$V_PASS" "$N"
    else
        printf '%b%s lolos%b, %b%s belum terbukti%b\n' "$G" "$V_PASS" "$N" "$R" "$V_FAIL" "$N"
    fi
fi
echo "   Berkas log    : $LOGFILE"

if [ "$WARN_COUNT" -gt 0 ]; then
    echo
    printf '   %b%s peringatan:%b\n' "$Y" "$WARN_COUNT" "$N"
    for w in "${WARN_LIST[@]}"; do
        printf '     %b-%b %s\n' "$Y" "$N" "$w"
    done
fi

echo
echo "   Langkah berikutnya:"
echo
echo "   Di mesin ini (agent):"
echo "     Status daemon      : $OSSEC_DIR/bin/wazuh-control status"
echo "     Konfigurasi aktif  : $OSSEC_DIR/bin/wazuh-control info"
echo "     Pantau log         : tail -f $OSSEC_LOG"
echo "     Lihat pendaftaran  : cat $CLIENT_KEYS"
echo "     Status layanan     : launchctl print system/com.wazuh.agent"
echo
echo "   Di server manager:"
echo "     Perkakas agent_control hanya terpasang di manager, tidak di"
echo "     mesin agent, jadi perintah berikut dijalankan di sana."
echo
echo "     Pastikan agent terdaftar :"
echo "       /var/ossec/bin/agent_control -l | grep -i '$AGENT_NAME'"
echo "     Lihat rincian agent :"
echo "       /var/ossec/bin/agent_control -i <id-agent>"

# Izin Akses Disk Penuh tidak bisa diberikan lewat baris perintah tanpa
# perkakas pengelolaan perangkat, jadi disebutkan di sini supaya tidak
# terlewat pada pemasangan manual.
echo
echo "   Satu langkah manual yang tidak bisa diotomasi:"
echo
echo "     macOS membatasi pembacaan sebagian berkas, termasuk di dalam"
echo "     direktori pengguna. Tanpa izin Akses Disk Penuh, pemantauan"
echo "     di jalur itu berhenti tanpa pesan galat."
echo
echo "     Buka: Pengaturan Sistem > Privasi & Keamanan > Akses Disk Penuh"
echo "     Tambahkan dua berkas berikut, lalu hidupkan sakelarnya:"
echo "       $OSSEC_DIR/bin/wazuh-syscheckd"
echo "       $OSSEC_DIR/bin/wazuh-logcollector"
echo
echo "     Pada armada yang dikelola MDM, izin ini dikirim lewat profil"
echo "     PPPC sehingga tidak perlu disentuh satu per satu."
echo "=============================================================="

if [ "$CONNECTED" -ne 1 ]; then
    echo
    echo "agent belum tersambung. Periksa:"
    echo "  - group '$WAZUH_GROUP' sudah ada di manager?"
    echo "  - nama '$AGENT_NAME' bentrok dengan agent lain?"
    echo "  - port $WAZUH_REG_PORT dan $WAZUH_COMM_PORT terbuka dua arah?"
    echo
    echo "--- 25 baris terakhir $OSSEC_LOG ---"
    tail -25 "$OSSEC_LOG" 2>/dev/null || echo "(log tidak terbaca)"
    exit 2
fi

exit 0
