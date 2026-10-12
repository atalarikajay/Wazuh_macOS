#!/bin/bash
# =============================================================================
#  Pencabutan Wazuh Agent - macOS
#
#  CARA PAKAI
#      sudo bash uninstall_wazuh_macos.sh
#
#  Tanpa konfirmasi, untuk otomasi:
#      sudo ASSUME_YES=1 bash uninstall_wazuh_macos.sh
#
#  VARIABEL LINGKUNGAN
#    ASSUME_YES     isi 1 untuk melewati semua konfirmasi
#    KEEP_USER      isi 1 untuk membiarkan pengguna dan grup wazuh
#    PURGE_LOGS     isi 1 untuk menghapus juga log pemasangan di /var/log
#
#  KODE KELUAR
#    0  terhapus bersih, tidak ada sisa
#    1  gagal sebelum mulai, misalnya bukan root
#    2  terhapus, ada sisa yang bisa dibereskan
#    3  GAGAL, direktori agent masih ada
#
#  URUTAN PENTING
#  Layanan dibongkar dan proses dimatikan SEBELUM direktori dihapus.
#  Tanpa urutan itu, launchd menjalankan ulang agent tepat setelah
#  prosesnya mati, dan penghapusan direktori gagal sebagian.
#
#  TIDAK PERLU MENYALAKAN ULANG MESIN.
# =============================================================================
set -uo pipefail

ASSUME_YES="${ASSUME_YES:-0}"
KEEP_USER="${KEEP_USER:-0}"
PURGE_LOGS="${PURGE_LOGS:-0}"

OSSEC_DIR="/Library/Ossec"
CLIENT_KEYS="$OSSEC_DIR/etc/client.keys"
PLIST="/Library/LaunchDaemons/com.wazuh.agent.plist"
STARTUP_DIR="/Library/StartupItems/WAZUH"
PKG_ID="com.wazuh.pkg.wazuh-agent"
ENV_FILE="/tmp/wazuh_envs"
LOGFILE="/var/log/wazuh-agent-uninstall-$(date +%Y%m%d-%H%M%S).log"

R='\033[31m'; G='\033[32m'; Y='\033[33m'; GRY='\033[90m'; N='\033[0m'
STEP=0
STEP_TOTAL=6
declare -a PROBLEMS=()

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

ok(){   cwrite "$G"   "[ OK ]" "$*"; }
dim(){  cwrite "$GRY" "      " "$*"; }
prob(){ cwrite "$Y"   "[WARN]" "$*"; PROBLEMS+=("$*"); }
die(){  cwrite "$R"   "[FAIL]" "$*" >&2; exit 1; }
step(){ STEP=$((STEP + 1)); echo; cwrite "$Y" "[$STEP/$STEP_TOTAL]" "$*"; }

[ "$(uname -s)" = "Darwin" ] || die "Skrip ini hanya untuk macOS."
[ "$(id -u)" -eq 0 ] || die "Harus dijalankan sebagai root. Pakai: sudo bash $0"

exec > >(tee -a "$LOGFILE") 2>&1

ask() {
    local prompt="$1" varname="$2" answer=""

    # Uji baca sungguhan, bukan sekadar '[ -r /dev/tty ]'. Pada sesi
    # tanpa terminal kendali, berkas itu lolos uji -r tetapi membukanya
    # gagal dengan 'No such device or address'.
    if { : < /dev/tty; } 2>/dev/null; then
        read -r -p "$prompt" answer < /dev/tty
    elif [ -t 0 ]; then
        read -r -p "$prompt" answer
    else
        die "Tidak ada terminal untuk bertanya. Pakai ASSUME_YES=1."
    fi
    printf -v "$varname" '%s' "$answer" 2>/dev/null || eval "$varname=\$answer"
}

MACOS_VER="$(sw_vers -productVersion 2>/dev/null || echo '?')"

echo "=============================================================="
echo "   Pencabutan Wazuh Agent untuk macOS"
echo "=============================================================="
echo
echo "   Mesin      : $(scutil --get LocalHostName 2>/dev/null || hostname -s 2>/dev/null || echo '?')"
echo "   macOS      : $MACOS_VER"
echo "   Berkas log : $LOGFILE"

# =============================================================================
#  Langkah 1: periksa apa yang terpasang
# =============================================================================
step "Memeriksa apa yang terpasang"

FOUND_ANY=0

if [ -d "$OSSEC_DIR" ]; then
    FOUND_ANY=1
    DIR_SIZE="$(du -sh "$OSSEC_DIR" 2>/dev/null | awk '{print $1}' || echo '?')"
    dim "Direktori $OSSEC_DIR ada, ukuran $DIR_SIZE"
else
    dim "Direktori $OSSEC_DIR tidak ada"
fi

if [ -f "$PLIST" ]; then
    FOUND_ANY=1
    dim "Berkas layanan $PLIST ada"
fi

SVC_LOADED=0
if launchctl print system/com.wazuh.agent >/dev/null 2>&1; then
    SVC_LOADED=1; FOUND_ANY=1
    dim "Layanan com.wazuh.agent termuat di launchd"
elif launchctl list 2>/dev/null | grep -q 'com.wazuh.agent'; then
    SVC_LOADED=1; FOUND_ANY=1
    dim "Layanan com.wazuh.agent termuat di launchd"
fi

PKG_PRESENT=0
if pkgutil --pkgs 2>/dev/null | grep -qx "$PKG_ID"; then
    PKG_PRESENT=1; FOUND_ANY=1
    PKG_VER="$(pkgutil --pkg-info "$PKG_ID" 2>/dev/null | awk '/^version:/{print $2}' || true)"
    dim "Catatan paket $PKG_ID ada${PKG_VER:+, versi $PKG_VER}"
else
    dim "Catatan paket $PKG_ID tidak ada"
fi

# Identitas agent dibaca SEBELUM berkas dihapus, karena entri di manager
# harus dibersihkan manual memakai ID ini dan client.keys sudah tidak ada
# saat pesan penutup dicetak.
AGENT_IDENT=""
AGENT_ID=""
if [ -s "$CLIENT_KEYS" ]; then
    AGENT_ID="$(awk 'NR==1{print $1}' "$CLIENT_KEYS" 2>/dev/null || true)"
    AGENT_IDENT="$(awk 'NR==1{print $1" ("$2")"}' "$CLIENT_KEYS" 2>/dev/null || true)"
    [ -n "$AGENT_IDENT" ] && dim "Terdaftar di manager sebagai: $AGENT_IDENT"
fi

if [ "$FOUND_ANY" -eq 0 ]; then
    echo
    ok "Tidak ada jejak Wazuh Agent di mesin ini. Tidak ada yang perlu dihapus."
    echo
    exit 0
fi

# --- konfirmasi
if [ "$ASSUME_YES" != "1" ]; then
    echo
    echo "   Yang akan dihapus:"
    echo "     Layanan launchd com.wazuh.agent"
    echo "     Direktori $OSSEC_DIR beserta seluruh isinya"
    echo "     $STARTUP_DIR"
    echo "     Catatan paket $PKG_ID"
    [ "$KEEP_USER" = "1" ] && echo "     Pengguna dan grup wazuh DIBIARKAN"
    echo
    printf '   %bKunci pendaftaran agent ikut terhapus.%b\n' "$Y" "$N"
    printf '   %bBila agent dipasang ulang, ia mendaftar sebagai entri baru,%b\n' "$Y" "$N"
    printf '   %bdan entri lama perlu dihapus manual dari dashboard.%b\n' "$Y" "$N"
    if [ -n "$AGENT_IDENT" ]; then
        printf '   %bEntri saat ini: %s%b\n' "$Y" "$AGENT_IDENT" "$N"
    fi
    echo
    ask "   Lanjutkan pencabutan? (y/N): " GO
    case "${GO:-N}" in
        [Yy]*) : ;;
        *) echo "   Dibatalkan."; exit 0 ;;
    esac
fi

# =============================================================================
#  Langkah 2: hentikan layanan
# =============================================================================
step "Menghentikan layanan"

# wazuh-control stop lebih dulu, supaya daemon berhenti rapi dan menulis
# keadaan terakhirnya.
if [ -x "$OSSEC_DIR/bin/wazuh-control" ]; then
    "$OSSEC_DIR/bin/wazuh-control" stop >/dev/null 2>&1 || true
    dim "wazuh-control stop dijalankan"
fi

# Layanan dibongkar dari launchd. Tanpa ini, launchd menjalankan ulang
# agent tepat setelah prosesnya mati, karena plist memakai RunAtLoad.
#
# bootout adalah bentuk yang berlaku sejak macOS 10.11. Bentuk lama
# 'launchctl unload' dicoba sebagai cadangan untuk sistem lama.
if [ "$SVC_LOADED" -eq 1 ] || [ -f "$PLIST" ]; then
    if launchctl bootout system "$PLIST" >/dev/null 2>&1; then
        ok "Layanan dibongkar dengan launchctl bootout"
    elif launchctl unload -w "$PLIST" >/dev/null 2>&1; then
        ok "Layanan dibongkar dengan launchctl unload"
    else
        # Bootout mengembalikan kode bukan nol bila layanan memang sudah
        # tidak termuat, jadi keadaan itu diperiksa, bukan kode keluarnya.
        if launchctl print system/com.wazuh.agent >/dev/null 2>&1; then
            prob "Layanan masih termuat di launchd setelah dicoba dibongkar."
        else
            ok "Layanan tidak termuat di launchd"
        fi
    fi
else
    dim "Tidak ada layanan yang termuat"
fi

# Proses yang tersisa akan mengunci berkas. Dimatikan bertahap: sinyal
# biasa lebih dulu, baru paksa.
AGENT_PROCS="wazuh-agentd wazuh-logcollector wazuh-syscheckd wazuh-modulesd wazuh-execd agent-auth"
KILLED=0
for p in $AGENT_PROCS; do
    if pgrep -x "$p" >/dev/null 2>&1; then
        pkill -TERM -x "$p" >/dev/null 2>&1 || true
        KILLED=$((KILLED + 1))
    fi
done
if [ "$KILLED" -gt 0 ]; then
    sleep 3
    STILL=0
    for p in $AGENT_PROCS; do
        if pgrep -x "$p" >/dev/null 2>&1; then
            pkill -KILL -x "$p" >/dev/null 2>&1 || true
            STILL=$((STILL + 1))
        fi
    done
    sleep 1
    if [ "$STILL" -gt 0 ]; then
        ok "$KILLED proses agent dihentikan, $STILL perlu dipaksa"
    else
        ok "$KILLED proses agent dihentikan"
    fi
else
    dim "Tidak ada proses agent yang berjalan"
fi

# =============================================================================
#  Langkah 3: hapus berkas layanan
# =============================================================================
step "Menghapus berkas layanan"

for f in "$PLIST" "$STARTUP_DIR"; do
    if [ -e "$f" ]; then
        if rm -rf "$f" 2>/dev/null; then
            ok "Dihapus: $f"
        else
            prob "Gagal menghapus: $f"
        fi
    else
        dim "Tidak ada: $f"
    fi
done

# =============================================================================
#  Langkah 4: hapus direktori agent
# =============================================================================
step "Menghapus direktori agent"

if [ -d "$OSSEC_DIR" ]; then
    if rm -rf "$OSSEC_DIR" 2>/dev/null; then
        ok "Direktori $OSSEC_DIR dihapus"
    else
        # Coba sekali lagi setelah jeda. Pegangan berkas kadang butuh
        # waktu untuk dilepas setelah proses berhenti.
        dim "Percobaan pertama gagal, mencoba ulang setelah 5 detik"
        sleep 5
        if rm -rf "$OSSEC_DIR" 2>/dev/null; then
            ok "Direktori dihapus pada percobaan kedua"
        else
            prob "Direktori $OSSEC_DIR tidak bisa dihapus."
            if command -v lsof >/dev/null 2>&1; then
                HOLDERS="$(lsof +D "$OSSEC_DIR" 2>/dev/null | awk 'NR>1{print $1}' | sort -u | tr '\n' ' ')"
                [ -n "$HOLDERS" ] && dim "Proses yang memegang berkas: $HOLDERS"
            fi
        fi
    fi
else
    dim "Direktori $OSSEC_DIR tidak ada"
fi

# Catatan paket di basis data installer. Tanpa dihapus, pemasangan
# berikutnya bisa dianggap peningkatan versi.
if [ "$PKG_PRESENT" -eq 1 ]; then
    if pkgutil --forget "$PKG_ID" >/dev/null 2>&1; then
        ok "Catatan paket $PKG_ID dihapus"
    else
        prob "Gagal menghapus catatan paket $PKG_ID"
    fi
fi

# Catatan paket versi lama, bila ada.
for oldpkg in com.wazuh.pkg.wazuh-agent-etc com.wazuh.pkg.ossec-agent; do
    if pkgutil --pkgs 2>/dev/null | grep -qx "$oldpkg"; then
        pkgutil --forget "$oldpkg" >/dev/null 2>&1 || true
        dim "Catatan paket lama dihapus: $oldpkg"
    fi
done

# Berkas variabel pendaftaran yang mungkin tertinggal. Isinya alamat
# manager dan nama group.
if [ -f "$ENV_FILE" ]; then
    rm -f "$ENV_FILE" 2>/dev/null || true
    dim "Berkas variabel pendaftaran dihapus: $ENV_FILE"
fi

# =============================================================================
#  Langkah 5: pengguna dan grup
# =============================================================================
step "Pengguna dan grup wazuh"

if [ "$KEEP_USER" = "1" ]; then
    dim "Dibiarkan karena KEEP_USER=1"
else
    # Dibuang secara baku, berbeda dari versi Linux. Di macOS pengguna
    # wazuh dibuat khusus oleh paket ini lewat dscl dan tidak dipakai
    # perangkat lain, sedangkan di Linux pengguna sistem lebih sering
    # dipakai bersama.
    USER_REMOVED=0
    if dscl . -read /Users/wazuh >/dev/null 2>&1; then
        if dscl . -delete /Users/wazuh >/dev/null 2>&1; then
            ok "Pengguna wazuh dihapus"
            USER_REMOVED=1
        else
            prob "Gagal menghapus pengguna wazuh"
        fi
    else
        dim "Pengguna wazuh tidak ada"
    fi

    if dscl . -read /Groups/wazuh >/dev/null 2>&1; then
        if dscl . -delete /Groups/wazuh >/dev/null 2>&1; then
            ok "Grup wazuh dihapus"
        else
            prob "Gagal menghapus grup wazuh"
        fi
    else
        dim "Grup wazuh tidak ada"
    fi

    # Direktori beranda pengguna wazuh, dibuat paket di /var/wazuh.
    if [ "$USER_REMOVED" -eq 1 ] && [ -d /var/wazuh ]; then
        rm -rf /var/wazuh 2>/dev/null || true
        dim "Direktori /var/wazuh dihapus"
    fi
fi

# Log pemasangan dan pencabutan dari skrip. Log pencabutan yang sedang
# ditulis sekarang dikecualikan, karena masih dipakai sampai skrip selesai.
if [ "$PURGE_LOGS" = "1" ]; then
    COUNT=0
    for pat in 'wazuh-agent-install-*.log' 'wazuh-agent-uninstall-*.log'; do
        while IFS= read -r f; do
            [ -n "$f" ] || continue
            [ "$f" = "$LOGFILE" ] && continue
            rm -f "$f" 2>/dev/null && COUNT=$((COUNT + 1))
        done < <(find /var/log -maxdepth 1 -name "$pat" 2>/dev/null || true)
    done
    if [ "$COUNT" -gt 0 ]; then
        dim "$COUNT berkas log lama dihapus"
    fi
fi

# =============================================================================
#  Langkah 6: verifikasi
# =============================================================================
step "Verifikasi"

declare -a LEFTOVERS=()

if [ -d "$OSSEC_DIR" ]; then
    LEFTOVERS+=("Direktori $OSSEC_DIR masih ada")
else
    ok "Direktori agent terhapus"
fi

if [ -f "$PLIST" ]; then
    LEFTOVERS+=("Berkas layanan $PLIST masih ada")
else
    ok "Berkas layanan terhapus"
fi

if launchctl print system/com.wazuh.agent >/dev/null 2>&1; then
    LEFTOVERS+=("Layanan com.wazuh.agent masih termuat di launchd")
elif launchctl list 2>/dev/null | grep -q 'com.wazuh.agent'; then
    LEFTOVERS+=("Layanan com.wazuh.agent masih termuat di launchd")
else
    ok "Layanan tidak termuat di launchd"
fi

if pkgutil --pkgs 2>/dev/null | grep -qx "$PKG_ID"; then
    LEFTOVERS+=("Catatan paket $PKG_ID masih ada, jalankan: pkgutil --forget $PKG_ID")
else
    ok "Catatan paket terhapus"
fi

RUNNING=""
for p in $AGENT_PROCS; do
    pgrep -x "$p" >/dev/null 2>&1 && RUNNING="$RUNNING $p"
done
if [ -n "$RUNNING" ]; then
    LEFTOVERS+=("Proses masih berjalan:$RUNNING")
else
    ok "Tidak ada proses agent yang berjalan"
fi

if [ "$KEEP_USER" != "1" ]; then
    if dscl . -read /Users/wazuh >/dev/null 2>&1; then
        LEFTOVERS+=("Pengguna wazuh masih ada, jalankan: sudo dscl . -delete /Users/wazuh")
    else
        ok "Pengguna wazuh terhapus"
    fi
fi

# =============================================================================
#  Penutup
# =============================================================================
echo
echo "=============================================================="
if [ "${#LEFTOVERS[@]}" -eq 0 ]; then
    printf '   %bWazuh Agent terhapus bersih%b\n' "$G" "$N"
    echo "=============================================================="
    echo
    if [ -n "$AGENT_IDENT" ]; then
        echo "   LANGKAH TERAKHIR, DI SERVER MANAGER"
        echo
        echo "   Pencabutan ini hanya membersihkan endpoint. Entri agent di"
        echo "   manager tidak ikut terhapus, karena skrip berjalan di sini"
        echo "   dan tidak punya akses ke basis data manager."
        echo
        echo "   Jalankan di server manager untuk menghapus entri $AGENT_IDENT:"
        echo "     /var/ossec/bin/manage_agents -r ${AGENT_ID:-<id>}"
        echo
        echo "   Tanpa itu, agent tetap terdaftar di dashboard. Statusnya baru"
        echo "   berubah menjadi disconnected setelah beberapa menit tanpa"
        echo "   denyut, bukan seketika setelah pencabutan."
        echo
    fi
    echo "   Satu hal yang perlu dibereskan manual:"
    echo
    echo "     Bila dulu wazuh-syscheckd dan wazuh-logcollector pernah"
    echo "     ditambahkan ke Akses Disk Penuh, entrinya masih tertinggal"
    echo "     di daftar meskipun berkasnya sudah tidak ada."
    echo
    echo "     Buka: Pengaturan Sistem > Privasi & Keamanan > Akses Disk Penuh"
    echo "     Hapus entri yang menunjuk $OSSEC_DIR"
    echo
    echo "   Berkas log: $LOGFILE"
    echo
    exit 0
else
    # Sisa dipisah menurut keparahan. Direktori atau proses yang masih
    # ada berarti pencabutan benar benar gagal. Catatan paket yang
    # tertinggal hanya perlu satu perintah.
    HARD=0
    for l in "${LEFTOVERS[@]}"; do
        case "$l" in
            *"Direktori"*|*"masih berjalan"*) HARD=$((HARD + 1)) ;;
        esac
    done

    if [ "$HARD" -gt 0 ]; then
        printf '   %bGAGAL. Wazuh Agent TIDAK terhapus bersih%b\n' "$R" "$N"
    else
        printf '   %bTerhapus, dengan sisa yang bisa dibereskan sekarang%b\n' "$Y" "$N"
    fi
    echo "=============================================================="
    echo
    printf '   %bYang masih tertinggal:%b\n' "$Y" "$N"
    for l in "${LEFTOVERS[@]}"; do
        printf '     %b-%b %s\n' "$Y" "$N" "$l"
    done
    if [ "${#PROBLEMS[@]}" -gt 0 ]; then
        echo
        printf '   %bMasalah selama proses:%b\n' "$Y" "$N"
        for p in "${PROBLEMS[@]}"; do
            printf '     %b-%b %s\n' "$Y" "$N" "$p"
        done
    fi
    echo
    if [ "$HARD" -gt 0 ]; then
        printf '   %bJangan memasang ulang agent sebelum sisa di atas bersih.%b\n' "$R" "$N"
        echo "   Pemasangan di atas sisa membuat paket menganggapnya peningkatan"
        echo "   versi, sehingga konfigurasi lama dipulihkan dan pendaftaran baru"
        echo "   tidak pernah dijalankan."
        echo
        echo "   Langkah yang disarankan, tanpa perlu menyalakan ulang:"
        echo "     1. Hentikan sisa proses : sudo pkill -KILL -f wazuh"
        echo "     2. Bongkar layanan      : sudo launchctl bootout system $PLIST"
        echo "     3. Jalankan skrip ini sekali lagi"
        echo "     4. Bila direktori tetap terkunci, cari pemegang berkasnya:"
        echo "          sudo lsof +D $OSSEC_DIR"
    else
        echo "   Sisa di atas bisa dibereskan sekarang. Jalankan skrip ini sekali"
        echo "   lagi, atau ikuti perintah yang disebut pada tiap baris sisa."
    fi
    echo
    if [ -n "$AGENT_IDENT" ]; then
        echo "   Di server manager, hapus entri $AGENT_IDENT:"
        echo "     /var/ossec/bin/manage_agents -r ${AGENT_ID:-<id>}"
        echo
    fi
    echo "   Berkas log: $LOGFILE"
    echo

    if [ "$HARD" -gt 0 ]; then exit 3; else exit 2; fi
fi
