#!/usr/bin/env bash
#
# build_package.sh — Build script for valkey-audit packages (RPM, DEB, source tarballs)
#

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
readonly PRODUCT="valkey-audit"
readonly PACKAGE_NAME="percona-valkey-audit"
readonly DEFAULT_VERSION="0.2.2"
readonly DEFAULT_RELEASE="1"
readonly DEFAULT_BRANCH="packaging-vk91mods-v2"
readonly DEFAULT_REPO="https://github.com/EvgeniyPatlan/valkey-audit.git"

# Absolute path to the directory containing this script
BUILDER_SCRIPT_DIR="$(dirname "$(readlink -e "${0}")")"
readonly BUILDER_SCRIPT_DIR

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
log_info()  { printf '\033[1;32m[INFO]\033[0m  %s\n' "$*"; }
log_warn()  { printf '\033[1;33m[WARN]\033[0m  %s\n' "$*" >&2; }
log_error() { printf '\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2; }
die()       { log_error "$@"; exit 1; }

# ---------------------------------------------------------------------------
# Cleanup trap
# ---------------------------------------------------------------------------
cleanup() {
    local rc=$?
    if [[ $rc -ne 0 ]]; then
        log_error "Script exited with code $rc"
    fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
    cat <<EOF
Usage: $0 [OPTIONS]
    The following options may be given:
        --builddir=DIR                  Absolute path to the dir where all actions will be performed
        --get_sources                   Source will be downloaded from github
        --build_src_rpm                 If it is set - src rpm will be built
        --build_src_deb                 If it is set - source deb package will be built
        --build_rpm                     If it is set - rpm will be built
        --build_deb                     If it is set - deb will be built
        --install_deps                  Install build dependencies (root privileges are required)
        --branch=BRANCH                 Branch for build (default: ${DEFAULT_BRANCH})
        --repo=URL                      Repo for build (default: ${DEFAULT_REPO})
        --version=VER                   Version string (default: extracted from src/version.h)
        --release=REL                   Release number (default: ${DEFAULT_RELEASE})
        --use_local_packaging_script    Use local packaging scripts (located in ${BUILDER_SCRIPT_DIR}/{rpm,deb})
        --help                          Print usage
Example: $0 --builddir=/tmp/BUILD --get_sources --build_src_rpm --build_rpm
Example: $0 --builddir=/tmp/BUILD --get_sources --build_src_deb --build_deb
Example: $0 --builddir=/tmp/BUILD --install_deps --get_sources --build_deb
EOF
    exit 0
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
parse_arguments() {
    for arg in "$@"; do
        case "$arg" in
            --builddir=*)                WORKDIR="${arg#*=}" ;;
            --build_src_rpm=*|--build_src_rpm) SRPM=1 ;;
            --build_src_deb=*|--build_src_deb) SDEB=1 ;;
            --build_rpm=*|--build_rpm)   RPM=1 ;;
            --build_deb=*|--build_deb)   DEB=1 ;;
            --get_sources=*|--get_sources) SOURCE=1 ;;
            --branch=*)                  BRANCH="${arg#*=}" ;;
            --repo=*)                    REPO="${arg#*=}" ;;
            --version=*)                 VERSION="${arg#*=}" ;;
            --release=*)                 RELEASE="${arg#*=}" ;;
            --install_deps=*|--install_deps) INSTALL=1 ;;
            --use_local_packaging_script=*|--use_local_packaging_script) LOCAL_BUILD=1 ;;
            --help)                      usage ;;
            *)                           die "Unknown option: $arg" ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# find_and_copy_artifact SEARCH_SUBDIR GLOB_PATTERN
#   Looks for an artifact matching GLOB_PATTERN in $WORKDIR/SEARCH_SUBDIR first,
#   then falls back to $CURDIR/SEARCH_SUBDIR.  Copies the newest match into $WORKDIR.
#   Sets the variable FOUND_FILE to the basename of the found file.
find_and_copy_artifact() {
    local search_subdir="$1"
    local glob_pattern="$2"
    local found

    found="$(find "$WORKDIR/$search_subdir" -name "$glob_pattern" 2>/dev/null | sort | tail -n1 || true)"
    if [[ -n "$found" ]]; then
        FOUND_FILE="$(basename "$found")"
        cp "$found" "$WORKDIR/$FOUND_FILE"
        return 0
    fi

    found="$(find "$CURDIR/$search_subdir" -name "$glob_pattern" 2>/dev/null | sort | tail -n1 || true)"
    if [[ -n "$found" ]]; then
        FOUND_FILE="$(basename "$found")"
        cp "$found" "$WORKDIR/$FOUND_FILE"
        return 0
    fi

    log_error "No artifact matching '$glob_pattern' found in $search_subdir"
    return 1
}

# copy_artifacts DEST_SUBDIR FILE...
#   Copies the given files into both $WORKDIR/DEST_SUBDIR and $CURDIR/DEST_SUBDIR.
#   Glob expansion happens at the call site, so pass unquoted globs as arguments.
copy_artifacts() {
    local dest_subdir="$1"
    shift

    mkdir -p "$WORKDIR/$dest_subdir"
    mkdir -p "$CURDIR/$dest_subdir"
    cp "$@" "$WORKDIR/$dest_subdir/"
    cp "$@" "$CURDIR/$dest_subdir/"
}

# ---------------------------------------------------------------------------
# check_workdir
# ---------------------------------------------------------------------------
check_workdir() {
    if [[ -z "$WORKDIR" ]]; then
        die "--builddir is required"
    fi
    if [[ "$WORKDIR" == "$CURDIR" ]]; then
        die "Current directory cannot be used for building!"
    fi
    if [[ ! -d "$WORKDIR" ]]; then
        log_info "Creating build directory: $WORKDIR"
        mkdir -p "$WORKDIR"
    fi
}

# ---------------------------------------------------------------------------
# extract_version — read version from src/version.h in the source tree
# ---------------------------------------------------------------------------
extract_version() {
    local source_dir="$1"
    local version_file="$source_dir/src/version.h"
    if [[ ! -f "$version_file" ]]; then
        die "Version file not found: $version_file"
    fi

    local major minor patch
    major=$(grep '#define VALKEYAUDIT_VERSION_MAJOR' "$version_file" | awk '{print $3}')
    minor=$(grep '#define VALKEYAUDIT_VERSION_MINOR' "$version_file" | awk '{print $3}')
    patch=$(grep '#define VALKEYAUDIT_VERSION_PATCH' "$version_file" | awk '{print $3}')

    if [[ -z "$major" || -z "$minor" || -z "$patch" ]]; then
        die "Failed to extract version from $version_file"
    fi

    VERSION="${major}.${minor}.${patch}"
    log_info "Version: ${VERSION}"
}

# ---------------------------------------------------------------------------
# get_system — detect OS family (rpm vs deb) and platform details
# ---------------------------------------------------------------------------
get_system() {
    ARCH="$(uname -m)"

    if [[ -f /etc/redhat-release ]]; then
        RHEL="$(rpm --eval %rhel)"
        OS_NAME="el${RHEL}"
        OS="rpm"

        # Detect specific RHEL-family distro for EPEL handling
        if [[ -f /etc/oracle-release ]]; then
            PLATFORM_FAMILY="oracle"
        elif [[ -f /etc/fedora-release ]]; then
            PLATFORM_FAMILY="fedora"
        else
            PLATFORM_FAMILY="rhel"
        fi
    elif [[ -f /etc/SuSE-release ]] || [[ -f /etc/SUSE-brand ]] || grep -qi suse /etc/os-release 2>/dev/null; then
        OS="rpm"
        OS_NAME="suse"
        RHEL="0"
        PLATFORM_FAMILY="suse"
    elif [[ -f /etc/system-release ]] && grep -qi "amazon" /etc/system-release 2>/dev/null; then
        OS="rpm"
        RHEL="$(rpm --eval %rhel 2>/dev/null || echo 0)"
        OS_NAME="amzn2023"
        PLATFORM_FAMILY="amazon"
    elif command -v rpm &>/dev/null && ! command -v dpkg &>/dev/null; then
        OS="rpm"
        RHEL="$(rpm --eval %rhel 2>/dev/null || echo 0)"
        OS_NAME="rpm"
        PLATFORM_FAMILY="rhel"
    else
        OS_NAME="$(lsb_release -sc 2>/dev/null || echo unknown)"
        OS="deb"
        PLATFORM_FAMILY="deb"
    fi

    log_info "Detected OS: ${OS} (${PLATFORM_FAMILY}/${OS_NAME}), arch: ${ARCH}"
}

# ===========================================================================
# install_deps
# ===========================================================================
install_deps() {
    if [[ "$INSTALL" -eq 0 ]]; then
        log_info "Dependencies will not be installed"
        return 0
    fi

    if [[ "$(id -u)" -ne 0 ]]; then
        die "Cannot install dependencies — please run as root"
    fi

    if [[ "$OS" == "rpm" ]]; then
        install_deps_rpm
    else
        install_deps_deb
    fi
}

install_deps_rpm() {
    local pkg_mgr="yum"
    if command -v dnf &>/dev/null; then
        pkg_mgr="dnf"
    fi

    if [[ "$PLATFORM_FAMILY" == "suse" ]]; then
        log_info "Installing SUSE build dependencies..."
        zypper refresh
        zypper install -y \
            rpm-build rpmdevtools gcc gcc-c++ make cmake git tar gzip
    else
        # EPEL for RHEL-family where needed
        case "$PLATFORM_FAMILY" in
            oracle)
                local epel_pkg="oracle-epel-release-el${RHEL}"
                if ! rpm -q "$epel_pkg" &>/dev/null; then
                    log_info "Installing EPEL for Oracle Linux: $epel_pkg"
                    $pkg_mgr install -y "$epel_pkg" \
                        || log_warn "EPEL installation failed (non-critical)"
                fi
                ;;
            rhel)
                if ! rpm -q epel-release &>/dev/null; then
                    log_info "Installing EPEL repository..."
                    $pkg_mgr install -y epel-release \
                        || log_warn "EPEL installation failed (non-critical)"
                fi
                ;;
            fedora|amazon)
                log_info "Skipping EPEL (not needed for $PLATFORM_FAMILY)"
                ;;
        esac

        log_info "Installing RPM build dependencies..."
        $pkg_mgr install -y \
            rpm-build rpmdevtools gcc gcc-c++ make cmake git tar gzip wget

        # Percona Valkey 9.1 experimental repo (provides valkeymodule.h)
        if ! rpm -q percona-release &>/dev/null; then
            log_info "Installing percona-release..."
            $pkg_mgr install -y \
                https://repo.percona.com/yum/percona-release-latest.noarch.rpm
        fi
        log_info "Enabling Percona Valkey 9.1 experimental repository..."
        percona-release enable valkey-91 experimental

        log_info "Installing Percona Valkey development headers..."
        $pkg_mgr install -y percona-valkey-devel

        $pkg_mgr clean all
    fi
}

install_deps_deb() {
    log_info "Installing DEB build dependencies..."
    apt-get update

    DEBIAN_FRONTEND=noninteractive apt-get -y install \
        build-essential debhelper devscripts dpkg-dev \
        fakeroot ca-certificates lsb-release \
        git wget curl tar gzip make gcc cmake gnupg

    # Percona Valkey 9.1 experimental repo (provides valkeymodule.h)
    if ! dpkg -l percona-release &>/dev/null; then
        log_info "Installing percona-release..."
        wget -O /tmp/percona-release.deb \
            https://repo.percona.com/apt/percona-release_latest.generic_all.deb
        DEBIAN_FRONTEND=noninteractive apt-get -y install /tmp/percona-release.deb
        rm -f /tmp/percona-release.deb
    fi
    log_info "Enabling Percona Valkey 9.1 experimental repository..."
    percona-release enable valkey-91 experimental
    apt-get update

    log_info "Installing Percona Valkey development headers..."
    DEBIAN_FRONTEND=noninteractive apt-get -y install percona-valkey-dev
}

# ===========================================================================
# get_sources
# ===========================================================================
get_sources() {
    if [[ "$SOURCE" -eq 0 ]]; then
        log_info "Sources will not be downloaded"
        return 0
    fi

    cd "$WORKDIR" || die "Cannot cd to $WORKDIR"

    local product_full="${PRODUCT}-${VERSION}"

    cat > ${PRODUCT}.properties <<EOF
PRODUCT=${PRODUCT}
PRODUCT_FULL=${product_full}
VERSION=${VERSION}
BUILD_NUMBER=${BUILD_NUMBER:-}
BUILD_ID=${BUILD_ID:-}
EOF

    log_info "Cloning $REPO ..."
    rm -rf "${product_full}"
    if ! git clone "$REPO" "$product_full"; then
        die "Failed to clone repo from $REPO. Please retry."
    fi

    cd "$product_full" || die "Cannot cd to $product_full"

    if [[ -n "$BRANCH" ]]; then
        git reset --hard
        git clean -xdf
        git checkout "$BRANCH"
    fi

    local revision
    revision="$(git rev-parse --short HEAD)"
    echo "REVISION=${revision}" >> "${WORKDIR}/${PRODUCT}.properties"

    # If version was not set via --version, extract from cloned source
    if [[ "$VERSION_FROM_CLI" -eq 0 ]]; then
        extract_version "$(pwd)"
        product_full="${PRODUCT}-${VERSION}"
        export PRODUCT_FULL="${PRODUCT}-${VERSION}-${RELEASE}"

        # Update properties file with real version
        cat > "${WORKDIR}/${PRODUCT}.properties" <<PROPS
PRODUCT=${PRODUCT}
PRODUCT_FULL=${product_full}
VERSION=${VERSION}
BUILD_NUMBER=${BUILD_NUMBER:-}
BUILD_ID=${BUILD_ID:-}
REVISION=${revision}
PROPS
    fi

    if [[ "$LOCAL_BUILD" -eq 0 ]]; then
        log_info "Using packaging scripts from cloned repo"
        # packaging/ is already in the source tree
    else
        log_info "Using local packaging scripts"
        rm -rf packaging
        cp -r "${BUILDER_SCRIPT_DIR}" ./packaging
    fi

    # For DEB builds, ensure debian/ directory is at source root
    if [[ "$OS" == "deb" ]]; then
        cp -a packaging/deb/debian ./debian
    fi

    cd "$WORKDIR" || die "Cannot cd to $WORKDIR"

    # Rename directory if version was extracted after clone
    if [[ "$(basename "$(find . -maxdepth 1 -type d -name "${PRODUCT}-*" | head -1)")" != "$product_full" ]]; then
        local old_dir
        old_dir="$(find . -maxdepth 1 -type d -name "${PRODUCT}-*" | head -1)"
        if [[ -n "$old_dir" && "$old_dir" != "./${product_full}" ]]; then
            mv "$old_dir" "$product_full"
        fi
    fi

    tar --owner=0 --group=0 --exclude=.git -czf "${product_full}.tar.gz" "$product_full"

    echo "UPLOAD=UPLOAD/experimental/BUILDS/${PRODUCT}/${product_full}/${BRANCH}/${revision}/${BUILD_ID:-}" >> ${PRODUCT}.properties

    copy_artifacts "source_tarball" "${product_full}.tar.gz"

    cd "$CURDIR" || die "Cannot cd to $CURDIR"
}

# ===========================================================================
# RPM functions
# ===========================================================================

build_srpm() {
    if [[ "$SRPM" -eq 0 ]]; then
        log_info "SRC RPM will not be created"
        return 0
    fi

    if [[ "$OS" == "deb" ]]; then
        die "Cannot build src rpm on a Debian-based system"
    fi

    cd "$WORKDIR" || die "Cannot cd to $WORKDIR"

    find_and_copy_artifact "source_tarball" "${PRODUCT}*.tar.gz"
    local tarfile="$FOUND_FILE"

    # Clean up everything except the tarball
    rm -fr rpmbuild
    mkdir -vp rpmbuild/{SOURCES,SPECS,BUILD,SRPMS,RPMS}

    # Extract rpm/ from the tarball
    tar vxzf "${WORKDIR}/${tarfile}" --wildcards '*/packaging/rpm' --strip=1

    cp -av packaging/rpm/* rpmbuild/SOURCES
    cp -av packaging/rpm/${PRODUCT}.spec rpmbuild/SPECS/

    mv -fv "$tarfile" "${WORKDIR}/rpmbuild/SOURCES"

    sed -i "s/^Version:.*$/Version:        ${VERSION}/" "${WORKDIR}/rpmbuild/SPECS/${PRODUCT}.spec"
    sed -i "s/^Release:.*$/Release:        ${RELEASE}%{?dist}/" "${WORKDIR}/rpmbuild/SPECS/${PRODUCT}.spec"

    rpmbuild -bs --define "_topdir ${WORKDIR}/rpmbuild" --define "dist .generic" \
        --define "version ${VERSION}" rpmbuild/SPECS/${PRODUCT}.spec

    copy_artifacts "srpm" rpmbuild/SRPMS/*.src.rpm

    cd "$CURDIR" || die "Cannot cd to $CURDIR"
}

build_rpm() {
    if [[ "$RPM" -eq 0 ]]; then
        log_info "RPM will not be created"
        return 0
    fi

    if [[ "$OS" == "deb" ]]; then
        die "Cannot build rpm on a Debian-based system"
    fi

    find_and_copy_artifact "srpm" "${PACKAGE_NAME}*.src.rpm"
    local src_rpm="$FOUND_FILE"

    cd "$WORKDIR" || die "Cannot cd to $WORKDIR"

    rm -fr rb
    mkdir -vp rb/{SOURCES,SPECS,BUILD,SRPMS,RPMS,BUILDROOT}
    cp "$src_rpm" rb/SRPMS/

    RHEL="$(rpm --eval %rhel)"
    ARCH="$(uname -m)"

    rpmbuild --define "_topdir ${WORKDIR}/rb" --define "dist .${OS_NAME}" \
        --define "version ${VERSION}" --rebuild "rb/SRPMS/${src_rpm}"

    copy_artifacts "rpm" rb/RPMS/*/*.rpm

    cd "$CURDIR" || die "Cannot cd to $CURDIR"
}

# ===========================================================================
# DEB functions
# ===========================================================================

build_source_deb() {
    if [[ "$SDEB" -eq 0 ]]; then
        log_info "Source deb package will not be created"
        return 0
    fi

    if [[ "$OS" == "rpm" ]]; then
        die "Cannot build source deb on an RPM-based system"
    fi

    cd "$WORKDIR" || die "Cannot cd to $WORKDIR"

    # Clean previous build artifacts but preserve properties and source_tarball/
    rm -rf "${PRODUCT}-"* "${PACKAGE_NAME}-"* "${PACKAGE_NAME}_"*
    rm -f ./*.dsc ./*.orig.tar.gz ./*.changes ./*.debian.tar.* ./*.diff.*

    find_and_copy_artifact "source_tarball" "${PRODUCT}*.tar.gz"
    local tarfile="$FOUND_FILE"

    local debian_codename
    debian_codename="$(lsb_release -sc 2>/dev/null || echo unstable)"
    ARCH="$(uname -m)"

    tar zxf "$tarfile"
    mv "${PRODUCT}-${VERSION}" "${PACKAGE_NAME}-${VERSION}"
    local builddir="${PACKAGE_NAME}-${VERSION}"

    # Repack orig tarball with the correct top-level directory name;
    # dpkg-source expects the orig tarball directory to match the source package name.
    tar czf "${PACKAGE_NAME}_${VERSION}.orig.tar.gz" "$builddir"
    rm -f "$tarfile"

    cd "$builddir" || die "Cannot cd to $builddir"

    # Ensure debian/ directory exists
    if [[ ! -d debian ]]; then
        cp -a packaging/deb/debian ./debian
    fi

    # Regenerate the debian changelog
    cd debian || die "Cannot cd to debian"
    rm -rf changelog
    {
        echo "${PACKAGE_NAME} (${VERSION}-${RELEASE}) unstable; urgency=low"
        echo ""
        echo "  * Initial Release."
        echo ""
        echo " -- Percona Build/Release Team <info@percona.com>  $(date -R)"
    } > changelog
    cd ..

    # -d: skip dpkg-checkbuilddeps for source-only builds; the binary builder
    # will satisfy Build-Depends from the .dsc later.
    dch -D unstable --force-distribution -v "${VERSION}-${RELEASE}" \
        "Update to new ${PACKAGE_NAME} version ${VERSION}"
    dpkg-buildpackage -S -d

    cd ..

    copy_artifacts "source_deb" ./*_source.changes
    copy_artifacts "source_deb" ./*.dsc
    copy_artifacts "source_deb" ./*.orig.tar.gz
    # 3.0 (quilt) produces .debian.tar.*, older formats produce .diff.*
    copy_artifacts "source_deb" ./*.debian.tar.* 2>/dev/null \
        || copy_artifacts "source_deb" ./*diff* 2>/dev/null \
        || true

    cd "$CURDIR" || die "Cannot cd to $CURDIR"
}

build_deb() {
    if [[ "$DEB" -eq 0 ]]; then
        log_info "Deb package will not be created"
        return 0
    fi

    if [[ "$OS" == "rpm" ]]; then
        die "Cannot build deb on an RPM-based system"
    fi

    for file in 'dsc' 'orig.tar.gz' 'changes'; do
        find_and_copy_artifact "source_deb" "${PACKAGE_NAME}*.${file}"
    done
    # 3.0 (quilt) produces .debian.tar.*, older formats produce .diff.*
    find_and_copy_artifact "source_deb" "${PACKAGE_NAME}*.debian.tar.*" \
        || find_and_copy_artifact "source_deb" "${PACKAGE_NAME}*diff*" \
        || true

    cd "$WORKDIR" || die "Cannot cd to $WORKDIR"
    rm -fv ./*.deb
    rm -rf "${PACKAGE_NAME}-${VERSION}"

    local debian_codename
    debian_codename="$(lsb_release -sc 2>/dev/null || echo unstable)"
    ARCH="$(uname -m)"

    echo "DEBIAN=${debian_codename}" >> ${PRODUCT}.properties
    echo "ARCH=${ARCH}" >> ${PRODUCT}.properties

    local dsc
    dsc="$(basename "$(find . -name '*.dsc' | sort | tail -n1)")"

    dpkg-source -x "$dsc"

    cd "${PACKAGE_NAME}-${VERSION}" || die "Cannot cd to ${PACKAGE_NAME}-${VERSION}"

    dch -m -D "$debian_codename" --force-distribution \
        -v "${VERSION}-${RELEASE}.${debian_codename}" 'Update distribution'

    # Clear locale variables to avoid dpkg-buildpackage warnings
    # shellcheck disable=SC2046
    unset $(locale | cut -d= -f1) 2>/dev/null || true

    dpkg-buildpackage -rfakeroot -us -uc -b

    cd "$WORKDIR" || die "Cannot cd to $WORKDIR"

    copy_artifacts "deb" "$WORKDIR"/*.*deb

    cd "$CURDIR" || die "Cannot cd to $CURDIR"
}

# ===========================================================================
# Main
# ===========================================================================
CURDIR="$(pwd)"
WORKDIR=""
SRPM=0
SDEB=0
RPM=0
DEB=0
SOURCE=0
OS_NAME=""
ARCH=""
OS=""
PLATFORM_FAMILY=""
RHEL="0"
INSTALL=0
BRANCH="$DEFAULT_BRANCH"
REPO="$DEFAULT_REPO"
VERSION=""
VERSION_FROM_CLI=0
RELEASE="$DEFAULT_RELEASE"
LOCAL_BUILD=0

parse_arguments "$@"

# Track whether version was explicitly set via CLI
if [[ -n "$VERSION" ]]; then
    VERSION_FROM_CLI=1
fi

# PRODUCT_FULL is set after parsing so --version can override; exported for child processes
export PRODUCT_FULL="${PRODUCT}-${VERSION}-${RELEASE}"

if [[ $# -eq 0 ]]; then
    usage
fi

check_workdir
get_system

# If VERSION was not set via --version, try to read from properties file, then fall back to DEFAULT_VERSION
if [[ -z "$VERSION" ]]; then
    if [[ -f "$WORKDIR/${PRODUCT}.properties" ]]; then
        VERSION="$(grep '^VERSION=' "$WORKDIR/${PRODUCT}.properties" | cut -d= -f2)"
        if [[ -n "$VERSION" ]]; then
            log_info "Read version from ${PRODUCT}.properties: ${VERSION}"
        fi
    fi
    if [[ -z "$VERSION" && -f "$CURDIR/${PRODUCT}.properties" ]]; then
        VERSION="$(grep '^VERSION=' "$CURDIR/${PRODUCT}.properties" | cut -d= -f2)"
        if [[ -n "$VERSION" ]]; then
            log_info "Read version from ${PRODUCT}.properties: ${VERSION}"
        fi
    fi
    if [[ -z "$VERSION" ]]; then
        VERSION="$DEFAULT_VERSION"
        log_info "Using default version: ${VERSION}"
    fi
    export PRODUCT_FULL="${PRODUCT}-${VERSION}-${RELEASE}"
fi

install_deps
get_sources
build_srpm
build_source_deb
build_rpm
build_deb
