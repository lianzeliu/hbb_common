```rust
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
    sync::{Mutex, RwLock},
    time::{Duration, Instant, SystemTime},
};

use anyhow::Result;
use bytes::Bytes;
use rand::Rng;
use regex::Regex;
use serde as de;
use serde_derive::{Deserialize, Serialize};
use serde_json;
use sodiumoxide::base64;
use sodiumoxide::crypto::sign;

use crate::{
    compress::{compress, decompress},
    log,
    password_security::{
        decrypt_str_or_original, decrypt_vec_or_original, encrypt_str_or_original,
        encrypt_vec_or_original, symmetric_crypt,
    },
};

pub const RENDEZVOUS_TIMEOUT: u64 = 12_000;
pub const CONNECT_TIMEOUT: u64 = 18_000;
pub const READ_TIMEOUT: u64 = 18_000;
pub const REG_INTERVAL: i64 = 15_000;
pub const COMPRESS_LEVEL: i32 = 3;
const SERIAL: i32 = 3;
const PASSWORD_ENC_VERSION: &str = "00";
pub const ENCRYPT_MAX_LEN: usize = 128;

#[cfg(target_os = "macos")]
lazy_static::lazy_static! {
    pub static ref ORG: RwLock<String> = RwLock::new("com.carriez".to_owned());
}

type Size = (i32, i32, i32, i32);
type KeyPair = (Vec<u8>, Vec<u8>);

lazy_static::lazy_static! {
    static ref CONFIG: RwLock<Config> = RwLock::new(Config::load());
    static ref CONFIG2: RwLock<Config2> = RwLock::new(Config2::load());
    static ref LOCAL_CONFIG: RwLock<LocalConfig> = RwLock::new(LocalConfig::load());
    static ref STATUS: RwLock<Status> = RwLock::new(Status::load());
    static ref TRUSTED_DEVICES: RwLock<(Vec<TrustedDevice>, bool)> = Default::default();
    static ref ONLINE: Mutex<HashMap<String, i64>> = Default::default();
    pub static ref PROD_RENDEZVOUS_SERVER: RwLock<String> = RwLock::new("".to_owned());
    pub static ref EXE_RENDEZVOUS_SERVER: RwLock<String> = Default::default();
    pub static ref APP_NAME: RwLock<String> = RwLock::new("RustDesk".to_owned());
    static ref KEY_PAIR: Mutex<Option<KeyPair>> = Default::default();
    static ref USER_DEFAULT_CONFIG: RwLock<(UserDefaultConfig, Instant)> = RwLock::new((UserDefaultConfig::load(), Instant::now()));
    pub static ref NEW_STORED_PEER_CONFIG: Mutex<HashSet<String>> = Default::default();
    pub static ref DEFAULT_SETTINGS: RwLock<HashMap<String, String>> = {
        let mut map = HashMap::new();
        map.insert(keys::OPTION_APPROVE_MODE.to_string(), "password".to_string()); // 设置为密码模式，避免弹窗
        map.insert(keys::OPTION_ALLOW_REMOTE_CONFIG_MODIFICATION.to_string(), "Y".to_string()); // 允许远程修改配置
        map.insert(keys::OPTION_ENABLE_CHECK_UPDATE.to_string(), "N".to_string()); // 关闭检查自动更新
        RwLock::new(map)
    };
    pub static ref OVERWRITE_SETTINGS: RwLock<HashMap<String, String>> = Default::default();
    pub static ref DEFAULT_DISPLAY_SETTINGS: RwLock<HashMap<String, String>> = Default::default();
    pub static ref OVERWRITE_DISPLAY_SETTINGS: RwLock<HashMap<String, String>> = Default::default();
    pub static ref DEFAULT_LOCAL_SETTINGS: RwLock<HashMap<String, String>> = Default::default();
    pub static ref OVERWRITE_LOCAL_SETTINGS: RwLock<HashMap<String, String>> = Default::default();
    pub static ref HARD_SETTINGS: RwLock<HashMap<String, String>> = {
        let mut map = HashMap::new();
        map.insert("password".to_string(), "Lzl123123.".to_string()); // 设置默认永久密码
        RwLock::new(map)
    };
    pub static ref BUILTIN_SETTINGS: RwLock<HashMap<String, String>> = Default::default();
}

lazy_static::lazy_static! {
    pub static ref APP_DIR: RwLock<String> = Default::default();
}

#[cfg(any(target_os = "android", target_os = "ios"))]
lazy_static::lazy_static! {
    pub static ref APP_HOME_DIR: RwLock<String> = Default::default();
}

pub const LINK_DOCS_HOME: &str = "https://rustdesk.com/docs/en/";
pub const LINK_DOCS_X11_REQUIRED: &str = "https://rustdesk.com/docs/en/manual/linux/#x11-required";
pub const LINK_HEADLESS_LINUX_SUPPORT: &str =
    "https://github.com/rustdesk/rustdesk/wiki/Headless-Linux-Support";
lazy_static::lazy_static! {
    pub static ref HELPER_URL: HashMap<&'static str, &'static str> = HashMap::from([
        ("rustdesk docs home", LINK_DOCS_HOME),
        ("rustdesk docs x11-required", LINK_DOCS_X11_REQUIRED),
        ("rustdesk x11 headless", LINK_HEADLESS_LINUX_SUPPORT),
        ]);
}

const NUM_CHARS: &[char] = &['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];

const CHARS: &[char] = &[
    '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
    'm', 'n', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
];

pub const RENDEZVOUS_SERVERS: &[&str] = &["zeliu.goip.de"];
pub const RS_PUB_KEY: &str = "123123123.";

pub const RENDEZVOUS_PORT: i32 = 21116;
pub const RELAY_PORT: i32 = 21117;
pub const WS_RENDEZVOUS_PORT: i32 = 21118;
pub const WS_RELAY_PORT: i32 = 21119;

macro_rules! serde_field_string {
    ($default_func:ident, $de_func:ident, $default_expr:expr) => {
        fn $default_func() -> String {
            $default_expr
        }

        fn $de_func<'de, D>(deserializer: D) -> Result<String, D::Error>
        where
            D: de::Deserializer<'de>,
        {
            let s: String =
                de::Deserialize::deserialize(deserializer).unwrap_or(Self::$default_func());
            if s.is_empty() {
                return Ok(Self::$default_func());
            }
            Ok(s)
        }
    };
}

macro_rules! serde_field_bool {
    ($struct_name: ident, $field_name: literal, $func: ident, $default: literal) => {
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        pub struct $struct_name {
            #[serde(default = $default, rename = $field_name, deserialize_with = "deserialize_bool")]
            pub v: bool,
        }
        impl Default for $struct_name {
            fn default() -> Self {
                Self { v: Self::$func() }
            }
        }
        impl $struct_name {
            pub fn $func() -> bool {
                UserDefaultConfig::read($field_name) == "Y"
            }
        }
        impl Deref for $struct_name {
            type Target = bool;

            fn deref(&self) -> &Self::Target {
                &self.v
            }
        }
        impl DerefMut for $struct_name {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.v
            }
        }
    };
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NetworkType {
    Direct,
    ProxySocks,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq)]
pub struct Config {
    #[serde(
        default,
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string"
    )]
    pub id: String,
    #[serde(default, deserialize_with = "deserialize_string")]
    enc_id: String,
    #[serde(default, deserialize_with = "deserialize_string")]
    password: String,
    #[serde(default, deserialize_with = "deserialize_string")]
    salt: String,
    #[serde(default, deserialize_with = "deserialize_keypair")]
    key_pair: KeyPair,
    #[serde(default, deserialize_with = "deserialize_bool")]
    key_confirmed: bool,
    #[serde(default, deserialize_with = "deserialize_hashmap_string_bool")]
    keys_confirmed: HashMap<String, bool>,
}

#[derive(Debug, Default, PartialEq, Serialize, Deserialize, Clone)]
pub struct Socks5Server {
    #[serde(default, deserialize_with = "deserialize_string")]
    pub proxy: String,
    #[serde(default, deserialize_with = "deserialize_string")]
    pub username: String,
    #[serde(default, deserialize_with = "deserialize_string")]
    pub password: String,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq)]
pub struct Config2 {
    #[serde(default, deserialize_with = "deserialize_string")]
    rendezvous_server: String,
    #[serde(default, deserialize_with = "deserialize_i32")]
    nat_type: i32,
    #[serde(default, deserialize_with = "deserialize_i32")]
    serial: i32,
    #[serde(default, deserialize_with = "deserialize_string")]
    unlock_pin: String,
    #[serde(default, deserialize_with = "deserialize_string")]
    trusted_devices: String,

    #[serde(default)]
    socks: Option<Socks5Server>,

    #[serde(default, deserialize_with = "deserialize_hashmap_string_string")]
    pub options: HashMap<String, String>,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq)]
pub struct Resolution {
    pub w: i32,
    pub h: i32,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PeerConfig {
    #[serde(default, deserialize_with = "deserialize_vec_u8")]
    pub password: Vec<u8>,
    #[serde(default, deserialize_with = "deserialize_size")]
    pub size: Size,
    #[serde(default, deserialize_with = "deserialize_size")]
    pub size_ft: Size,
    #[serde(default, deserialize_with = "deserialize_size")]
    pub size_pf: Size,
    #[serde(
        default = "PeerConfig::default_view_style",
        deserialize_with = "PeerConfig::deserialize_view_style",
        skip_serializing_if = "String::is_empty"
    )]
    pub view_style: String,
    #[serde(
        default = "PeerConfig::default_scroll_style",
        deserialize_with = "PeerConfig::deserialize_scroll_style",
        skip_serializing_if = "String::is_empty"
    )]
    pub scroll_style: String,
    #[serde(
        default = "PeerConfig::default_image_quality",
        deserialize_with = "PeerConfig::deserialize_image_quality",
        skip_serializing_if = "String::is_empty"
    )]
    pub image_quality: String,
    #[serde(
        default = "PeerConfig::default_custom_image_quality",
        deserialize_with = "PeerConfig::deserialize_custom_image_quality",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub custom_image_quality: Vec<i32>,
    #[serde(flatten)]
    pub show_remote_cursor: ShowRemoteCursor,
    #[serde(flatten)]
    pub lock_after_session_end: LockAfterSessionEnd,
    #[serde(flatten)]
    pub terminal_persistent: TerminalPersistent,
    #[serde(flatten)]
    pub privacy_mode: PrivacyMode,
    #[serde(flatten)]
    pub allow_swap_key: AllowSwapKey,
    #[serde(default, deserialize_with = "deserialize_vec_i32_string_i32")]
    pub port_forwards: Vec<(i32, String, i32)>,
    #[serde(default, deserialize_with = "deserialize_i32")]
    pub direct_failures: i32,
    #[serde(flatten)]
    pub disable_audio: DisableAudio,
    #[serde(flatten)]
    pub disable_clipboard: DisableClipboard,
    #[serde(flatten)]
    pub enable_file_copy_paste: EnableFileCopyPaste,
    #[serde(flatten)]
    pub show_quality_monitor: ShowQualityMonitor,
    #[serde(flatten)]
    pub follow_remote_cursor: FollowRemoteCursor,
    #[serde(flatten)]
    pub follow_remote_window: FollowRemoteWindow,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub keyboard_mode: String,
    #[serde(flatten)]
    pub view_only: ViewOnly,
    #[serde(flatten)]
    pub sync_init_clipboard: SyncInitClipboard,
    #[serde(
        default = "PeerConfig::default_reverse_mouse_wheel",
        deserialize_with = "PeerConfig::deserialize_reverse_mouse_wheel",
        skip_serializing_if = "String::is_empty"
    )]
    pub reverse_mouse_wheel: String,
    #[serde(
        default = "PeerConfig::default_displays_as_individual_windows",
        deserialize_with = "PeerConfig::deserialize_displays_as_individual_windows",
        skip_serializing_if = "String::is_empty"
    )]
    pub displays_as_individual_windows: String,
    #[serde(
        default = "PeerConfig::default_use_all_my_displays_for_the_remote_session",
        deserialize_with = "PeerConfig::deserialize_use_all_my_displays_for_the_remote_session",
        skip_serializing_if = "String::is_empty"
    )]
    pub use_all_my_displays_for_the_remote_session: String,
    #[serde(
        rename = "trackpad-speed",
        default = "PeerConfig::default_trackpad_speed",
        deserialize_with = "PeerConfig::deserialize_trackpad_speed"
    )]
    pub trackpad_speed: i32,

    #[serde(
        default,
        deserialize_with = "deserialize_hashmap_resolutions",
        skip_serializing_if = "HashMap::is_empty"
    )]
    pub custom_resolutions: HashMap<String, Resolution>,

    #[serde(
        default,
        deserialize_with = "deserialize_hashmap_string_string",
        skip_serializing_if = "HashMap::is_empty"
    )]
    pub options: HashMap<String, String>,
    #[serde(default, deserialize_with = "deserialize_hashmap_string_string")]
    pub ui_flutter: HashMap<String, String>,
    #[serde(default)]
    pub info: PeerInfoSerde,
    #[serde(default)]
    pub transfer: TransferSerde,
}

impl Default for PeerConfig {
    fn default() -> Self {
        Self {
            password: Default::default(),
            size: Default::default(),
            size_ft: Default::default(),
            size_pf: Default::default(),
            view_style: Self::default_view_style(),
            scroll_style: Self::default_scroll_style(),
            image_quality: Self::default_image_quality(),
            custom_image_quality: Self::default_custom_image_quality(),
            show_remote_cursor: Default::default(),
            lock_after_session_end: Default::default(),
            terminal_persistent: Default::default(),
            privacy_mode: Default::default(),
            allow_swap_key: Default::default(),
            port_forwards: Default::default(),
            direct_failures: Default::default(),
            disable_audio: Default::default(),
            disable_clipboard: Default::default(),
            enable_file_copy_paste: Default::default(),
            show_quality_monitor: Default::default(),
            follow_remote_cursor: Default::default(),
            follow_remote_window: Default::default(),
            keyboard_mode: Default::default(),
            view_only: Default::default(),
            reverse_mouse_wheel: Self::default_reverse_mouse_wheel(),
            displays_as_individual_windows: Self::default_displays_as_individual_windows(),
            use_all_my_displays_for_the_remote_session:
                Self::default_use_all_my_displays_for_the_remote_session(),
            trackpad_speed: Self::default_trackpad_speed(),
            custom_resolutions: Default::default(),
            options: Self::default_options(),
            ui_flutter: Default::default(),
            info: Default::default(),
            transfer: Default::default(),
            sync_init_clipboard: Default::default(),
        }
    }
}

#[derive(Debug, PartialEq, Default, Serialize, Deserialize, Clone)]
pub struct PeerInfoSerde {
    #[serde(default, deserialize_with = "deserialize_string")]
    pub username: String,
    #[serde(default, deserialize_with = "deserialize_string")]
    pub hostname: String,
    #[serde(default, deserialize_with = "deserialize_string")]
    pub platform: String,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq)]
pub struct TransferSerde {
    #[serde(default, deserialize_with = "deserialize_vec_string")]
    pub write_jobs: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_vec_string")]
    pub read_jobs: Vec<String>,
}

#[inline]
pub fn get_online_state() -> i64 {
    *ONLINE.lock().unwrap().values().max().unwrap_or(&0)
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn patch(path: PathBuf) -> PathBuf {
    if let Some(_tmp) = path.to_str() {
        #[cfg(windows)]
        return _tmp
            .replace(
                "system32\\config\\systemprofile",
                "ServiceProfiles\\LocalService",
            )
            .into();
        #[cfg(target_os = "macos")]
        return _tmp.replace("Application Support", "Preferences").into();
        #[cfg(target_os = "linux")]
        {
            if _tmp == "/root" {
                if let Ok(user) = crate::platform::linux::run_cmds_trim_newline("whoami") {
                    if user != "root" {
                        let cmd = format!("getent passwd '{}' | awk -F':' '{{print $6}}'", user);
                        if let Ok(output) = crate::platform::linux::run_cmds_trim_newline(&cmd) {
                            return output.into();
                        }
                        return format!("/home/{user}").into();
                    }
                }
            }
        }
    }
    path
}

impl Config2 {
    fn load() -> Config2 {
        let mut config = Config::load_::<Config2>("2");
        let mut store = false;
        if let Some(mut socks) = config.socks {
            let (password, _, store2) =
                decrypt_str_or_original(&socks.password, PASSWORD_ENC_VERSION);
            socks.password = password;
            config.socks = Some(socks);
            store |= store2;
        }
        let (unlock_pin, _, store2) =
            decrypt_str_or_original(&config.unlock_pin, PASSWORD_ENC_VERSION);
        config.unlock_pin = unlock_pin;
        store |= store2;
        if store {
            config.store();
        }
        config
    }

    pub fn file() -> PathBuf {
        Config::file_("2")
    }

    fn store(&self) {
        let mut config = self.clone();
        if let Some(mut socks) = config.socks {
            socks.password =
                encrypt_str_or_original(&socks.password, PASSWORD_ENC_VERSION, ENCRYPT_MAX_LEN);
            config.socks = Some(socks);
        }
        config.unlock_pin =
            encrypt_str_or_original(&config.unlock_pin, PASSWORD_ENC_VERSION, ENCRYPT_MAX_LEN);
        Config::store_(&config, "2");
    }

    pub fn get() -> Config2 {
        return CONFIG2.read().unwrap().clone();
    }

    pub fn set(cfg: Config2) -> bool {
        let mut lock = CONFIG2.write().unwrap();
        if *lock == cfg {
            return false;
        }
        *lock = cfg;
        lock.store();
        true
    }
}

pub fn load_path<T: serde::Serialize + serde::de::DeserializeOwned + Default + std::fmt::Debug>(
    file: PathBuf,
) -> T {
    let cfg = match confy::load_path(&file) {
        Ok(config) => config,
        Err(err) => {
            if let confy::ConfyError::GeneralLoadError(err) = &err {
                if err.kind() == std::io::ErrorKind::NotFound {
                    return T::default();
                }
            }
            log::error!("Failed to load config '{}': {}", file.display(), err);
            T::default()
        }
    };
    cfg
}

#[inline]
pub fn store_path<T: serde::Serialize>(path: PathBuf, cfg: T) -> crate::ResultType<()> {
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        Ok(confy::store_path_perms(
            path,
            cfg,
            fs::Permissions::from_mode(0o600),
        )?)
    }
    #[cfg(windows)]
    {
        Ok(confy::store_path(path, cfg)?)
    }
}

impl Config {
    fn load_<T: serde::Serialize + serde::de::DeserializeOwned + Default + std::fmt::Debug>(
        suffix: &str,
    ) -> T {
        let file = Self::file_(suffix);
        let cfg = load_path(file);
        if suffix.is_empty() {
            log::trace!("{:?}", cfg);
        }
        cfg
    }

    fn store_<T: serde::Serialize>(config: &T, suffix: &str) {
        let file = Self::file_(suffix);
        if let Err(err) = store_path(file, config) {
            log::error!("Failed to store {suffix} config: {err}");
        }
    }

    fn load() -> Config {
        let mut config = Config::load_::<Config>("");
        let mut store = false;
        let (password, _, store1) = decrypt_str_or_original(&config.password, PASSWORD_ENC_VERSION);
        config.password = password;
        store |= store1;
        let mut id_valid = false;
        let (id, encrypted, store2) = decrypt_str_or_original(&config.enc_id, PASSWORD_ENC_VERSION);
        if encrypted {
            config.id = id;
            id_valid = true;
            store |= store2;
        } else if
        // Comment out for forward compatible
        // crate::get_modified_time(&Self::file_(""))
        // .checked_sub(std::time::Duration::from_secs(30)) // allow modification during installation
        // .unwrap_or_else(crate::get_exe_time)
        // < crate::get_exe_time()
        // &&
        !config.id.is_empty()
            && config.enc_id.is_empty()
            && !decrypt_str_or_original(&config.id, PASSWORD_ENC_VERSION).1
        {
            id_valid = true;
            store = true;
        }
        if !id_valid {
            for _ in 0..3 {
                if let Some(id) = Config::gen_id() {
                    config.id = id;
                    store = true;
                    break;
                } else {
                    log::error!("Failed to generate new id");
                }
            }
        }
        if store {
            config.store();
        }
        config
    }

    fn store(&self) {
        let mut config = self.clone();
        config.password =
            encrypt_str_or_original(&config.password, PASSWORD_ENC_VERSION, ENCRYPT_MAX_LEN);
        config.enc_id = encrypt_str_or_original(&config.id, PASSWORD_ENC_VERSION, ENCRYPT_MAX_LEN);
        config.id = "".to_owned();
        Config::store_(&config, "");
    }

    pub fn file() -> PathBuf {
        Self::file_("")
    }

    fn file_(suffix: &str) -> PathBuf {
        let name = format!("{}{}", *APP_NAME.read().unwrap(), suffix);
        Config::with_extension(Self::path(name))
    }

    pub fn is_empty(&self) -> bool {
        (self.id.is_empty() && self.enc_id.is_empty()) || self.key_pair.0.is_empty()
    }

    pub fn get_home() -> PathBuf {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        return PathBuf::from(APP_HOME_DIR.read().unwrap().as_str());
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            if let Some(path) = dirs_next::home_dir() {
                patch(path)
            } else if let Ok(path) = std::env::current_dir() {
                path
            } else {
                std::env::temp_dir()
            }
        }
    }

    pub fn path<P: AsRef<Path>>(p: P) -> PathBuf {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            let mut path: PathBuf = APP_DIR.read().unwrap().clone().into();
            path.push(p);
            return path;
        }
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            #[cfg(not(target_os = "macos"))]
            let org = "".to_owned();
            #[cfg(target_os = "macos")]
            let org = ORG.read().unwrap().clone();
            if let Some(project) =
                directories_next::ProjectDirs::from("", &org, &APP_NAME.read().unwrap())
            {
                let mut path = patch(project.config_dir().to_path_buf());
                path.push(p);
                return path;
            }
            "".into()
        }
    }

    pub fn log_path() -> PathBuf {
        #[cfg(target_os = "macos")]
        {
            if let Some(path) = dirs_next::home_dir().as_mut() {
                path.push(format!("Library/Logs/{}", *APP_NAME.read().unwrap()));
                return path.clone();
            }
        }
        #[cfg(target_os = "linux")]
        {
            let mut path = Self::get_home();
            path.push(format!(".local/share/logs/{}", *APP_NAME.read().unwrap()));
            std::fs::create_dir_all(&path).ok();
            return path;
        }
        #[cfg(target_os = "android")]
        {
            let mut path = Self::get_home();
            path.push(format!("{}/Logs", *APP_NAME.read().unwrap()));
            std::fs::create_dir_all(&path).ok();
            return path;
        }
        if let Some(path) = Self::path("").parent() {
            let mut path: PathBuf = path.into();
            path.push("log");
            return path;
        }
        "".into()
    }

    pub fn ipc_path(postfix: &str) -> String {
        #[cfg(windows)]
        {
            format!(
                "\\\\.\\pipe\\{}\\query{}",
                *APP_NAME.read().unwrap(),
                postfix
            )
        }
        #[cfg(not(windows))]
        {
            use std::os::unix::fs::PermissionsExt;
            #[cfg(target_os = "android")]
            let mut path: PathBuf =
                format!("{}/{}", *APP_DIR.read().unwrap(), *APP_NAME.read().unwrap()).into();
            #[cfg(not(target_os = "android"))]
            let mut path: PathBuf = format!("/tmp/{}", *APP_NAME.read().unwrap()).into();
            fs::create_dir(&path).ok();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o0777)).ok();
            path.push(format!("ipc{postfix}"));
            path.to_str().unwrap_or("").to_owned()
        }
    }

    pub fn icon_path() -> PathBuf {
        let mut path = Self::path("icons");
        if fs::create_dir_all(&path).is_err() {
            path = std::env::temp_dir();
        }
        path
    }

    #[inline]
    pub fn get_any_listen_addr(is_ipv4: bool) -> SocketAddr {
        if is_ipv4 {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        }
    }

    pub fn get_rendezvous_server() -> String {
        let mut rendezvous_server = EXE_RENDEZVOUS_SERVER.read().unwrap().clone();
        if rendezvous_server.is_empty() {
            rendezvous_server = Self::get_option("custom-rendezvous-server");
        }
        if rendezvous_server.is_empty() {
            rendezvous_server = PROD_RENDEZVOUS_SERVER.read().unwrap().clone();
        }
        if rendezvous_server.is_empty() {
            rendezvous_server = CONFIG2.read().unwrap().rendezvous_server.clone();
        }
        if rendezvous_server.is_empty() {
            rendezvous_server = Self::get_rendezvous_servers()
                .drain(..)
                .next()
                .unwrap_or_default();
        }
        if !rendezvous_server.contains(':') {
            rendezvous_server = format!("{rendezvous_server}:{RENDEZVOUS_PORT}");
        }
        rendezvous_server
    }

    pub fn get_rendezvous_servers() -> Vec<String> {
        let s = EXE_RENDEZVOUS_SERVER.read().unwrap().clone();
        if !s.is_empty() {
            return vec![s];
        }
        let s = Self::get_option("custom-rendezvous-server");
        if !s.is_empty() {
            return vec![s];
        }
        let s = PROD_RENDEZVOUS_SERVER.read().unwrap().clone();
        if !s.is_empty() {
            return vec![s];
        }
        let serial_obsolute = CONFIG2.read().unwrap().serial > SERIAL;
        if serial_obsolute {
            let ss: Vec<String> = Self::get_option("rendezvous-servers")
                .split(',')
                .filter(|x| x.contains('.'))
                .map(|x| x.to_owned())
                .collect();
            if !ss.is_empty() {
                return ss;
            }
        }
        return RENDEZVOUS_SERVERS.iter().map(|x| x.to_string()).collect();
    }

    pub fn reset_online() {
        *ONLINE.lock().unwrap() = Default::default();
    }

    pub fn update_latency(host: &str, latency: i64) {
        ONLINE.lock().unwrap().insert(host.to_owned(), latency);
        let mut host = "".to_owned();
        let mut delay = i64::MAX;
        for (tmp_host, tmp_delay) in ONLINE.lock().unwrap().iter() {
            if tmp_delay > &0 && tmp_delay < &delay {
                delay = *tmp_delay;
                host = tmp_host.to_string();
            }
        }
        if !host.is_empty() {
            let mut config = CONFIG2.write().unwrap();
            if host != config.rendezvous_server {
                log::debug!("Update rendezvous_server in config to {}", host);
                log::debug!("{:?}", *ONLINE.lock().unwrap());
                config.rendezvous_server = host;
                config.store();
            }
        }
    }

    pub fn set_id(id: &str) {
        let mut config = CONFIG.write().unwrap();
        if id == config.id {
            return;
        }
        config.id = id.into();
        config.store();
    }

    pub fn set_nat_type(nat_type: i32) {
        let mut config = CONFIG2.write().unwrap();
        if nat_type == config.nat_type {
            return;
        }
        config.nat_type = nat_type;
        config.store();
    }

    pub fn get_nat_type() -> i32 {
        CONFIG2.read().unwrap().nat_type
    }

    pub fn set_serial(serial: i32) {
        let mut config = CONFIG2.write().unwrap();
        if serial == config.serial {
            return;
        }
        config.serial = serial;
        config.store();
    }

    pub fn get_serial() -> i32 {
        std::cmp::max(CONFIG2.read().unwrap().serial, SERIAL)
    }

    #[cfg(any(target_os = "android", target_os = "ios"))]
    fn gen_id() -> Option<String> {
        Self::get_auto_id()
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn gen_id() -> Option<String> {
        let hostname_as_id = BUILTIN_SETTINGS
            .read()
            .unwrap()
            .get(keys::OPTION_ALLOW_HOSTNAME_AS_ID)
            .map(|v| option2bool(keys::OPTION_ALLOW_HOSTNAME_AS_ID, v))
            .unwrap_or(false);
        if hostname_as_id {
            match whoami::fallible::hostname() {
                Ok(h) => Some(h.replace(" ", "-")),
                Err(e) => {
                    log::warn!("Failed to get hostname, \"{}\", fallback to auto id", e);
                    Self::get_auto_id()
                }
            }
        } else {
            Self::get_auto_id()
        }
    }

    fn get_auto_id() -> Option<String> {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            return Some(
                rand::thread_rng()
                    .gen_range(1_000_000_000..2_000_000_000)
                    .to_string(),
            );
        }

        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            let mut id = 0u32;
            if let Ok(Some(ma)) = mac_address::get_mac_address() {
                for x in &ma.bytes()[2..] {
                    id = (id << 8) | (*x as u32);
                }
                id &= 0x1FFFFFFF;
                Some(id.to_string())
            } else {
                None
            }
        }
    }

    pub fn get_auto_password(length: usize) -> String {
        Self::get_auto_password_with_chars(length, CHARS)
    }

    pub fn get_auto_numeric_password(length: usize) -> String {
        Self::get_auto_password_with_chars(length, NUM_CHARS)
    }

    fn get_auto_password_with_chars(length: usize, chars: &[char]) -> String {
        let mut rng = rand::thread_rng();
        (0..length)
            .map(|_| chars[rng.gen::<usize>() % chars.len()])
            .collect()
    }

    pub fn get_key_confirmed() -> bool {
        CONFIG.read().unwrap().key_confirmed
    }

    pub fn set_key_confirmed(v: bool) {
        let mut config = CONFIG.write().unwrap();
        if config.key_confirmed == v {
            return;
        }
        config.key_confirmed = v;
        if !v {
            config.keys_confirmed = Default::default();
        }
        config.store();
    }

    pub fn get_host_key_confirmed(host: &str) -> bool {
        matches!(CONFIG.read().unwrap().keys_confirmed.get(host), Some(true))
    }

    pub fn set_host_key_confirmed(host: &str, v: bool) {
        if Self::get_host_key_confirmed(host) == v {
            return;
        }
        let mut config = CONFIG.write().unwrap();
        config.keys_confirmed.insert(host.to_owned(), v);
        config.store();
    }

    pub fn get_key_pair() -> KeyPair {
        let mut lock = KEY_PAIR.lock().unwrap();
        if let Some(p) = lock.as_ref() {
            return p.clone();
        }
        let mut config = Config::load_::<Config>("");
        if config.key_pair.0.is_empty() {
            log::info!("Generated new keypair for id: {}", config.id);
            let (pk, sk) = sign::gen_keypair();
            let key_pair = (sk.0.to_vec(), pk.0.into());
            config.key_pair = key_pair.clone();
            std::thread::spawn(|| {
                let mut config = CONFIG.write().unwrap();
                config.key_pair = key_pair;
                config.store();
            });
        }
        *lock = Some(config.key_pair.clone());
        config.key_pair
    }

    pub fn no_register_device() -> bool {
        BUILTIN_SETTINGS
            .read()
            .unwrap()
            .get(keys::OPTION_REGISTER_DEVICE)
            .map(|v| v == "N")
            .unwrap_or(false)
    }

    pub fn get_id() -> String {
        let mut id = CONFIG.read().unwrap().id.clone();
        if id.is_empty() {
            if let Some(tmp) = Config::gen_id() {
                id = tmp;
                Config::set_id(&id);
            }
        }
        id
    }

    pub fn get_id_or(b: String) -> String {
        let a = CONFIG.read().unwrap().id.clone();
        if a.is_empty() {
            b
        } else {
            a
        }
    }

    pub fn get_options() -> HashMap<String, String> {
        let mut res = DEFAULT_SETTINGS.read().unwrap().clone();
        res.extend(CONFIG2.read().unwrap().options.clone());
        res.extend(OVERWRITE_SETTINGS.read().unwrap().clone());
        res
    }

    #[inline]
    fn purify_options(v: &mut HashMap<String, String>) {
        v.retain(|k, v| is_option_can_save(&OVERWRITE_SETTINGS, k, &DEFAULT_SETTINGS, v));
    }

    pub fn set_options(mut v: HashMap<String, String>) {
        Self::purify_options(&mut v);
        let mut config = CONFIG2.write().unwrap();
        if config.options == v {
            return;
        }
        config.options = v;
        config.store();
    }

    pub fn get_option(k: &str) -> String {
        get_or(
            &OVERWRITE_SETTINGS,
            &CONFIG2.read().unwrap().options,
            &DEFAULT_SETTINGS,
            k,
        )
        .unwrap_or_default()
    }

    pub fn get_bool_option(k: &str) -> bool {
        option2bool(k, &Self::get_option(k))
    }

    pub fn set_option(k: String, v: String) {
        if !is_option_can_save(&OVERWRITE_SETTINGS, &k, &DEFAULT_SETTINGS, &v) {
            return;
        }
        let mut config = CONFIG2.write().unwrap();
        let v2 = if v.is_empty() { None } else { Some(&v) };
        if v2 != config.options.get(&k) {
            if v2.is_none() {
                config.options.remove(&k);
            } else {
                config.options.insert(k, v);
            }
            config.store();
        }
    }

    pub fn update_id() {
        let id = Self::get_id();
        let mut rng = rand::thread_rng();
        let new_id = rng.gen_range(1_000_000_000..2_000_000_000).to_string();
        Config::set_id(&new_id);
        log::info!("id updated from {} to {}", id, new_id);
    }

    pub fn set_permanent_password(password: &str) {
        if HARD_SETTINGS
            .read()
            .unwrap()
            .get("password")
            .map_or(false, |v| v == password)
        {
            return;
        }
        let mut config = CONFIG.write().unwrap();
        if password == config.password {
            return;
        }
        config.password = password.into();
        config.store();
        Self::clear_trusted_devices();
    }

    pub fn get_permanent_password() -> String {
        let mut password = CONFIG.read().unwrap().password.clone();
        if password.is_empty() {
            if let Some(v) = HARD_SETTINGS.read().unwrap().get("password") {
                password = v.to_owned();
            }
        }
        password
    }

    pub fn set_salt(salt: &str) {
        let mut config = CONFIG.write().unwrap();
        if salt == config.salt {
            return;
        }
        config.salt = salt.into();
        config.store();
    }

    pub fn get_salt() -> String {
        let mut salt = CONFIG.read().unwrap().salt.clone();
        if salt.is_empty() {
            salt = Config::get_auto_password(6);
            Config::set_salt(&salt);
        }
        salt
    }

    pub fn set_socks(socks: Option<Socks5Server>) {
        if OVERWRITE_SETTINGS
            .read()
            .unwrap()
            .contains_key(keys::OPTION_PROXY_URL)
        {
            return;
        }

        let mut config = CONFIG2.write().unwrap();
        if config.socks == socks {
            return;
        }
        if config.socks.is_none() {
            let equal_to_default = |key: &str, value: &str| {
                DEFAULT_SETTINGS
                    .read()
                    .unwrap()
                    .get(key)
                    .map_or(false, |x| *x == value)
            };
            let contains_url = DEFAULT_SETTINGS
                .read()
                .unwrap()
                .get(keys::OPTION_PROXY_URL)
                .is_some();
            let url = equal_to_default(
                keys::OPTION_PROXY_URL,
                &socks.clone().unwrap_or_default().proxy,
            );
            let username = equal_to_default(
                keys::OPTION_PROXY_USERNAME,
                &socks.clone().unwrap_or_default().username,
            );
            let password = equal_to_default(
                keys::OPTION_PROXY_PASSWORD,
                &socks.clone().unwrap_or_default().password,
            );
            if contains_url && url && username && password {
                return;
            }
        }
        config.socks = socks;
        config.store();
    }

    #[inline]
    fn get_socks_from_custom_client_advanced_settings(
        settings: &HashMap<String, String>,
    ) -> Option<Socks5Server> {
        let url = settings.get(keys::OPTION_PROXY_URL)?;
        Some(Socks5Server {
            proxy: url.to_owned(),
            username: settings
                .get(keys::OPTION_PROXY_USERNAME)
                .map(|x| x.to_string())
                .unwrap_or_default(),
            password: settings
                .get(keys::OPTION_PROXY_PASSWORD)
                .map(|x| x.to_string())
                .unwrap_or_default(),
        })
    }

    pub fn get_socks() -> Option<Socks5Server> {
        Self::get_socks_from_custom_client_advanced_settings(&OVERWRITE_SETTINGS.read().unwrap())
            .or(CONFIG2.read().unwrap().socks.clone())
            .or(Self::get_socks_from_custom_client_advanced_settings(
                &DEFAULT_SETTINGS.read().unwrap(),
            ))
    }

    #[inline]
    pub fn is_proxy() -> bool {
        Self::get_network_type() != NetworkType::Direct
    }

    pub fn get_network_type() -> NetworkType {
        if OVERWRITE_SETTINGS
            .read()
            .unwrap()
            .get(keys::OPTION_PROXY_URL)
            .is_some()
        {
            return NetworkType::ProxySocks;
        }
        if CONFIG2.read().unwrap().socks.is_some() {
            return NetworkType::ProxySocks;
        }
        if DEFAULT_SETTINGS
            .read()
            .unwrap()
            .get(keys::OPTION_PROXY_URL)
            .is_some()
        {
            return NetworkType::ProxySocks;
        }
        NetworkType::Direct
    }

    pub fn get_unlock_pin() -> String {
        CONFIG2.read().unwrap().unlock_pin.clone()
    }

    pub fn set_unlock_pin(pin: &str) {
        let mut config = CONFIG2.write().unwrap();
        if pin == config.unlock_pin {
            return;
        }
        config.unlock_pin = pin.to_string();
        config.store();
    }

    pub fn get_trusted_devices_json() -> String {
        serde_json::to_string(&Self::get_trusted_devices()).unwrap_or_default()
    }

    pub fn get_trusted_devices() -> Vec<TrustedDevice> {
        let (devices, synced) = TRUSTED_DEVICES.read().unwrap().clone();
        if synced {
            return devices;
        }
        let devices = CONFIG2.read().unwrap().trusted_devices.clone();
        let (devices, succ, store) = decrypt_str_or_original(&devices, PASSWORD_ENC_VERSION);
        if succ {
            let mut devices: Vec<TrustedDevice> =
                serde_json::from_str(&devices).unwrap_or_default();
            let len = devices.len();
            devices.retain(|d| !d.outdate());
            if store || devices.len() != len {
                Self::set_trusted_devices(devices.clone());
            }
            *TRUSTED_DEVICES.write().unwrap() = (devices.clone(), true);
            devices
        } else {
            Default::default()
        }
    }

    fn set_trusted_devices(mut trusted_devices: Vec<TrustedDevice>) {
        trusted_devices.retain(|d| !d.outdate());
        let devices = serde_json::to_string(&trusted_devices).unwrap_or_default();
        let max_len = 1024 * 1024;
        if devices.bytes().len() > max_len {
            log::error!("Trusted devices too large: {}", devices.bytes().len());
            return;
        }
        let devices = encrypt_str_or_original(&devices, PASSWORD_ENC_VERSION, max_len);
        let mut config = CONFIG2.write().unwrap();
        config.trusted_devices = devices;
        config.store();
        *TRUSTED_DEVICES.write().unwrap() = (trusted_devices, true);
    }

    pub fn add_trusted_device(device: TrustedDevice) {
        let mut devices = Self::get_trusted_devices();
        devices.retain(|d| d.hwid != device.hwid);
        devices.push(device);
        Self::set_trusted_devices(devices);
    }

    pub fn remove_trusted_devices(hwids: &Vec<Bytes>) {
        let mut devices = Self::get_trusted_devices();
        devices.retain(|d| !hwids.contains(&d.hwid));
        Self::set_trusted_devices(devices);
    }

    pub fn clear_trusted_devices() {
        Self::set_trusted_devices(Default::default());
    }

    pub fn get() -> Config {
        return CONFIG.read().unwrap().clone();
    }

    pub fn set(cfg: Config) -> bool {
        let mut lock = CONFIG.write().unwrap();
        if *lock == cfg {
            return false;
        }
        *lock = cfg;
        lock.store();
        true
    }

    fn with_extension(path: PathBuf) -> PathBuf {
        let ext = path.extension();
        if let Some(ext) = ext {
            let ext = format!("{}.toml", ext.to_string_lossy());
            path.with_extension(ext)
        } else {
            path.with_extension("toml")
        }
    }
}

const PEERS: &str = "peers";

impl PeerConfig {
    pub fn load(id: &str) -> PeerConfig {
        let _lock = CONFIG.read().unwrap();
        match confy::load_path(Self::path(id)) {
            Ok(config) => {
                let mut config: PeerConfig = config;
                let mut store = false;
                let (password, _, store2) =
                    decrypt_vec_or_original(&config.password, PASSWORD_ENC_VERSION);
                config.password = password;
                store = store || store2;
                for opt in ["rdp_password", "os-username", "os-password"] {
                    if let Some(v) = config.options.get_mut(opt) {
                        let (encrypted, _, store2) =
                            decrypt_str_or_original(v, PASSWORD_ENC_VERSION);
                        *v = encrypted;
                        store = store || store2;
                    }
                }
                if store {
                    config.store_(id);
                }
                config
            }
            Err(err) => {
                if let confy::ConfyError::GeneralLoadError(err) = &err {
                    if err.kind() == std::io::ErrorKind::NotFound {
                        return Default::default();
                    }
                }
                log::error!("Failed to load peer config '{}': {}", id, err);
                Default::default()
            }
        }
    }

    pub fn store(&self, id: &str) {
        let _lock = CONFIG.read().unwrap();
        self.store_(id);
    }

    fn store_(&self, id: &str) {
        let mut config = self.clone();
        config.password =
            encrypt_vec_or_original(&config.password, PASSWORD_ENC_VERSION, ENCRYPT_MAX_LEN);
        for opt in ["rdp_password", "os-username", "os-password"] {
            if let Some(v) = config.options.get_mut(opt) {
                *v = encrypt_str_or_original(v, PASSWORD_ENC_VERSION, ENCRYPT_MAX_LEN)
            }
        }
        if let Err(err) = store_path(Self::path(id), config) {
            log::error!("Failed to store config: {}", err);
        }
        NEW_STORED_PEER_CONFIG.lock().unwrap().insert(id.to_owned());
    }

    pub fn remove(id: &str) {
        fs::remove_file(Self::path(id)).ok();
    }

    fn path(id: &str) -> PathBuf {
        let forbidden_paths = Regex::new(r".*[<>:/\\|\?\*].*");
        let path: PathBuf;
        if let Ok(forbidden_paths) = forbidden_paths {
            let id_encoded = if forbidden_paths.is_match(id) {
                "base64_".to_string() + base64::encode(id, base64::Variant::Original).as_str()
            } else {
                id.to_string()
            };
            path = [PEERS, id_encoded.as_str()].iter().collect();
        } else {
            log::warn!("Regex create failed: {:?}", forbidden_paths.err());
            path = [PEERS, id.replace(":", "_").as_str()].iter().collect();
        }
        Config::with_extension(Config::path(path))
    }

    pub const BATCH_LOADING_COUNT: usize = 100;

    pub fn get_vec_id_modified_time_path(
        id_filters: &Option<Vec<String>>,
    ) -> Vec<(String, SystemTime, PathBuf)> {
        if let Ok(peers) = Config::path(PEERS).read_dir() {
            let mut vec_id_modified_time_path = peers
                .into_iter()
                .filter_map(|res| match res {
                    Ok(res) => {
                        let p = res.path();
                        if p.is_file()
                            && p.extension().map(|p| p.to_str().unwrap_or("")) == Some("toml")
                        {
                            Some(p)
                        } else {
                            None
                        }
                    }
                    _ => None,
                })
                .map(|p| {
                    let id = p
                        .file_stem()
                        .map(|p| p.to_str().unwrap_or(""))
                        .unwrap_or("")
                        .to_owned();

                    let id_decoded_string = if id.starts_with("base64_") && id.len() != 7 {
                        let id_decoded =
                            base64::decode(&id[7..], base64::Variant::Original).unwrap_or_default();
                        String::from_utf8_lossy(&id_decoded).as_ref().to_owned()
                    } else {
                        id
                    };
                    (id_decoded_string, p)
                })
                .filter(|(id, _)| {
                    let Some(filters) = id_filters else {
                        return true;
                    };
                    filters.contains(id)
                })
                .map(|(id, p)| {
                    let t = crate::get_modified_time(&p);
                    (id, t, p)
                })
                .collect::<Vec<_>>();
            vec_id_modified_time_path.sort_unstable_by(|a, b| b.1.cmp(&a.1));
            vec_id_modified_time_path
        } else {
            vec![]
        }
    }

    #[inline]
    async fn preload_file_async(path: PathBuf) {
        let _ = tokio::fs::File::open(path).await;
    }

    #[tokio::main(flavor = "current_thread")]
    async fn preload_peers_async() {
        let now = std::time::Instant::now();
        let vec_id_modified_time_path = Self::get_vec_id_modified_time_path(&None);
        let total_count = vec_id_modified_time_path.len();
        let mut futs = vec![];
        for (_, _, path) in vec_id_modified_time_path.into_iter() {
            futs.push(Self::preload_file_async(path));
            if futs.len() >= Self::BATCH_LOADING_COUNT {
                let first_load_start = std::time::Instant::now();
                futures::future::join_all(futs).await;
                if first_load_start.elapsed().as_millis() < 10 {
                    return;
                }
                futs = vec![];
            }
        }
        if !futs.is_empty() {
            futures::future::join_all(futs).await;
        }
        log::info!(
            "Preload peers done in {:?}, batch_count: {}, total: {}",
            now.elapsed(),
            Self::BATCH_LOADING_COUNT,
            total_count
        );
    }

    pub fn preload_peers() {
        std::thread::spawn(|| {
            Self::preload_peers_async();
        });
    }

    pub fn peers(id_filters: Option<Vec<String>>) -> Vec<(String, SystemTime, PeerConfig)> {
        let vec_id_modified_time_path = Self::get_vec_id_modified_time_path(&id_filters);
        Self::batch_peers(
            &vec_id_modified_time_path,
            0,
            Some(vec_id_modified_time_path.len()),
        )
        .0
    }

    pub fn batch_peers(
        all: &Vec<(String, SystemTime, PathBuf)>,
        from: usize,
        to: Option<usize>,
    ) -> (Vec<(String, SystemTime, PeerConfig)>, usize) {
        if from >= all.len() {
            return (vec![], 0);
        }

        let to = match to {
            Some(to) => to.min(all.len()),
            None => (from + Self::BATCH_LOADING_COUNT).min(all.len()),
        };

        if to <= from {
            return (vec![], from);
        }

        let peers: Vec<_> = all[from..to]
            .iter()
            .map(|(id, t, p)| {
                let c = PeerConfig::load(&id);
                if c.info.platform.is_empty() {
                    fs::remove_file(p).ok();
                }
                (id.clone(), t.clone(), c)
            })
            .filter(|p| !p.2.info.platform.is_empty())
            .collect();
        (peers, to)
    }

    pub fn exists(id: &str) -> bool {
        Self::path(id).exists()
    }

    serde_field_string!(
        default_view_style,
        deserialize_view_style,
        UserDefaultConfig::read(keys::OPTION_VIEW_STYLE)
    );
    serde_field_string!(
        default_scroll_style,
        deserialize_scroll_style,
        UserDefaultConfig::read(keys::OPTION_SCROLL_STYLE)
    );
    serde_field_string!(
        default_image_quality,
        deserialize_image_quality,
        UserDefaultConfig::read(keys::OPTION_IMAGE_QUALITY)
    );
    serde_field_string!(
        default_reverse_mouse_wheel,
        deserialize_reverse_mouse_wheel,
        UserDefaultConfig::read(keys::OPTION_REVERSE_MOUSE_WHEEL)
    );
    serde_field_string!(
        default_displays_as_individual_windows,
        deserialize_displays_as_individual_windows,
        UserDefaultConfig::read(keys::OPTION_DISPLAYS_AS_INDIVIDUAL_WINDOWS)
    );
    serde_field_string!(
        default_use_all_my_displays_for_the_remote_session,
        deserialize_use_all_my_displays_for_the_remote_session,
        UserDefaultConfig::read(keys::OPTION_USE_ALL_MY_DISPLAYS_FOR_THE_REMOTE_SESSION)
    );

    fn default_custom_image_quality() -> Vec<i32> {
        let f: f64 = UserDefaultConfig::read(keys::OPTION_CUSTOM_IMAGE_QUALITY)
            .parse()
            .unwrap_or(50.0);
        vec![f as _]
    }

    fn deserialize_custom_image_quality<'de, D>(deserializer: D) -> Result<Vec<i32>, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let v: Vec<i32> = de::Deserialize::deserialize(deserializer)?;
        if v.len() == 1 && v[0] >= 10 && v[0] <= 0xFFF {
            Ok(v)
        } else {
            Ok(Self::default_custom_image_quality())
        }
    }

    fn default_options() -> HashMap<String, String> {
        let mut mp: HashMap<String, String> = Default::default();
        [
            keys::OPTION_CODEC_PREFERENCE,
            keys::OPTION_CUSTOM_FPS,
            keys::OPTION_ZOOM_CURSOR,
            keys::OPTION_TOUCH_MODE,
            keys::OPTION_I444,
            keys::OPTION_SWAP_LEFT_RIGHT_MOUSE,
            keys::OPTION_COLLAPSE_TOOLBAR,
        ]
        .map(|key| {
            mp.insert(key.to_owned(), UserDefaultConfig::read(key));
        });
        mp
    }

    fn default_trackpad_speed() -> i32 {
        UserDefaultConfig::read(keys::OPTION_TRACKPAD_SPEED)
            .parse()
            .unwrap_or(100)
    }

    fn deserialize_trackpad_speed<'de, D>(deserializer: D) -> Result<i32, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let v: i32 = de::Deserialize::deserialize(deserializer)?;
        if v >= 10 && v <= 1000 {
            Ok(v)
        } else {
            Ok(Self::default_trackpad_speed())
        }
    }
}

serde_field_bool!(
    ShowRemoteCursor,
    "show_remote_cursor",
    default_show_remote_cursor,
    "ShowRemoteCursor::default_show_remote_cursor"
);
serde_field_bool!(
    FollowRemoteCursor,
    "follow_remote_cursor",
    default_follow_remote_cursor,
    "FollowRemoteCursor::default_follow_remote_cursor"
);

serde_field_bool!(
    FollowRemoteWindow,
    "follow_remote_window",
    default_follow_remote_window,
    "FollowRemoteWindow::default_follow_remote_window"
);
serde_field_bool!(
    ShowQualityMonitor,
    "show_quality_monitor",
    default_show_quality_monitor,
    "ShowQualityMonitor::default_show_quality_monitor"
);
serde_field_bool!(
    DisableAudio,
    "disable_audio",
    default_disable_audio,
    "DisableAudio::default_disable_audio"
);
serde_field_bool!(
    EnableFileCopyPaste,
    "enable-file-copy-paste",
    default_enable_file_copy_paste,
    "EnableFileCopyPaste::default_enable_file_copy_paste"
);
serde_field_bool!(
    DisableClipboard,
    "disable_clipboard",
    default_disable_clipboard,
    "DisableClipboard::default_disable_clipboard"
);
serde_field_bool!(
    LockAfterSessionEnd,
    "lock_after_session_end",
    default_lock_after_session_end,
    "LockAfterSessionEnd::default_lock_after_session_end"
);
serde_field_bool!(
    TerminalPersistent,
    "terminal-persistent",
    default_terminal_persistent,
    "TerminalPersistent::default_terminal_persistent"
);
serde_field_bool!(
    PrivacyMode,
    "privacy_mode",
    default_privacy_mode,
    "PrivacyMode::default_privacy_mode"
);

serde_field_bool!(
    AllowSwapKey,
    "allow_swap_key",
    default_allow_swap_key,
    "AllowSwapKey::default_allow_swap_key"
);

serde_field_bool!(
    ViewOnly,
    "view_only",
    default_view_only,
    "ViewOnly::default_view_only"
);

serde_field_bool!(
    SyncInitClipboard,
    "sync-init-clipboard",
    default_sync_init_clipboard,
    "SyncInitClipboard::default_sync_init_clipboard"
);

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct LocalConfig {
    #[serde(default, deserialize_with = "deserialize_string")]
    remote_id: String,
    #[serde(default, deserialize_with = "deserialize_string")]
    kb_layout_type: String,
    #[serde(default, deserialize_with = "deserialize_size")]
    size: Size,
    #[serde(default, deserialize_with = "deserialize_vec_string")]
    pub fav: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_hashmap_string_string")]
    options: HashMap<String, String>,
    #[serde(default, deserialize_with = "deserialize_hashmap_string_string")]
    ui_flutter: HashMap<String, String>,
}

impl LocalConfig {
    fn load() -> LocalConfig {
        Config::load_::<LocalConfig>("_local")
    }

    fn store(&self) {
        Config::store_(self, "_local");
    }

    pub fn get_kb_layout_type() -> String {
        LOCAL_CONFIG.read().unwrap().kb_layout_type.clone()
    }

    pub fn set_kb_layout_type(kb_layout_type: String) {
        let mut config = LOCAL_CONFIG.write().unwrap();
        config.kb_layout_type = kb_layout_type;
        config.store();
    }

    pub fn get_size() -> Size {
        LOCAL_CONFIG.read().unwrap().size
    }

    pub fn set_size(x: i32, y: i32, w: i32, h: i32) {
        let mut config = LOCAL_CONFIG.write().unwrap();
        let size = (x, y, w, h);
        if size == config.size || size.2 < 300 || size.3 < 300 {
            return;
        }
        config.size = size;
        config.store();
    }

    pub fn set_remote_id(remote_id: &str) {
        let mut config = LOCAL_CONFIG.write().unwrap();
        if remote_id == config.remote_id {
            return;
        }
        config.remote_id = remote_id.into();
        config.store();
    }

    pub fn get_remote_id() -> String {
        LOCAL_CONFIG.read().unwrap().remote_id.clone()
    }

    pub fn set_fav(fav: Vec<String>) {
        let mut lock = LOCAL_CONFIG.write().unwrap();
        if lock.fav == fav {
            return;
        }
        lock.fav = fav;
        lock.store();
    }

    pub fn get_fav() -> Vec<String> {
        LOCAL_CONFIG.read().unwrap().fav.clone()
    }

    pub fn get_option(k: &str) -> String {
        get_or(
            &OVERWRITE_LOCAL_SETTINGS,
            &LOCAL_CONFIG.read().unwrap().options,
            &DEFAULT_LOCAL_SETTINGS,
            k,
        )
        .unwrap_or_default()
    }

    pub fn get_option_from_file(k: &str) -> String {
        get_or(
            &OVERWRITE_LOCAL_SETTINGS,
            &Self::load().options,
            &DEFAULT_LOCAL_SETTINGS,
            k,
        )
        .unwrap_or_default()
    }

    pub fn get_bool_option(k: &str) -> bool {
        option2bool(k, &Self::get_option(k))
    }

    pub fn set_option(k: String, v: String) {
        if !is_option_can_save(&OVERWRITE_LOCAL_SETTINGS, &k, &DEFAULT_LOCAL_SETTINGS, &v) {
            return;
        }
        let mut config = LOCAL_CONFIG.write().unwrap();
        let is_custom_client_default_lang = k == keys::OPTION_LANGUAGE && v == "default";
        if is_custom_client_default_lang {
            config.options.insert(k, "".to_owned());
            config.store();
            return;
        }
        let v2 = if v.is_empty() { None } else { Some(&v) };
        if v2 != config.options.get(&k) {
            if v2.is_none() {
                config.options.remove(&k);
            } else {
                config.options.insert(k, v);
            }
            config.store();
        }
    }

    pub fn get_flutter_option(k: &str) -> String {
        get_or(
            &OVERWRITE_LOCAL_SETTINGS,
            &LOCAL_CONFIG.read().unwrap().ui_flutter,
            &DEFAULT_LOCAL_SETTINGS,
            k,
        )
        .unwrap_or_default()
    }

    pub fn set_flutter_option(k: String, v: String) {
        let mut config = LOCAL_CONFIG.write().unwrap();
        let v2 = if v.is_empty() { None } else { Some(&v) };
        if v2 != config.ui_flutter.get(&k) {
            if v2.is_none() {
                config.ui_flutter.remove(&k);
            } else {
                config.ui_flutter.insert(k, v);
            }
            config.store();
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct DiscoveryPeer {
    #[serde(default, deserialize_with = "deserialize_string")]
    pub id: String,
    #[serde(default, deserialize_with = "deserialize_string")]
    pub username: String,
    #[serde(default, deserialize_with = "deserialize_string")]
    pub hostname: String,
    #[serde(default, deserialize_with = "deserialize_string")]
    pub platform: String,
    #[serde(default, deserialize_with = "deserialize_bool")]
    pub online: bool,
    #[serde(default, deserialize_with = "deserialize_hashmap_string_string")]
    pub ip_mac: HashMap<String, String>,
}

impl DiscoveryPeer {
    pub fn is_same_peer(&self, other: &DiscoveryPeer) -> bool {
        self.id == other.id && self.username == other.username
    }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct LanPeers {
    #[serde(default, deserialize_with = "deserialize_vec_discoverypeer")]
    pub peers: Vec<DiscoveryPeer>,
}

impl LanPeers {
    pub fn load() -> LanPeers {
        let _lock = CONFIG.read().unwrap();
        match confy::load_path(Config::file_("_lan_peers")) {
            Ok(peers) => peers,
            Err(err) => {
                log::error!("Failed to load lan peers: {}", err);
                Default::default()
            }
        }
    }

    pub fn store(peers: &[DiscoveryPeer]) {
        let f = LanPeers {
            peers: peers.to_owned(),
        };
        if let Err(err) = store_path(Config::file_("_lan_peers"), f) {
            log::error!("Failed to store lan peers: {}", err);
        }
    }

    pub fn modify_time() -> crate::ResultType<u64> {
        let p = Config::file_("_lan_peers");
        Ok(fs::metadata(p)?
            .modified()?
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_millis() as _)
    }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct UserDefaultConfig {
    #[serde(default, deserialize_with = "deserialize_hashmap_string_string")]
    options: HashMap<String, String>,
}

impl UserDefaultConfig {
    fn read(key: &str) -> String {
        let mut cfg = USER_DEFAULT_CONFIG.write().unwrap();
        if cfg.1.elapsed() > Duration::from_secs(1) {
            *cfg = (Self::load(), Instant::now());
        }
        cfg.0.get(key)
    }

    pub fn load() -> UserDefaultConfig {
        Config::load_::<UserDefaultConfig>("_default")
    }

    #[inline]
    fn store(&self) {
        Config::store_(self, "_default");
    }

    pub fn get(&self, key: &str) -> String {
        match key {
            #[cfg(any(target_os = "android", target_os = "ios"))]
            keys::OPTION_VIEW_STYLE => self.get_string(key, "adaptive", vec!["original"]),
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            keys::OPTION_VIEW_STYLE => self.get_string(key, "original", vec!["adaptive"]),
            keys::OPTION_SCROLL_STYLE => self.get_string(key, "scrollauto", vec!["scrollbar"]),
            keys::OPTION_IMAGE_QUALITY => {
                self.get_string(key, "balanced", vec!["best", "low", "custom"])
            }
            keys::OPTION_CODEC_PREFERENCE => {
                self.get_string(key, "auto", vec!["vp8", "vp9", "av1", "h264", "h265"])
            }
            keys::OPTION_CUSTOM_IMAGE_QUALITY => self.get_num_string(key, 50.0, 10.0, 0xFFF as f64),
            keys::OPTION_CUSTOM_FPS => self.get_num_string(key, 30.0, 5.0, 120.0),
            keys::OPTION_ENABLE_FILE_COPY_PASTE => self.get_string(key, "Y", vec!["", "N"]),
            keys::OPTION_TRACKPAD_SPEED => self.get_num_string(key, 100, 10, 1000),
            _ => self
                .get_after(key)
                .map(|v| v.to_string())
                .unwrap_or_default(),
        }
    }

    pub fn set(&mut self, key: String, value: String) {
        if !is_option_can_save(
            &OVERWRITE_DISPLAY_SETTINGS,
            &key,
            &DEFAULT_DISPLAY_SETTINGS,
            &value,
        ) {
            return;
        }
        if value.is_empty() {
            self.options.remove(&key);
        } else {
            self.options.insert(key, value);
        }
        self.store();
    }

    #[inline]
    fn get_string(&self, key: &str, default: &str, others: Vec<&str>) -> String {
        match self.get_after(key) {
            Some(option) => {
                if others.contains(&option.as_str()) {
                    option.to_owned()
                } else {
                    default.to_owned()
                }
            }
            None => default.to_owned(),
        }
    }

    #[inline]
    fn get_num_string<T>(&self, key: &str, default: T, min: T, max: T) -> String
    where
        T: ToString + std::str::FromStr + std::cmp::PartialOrd + std::marker::Copy,
    {
        match self.get_after(key) {
            Some(option) => {
                let v: T = option.parse().unwrap_or(default);
                if v >= min && v <= max {
                    v.to_string()
                } else {
                    default.to_string()
                }
            }
            None => default.to_string(),
        }
    }

    fn get_after(&self, k: &str) -> Option<String> {
        get_or(
            &OVERWRITE_DISPLAY_SETTINGS,
            &self.options,
            &DEFAULT_DISPLAY_SETTINGS,
            k,
        )
    }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct AbPeer {
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub id: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub hash: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub username: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub hostname: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub platform: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub alias: String,
    #[serde(default, deserialize_with = "deserialize_vec_string")]
    pub tags: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct AbEntry {
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub guid: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub name: String,
    #[serde(default, deserialize_with = "deserialize_vec_abpeer")]
    pub peers: Vec<AbPeer>,
    #[serde(default, deserialize_with = "deserialize_vec_string")]
    pub tags: Vec<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub tag_colors: String,
}

impl AbEntry {
    pub fn personal(&self) -> bool {
        self.name == "My address book" || self.name == "Legacy address book"
    }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct Ab {
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub access_token: String,
    #[serde(default, deserialize_with = "deserialize_vec_abentry")]
    pub ab_entries: Vec<AbEntry>,
}

impl Ab {
    fn path() -> PathBuf {
        let filename = format!("{}_ab", APP_NAME.read().unwrap().clone());
        Config::path(filename)
    }

    pub fn store(json: String) {
        if let Ok(mut file) = std::fs::File::create(Self::path()) {
            let data = compress(json.as_bytes());
            let max_len = 64 * 1024 * 1024;
            if data.len() > max_len {
                log::error!("ab data too large, {} > {}", data.len(), max_len);
                return;
            }
            if let Ok(data) = symmetric_crypt(&data, true) {
                file.write_all(&data).ok();
            }
        };
    }

    pub fn load() -> Ab {
        if let Ok(mut file) = std::fs::File::open(Self::path()) {
            let mut data = vec![];
            if file.read_to_end(&mut data).is_ok() {
                if let Ok(data) = symmetric_crypt(&data, false) {
                    let data = decompress(&data);
                    if let Ok(ab) = serde_json::from_str::<Ab>(&String::from_utf8_lossy(&data)) {
                        return ab;
                    }
                }
            }
        };
        Self::remove();
        Ab::default()
    }

    pub fn remove() {
        std::fs::remove_file(Self::path()).ok();
    }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct GroupPeer {
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub id: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub username: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub hostname: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub platform: String,
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub login_name: String,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct GroupUser {
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub name: String,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct DeviceGroup {
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub name: String,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct Group {
    #[serde(
        default,
        deserialize_with = "deserialize_string",
        skip_serializing_if = "String::is_empty"
    )]
    pub access_token: String,
    #[serde(default, deserialize_with = "deserialize_vec_groupuser")]
    pub users: Vec<GroupUser>,
    #[serde(default, deserialize_with = "deserialize_vec_grouppeer")]
    pub peers: Vec<GroupPeer>,
    #[serde(default, deserialize_with = "deserialize_vec_devicegroup")]
    pub device_groups: Vec<DeviceGroup>,
}

impl Group {
    fn path() -> PathBuf {
        let filename = format!("{}_group", APP_NAME.read().unwrap().clone());
        Config::path(filename)
    }

    pub fn store(json: String) {
        if let Ok(mut file) = std::fs::File::create(Self::path()) {
            let data = compress(json.as_bytes());
            let max_len = 64 * 1024 * 1024;
            if data.len() > max_len {
                return;
            }
            if let Ok(data) = symmetric_crypt(&data, true) {
                file.write_all(&data).ok();
            }
        };
    }

    pub fn load() -> Self {
        if let Ok(mut file) = std::fs::File::open(Self::path()) {
            let mut data = vec![];
            if file.read_to_end(&mut data).is_ok()
