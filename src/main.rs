#![allow(clippy::uninlined_format_args)]
#![allow(clippy::type_complexity)]

use dbus::{blocking::Connection, arg::{Variant, RefArg, PropMap}, Path, MethodErr};
use dbus_crossroads::{Crossroads, Context, IfaceToken, IfaceBuilder};
use std::{error::Error, collections::BTreeMap, sync::{atomic::AtomicU64, Mutex}, env::VarError};
use std::os::unix::fs::OpenOptionsExt;
use serde::{Serialize, Deserialize};

mod serde_base64 {
    use serde::{Serialize, Deserialize, Serializer, Deserializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        String::serialize(&base64::encode(v), s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let base64 = String::deserialize(d)?;
        base64::decode(base64.as_bytes()).map_err(serde::de::Error::custom)
    }
}

type Secret = (Path<'static>, Vec<u8>, Vec<u8>, String);

/// The global singleton storing all states of the application
#[derive(Serialize, Deserialize, Debug)]
struct Service {
    next_sess_id: AtomicU64,
    next_item_id: AtomicU64,
    items: BTreeMap<String, Item>
}

impl Service {
    // The Default trait is not const so we need this one
    const fn new() -> Self {
        Service { next_sess_id: AtomicU64::new(0), next_item_id: AtomicU64::new(0), items: BTreeMap::new() }
    }

    fn save(&self) -> Result<(), Box<dyn Error>> {
        let config_dir = get_config_directory()?;
        std::fs::create_dir_all(&config_dir)?;

        let config_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .mode(0o600)
            .open(format!("{config_dir}/secrets"))?;

        serde_json::to_writer(config_file, self)?;

        Ok(())
    }

    fn load(&mut self) -> Result<(), Box<dyn Error>> {
        let config_dir = get_config_directory()?;
        if let Ok(file) = std::fs::File::open(format!("{config_dir}/secrets")) {
            *self = serde_json::from_reader(file)?
        }
        Ok(())
    }
}

#[allow(non_upper_case_globals)]
static service_mutex: Mutex<Service> = Mutex::new(Service::new());

#[derive(Serialize, Deserialize, Debug, Default)]
struct Item {
    label: String,
    attributes: BTreeMap<String, String>,
    #[serde(with="serde_base64")]
    content: Vec<u8>,
    content_type: String,
    created: u64,
    modified: u64
}

#[derive(Debug, Clone)]
struct ItemHandle(String);

impl ItemHandle {
    fn with_item<T>(&self, cb: impl FnOnce(&Item) -> T) -> T {
        let service = service_mutex.lock().unwrap();
        let item = service.items.get(&self.0).unwrap();
        cb(item)
    }

    fn with_item_mut<T>(&self, cb: impl FnOnce(&mut Item) -> T) -> T {
        let mut service = service_mutex.lock().unwrap();
        let item = service.items.get_mut(&self.0).unwrap();
        let result = cb(item);
        service.save().unwrap();
        result
    }

    fn delete(
        ctx: &mut Context,
        cr: &mut Crossroads,
        (): ()
    ) -> Result<(Path<'static>, ), MethodErr> {
        cr.remove::<Self>(ctx.path()).unwrap();
        Ok((Path::new("/").unwrap(),))
    }

    fn get_secret(
        ctx: &mut Context,
        item_handle: &mut ItemHandle,
        (sess,): (Path<'static>,)
    ) -> Result<(Secret, ), MethodErr> {
        item_handle.with_item(|item| {
            Ok(((sess.clone(), vec![], item.content.clone(), item.content_type.clone()), ))
        })
    }

    fn set_secret(
        ctx: &mut Context,
        item_handle: &mut ItemHandle,
        (secret,): (Secret, )
    ) -> Result<(), MethodErr> {
        let (_, _, content, content_type) = secret;
        item_handle.with_item_mut(|item| {
            item.content = content;
            item.content_type = content_type;
            Ok(())
        })
    }

    fn register_dbus(cr: &mut Crossroads) -> IfaceToken<Self> {
        cr.register("org.freedesktop.Secret.Item", |iface_builder: &mut IfaceBuilder<ItemHandle>| {
            iface_builder.method_with_cr("Delete", (), ("Prompt", ), Self::delete);
            iface_builder.method("GetSecret", ("session", ), ("secret", ), Self::get_secret);


            iface_builder.property("Locked")
                .get(|_, _| Ok(false));

            iface_builder.property("Attributes")
                .get(|_, item_handle| item_handle.with_item(|item| Ok(item.attributes.clone())))
                .set(|_, item_handle, value| item_handle.with_item_mut(|item| {
                    item.attributes = value;
                    Ok(None)
                }));

            iface_builder.property("Label")
                .get(|_, item_handle| item_handle.with_item(|item| Ok(item.label.clone())))
                .set(|_, item_handle, value| item_handle.with_item_mut(|item| {
                    item.label = value;
                    Ok(None)
                }));

            iface_builder.property("Created")
                .get(|_, item_handle| item_handle.with_item(|item| Ok(item.created)));
            
            iface_builder.property("Modified")
                .get(|_, item_handle| item_handle.with_item(|item| Ok(item.modified)));
        })
    }
}

struct CollectionHandle;

impl CollectionHandle {
    fn create_item(
        _: &mut Context,
        _: &mut Crossroads,
        (properties, secret, replace): (PropMap, Secret, bool)
    ) -> Result<(Path<'static>, Path<'static>), MethodErr> {
        let label = properties.get("org.freedesktop.Secret.Item.Label")
            .and_then(|b| b.as_str().map(|x| x.to_string()))
            .unwrap_or_default();
        let attributes = properties.get("org.freedesktop.Secret.Item.Attributes")
            .and_then(|b| Some(
                dbus::arg::cast::<PropMap>(&b.0)?.into_iter()
                    .map(|(k, v)| (k.to_string(), v.as_str().unwrap().to_string()))
                    .collect::<BTreeMap<String, String>>()
            ))
            .unwrap_or_default();
        
        let now = get_unix_timestamp();
        let item = Item { label, attributes, created: now, modified: now, ..Default::default() };


        
    }


    fn register_dbus(cr: &mut Crossroads) -> IfaceToken<Self> {
        cr.register("org.freedesktop.Secret.Collection", |iface_builder| {
            // iface_builder.method()
        })
    }
}


struct ServiceHandle;

impl ServiceHandle {
    fn open_session(
        _: &mut Context,
        _: &mut Crossroads,
        (algorithm, input): (String, Variant<Box<dyn RefArg>>)
    ) -> Result<(Variant<&'static str>, Path<'static>), MethodErr> {
        let service = service_mutex.lock().unwrap();

        eprintln!("{}, {:?}", algorithm, input);
        if algorithm != "plain" {
            return Err(dbus::Error::new_custom("org.freedesktop.DBus.Error.NotSupported", "").into())
        }
        
        let session_id = service.next_sess_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let session_id_str = format!("/org/freedesktop/secrets/session/s{session_id}");
        // cr.insert(session_id_str.clone(), &[], Session::default());

        Ok((Variant(""), Path::new(session_id_str).unwrap()))
    }

    fn search_item(
        _: &mut Context,
        _: &mut ServiceHandle,
        (attributes,): (BTreeMap<String, String>,)
    ) -> Result<(Vec<Path<'static>>, Vec<Path<'static>>), MethodErr> {
        eprintln!("{:?}", attributes);
                    
        Ok((Vec::<Path>::new(), Vec::<Path>::new()))
    }

    fn register_dbus(cr: &mut Crossroads) -> IfaceToken<Self> {
        cr.register("org.freedesktop.Secret.Service", |iface_builder| {
            iface_builder.method_with_cr("OpenSession", ("algorithm", "input"), ("output", "result"), Self::open_session);
            iface_builder.method("SearchItems", ("attributes",), ("unlocked", "locked"), Self::search_item);
        })
    }
}

fn get_config_directory() -> Result<String, VarError> {
    let xdg_config_dir = std::env::var("XDG_CONFIG_HOME").map(|x| format!("{x}/dssd"));
    let home_config_dir = std::env::var("HOME").map(|x| format!("{x}/.config/dssd"));
    xdg_config_dir.or(home_config_dir)
}

fn get_unix_timestamp() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

fn main() -> Result<(), Box<dyn Error>> {
    let c = Connection::new_session()?;
    c.request_name("org.freedesktop.secrets", false, true, false)?;

    let mut cr = Crossroads::new();

    let service_iface_token = ServiceHandle::register_dbus(&mut cr);
    cr.insert("/org/freedesktop/secrets", &[service_iface_token], ServiceHandle);

    cr.serve(&c)?;
    unreachable!()
}