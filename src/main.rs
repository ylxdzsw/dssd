#![allow(clippy::uninlined_format_args)]
#![allow(clippy::type_complexity)]
#![allow(non_upper_case_globals)]
#![feature(let_chains)]

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
    next_item_id: u64,
    items: BTreeMap<u64, Item>
}

impl Service {
    // The Default trait is not const so we need this one
    const fn new() -> Self {
        Service { next_item_id: 0, items: BTreeMap::new() }
    }

    fn save(&self) -> Result<(), Box<dyn Error>> {
        let config_dir = get_config_directory()?;
        eprintln!("save to {config_dir}");
        std::fs::create_dir_all(&config_dir)?;

        let config_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .mode(0o600)
            .open(format!("{config_dir}/secrets"))?;

        serde_json::to_writer(config_file, self)?;

        Ok(())
    }

    fn load(&mut self, cr: &mut Crossroads) -> Result<(), Box<dyn Error>> {
        let config_dir = get_config_directory()?;
        if let Ok(file) = std::fs::File::open(format!("{config_dir}/secrets")) {
            *self = serde_json::from_reader(file)?
        }

        for &item_id in self.items.keys() {
            let item_id_str = Item::id_to_string(item_id);
            cr.insert(item_id_str, &[item_iface_token_mutex.lock().unwrap().unwrap()], ItemHandle(item_id));
        }

        Ok(())
    }

    fn find_by_attributes(&self, attributes: &BTreeMap<String, String>) -> Vec<u64> {
        self.items.iter()
            .filter(|(_, item)| attributes.iter().all(|(attr, value)| item.attributes.get(attr) == Some(value)))
            .map(|(&item_id, _)| item_id)
            .collect()
    }
}

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

impl Item {
    fn id_to_string(id: u64) -> String {
        format!("/org/freedesktop/secrets/collection/Login/{id}")
    }
}

static next_sess_id: AtomicU64 = AtomicU64::new(0);
static service_mutex: Mutex<Service> = Mutex::new(Service::new());
static service_iface_token_mutex: Mutex<Option<IfaceToken<ServiceHandle>>> = Mutex::new(None);
static collection_iface_token_mutex: Mutex<Option<IfaceToken<CollectionHandle>>> = Mutex::new(None);
static item_iface_token_mutex: Mutex<Option<IfaceToken<ItemHandle>>> = Mutex::new(None);
static session_iface_token_mutex: Mutex<Option<IfaceToken<SessionHandle>>> = Mutex::new(None);

struct ServiceHandle;

impl ServiceHandle {
    fn open_session(
        _ctx: &mut Context,
        cr: &mut Crossroads,
        (algorithm, input): (String, Variant<Box<dyn RefArg>>)
    ) -> Result<(Variant<&'static str>, Path<'static>), MethodErr> {
        eprintln!("{}, {:?}", algorithm, input);
        if algorithm != "plain" {
            return Err(dbus::Error::new_custom("org.freedesktop.DBus.Error.NotSupported", "").into())
        }

        let session_id = next_sess_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let session_id_str = format!("/org/freedesktop/secrets/session/{session_id}");
        cr.insert(session_id_str.clone(), &[session_iface_token_mutex.lock().unwrap().unwrap()], SessionHandle);

        Ok((Variant(""), Path::new(session_id_str).unwrap()))
    }

    fn search_item(
        _ctx: &mut Context,
        _cr: &mut ServiceHandle,
        (attributes,): (BTreeMap<String, String>,)
    ) -> Result<(Vec<Path<'static>>, Vec<Path<'static>>), MethodErr> {
        eprintln!("Search Item {attributes:?}");

        let service = service_mutex.lock().unwrap();
        let results: Result<Vec<_>, _> = service.find_by_attributes(&attributes).into_iter()
            .map(Item::id_to_string)
            .map(Path::new)
            .collect();

        eprintln!("Search Item Results {results:?}");
                    
        Ok((results.unwrap(), Vec::<Path>::new()))
    }

    fn register_dbus(cr: &mut Crossroads) {
        let iface_token = cr.register("org.freedesktop.Secret.Service", |iface_builder| {
            iface_builder.method_with_cr("OpenSession", ("algorithm", "input"), ("output", "result"), Self::open_session);
            iface_builder.method("SearchItems", ("attributes",), ("unlocked", "locked"), Self::search_item);
        });

        *service_iface_token_mutex.lock().unwrap() = Some(iface_token)
    }
}

struct CollectionHandle;

impl CollectionHandle {
    fn create_item(
        _ctx: &mut Context,
        cr: &mut Crossroads,
        (properties, secret, replace): (PropMap, Secret, bool)
    ) -> Result<(Path<'static>, Path<'static>), MethodErr> {

        eprintln!("Create Item: {properties:?} {secret:?} {replace:?}");

        let label = properties.get("org.freedesktop.Secret.Item.Label")
            .and_then(|b| b.as_str().map(|x| x.to_string()))
            .unwrap_or_default();
        let attributes = properties.get("org.freedesktop.Secret.Item.Attributes")
            .and_then(|b| {
                let mut key = None;
                let mut result = BTreeMap::new();
                for x in b.0.as_iter()? {
                    eprintln!("x {:?}", x);
                    let x = x.as_str().unwrap().to_string();
                    if let Some(k) = key.take() {
                        result.insert(k, x);
                    } else {
                        key = Some(x)
                    }
                }
                Some(result)
            })
            .unwrap_or_default();
        
        let (_, _, content, content_type) = secret;

        let now = get_unix_timestamp();
        let item = Item { label, attributes, created: now, modified: now, content, content_type };

        let mut service = service_mutex.lock().unwrap();

        let item_id = if replace && let Some(&item_id) = service.find_by_attributes(&item.attributes).first() {
            item_id
        } else {
            let item_id = service.next_item_id;
            service.next_item_id += 1;
            item_id
        };

        service.items.insert(item_id, item);
        service.save().unwrap();

        let item_id_str = format!("/org/freedesktop/secrets/collection/Login/{item_id}");
        cr.insert(item_id_str.clone(), &[item_iface_token_mutex.lock().unwrap().unwrap()], ItemHandle(item_id));

        Ok((Path::new(item_id_str).unwrap(), Path::new("/").unwrap()))
    }

    fn register_dbus(cr: &mut Crossroads) {
        let iface_token = cr.register("org.freedesktop.Secret.Collection", |iface_builder| {
            iface_builder.method_with_cr("CreateItem", ("properties", "secret", "replace"), ("item", "prompt"), Self::create_item);
        });

        *collection_iface_token_mutex.lock().unwrap() = Some(iface_token);
    }
}

#[derive(Debug, Clone)]
struct ItemHandle(u64);

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
        item.modified = get_unix_timestamp();
        service.save().unwrap();
        result
    }

    fn delete(
        ctx: &mut Context,
        cr: &mut Crossroads,
        (): ()
    ) -> Result<(Path<'static>, ), MethodErr> {
        cr.remove::<Self>(ctx.path()).unwrap();

        // TODO: 
        // also remember to save

        Ok((Path::new("/").unwrap(),))
    }

    fn get_secret(
        _ctx: &mut Context,
        item_handle: &mut ItemHandle,
        (sess,): (Path<'static>,)
    ) -> Result<(Secret, ), MethodErr> {
        item_handle.with_item(|item| {
            Ok(((sess.clone(), vec![], item.content.clone(), item.content_type.clone()), ))
        })
    }

    fn set_secret(
        _ctx: &mut Context,
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

    fn register_dbus(cr: &mut Crossroads) {
        let iface_token = cr.register("org.freedesktop.Secret.Item", |iface_builder: &mut IfaceBuilder<ItemHandle>| {
            iface_builder.method_with_cr("Delete", (), ("Prompt", ), Self::delete);
            iface_builder.method("GetSecrets", ("session", ), ("secret", ), Self::get_secret);
            iface_builder.method("SetSecret", ("secret", ), (), Self::set_secret);


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
        });

        *item_iface_token_mutex.lock().unwrap() = Some(iface_token);
    }
}

struct SessionHandle;

impl SessionHandle {
    fn delete(
        ctx: &mut Context,
        cr: &mut Crossroads,
        (): ()
    ) -> Result<(), MethodErr> {
        cr.remove::<Self>(ctx.path()).unwrap();
        Ok(())
    }

    fn register_dbus(cr: &mut Crossroads) {
        let iface_token = cr.register("org.freedesktop.Secret.Session", |iface_builder: &mut IfaceBuilder<SessionHandle>| {
            iface_builder.method_with_cr("Delete", (), (), Self::delete);
        });

        *session_iface_token_mutex.lock().unwrap() = Some(iface_token);
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

    ServiceHandle::register_dbus(&mut cr);
    CollectionHandle::register_dbus(&mut cr);
    ItemHandle::register_dbus(&mut cr);
    SessionHandle::register_dbus(&mut cr);

    cr.insert("/org/freedesktop/secrets", &[service_iface_token_mutex.lock()?.unwrap()], ServiceHandle);
    cr.insert("/org/freedesktop/secrets/aliases/default", &[collection_iface_token_mutex.lock()?.unwrap()], CollectionHandle);
    cr.insert("/org/freedesktop/secrets/collection/Login", &[collection_iface_token_mutex.lock()?.unwrap()], CollectionHandle);

    service_mutex.lock().unwrap().load(&mut cr)?;

    cr.serve(&c)?;
    unreachable!()
}

// todo: implement unlock. it is called with empty array



// method call time=1672515928.881481 sender=:1.221 -> destination=:1.218 serial=31 path=/org/freedesktop/secrets; interface=org.freedesktop.Secret.Service; member=GetSecrets
//    array [
//       object path "/org/freedesktop/secrets/collection/Login/1"
//    ]
//    object path "/org/freedesktop/secrets/session/0"