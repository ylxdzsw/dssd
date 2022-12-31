#![allow(clippy::uninlined_format_args)]

use dbus::{blocking::Connection, arg::{Variant, RefArg}, Path, MethodErr};
use dbus_crossroads::{Crossroads, Context, IfaceToken};
use std::{error::Error, collections::{HashMap}, sync::atomic::AtomicU64};

#[derive(Default)]
struct Session {} // TODO: implement the Close method

/// The global object storing all states of the application
#[derive(Default)]
struct Service {
    last_id: AtomicU64
}

impl Service {
    fn open_session(
        ctx: &mut Context,
        cr: &mut Crossroads,
        (algorithm, input): (String, Variant<Box<dyn RefArg>>)
    ) -> Result<(Variant<&'static str>, Path<'static>), MethodErr> {
        let service: &mut Service = cr.data_mut(ctx.path()).unwrap();

        println!("{}, {:?}", algorithm, input);
        if algorithm != "plain" {
            return Err(dbus::Error::new_custom("org.freedesktop.DBus.Error.NotSupported", "").into())
        }
        
        let session_id = service.last_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let session_id_str = format!("/org/freedesktop/secrets/session/s{session_id}");
        cr.insert(session_id_str.clone(), &[], Session::default());

        Ok((Variant(""), Path::new(session_id_str).unwrap()))
    }

    fn search_item(
        ctx: &mut Context,
        service: &mut Service,
        (attributes,): (HashMap<String, String>,)
    ) -> Result<(Vec<Path<'static>>, Vec<Path<'static>>), MethodErr> {
        println!("{:?}", attributes);
                    
        Ok((Vec::<Path>::new(), Vec::<Path>::new()))
    }

    fn register_dbus(cr: &mut Crossroads) -> IfaceToken<Self> {
        cr.register("org.freedesktop.Secret.Service", |iface_builder| {
            iface_builder.method_with_cr("OpenSession", ("algorithm", "input"), ("output", "result"), Self::open_session);
            iface_builder.method("SearchItems", ("attributes",), ("unlocked", "locked"), Self::search_item);
        })
    }
}



fn main() -> Result<(), Box<dyn Error>> {
    let c = Connection::new_session()?;
    c.request_name("org.freedesktop.secrets", false, true, false)?;

    let mut cr = Crossroads::new();

    let service_iface_token = Service::register_dbus(&mut cr);
    cr.insert("/org/freedesktop/secrets", &[service_iface_token], Service::default());

    cr.serve(&c)?;
    unreachable!()
}