use gettextrs::gettext;
use gtk::prelude::*;
use gtk4::{
    glib::{clone, spawn_future_local},
    prelude::OrientableExt,
};
use relm4::prelude::*;
use tokio::sync::mpsc;

use crate::events::{AuthenticationAgentEvent, AuthenticationUserEvent};

#[derive(Debug, zeroize::ZeroizeOnDrop)]
pub enum AppMsg {
    Confirm { user: String, password: String },
    Cancel,
    AuthEvent(AuthenticationAgentEvent),
}

pub struct App {
    message: String,
    identities: Vec<String>,
    cookie: Option<String>,
    retry_message: Option<String>,
    authenticating: bool,
    /// Whether to show the password entry and its controls. Hidden during an
    /// eager non-password flow until the PAM stack asks for a secret, so the
    /// user isn't shown a password box they can't use.
    show_password: bool,
    /// Placeholder for the password entry, set from the helper's prompt text.
    prompt: String,
    sender: mpsc::Sender<AuthenticationUserEvent>, // chosen_identity: Option<String>,
}

#[allow(unused_assignments)]
#[relm4::component(async, pub)]
impl AsyncComponent for App {
    type Input = AppMsg;
    type Output = ();
    type Init = (
        mpsc::Sender<AuthenticationUserEvent>,
        mpsc::Receiver<AuthenticationAgentEvent>,
    );
    type CommandOutput = ();

    view! {
        gtk::Window {
            set_title: Some("Authorize"),
            set_default_height: 250,
            set_default_width: 450,
            set_resizable: false,
            set_modal: true,
            set_hide_on_close: true,
            #[watch]
            set_visible: model.cookie.is_some(),

            connect_show[password_entry] => move |_| {
                password_entry.grab_focus();
            },
            connect_close_request[cancel_button] => move |_| {
                cancel_button.emit_clicked();
                gtk4::glib::Propagation::Proceed
            },

            gtk::Box {
                set_margin_end: 56,
                set_margin_start: 56,
                set_orientation: gtk::Orientation::Vertical,

                gtk::Label {
                    set_markup: &format!(r#"<b><span size='x-large'>{}</span></b>"#, gettext("Authentication Required")),
                    set_margin_horizontal: 16,
                    set_margin_vertical: 16,
                    set_halign: gtk::Align::Center,
                    set_justify: gtk::Justification::Fill,
                    set_use_markup: true,
                },

                gtk::Label {
                    #[watch]
                    set_label: &model.message,
                    set_single_line_mode: true,
                    set_wrap: true,
                    #[watch]
                    set_margin_bottom: if model.retry_message.is_some() { 8 } else { 16 },
                },

                gtk::Label {
                    #[watch]
                    set_label: &if let Some(retry_message) = model.retry_message.clone() {
                        retry_message.to_string()
                    } else {
                        "".to_string()
                    },
                    #[watch]
                    set_visible: model.retry_message.is_some(),
                    #[watch]
                    set_margin_bottom: 16,
                    set_halign: gtk::Align::Center,
                },

                gtk::Box {
                    set_baseline_position: gtk::BaselinePosition::Center,
                    set_spacing: 18,
                    #[watch]
                    set_visible: model.show_password,

                    #[name = "identity_dropdown"]
                    gtk::DropDown {
                        set_margin_bottom: 8,
                        set_hexpand: true,
                        #[watch]
                        set_model: Some( &gtk::StringList::new(&model.identities.iter().map(AsRef::as_ref).collect::<Vec<_>>()) ),
                        #[watch]
                        set_selected: {
                            if let Some(Ok(user))
                            = etc_passwd::Passwd::current_user().ok().flatten().map(|p| p.name.into_string()) {
                                model.identities.iter().position(|n| n == &user).unwrap_or(0) as u32
                            } else { 0 }

                        }

                    }
                },

                #[name = "password_entry"]
                gtk::PasswordEntry {
                    set_hexpand: true,
                    #[watch]
                    set_placeholder_text: Some(model.prompt.as_str()),
                    set_show_peek_icon: true,
                    #[watch]
                    set_visible: model.show_password,
                    #[watch]
                    set_editable: !model.authenticating,

                    // Focus the entry whenever it's revealed.
                    connect_map => move |entry| {
                        entry.grab_focus();
                    },

                    connect_activate[confirm_button] => move |_| {
                        confirm_button.emit_clicked();
                    }
                },

                gtk::FlowBox {
                    set_hexpand: true,
                    set_homogeneous: true,
                    set_margin_bottom: 16,
                    set_margin_top: 8,
                    set_max_children_per_line: 2,
                    set_valign: gtk::Align::End,
                    set_vexpand: true,

                    #[name = "cancel_button"]
                    append = &gtk::Button::with_label(&gettext("Cancel")){
                        connect_clicked[sender, password_entry] => move |_| {

                            sender.input(AppMsg::Cancel);
                            password_entry.set_text("");
                        }
                    },

                    #[name = "confirm_button"]
                    append = &gtk::Button::with_label(&gettext("Confirm")) {
                        #[watch]
                        set_visible: model.show_password,
                        connect_clicked[sender, identity_dropdown, password_entry] => move |_| {
                            let user: gtk::StringObject = identity_dropdown.selected_item().unwrap().dynamic_cast().unwrap();

                            sender.input(AppMsg::Confirm { user: user.string().to_string(), password: password_entry.text().to_string()});
                            password_entry.set_text("");

                        }
                    }
                }
            }

        }
    }

    async fn init(
        init: Self::Init,
        root: Self::Root,
        sender: AsyncComponentSender<Self>,
    ) -> AsyncComponentParts<Self> {
        let model = App {
            message: String::from(""),
            identities: Vec::new(),
            sender: init.0,
            cookie: None,
            authenticating: false,
            retry_message: None,
            show_password: false,
            prompt: gettext("Password"),
        };

        spawn_future_local(clone!(
            #[strong]
            sender,
            async move {
                let mut receiver = init.1;
                loop {
                    let event = receiver.recv().await.expect("Somehow the channel closed");
                    tracing::debug!("recieved event {:#?}", event);

                    sender.input(AppMsg::AuthEvent(event));
                }
            }
        ));

        let widgets = view_output!();

        AsyncComponentParts { model, widgets }
    }

    async fn update(
        &mut self,
        message: Self::Input,
        _sender: AsyncComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match &message {
            AppMsg::Confirm { user, password } => {
                if let Some(cookie) = self.cookie.clone() {
                    self.sender
                        .send(AuthenticationUserEvent::ProvidedPassword {
                            cookie,
                            username: user.clone(),
                            password: password.clone(),
                        })
                        .await
                        .unwrap();
                    self.retry_message = Some(gettext("Authenticating..."));
                    self.authenticating = true;
                }
            }
            AppMsg::Cancel => {
                if let Some(cookie) = self.cookie.clone() {
                    self.sender
                        .send(AuthenticationUserEvent::Canceled { cookie })
                        .await
                        .unwrap();
                    self.cookie = None;
                    self.message = String::new();
                    self.retry_message = Some(String::new());
                    self.authenticating = false;
                    self.identities = Vec::new();
                    self.show_password = false;
                }
            }
            AppMsg::AuthEvent(ev) => match ev {
                AuthenticationAgentEvent::Started {
                    cookie,
                    message,
                    names,
                } => {
                    if self.cookie.is_none() {
                        self.cookie = Some(cookie.clone());
                        self.message = message.clone();
                        self.identities = names.clone();
                        self.authenticating = false;
                        self.retry_message = None;
                        self.prompt = gettext("Password");
                        // A single identity spawns the helper eagerly, so a
                        // non-password method may drive the prompt; keep the entry
                        // hidden until the stack asks for a secret. With multiple
                        // identities the user picks one and submits, so it must be
                        // visible from the start.
                        self.show_password = names.len() != 1;
                    }
                }
                AuthenticationAgentEvent::Canceled { cookie } => {
                    if let Some(c) = &self.cookie {
                        if c == cookie {
                            self.cookie = None;
                            self.message = String::new();
                            self.identities = Vec::new();
                            self.retry_message = None;
                            self.authenticating = false;
                            self.show_password = false;
                        }
                    }
                }
                AuthenticationAgentEvent::AuthorizationSucceeded { cookie } => {
                    if let Some(c) = &self.cookie {
                        if c == cookie {
                            tracing::debug!("Authentication succeeded, closing window.");
                            self.cookie = None;
                            self.message.clear();
                            self.identities.clear();
                            self.retry_message = None;
                            self.authenticating = false;
                            self.show_password = false;
                        }
                    }
                }
                AuthenticationAgentEvent::AuthorizationRetry {
                    cookie,
                    retry_message,
                } => {
                    if let Some(c) = &self.cookie {
                        if c == cookie {
                            self.retry_message = retry_message.clone();
                            self.authenticating = false;
                            // A failed attempt drops back to the submit-first
                            // flow, so let the user type a password to retry.
                            self.show_password = true;
                        }
                    }
                }
                AuthenticationAgentEvent::Info { cookie, message } => {
                    // Show PAM info/error text in the status label. Doesn't reveal
                    // the password entry: a non-password method has no password to
                    // type.
                    if let Some(c) = &self.cookie {
                        if c == cookie {
                            self.retry_message = Some(message.clone());
                        }
                    }
                }
                AuthenticationAgentEvent::SecretRequested { cookie, prompt } => {
                    // The PAM stack wants a secret, so reveal the entry; this is
                    // also how an eager non-password flow falls through to a
                    // password. Clear any stale status from the previous method.
                    if let Some(c) = &self.cookie {
                        if c == cookie {
                            self.show_password = true;
                            self.authenticating = false;
                            self.retry_message = None;
                            self.prompt = if prompt.is_empty() {
                                gettext("Password")
                            } else {
                                prompt.clone()
                            };
                        }
                    }
                }
            },
        }
    }
}
