use eframe::{egui, App, Frame};
use secure_vault::vault::{Entry, EntryType, Vault};
use std::sync::{Arc, Mutex};

struct VaultApp {
    vault: Arc<Mutex<Option<Vault>>>,
    vault_number: Option<u32>, // Track current vault number
    password: String,
    entries: Vec<Entry>,
    selected_entry: Option<usize>,
    show_password: bool,
    editing: bool,
    edit_title: String,
    edit_content: String,
    edit_type: EntryType,
    new_entry_title: String,
    new_entry_content: String,
    new_entry_type: EntryType,
    error_message: Option<String>,
}

impl Default for VaultApp {
    fn default() -> Self {
        VaultApp {
            vault: Arc::new(Mutex::new(None)),
            vault_number: None,
            password: String::new(),
            entries: Vec::new(),
            selected_entry: None,
            show_password: false,
            editing: false,
            edit_title: String::new(),
            edit_content: String::new(),
            edit_type: EntryType::default(),
            new_entry_title: String::new(),
            new_entry_content: String::new(),
            new_entry_type: EntryType::default(),
            error_message: None,
        }
    }
}

impl VaultApp {
    fn load_vault(&mut self) {
        let password = self.password.trim();
        if password.is_empty() {
            self.error_message = Some("Password cannot be empty.".to_string());
            return;
        }

        if let Some(filename) = Vault::find_vault_by_passcode(password) {
            if let Some(vault_number) = Vault::parse_vault_number(&filename) {
                match Vault::load_encrypted(&filename, password) {
                    Ok(vault) => {
                        self.entries = vault.entries.clone();
                        *self.vault.lock().unwrap() = Some(vault);
                        self.vault_number = Some(vault_number);
                        self.error_message = None;
                    }
                    Err(e) => {
                        self.error_message = Some(format!("Failed to load vault: {}", e));
                        self.entries.clear();
                        *self.vault.lock().unwrap() = None;
                        self.vault_number = None;
                    }
                }
            } else {
                self.error_message = Some("Invalid vault filename format.".to_string());
            }
        } else {
            self.error_message = Some("No vault matches this passcode.".to_string());
            self.entries.clear();
            *self.vault.lock().unwrap() = None;
            self.vault_number = None;
        }
    }

    fn save_vault(&mut self) {
        let password = self.password.trim();
        if password.is_empty() {
            self.error_message = Some("Password cannot be empty.".to_string());
            return;
        }

        if let Ok(mut guard) = self.vault.lock() {
            if let Some(vault) = guard.as_mut() {
                vault.entries = self.entries.clone();
                match vault.save_with_number(password, self.vault_number) {
                    Ok(filename) => {
                        self.vault_number = Vault::parse_vault_number(&filename);
                        self.error_message = None;
                    }
                    Err(e) => self.error_message = Some(format!("Failed to save vault: {}", e)),
                }
            } else {
                let vault = Vault { entries: self.entries.clone() };
                match vault.save_with_number(password, None) {
                    Ok(filename) => {
                        self.vault_number = Vault::parse_vault_number(&filename);
                        *self.vault.lock().unwrap() = Some(vault);
                        self.error_message = None;
                    }
                    Err(e) => self.error_message = Some(format!("Failed to save vault: {}", e)),
                }
            }
        }
    }

    fn initialize_vault(&mut self) {
        let password = self.password.trim();
        if password.is_empty() {
            self.error_message = Some("Password cannot be empty.".to_string());
            return;
        }

        let vault = Vault::new();
        match vault.save_with_number(password, None) {
            Ok(filename) => {
                self.vault_number = Vault::parse_vault_number(&filename);
                *self.vault.lock().unwrap() = Some(vault);
                self.entries.clear();
                self.error_message = None;
            }
            Err(e) => self.error_message = Some(format!("Failed to initialize vault: {}", e)),
        }
    }
}

impl App for VaultApp {

    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Secure Vault");

            // Password input, Load Vault and Initialize Vault buttons
            ui.horizontal(|ui| {
                if self.show_password {
                    ui.label("Password (visible):");
                    ui.text_edit_singleline(&mut self.password);
                } else {
                    ui.label("Master Password:");
                    ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
                }
                ui.checkbox(&mut self.show_password, "Show Password");

                if ui.button("Load Vault").clicked() {
                    self.load_vault();
                    self.selected_entry = None;
                }
                if ui.button("Initialize New Vault").clicked() {
                    self.initialize_vault();
                    self.selected_entry = None;
                }
            });

            if let Some(err) = &self.error_message {
                ui.colored_label(egui::Color32::RED, err);
            }

            ui.separator();

            // List entries after vault loaded
            if !self.entries.is_empty() {
                ui.label("Entries:");
                egui::ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
                    for (i, entry) in self.entries.iter().enumerate() {
                        let label = format!("{}: {} ({:?})", i + 1, entry.title, entry.entry_type);
                        if ui.selectable_label(self.selected_entry == Some(i), label).clicked() {
                            self.selected_entry = Some(i);
                            // Setup edit fields when selecting
                            let e = &self.entries[i];
                            self.edit_title = e.title.clone();
                            self.edit_content = e.content.clone();
                            self.edit_type = e.entry_type.clone();
                            self.editing = false;
                        }
                    }
                });
            } else {
                ui.label("No entries loaded.");
            }

            ui.separator();

            // Entry details & edit/remove buttons
            if let Some(selected) = self.selected_entry {
                ui.group(|ui| {
                    ui.heading("Selected Entry");

                    if self.editing {
                        ui.horizontal(|ui| {
                            ui.label("Title:");
                            ui.text_edit_singleline(&mut self.edit_title);
                        });

                        ui.horizontal(|ui| {
                            ui.label("Type:");
                            egui::ComboBox::from_id_salt("edit_type")
                                .selected_text(format!("{:?}", self.edit_type))
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(&mut self.edit_type, EntryType::Note, "Note");
                                    ui.selectable_value(&mut self.edit_type, EntryType::Password, "Password");
                                });
                        });

                        ui.label("Content:");
                        ui.text_edit_multiline(&mut self.edit_content);

                        ui.horizontal(|ui| {
                            if ui.button("Save").clicked() {
                                // Save edits
                                self.entries[selected].title = self.edit_title.clone();
                                self.entries[selected].entry_type = self.edit_type.clone();
                                self.entries[selected].content = self.edit_content.clone();
                                self.save_vault();
                                self.editing = false;
                            }
                            if ui.button("Cancel").clicked() {
                                self.editing = false;
                            }
                        });
                    } else {
                        let entry = &self.entries[selected];
                        ui.label(format!("Title: {}", entry.title));
                        ui.label(format!("Type: {:?}", entry.entry_type));
                        if let EntryType::Password = entry.entry_type {
                            if self.show_password {
                                ui.label(format!("Content: {}", entry.content));
                            } else {
                                ui.label("Content: ********");
                            }
                        } else {
                            ui.label(format!("Content:\n{}", entry.content));
                        }

                        ui.horizontal(|ui| {
                            if ui.button("Edit").clicked() {
                                self.editing = true;
                            }
                            if ui.button("Remove").clicked() {
                                self.entries.remove(selected);
                                self.selected_entry = None;
                                self.save_vault();
                            }
                        });
                    }
                });
            }

            ui.separator();

            // Add new entry
            ui.group(|ui| {
                ui.heading("Add New Entry");

                ui.horizontal(|ui| {
                    ui.label("Title:");
                    ui.text_edit_singleline(&mut self.new_entry_title);
                });

                ui.horizontal(|ui| {
                    ui.label("Type:");
                    egui::ComboBox::from_id_salt("new_type")
                        .selected_text(format!("{:?}", self.new_entry_type))
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.new_entry_type, EntryType::Note, "Note");
                            ui.selectable_value(&mut self.new_entry_type, EntryType::Password, "Password");
                        });
                });

                ui.label("Content:");
                ui.text_edit_multiline(&mut self.new_entry_content);

                if ui.button("Add Entry").clicked() {
                    if self.new_entry_title.trim().is_empty() || self.new_entry_content.trim().is_empty() {
                        self.error_message = Some("Title and content cannot be empty.".to_string());
                    } else {
                        let entry = Entry {
                            title: self.new_entry_title.trim().to_string(),
                            entry_type: self.new_entry_type.clone(),
                            content: self.new_entry_content.trim().to_string(),
                        };
                        self.entries.push(entry);
                        self.save_vault();

                        // Reset input fields
                        self.new_entry_title.clear();
                        self.new_entry_content.clear();
                        self.error_message = None;
                    }
                }
            });
        });
    }
}

fn main() -> eframe::Result<()> {
    let app = VaultApp::default();
    let native_options = eframe::NativeOptions::default();
    eframe::run_native("Secure Vault", native_options, Box::new(|_cc| Ok(Box::new(app))))
}
