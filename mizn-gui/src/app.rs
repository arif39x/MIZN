use eframe::egui;
use crate::state::AppState;
use crate::views;

#[derive(PartialEq)]
pub enum Tab {
    Dashboard,
    NetworkInspector,
    SecurityCenter,
}

pub struct MiznApp {
    state: AppState,
    current_tab: Tab,
}

impl MiznApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());

        Self {
            state: AppState::new(cc.egui_ctx.clone()),
            current_tab: Tab::Dashboard,
        }
    }
}

impl eframe::App for MiznApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Top Navigation Bar
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("MIZN");
                ui.separator();
                ui.selectable_value(&mut self.current_tab, Tab::Dashboard, "Dashboard");
                ui.selectable_value(&mut self.current_tab, Tab::NetworkInspector, "Network Inspector");
                ui.selectable_value(&mut self.current_tab, Tab::SecurityCenter, "Security Center");
            });
        });

        // Main Content Area
        egui::CentralPanel::default().show(ctx, |ui| {
            match self.current_tab {
                Tab::Dashboard => views::dashboard::render(ui, &self.state),
                Tab::NetworkInspector => views::top_talkers::render(ui, &self.state),
                Tab::SecurityCenter => views::alerts::render(ui, &self.state),
            }
        });
    }
}
