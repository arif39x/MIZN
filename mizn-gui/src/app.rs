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
    inspected_pid: Option<i32>,
}

impl MiznApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = egui::Color32::from_rgb(15, 20, 25);
        visuals.window_fill = egui::Color32::from_rgb(20, 25, 30);
        visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(30, 35, 45);
        visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(45, 50, 60);
        visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(60, 65, 80);
        visuals.widgets.active.bg_fill = egui::Color32::from_rgb(80, 85, 100);
        visuals.selection.bg_fill = egui::Color32::from_rgb(0, 255, 180); // Neon cyan
        cc.egui_ctx.set_visuals(visuals);

        Self {
            state: AppState::new(cc.egui_ctx.clone()),
            current_tab: Tab::Dashboard,
            inspected_pid: None,
        }
    }
}

impl eframe::App for MiznApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::SidePanel::left("left_panel")
            .resizable(false)
            .min_width(220.0)
            .show(ctx, |ui| {
                ui.add_space(20.0);
                ui.vertical_centered(|ui| {
                    ui.heading(egui::RichText::new("MIZN").size(36.0).color(egui::Color32::from_rgb(0, 255, 180)).strong());
                    ui.label(egui::RichText::new("COMMAND CENTER").size(11.0).color(egui::Color32::DARK_GRAY));
                });
                ui.add_space(30.0);

                let mut nav_btn = |ui: &mut egui::Ui, text, tab: Tab| {
                    let mut text = egui::RichText::new(text).size(16.0);
                    if self.current_tab == tab {
                        text = text.color(egui::Color32::from_rgb(0, 255, 180)).strong();
                    } else {
                        text = text.color(egui::Color32::LIGHT_GRAY);
                    }
                    if ui.add(egui::Button::new(text).fill(egui::Color32::TRANSPARENT)).clicked() {
                        self.current_tab = tab;
                    }
                    ui.add_space(8.0);
                };

                nav_btn(ui, "📊 Dashboard", Tab::Dashboard);
                nav_btn(ui, "🌐 Network Inspector", Tab::NetworkInspector);
                nav_btn(ui, "🛡 Security Center", Tab::SecurityCenter);

                ui.with_layout(egui::Layout::bottom_up(egui::Align::Center), |ui| {
                    ui.add_space(20.0);
                    ui.label(egui::RichText::new("v0.1.0-alpha").size(10.0).color(egui::Color32::DARK_GRAY));
                });
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            // Apply a slight margin around the central panel content
            egui::Frame::none().inner_margin(egui::Margin::same(16.0)).show(ui, |ui| {
                match self.current_tab {
                    Tab::Dashboard => views::dashboard::render(ui, &self.state),
                    Tab::NetworkInspector => views::top_talkers::render(ui, &self.state, &mut self.inspected_pid),
                    Tab::SecurityCenter => views::alerts::render(ui, &self.state),
                }
            });
        });
    }
}
